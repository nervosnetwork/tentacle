use bytes::Bytes;
use futures::prelude::*;
use std::{
    fmt,
    ops::{Deref, DerefMut},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use crate::channel::QuickSinkExt;
use crate::{
    ProtocolId, SessionId,
    channel::{mpsc, mpsc::Priority},
    error::SendErrorKind,
    multiaddr::Multiaddr,
    secio::PublicKey,
    service::{
        ServiceAsyncControl, ServiceControl, SessionType, TargetProtocol, TargetSession,
        event::ServiceTask,
    },
    session::SessionEvent,
};

pub(crate) struct SessionController {
    pub(crate) sender: mpsc::Sender<SessionEvent>,
    pub(crate) inner: Arc<SessionContext>,
}

impl SessionController {
    pub(crate) fn new(
        event_sender: mpsc::Sender<SessionEvent>,
        inner: Arc<SessionContext>,
    ) -> Self {
        Self {
            sender: event_sender,
            inner,
        }
    }

    pub(crate) async fn send(&mut self, priority: Priority, event: SessionEvent) -> Result {
        if priority.is_high() {
            self.sender.quick_send(event).await.map_err(|_err| {
                // await only return err when channel close
                SendErrorKind::BrokenPipe
            })
        } else {
            self.sender.send(event).await.map_err(|_err| {
                // await only return err when channel close
                SendErrorKind::BrokenPipe
            })
        }
    }

    /// Reserve byte capacity before handing protocol data to the session.
    /// Returns `true` exactly once when this message would exceed the limit.
    pub(crate) async fn send_message(
        &mut self,
        priority: Priority,
        proto_id: ProtocolId,
        data: Bytes,
        mut guard: PendingDataGuard,
    ) -> bool {
        let data_size = data.len();
        if guard.context().closed() {
            return false;
        }

        match guard.resize(data_size) {
            PendingDataReservation::Reserved => {}
            PendingDataReservation::LimitReached => {
                let id = self.inner.id;
                let _ignore = self
                    .send(Priority::High, SessionEvent::SessionClose { id })
                    .await;
                return true;
            }
            PendingDataReservation::Closed => return false,
        }

        // A concurrent sender may have reached the limit after this message
        // reserved its bytes. Do not admit the message after that happens.
        if self.inner.closed() {
            return false;
        }

        let _ignore = self
            .send(
                priority,
                SessionEvent::ProtocolMessage {
                    proto_id,
                    data,
                    guard,
                },
            )
            .await;
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PendingDataReservation {
    Reserved,
    LimitReached,
    Closed,
}

/// Session context, contains basic information about the current connection
#[derive(Clone, Debug)]
pub struct SessionContext {
    /// Session's ID
    pub id: SessionId,
    /// Remote socket address
    pub address: Multiaddr,
    /// Session type (server or client)
    pub ty: SessionType,
    // TODO: use reference?
    /// Remote public key
    pub remote_pubkey: Option<PublicKey>,
    pub(crate) closed: Arc<AtomicBool>,
    pending_data_size: Arc<AtomicUsize>,
    send_buffer_size: usize,
}

impl SessionContext {
    pub(crate) fn new(
        id: SessionId,
        address: Multiaddr,
        ty: SessionType,
        remote_pubkey: Option<PublicKey>,
        closed: Arc<AtomicBool>,
        pending_data_size: Arc<AtomicUsize>,
        send_buffer_size: usize,
    ) -> SessionContext {
        SessionContext {
            id,
            address,
            ty,
            remote_pubkey,
            closed,
            pending_data_size,
            send_buffer_size,
        }
    }

    /// Atomically reserve pending-byte capacity without exceeding the limit.
    pub(crate) fn reserve_pending_data(&self, data_size: usize) -> PendingDataReservation {
        if self.closed() {
            return PendingDataReservation::Closed;
        }

        if self
            .pending_data_size
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(data_size)
                    .filter(|next| *next <= self.send_buffer_size)
            })
            .is_err()
        {
            return if !self.closed.swap(true, Ordering::SeqCst) {
                PendingDataReservation::LimitReached
            } else {
                PendingDataReservation::Closed
            };
        }

        // Coordinate with a concurrent limit breach or shutdown occurring
        // immediately after the atomic reservation.
        if self.closed() {
            self.decr_pending_data_size(data_size);
            PendingDataReservation::Closed
        } else {
            PendingDataReservation::Reserved
        }
    }

    // Decrease when data sent to underlying Yamux Stream
    pub(crate) fn decr_pending_data_size(&self, data_size: usize) {
        self.pending_data_size
            .fetch_sub(data_size, Ordering::AcqRel);
    }

    /// Whether this session is gone.
    ///
    /// This also becomes `true` the moment an outbound message would exceed
    /// [`crate::builder::ServiceBuilder::set_send_buffer_size`], which is when
    /// the session is scheduled to be closed — slightly before the close has
    /// actually been carried out.
    pub fn closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
    /// Outbound bytes queued for this session but not yet handed to the
    /// transport. Never exceeds the configured send buffer size, because
    /// capacity is reserved before a message is accepted.
    pub fn pending_data_size(&self) -> usize {
        self.pending_data_size.load(Ordering::Acquire)
    }
}

/// Ownership of send-buffer capacity reserved for one queued message.
///
/// Bytes count against the session's send buffer from the moment they are
/// reserved until they stop being queued — either because the transport sink
/// took them, or because they were thrown away. Every queue in between (the
/// session's per-substream buffer, the substream channel, the substream's own
/// write buffers) carries this guard next to the data, so the capacity is
/// returned exactly once no matter which of those paths the data leaves by:
/// a written frame, a closed substream, a cleared buffer, a disconnected
/// channel or a dropped task.
///
/// Dropping the guard is the release; there is deliberately no way to leak it.
pub(crate) struct PendingDataGuard {
    context: SessionContext,
    size: usize,
}

impl PendingDataGuard {
    pub(crate) fn new(context: SessionContext, size: usize) -> Self {
        Self { context, size }
    }

    pub(crate) fn context(&self) -> &SessionContext {
        &self.context
    }

    pub(crate) fn resize(&mut self, size: usize) -> PendingDataReservation {
        if size > self.size {
            match self.context.reserve_pending_data(size - self.size) {
                PendingDataReservation::Reserved => self.size = size,
                result => return result,
            }
        } else if size < self.size {
            self.context.decr_pending_data_size(self.size - size);
            self.size = size;
        }
        PendingDataReservation::Reserved
    }
}

impl Drop for PendingDataGuard {
    fn drop(&mut self) {
        self.context.decr_pending_data_size(self.size);
    }
}

impl fmt::Debug for PendingDataGuard {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PendingDataGuard({})", self.size)
    }
}

type Result = std::result::Result<(), SendErrorKind>;

/// The Service runtime can send some instructions to the inside of the handle.
/// This is the sending channel.
// TODO: Need to maintain the network topology map here?
pub struct ServiceContext {
    listens: Vec<Multiaddr>,
    inner: ServiceAsyncControl,
}

impl ServiceContext {
    /// New
    pub(crate) fn new(task_sender: mpsc::Sender<ServiceTask>, closed: Arc<AtomicBool>) -> Self {
        ServiceContext {
            inner: ServiceControl::new(task_sender, closed).into(),
            listens: Vec::new(),
        }
    }

    /// Create a new listener
    #[inline]
    pub async fn listen(&self, address: Multiaddr) -> Result {
        self.inner.listen(address).await
    }

    /// Initiate a connection request to address
    #[inline]
    pub async fn dial(&self, address: Multiaddr, target: TargetProtocol) -> Result {
        self.inner.dial(address, target).await
    }

    /// Disconnect a connection
    #[inline]
    pub async fn disconnect(&self, session_id: SessionId) -> Result {
        self.inner.disconnect(session_id).await
    }

    /// Send message
    #[inline]
    pub async fn send_message_to(
        &self,
        session_id: SessionId,
        proto_id: ProtocolId,
        data: Bytes,
    ) -> Result {
        self.inner.send_message_to(session_id, proto_id, data).await
    }

    /// Send message on quick channel
    #[inline]
    pub async fn quick_send_message_to(
        &self,
        session_id: SessionId,
        proto_id: ProtocolId,
        data: Bytes,
    ) -> Result {
        self.inner
            .quick_send_message_to(session_id, proto_id, data)
            .await
    }

    /// Send data to the specified protocol for the specified sessions.
    #[inline]
    pub async fn filter_broadcast(
        &self,
        session_ids: TargetSession,
        proto_id: ProtocolId,
        data: Bytes,
    ) -> Result {
        self.inner
            .filter_broadcast(session_ids, proto_id, data)
            .await
    }

    /// Send data to the specified protocol for the specified sessions on quick channel.
    #[inline]
    pub async fn quick_filter_broadcast(
        &self,
        session_ids: TargetSession,
        proto_id: ProtocolId,
        data: Bytes,
    ) -> Result {
        self.inner
            .quick_filter_broadcast(session_ids, proto_id, data)
            .await
    }

    /// Send a future task
    #[inline]
    pub async fn future_task<T>(&self, task: T) -> Result
    where
        T: Future<Output = ()> + 'static + Send,
    {
        self.inner.future_task(task).await
    }

    /// Try open a protocol
    ///
    /// If the protocol has been open, do nothing
    #[inline]
    pub async fn open_protocol(&self, session_id: SessionId, proto_id: ProtocolId) -> Result {
        self.inner.open_protocol(session_id, proto_id).await
    }

    /// Try open protocol
    ///
    /// If the protocol has been open, do nothing
    #[inline]
    pub async fn open_protocols(&self, session_id: SessionId, target: TargetProtocol) -> Result {
        self.inner.open_protocols(session_id, target).await
    }

    /// Try close a protocol
    ///
    /// If the protocol has been closed, do nothing
    #[inline]
    pub async fn close_protocol(&self, session_id: SessionId, proto_id: ProtocolId) -> Result {
        self.inner.close_protocol(session_id, proto_id).await
    }

    /// Get the internal channel sender side handle
    #[inline]
    pub fn control(&self) -> &ServiceAsyncControl {
        &self.inner
    }

    /// Get service listen address list
    #[inline]
    pub fn listens(&self) -> &[Multiaddr] {
        self.listens.as_ref()
    }

    /// Update listen list
    #[inline]
    pub(crate) fn update_listens(&mut self, address_list: Vec<Multiaddr>) {
        self.listens = address_list;
    }

    /// Set a service notify token
    pub async fn set_service_notify(
        &self,
        proto_id: ProtocolId,
        interval: Duration,
        token: u64,
    ) -> Result {
        self.inner
            .set_service_notify(proto_id, interval, token)
            .await
    }

    /// Set a session notify token
    pub async fn set_session_notify(
        &self,
        session_id: SessionId,
        proto_id: ProtocolId,
        interval: Duration,
        token: u64,
    ) -> Result {
        self.inner
            .set_session_notify(session_id, proto_id, interval, token)
            .await
    }

    /// Remove a service timer by a token
    pub async fn remove_service_notify(&self, proto_id: ProtocolId, token: u64) -> Result {
        self.inner.remove_service_notify(proto_id, token).await
    }

    /// Remove a session timer by a token
    pub async fn remove_session_notify(
        &self,
        session_id: SessionId,
        proto_id: ProtocolId,
        token: u64,
    ) -> Result {
        self.inner
            .remove_session_notify(session_id, proto_id, token)
            .await
    }

    /// Close service.
    ///
    /// Order:
    /// 1. close all listens
    /// 2. try close all session's protocol stream
    /// 3. try close all session
    /// 4. close service
    pub async fn close(&self) -> Result {
        self.inner.close().await
    }

    /// Shutdown service, don't care anything, may cause partial message loss
    pub async fn shutdown(&self) -> Result {
        self.inner.shutdown().await
    }

    pub(crate) fn clone_self(&self) -> Self {
        ServiceContext {
            inner: self.inner.clone(),
            listens: self.listens.clone(),
        }
    }
}

/// Protocol handle context
pub struct ProtocolContext {
    inner: ServiceContext,
    /// Protocol id
    pub proto_id: ProtocolId,
}

impl ProtocolContext {
    pub(crate) fn new(service_context: ServiceContext, proto_id: ProtocolId) -> Self {
        ProtocolContext {
            inner: service_context,
            proto_id,
        }
    }

    #[inline]
    pub(crate) fn as_mut<'a, 'b: 'a>(
        &'b mut self,
        session: &'a SessionContext,
    ) -> ProtocolContextMutRef<'a> {
        ProtocolContextMutRef {
            inner: self,
            session,
        }
    }
}

/// Protocol handle context with session context
///
/// Use in the callback method with a clear source of the event
/// means tentacle know the event product from which session
pub struct ProtocolContextMutRef<'a> {
    inner: &'a mut ProtocolContext,
    /// Session context
    pub session: &'a SessionContext,
}

impl ProtocolContextMutRef<'_> {
    /// Send message to current protocol current session
    ///
    /// `Ok(())` means the message was handed to the service, not that it was
    /// delivered. It is also returned when the message is deliberately dropped
    /// because the session is gone or has just exceeded
    /// [`crate::builder::ServiceBuilder::set_send_buffer_size`] — in the latter
    /// case the session is closed and
    /// [`crate::service::ServiceError::SessionBlocked`] is reported to the
    /// service handle. `Err(_)` only reports that the service itself is no
    /// longer reachable.
    #[inline]
    pub async fn send_message(&self, data: Bytes) -> Result {
        self.send_message_inner(data, false).await
    }

    /// Send message to current protocol current session on quick channel
    ///
    /// Same delivery semantics as [`ProtocolContextMutRef::send_message`].
    #[inline]
    pub async fn quick_send_message(&self, data: Bytes) -> Result {
        self.send_message_inner(data, true).await
    }

    async fn send_message_inner(&self, data: Bytes, quick: bool) -> Result {
        let data_size = data.len();
        match self.session.reserve_pending_data(data_size) {
            PendingDataReservation::Reserved => {
                let guard = PendingDataGuard::new(self.session.clone(), data_size);
                self.inner
                    .control()
                    .send_reserved_message_to(guard, self.proto_id(), data, quick)
                    .await
            }
            PendingDataReservation::LimitReached => {
                self.inner
                    .control()
                    .report_session_blocked(self.session.clone(), quick)
                    .await
            }
            PendingDataReservation::Closed => {
                // Keep closed-session sends cancellation-safe. Returning a
                // ready future here lets a protocol callback that repeatedly
                // ignores the result spin forever without giving the runtime
                // a chance to tear the protocol task down.
                crate::runtime::yield_now().await;
                Ok(())
            }
        }
    }

    /// Protocol id
    #[inline]
    pub fn proto_id(&self) -> ProtocolId {
        self.inner.proto_id
    }
}

impl Deref for ProtocolContext {
    type Target = ServiceContext;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for ProtocolContext {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Deref for ProtocolContextMutRef<'_> {
    type Target = ProtocolContext;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.inner
    }
}

impl DerefMut for ProtocolContextMutRef<'_> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner
    }
}

#[cfg(test)]
mod pending_data_tests {
    use super::*;
    use crate::{channel::mpsc, service::SessionType};

    fn controller() -> (SessionController, mpsc::Receiver<SessionEvent>) {
        let (sender, receiver) = mpsc::channel(4);
        let context = Arc::new(SessionContext::new(
            SessionId::default(),
            "/ip4/127.0.0.1/tcp/1".parse().unwrap(),
            SessionType::Inbound,
            None,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicUsize::new(0)),
            4,
        ));
        (SessionController::new(sender, context), receiver)
    }

    #[tokio::test]
    async fn resized_message_is_checked_before_session_channel_admission() {
        let (mut controller, mut receiver) = controller();
        assert_eq!(
            controller.inner.reserve_pending_data(3),
            PendingDataReservation::Reserved
        );
        let guard = PendingDataGuard::new(controller.inner.as_ref().clone(), 3);

        assert!(
            controller
                .send_message(
                    Priority::Normal,
                    1.into(),
                    Bytes::from_static(b"12345"),
                    guard,
                )
                .await
        );
        assert_eq!(controller.inner.pending_data_size(), 0);
        assert!(controller.inner.closed());
        assert!(matches!(
            receiver.next().await,
            Some((Priority::High, SessionEvent::SessionClose { .. }))
        ));
    }

    #[tokio::test]
    async fn closed_session_channel_rolls_back_reserved_bytes() {
        let (mut controller, receiver) = controller();
        assert_eq!(
            controller.inner.reserve_pending_data(4),
            PendingDataReservation::Reserved
        );
        let guard = PendingDataGuard::new(controller.inner.as_ref().clone(), 4);
        drop(receiver);
        assert!(
            !controller
                .send_message(
                    Priority::Normal,
                    1.into(),
                    Bytes::from_static(b"data"),
                    guard,
                )
                .await
        );
        assert_eq!(controller.inner.pending_data_size(), 0);
    }

    #[test]
    fn pending_byte_reservation_rejects_overflow() {
        let (controller, _receiver) = controller();
        controller
            .inner
            .pending_data_size
            .store(usize::MAX, Ordering::Release);
        assert_eq!(
            controller.inner.reserve_pending_data(1),
            PendingDataReservation::LimitReached
        );
        assert_eq!(controller.inner.pending_data_size(), usize::MAX);
    }

    #[tokio::test]
    async fn protocol_sender_reserves_bytes_before_service_queue_admission() {
        let (controller, _session_receiver) = controller();
        let session = controller.inner.clone();
        let (task_sender, mut task_receiver) = mpsc::channel(4);
        let service_context = ServiceContext::new(task_sender, Arc::new(AtomicBool::new(false)));
        let mut protocol_context = ProtocolContext::new(service_context, 1.into());

        protocol_context
            .as_mut(&session)
            .send_message(Bytes::from_static(b"1234"))
            .await
            .unwrap();
        assert_eq!(session.pending_data_size(), 4);
        let (_, queued) = task_receiver.next().await.unwrap();
        assert!(matches!(
            &queued,
            ServiceTask::ProtocolMessage { reservations, .. } if reservations.len() == 1
        ));

        protocol_context
            .as_mut(&session)
            .send_message(Bytes::from_static(b"5"))
            .await
            .unwrap();
        assert!(session.closed());
        assert_eq!(session.pending_data_size(), 4);
        assert!(matches!(
            task_receiver.next().await,
            Some((_, ServiceTask::SessionBlocked { .. }))
        ));
        drop(queued);
        assert_eq!(session.pending_data_size(), 0);
    }

    #[tokio::test]
    async fn cancelling_pending_protocol_send_releases_its_reservation() {
        let (controller, _session_receiver) = controller();
        let session = controller.inner.clone();
        let (task_sender, mut task_receiver) = mpsc::channel(0);
        let service_context = ServiceContext::new(task_sender, Arc::new(AtomicBool::new(false)));
        let mut protocol_context = ProtocolContext::new(service_context, 1.into());

        protocol_context
            .as_mut(&session)
            .send_message(Bytes::from_static(b"12"))
            .await
            .unwrap();
        assert_eq!(session.pending_data_size(), 2);

        let context = protocol_context.as_mut(&session);
        let mut pending_send = Box::pin(context.send_message(Bytes::from_static(b"34")));
        assert!(pending_send.as_mut().now_or_never().is_none());
        assert_eq!(session.pending_data_size(), 4);

        drop(pending_send);
        assert_eq!(session.pending_data_size(), 2);

        let (_, queued) = task_receiver.next().await.unwrap();
        drop(queued);
        assert_eq!(session.pending_data_size(), 0);
    }

    #[tokio::test]
    async fn protocol_sender_rolls_back_when_service_queue_is_closed() {
        let (controller, _session_receiver) = controller();
        let session = controller.inner.clone();
        let (task_sender, task_receiver) = mpsc::channel(1);
        drop(task_receiver);
        let service_context = ServiceContext::new(task_sender, Arc::new(AtomicBool::new(false)));
        let mut protocol_context = ProtocolContext::new(service_context, 1.into());

        assert!(
            protocol_context
                .as_mut(&session)
                .send_message(Bytes::from_static(b"1234"))
                .await
                .is_err()
        );
        assert_eq!(session.pending_data_size(), 0);
    }

    /// Reserved bytes must come back whenever queued data is discarded rather
    /// than written. Without this, a session that closes protocols while data
    /// is queued permanently loses part of its send budget and is eventually
    /// killed even though it is healthy.
    #[test]
    fn dropping_queued_data_returns_reserved_capacity() {
        let (controller, _receiver) = controller();
        let session = controller.inner.clone();

        assert_eq!(
            session.reserve_pending_data(3),
            PendingDataReservation::Reserved
        );
        let guard = PendingDataGuard::new(session.as_ref().clone(), 3);
        assert_eq!(session.pending_data_size(), 3);

        // Simulates every queue between the session and the transport being
        // discarded: substream closed, buffer cleared, channel disconnected.
        drop(guard);
        assert_eq!(session.pending_data_size(), 0);

        // And the freed capacity is immediately reusable.
        assert_eq!(
            session.reserve_pending_data(4),
            PendingDataReservation::Reserved
        );
        assert_eq!(session.pending_data_size(), 4);
    }

    /// Each reservation is released exactly once, so a long-lived session can
    /// keep sending instead of slowly exhausting its own budget.
    #[test]
    fn capacity_is_reusable_across_many_messages() {
        let (controller, _receiver) = controller();
        let session = controller.inner.clone();

        for _ in 0..1000 {
            assert_eq!(
                session.reserve_pending_data(4),
                PendingDataReservation::Reserved
            );
            drop(PendingDataGuard::new(session.as_ref().clone(), 4));
            assert_eq!(session.pending_data_size(), 0);
        }
    }
}
