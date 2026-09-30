use futures::prelude::*;
use nohash_hasher::IntMap;

use std::fmt::Debug;
use std::sync::{Arc, atomic::Ordering};
use std::time::Duration;

use crate::{
    ProtocolId, SessionId,
    channel::mpsc,
    context::{PendingDataGuard, PendingDataReservation, SessionContext},
    error::SendErrorKind,
    lock::RwLock,
    multiaddr::Multiaddr,
    service::{
        TargetProtocol, TargetSession,
        event::{RawSessionInfo, ServiceTask},
    },
};
use bytes::Bytes;
use std::sync::atomic::AtomicBool;

type Result = std::result::Result<(), SendErrorKind>;
type SessionRegistry = Arc<RwLock<IntMap<SessionId, Arc<SessionContext>>>>;

fn resolve_target_sessions(
    sessions: &SessionRegistry,
    target: TargetSession,
) -> Vec<Arc<SessionContext>> {
    match target {
        TargetSession::Single(id) => sessions.read().get(&id).cloned().into_iter().collect(),
        TargetSession::Multi(ids) => {
            let ids: Vec<_> = ids.collect();
            let sessions = sessions.read();
            ids.into_iter()
                .filter_map(|id| sessions.get(&id).cloned())
                .collect()
        }
        TargetSession::Filter(mut filter) => {
            let snapshot: Vec<_> = sessions.read().values().cloned().collect();
            snapshot
                .into_iter()
                .filter(|context| filter(&context.id))
                .collect()
        }
        TargetSession::All => sessions.read().values().cloned().collect(),
    }
}

fn protocol_message_task(
    sessions: &SessionRegistry,
    target: TargetSession,
    proto_id: ProtocolId,
    mut data: Bytes,
) -> Option<ServiceTask> {
    let mut reservations = Vec::new();
    let mut blocked = Vec::new();
    for context in resolve_target_sessions(sessions, target) {
        match context.reserve_pending_data(data.len()) {
            PendingDataReservation::Reserved => {
                reservations.push(PendingDataGuard::new(context.as_ref().clone(), data.len()));
            }
            PendingDataReservation::LimitReached => blocked.push(context.as_ref().clone()),
            PendingDataReservation::Closed => {}
        }
    }
    if reservations.is_empty() {
        // There is no target whose budget accounts for this allocation. A
        // blocked-only task still has to notify the service, but must not keep
        // the caller's payload alive while waiting in the service queue.
        data = Bytes::new();
    }

    if reservations.is_empty() && blocked.is_empty() {
        return None;
    }

    Some(ServiceTask::ProtocolMessage {
        proto_id,
        data,
        reservations,
        blocked,
    })
}

/// Service control, used to send commands externally at runtime
#[derive(Clone)]
pub struct ServiceControl {
    pub(crate) task_sender: mpsc::Sender<ServiceTask>,
    closed: Arc<AtomicBool>,
    sessions: SessionRegistry,
}

impl ServiceControl {
    /// New
    pub(crate) fn new(task_sender: mpsc::Sender<ServiceTask>, closed: Arc<AtomicBool>) -> Self {
        ServiceControl {
            task_sender,
            closed,
            sessions: Arc::new(RwLock::new(IntMap::default())),
        }
    }

    /// Send raw event
    pub(crate) fn send(&self, event: ServiceTask) -> Result {
        if self.closed.load(Ordering::SeqCst) {
            return Err(SendErrorKind::BrokenPipe);
        }
        self.task_sender.try_send(event).map_err(|err| {
            if err.is_full() {
                SendErrorKind::WouldBlock
            } else {
                SendErrorKind::BrokenPipe
            }
        })
    }

    /// Send raw event on quick channel
    #[inline]
    fn quick_send(&self, event: ServiceTask) -> Result {
        if self.closed.load(Ordering::SeqCst) {
            return Err(SendErrorKind::BrokenPipe);
        }
        self.task_sender.try_quick_send(event).map_err(|err| {
            if err.is_full() {
                SendErrorKind::WouldBlock
            } else {
                SendErrorKind::BrokenPipe
            }
        })
    }

    /// Create a new listener
    #[inline]
    pub fn listen(&self, address: Multiaddr) -> Result {
        self.quick_send(ServiceTask::Listen { address })
    }

    /// Initiate a connection request to address
    #[inline]
    pub fn dial(&self, address: Multiaddr, target: TargetProtocol) -> Result {
        self.quick_send(ServiceTask::Dial { address, target })
    }

    /// Receive an established connection session
    /// and build the tentacle protocol on top of it.
    #[inline]
    pub fn raw_session<T>(
        &self,
        raw_session: T,
        remote_address: Multiaddr,
        info: RawSessionInfo,
    ) -> Result
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        self.quick_send(ServiceTask::RawSession {
            raw_session: Box::new(raw_session),
            remote_address,
            session_info: info,
        })
    }

    /// Disconnect a connection
    #[inline]
    pub fn disconnect(&self, session_id: SessionId) -> Result {
        self.quick_send(ServiceTask::Disconnect { session_id })
    }

    /// Send message
    #[inline]
    pub fn send_message_to(
        &self,
        session_id: SessionId,
        proto_id: ProtocolId,
        data: Bytes,
    ) -> Result {
        self.filter_broadcast(TargetSession::Single(session_id), proto_id, data)
    }

    /// Send message on quick channel
    #[inline]
    pub fn quick_send_message_to(
        &self,
        session_id: SessionId,
        proto_id: ProtocolId,
        data: Bytes,
    ) -> Result {
        self.quick_filter_broadcast(TargetSession::Single(session_id), proto_id, data)
    }

    /// Send data to the specified protocol for the specified sessions.
    #[inline]
    pub fn filter_broadcast(
        &self,
        target: TargetSession,
        proto_id: ProtocolId,
        data: Bytes,
    ) -> Result {
        if self.closed.load(Ordering::SeqCst) {
            return Err(SendErrorKind::BrokenPipe);
        }
        match protocol_message_task(&self.sessions, target, proto_id, data) {
            Some(task) => self.send(task),
            None => Ok(()),
        }
    }

    /// Send data to the specified protocol for the specified sessions on quick channel.
    #[inline]
    pub fn quick_filter_broadcast(
        &self,
        target: TargetSession,
        proto_id: ProtocolId,
        data: Bytes,
    ) -> Result {
        if self.closed.load(Ordering::SeqCst) {
            return Err(SendErrorKind::BrokenPipe);
        }
        match protocol_message_task(&self.sessions, target, proto_id, data) {
            Some(task) => self.quick_send(task),
            None => Ok(()),
        }
    }

    /// Send a future task
    #[inline]
    pub fn future_task<T>(&self, task: T) -> Result
    where
        T: Future<Output = ()> + 'static + Send,
    {
        self.send(ServiceTask::FutureTask {
            task: Box::pin(task),
        })
    }

    /// Try open a protocol
    ///
    /// If the protocol has been open, do nothing
    #[inline]
    pub fn open_protocol(&self, session_id: SessionId, proto_id: ProtocolId) -> Result {
        self.quick_send(ServiceTask::ProtocolOpen {
            session_id,
            target: proto_id.into(),
        })
    }

    /// Try open protocol
    ///
    /// If the protocol has been open, do nothing
    #[inline]
    pub fn open_protocols(&self, session_id: SessionId, target: TargetProtocol) -> Result {
        self.quick_send(ServiceTask::ProtocolOpen { session_id, target })
    }

    /// Try close a protocol
    ///
    /// If the protocol has been closed, do nothing
    #[inline]
    pub fn close_protocol(&self, session_id: SessionId, proto_id: ProtocolId) -> Result {
        self.quick_send(ServiceTask::ProtocolClose {
            session_id,
            proto_id,
        })
    }

    /// Set a service notify token
    pub fn set_service_notify(
        &self,
        proto_id: ProtocolId,
        interval: Duration,
        token: u64,
    ) -> Result {
        self.send(ServiceTask::SetProtocolNotify {
            proto_id,
            interval,
            token,
        })
    }

    /// remove a service notify token
    pub fn remove_service_notify(&self, proto_id: ProtocolId, token: u64) -> Result {
        self.send(ServiceTask::RemoveProtocolNotify { proto_id, token })
    }

    /// Set a session notify token
    pub fn set_session_notify(
        &self,
        session_id: SessionId,
        proto_id: ProtocolId,
        interval: Duration,
        token: u64,
    ) -> Result {
        self.send(ServiceTask::SetProtocolSessionNotify {
            session_id,
            proto_id,
            interval,
            token,
        })
    }

    /// Remove a session notify token
    pub fn remove_session_notify(
        &self,
        session_id: SessionId,
        proto_id: ProtocolId,
        token: u64,
    ) -> Result {
        self.send(ServiceTask::RemoveProtocolSessionNotify {
            session_id,
            proto_id,
            token,
        })
    }

    /// Close service
    ///
    /// Order:
    /// 1. close all listens
    /// 2. try close all session's protocol stream
    /// 3. try close all session
    /// 4. close service
    pub fn close(&self) -> Result {
        self.quick_send(ServiceTask::Shutdown(false))
    }

    /// Shutdown service, don't care anything, may cause partial message loss
    pub fn shutdown(&self) -> Result {
        self.quick_send(ServiceTask::Shutdown(true))
    }
}

impl From<ServiceControl> for ServiceAsyncControl {
    fn from(control: ServiceControl) -> Self {
        ServiceAsyncControl {
            task_sender: control.task_sender,
            closed: control.closed,
            sessions: control.sessions,
        }
    }
}

impl From<ServiceAsyncControl> for ServiceControl {
    fn from(control: ServiceAsyncControl) -> Self {
        ServiceControl {
            task_sender: control.task_sender,
            closed: control.closed,
            sessions: control.sessions,
        }
    }
}

impl Debug for ServiceControl {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "ServiceControl")
    }
}

impl Debug for ServiceAsyncControl {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "ServiceAsyncControl")
    }
}

/// Service control, used to send commands externally at runtime, All interfaces are async methods
#[derive(Clone)]
pub struct ServiceAsyncControl {
    task_sender: mpsc::Sender<ServiceTask>,
    closed: Arc<AtomicBool>,
    sessions: SessionRegistry,
}

impl ServiceAsyncControl {
    /// Send raw event
    async fn send(&self, event: ServiceTask) -> Result {
        if self.closed.load(Ordering::SeqCst) {
            return Err(SendErrorKind::BrokenPipe);
        }
        self.task_sender.async_send(event).await.map_err(|_err| {
            // await only return err when channel close
            SendErrorKind::BrokenPipe
        })
    }

    /// Send raw event on quick channel
    #[inline]
    async fn quick_send(&self, event: ServiceTask) -> Result {
        if self.closed.load(Ordering::SeqCst) {
            return Err(SendErrorKind::BrokenPipe);
        }
        self.task_sender
            .async_quick_send(event)
            .await
            .map_err(|_err| {
                // await only return err when channel close
                SendErrorKind::BrokenPipe
            })
    }

    /// Create a new listener
    #[inline]
    pub async fn listen(&self, address: Multiaddr) -> Result {
        self.quick_send(ServiceTask::Listen { address }).await
    }

    /// Initiate a connection request to address
    #[inline]
    pub async fn dial(&self, address: Multiaddr, target: TargetProtocol) -> Result {
        self.quick_send(ServiceTask::Dial { address, target }).await
    }

    /// Receive an established connection session
    /// and build the tentacle protocol on top of it.
    #[inline]
    pub async fn raw_session<T>(
        &self,
        raw_session: T,
        remote_address: Multiaddr,
        info: RawSessionInfo,
    ) -> Result
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        self.quick_send(ServiceTask::RawSession {
            raw_session: Box::new(raw_session),
            remote_address,
            session_info: info,
        })
        .await
    }

    /// Disconnect a connection
    #[inline]
    pub async fn disconnect(&self, session_id: SessionId) -> Result {
        self.quick_send(ServiceTask::Disconnect { session_id })
            .await
    }

    /// Send message
    #[inline]
    pub async fn send_message_to(
        &self,
        session_id: SessionId,
        proto_id: ProtocolId,
        data: Bytes,
    ) -> Result {
        self.filter_broadcast(TargetSession::Single(session_id), proto_id, data)
            .await
    }

    /// Send message on quick channel
    #[inline]
    pub async fn quick_send_message_to(
        &self,
        session_id: SessionId,
        proto_id: ProtocolId,
        data: Bytes,
    ) -> Result {
        self.quick_filter_broadcast(TargetSession::Single(session_id), proto_id, data)
            .await
    }

    /// Send data to the specified protocol for the specified sessions.
    #[inline]
    pub async fn filter_broadcast(
        &self,
        target: TargetSession,
        proto_id: ProtocolId,
        data: Bytes,
    ) -> Result {
        if self.closed.load(Ordering::SeqCst) {
            return Err(SendErrorKind::BrokenPipe);
        }
        match protocol_message_task(&self.sessions, target, proto_id, data) {
            Some(task) => self.send(task).await,
            None => Ok(()),
        }
    }

    /// Send data to the specified protocol for the specified sessions on quick channel.
    #[inline]
    pub async fn quick_filter_broadcast(
        &self,
        target: TargetSession,
        proto_id: ProtocolId,
        data: Bytes,
    ) -> Result {
        if self.closed.load(Ordering::SeqCst) {
            return Err(SendErrorKind::BrokenPipe);
        }
        match protocol_message_task(&self.sessions, target, proto_id, data) {
            Some(task) => self.quick_send(task).await,
            None => Ok(()),
        }
    }

    pub(crate) async fn send_reserved_message_to(
        &self,
        guard: PendingDataGuard,
        proto_id: ProtocolId,
        data: Bytes,
        quick: bool,
    ) -> Result {
        let task = ServiceTask::ProtocolMessage {
            proto_id,
            data,
            reservations: vec![guard],
            blocked: Vec::new(),
        };
        if quick {
            self.quick_send(task).await
        } else {
            self.send(task).await
        }
    }

    pub(crate) async fn report_session_blocked(
        &self,
        session_context: crate::context::SessionContext,
        quick: bool,
    ) -> Result {
        let task = ServiceTask::SessionBlocked { session_context };
        if quick {
            self.quick_send(task).await
        } else {
            self.send(task).await
        }
    }

    pub(crate) fn register_session(&self, context: Arc<SessionContext>) {
        self.sessions.write().insert(context.id, context);
    }

    pub(crate) fn unregister_session(&self, session_id: SessionId) {
        self.sessions.write().remove(&session_id);
    }

    /// Send a future task
    #[inline]
    pub async fn future_task<T>(&self, task: T) -> Result
    where
        T: Future<Output = ()> + 'static + Send,
    {
        self.send(ServiceTask::FutureTask {
            task: Box::pin(task),
        })
        .await
    }

    /// Try open a protocol
    ///
    /// If the protocol has been open, do nothing
    #[inline]
    pub async fn open_protocol(&self, session_id: SessionId, proto_id: ProtocolId) -> Result {
        self.quick_send(ServiceTask::ProtocolOpen {
            session_id,
            target: proto_id.into(),
        })
        .await
    }

    /// Try open protocol
    ///
    /// If the protocol has been open, do nothing
    #[inline]
    pub async fn open_protocols(&self, session_id: SessionId, target: TargetProtocol) -> Result {
        self.quick_send(ServiceTask::ProtocolOpen { session_id, target })
            .await
    }

    /// Try close a protocol
    ///
    /// If the protocol has been closed, do nothing
    #[inline]
    pub async fn close_protocol(&self, session_id: SessionId, proto_id: ProtocolId) -> Result {
        self.quick_send(ServiceTask::ProtocolClose {
            session_id,
            proto_id,
        })
        .await
    }

    /// Set a service notify token
    pub async fn set_service_notify(
        &self,
        proto_id: ProtocolId,
        interval: Duration,
        token: u64,
    ) -> Result {
        self.send(ServiceTask::SetProtocolNotify {
            proto_id,
            interval,
            token,
        })
        .await
    }

    /// remove a service notify token
    pub async fn remove_service_notify(&self, proto_id: ProtocolId, token: u64) -> Result {
        self.send(ServiceTask::RemoveProtocolNotify { proto_id, token })
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
        self.send(ServiceTask::SetProtocolSessionNotify {
            session_id,
            proto_id,
            interval,
            token,
        })
        .await
    }

    /// Remove a session notify token
    pub async fn remove_session_notify(
        &self,
        session_id: SessionId,
        proto_id: ProtocolId,
        token: u64,
    ) -> Result {
        self.send(ServiceTask::RemoveProtocolSessionNotify {
            session_id,
            proto_id,
            token,
        })
        .await
    }

    /// Close service
    ///
    /// Order:
    /// 1. close all listens
    /// 2. try close all session's protocol stream
    /// 3. try close all session
    /// 4. close service
    pub async fn close(&self) -> Result {
        self.quick_send(ServiceTask::Shutdown(false)).await
    }

    /// Shutdown service, don't care anything, may cause partial message loss
    pub async fn shutdown(&self) -> Result {
        self.quick_send(ServiceTask::Shutdown(true)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::SessionType;
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    fn session(id: usize, send_buffer_size: usize) -> Arc<SessionContext> {
        Arc::new(SessionContext::new(
            SessionId::new(id),
            format!("/ip4/127.0.0.1/tcp/{}", id + 1).parse().unwrap(),
            SessionType::Inbound,
            None,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicUsize::new(0)),
            send_buffer_size,
        ))
    }

    #[tokio::test]
    async fn public_broadcast_reserves_each_target_before_queueing() {
        let (task_sender, mut task_receiver) = mpsc::channel(4);
        let control = ServiceControl::new(task_sender, Arc::new(AtomicBool::new(false)));
        let async_control: ServiceAsyncControl = control.clone().into();
        let first = session(1, 4);
        let second = session(2, 4);
        async_control.register_session(first.clone());
        async_control.register_session(second.clone());

        control
            .filter_broadcast(
                TargetSession::All,
                ProtocolId::new(1),
                Bytes::from_static(b"data"),
            )
            .unwrap();

        assert_eq!(first.pending_data_size(), 4);
        assert_eq!(second.pending_data_size(), 4);
        let (_, task) = task_receiver.next().await.unwrap();
        assert!(matches!(
            &task,
            ServiceTask::ProtocolMessage { reservations, .. } if reservations.len() == 2
        ));

        drop(task);
        assert_eq!(first.pending_data_size(), 0);
        assert_eq!(second.pending_data_size(), 0);
    }

    #[tokio::test]
    async fn limit_breach_does_not_queue_an_unreserved_payload() {
        let (task_sender, mut task_receiver) = mpsc::channel(4);
        let control = ServiceControl::new(task_sender, Arc::new(AtomicBool::new(false)));
        let async_control: ServiceAsyncControl = control.clone().into();
        let session = session(1, 4);
        async_control.register_session(session.clone());

        control
            .send_message_to(session.id, ProtocolId::new(1), Bytes::from_static(b"data"))
            .unwrap();
        control
            .send_message_to(
                session.id,
                ProtocolId::new(1),
                Bytes::from_static(b"unreserved"),
            )
            .unwrap();

        assert!(session.closed());
        assert_eq!(session.pending_data_size(), 4);
        let (_, reserved_task) = task_receiver.next().await.unwrap();
        let (_, blocked_task) = task_receiver.next().await.unwrap();
        assert!(matches!(
            &blocked_task,
            ServiceTask::ProtocolMessage {
                data,
                reservations,
                blocked,
                ..
            } if data.is_empty() && reservations.is_empty() && blocked.len() == 1
        ));

        drop(reserved_task);
        drop(blocked_task);
        assert_eq!(session.pending_data_size(), 0);
    }

    #[tokio::test]
    async fn cancelled_public_send_releases_pre_queue_reservations() {
        let (task_sender, mut task_receiver) = mpsc::channel(0);
        let control: ServiceAsyncControl =
            ServiceControl::new(task_sender, Arc::new(AtomicBool::new(false))).into();
        let session = session(1, 4);
        control.register_session(session.clone());

        control
            .send_message_to(session.id, ProtocolId::new(1), Bytes::from_static(b"12"))
            .await
            .unwrap();
        assert_eq!(session.pending_data_size(), 2);

        let mut pending_send = Box::pin(control.send_message_to(
            session.id,
            ProtocolId::new(1),
            Bytes::from_static(b"34"),
        ));
        assert!(pending_send.as_mut().now_or_never().is_none());
        assert_eq!(session.pending_data_size(), 4);

        drop(pending_send);
        assert_eq!(session.pending_data_size(), 2);

        let (_, task) = task_receiver.next().await.unwrap();
        drop(task);
        assert_eq!(session.pending_data_size(), 0);
    }
}
