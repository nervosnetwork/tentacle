use futures::prelude::*;

use std::fmt::Debug;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

use crate::{
    ProtocolId, SessionId,
    channel::mpsc,
    error::SendErrorKind,
    multiaddr::Multiaddr,
    service::{
        TargetProtocol, TargetSession,
        event::{RawSessionInfo, ServiceTask},
    },
};
use bytes::Bytes;

type Result = std::result::Result<(), SendErrorKind>;

#[derive(Clone)]
pub(crate) struct ServiceTaskBudget {
    limit: usize,
    queued: Arc<AtomicUsize>,
}

impl ServiceTaskBudget {
    pub(crate) fn new(limit: usize) -> Self {
        ServiceTaskBudget {
            limit,
            queued: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn acquire(&self) -> Result {
        let mut current = self.queued.load(Ordering::Acquire);
        loop {
            if current >= self.limit {
                return Err(SendErrorKind::WouldBlock);
            }
            match self.queued.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => current = actual,
            }
        }
    }

    pub(crate) fn release(&self) {
        self.queued.fetch_sub(1, Ordering::AcqRel);
    }
}

fn acquire_task_budget(
    event: &ServiceTask,
    budget: &ServiceTaskBudget,
) -> std::result::Result<bool, SendErrorKind> {
    if event.counts_against_budget() {
        budget.acquire()?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Service control, used to send commands externally at runtime
#[derive(Clone)]
pub struct ServiceControl {
    pub(crate) task_sender: mpsc::Sender<ServiceTask>,
    closed: Arc<AtomicBool>,
    task_budget: ServiceTaskBudget,
}

impl ServiceControl {
    /// New
    pub(crate) fn new(
        task_sender: mpsc::Sender<ServiceTask>,
        closed: Arc<AtomicBool>,
        task_budget: ServiceTaskBudget,
    ) -> Self {
        ServiceControl {
            task_sender,
            closed,
            task_budget,
        }
    }

    /// Send raw event
    pub(crate) fn send(&self, event: ServiceTask) -> Result {
        if self.closed.load(Ordering::SeqCst) {
            return Err(SendErrorKind::BrokenPipe);
        }
        let acquired_budget = acquire_task_budget(&event, &self.task_budget)?;
        self.task_sender.try_send(event).map_err(|err| {
            if acquired_budget {
                self.task_budget.release();
            }
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
        let acquired_budget = acquire_task_budget(&event, &self.task_budget)?;
        self.task_sender.try_quick_send(event).map_err(|err| {
            if acquired_budget {
                self.task_budget.release();
            }
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
        self.send(ServiceTask::ProtocolMessage {
            target,
            proto_id,
            data,
        })
    }

    /// Send data to the specified protocol for the specified sessions on quick channel.
    #[inline]
    pub fn quick_filter_broadcast(
        &self,
        target: TargetSession,
        proto_id: ProtocolId,
        data: Bytes,
    ) -> Result {
        self.quick_send(ServiceTask::ProtocolMessage {
            target,
            proto_id,
            data,
        })
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
            task_budget: control.task_budget,
        }
    }
}

impl From<ServiceAsyncControl> for ServiceControl {
    fn from(control: ServiceAsyncControl) -> Self {
        ServiceControl {
            task_sender: control.task_sender,
            closed: control.closed,
            task_budget: control.task_budget,
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
    task_budget: ServiceTaskBudget,
}

impl ServiceAsyncControl {
    /// Send raw event
    async fn send(&self, event: ServiceTask) -> Result {
        if self.closed.load(Ordering::SeqCst) {
            return Err(SendErrorKind::BrokenPipe);
        }
        let acquired_budget = acquire_task_budget(&event, &self.task_budget)?;
        self.task_sender.async_send(event).await.map_err(|_err| {
            if acquired_budget {
                self.task_budget.release();
            }
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
        let acquired_budget = acquire_task_budget(&event, &self.task_budget)?;
        self.task_sender
            .async_quick_send(event)
            .await
            .map_err(|_err| {
                if acquired_budget {
                    self.task_budget.release();
                }
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
        self.send(ServiceTask::ProtocolMessage {
            target,
            proto_id,
            data,
        })
        .await
    }

    /// Send data to the specified protocol for the specified sessions on quick channel.
    #[inline]
    pub async fn quick_filter_broadcast(
        &self,
        target: TargetSession,
        proto_id: ProtocolId,
        data: Bytes,
    ) -> Result {
        self.quick_send(ServiceTask::ProtocolMessage {
            target,
            proto_id,
            data,
        })
        .await
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
    use crate::channel::mpsc as priority_mpsc;

    /// Build a control plus its keep-alive receiver. The receiver must be kept
    /// in scope by the caller; dropping it would close the channel and turn
    /// every subsequent send into a `BrokenPipe` error.
    fn make_control(
        channel_buf: usize,
        budget_limit: usize,
    ) -> (
        ServiceControl,
        ServiceTaskBudget,
        priority_mpsc::Receiver<ServiceTask>,
    ) {
        let (sender, receiver) = priority_mpsc::channel(channel_buf);
        let budget = ServiceTaskBudget::new(budget_limit);
        let control = ServiceControl::new(sender, Arc::new(AtomicBool::new(false)), budget.clone());
        (control, budget, receiver)
    }

    fn protocol_msg() -> ServiceTask {
        ServiceTask::ProtocolMessage {
            target: TargetSession::All,
            proto_id: 1.into(),
            data: Bytes::new(),
        }
    }

    #[test]
    fn service_task_budget_is_shared_by_control_clones() {
        // Channel must have enough capacity to admit the budget'd ProtocolMessage
        // plus the un-counted Shutdown task. With buffer=1 and 1 base sender + 1
        // clone, the channel capacity is buffer + num_senders = 3, which is enough.
        let (control, budget, _receiver) = make_control(1, 1);
        let cloned = control.clone();

        assert!(
            control
                .filter_broadcast(TargetSession::All, 1.into(), Bytes::new())
                .is_ok()
        );
        // close() sends Shutdown, which is NOT counted against the budget but
        // still occupies a channel slot.
        assert!(control.close().is_ok());
        assert!(matches!(
            cloned.filter_broadcast(TargetSession::All, 1.into(), Bytes::new()),
            Err(SendErrorKind::WouldBlock)
        ));

        budget.release();
        assert!(
            cloned
                .filter_broadcast(TargetSession::All, 1.into(), Bytes::new())
                .is_ok()
        );
    }

    /// `counts_against_budget()` must only return `true` for the resource-
    /// heavy task variants. Adding new variants in the future without
    /// updating this mapping would be a silent regression of the fix.
    /// (`RawSession` is omitted because it requires a real `AsyncRw`.)
    #[test]
    fn counts_against_budget_classification() {
        assert!(protocol_msg().counts_against_budget());
        assert!(
            ServiceTask::FutureTask {
                task: Box::pin(async {}),
            }
            .counts_against_budget()
        );

        // None of the control-plane / lifecycle variants should be metered.
        let non_counted: Vec<ServiceTask> = vec![
            ServiceTask::ProtocolOpen {
                session_id: 1.into(),
                target: TargetProtocol::Single(1.into()),
            },
            ServiceTask::ProtocolClose {
                session_id: 1.into(),
                proto_id: 1.into(),
            },
            ServiceTask::SetProtocolNotify {
                proto_id: 1.into(),
                interval: Duration::from_secs(1),
                token: 0,
            },
            ServiceTask::RemoveProtocolNotify {
                proto_id: 1.into(),
                token: 0,
            },
            ServiceTask::SetProtocolSessionNotify {
                session_id: 1.into(),
                proto_id: 1.into(),
                interval: Duration::from_secs(1),
                token: 0,
            },
            ServiceTask::RemoveProtocolSessionNotify {
                session_id: 1.into(),
                proto_id: 1.into(),
                token: 0,
            },
            ServiceTask::Disconnect {
                session_id: 1.into(),
            },
            ServiceTask::Dial {
                address: "/ip4/127.0.0.1/tcp/1".parse().unwrap(),
                target: TargetProtocol::All,
            },
            ServiceTask::Listen {
                address: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            },
            ServiceTask::Shutdown(false),
            ServiceTask::Shutdown(true),
        ];
        for task in non_counted {
            assert!(
                !task.counts_against_budget(),
                "task should not be counted: {:?}",
                task
            );
        }
    }

    /// Non-counted control tasks must not consume budget even when the
    /// budget is already saturated. This guards against control-plane
    /// starvation.
    #[test]
    fn non_counted_tasks_bypass_budget_even_when_full() {
        let (control, _budget, _receiver) = make_control(8, 1);

        // Exhaust the budget with a counted task.
        assert!(
            control
                .filter_broadcast(TargetSession::All, 1.into(), Bytes::new())
                .is_ok()
        );
        assert!(matches!(
            control.filter_broadcast(TargetSession::All, 1.into(), Bytes::new()),
            Err(SendErrorKind::WouldBlock)
        ));

        // Control-plane tasks must still go through.
        assert!(control.open_protocol(1.into(), 1.into()).is_ok());
        assert!(control.close_protocol(1.into(), 1.into()).is_ok());
        assert!(control.disconnect(1.into()).is_ok());
        assert!(
            control
                .set_service_notify(1.into(), Duration::from_secs(1), 0)
                .is_ok()
        );
        assert!(control.close().is_ok());
    }

    /// When the underlying channel rejects a send (e.g. because the per-sender
    /// guaranteed slot is already in use), the optimistically-acquired budget
    /// slot must be released so it doesn't leak.
    #[test]
    fn budget_is_released_when_underlying_channel_send_fails() {
        // buffer=0 + 1 sender => channel capacity = 1.
        let (sender, _receiver) = priority_mpsc::channel(0);
        let budget = ServiceTaskBudget::new(8);
        let control = ServiceControl::new(sender, Arc::new(AtomicBool::new(false)), budget.clone());

        // First send fills the single channel slot.
        assert!(
            control
                .filter_broadcast(TargetSession::All, 1.into(), Bytes::new())
                .is_ok()
        );
        assert_eq!(budget.queued.load(Ordering::Acquire), 1);

        // Channel is now full for this sender => try_send returns Full.
        // The wrapper must translate to WouldBlock AND release the budget.
        assert!(matches!(
            control.filter_broadcast(TargetSession::All, 1.into(), Bytes::new()),
            Err(SendErrorKind::WouldBlock)
        ));
        assert_eq!(
            budget.queued.load(Ordering::Acquire),
            1,
            "failed send must not retain its optimistic budget slot",
        );
    }

    /// When the service is already closed, the budget must not be acquired at
    /// all. Otherwise repeated post-close sends would slowly inflate the
    /// counter.
    #[test]
    fn closed_service_does_not_acquire_budget() {
        let (sender, _receiver) = priority_mpsc::channel(8);
        let budget = ServiceTaskBudget::new(4);
        let closed = Arc::new(AtomicBool::new(true));
        let control = ServiceControl::new(sender, closed, budget.clone());

        for _ in 0..16 {
            assert!(matches!(
                control.filter_broadcast(TargetSession::All, 1.into(), Bytes::new()),
                Err(SendErrorKind::BrokenPipe)
            ));
        }
        assert_eq!(budget.queued.load(Ordering::Acquire), 0);
    }

    /// Directly models the finding's attack scenario: many cloned
    /// `ServiceControl` senders (mimicking per-session `ServiceContext`
    /// clones) must NOT be able to enqueue more counted tasks than the
    /// budget limit, regardless of how many clones exist.
    #[test]
    fn many_clones_cannot_exceed_budget_limit() {
        const LIMIT: usize = 4;
        const CLONES: usize = 64;
        // Channel large enough that channel capacity is not the limiting factor.
        let (sender, _receiver) = priority_mpsc::channel(1024);
        let budget = ServiceTaskBudget::new(LIMIT);
        let control = ServiceControl::new(sender, Arc::new(AtomicBool::new(false)), budget.clone());

        let clones: Vec<_> = (0..CLONES).map(|_| control.clone()).collect();

        let mut accepted = 0usize;
        // Each clone tries to push 2 tasks; total attempts = 128 >> LIMIT.
        for c in &clones {
            for _ in 0..2 {
                if c.filter_broadcast(TargetSession::All, 1.into(), Bytes::new())
                    .is_ok()
                {
                    accepted += 1;
                }
            }
        }

        assert_eq!(
            accepted, LIMIT,
            "budget must cap aggregate counted-task admission to LIMIT regardless of sender clones",
        );
        assert_eq!(budget.queued.load(Ordering::Acquire), LIMIT);
    }

    /// Simulates the service loop's behaviour: dequeueing a counted task must
    /// release its budget slot so further sends can succeed.
    #[test]
    fn service_loop_dequeue_release_pattern_frees_budget() {
        let (sender, mut receiver) = priority_mpsc::channel(8);
        let budget = ServiceTaskBudget::new(2);
        let control = ServiceControl::new(sender, Arc::new(AtomicBool::new(false)), budget.clone());

        // Fill the budget.
        assert!(
            control
                .filter_broadcast(TargetSession::All, 1.into(), Bytes::new())
                .is_ok()
        );
        assert!(
            control
                .filter_broadcast(TargetSession::All, 1.into(), Bytes::new())
                .is_ok()
        );
        assert!(matches!(
            control.filter_broadcast(TargetSession::All, 1.into(), Bytes::new()),
            Err(SendErrorKind::WouldBlock)
        ));

        // Simulate one service-loop iteration: pull a task and release if it
        // counts against the budget (mirrors service.rs:1829-1833).
        let (_priority, task) = receiver.try_next().expect("queued task").expect("some task");
        assert!(task.counts_against_budget());
        budget.release();

        // The freshly-released slot must let the next send succeed.
        assert!(
            control
                .filter_broadcast(TargetSession::All, 1.into(), Bytes::new())
                .is_ok()
        );
    }

    /// `ServiceControl` <-> `ServiceAsyncControl` conversions must preserve
    /// the shared `Arc<AtomicUsize>` counter so async paths are also covered.
    #[test]
    fn async_control_conversion_preserves_shared_budget() {
        let (control, budget, _receiver) = make_control(8, 1);
        let async_control: ServiceAsyncControl = control.clone().into();

        // Saturate via the sync control.
        assert!(
            control
                .filter_broadcast(TargetSession::All, 1.into(), Bytes::new())
                .is_ok()
        );

        // The async control's acquire path must also see the saturated budget.
        let evt = protocol_msg();
        assert!(matches!(
            acquire_task_budget(&evt, &async_control.task_budget),
            Err(SendErrorKind::WouldBlock)
        ));

        budget.release();
        assert!(acquire_task_budget(&evt, &async_control.task_budget).is_ok());
    }

    /// Direct unit tests on `ServiceTaskBudget` boundary behaviour.
    #[test]
    fn budget_acquire_release_boundaries() {
        let b = ServiceTaskBudget::new(3);
        assert!(b.acquire().is_ok());
        assert!(b.acquire().is_ok());
        assert!(b.acquire().is_ok());
        assert!(matches!(b.acquire(), Err(SendErrorKind::WouldBlock)));
        b.release();
        assert!(b.acquire().is_ok());
        // Drain.
        b.release();
        b.release();
        b.release();
        assert_eq!(b.queued.load(Ordering::Acquire), 0);
    }

    /// A zero-limit budget should reject every counted task while still letting
    /// non-counted control tasks pass through.
    #[test]
    fn zero_limit_budget_blocks_counted_admits_non_counted() {
        let (sender, _receiver) = priority_mpsc::channel(8);
        let budget = ServiceTaskBudget::new(0);
        let control = ServiceControl::new(sender, Arc::new(AtomicBool::new(false)), budget);

        assert!(matches!(
            control.filter_broadcast(TargetSession::All, 1.into(), Bytes::new()),
            Err(SendErrorKind::WouldBlock)
        ));
        assert!(control.open_protocol(1.into(), 1.into()).is_ok());
    }
}
