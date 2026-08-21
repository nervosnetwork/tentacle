//! Regression test for the "empty yamux session can persist indefinitely"
//! security fix.
//!
//! Scenario reproduced by this test:
//!   1. A peer connects and negotiates a protocol.
//!   2. The peer keeps the protocol substream open past the session `timeout`
//!      so the initial one-shot timeout check fires while a substream still
//!      exists (the pre-fix code path that leaked idle sessions).
//!   3. The peer then closes the last protocol substream while keeping the
//!      underlying transport alive.
//!   4. The fixed code re-arms the session timeout the moment `substreams`
//!      becomes empty. After another `timeout` interval the session must be
//!      reaped, emitting `ServiceError::SessionTimeout` and then closing the
//!      session cleanly.
//!
//! Without the fix, step 3 would leave the session/yamux/TCP connection
//! alive indefinitely and neither `SessionTimeout` nor `SessionClose` would
//! be observed after the last protocol was closed.

use futures::channel;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tentacle::{
    ProtocolId, async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContextMutRef, ServiceContext},
    multiaddr::Multiaddr,
    secio::SecioKeyPair,
    service::{ProtocolHandle, ProtocolMeta, Service, ServiceError, ServiceEvent, TargetProtocol},
    traits::{ServiceHandle, SessionProtocol},
};

const SESSION_TIMEOUT: Duration = Duration::from_secs(2);
/// Wait strictly longer than SESSION_TIMEOUT before closing the protocol so
/// that the initial (session-open) timeout check has already been consumed
/// while `substreams` was non-empty — this is exactly the pre-fix leak
/// scenario.
const CLOSE_AFTER: Duration = Duration::from_millis(2500);

fn create<F>(secio: bool, meta: ProtocolMeta, shandle: F) -> Service<F, SecioKeyPair>
where
    F: ServiceHandle + Unpin + 'static,
{
    let builder = ServiceBuilder::default()
        .insert_protocol(meta)
        .forever(true)
        .timeout(SESSION_TIMEOUT);

    if secio {
        builder
            .handshake_type(SecioKeyPair::secp256k1_generated().into())
            .build(shandle)
    } else {
        builder.build(shandle)
    }
}

/// Client-side protocol handler: after `connected`, arms a one-shot notify
/// that will close the protocol substream once the initial session timeout
/// window has already elapsed.
struct ClientProto;

#[async_trait]
impl SessionProtocol for ClientProto {
    async fn connected(&mut self, context: ProtocolContextMutRef<'_>, _version: &str) {
        // Schedule a single notify that fires after the initial session-open
        // timeout has been consumed.
        context
            .set_session_notify(context.session.id, context.proto_id, CLOSE_AFTER, 1)
            .await
            .ok();
    }

    async fn notify(&mut self, context: ProtocolContextMutRef<'_>, token: u64) {
        if token == 1 {
            // Close the last (and only) protocol substream while keeping the
            // TCP/yamux transport open. In the pre-fix code this leaves an
            // idle protocol-less session alive forever.
            context
                .close_protocol(context.session.id, context.proto_id)
                .await
                .ok();
        }
    }
}

/// Server-side `ServiceHandle`: observes `ServiceError::SessionTimeout` and
/// `ServiceEvent::SessionClose` and forwards the observation on a channel.
#[derive(Clone)]
struct ServerHandle {
    saw_session_timeout: Arc<AtomicBool>,
    close_sender: crossbeam_channel::Sender<()>,
}

#[async_trait]
impl ServiceHandle for ServerHandle {
    async fn handle_error(&mut self, _control: &mut ServiceContext, error: ServiceError) {
        if let ServiceError::SessionTimeout { .. } = error {
            self.saw_session_timeout.store(true, Ordering::SeqCst);
        }
    }

    async fn handle_event(&mut self, _control: &mut ServiceContext, event: ServiceEvent) {
        if let ServiceEvent::SessionClose { .. } = event {
            self.close_sender.try_send(()).ok();
        }
    }
}

fn create_meta(id: ProtocolId, client: bool) -> ProtocolMeta {
    if client {
        MetaBuilder::new()
            .id(id)
            .session_handle(move || ProtocolHandle::Callback(Box::new(ClientProto)))
            .build()
    } else {
        // The server-side protocol does nothing on its own; the client
        // drives open/close so the server must reap the idle session
        // via the re-armed timeout.
        MetaBuilder::new().id(id).build()
    }
}

fn test_idle_session_reaped_after_last_protocol_close(secio: bool) {
    let saw_session_timeout = Arc::new(AtomicBool::new(false));
    let (close_sender, close_receiver) = crossbeam_channel::unbounded();
    let (addr_sender, addr_receiver) = channel::oneshot::channel::<Multiaddr>();

    // --- server -------------------------------------------------------------
    let server_handle = ServerHandle {
        saw_session_timeout: saw_session_timeout.clone(),
        close_sender,
    };
    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create(secio, create_meta(1.into(), false), server_handle);
        rt.block_on(async move {
            let listen_addr = service
                .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .await
                .unwrap();
            addr_sender.send(listen_addr).ok();
            service.run().await;
        });
    });

    // --- client -------------------------------------------------------------
    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create(secio, create_meta(1.into(), true), ());
        rt.block_on(async move {
            let listen_addr = addr_receiver.await.unwrap();
            service
                .dial(listen_addr, TargetProtocol::All)
                .await
                .unwrap();
            service.run().await;
        });
    });

    // The full sequence is:
    //   - open protocol
    //   - wait CLOSE_AFTER (> SESSION_TIMEOUT) — during this window the
    //     initial one-shot timer fires but is a no-op because substreams != 0
    //   - client closes protocol → substreams becomes empty → new timer armed
    //   - after another SESSION_TIMEOUT the server observes SessionTimeout
    //     and then SessionClose.
    let overall_budget = CLOSE_AFTER + SESSION_TIMEOUT + Duration::from_secs(5);
    let deadline = Instant::now() + overall_budget;

    let mut got_close = false;
    while Instant::now() < deadline {
        if close_receiver
            .recv_timeout(Duration::from_millis(200))
            .is_ok()
        {
            got_close = true;
            break;
        }
    }

    assert!(
        saw_session_timeout.load(Ordering::SeqCst),
        "server never observed ServiceError::SessionTimeout after the last protocol was closed; \
         idle session was leaked"
    );
    assert!(
        got_close,
        "server never observed ServiceEvent::SessionClose after the idle timeout; \
         idle session was leaked"
    );
}

#[test]
fn test_idle_session_reaped_after_last_protocol_close_with_secio() {
    test_idle_session_reaped_after_last_protocol_close(true);
}

#[test]
fn test_idle_session_reaped_after_last_protocol_close_with_no_secio() {
    test_idle_session_reaped_after_last_protocol_close(false);
}
