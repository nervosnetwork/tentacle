//! QUIC end-to-end integration tests.
//!
//! These tests build full `Service` instances with the QUIC transport
//! enabled (via `ServiceBuilder::quic_config`) and verify that:
//!
//! 1. two peers can complete a QUIC handshake, open a protocol, and
//!    exchange messages bidirectionally;
//! 2. multiple protocols can be multiplexed over a single QUIC session
//!    without crosstalk;
//! 3. an outbound shutdown propagates to the peer's `disconnected`
//!    callback;
//! 4. dialing with a mismatched `/p2p/<peer_id>` is rejected at
//!    handshake time;
//! 5. enabling QUIC does not regress the classic TCP path — a
//!    QUIC-enabled service still routes plain `/tcp/` addresses through
//!    the secio + yamux pipeline and can dial / listen on TCP normally;
//! 6. a `HandshakeType::Secio` service that did **not** call
//!    `quic_config(...)` dialing a `/quic-v1` address surfaces
//!    `QuicError(NotConfigured)` — a precise, actionable hint instead
//!    of the generic `NotSupported`.
//!
//! Each test runs the server and client on dedicated tokio runtimes in
//! their own threads, communicating over crossbeam / oneshot channels.

#![cfg(feature = "quic")]

use bytes::Bytes;
use futures::channel::oneshot;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};
use tentacle::{
    ProtocolId, async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef, ServiceContext},
    error::TransportErrorKind,
    multiaddr::Multiaddr,
    quic::config::QuicConfig,
    secio::SecioKeyPair,
    service::{ProtocolHandle, ProtocolMeta, Service, ServiceError, ServiceEvent, TargetProtocol},
    traits::{ServiceHandle, ServiceProtocol},
};

// ────────────────────────────── service helpers ──────────────────────────────

fn build_service<F>(
    key: SecioKeyPair,
    metas: Vec<ProtocolMeta>,
    handle: F,
    enable_quic: bool,
) -> Service<F, SecioKeyPair>
where
    F: ServiceHandle + Unpin + 'static,
{
    let mut builder = ServiceBuilder::default().forever(true);
    for meta in metas {
        builder = builder.insert_protocol(meta);
    }
    builder = builder.handshake_type(key.into());
    if enable_quic {
        builder = builder.quic_config(QuicConfig::default());
    }
    builder.build(handle)
}

// ─────────────────────────────── protocol handles ───────────────────────────────

struct EchoCounter {
    sender: crossbeam_channel::Sender<(ProtocolId, Bytes)>,
    target: usize,
    seen: usize,
}

#[async_trait]
impl ServiceProtocol for EchoCounter {
    async fn init(&mut self, _context: &mut ProtocolContext) {}

    async fn connected(&mut self, context: ProtocolContextMutRef<'_>, _version: &str) {
        if context.session.ty.is_outbound() {
            // Outbound side starts the conversation.
            let _ignore = context.send_message(Bytes::from_static(b"ping-0")).await;
        }
    }

    async fn received(&mut self, context: ProtocolContextMutRef<'_>, data: Bytes) {
        if let Err(_) = self.sender.try_send((context.proto_id, data.clone())) {
            return;
        }
        self.seen += 1;
        if self.seen >= self.target {
            return;
        }
        // Server echoes back; client also echoes a few times to drive a
        // continuous exchange.
        let _ignore = context.send_message(data).await;
    }
}

fn make_echo_meta(
    id: ProtocolId,
    target: usize,
) -> (
    ProtocolMeta,
    crossbeam_channel::Receiver<(ProtocolId, Bytes)>,
) {
    let (sender, receiver) = crossbeam_channel::unbounded();
    let meta = MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            let handle = Box::new(EchoCounter {
                sender: sender.clone(),
                target,
                seen: 0,
            });
            ProtocolHandle::Callback(handle)
        })
        .build();
    (meta, receiver)
}

struct DisconnectTracker {
    connect_count: Arc<AtomicUsize>,
    disconnect_count: Arc<AtomicUsize>,
    notify: oneshot::Sender<()>,
}

impl DisconnectTracker {
    fn into_meta(self, id: ProtocolId) -> ProtocolMeta {
        let connect = self.connect_count.clone();
        let disconnect = self.disconnect_count.clone();
        let notify = std::sync::Mutex::new(Some(self.notify));
        MetaBuilder::new()
            .id(id)
            .service_handle(move || {
                let handle = Box::new(DisconnectInner {
                    connect_count: connect.clone(),
                    disconnect_count: disconnect.clone(),
                    notify_tx: notify.lock().unwrap().take(),
                });
                ProtocolHandle::Callback(handle)
            })
            .build()
    }
}

struct DisconnectInner {
    connect_count: Arc<AtomicUsize>,
    disconnect_count: Arc<AtomicUsize>,
    notify_tx: Option<oneshot::Sender<()>>,
}

#[async_trait]
impl ServiceProtocol for DisconnectInner {
    async fn init(&mut self, _context: &mut ProtocolContext) {}

    async fn connected(&mut self, _context: ProtocolContextMutRef<'_>, _version: &str) {
        self.connect_count.fetch_add(1, Ordering::SeqCst);
    }

    async fn disconnected(&mut self, _context: ProtocolContextMutRef<'_>) {
        self.disconnect_count.fetch_add(1, Ordering::SeqCst);
        if let Some(tx) = self.notify_tx.take() {
            let _ignore = tx.send(());
        }
    }
}

#[derive(Default)]
struct CollectingHandle {
    errors: Arc<std::sync::Mutex<Vec<String>>>,
}

#[async_trait]
impl ServiceHandle for CollectingHandle {
    async fn handle_error(&mut self, _env: &mut ServiceContext, error: ServiceError) {
        let summary = format!("{:?}", error);
        self.errors.lock().unwrap().push(summary);
    }

    async fn handle_event(&mut self, _env: &mut ServiceContext, _event: ServiceEvent) {}
}

// ───────────────────────────── basic connectivity ─────────────────────────────

/// Test 1: two QUIC services exchange messages over a single protocol.
#[test]
fn test_quic_basic_connectivity() {
    check_quic_basic_connectivity(false);
}

#[test]
fn test_quic_control_listen_connectivity() {
    check_quic_basic_connectivity(true);
}

struct ListenAddressSender(Option<oneshot::Sender<Multiaddr>>);

#[async_trait]
impl ServiceHandle for ListenAddressSender {
    async fn handle_error(&mut self, _context: &mut ServiceContext, error: ServiceError) {
        panic!("unexpected server error: {:?}", error);
    }

    async fn handle_event(&mut self, _context: &mut ServiceContext, event: ServiceEvent) {
        if let ServiceEvent::ListenStarted { address } = event
            && let Some(sender) = self.0.take()
        {
            let _ignore = sender.send(address);
        }
    }
}

fn check_quic_basic_connectivity(via_control: bool) {
    let (server_meta, server_rx) = make_echo_meta(1.into(), 50);
    let (client_meta, client_rx) = make_echo_meta(1.into(), 50);

    let server_key = SecioKeyPair::secp256k1_generated();
    let server_pid = server_key.peer_id();

    let (addr_tx, addr_rx) = oneshot::channel::<Multiaddr>();

    let _server = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = build_service(
            server_key,
            vec![server_meta],
            ListenAddressSender(Some(addr_tx)),
            true,
        );
        rt.block_on(async move {
            let address = "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap();
            if via_control {
                service
                    .control()
                    .listen(address)
                    .await
                    .expect("control listen");
            } else {
                service.listen(address).await.expect("server listen");
            }
            service.run().await
        });
    });

    let _client = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = build_service(
            SecioKeyPair::secp256k1_generated(),
            vec![client_meta],
            (),
            true,
        );
        rt.block_on(async move {
            let listen_addr = addr_rx.await.unwrap();
            let dial: Multiaddr = format!("{}/p2p/{}", listen_addr, server_pid.to_base58())
                .parse()
                .unwrap();
            service.dial(dial, TargetProtocol::All).await.expect("dial");
            service.run().await
        });
    });

    // Wait for both sides to observe at least 10 messages each. The
    // continuous ping/pong drives more than that quickly.
    let collect = |rx: &crossbeam_channel::Receiver<(ProtocolId, Bytes)>, n: usize| {
        let mut got = 0;
        while got < n {
            match rx.recv_timeout(Duration::from_secs(15)) {
                Ok(_) => got += 1,
                Err(_) => break,
            }
        }
        got
    };

    assert!(
        collect(&server_rx, 10) >= 10,
        "server should receive at least 10 messages over quic"
    );
    assert!(
        collect(&client_rx, 10) >= 10,
        "client should receive at least 10 messages over quic"
    );
}

// ────────────────────────────── multi-protocol ──────────────────────────────

/// Test 2: open three protocols on a single QUIC session, exchange
/// messages on each, and assert no crosstalk (each receiver only sees
/// messages tagged with its own protocol id).
#[test]
fn test_quic_multi_protocol() {
    let (s0, s0_rx) = make_echo_meta(0.into(), 30);
    let (s1, s1_rx) = make_echo_meta(1.into(), 30);
    let (s2, s2_rx) = make_echo_meta(2.into(), 30);
    let (c0, c0_rx) = make_echo_meta(0.into(), 30);
    let (c1, c1_rx) = make_echo_meta(1.into(), 30);
    let (c2, c2_rx) = make_echo_meta(2.into(), 30);

    let server_key = SecioKeyPair::secp256k1_generated();
    let server_pid = server_key.peer_id();
    let (addr_tx, addr_rx) = oneshot::channel::<Multiaddr>();

    let _server = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = build_service(server_key, vec![s0, s1, s2], (), true);
        rt.block_on(async move {
            let listen = service
                .listen("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
                .await
                .expect("server listen");
            let _ignore = addr_tx.send(listen);
            service.run().await
        });
    });

    let _client = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = build_service(
            SecioKeyPair::secp256k1_generated(),
            vec![c0, c1, c2],
            (),
            true,
        );
        rt.block_on(async move {
            let listen_addr = addr_rx.await.unwrap();
            let dial: Multiaddr = format!("{}/p2p/{}", listen_addr, server_pid.to_base58())
                .parse()
                .unwrap();
            service.dial(dial, TargetProtocol::All).await.expect("dial");
            service.run().await
        });
    });

    let collect_for = |rx: &crossbeam_channel::Receiver<(ProtocolId, Bytes)>,
                       expected_id: ProtocolId,
                       n: usize| {
        let mut got = 0;
        while got < n {
            match rx.recv_timeout(Duration::from_secs(15)) {
                Ok((pid, _)) => {
                    assert_eq!(pid, expected_id, "crosstalk between protocols");
                    got += 1;
                }
                Err(_) => break,
            }
        }
        got
    };

    assert!(collect_for(&s0_rx, 0.into(), 5) >= 5);
    assert!(collect_for(&s1_rx, 1.into(), 5) >= 5);
    assert!(collect_for(&s2_rx, 2.into(), 5) >= 5);
    assert!(collect_for(&c0_rx, 0.into(), 5) >= 5);
    assert!(collect_for(&c1_rx, 1.into(), 5) >= 5);
    assert!(collect_for(&c2_rx, 2.into(), 5) >= 5);
}

// ─────────────────────────────── graceful close ───────────────────────────────

/// Test 3: client `disconnect`s its session, and the server's
/// `disconnected` callback fires.
#[test]
fn test_quic_graceful_close() {
    let server_disconnect_count = Arc::new(AtomicUsize::new(0));
    let server_connect_count = Arc::new(AtomicUsize::new(0));
    let (server_done_tx, server_done_rx) = oneshot::channel::<()>();
    let server_meta = DisconnectTracker {
        connect_count: server_connect_count.clone(),
        disconnect_count: server_disconnect_count.clone(),
        notify: server_done_tx,
    }
    .into_meta(1.into());

    // Client just connects, then disconnects after `connected`.
    struct ClientCloser;
    #[async_trait]
    impl ServiceProtocol for ClientCloser {
        async fn init(&mut self, _context: &mut ProtocolContext) {}
        async fn connected(&mut self, context: ProtocolContextMutRef<'_>, _version: &str) {
            let _ignore = context.disconnect(context.session.id).await;
        }
    }
    let client_meta = MetaBuilder::new()
        .id(1.into())
        .service_handle(|| ProtocolHandle::Callback(Box::new(ClientCloser)))
        .build();

    let server_key = SecioKeyPair::secp256k1_generated();
    let server_pid = server_key.peer_id();
    let (addr_tx, addr_rx) = oneshot::channel::<Multiaddr>();

    let _server = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = build_service(server_key, vec![server_meta], (), true);
        rt.block_on(async move {
            let listen = service
                .listen("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
                .await
                .expect("server listen");
            let _ignore = addr_tx.send(listen);
            service.run().await
        });
    });

    let _client = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = build_service(
            SecioKeyPair::secp256k1_generated(),
            vec![client_meta],
            (),
            true,
        );
        rt.block_on(async move {
            let listen_addr = addr_rx.await.unwrap();
            let dial: Multiaddr = format!("{}/p2p/{}", listen_addr, server_pid.to_base58())
                .parse()
                .unwrap();
            service.dial(dial, TargetProtocol::All).await.expect("dial");
            service.run().await
        });
    });

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        let _ignore = tokio::time::timeout(Duration::from_secs(15), server_done_rx).await;
    });

    assert!(
        server_connect_count.load(Ordering::SeqCst) >= 1,
        "server must have observed connected"
    );
    assert!(
        server_disconnect_count.load(Ordering::SeqCst) >= 1,
        "server must have observed disconnected"
    );
}

// ─────────────────────────────── peer-id mismatch ───────────────────────────────

/// Test 4: dialing with a `/p2p/<wrong>` is rejected at the QUIC TLS
/// handshake; the dial result surfaces as `DialerError::TransportError(QuicError(...))`.
#[test]
fn test_quic_peer_id_mismatch() {
    let server_key = SecioKeyPair::secp256k1_generated();
    let (addr_tx, addr_rx) = oneshot::channel::<Multiaddr>();
    let (s_meta, _) = make_echo_meta(1.into(), 1);

    let _server = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = build_service(server_key, vec![s_meta], (), true);
        rt.block_on(async move {
            let listen = service
                .listen("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
                .await
                .expect("server listen");
            let _ignore = addr_tx.send(listen);
            service.run().await
        });
    });

    // Use a peer id from a different key so the verifier rejects it.
    let wrong_pid = SecioKeyPair::secp256k1_generated().peer_id();
    let errors: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let errors_clone = errors.clone();
    let (c_meta, _) = make_echo_meta(1.into(), 1);

    let client_thread = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handle = CollectingHandle {
            errors: errors_clone,
        };
        let mut service = build_service(
            SecioKeyPair::secp256k1_generated(),
            vec![c_meta],
            handle,
            true,
        );
        rt.block_on(async move {
            let listen_addr = addr_rx.await.unwrap();
            let dial: Multiaddr = format!("{}/p2p/{}", listen_addr, wrong_pid.to_base58())
                .parse()
                .unwrap();
            service.dial(dial, TargetProtocol::All).await.expect("dial");

            // The dial result is delivered to `ServiceHandle::handle_error`
            // via the service main loop, so it must be running to observe
            // the failure.
            let run = tokio::spawn(async move { service.run().await });

            tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    if !errors.lock().unwrap().is_empty() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .expect("dial error must surface");
            run.abort();
        });
    });

    client_thread.join().expect("client thread join");
}

// ─────────────────────────────── cross-transport ───────────────────────────────

/// Test 5a: a QUIC-enabled service still routes plain TCP addresses
/// through the classic TCP stack and can complete a normal TCP+secio
/// session — proving that enabling QUIC does not regress non-QUIC
/// transports.
#[test]
fn test_quic_cross_transport_tcp_still_works() {
    let (server_meta, server_rx) = make_echo_meta(1.into(), 5);
    let (client_meta, client_rx) = make_echo_meta(1.into(), 5);

    let server_key = SecioKeyPair::secp256k1_generated();
    let (addr_tx, addr_rx) = oneshot::channel::<Multiaddr>();

    let _server = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        // QUIC enabled, but server listens on TCP.
        let mut service = build_service(server_key, vec![server_meta], (), true);
        rt.block_on(async move {
            let listen = service
                .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .await
                .expect("server listen tcp");
            let _ignore = addr_tx.send(listen);
            service.run().await
        });
    });

    let _client = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        // QUIC also enabled on client; the dial address is TCP.
        let mut service = build_service(
            SecioKeyPair::secp256k1_generated(),
            vec![client_meta],
            (),
            true,
        );
        rt.block_on(async move {
            let listen_addr = addr_rx.await.unwrap();
            service
                .dial(listen_addr, TargetProtocol::All)
                .await
                .expect("client dial tcp");
            service.run().await
        });
    });

    let collect = |rx: &crossbeam_channel::Receiver<(ProtocolId, Bytes)>, n: usize| {
        let mut got = 0;
        while got < n {
            match rx.recv_timeout(Duration::from_secs(15)) {
                Ok(_) => got += 1,
                Err(_) => break,
            }
        }
        got
    };
    assert!(collect(&server_rx, 3) >= 3, "server tcp echo");
    assert!(collect(&client_rx, 3) >= 3, "client tcp echo");
}

/// Test 6: a `HandshakeType::Secio` service that did NOT call
/// `ServiceBuilder::quic_config(...)` dialing a `/quic-v1` address must
/// surface `QuicError(NotConfigured)` (not the misleading generic
/// `NotSupported`). The user has a valid tentacle identity and the
/// address shape is fine — they just forgot to opt into QUIC, and the
/// error should hint exactly that.
#[test]
fn test_quic_not_enabled_rejected() {
    use tentacle::quic::error::QuicErrorKind;

    let (c_meta, _) = make_echo_meta(1.into(), 1);
    let mut service = build_service(
        SecioKeyPair::secp256k1_generated(),
        vec![c_meta],
        (),
        false, // no quic_config(...)
    );
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        let res = service
            .dial(
                "/ip4/127.0.0.1/udp/4433/quic-v1".parse().unwrap(),
                TargetProtocol::All,
            )
            .await;
        match res {
            Err(TransportErrorKind::QuicError(QuicErrorKind::NotConfigured)) => (),
            other => panic!(
                "expected TransportErrorKind::QuicError(NotConfigured), got {:?}",
                other
                    .map(|_| "Ok".to_string())
                    .unwrap_or_else(|e| format!("{:?}", e))
            ),
        }
    });
}

// ─────────────────────── stalled-handshake accept-loop DoS ───────────────────────

/// Reports `SessionOpen` to a channel so a test can observe inbound sessions.
struct SessionOpenReporter(crossbeam_channel::Sender<()>);

#[async_trait]
impl ServiceHandle for SessionOpenReporter {
    async fn handle_error(&mut self, _context: &mut ServiceContext, _error: ServiceError) {}

    async fn handle_event(&mut self, _context: &mut ServiceContext, event: ServiceEvent) {
        if let ServiceEvent::SessionOpen { .. } = event {
            let _ignore = self.0.send(());
        }
    }
}

/// A UDP relay that forwards only a peer's **first** datagram to `server` and
/// drops everything afterwards.
///
/// A real QUIC client dialing the relay therefore gets its Initial delivered —
/// the server allocates an inbound connection attempt — but the client's
/// handshake flight never arrives, so that attempt stays pending until it
/// times out. This is the unauthenticated "start a handshake and go silent"
/// attacker from the finding, without needing to hand-craft QUIC packets.
fn spawn_stalling_relay(server: std::net::SocketAddr) -> std::net::SocketAddr {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind relay");
    let relay_addr = socket.local_addr().expect("relay addr");
    thread::spawn(move || {
        let mut buf = [0u8; 2048];
        let mut forwarded = false;
        while let Ok((n, from)) = socket.recv_from(&mut buf) {
            // Drop the server's replies, and every client datagram but the first.
            if from != server && !forwarded {
                let _ignore = socket.send_to(&buf[..n], server);
                forwarded = true;
            }
        }
    });
    relay_addr
}

/// Start a QUIC dial through `relay` and leave it hanging forever.
fn spawn_stalled_dial(relay: std::net::SocketAddr) {
    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let endpoint = tentacle::quic::endpoint::QuicEndpoint::new(
                SecioKeyPair::secp256k1_generated(),
                QuicConfig::default(),
            )
            .expect("attacker endpoint");
            let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", relay.port())
                .parse()
                .unwrap();
            let _ignore = endpoint.dial(addr).await;
            // Keep the runtime (and the stalled attempt) alive for the test.
            tokio::time::sleep(Duration::from_secs(120)).await;
        });
    });
}

/// Test 8: inbound QUIC handshakes that never complete must not stall the
/// accept loop. Several peers send a QUIC Initial and then go silent; a
/// legitimate peer dialing afterwards must still connect promptly instead of
/// waiting for those handshakes to time out.
#[test]
fn test_quic_stalled_handshake_does_not_block_accept_loop() {
    const STALLED_PEERS: usize = 3;

    let server_key = SecioKeyPair::secp256k1_generated();
    let server_pid = server_key.peer_id();

    let (open_tx, open_rx) = crossbeam_channel::unbounded();
    let (addr_tx, addr_rx) = crossbeam_channel::bounded(1);

    let _server = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = build_service(
            server_key,
            vec![make_echo_meta(1.into(), 1).0],
            SessionOpenReporter(open_tx),
            true,
        );
        rt.block_on(async move {
            let listen = service
                .listen("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
                .await
                .expect("server listen");
            let _ignore = addr_tx.send(listen);
            service.run().await
        });
    });

    let listen_addr = addr_rx
        .recv_timeout(Duration::from_secs(15))
        .expect("listen address");
    let server_socket: std::net::SocketAddr = {
        let port = listen_addr
            .iter()
            .find_map(|p| match p {
                tentacle::multiaddr::Protocol::Udp(port) => Some(port),
                _ => None,
            })
            .expect("listen port");
        format!("127.0.0.1:{port}").parse().unwrap()
    };

    // Occupy the listener with handshakes that will never complete.
    for _ in 0..STALLED_PEERS {
        spawn_stalled_dial(spawn_stalling_relay(server_socket));
    }
    thread::sleep(Duration::from_millis(500));

    // A legitimate peer must still get in promptly.
    let dial_addr: Multiaddr = format!("{}/p2p/{}", listen_addr, server_pid.to_base58())
        .parse()
        .unwrap();
    let _client = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = build_service(
            SecioKeyPair::secp256k1_generated(),
            vec![make_echo_meta(1.into(), 1).0],
            (),
            true,
        );
        rt.block_on(async move {
            service.dial(dial_addr, TargetProtocol::All).await.ok();
            service.run().await
        });
    });

    open_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("legitimate peer must connect while other handshakes are pending");
}

// ────────────────────── low-level listener API (downstream) ──────────────────────

/// Test 9: a downstream project that wants the QUIC transport without the full
/// `Service` can drive a listener itself through the public
/// `QuicListener::for_each_handshake`, which keeps accepting while handshakes
/// run concurrently under a capacity bound.
#[test]
fn test_quic_listener_for_each_handshake_public_api() {
    use std::ops::ControlFlow;
    use tentacle::quic::endpoint::{HandshakeCapacity, QuicEndpoint};

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let config = QuicConfig::default();
        let capacity = HandshakeCapacity::new(config.max_pending_handshakes);
        assert_eq!(capacity.available(), config.max_pending_handshakes);

        let server_key = SecioKeyPair::secp256k1_generated();
        let server_pid = server_key.peer_id();
        let server = QuicEndpoint::new(server_key, config).expect("server endpoint");
        let listener = server
            .listen("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
            .expect("listen");
        let listen_addr = listener.listen_addr().clone();

        let (peer_tx, peer_rx) = crossbeam_channel::unbounded();
        let serving = tokio::spawn(async move {
            listener
                .for_each_handshake(capacity, move |result| {
                    let peer_tx = peer_tx.clone();
                    async move {
                        let _ignore =
                            peer_tx.send(result.map(|(addr, handshake)| {
                                (addr, handshake.remote_pubkey().peer_id())
                            }));
                        // One peer is enough for this test.
                        ControlFlow::Break(())
                    }
                })
                .await
        });

        let client_key = SecioKeyPair::secp256k1_generated();
        let client_pid = client_key.peer_id();
        let client = QuicEndpoint::new(client_key, QuicConfig::default()).expect("client endpoint");
        let dial_addr: Multiaddr = format!("{}/p2p/{}", listen_addr, server_pid.to_base58())
            .parse()
            .unwrap();
        let handshake = client.dial(dial_addr).await.expect("dial");
        assert_eq!(handshake.remote_pubkey().peer_id(), server_pid);

        let (remote_addr, remote_pid) = peer_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("listener must report the inbound peer")
            .expect("inbound handshake must succeed");
        assert_eq!(remote_pid, client_pid, "identity must be verified");
        assert!(
            remote_addr.to_string().contains("/quic-v1"),
            "expected a quic multiaddr, got {remote_addr}"
        );

        // `ControlFlow::Break` must stop the listener loop.
        tokio::time::timeout(Duration::from_secs(10), serving)
            .await
            .expect("for_each_handshake must resolve after Break")
            .expect("listener task");
    });
}
