//! QUIC inbound handshakes are concurrent and bounded.
//!
//! Run with `cargo run --example quic_service --features quic`.
//!
//! A QUIC listener has to finish a TLS handshake before it knows who the peer
//! is, and a peer can simply send the opening packet and then go silent. If the
//! listener drove those handshakes one at a time, a single unauthenticated peer
//! could keep the whole listener busy until its handshake timed out — around 30
//! seconds with the default idle timeout, repeatable indefinitely.
//!
//! `Service` therefore keeps accepting while handshakes run concurrently, under
//! two limits that [`QuicConfig`] exposes:
//!
//! * [`QuicConfig::handshake_timeout`] — how long a single inbound handshake
//!   may take before it is abandoned and its capacity returned. This is
//!   independent of `max_idle_timeout`, which only applies once a connection is
//!   established.
//! * [`QuicConfig::max_pending_handshakes`] — how many inbound handshakes may
//!   be in flight at once, shared by every QUIC listener of the service. Peers
//!   arriving beyond this bound are refused immediately, so the memory a
//!   stranger can make the node allocate is capped.
//!
//! This example starts a QUIC service, parks several peers mid-handshake, and
//! then connects normally to show that the honest peer is served right away
//! instead of queueing behind the silent ones.

use std::{
    net::{SocketAddr, UdpSocket},
    str,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use bytes::Bytes;
use tentacle::{
    ProtocolId, async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef, ServiceContext},
    multiaddr::{Multiaddr, Protocol},
    quic::{config::QuicConfig, endpoint::QuicEndpoint},
    secio::SecioKeyPair,
    service::{ProtocolHandle, ProtocolMeta, Service, ServiceError, ServiceEvent, TargetProtocol},
    traits::{ServiceHandle, ServiceProtocol},
};

/// Peers that open a connection and then never say anything again.
const SILENT_PEERS: usize = 4;
/// Give up on an inbound handshake after this long.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Never work on more than this many inbound handshakes at once.
const MAX_PENDING_HANDSHAKES: usize = 8;
/// How long the honest peer is allowed to take to connect *and* exchange a
/// message. Without concurrent handshakes it would have to wait for the silent
/// handshakes to expire first.
const HONEST_PEER_BUDGET: Duration = Duration::from_secs(2);

const PROTO_ID: ProtocolId = ProtocolId::new(1);

fn quic_config() -> QuicConfig {
    QuicConfig {
        handshake_timeout: HANDSHAKE_TIMEOUT,
        max_pending_handshakes: MAX_PENDING_HANDSHAKES,
        ..QuicConfig::default()
    }
}

fn build_service<H: ServiceHandle + Unpin + 'static>(
    handle: H,
    greeter: Greeter,
) -> Service<H, SecioKeyPair> {
    ServiceBuilder::default()
        .insert_protocol(create_meta(PROTO_ID, greeter))
        .handshake_type(SecioKeyPair::secp256k1_generated().into())
        .quic_config(quic_config())
        .build(handle)
}

// ───────────────────────────────── protocol ─────────────────────────────────

fn create_meta(id: ProtocolId, greeter: Greeter) -> ProtocolMeta {
    MetaBuilder::new()
        .id(id)
        .service_handle(move || ProtocolHandle::Callback(Box::new(greeter)))
        .build()
}

#[derive(Default)]
struct Greeter {
    /// Sent to the peer once the protocol opens. Used by the dialing side.
    greeting: Option<&'static str>,
    /// Where to report messages from peers. Used by the listening side.
    received: Option<mpsc::Sender<String>>,
}

#[async_trait]
impl ServiceProtocol for Greeter {
    async fn init(&mut self, _context: &mut ProtocolContext) {}

    async fn connected(&mut self, context: ProtocolContextMutRef<'_>, _version: &str) {
        if let Some(greeting) = self.greeting {
            let _ignore = context
                .send_message(Bytes::from_static(greeting.as_bytes()))
                .await;
        }
    }

    async fn received(&mut self, context: ProtocolContextMutRef<'_>, data: Bytes) {
        if let Some(sender) = self.received.as_ref() {
            let _ignore = sender.send(format!(
                "{:?} from session {}",
                str::from_utf8(&data).unwrap_or("<binary>"),
                context.session.id
            ));
        }
    }
}

// ────────────────────────────── service handles ──────────────────────────────

/// Publishes the listen address to the main thread.
struct ServerHandle {
    listening: Option<mpsc::Sender<Multiaddr>>,
}

#[async_trait]
impl ServiceHandle for ServerHandle {
    async fn handle_error(&mut self, _context: &mut ServiceContext, error: ServiceError) {
        println!("  server error: {error:?}");
    }

    async fn handle_event(&mut self, _context: &mut ServiceContext, event: ServiceEvent) {
        if let ServiceEvent::ListenStarted { address } = event
            && let Some(sender) = self.listening.take()
        {
            let _ignore = sender.send(address);
        }
    }
}

struct QuietHandle;

#[async_trait]
impl ServiceHandle for QuietHandle {
    async fn handle_error(&mut self, _context: &mut ServiceContext, _error: ServiceError) {}
    async fn handle_event(&mut self, _context: &mut ServiceContext, _event: ServiceEvent) {}
}

// ─────────────────────────────── silent peers ───────────────────────────────

/// A UDP relay that passes a peer's **first** datagram on to `server` and drops
/// everything after it.
///
/// A real QUIC client dialing the relay therefore gets its opening packet
/// delivered — the server allocates an inbound handshake for it — but the rest
/// of the client's handshake never arrives, so that handshake stays pending
/// until `handshake_timeout` expires. This stands in for an unauthenticated
/// peer that connects and then goes quiet.
fn spawn_silent_relay(server: SocketAddr) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind relay");
    let relay_addr = socket.local_addr().expect("relay address");
    thread::spawn(move || {
        let mut buf = [0u8; 2048];
        let mut forwarded = false;
        while let Ok((n, from)) = socket.recv_from(&mut buf) {
            if from != server && !forwarded {
                let _ignore = socket.send_to(&buf[..n], server);
                forwarded = true;
            }
        }
    });
    relay_addr
}

/// Start a QUIC connection through `relay` and leave it hanging.
fn spawn_silent_peer(relay: SocketAddr) {
    thread::spawn(move || {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async move {
                let endpoint =
                    QuicEndpoint::new(SecioKeyPair::secp256k1_generated(), quic_config())
                        .expect("silent peer endpoint");
                let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", relay.port())
                    .parse()
                    .unwrap();
                let _ignore = endpoint.dial(addr).await;
                // Hold the connection attempt open for the rest of the example.
                tokio::time::sleep(Duration::from_secs(120)).await;
            });
    });
}

// ──────────────────────────────────── main ────────────────────────────────────

fn main() {
    let (listen_tx, listen_rx) = mpsc::channel();
    let (message_tx, message_rx) = mpsc::channel();

    thread::spawn(move || {
        let mut service = build_service(
            ServerHandle {
                listening: Some(listen_tx),
            },
            Greeter {
                received: Some(message_tx),
                ..Greeter::default()
            },
        );
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async move {
                service
                    .listen("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
                    .await
                    .expect("quic listen");
                service.run().await
            });
    });

    let listen_addr = listen_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("listen address");
    println!("server listening on {listen_addr}");
    println!(
        "handshake_timeout = {HANDSHAKE_TIMEOUT:?}, max_pending_handshakes = {MAX_PENDING_HANDSHAKES}"
    );

    let server_socket = udp_socket_addr(&listen_addr);
    println!("\nparking {SILENT_PEERS} peers mid-handshake ...");
    for _ in 0..SILENT_PEERS {
        spawn_silent_peer(spawn_silent_relay(server_socket));
    }
    // Let the silent peers reach the listener before the honest one dials.
    thread::sleep(Duration::from_millis(500));

    println!("connecting an honest peer while those handshakes are still pending ...");
    let dial_addr = listen_addr.clone();
    let started = Instant::now();
    thread::spawn(move || {
        let mut service = build_service(
            QuietHandle,
            Greeter {
                greeting: Some("hello over quic"),
                ..Greeter::default()
            },
        );
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async move {
                service
                    .dial(dial_addr, TargetProtocol::All)
                    .await
                    .expect("quic dial");
                service.run().await
            });
    });

    let message = message_rx
        .recv_timeout(HONEST_PEER_BUDGET)
        .expect("the honest peer must not queue behind the silent ones");
    let elapsed = started.elapsed();

    println!("\nserver received {message} after {elapsed:?}");
    println!(
        "the {SILENT_PEERS} silent handshakes are still pending and will be dropped \
         after {HANDSHAKE_TIMEOUT:?}"
    );
    println!("done");
}

/// Extract the `SocketAddr` of a `/ip4/<ip>/udp/<port>/quic-v1` multiaddr.
fn udp_socket_addr(addr: &Multiaddr) -> SocketAddr {
    let mut ip = None;
    let mut port = None;
    for protocol in addr.iter() {
        match protocol {
            Protocol::Ip4(value) => ip = Some(std::net::IpAddr::V4(value)),
            Protocol::Ip6(value) => ip = Some(std::net::IpAddr::V6(value)),
            Protocol::Udp(value) => port = Some(value),
            _ => (),
        }
    }
    SocketAddr::new(ip.expect("listen ip"), port.expect("listen port"))
}
