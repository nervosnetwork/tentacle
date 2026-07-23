//! Same as [`examples/simple.rs`](./simple.rs), but built on QUIC
//! instead of TCP + secio + yamux.
//!
//! Four run modes:
//!
//! ```bash
//! # Plain server / client — dial address has no /p2p/<id> pin
//! cargo run --features quic --example quic_simple -- server
//! cargo run --features quic --example quic_simple -- client
//!
//! # Server prints its PeerId on stdout so the client can pin it
//! cargo run --features quic --example quic_simple -- server-with-peer-id
//!
//! # Client pins the server's PeerId; the TentacleQuicServerCertVerifier
//! # will reject the handshake if the server's identity does not match
//! cargo run --features quic --example quic_simple -- client-with-peer-id <peer_id>
//! ```
//!
//! The [`PHandle`] / [`SHandle`] implementations are intentionally
//! identical to the ones in `simple.rs` — the only differences are:
//!
//! - the call to [`ServiceBuilder::quic_config`] to enable the
//!   QUIC transport, and
//! - the listen / dial addresses use the
//!   `/ip4/.../udp/<port>/quic-v1` shape instead of `/ip4/.../tcp/<port>`.
//!
//! Everything else — protocol meta, message handlers, scheduled
//! tasks — runs unchanged, demonstrating that QUIC support is
//! transparent at the protocol-handler layer.
//!
//! Logging defaults to `info` level; override with `RUST_LOG=...`.

use bytes::Bytes;
use futures::{
    channel::oneshot::{Sender, channel},
    future::select,
    prelude::*,
};
use log::info;
use std::collections::HashMap;
use std::{str, time::Duration};
use tentacle::{
    ProtocolId, SessionId, async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef, ServiceContext},
    multiaddr::Multiaddr,
    quic::config::QuicConfig,
    secio::{PeerId, SecioKeyPair},
    service::{
        ProtocolHandle, ProtocolMeta, Service, ServiceError, ServiceEvent, TargetProtocol,
        TargetSession,
    },
    traits::{ServiceHandle, ServiceProtocol},
};

// Any protocol will be abstracted into a ProtocolMeta structure.
// From an implementation point of view, tentacle treats any protocol equally —
// QUIC or TCP makes no difference at this layer.
fn create_meta(id: ProtocolId) -> ProtocolMeta {
    MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            // All protocols use the same handle.
            // This is just an example. In a real environment, each protocol
            // would typically have its own handle.
            let handle = Box::new(PHandle {
                count: 0,
                connected_session_ids: Vec::new(),
                clear_handle: HashMap::new(),
            });
            ProtocolHandle::Callback(handle)
        })
        .build()
}

#[derive(Default)]
struct PHandle {
    count: usize,
    connected_session_ids: Vec<SessionId>,
    clear_handle: HashMap<SessionId, Sender<()>>,
}

#[async_trait]
impl ServiceProtocol for PHandle {
    async fn init(&mut self, context: &mut ProtocolContext) {
        if context.proto_id == 0.into() {
            let _ = context
                .set_service_notify(0.into(), Duration::from_secs(5), 3)
                .await;
        }
    }

    async fn connected(&mut self, context: ProtocolContextMutRef<'_>, version: &str) {
        let session = context.session;
        self.connected_session_ids.push(session.id);
        info!(
            "proto id [{}] open on session [{}], address: [{}], type: [{:?}], version: {}",
            context.proto_id, session.id, session.address, session.ty, version
        );
        info!("connected sessions are: {:?}", self.connected_session_ids);

        if context.proto_id != 1.into() {
            return;
        }

        // Register a scheduled task to send data to the remote peer.
        // Clear the task via channel when disconnected.
        let (sender, receiver) = channel();
        self.clear_handle.insert(session.id, sender);
        let session_id = session.id;
        let interval_sender = context.control().clone();

        let interval_send_task = async move {
            let mut interval =
                tokio::time::interval_at(tokio::time::Instant::now(), Duration::from_secs(5));
            loop {
                interval.tick().await;
                let _ = interval_sender
                    .send_message_to(
                        session_id,
                        1.into(),
                        Bytes::from("I am an interval message"),
                    )
                    .await;
            }
        };

        let task = select(receiver, interval_send_task.boxed());

        let _ = context
            .future_task(async move {
                task.await;
            })
            .await;
    }

    async fn disconnected(&mut self, context: ProtocolContextMutRef<'_>) {
        let new_list = self
            .connected_session_ids
            .iter()
            .filter(|&id| id != &context.session.id)
            .cloned()
            .collect();
        self.connected_session_ids = new_list;

        if let Some(handle) = self.clear_handle.remove(&context.session.id) {
            let _ = handle.send(());
        }

        info!(
            "proto id [{}] close on session [{}]",
            context.proto_id, context.session.id
        );
    }

    async fn received(&mut self, context: ProtocolContextMutRef<'_>, data: bytes::Bytes) {
        self.count += 1;
        info!(
            "received from [{}]: proto [{}] data {:?}, message count: {}",
            context.session.id,
            context.proto_id,
            str::from_utf8(data.as_ref()).unwrap(),
            self.count
        );
    }

    async fn notify(&mut self, context: &mut ProtocolContext, token: u64) {
        info!(
            "proto [{}] received notify token: {}",
            context.proto_id, token
        );
    }
}

struct SHandle;

#[async_trait]
impl ServiceHandle for SHandle {
    // A lot of internal error events surface here, but not all errors need to
    // close the service — some are informational. With QUIC enabled, expect
    // additional `TransportErrorKind::QuicError(...)` variants alongside the
    // classic ones.
    async fn handle_error(&mut self, _context: &mut ServiceContext, error: ServiceError) {
        info!("service error: {:?}", error);
    }
    async fn handle_event(&mut self, context: &mut ServiceContext, event: ServiceEvent) {
        info!("service event: {:?}", event);
        if let ServiceEvent::SessionOpen { .. } = event {
            let delay_sender = context.control().clone();

            let _ = context
                .future_task(async move {
                    tokio::time::sleep_until(tokio::time::Instant::now() + Duration::from_secs(3))
                        .await;
                    let _ = delay_sender
                        .filter_broadcast(
                            TargetSession::All,
                            0.into(),
                            Bytes::from("I am a delayed message"),
                        )
                        .await;
                })
                .await;
        }
    }
}

fn main() {
    // Default to `info` level so the example is interactive out of the box;
    // `RUST_LOG=...` still overrides as usual.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let mode = std::env::args().nth(1);
    match mode.as_deref() {
        Some("server") => {
            info!("Starting QUIC server ......");
            server(/* print_peer_id = */ false);
        }
        Some("server-with-peer-id") => {
            info!("Starting QUIC server (PeerId pinning enabled) ......");
            server(/* print_peer_id = */ true);
        }
        Some("client") => {
            info!("Starting QUIC client ......");
            client(None);
        }
        Some("client-with-peer-id") => {
            let peer_id_str = std::env::args().nth(2).unwrap_or_else(|| {
                eprintln!(
                    "usage: quic_simple client-with-peer-id <server_peer_id>\n\
                     (run `quic_simple server-with-peer-id` in another terminal first to get one)"
                );
                std::process::exit(2);
            });
            // Validate by parsing the full dial multiaddr — a malformed peer_id
            // fails here rather than only at TLS handshake time, and we avoid
            // pulling `bs58` directly into the example's dependency surface.
            let dial_addr: Multiaddr =
                format!("/ip4/127.0.0.1/udp/4433/quic-v1/p2p/{}", peer_id_str)
                    .parse()
                    .unwrap_or_else(|e| {
                        eprintln!("invalid peer id {:?}: {:?}", peer_id_str, e);
                        std::process::exit(2);
                    });
            info!(
                "Starting QUIC client pinned to peer_id {} ......",
                peer_id_str
            );
            client(Some(dial_addr));
        }
        _ => {
            eprintln!(
                "usage: quic_simple <server|server-with-peer-id|client|client-with-peer-id <peer_id>>"
            );
            std::process::exit(2);
        }
    }
}

// A p2p application is a service. During the construction process,
// all protocols supported by the application need to be registered as meta.
// `quic_config(...)` is the one extra call that distinguishes this from
// `examples/simple.rs`; everything else is identical.
//
// We hold onto the `SecioKeyPair` *before* moving it into the builder so the
// caller can recover the PeerId (the keypair is consumed by
// `handshake_type(...)`). This is also how a real application would record
// its identity for logging / discovery.
fn create_server() -> (Service<SHandle, SecioKeyPair>, PeerId) {
    let key = SecioKeyPair::secp256k1_generated();
    let peer_id = key.peer_id();
    let service = ServiceBuilder::default()
        .insert_protocol(create_meta(0.into()))
        .insert_protocol(create_meta(1.into()))
        // QUIC requires `HandshakeType::Secio` — the secio identity is bound
        // into the QUIC TLS certificate. See `docs/quic_en.md` for details.
        .handshake_type(key.into())
        .quic_config(QuicConfig::default())
        .build(SHandle);
    (service, peer_id)
}

/// Proto 0 open success
/// Proto 1 open success
/// Proto 2 open failure
///
/// Because the server only supports 0 and 1.
fn create_client() -> Service<SHandle, SecioKeyPair> {
    ServiceBuilder::default()
        .insert_protocol(create_meta(0.into()))
        .insert_protocol(create_meta(1.into()))
        .insert_protocol(create_meta(2.into()))
        .handshake_type(SecioKeyPair::secp256k1_generated().into())
        .quic_config(QuicConfig::default())
        .build(SHandle)
}

fn server(print_peer_id: bool) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(async {
        let (mut service, peer_id) = create_server();
        if print_peer_id {
            // Use println! so the value is easy to copy even with logging off;
            // pass it back to `client-with-peer-id <peer_id>` in another terminal.
            println!("Server PeerId: {}", peer_id.to_base58());
        }
        service
            .listen("/ip4/127.0.0.1/udp/4433/quic-v1".parse().unwrap())
            .await
            .unwrap();
        service.run().await
    });
}

fn client(pinned_dial_addr: Option<Multiaddr>) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    // No `/p2p/<peer_id>` pin → `TentacleQuicServerCertVerifier` still verifies
    // the server's identity binding (binding_sig over SPKI must be valid), but
    // accepts any well-formed tentacle identity. With a pin, the verifier
    // additionally requires the derived PeerId to match `/p2p/<id>`; mismatch
    // aborts the TLS handshake.
    let dial_addr: Multiaddr =
        pinned_dial_addr.unwrap_or_else(|| "/ip4/127.0.0.1/udp/4433/quic-v1".parse().unwrap());

    rt.block_on(async {
        let mut service = create_client();
        service.dial(dial_addr, TargetProtocol::All).await.unwrap();
        service.run().await
    });
}
