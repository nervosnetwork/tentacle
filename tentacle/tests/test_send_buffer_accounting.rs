//! A healthy session must be able to send far more than `send_buffer_size` in
//! total.
//!
//! The send buffer bounds how many bytes may be *queued* at once, not how many
//! may ever be sent. Capacity is reserved when a message is accepted and has to
//! be returned once the message stops being queued — whether it was written to
//! the transport or discarded along the way. If any of those release paths is
//! missed, the counter only ever grows, and a perfectly healthy session is
//! eventually closed for "blocking" after it has sent `send_buffer_size` bytes
//! in total.
//!
//! The exchange below is a strict ping-pong, so at most a couple of messages
//! are ever in flight and the instantaneous queue stays far below the limit,
//! while the cumulative traffic is many times the limit.

use bytes::Bytes;
use crossbeam_channel::{Sender, bounded};
use futures::channel;
use std::{thread, time::Duration};
use tentacle::{
    ProtocolId, async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef, ServiceContext},
    multiaddr::Multiaddr,
    secio::SecioKeyPair,
    service::{ProtocolHandle, Service, ServiceError, TargetProtocol},
    traits::{ServiceHandle, ServiceProtocol},
};

const SEND_BUFFER_SIZE: usize = 16 * 1024;
const MESSAGE_SIZE: usize = 1024;
/// Cumulative traffic in each direction, many times the send buffer.
const ROUND_TRIPS: usize = 200;

#[derive(Debug, PartialEq, Eq)]
enum Report {
    Done,
    Blocked,
}

/// Echoes whatever it receives.
struct Echo;

#[async_trait]
impl ServiceProtocol for Echo {
    async fn init(&mut self, _context: &mut ProtocolContext) {}

    async fn received(&mut self, context: ProtocolContextMutRef<'_>, data: Bytes) {
        let _ignore = context.send_message(data).await;
    }
}

/// Sends one message at a time, waiting for the echo before sending the next.
struct PingPong {
    seen: usize,
    report: Sender<Report>,
}

#[async_trait]
impl ServiceProtocol for PingPong {
    async fn init(&mut self, _context: &mut ProtocolContext) {}

    async fn connected(&mut self, context: ProtocolContextMutRef<'_>, _version: &str) {
        let _ignore = context
            .send_message(Bytes::from(vec![0u8; MESSAGE_SIZE]))
            .await;
    }

    async fn received(&mut self, context: ProtocolContextMutRef<'_>, data: Bytes) {
        self.seen += 1;
        if self.seen >= ROUND_TRIPS {
            let _ignore = self.report.send(Report::Done);
            return;
        }
        let _ignore = context.send_message(data).await;
    }
}

struct Handle(Sender<Report>);

#[async_trait]
impl ServiceHandle for Handle {
    async fn handle_error(&mut self, _context: &mut ServiceContext, error: ServiceError) {
        if let ServiceError::SessionBlocked { .. } = error {
            let _ignore = self.0.send(Report::Blocked);
        }
    }
}

fn build<P>(
    secio: bool,
    id: ProtocolId,
    proto: P,
    report: Sender<Report>,
) -> Service<Handle, SecioKeyPair>
where
    P: ServiceProtocol + Send + Unpin + 'static,
{
    let proto = std::sync::Mutex::new(Some(Box::new(proto)));
    let meta = MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            ProtocolHandle::Callback(
                proto
                    .lock()
                    .unwrap()
                    .take()
                    .expect("one session per service"),
            )
        })
        .build();
    let builder = ServiceBuilder::default()
        .insert_protocol(meta)
        .set_send_buffer_size(SEND_BUFFER_SIZE);
    if secio {
        builder
            .handshake_type(SecioKeyPair::secp256k1_generated().into())
            .build(Handle(report))
    } else {
        builder.build(Handle(report))
    }
}

fn healthy_session_outlives_its_send_buffer(secio: bool) {
    let (report_tx, report_rx) = bounded(4);
    let (addr_tx, addr_rx) = channel::oneshot::channel::<Multiaddr>();

    let server_report = report_tx.clone();
    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = build(secio, 1.into(), Echo, server_report);
        rt.block_on(async move {
            let listen_addr = service
                .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .await
                .unwrap();
            let _ignore = addr_tx.send(listen_addr);
            service.run().await
        });
    });

    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = build(
            secio,
            1.into(),
            PingPong {
                seen: 0,
                report: report_tx.clone(),
            },
            report_tx,
        );
        rt.block_on(async move {
            let listen_addr = addr_rx.await.unwrap();
            service
                .dial(listen_addr, TargetProtocol::All)
                .await
                .unwrap();
            service.run().await
        });
    });

    match report_rx.recv_timeout(Duration::from_secs(60)) {
        Ok(Report::Done) => (),
        Ok(Report::Blocked) => panic!(
            "session was closed as blocked after sending more than {SEND_BUFFER_SIZE} bytes in \
             total; send-buffer capacity is not being released"
        ),
        Err(error) => panic!("ping-pong did not finish: {error:?}"),
    }
}

#[test]
fn healthy_session_outlives_its_send_buffer_with_secio() {
    healthy_session_outlives_its_send_buffer(true)
}

#[test]
fn healthy_session_outlives_its_send_buffer_with_no_secio() {
    healthy_session_outlives_its_send_buffer(false)
}
