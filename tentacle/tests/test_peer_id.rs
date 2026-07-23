use std::{borrow::Cow, net::TcpListener, sync::mpsc::channel, thread, time::Duration};
use tentacle::{
    ProtocolId, async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ServiceContext},
    error::DialerErrorKind,
    multiaddr::Multiaddr,
    multiaddr::Protocol as MultiProtocol,
    secio::SecioKeyPair,
    service::{
        ProtocolHandle, ProtocolMeta, Service, ServiceControl, ServiceError, ServiceEvent,
        TargetProtocol,
    },
    traits::{ServiceHandle, ServiceProtocol},
};

pub fn create<F>(key_pair: SecioKeyPair, meta: ProtocolMeta, shandle: F) -> Service<F, SecioKeyPair>
where
    F: ServiceHandle + Unpin + 'static,
{
    ServiceBuilder::default()
        .insert_protocol(meta)
        .forever(true)
        .handshake_type(key_pair.into())
        .build(shandle)
}

struct PHandle;

#[async_trait]
impl ServiceProtocol for PHandle {
    async fn init(&mut self, _control: &mut ProtocolContext) {}
}

#[derive(Clone)]
struct EmptySHandle {
    sender: crossbeam_channel::Sender<usize>,
    error_count: usize,
}

#[async_trait]
impl ServiceHandle for EmptySHandle {
    async fn handle_error(&mut self, _env: &mut ServiceContext, error: ServiceError) {
        self.error_count += 1;

        match error {
            ServiceError::DialerError { error, .. } => match error {
                DialerErrorKind::PeerIdNotMatch => {}
                err => panic!(
                    "test fail, expected DialerErrorKind::PeerIdNotMatch, got {:?}",
                    err
                ),
            },
            _ => {
                panic!("test fail {:?}", error);
            }
        }

        if self.error_count > 8 {
            let _res = self.sender.try_send(self.error_count);
        }
    }

    async fn handle_event(&mut self, _control: &mut ServiceContext, event: ServiceEvent) {
        if let ServiceEvent::SessionOpen { .. } = event {
            let _res = self.sender.try_send(self.error_count);
        }
    }
}

fn create_shandle() -> (EmptySHandle, crossbeam_channel::Receiver<usize>) {
    let (sender, receiver) = crossbeam_channel::bounded(2);
    (
        EmptySHandle {
            sender,
            error_count: 0,
        },
        receiver,
    )
}

fn create_meta(id: ProtocolId) -> ProtocolMeta {
    MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            if id == 0.into() {
                ProtocolHandle::None
            } else {
                let handle = Box::new(PHandle);
                ProtocolHandle::Callback(handle)
            }
        })
        .build()
}

fn test_peer_id(fail: bool) {
    let meta = create_meta(1.into());
    let key = SecioKeyPair::secp256k1_generated();
    let (addr_sender, addr_receiver) = channel::<Multiaddr>();
    let mut service = create(key.clone(), meta, ());

    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let listen_addr = service
                .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .await
                .unwrap();

            addr_sender.send(listen_addr).unwrap();

            service.run().await
        });
    });

    let mut listen_addr = addr_receiver.recv().unwrap();

    let (shandle, error_receiver) = create_shandle();
    let meta = create_meta(1.into());
    let mut service = create(SecioKeyPair::secp256k1_generated(), meta, shandle);
    let control: ServiceControl = service.control().clone().into();
    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move { service.run().await });
    });

    if fail {
        (1..11).for_each(|_| {
            let mut addr = listen_addr.clone();
            addr.push(MultiProtocol::P2P(Cow::Owned(
                SecioKeyPair::secp256k1_generated().peer_id().into_bytes(),
            )));
            control.dial(addr, TargetProtocol::All).unwrap();
        });
        assert_eq!(error_receiver.recv(), Ok(9));
    } else {
        listen_addr.push(MultiProtocol::P2P(Cow::Owned(key.peer_id().into_bytes())));
        control.dial(listen_addr, TargetProtocol::All).unwrap();
        assert_eq!(error_receiver.recv(), Ok(0));
    }
}

#[test]
fn pending_dial_peer_id_does_not_suppress_different_address() {
    // 1. Start the victim tentacle service and capture its listen address.
    let meta = create_meta(1.into());
    let victim_key = SecioKeyPair::secp256k1_generated();
    let victim_peer_id = victim_key.peer_id();
    let (addr_sender, addr_receiver) = channel::<Multiaddr>();
    let mut victim_service = create(victim_key, meta, ());

    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let listen_addr = victim_service
                .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .await
                .unwrap();

            addr_sender.send(listen_addr).unwrap();

            victim_service.run().await
        });
    });

    // 2. Start a raw TCP listener that plays the role of the attacker.
    //    It accepts the incoming connect (so the dialer's asynchronous
    //    `dial_future` reaches the point where `dial_protocols` is
    //    definitely populated with `spoofed_addr`), then stalls holding
    //    the socket so the secio handshake never completes.
    //    `accepted_tx` is used as an explicit synchronization barrier
    //    between the attacker socket accepting the spoofed dial and the
    //    test issuing the legitimate dial.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let stalled_addr = listener.local_addr().unwrap();
    let (accepted_tx, accepted_rx) = channel::<()>();
    thread::spawn(move || {
        // Accept the spoofed dial; if this panics the test will fail loudly.
        let accepted = listener.accept().unwrap();
        // Signal the main thread: at this point the dialer must have
        // already executed `dial_inner`, which synchronously inserts
        // `spoofed_addr` into `dial_protocols` before spawning the async
        // dial future that we just observed connecting.
        accepted_tx.send(()).ok();
        // Hold the connection so the pending dial keeps occupying
        // `dial_protocols` (up to the default handshake timeout).
        thread::sleep(Duration::from_secs(30));
        drop(accepted);
    });

    let mut spoofed_addr: Multiaddr =
        format!("/ip4/{}/tcp/{}", stalled_addr.ip(), stalled_addr.port())
            .parse()
            .unwrap();
    spoofed_addr.push(MultiProtocol::P2P(Cow::Owned(
        victim_peer_id.clone().into_bytes(),
    )));

    let mut victim_addr = addr_receiver.recv().unwrap();
    victim_addr.push(MultiProtocol::P2P(Cow::Owned(victim_peer_id.into_bytes())));

    // 3. Start the dialer tentacle service.
    let (shandle, session_receiver) = create_shandle();
    let meta = create_meta(1.into());
    let mut dialer_service = create(SecioKeyPair::secp256k1_generated(), meta, shandle);
    let control: ServiceControl = dialer_service.control().clone().into();
    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move { dialer_service.run().await });
    });

    // 4. Issue the spoofed dial and wait until the attacker listener has
    //    actually accepted it. Once `accepted_rx` fires we know:
    //      a) the dialer already processed `ServiceTask::Dial(spoofed)`,
    //      b) `dial_inner` synchronously inserted `spoofed_addr` into
    //         `dial_protocols`, then spawned the async dial future,
    //      c) the async dial future has already run far enough to complete
    //         the TCP connect (proving `dial_protocols` is now populated).
    //    This is a strict post-condition of the pending-state we need to
    //    exercise the (previously vulnerable) dedup path.
    control.dial(spoofed_addr, TargetProtocol::All).unwrap();
    accepted_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("attacker listener must accept the spoofed dial");

    // 5. Now issue the legitimate dial. Under the fix, the legitimate dial
    //    must proceed even though `dial_protocols` still holds a pending
    //    entry with the same (unauthenticated) /p2p/<peer_id>. Under the
    //    vulnerable code, this dial would have been silently suppressed
    //    and the assertion below would time out.
    control.dial(victim_addr, TargetProtocol::All).unwrap();

    assert_eq!(
        session_receiver.recv_timeout(Duration::from_secs(10)),
        Ok(0),
        "legitimate dial must complete even though a spoofed pending dial \
         with the same /p2p/<peer_id> is still in `dial_protocols`"
    );
}

// Positive control for the new opt-in behavior: once we already hold an
// authenticated session for a given /p2p/<peer_id>, a follow-up dial that
// carries the same /p2p component should be short-circuited by
// `Service::dial` / `ServiceTask::Dial` without ever attempting a new TCP
// connect. This exercises `is_peer_id_authenticated_connected`.
#[test]
fn dial_deduped_after_authenticated_session_established() {
    let meta = create_meta(1.into());
    let victim_key = SecioKeyPair::secp256k1_generated();
    let victim_peer_id = victim_key.peer_id();
    let (addr_sender, addr_receiver) = channel::<Multiaddr>();
    let mut victim_service = create(victim_key, meta, ());

    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let listen_addr = victim_service
                .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .await
                .unwrap();
            addr_sender.send(listen_addr).unwrap();
            victim_service.run().await
        });
    });

    let mut victim_addr = addr_receiver.recv().unwrap();
    victim_addr.push(MultiProtocol::P2P(Cow::Owned(
        victim_peer_id.clone().into_bytes(),
    )));

    let (shandle, session_receiver) = create_shandle();
    let meta = create_meta(1.into());
    let mut dialer_service = create(SecioKeyPair::secp256k1_generated(), meta, shandle);
    let control: ServiceControl = dialer_service.control().clone().into();
    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move { dialer_service.run().await });
    });

    // First dial: reach an authenticated session with the victim.
    control
        .dial(victim_addr.clone(), TargetProtocol::All)
        .unwrap();
    assert_eq!(
        session_receiver.recv_timeout(Duration::from_secs(10)),
        Ok(0)
    );

    // Second dial: a *different* address carrying the same /p2p/<peer_id>.
    // Because we already hold an authenticated session for that peer id,
    // the dial must be short-circuited without touching the network. In
    // particular, no TransportError must surface (which would panic
    // `EmptySHandle::handle_error`), and no phantom SessionOpen must arrive.
    let (connect_tx, connect_rx) = channel::<()>();
    let decoy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    decoy_listener.set_nonblocking(true).unwrap();
    let decoy_port = decoy_listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let start = std::time::Instant::now();
        loop {
            match decoy_listener.accept() {
                Ok(_) => {
                    connect_tx.send(()).ok();
                    break;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if start.elapsed() > Duration::from_millis(900) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    let mut second_addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", decoy_port)
        .parse()
        .unwrap();
    second_addr.push(MultiProtocol::P2P(Cow::Owned(victim_peer_id.into_bytes())));
    control.dial(second_addr, TargetProtocol::All).unwrap();

    assert!(
        connect_rx.recv_timeout(Duration::from_millis(900)).is_err(),
        "dial with a duplicate authenticated /p2p/<peer_id> must be deduped before TCP connect"
    );

    match session_receiver.recv_timeout(Duration::from_millis(800)) {
        Err(_) => (),
        Ok(v) => panic!(
            "dial with a duplicate authenticated /p2p/<peer_id> must be \
             deduped, but observed event value {}",
            v
        ),
    }
}

#[test]
fn test_fail() {
    test_peer_id(true)
}

#[test]
fn test_succeed() {
    test_peer_id(false)
}
