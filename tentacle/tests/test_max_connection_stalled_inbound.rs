use std::{
    io::{self, Read},
    net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream as StdTcpStream},
    thread,
    time::Duration,
};

use futures::channel;
use tentacle::{
    ProtocolId, async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::ServiceContext,
    error::DialerErrorKind,
    multiaddr::{Multiaddr, Protocol},
    secio::SecioKeyPair,
    service::{
        ProtocolHandle, ProtocolMeta, Service, ServiceControl, ServiceError, ServiceEvent,
        TargetProtocol,
    },
    traits::ServiceHandle,
};

const MAX_CONNECTIONS: usize = 2;

struct ServerHandle {
    session_open_sender: crossbeam_channel::Sender<()>,
    dial_error_sender: crossbeam_channel::Sender<DialerErrorKind>,
}

#[async_trait]
impl ServiceHandle for ServerHandle {
    async fn handle_event(&mut self, _env: &mut ServiceContext, event: ServiceEvent) {
        if let ServiceEvent::SessionOpen { .. } = event {
            self.session_open_sender.send(()).unwrap();
        }
    }

    async fn handle_error(&mut self, _env: &mut ServiceContext, error: ServiceError) {
        if let ServiceError::DialerError { error, .. } = error {
            let _ignore = self.dial_error_sender.send(error);
        }
    }
}

fn create_meta(id: ProtocolId) -> ProtocolMeta {
    MetaBuilder::new()
        .id(id)
        .service_handle(move || ProtocolHandle::None)
        .build()
}

fn create_service<F>(handle: F) -> Service<F, SecioKeyPair>
where
    F: ServiceHandle + Unpin + 'static,
{
    ServiceBuilder::default()
        .insert_protocol(create_meta(1.into()))
        .handshake_type(SecioKeyPair::secp256k1_generated().into())
        .max_connection_number(MAX_CONNECTIONS)
        .max_outbound_connection_number(MAX_CONNECTIONS)
        .timeout(Duration::from_secs(1))
        .forever(true)
        .build(handle)
}

fn socket_addr(listen_addr: &Multiaddr) -> SocketAddr {
    let mut ip = None;
    let mut port = None;
    for proto in listen_addr.iter() {
        match proto {
            Protocol::Ip4(addr) => ip = Some(IpAddr::V4(addr)),
            Protocol::Ip6(addr) => ip = Some(IpAddr::V6(addr)),
            Protocol::Tcp(p) => port = Some(p),
            _ => {}
        }
    }
    SocketAddr::new(ip.unwrap(), port.unwrap())
}

fn connect_stalled(addr: SocketAddr) -> StdTcpStream {
    let stream = StdTcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
}

fn multiaddr_from_socket_addr(addr: SocketAddr) -> Multiaddr {
    format!("/ip4/{}/tcp/{}", addr.ip(), addr.port())
        .parse()
        .unwrap()
}

fn spawn_stalled_acceptor() -> (Multiaddr, crossbeam_channel::Receiver<StdTcpStream>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (sender, receiver) = crossbeam_channel::unbounded();
    thread::spawn(move || {
        while let Ok((stream, _)) = listener.accept() {
            if sender.send(stream).is_err() {
                break;
            }
        }
    });
    (multiaddr_from_socket_addr(addr), receiver)
}

fn assert_stream_closed(mut stream: StdTcpStream) {
    let mut buf = [0; 1];
    match stream.read(&mut buf) {
        Ok(0) => {}
        Ok(n) => panic!("expected rejected inbound stream to close, read {n} bytes"),
        Err(err) => panic!("expected rejected inbound stream to close, got {err:?}"),
    }
}

fn assert_stream_stays_open(mut stream: StdTcpStream) {
    let mut buf = [0; 1];
    match stream.read(&mut buf) {
        Err(err)
            if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut => {
        }
        Ok(0) => panic!("expected inbound stream to stay open after capacity was released"),
        Ok(n) => panic!("expected no bytes from stalled inbound stream, read {n} bytes"),
        Err(err) => panic!("expected inbound stream to stay open, got {err:?}"),
    }
}

#[test]
fn stalled_inbound_connections_count_toward_connection_limit() {
    let (addr_sender, addr_receiver) = channel::oneshot::channel::<Multiaddr>();
    let (session_open_sender, session_open_receiver) = crossbeam_channel::unbounded();
    let (dial_error_sender, _dial_error_receiver) = crossbeam_channel::unbounded();

    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create_service(ServerHandle {
            session_open_sender,
            dial_error_sender,
        });
        rt.block_on(async move {
            let listen_addr = service
                .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .await
                .unwrap();
            addr_sender.send(listen_addr).unwrap();
            service.run().await
        });
    });

    let listen_addr = futures::executor::block_on(addr_receiver).unwrap();
    let addr = socket_addr(&listen_addr);

    let mut stalled = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        stalled.push(connect_stalled(addr));
    }

    thread::sleep(Duration::from_millis(300));

    let rejected = connect_stalled(addr);
    assert_stream_closed(rejected);

    assert!(
        session_open_receiver
            .recv_timeout(Duration::from_millis(300))
            .is_err(),
        "stalled or rejected inbound sockets must not create sessions"
    );

    let released = stalled.pop().unwrap();
    released.shutdown(Shutdown::Both).unwrap();
    drop(released);
    thread::sleep(Duration::from_millis(1_500));

    let accepted = connect_stalled(addr);
    assert_stream_stays_open(accepted);

    assert!(
        session_open_receiver
            .recv_timeout(Duration::from_millis(300))
            .is_err(),
        "accepted stalled inbound socket must not create a session before handshake"
    );
}

#[test]
fn stalled_outbound_connections_count_toward_connection_limit() {
    let (control_sender, control_receiver) = channel::oneshot::channel::<ServiceControl>();
    let (session_open_sender, session_open_receiver) = crossbeam_channel::unbounded();
    let (dial_error_sender, dial_error_receiver) = crossbeam_channel::unbounded();

    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create_service(ServerHandle {
            session_open_sender,
            dial_error_sender,
        });
        let control = service.control().clone().into();
        control_sender.send(control).unwrap();
        rt.block_on(async move { service.run().await });
    });

    let control = futures::executor::block_on(control_receiver).unwrap();

    let mut accepted = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        let (addr, receiver) = spawn_stalled_acceptor();
        control.dial(addr, TargetProtocol::All).unwrap();
        accepted.push(receiver.recv_timeout(Duration::from_secs(2)).unwrap());
    }

    let (rejected_addr, rejected_receiver) = spawn_stalled_acceptor();
    control.dial(rejected_addr, TargetProtocol::All).unwrap();
    assert!(
        rejected_receiver
            .recv_timeout(Duration::from_millis(300))
            .is_err(),
        "rejected outbound dial must not open a TCP connection"
    );
    assert!(
        dial_error_receiver
            .recv_timeout(Duration::from_secs(2))
            .is_ok(),
        "outbound dial over capacity must report a dial error"
    );

    assert!(
        session_open_receiver
            .recv_timeout(Duration::from_millis(300))
            .is_err(),
        "stalled or rejected outbound sockets must not create sessions"
    );

    let released = accepted.pop().unwrap();
    released.shutdown(Shutdown::Both).unwrap();
    drop(released);
    thread::sleep(Duration::from_millis(500));

    let (accepted_addr, accepted_receiver) = spawn_stalled_acceptor();
    control.dial(accepted_addr, TargetProtocol::All).unwrap();
    accepted_receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("capacity released for a new outbound connection");

    assert!(
        session_open_receiver
            .recv_timeout(Duration::from_millis(300))
            .is_err(),
        "accepted stalled outbound socket must not create a session before handshake"
    );
}
