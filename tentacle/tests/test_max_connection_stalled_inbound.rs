use std::{
    io::{self, Read},
    net::{IpAddr, Shutdown, SocketAddr, TcpStream as StdTcpStream},
    thread,
    time::Duration,
};

use futures::channel;
use tentacle::{
    ProtocolId, async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::ServiceContext,
    multiaddr::{Multiaddr, Protocol},
    secio::SecioKeyPair,
    service::{ProtocolHandle, ProtocolMeta, Service, ServiceEvent},
    traits::ServiceHandle,
};

const MAX_CONNECTIONS: usize = 2;

struct ServerHandle {
    session_open_sender: crossbeam_channel::Sender<()>,
}

#[async_trait]
impl ServiceHandle for ServerHandle {
    async fn handle_event(&mut self, _env: &mut ServiceContext, event: ServiceEvent) {
        if let ServiceEvent::SessionOpen { .. } = event {
            self.session_open_sender.send(()).unwrap();
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
        .timeout(Duration::from_secs(1))
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

    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create_service(ServerHandle {
            session_open_sender,
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
