use std::{
    io::{self, Read, Write},
    net::{IpAddr, Shutdown, SocketAddr, TcpStream},
    thread,
    time::Duration,
};

use futures::channel;
use tentacle::{
    async_trait,
    builder::ServiceBuilder,
    context::ServiceContext,
    multiaddr::{Multiaddr, Protocol},
    secio::SecioKeyPair,
    service::ServiceEvent,
    traits::ServiceHandle,
};

struct EmptyHandle;

#[async_trait]
impl ServiceHandle for EmptyHandle {
    async fn handle_event(&mut self, _context: &mut ServiceContext, _event: ServiceEvent) {}
}

fn socket_addr(listen_addr: &Multiaddr) -> SocketAddr {
    let mut ip = None;
    let mut port = None;
    for protocol in listen_addr.iter() {
        match protocol {
            Protocol::Ip4(addr) => ip = Some(IpAddr::V4(addr)),
            Protocol::Ip6(addr) => ip = Some(IpAddr::V6(addr)),
            Protocol::Tcp(value) => port = Some(value),
            _ => {}
        }
    }
    SocketAddr::new(ip.expect("listen IP"), port.expect("listen port"))
}

fn spawn_server(max_connections: usize, timeout: Duration) -> SocketAddr {
    let (address_sender, address_receiver) = channel::oneshot::channel();
    thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let mut service = ServiceBuilder::default()
            .handshake_type(SecioKeyPair::secp256k1_generated().into())
            .max_connection_number(max_connections)
            .timeout(timeout)
            .build(EmptyHandle);
        runtime.block_on(async move {
            let listen_addr = service
                .listen("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"))
                .await
                .expect("listen");
            address_sender.send(listen_addr).expect("send address");
            service.run().await;
        });
    });

    socket_addr(&futures::executor::block_on(address_receiver).expect("receive address"))
}

fn connect_stalled(address: SocketAddr, read_timeout: Duration) -> TcpStream {
    let stream = TcpStream::connect(address).expect("connect");
    stream
        .set_read_timeout(Some(read_timeout))
        .expect("set read timeout");
    stream
}

fn assert_stream_closed(mut stream: TcpStream) {
    let mut byte = [0; 1];
    match stream.read(&mut byte) {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
            ) => {}
        result => panic!("expected server to close the stream, got {result:?}"),
    }
}

fn assert_stream_open(mut stream: TcpStream) {
    let mut byte = [0; 1];
    match stream.read(&mut byte) {
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) => {}
        result => panic!("expected stream to remain open, got {result:?}"),
    }
}

#[test]
fn stalled_inbound_connections_are_limited_before_handshake() {
    let address = spawn_server(2, Duration::from_secs(10));
    let mut stalled = vec![
        connect_stalled(address, Duration::from_secs(2)),
        connect_stalled(address, Duration::from_secs(2)),
    ];
    thread::sleep(Duration::from_millis(200));

    let rejected = connect_stalled(address, Duration::from_secs(2));
    assert_stream_closed(rejected);

    let released = stalled.pop().expect("stalled connection");
    released.shutdown(Shutdown::Both).expect("shutdown");
    drop(released);
    thread::sleep(Duration::from_millis(200));

    let replacement = connect_stalled(address, Duration::from_millis(300));
    assert_stream_open(replacement);
}

#[test]
fn partial_protocol_prefix_obeys_detection_timeout() {
    let address = spawn_server(1, Duration::from_millis(200));
    let mut stream = connect_stalled(address, Duration::from_secs(2));
    stream.write_all(b"x").expect("write partial prefix");
    assert_stream_closed(stream);

    let replacement = connect_stalled(address, Duration::from_millis(100));
    assert_stream_open(replacement);
}
