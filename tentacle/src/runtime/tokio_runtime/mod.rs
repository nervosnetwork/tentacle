use super::proxy::socks5_config;
use multiaddr::MultiAddr;
pub use tokio::{
    net::{TcpListener, TcpStream},
    spawn,
    task::{block_in_place, spawn_blocking, yield_now, JoinHandle},
};

use crate::service::{
    config::{TcpSocket, TcpSocketConfig, TcpSocketTransformer},
    ProxyConfig,
};
use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
#[cfg(unix)]
use std::os::unix::io::{FromRawFd, IntoRawFd};
#[cfg(windows)]
use std::os::windows::io::{FromRawSocket, IntoRawSocket};
use std::{io, net::SocketAddr, str::FromStr};
use tokio::net::TcpSocket as TokioTcp;

#[cfg(feature = "tokio-timer")]
pub use {
    time::{interval, Interval},
    tokio::time::{sleep as delay_for, timeout, MissedTickBehavior, Sleep as Delay, Timeout},
};

#[cfg(feature = "tokio-timer")]
mod time {
    use futures::Stream;
    use std::{
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };
    use tokio::time::{
        interval_at as inner_interval, Instant, Interval as Inner, MissedTickBehavior,
    };

    pub struct Interval(Inner);

    impl Interval {
        /// Same as tokio::time::interval
        pub fn new(period: Duration) -> Self {
            Self::new_at(Duration::ZERO, period)
        }

        /// Same as tokio::time::interval_at
        pub fn new_at(start_since_now: Duration, period: Duration) -> Self {
            Self(inner_interval(Instant::now() + start_since_now, period))
        }

        pub fn set_missed_tick_behavior(&mut self, behavior: MissedTickBehavior) {
            self.0.set_missed_tick_behavior(behavior);
        }
    }

    impl Stream for Interval {
        type Item = ();

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<()>> {
            match self.0.poll_tick(cx) {
                Poll::Ready(_) => Poll::Ready(Some(())),
                Poll::Pending => Poll::Pending,
            }
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            (usize::MAX, None)
        }
    }

    pub fn interval(period: Duration) -> Interval {
        Interval::new(period)
    }
}

pub(crate) fn listen(addr: SocketAddr, tcp_config: TcpSocketConfig) -> io::Result<TcpListener> {
    let domain = Domain::for_address(addr);
    let socket = Socket::new(domain, Type::STREAM, Some(SocketProtocol::TCP))?;

    // reuse addr and reuse port's situation on each platform
    // https://stackoverflow.com/questions/14388706/how-do-so-reuseaddr-and-so-reuseport-differ

    let socket = {
        // On platforms with Berkeley-derived sockets, this allows to quickly
        // rebind a socket, without needing to wait for the OS to clean up the
        // previous one.
        //
        // On Windows, this allows rebinding sockets which are actively in use,
        // which allows “socket hijacking”, so we explicitly don't set it here.
        // https://docs.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse
        //
        // user can disable it on tcp_config
        #[cfg(not(windows))]
        socket.set_reuse_address(true)?;
        let t = (tcp_config.tcp_socket_config)(TcpSocket { inner: socket })?;
        t.inner.set_nonblocking(true)?;
        // safety: fd convert by socket2
        unsafe {
            #[cfg(unix)]
            let socket = TokioTcp::from_raw_fd(t.into_raw_fd());
            #[cfg(windows)]
            let socket = TokioTcp::from_raw_socket(t.into_raw_socket());
            socket
        }
    };
    // `bind` twice will return error
    //
    // code 22 means:
    // EINVAL The socket is already bound to an address.
    // ref: https://man7.org/linux/man-pages/man2/bind.2.html
    if let Err(e) = socket.bind(addr) {
        if Some(22) != e.raw_os_error() {
            return Err(e);
        }
    }

    socket.listen(1024)
}

async fn connect_direct(
    addr: SocketAddr,
    tcp_socket_transformer: TcpSocketTransformer,
) -> io::Result<TcpStream> {
    let domain = Domain::for_address(addr);
    let socket = Socket::new(domain, Type::STREAM, Some(SocketProtocol::TCP))?;

    let socket = {
        let t = tcp_socket_transformer(TcpSocket { inner: socket })?;
        t.inner.set_nonblocking(true)?;
        // safety: fd convert by socket2
        unsafe {
            #[cfg(unix)]
            let socket = TokioTcp::from_raw_fd(t.into_raw_fd());
            #[cfg(windows)]
            let socket = TokioTcp::from_raw_socket(t.into_raw_socket());
            socket
        }
    };

    socket.connect(addr).await
}

async fn connect_by_proxy<A>(
    target_addr: A,
    tcp_socket_transformer: TcpSocketTransformer,
    proxy_config: ProxyConfig,
) -> io::Result<TcpStream>
where
    A: Into<shadowsocks::relay::Address>,
{
    let socks5_config = socks5_config::parse(&proxy_config.proxy_url)?;

    let dial_addr: SocketAddr = socks5_config.proxy_url.parse().map_err(io::Error::other)?;
    let stream = connect_direct(dial_addr, tcp_socket_transformer).await?;

    super::proxy::socks5::establish_connection(stream, target_addr, socks5_config)
        .await
        .map_err(io::Error::other)
}

pub(crate) async fn connect(
    target_addr: SocketAddr,
    tcp_config: TcpSocketConfig,
) -> io::Result<TcpStream> {
    let TcpSocketConfig {
        tcp_socket_config,
        proxy_config,
    } = tcp_config;

    match proxy_config {
        Some(proxy_config) => connect_by_proxy(target_addr, tcp_socket_config, proxy_config).await,
        None => connect_direct(target_addr, tcp_socket_config).await,
    }
}

pub(crate) async fn connect_onion(
    onion_addr: MultiAddr,
    tcp_config: TcpSocketConfig,
) -> io::Result<TcpStream> {
    let TcpSocketConfig {
        tcp_socket_config,
        proxy_config,
    } = tcp_config;
    let proxy_config = proxy_config.ok_or(io::Error::other(
        "need tor proxy server to connect to onion address",
    ))?;
    let onion_protocol = onion_addr.iter().next().ok_or(io::Error::other(
        "connect_onion need Protocol::Onion3 multiaddr",
    ))?;
    // onion_str looks like: "/onion3/wsglappcvp4y4e2ff3ubowpkoxuoaudzvmih6gc54442vfabebwf42ad:8114"
    let onion_str = onion_protocol.to_string();
    // remove prefix "/onion3/", if not contains /onion3/, return error
    let onion_str = onion_str
        .strip_prefix("/onion3/")
        .ok_or(io::Error::other(format!(
            "connect_onion need Protocol::Onion3 multiaddr, but got {}",
            onion_str
        )))?;
    let onion_str = onion_str.replace(":", ".onion:");
    let onion_address =
        shadowsocks::relay::Address::from_str(&onion_str).map_err(std::io::Error::other)?;

    connect_by_proxy(onion_address, tcp_socket_config, proxy_config).await
}
