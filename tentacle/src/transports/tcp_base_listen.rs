use std::{
    collections::{HashMap, hash_map::Entry},
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use futures::{
    SinkExt, Stream,
    channel::mpsc::{self, Receiver, Sender},
};
use log::debug;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[cfg(any(feature = "ws", feature = "tls"))]
use crate::multiaddr::Protocol;
#[cfg(feature = "ws")]
use {crate::transports::ws::WsStream, tokio_tungstenite::accept_async};
#[cfg(feature = "tls")]
use {
    crate::{service::TlsConfig, transports::parse_tls_domain_name},
    std::borrow::Cow,
    tokio_rustls::{
        TlsAcceptor,
        rustls::{ServerConfig, server::ResolvesServerCertUsingSni},
    },
};

use crate::{
    multiaddr::Multiaddr,
    runtime::{TcpListener, TcpStream},
    service::config::TcpSocketConfig,
    transports::proxy_protocol::{ProxyProtocolResult, parse_proxy_protocol},
    transports::{MultiStream, Result, TcpListenMode, TransportErrorKind, tcp_listen},
    utils::{multiaddr_to_socketaddr, socketaddr_to_multiaddr},
};

#[cfg(feature = "tls")]
fn default_tls_server_config() -> ServerConfig {
    ServerConfig::builder_with_provider(
        tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .expect("the aws-lc-rs provider supports rustls default protocol versions")
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(ResolvesServerCertUsingSni::new()))
}

pub enum TcpBaseListenerEnum {
    Upgrade,
    New(TcpBaseListener),
}

/// Tcp listen bind
#[allow(clippy::too_many_arguments)]
pub async fn bind(
    address: impl Future<Output = Result<Multiaddr>>,
    tcp_config: TcpSocketConfig,
    listen_mode: TcpListenMode,
    #[cfg(feature = "tls")] config: TlsConfig,
    global: Arc<crate::lock::Mutex<HashMap<SocketAddr, UpgradeMode>>>,
    timeout: Duration,
    trusted_proxies: Arc<Vec<IpAddr>>,
    connection_limiter: Option<Arc<Semaphore>>,
) -> Result<(Multiaddr, TcpBaseListenerEnum)> {
    let addr = address.await?;
    let upgrade_mode: UpgradeMode = listen_mode.into();
    match multiaddr_to_socketaddr(&addr) {
        Some(socket_address) => {
            let (local_addr, tcp) = if socket_address.port() == 0 {
                // this branch must be unique address
                let (local_addr, tcp) = tcp_listen(socket_address, tcp_config).await?;
                global
                    .clone()
                    .lock()
                    .insert(local_addr, upgrade_mode.clone());
                (local_addr, tcp)
            } else {
                // Global register global listener upgrade mode
                match global.clone().lock().entry(socket_address) {
                    Entry::Occupied(v) => {
                        #[allow(unused_mut)]
                        let mut tcp_base_addr: Multiaddr = socketaddr_to_multiaddr(socket_address);
                        let listen_addr = match listen_mode {
                            TcpListenMode::Tcp => tcp_base_addr,
                            #[cfg(feature = "ws")]
                            TcpListenMode::Ws => {
                                tcp_base_addr.push(Protocol::Ws);
                                tcp_base_addr
                            }
                            #[cfg(feature = "tls")]
                            TcpListenMode::Tls => {
                                match parse_tls_domain_name(&addr) {
                                    None => return Err(TransportErrorKind::NotSupported(addr)),
                                    Some(d) => {
                                        tcp_base_addr.push(Protocol::Tls(Cow::Owned(d)));
                                    }
                                }
                                tcp_base_addr
                            }
                        };
                        v.get().combine(listen_mode.into());
                        return Ok((listen_addr, TcpBaseListenerEnum::Upgrade));
                    }
                    Entry::Vacant(v) => {
                        v.insert(upgrade_mode.clone());
                    }
                }
                tcp_listen(socket_address, tcp_config).await?
            };
            #[allow(unused_mut)]
            let mut tcp_base_addr: Multiaddr = socketaddr_to_multiaddr(local_addr);
            let listen_addr = match listen_mode {
                TcpListenMode::Tcp => tcp_base_addr,
                #[cfg(feature = "ws")]
                TcpListenMode::Ws => {
                    tcp_base_addr.push(Protocol::Ws);
                    tcp_base_addr
                }
                #[cfg(feature = "tls")]
                TcpListenMode::Tls => {
                    match parse_tls_domain_name(&addr) {
                        None => return Err(TransportErrorKind::NotSupported(addr)),
                        Some(d) => {
                            tcp_base_addr.push(Protocol::Tls(Cow::Owned(d)));
                        }
                    }
                    tcp_base_addr
                }
            };
            #[cfg(feature = "tls")]
            let tls_server_config = config.tls_server_config.unwrap_or(
                // if enable tls but not set tls config, it will use a empty server config
                Arc::new(default_tls_server_config()),
            );

            Ok((
                listen_addr,
                TcpBaseListenerEnum::New({
                    let tcp_listen = TcpBaseListener::new(
                        timeout,
                        tcp,
                        local_addr,
                        upgrade_mode,
                        global,
                        trusted_proxies,
                        connection_limiter,
                    );
                    #[cfg(feature = "tls")]
                    let tcp_listen = tcp_listen.tls_config(tls_server_config);
                    tcp_listen
                }),
            ))
        }
        None => Err(TransportErrorKind::NotSupported(addr)),
    }
}

#[derive(Clone)]
pub(crate) struct UpgradeMode {
    inner: Arc<AtomicU8>,
}

impl UpgradeMode {
    pub fn combine(&self, other: UpgradeModeEnum) {
        let other = other as u8;
        self.inner.fetch_or(other, Ordering::AcqRel);
    }

    pub fn to_enum(&self) -> UpgradeModeEnum {
        self.inner.load(Ordering::Acquire).into()
    }
}

impl From<UpgradeModeEnum> for UpgradeMode {
    fn from(value: UpgradeModeEnum) -> Self {
        Self {
            inner: Arc::new(AtomicU8::from(value as u8)),
        }
    }
}

impl From<TcpListenMode> for UpgradeMode {
    fn from(value: TcpListenMode) -> Self {
        match value {
            TcpListenMode::Tcp => UpgradeModeEnum::OnlyTcp.into(),
            #[cfg(feature = "tls")]
            TcpListenMode::Tls => UpgradeModeEnum::OnlyTls.into(),
            #[cfg(feature = "ws")]
            TcpListenMode::Ws => UpgradeModeEnum::OnlyWs.into(),
        }
    }
}

impl From<TcpListenMode> for UpgradeModeEnum {
    fn from(value: TcpListenMode) -> Self {
        match value {
            TcpListenMode::Tcp => UpgradeModeEnum::OnlyTcp,
            #[cfg(feature = "tls")]
            TcpListenMode::Tls => UpgradeModeEnum::OnlyTls,
            #[cfg(feature = "ws")]
            TcpListenMode::Ws => UpgradeModeEnum::OnlyWs,
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum UpgradeModeEnum {
    OnlyTcp = 0b1,
    #[cfg(feature = "ws")]
    OnlyWs = 0b10,
    #[cfg(feature = "tls")]
    OnlyTls = 0b100,
    #[cfg(feature = "ws")]
    TcpAndWs = 0b11,
    #[cfg(feature = "tls")]
    TcpAndTls = 0b101,
    #[cfg(all(feature = "ws", feature = "tls"))]
    All = 0b111,
}

impl From<u8> for UpgradeModeEnum {
    fn from(value: u8) -> Self {
        match value {
            0b1 => UpgradeModeEnum::OnlyTcp,
            #[cfg(feature = "ws")]
            0b10 => UpgradeModeEnum::OnlyWs,
            #[cfg(feature = "ws")]
            0b11 => UpgradeModeEnum::TcpAndWs,
            #[cfg(feature = "tls")]
            0b100 => UpgradeModeEnum::OnlyTls,
            #[cfg(feature = "tls")]
            0b101 => UpgradeModeEnum::TcpAndTls,
            #[cfg(all(feature = "ws", feature = "tls"))]
            0b111 => UpgradeModeEnum::All,
            _ => unreachable!(),
        }
    }
}

pub struct TcpBaseListener {
    inner: TcpListener,
    upgrade_mode: UpgradeMode,
    timeout: Duration,
    local_addr: SocketAddr,
    sender: Sender<(Multiaddr, MultiStream, Option<OwnedSemaphorePermit>)>,
    pending_stream: Receiver<(Multiaddr, MultiStream, Option<OwnedSemaphorePermit>)>,
    global: Arc<crate::lock::Mutex<HashMap<SocketAddr, UpgradeMode>>>,
    #[cfg(feature = "tls")]
    tls_config: Arc<ServerConfig>,
    /// Trusted proxy addresses for HAProxy PROXY protocol and X-Forwarded-For header parsing.
    trusted_proxies: Arc<Vec<IpAddr>>,
    connection_limiter: Option<Arc<Semaphore>>,
}

impl Drop for TcpBaseListener {
    fn drop(&mut self) {
        self.global.lock().remove(&self.local_addr);
    }
}

impl TcpBaseListener {
    fn new(
        timeout: Duration,
        inner: TcpListener,
        local_addr: SocketAddr,
        upgrade_mode: UpgradeMode,
        global: Arc<crate::lock::Mutex<HashMap<SocketAddr, UpgradeMode>>>,
        trusted_proxies: Arc<Vec<IpAddr>>,
        connection_limiter: Option<Arc<Semaphore>>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(128);

        Self {
            inner,
            timeout,
            upgrade_mode,
            local_addr,
            global,
            sender: tx,
            pending_stream: rx,
            #[cfg(feature = "tls")]
            tls_config: Arc::new(default_tls_server_config()),
            trusted_proxies,
            connection_limiter,
        }
    }

    #[cfg(feature = "tls")]
    fn tls_config(mut self, tls_config: Arc<ServerConfig>) -> Self {
        self.tls_config = tls_config;
        self
    }

    fn poll_pending(
        &mut self,
        cx: &mut Context,
    ) -> Poll<(Multiaddr, MultiStream, Option<OwnedSemaphorePermit>)> {
        match Pin::new(&mut self.pending_stream).as_mut().poll_next(cx) {
            Poll::Ready(Some(res)) => Poll::Ready(res),
            Poll::Ready(None) | Poll::Pending => Poll::Pending,
        }
    }

    fn poll_listen(&mut self, cx: &mut Context) -> Poll<std::result::Result<(), io::Error>> {
        match self.inner.poll_accept(cx)? {
            Poll::Ready((stream, _)) => {
                let connection_permit = if let Some(limiter) = self.connection_limiter.as_ref() {
                    match limiter.clone().try_acquire_owned() {
                        Ok(permit) => Some(permit),
                        Err(_) => {
                            debug!("connection limit reached, dropping inbound stream");
                            return Poll::Ready(Ok(()));
                        }
                    }
                } else {
                    None
                };
                // Why can't get the peer address of the connected stream ?
                // Error will be "Transport endpoint is not connected",
                // so why incoming will appear unconnected stream ?
                match stream.peer_addr() {
                    Ok(remote_address) => {
                        let timeout = self.timeout;
                        let sender = self.sender.clone();
                        let upgrade_mode = self.upgrade_mode.to_enum();
                        let trusted_proxies = Arc::clone(&self.trusted_proxies);
                        #[cfg(feature = "tls")]
                        let acceptor = TlsAcceptor::from(Arc::clone(&self.tls_config));
                        crate::runtime::spawn(protocol_select(
                            stream,
                            timeout,
                            upgrade_mode,
                            sender,
                            remote_address,
                            trusted_proxies,
                            connection_permit,
                            #[cfg(feature = "tls")]
                            acceptor,
                        ));
                    }
                    Err(err) => {
                        debug!("stream get peer address error: {:?}", err);
                    }
                }
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Stream for TcpBaseListener {
    type Item =
        std::result::Result<(Multiaddr, MultiStream, Option<OwnedSemaphorePermit>), io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Poll::Ready(res) = self.poll_pending(cx) {
            return Poll::Ready(Some(Ok(res)));
        }

        loop {
            let is_pending = self.poll_listen(cx)?.is_pending();
            match self.poll_pending(cx) {
                Poll::Ready(res) => return Poll::Ready(Some(Ok(res))),
                Poll::Pending => {
                    if is_pending {
                        break;
                    }
                }
            }
        }
        Poll::Pending
    }
}

/// Read a complete protocol prefix without consuming it. Use the same bounded
/// detector both before and after consuming a trusted PROXY header.
async fn peek_protocol_prefix(stream: &TcpStream, timeout: Duration) -> io::Result<[u8; 16]> {
    peek_protocol_prefix_with(timeout, || async {
        let mut prefix = [0u8; 16];
        let n = stream.peek(&mut prefix).await?;
        Ok((n, prefix))
    })
    .await
}

async fn peek_protocol_prefix_with<F, Fut>(timeout: Duration, mut peek: F) -> io::Result<[u8; 16]>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = io::Result<(usize, [u8; 16])>>,
{
    crate::runtime::timeout(timeout, async {
        loop {
            let (n, prefix) = peek().await?;
            match n {
                16 => return Ok(prefix),
                0 => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed during protocol detection",
                    ));
                }
                _ => {
                    // Partial peeked bytes remain immediately readable. Yield
                    // so both the deadline and other tasks can make progress.
                    crate::runtime::delay_for(Duration::from_millis(10)).await;
                }
            }
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "protocol detection timed out"))?
}

#[allow(clippy::too_many_arguments)]
async fn protocol_select(
    mut stream: TcpStream,
    timeout: Duration,
    #[allow(unused_mut)] mut upgrade_mode: UpgradeModeEnum,
    mut sender: Sender<(Multiaddr, MultiStream, Option<OwnedSemaphorePermit>)>,
    #[allow(unused_mut)] mut remote_address: SocketAddr,
    trusted_proxies: Arc<Vec<IpAddr>>,
    connection_permit: Option<OwnedSemaphorePermit>,
    #[cfg(feature = "tls")] acceptor: TlsAcceptor,
) {
    #[cfg_attr(not(any(feature = "tls", feature = "ws")), allow(unused_variables))]
    let peek_buf = match peek_protocol_prefix(&stream, timeout).await {
        Ok(prefix) => prefix,
        Err(error) => {
            debug!(
                "stream encountered error during protocol detection: {}",
                error
            );
            return;
        }
    };

    // Track whether PROXY protocol has been parsed (to avoid double parsing when
    // TcpAndTls continues to OnlyTcp or OnlyTls)
    #[allow(unused_mut)]
    let mut proxy_parsed = false;

    #[allow(clippy::never_loop)]
    loop {
        match upgrade_mode {
            UpgradeModeEnum::OnlyTcp => {
                // Check if connection is from trusted proxy and try to parse PROXY protocol
                if !proxy_parsed
                    && trusted_proxies.contains(&remote_address.ip())
                    && try_parse_proxy_protocol(&mut stream, timeout, &mut remote_address)
                        .await
                        .is_err()
                {
                    return;
                }

                if sender
                    .send((
                        socketaddr_to_multiaddr(remote_address),
                        MultiStream::Tcp(stream),
                        connection_permit,
                    ))
                    .await
                    .is_err()
                {
                    debug!("receiver closed unexpectedly")
                }
                return;
            }
            #[cfg(feature = "ws")]
            UpgradeModeEnum::OnlyWs => {
                // Check if connection is from trusted proxy and try to extract X-Forwarded-For
                if trusted_proxies.contains(&remote_address.ip()) {
                    remote_address =
                        extract_forwarded_for_from_ws_handshake(&stream, remote_address).await;
                }

                match crate::runtime::timeout(timeout, accept_async(stream)).await {
                    Err(_) => {
                        debug!("accept websocket stream timeout");
                    }
                    Ok(res) => match res {
                        Ok(stream) => {
                            let mut addr = socketaddr_to_multiaddr(remote_address);
                            addr.push(Protocol::Ws);
                            if sender
                                .send((
                                    addr,
                                    MultiStream::Ws(Box::new(WsStream::new(stream))),
                                    connection_permit,
                                ))
                                .await
                                .is_err()
                            {
                                debug!("receiver closed unexpectedly")
                            }
                        }
                        Err(err) => {
                            debug!("accept websocket stream err: {:?}", err);
                        }
                    },
                }
                return;
            }
            #[cfg(feature = "tls")]
            UpgradeModeEnum::OnlyTls => {
                // Check if connection is from trusted proxy and try to parse PROXY protocol
                if !proxy_parsed
                    && trusted_proxies.contains(&remote_address.ip())
                    && try_parse_proxy_protocol(&mut stream, timeout, &mut remote_address)
                        .await
                        .is_err()
                {
                    return;
                }

                match crate::runtime::timeout(timeout, acceptor.accept(stream)).await {
                    Err(_) => debug!("accept tls server stream timeout"),
                    Ok(res) => match res {
                        Ok(stream) => {
                            let mut addr = socketaddr_to_multiaddr(remote_address);
                            addr.push(Protocol::Tls(Cow::Borrowed("")));
                            if sender
                                .send((addr, MultiStream::Tls(Box::new(stream)), connection_permit))
                                .await
                                .is_err()
                            {
                                debug!("receiver closed unexpectedly")
                            }
                        }
                        Err(err) => {
                            debug!("accept tls server stream err: {:?}", err);
                        }
                    },
                }
                return;
            }
            #[cfg(feature = "tls")]
            UpgradeModeEnum::TcpAndTls => {
                // Parse PROXY protocol first if from trusted proxy, then re-peek for protocol detection
                let current_peek_buf = if trusted_proxies.contains(&remote_address.ip()) {
                    match crate::runtime::timeout(timeout, parse_proxy_protocol(&mut stream)).await
                    {
                        Ok(ProxyProtocolResult::Success(addr)) => {
                            debug!(
                                "PROXY protocol parsed successfully: {} -> {}",
                                remote_address, addr
                            );
                            proxy_parsed = true;
                            remote_address = addr;
                            // After parsing PROXY protocol, we need to peek fresh data
                            match peek_protocol_prefix(&stream, timeout).await {
                                Ok(prefix) => prefix,
                                Err(error) => {
                                    debug!(
                                        "protocol detection failed after PROXY parsing: {}",
                                        error
                                    );
                                    return;
                                }
                            }
                        }
                        Ok(ProxyProtocolResult::NotProxyProtocol) => {
                            debug!("Not a PROXY protocol connection from {}", remote_address);
                            proxy_parsed = true;
                            peek_buf
                        }
                        Ok(ProxyProtocolResult::Error(e)) => {
                            log::warn!(
                                "PROXY protocol parse error from trusted proxy {}: {}",
                                remote_address,
                                e
                            );
                            return;
                        }
                        Err(_) => {
                            log::warn!(
                                "PROXY protocol parse timeout from trusted proxy {}",
                                remote_address
                            );
                            return;
                        }
                    }
                } else {
                    peek_buf
                };

                // The first sixteen bytes of secio's Propose message's mode is fixed
                // it's bytes like follow:
                //
                // | 4 byte | 4 byte | 4 byte | 4 byte | 4 byte |...
                // |--|--|--|--|--|
                // | LengthDelimitedCodec header| molecule propose header | rand start | rand end/pubkey start | pubkey end/exchange start |...
                //
                // LengthDelimitedCodec header is big-end total len
                // molecule propose header is little-end total len
                // rand start offset is 24 = (5(feild count) + 1(total len))* 4
                let length_delimited_header = u32::from_be_bytes(
                    TryInto::<[u8; 4]>::try_into(&current_peek_buf[..4]).unwrap(),
                );
                let molecule_header = u32::from_le_bytes(
                    TryInto::<[u8; 4]>::try_into(&current_peek_buf[4..8]).unwrap(),
                );
                let rand_start = u32::from_le_bytes(
                    TryInto::<[u8; 4]>::try_into(&current_peek_buf[8..12]).unwrap(),
                );
                let rand_end = u32::from_le_bytes(
                    TryInto::<[u8; 4]>::try_into(&current_peek_buf[12..16]).unwrap(),
                );

                // The first twelve bytes of yamux's message's mode is fixed
                // it's bytes like follow:
                // | byte | byte | 2 byte | 4 byte | 4 byte | ...
                // |--|--|--|--|--|
                // | version | type | flags(big-end) | steam_id(big-end) | header_len(big-end) |...
                //
                // yamux version is fixed = 0x0
                // open window message type = 0x1, ping message type = 0x2
                // flags is Syn = 0x1
                // open window message stream id = 0x1(client standard implementation, but does not check, but can't be zero), ping message steam id = 0x0
                // header_len is not a fixed value.
                // It may be the ping_id or the window length value expressed in windowupdate.
                let yamux_version = current_peek_buf[0];
                let yamux_ty = current_peek_buf[1];
                let yamux_flags = u16::from_be_bytes(
                    TryInto::<[u8; 2]>::try_into(&current_peek_buf[2..4]).unwrap(),
                );
                let yamux_stream_id = u32::from_be_bytes(
                    TryInto::<[u8; 4]>::try_into(&current_peek_buf[4..8]).unwrap(),
                );

                if (length_delimited_header == molecule_header
                    && rand_start == 24
                    && rand_start < rand_end
                    && rand_end < molecule_header)
                    || (yamux_version == 0
                        && ((yamux_ty == 0x1 && yamux_stream_id != 0)
                            || (yamux_ty == 0x2 && yamux_stream_id == 0))
                        && yamux_flags == 0x1)
                {
                    upgrade_mode = UpgradeModeEnum::OnlyTcp;
                    continue;
                } else {
                    upgrade_mode = UpgradeModeEnum::OnlyTls;
                    continue;
                }
            }
            #[cfg(feature = "ws")]
            UpgradeModeEnum::TcpAndWs => {
                let mut headers = [httparse::EMPTY_HEADER; 16];
                let mut req = httparse::Request::new(&mut headers);

                match req.parse(&peek_buf) {
                    Ok(_) => {
                        upgrade_mode = UpgradeModeEnum::OnlyWs;
                        continue;
                    }
                    Err(_) => {
                        upgrade_mode = UpgradeModeEnum::OnlyTcp;
                        continue;
                    }
                }
            }
            #[cfg(all(feature = "ws", feature = "tls"))]
            UpgradeModeEnum::All => {
                let mut headers = [httparse::EMPTY_HEADER; 16];
                let mut req = httparse::Request::new(&mut headers);

                match req.parse(&peek_buf) {
                    Ok(_) => {
                        upgrade_mode = UpgradeModeEnum::OnlyWs;
                        continue;
                    }
                    Err(_) => {
                        upgrade_mode = UpgradeModeEnum::TcpAndTls;
                        continue;
                    }
                }
            }
        }
    }
}

/// Try to parse PROXY protocol from stream.
/// Returns Ok is successful.
async fn try_parse_proxy_protocol(
    stream: &mut TcpStream,
    timeout: Duration,
    remote_address: &mut SocketAddr,
) -> std::result::Result<(), ()> {
    match crate::runtime::timeout(timeout, parse_proxy_protocol(stream)).await {
        Ok(ProxyProtocolResult::Success(addr)) => {
            debug!(
                "PROXY protocol parsed successfully: {} -> {}",
                remote_address, addr
            );
            *remote_address = addr;
            Ok(())
        }
        Ok(ProxyProtocolResult::NotProxyProtocol) => {
            debug!("Not a PROXY protocol connection from {}", remote_address);
            Ok(())
        }
        Ok(ProxyProtocolResult::Error(e)) => {
            log::warn!(
                "PROXY protocol parse error from trusted proxy {}: {}",
                remote_address,
                e
            );
            Err(())
        }
        Err(_) => {
            log::warn!(
                "PROXY protocol parse timeout from trusted proxy {}",
                remote_address
            );
            Err(())
        }
    }
}

/// Extract X-Forwarded-For from WebSocket HTTP upgrade request using peek
/// This function peeks the HTTP headers without consuming them, so the WebSocket
/// handshake can proceed normally afterwards.
///
/// # Security Warning
///
/// This function takes the FIRST IP from the X-Forwarded-For header chain.
/// In a multi-proxy setup (Client -> Proxy1 -> Proxy2 -> Server), a malicious
/// client could forge the first IP. For maximum security with multiple proxies,
/// you should know how many trusted proxies are in front of your server and
/// count from the right side of the chain.
///
/// Current behavior is suitable for single-proxy setups where only one trusted
/// proxy directly connects to the server.
#[cfg(feature = "ws")]
async fn extract_forwarded_for_from_ws_handshake(
    stream: &TcpStream,
    fallback_address: SocketAddr,
) -> SocketAddr {
    use std::net::IpAddr;

    // Peek enough bytes to read HTTP headers (4KB should be enough for most cases)
    let mut peek_buf = [0u8; 4096];
    let n = match stream.peek(&mut peek_buf).await {
        Ok(n) => n,
        Err(_) => return fallback_address,
    };

    // Parse HTTP request headers
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);

    if req.parse(&peek_buf[..n]).is_err() {
        return fallback_address;
    }

    // Look for X-Forwarded-For and X-Forwarded-Port headers
    let mut forwarded_ip: Option<IpAddr> = None;
    let mut forwarded_port: Option<u16> = None;

    for header in req.headers.iter() {
        if header.name.eq_ignore_ascii_case("x-forwarded-for") {
            if let Ok(value_str) = std::str::from_utf8(header.value) {
                // X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
                // We want the first one (the original client)
                if let Some(first_ip) = value_str.split(',').next() {
                    let ip_str = first_ip.trim();
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        forwarded_ip = Some(ip);
                    }
                }
            }
        } else if header.name.eq_ignore_ascii_case("x-forwarded-port") {
            if let Ok(value_str) = std::str::from_utf8(header.value) {
                // X-Forwarded-Port can also contain multiple ports, take the first one
                if let Some(first_port) = value_str.split(',').next() {
                    if let Ok(port) = first_port.trim().parse::<u16>() {
                        forwarded_port = Some(port);
                    }
                }
            }
        }
    }

    match forwarded_ip {
        Some(ip) => {
            // Use X-Forwarded-Port if available, otherwise fallback to the original port
            let port = forwarded_port.unwrap_or(fallback_address.port());
            debug!("X-Forwarded-For header found: {}:{}", ip, port);
            SocketAddr::new(ip, port)
        }
        None => fallback_address,
    }
}

#[cfg(test)]
mod protocol_detection_tests {
    use super::*;
    use futures::future;
    use std::sync::atomic::AtomicUsize;

    #[tokio::test]
    async fn pending_peek_times_out_and_releases_connection_slot() {
        let limiter = Arc::new(Semaphore::new(1));
        let permit = limiter.clone().try_acquire_owned().unwrap();
        let detect = async move {
            let _permit = permit;
            peek_protocol_prefix_with(Duration::from_millis(30), future::pending).await
        };
        let error = crate::runtime::timeout(Duration::from_secs(2), detect)
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(limiter.available_permits(), 1);
    }

    #[tokio::test]
    async fn partial_peek_yields_and_obeys_deadline() {
        let reads = AtomicUsize::new(0);
        let error = peek_protocol_prefix_with(Duration::from_millis(30), || {
            let count = reads.fetch_add(1, Ordering::SeqCst);
            // Fail fast if cooperative waiting is accidentally removed. This
            // also prevents a regressed detector from hanging the test runtime.
            future::ready(if count < 10 {
                Ok((1, [0; 16]))
            } else {
                Err(io::Error::other("detector polled without yielding"))
            })
        })
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(reads.load(Ordering::SeqCst) <= 10);
    }

    #[tokio::test]
    async fn eof_and_io_errors_are_not_retried() {
        for kind in [io::ErrorKind::UnexpectedEof, io::ErrorKind::ConnectionReset] {
            let reads = AtomicUsize::new(0);
            let error = peek_protocol_prefix_with(Duration::from_secs(1), || {
                assert_eq!(reads.fetch_add(1, Ordering::SeqCst), 0);
                future::ready(if kind == io::ErrorKind::UnexpectedEof {
                    Ok((0, [0; 16]))
                } else {
                    Err(io::Error::from(kind))
                })
            })
            .await
            .unwrap_err();
            assert_eq!(error.kind(), kind);
        }
    }

    #[tokio::test]
    async fn completed_prefix_is_returned_after_partial_read() {
        let mut reads = 0;
        let prefix = [7; 16];
        let result = peek_protocol_prefix_with(Duration::from_secs(1), || {
            reads += 1;
            future::ready(Ok((if reads == 1 { 8 } else { 16 }, prefix)))
        })
        .await
        .unwrap();
        assert_eq!(result, prefix);
        assert_eq!(reads, 2);
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn post_proxy_detection_preserves_prefix_address_and_permit() {
        use futures::StreamExt;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Complete, ordinary PROXY + yamux input: no stalled network peer.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (accepted, client) = tokio::join!(
            listener.accept(),
            TcpStream::connect(listener.local_addr().unwrap()),
        );
        let (server, remote) = accepted.unwrap();
        let mut client = client.unwrap();
        let prefix = [0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        client
            .write_all(b"PROXY TCP4 10.0.0.1 127.0.0.1 1234 80\r\n")
            .await
            .unwrap();
        client.write_all(&prefix).await.unwrap();

        let limiter = Arc::new(Semaphore::new(1));
        let permit = limiter.clone().try_acquire_owned().unwrap();
        let (sender, mut receiver) = mpsc::channel(1);
        let select = protocol_select(
            server,
            Duration::from_secs(1),
            UpgradeModeEnum::TcpAndTls,
            sender,
            remote,
            Arc::new(vec![remote.ip()]),
            Some(permit),
            TlsAcceptor::from(Arc::new(default_tls_server_config())),
        );
        let (_, result) = crate::runtime::timeout(Duration::from_secs(2), async {
            tokio::join!(select, receiver.next())
        })
        .await
        .unwrap();
        let (address, stream, permit) = result.expect("TCP stream after PROXY header");
        assert_eq!(address.to_string(), "/ip4/10.0.0.1/tcp/1234");
        assert_eq!(limiter.available_permits(), 0);
        let MultiStream::Tcp(mut stream) = stream else {
            panic!("expected TCP")
        };
        let mut observed = [0; 16];
        crate::runtime::timeout(Duration::from_secs(1), stream.read_exact(&mut observed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(observed, prefix);
        drop(stream);
        drop(permit);
        assert_eq!(limiter.available_permits(), 1);
    }

    /// A peer that sends a trusted PROXY header and then goes silent must not
    /// pin a connection slot. The post-PROXY detector used to `peek` with no
    /// deadline at all, so such a peer held its permit — and its socket —
    /// forever.
    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn post_proxy_silent_peer_releases_connection_slot() {
        use tokio::io::AsyncWriteExt;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (accepted, client) = tokio::join!(
            listener.accept(),
            TcpStream::connect(listener.local_addr().unwrap()),
        );
        let (server, remote) = accepted.unwrap();
        let mut client = client.unwrap();
        // Only the PROXY header: never the protocol prefix that follows it.
        client
            .write_all(b"PROXY TCP4 10.0.0.1 127.0.0.1 1234 80\r\n")
            .await
            .unwrap();

        let limiter = Arc::new(Semaphore::new(1));
        let permit = limiter.clone().try_acquire_owned().unwrap();
        let (sender, _receiver) = mpsc::channel(1);
        let detection_timeout = Duration::from_millis(200);
        crate::runtime::timeout(
            Duration::from_secs(5),
            protocol_select(
                server,
                detection_timeout,
                UpgradeModeEnum::TcpAndTls,
                sender,
                remote,
                Arc::new(vec![remote.ip()]),
                Some(permit),
                TlsAcceptor::from(Arc::new(default_tls_server_config())),
            ),
        )
        .await
        .expect("post-PROXY detection must obey its deadline");
        assert_eq!(
            limiter.available_permits(),
            1,
            "the connection slot must be released"
        );
        // Keep the peer alive for the whole test so the stall is a silent
        // peer rather than a closed socket.
        drop(client);
    }
}
