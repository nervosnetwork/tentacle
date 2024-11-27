use std::{
    collections::{hash_map::Entry, HashMap},
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};

use futures::{
    channel::mpsc::{self, Receiver, Sender},
    SinkExt, Stream,
};
use log::debug;

#[cfg(any(feature = "ws", feature = "tls"))]
use crate::multiaddr::Protocol;
#[cfg(feature = "ws")]
use {crate::transports::ws::WsStream, tokio_tungstenite::accept_async};
#[cfg(feature = "tls")]
use {
    crate::{service::TlsConfig, transports::parse_tls_domain_name},
    std::borrow::Cow,
    tokio_rustls::{
        rustls::{server::ResolvesServerCertUsingSni, ServerConfig},
        TlsAcceptor,
    },
};

use crate::{
    multiaddr::Multiaddr,
    runtime::{TcpListener, TcpStream},
    service::config::TcpSocketConfig,
    transports::{tcp_listen, MultiStream, Result, TransportErrorKind},
    utils::{multiaddr_to_socketaddr, socketaddr_to_multiaddr},
};

pub enum TcpBaseListenerEnum {
    Upgrade,
    New(TcpBaseListener),
}

/// Tcp listen bind
pub async fn bind(
    address: impl Future<Output = Result<Multiaddr>>,
    tcp_config: TcpSocketConfig,
    self_mode: UpgradeMode,
    #[cfg(feature = "tls")] config: TlsConfig,
    global: Arc<crate::lock::Mutex<HashMap<SocketAddr, UpgradeMode>>>,
    timeout: Duration,
) -> Result<(Multiaddr, TcpBaseListenerEnum)> {
    let addr = address.await?;
    match multiaddr_to_socketaddr(&addr) {
        Some(socket_address) => {
            // Global register global listener upgrade mode
            match global.clone().lock().entry(socket_address) {
                Entry::Occupied(v) => {
                    #[allow(unused_mut)]
                    let mut tcp_base_addr: Multiaddr = socketaddr_to_multiaddr(socket_address);
                    let listen_addr = match self_mode.to_enum() {
                        UpgradeModeEnum::OnlyTcp => tcp_base_addr,
                        #[cfg(feature = "ws")]
                        UpgradeModeEnum::OnlyWs => {
                            tcp_base_addr.push(Protocol::Ws);
                            tcp_base_addr
                        }
                        #[cfg(feature = "tls")]
                        UpgradeModeEnum::OnlyTLS => {
                            match parse_tls_domain_name(&addr) {
                                None => return Err(TransportErrorKind::NotSupported(addr)),
                                Some(d) => {
                                    tcp_base_addr.push(Protocol::Tls(Cow::Owned(d)));
                                }
                            }
                            tcp_base_addr
                        }
                        #[allow(unreachable_patterns)]
                        _ => unreachable!(),
                    };
                    v.get().combine(self_mode);
                    return Ok((listen_addr, TcpBaseListenerEnum::Upgrade));
                }
                Entry::Vacant(v) => {
                    v.insert(self_mode.clone());
                }
            }
            let (local_addr, tcp) = tcp_listen(socket_address, tcp_config).await?;

            #[allow(unused_mut)]
            let mut tcp_base_addr: Multiaddr = socketaddr_to_multiaddr(local_addr);
            let listen_addr = match self_mode.to_enum() {
                UpgradeModeEnum::OnlyTcp => tcp_base_addr,
                #[cfg(feature = "ws")]
                UpgradeModeEnum::OnlyWs => {
                    tcp_base_addr.push(Protocol::Ws);
                    tcp_base_addr
                }
                #[cfg(feature = "tls")]
                UpgradeModeEnum::OnlyTLS => {
                    match parse_tls_domain_name(&addr) {
                        None => return Err(TransportErrorKind::NotSupported(addr)),
                        Some(d) => {
                            tcp_base_addr.push(Protocol::Tls(Cow::Owned(d)));
                        }
                    }
                    tcp_base_addr
                }
                #[allow(unreachable_patterns)]
                _ => unreachable!(),
            };
            #[cfg(feature = "tls")]
            let tls_server_config = if matches!(self_mode.to_enum(), UpgradeModeEnum::OnlyTLS) {
                config.tls_server_config.ok_or_else(|| {
                    TransportErrorKind::TlsError("server config not found".to_string())
                })?
            } else {
                Arc::new(
                    ServerConfig::builder()
                        .with_no_client_auth()
                        .with_cert_resolver(Arc::new(ResolvesServerCertUsingSni::new())),
                )
            };
            Ok((
                listen_addr,
                TcpBaseListenerEnum::New({
                    let tcp_listen =
                        TcpBaseListener::new(timeout, tcp, local_addr, self_mode, global);
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
    pub fn only_tcp() -> Self {
        Self {
            inner: Arc::new(AtomicU8::new(0b1)),
        }
    }

    pub fn combine(&self, other: UpgradeMode) {
        let other = other.inner.load(Ordering::Acquire);
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

#[repr(u8)]
pub enum UpgradeModeEnum {
    OnlyTcp = 0b1,
    #[cfg(feature = "ws")]
    OnlyWs = 0b10,
    #[cfg(feature = "tls")]
    OnlyTLS = 0b100,
    #[cfg(feature = "ws")]
    TcpAndWs = 0b11,
    #[cfg(feature = "tls")]
    TcpAndTLS = 0b101,
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
            0b100 => UpgradeModeEnum::OnlyTLS,
            #[cfg(feature = "tls")]
            0b101 => UpgradeModeEnum::TcpAndTLS,
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
    sender: Sender<(Multiaddr, MultiStream)>,
    pending_stream: Receiver<(Multiaddr, MultiStream)>,
    global: Arc<crate::lock::Mutex<HashMap<SocketAddr, UpgradeMode>>>,
    #[cfg(feature = "tls")]
    tls_config: Arc<ServerConfig>,
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
            tls_config: Arc::new(
                ServerConfig::builder()
                    .with_no_client_auth()
                    .with_cert_resolver(Arc::new(ResolvesServerCertUsingSni::new())),
            ),
        }
    }

    #[cfg(feature = "tls")]
    fn tls_config(mut self, tls_config: Arc<ServerConfig>) -> Self {
        self.tls_config = tls_config;
        self
    }

    fn poll_pending(&mut self, cx: &mut Context) -> Poll<(Multiaddr, MultiStream)> {
        match Pin::new(&mut self.pending_stream).as_mut().poll_next(cx) {
            Poll::Ready(Some(res)) => Poll::Ready(res),
            Poll::Ready(None) | Poll::Pending => Poll::Pending,
        }
    }

    fn poll_listen(&mut self, cx: &mut Context) -> Poll<std::result::Result<(), io::Error>> {
        match self.inner.poll_accept(cx)? {
            Poll::Ready((stream, _)) => {
                // Why can't get the peer address of the connected stream ?
                // Error will be "Transport endpoint is not connected",
                // so why incoming will appear unconnected stream ?
                match stream.peer_addr() {
                    Ok(remote_address) => {
                        let timeout = self.timeout;
                        let sender = self.sender.clone();
                        let upgrade_mode = self.upgrade_mode.to_enum();
                        #[cfg(feature = "tls")]
                        let acceptor = TlsAcceptor::from(Arc::clone(&self.tls_config));
                        crate::runtime::spawn(async move {
                            protocol_select(
                                stream,
                                timeout,
                                upgrade_mode,
                                sender,
                                remote_address,
                                #[cfg(feature = "tls")]
                                acceptor,
                            )
                            .await
                        });
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
    type Item = std::result::Result<(Multiaddr, MultiStream), io::Error>;

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

async fn protocol_select(
    stream: TcpStream,
    #[allow(unused_variables)] timeout: Duration,
    #[allow(unused_mut)] mut upgrade_mode: UpgradeModeEnum,
    mut sender: Sender<(Multiaddr, MultiStream)>,
    remote_address: SocketAddr,
    #[cfg(feature = "tls")] acceptor: TlsAcceptor,
) {
    loop {
        match upgrade_mode {
            UpgradeModeEnum::OnlyTcp => {
                if sender
                    .send((
                        socketaddr_to_multiaddr(remote_address),
                        MultiStream::Tcp(stream),
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
                match crate::runtime::timeout(timeout, accept_async(stream)).await {
                    Err(_) => debug!("accept websocket stream timeout"),
                    Ok(res) => match res {
                        Ok(stream) => {
                            let mut addr = socketaddr_to_multiaddr(remote_address);
                            addr.push(Protocol::Ws);
                            if sender
                                .send((addr, MultiStream::Ws(Box::new(WsStream::new(stream)))))
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
            UpgradeModeEnum::OnlyTLS => {
                match crate::runtime::timeout(timeout, acceptor.accept(stream)).await {
                    Err(_) => debug!("accept tls server stream timeout"),
                    Ok(res) => match res {
                        Ok(stream) => {
                            let mut addr = socketaddr_to_multiaddr(remote_address);
                            addr.push(Protocol::Tls(Cow::Borrowed("")));
                            if sender
                                .send((addr, MultiStream::Tls(Box::new(stream))))
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
            UpgradeModeEnum::TcpAndTLS => {
                let mut peek_buf = [0u8; 16];
                if let Err(e) = stream.peek(&mut peek_buf).await {
                    debug!("stream encountered err: {}, close unexpectedly", e);
                    return;
                }

                // The first sixteen bytes of secio proposol are fixed
                // it's molecule bytes is
                // molecule header u32 = 4 of u8
                // field count = 5 + 1 of u8
                // rand len = 16 of u8
                // it's always [0, 0, 0, 173, 173, 0, 0, 0, 24, 0, 0, 0, 44, 0, 0, 0]
                if peek_buf == [0, 0, 0, 173, 173, 0, 0, 0, 24, 0, 0, 0, 44, 0, 0, 0] {
                    upgrade_mode = UpgradeModeEnum::OnlyTcp;
                    continue;
                } else {
                    upgrade_mode = UpgradeModeEnum::OnlyTLS;
                    continue;
                }
            }
            #[cfg(feature = "ws")]
            UpgradeModeEnum::TcpAndWs => {
                let mut peek_buf = [0u8; 16];
                if let Err(e) = stream.peek(&mut peek_buf).await {
                    debug!("stream encountered err: {}, close unexpectedly", e);
                    return;
                }
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
                let mut peek_buf = [0u8; 16];
                if let Err(e) = stream.peek(&mut peek_buf).await {
                    debug!("stream encountered err: {}, close unexpectedly", e);
                    return;
                }

                let mut headers = [httparse::EMPTY_HEADER; 16];
                let mut req = httparse::Request::new(&mut headers);

                match req.parse(&peek_buf) {
                    Ok(_) => {
                        upgrade_mode = UpgradeModeEnum::OnlyWs;
                        continue;
                    }
                    Err(_) => {
                        upgrade_mode = UpgradeModeEnum::TcpAndTLS;
                        continue;
                    }
                }
            }
        }
    }
}
