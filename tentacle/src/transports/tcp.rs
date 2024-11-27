use futures::{future::ok, TryFutureExt};
use std::{
    collections::HashMap, future::Future, net::SocketAddr, pin::Pin, sync::Arc, time::Duration,
};

#[cfg(feature = "tls")]
use crate::service::TlsConfig;
use crate::{
    error::TransportErrorKind,
    multiaddr::Multiaddr,
    runtime::TcpStream,
    service::config::TcpSocketConfig,
    transports::{
        tcp_base_listen::{bind, TcpBaseListenerEnum, UpgradeMode},
        tcp_dial, Result, Transport, TransportFuture,
    },
    utils::{dns::DnsResolver, multiaddr_to_socketaddr},
};

/// Tcp connect
async fn connect(
    address: impl Future<Output = Result<Multiaddr>>,
    timeout: Duration,
    original: Option<Multiaddr>,
    tcp_config: TcpSocketConfig,
) -> Result<(Multiaddr, TcpStream)> {
    let addr = address.await?;
    match multiaddr_to_socketaddr(&addr) {
        Some(socket_address) => {
            let stream = tcp_dial(socket_address, tcp_config, timeout).await?;
            Ok((original.unwrap_or(addr), stream))
        }
        None => Err(TransportErrorKind::NotSupported(original.unwrap_or(addr))),
    }
}

/// Tcp transport
pub struct TcpTransport {
    timeout: Duration,
    tcp_config: TcpSocketConfig,
    self_mode: UpgradeMode,
    global: Arc<crate::lock::Mutex<HashMap<SocketAddr, UpgradeMode>>>,
    #[cfg(feature = "tls")]
    tls_config: TlsConfig,
}

impl TcpTransport {
    pub fn new(timeout: Duration, tcp_config: TcpSocketConfig) -> Self {
        TcpTransport {
            timeout,
            tcp_config,
            self_mode: UpgradeMode::only_tcp(),
            global: Arc::new(crate::lock::Mutex::new(Default::default())),
            #[cfg(feature = "tls")]
            tls_config: TlsConfig::default(),
        }
    }

    pub fn listen_upgrade_modes(
        mut self,
        self_mode: UpgradeMode,
        global: Arc<crate::lock::Mutex<HashMap<SocketAddr, UpgradeMode>>>,
    ) -> Self {
        self.self_mode = self_mode;
        self.global = global;
        self
    }

    #[cfg(feature = "tls")]
    pub fn tls_config(mut self, tls_config: TlsConfig) -> Self {
        self.tls_config = tls_config;
        self
    }
}

// If `Existence type` is available, `Pin<Box<...>>` will no longer be needed here, and the signature is `TransportFuture<impl Future<Output=xxx>>`
pub type TcpListenFuture =
    TransportFuture<Pin<Box<dyn Future<Output = Result<(Multiaddr, TcpBaseListenerEnum)>> + Send>>>;
pub type TcpDialFuture =
    TransportFuture<Pin<Box<dyn Future<Output = Result<(Multiaddr, TcpStream)>> + Send>>>;

impl Transport for TcpTransport {
    type ListenFuture = TcpListenFuture;
    type DialFuture = TcpDialFuture;

    fn listen(self, address: Multiaddr) -> Result<Self::ListenFuture> {
        match DnsResolver::new(address.clone()) {
            Some(dns) => {
                let task = bind(
                    dns.map_err(|(multiaddr, io_error)| {
                        TransportErrorKind::DnsResolverError(multiaddr, io_error)
                    }),
                    self.tcp_config,
                    self.self_mode,
                    #[cfg(feature = "tls")]
                    self.tls_config,
                    self.global,
                    self.timeout,
                );
                Ok(TransportFuture::new(Box::pin(task)))
            }
            None => {
                let task = bind(
                    ok(address),
                    self.tcp_config,
                    self.self_mode,
                    #[cfg(feature = "tls")]
                    self.tls_config,
                    self.global,
                    self.timeout,
                );
                Ok(TransportFuture::new(Box::pin(task)))
            }
        }
    }

    fn dial(self, address: Multiaddr) -> Result<Self::DialFuture> {
        match DnsResolver::new(address.clone()) {
            Some(dns) => {
                // Why do this?
                // Because here need to save the original address as an index to open the specified protocol.
                let task = connect(
                    dns.map_err(|(multiaddr, io_error)| {
                        TransportErrorKind::DnsResolverError(multiaddr, io_error)
                    }),
                    self.timeout,
                    Some(address),
                    self.tcp_config,
                );
                Ok(TransportFuture::new(Box::pin(task)))
            }
            None => {
                let dial = connect(ok(address), self.timeout, None, self.tcp_config);
                Ok(TransportFuture::new(Box::pin(dial)))
            }
        }
    }
}
