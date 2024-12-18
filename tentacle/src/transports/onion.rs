use futures::future::ok;
use std::{
    collections::HashMap, future::Future, net::SocketAddr, pin::Pin, sync::Arc, time::Duration,
};

#[cfg(feature = "tls")]
use crate::service::TlsConfig;
use crate::{
    multiaddr::Multiaddr,
    runtime::TcpStream,
    service::config::TcpSocketConfig,
    transports::{
        onion_dial, tcp_base_listen::UpgradeMode, Result, TcpListenMode, TransportDial,
        TransportFuture,
    },
};

/// Onion connect
async fn connect(
    address: impl Future<Output = Result<Multiaddr>>,
    timeout: Duration,
    tcp_config: TcpSocketConfig,
) -> Result<(Multiaddr, TcpStream)> {
    let addr = address.await?;
    let stream = onion_dial(addr.clone(), tcp_config, timeout).await?;
    Ok((addr, stream))
}

/// Onion transport
pub struct OnionTransport {
    timeout: Duration,
    tcp_config: TcpSocketConfig,
    listen_mode: TcpListenMode,
    global: Arc<crate::lock::Mutex<HashMap<SocketAddr, UpgradeMode>>>,
    #[cfg(feature = "tls")]
    tls_config: TlsConfig,
}

impl OnionTransport {
    pub fn new(timeout: Duration, tcp_config: TcpSocketConfig) -> Self {
        Self {
            timeout,
            tcp_config,
            listen_mode: TcpListenMode::Tcp,
            global: Arc::new(crate::lock::Mutex::new(Default::default())),
            #[cfg(feature = "tls")]
            tls_config: Default::default(),
        }
    }
}

pub type OnionDialFuture =
    TransportFuture<Pin<Box<dyn Future<Output = Result<(Multiaddr, TcpStream)>> + Send>>>;

impl TransportDial for OnionTransport {
    type DialFuture = OnionDialFuture;

    fn dial(self, address: Multiaddr) -> Result<Self::DialFuture> {
        let dial = connect(ok(address), self.timeout, self.tcp_config);
        Ok(TransportFuture::new(Box::pin(dial)))
    }
}
