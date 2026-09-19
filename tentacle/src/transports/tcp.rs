use futures::{TryFutureExt, future::ok};
use std::{
    collections::HashMap, future::Future, net::SocketAddr, pin::Pin, sync::Arc, time::Duration,
};

#[cfg(feature = "tls")]
use crate::service::TlsConfig;
use crate::{
    error::TransportErrorKind,
    multiaddr::Multiaddr,
    runtime::{self, TcpStream},
    service::config::TcpSocketConfig,
    transports::{
        Result, TcpListenMode, TransportDial, TransportFuture, TransportListen,
        tcp_base_listen::{TcpBaseListenerEnum, UpgradeMode, bind},
        tcp_dial,
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
    listen_mode: TcpListenMode,
    global: Arc<crate::lock::Mutex<HashMap<SocketAddr, UpgradeMode>>>,
    #[cfg(feature = "tls")]
    tls_config: TlsConfig,
    /// Trusted proxy addresses for HAProxy PROXY protocol and X-Forwarded-For header parsing.
    trusted_proxies: Arc<Vec<std::net::IpAddr>>,
}

impl TcpTransport {
    pub fn new(timeout: Duration, tcp_config: TcpSocketConfig) -> Self {
        Self {
            timeout,
            tcp_config,
            listen_mode: TcpListenMode::Tcp,
            global: Arc::new(crate::lock::Mutex::new(Default::default())),
            #[cfg(feature = "tls")]
            tls_config: Default::default(),
            trusted_proxies: Arc::new(Vec::new()),
        }
    }

    pub fn from_multi_transport(
        multi_transport: super::MultiTransport,
        listen_mode: TcpListenMode,
    ) -> Self {
        Self {
            timeout: multi_transport.timeout.timeout,
            tcp_config: match listen_mode {
                TcpListenMode::Tcp => multi_transport.tcp_config.tcp,
                #[cfg(feature = "ws")]
                TcpListenMode::Ws => multi_transport.tcp_config.ws,
                #[cfg(feature = "tls")]
                TcpListenMode::Tls => multi_transport.tcp_config.tls,
            },
            listen_mode,
            global: multi_transport.listens_upgrade_modes,
            #[cfg(feature = "tls")]
            tls_config: multi_transport.tls_config.unwrap_or_default(),
            trusted_proxies: multi_transport.trusted_proxies,
        }
    }
}

// If `Existence type` is available, `Pin<Box<...>>` will no longer be needed here, and the signature is `TransportFuture<impl Future<Output=xxx>>`
pub type TcpListenFuture =
    TransportFuture<Pin<Box<dyn Future<Output = Result<(Multiaddr, TcpBaseListenerEnum)>> + Send>>>;
pub type TcpDialFuture =
    TransportFuture<Pin<Box<dyn Future<Output = Result<(Multiaddr, TcpStream)>> + Send>>>;

impl TransportListen for TcpTransport {
    type ListenFuture = TcpListenFuture;

    fn listen(self, address: Multiaddr) -> Result<Self::ListenFuture> {
        match DnsResolver::new(address.clone()) {
            Some(dns) => {
                let task = bind(
                    dns.map_err(|(multiaddr, io_error)| {
                        TransportErrorKind::DnsResolverError(multiaddr, io_error)
                    }),
                    self.tcp_config,
                    self.listen_mode,
                    #[cfg(feature = "tls")]
                    self.tls_config,
                    self.global,
                    self.timeout,
                    self.trusted_proxies,
                );
                Ok(TransportFuture::new(Box::pin(task)))
            }
            None => {
                let task = bind(
                    ok(address),
                    self.tcp_config,
                    self.listen_mode,
                    #[cfg(feature = "tls")]
                    self.tls_config,
                    self.global,
                    self.timeout,
                    self.trusted_proxies,
                );
                Ok(TransportFuture::new(Box::pin(task)))
            }
        }
    }
}

impl TransportDial for TcpTransport {
    type DialFuture = TcpDialFuture;

    fn dial(self, address: Multiaddr) -> Result<Self::DialFuture> {
        match DnsResolver::new(address.clone()) {
            Some(dns) => {
                if let Some(proxy_url) = self.tcp_config.proxy_url.clone() {
                    let (target_addr, target_port) = dns.tcp_target();
                    let target_addr = target_addr.to_owned();
                    let proxy_random_auth = self.tcp_config.proxy_random_auth;
                    let timeout = self.timeout;
                    let task = async move {
                        let stream = match runtime::timeout(
                            timeout,
                            runtime::connect_by_proxy(
                                target_addr,
                                target_port,
                                proxy_url,
                                proxy_random_auth,
                            ),
                        )
                        .await
                        {
                            Err(_) => {
                                Err(TransportErrorKind::Io(std::io::ErrorKind::TimedOut.into()))
                            }
                            Ok(res) => res.map_err(|err| {
                                if err.to_string().contains("connect_by_proxy") {
                                    TransportErrorKind::ProxyError(err)
                                } else {
                                    err.into()
                                }
                            }),
                        }?;
                        Ok((address, stream))
                    };
                    return Ok(TransportFuture::new(Box::pin(task)));
                }

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

#[cfg(test)]
mod tests {
    use super::*;
    use futures::channel::oneshot;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[tokio::test]
    async fn proxy_dns_dial_sends_hostname_to_socks_server() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let (target_sender, target_receiver) = oneshot::channel();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            let mut greeting = [0; 2];
            socket.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting[0], 5);
            let mut methods = vec![0; greeting[1] as usize];
            socket.read_exact(&mut methods).await.unwrap();
            assert!(methods.contains(&0));
            socket.write_all(&[5, 0]).await.unwrap();

            let mut request = [0; 4];
            socket.read_exact(&mut request).await.unwrap();
            assert_eq!(request[..3], [5, 1, 0]);
            assert_eq!(request[3], 3);

            let mut domain_len = [0; 1];
            socket.read_exact(&mut domain_len).await.unwrap();
            let mut domain = vec![0; domain_len[0] as usize];
            socket.read_exact(&mut domain).await.unwrap();
            let mut port = [0; 2];
            socket.read_exact(&mut port).await.unwrap();
            let target = (String::from_utf8(domain).unwrap(), u16::from_be_bytes(port));
            target_sender.send(target).unwrap();

            socket
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });

        let address: Multiaddr = "/dns4/tentacle-proxy-leak.invalid/tcp/4242"
            .parse()
            .unwrap();
        let tcp_config = TcpSocketConfig {
            proxy_url: Some(format!("socks5://{}", proxy_addr).parse().unwrap()),
            proxy_random_auth: false,
            ..Default::default()
        };
        let transport = TcpTransport::new(Duration::from_secs(5), tcp_config);

        let (dialed_addr, _stream) = transport.dial(address.clone()).unwrap().await.unwrap();
        assert_eq!(dialed_addr, address);
        assert_eq!(
            target_receiver.await.unwrap(),
            ("tentacle-proxy-leak.invalid".to_string(), 4242)
        );
    }
}
