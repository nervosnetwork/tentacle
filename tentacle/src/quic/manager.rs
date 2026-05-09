//! Pooled UDP-endpoint reuse for the QUIC transport.
//!
//! Each [`quinn::Endpoint`] owns one UDP socket. A single physical UDP
//! port can host both inbound and outbound QUIC connections, so when
//! more than one QUIC listen / dial uses the same local listen address
//! it is more efficient to share the underlying endpoint than to spin
//! up a fresh one per call.
//!
//! [`QuicEndpointManager`] keeps a small `HashMap` keyed on listen
//! address and hands out cloned endpoint handles on demand. It is
//! deliberately minimal: no eviction, no driver task — `quinn::Endpoint`
//! self-drives once cloned.

use std::{collections::HashMap, net::SocketAddr};

use futures::io;

/// Pool of `quinn::Endpoint`s keyed by local listen [`SocketAddr`].
///
/// Each [`get_or_create_endpoint`](Self::get_or_create_endpoint) call
/// returns a clone of the already-bound endpoint when the address has
/// been seen before, otherwise it binds a fresh server endpoint with
/// the configured [`quinn::ServerConfig`].
pub struct QuicEndpointManager {
    data: HashMap<SocketAddr, quinn::Endpoint>,
    server_config: quinn::ServerConfig,
}

impl QuicEndpointManager {
    /// Build an empty manager that will use `server_config` for every
    /// future [`get_or_create_endpoint`](Self::get_or_create_endpoint)
    /// call.
    pub fn new(server_config: quinn::ServerConfig) -> Self {
        Self {
            data: Default::default(),
            server_config,
        }
    }

    /// Get a `quinn::Endpoint` bound to `listen_addr`, creating it on
    /// the first call. Subsequent calls with the same address return a
    /// clone of the pooled endpoint.
    ///
    /// Returns the I/O error from `quinn::Endpoint::server` when the
    /// underlying UDP socket bind fails (e.g. port in use).
    pub fn get_or_create_endpoint(
        &mut self,
        listen_addr: SocketAddr,
    ) -> io::Result<quinn::Endpoint> {
        match self.data.entry(listen_addr) {
            std::collections::hash_map::Entry::Occupied(occupied_entry) => {
                Ok(occupied_entry.get().clone())
            }
            std::collections::hash_map::Entry::Vacant(vacant_entry) => {
                let endpoint = quinn::Endpoint::server(self.server_config.clone(), listen_addr)?;
                vacant_entry.insert(endpoint.clone());
                Ok(endpoint)
            }
        }
    }

    /// Initiate a graceful close on every pooled endpoint and wait for
    /// each to drain its in-flight traffic. Useful at service
    /// shutdown.
    pub async fn close_all(&mut self) {
        for item in self.data.values() {
            item.close(0u32.into(), b"shutdown");
        }
        for item in self.data.values() {
            item.wait_idle().await;
        }
    }
}
