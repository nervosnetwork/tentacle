use std::{collections::HashMap, net::SocketAddr};

use futures::io;

pub struct QuicEndpointManager {
    data: HashMap<SocketAddr, quinn::Endpoint>,
    server_config: quinn::ServerConfig,
}

impl QuicEndpointManager {
    pub fn new(server_config: quinn::ServerConfig) -> Self {
        Self {
            data: Default::default(),
            server_config,
        }
    }
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
    pub async fn close_all(&mut self) {
        for item in self.data.values() {
            item.close(0u32.into(), b"shutdown");
        }
        for item in self.data.values() {
            item.wait_idle().await;
        }
    }
}
