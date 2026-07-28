use std::time::{Duration, Instant};

use log::debug;
use p2p::{
    context::{ProtocolContext, ProtocolContextMutRef},
    multiaddr::{Multiaddr, Protocol},
    utils::multiaddr_to_socketaddr,
    SessionId,
};

use super::{
    addr::AddrKnown,
    protocol::{encode, DiscoveryMessage, Node, Nodes},
    MAX_ADDR_TO_SEND,
};

// FIXME: should be a more high level version number

const VERSION: u32 = 0;

pub struct SessionState {
    // received pending messages
    pub(crate) addr_known: AddrKnown,
    // FIXME: Remote listen address, resolved by id protocol
    pub(crate) remote_addr: RemoteAddress,
    last_announce: Option<Instant>,
    pub(crate) announce_multiaddrs: Vec<Multiaddr>,
    pub(crate) received_get_nodes: bool,
    pub(crate) received_nodes: bool,
}

impl SessionState {
    pub(crate) fn new(context: ProtocolContextMutRef) -> SessionState {
        let mut addr_known = AddrKnown::default();
        let remote_addr = if context.session.ty.is_outbound() {
            let port = context
                .listens()
                .iter()
                .filter_map(|address| multiaddr_to_socketaddr(address))
                .map(|addr| addr.port())
                .next();

            let msg = encode(DiscoveryMessage::GetNodes {
                version: VERSION,
                count: MAX_ADDR_TO_SEND as u32,
                listen_port: port,
            });

            if context.send_message(msg).is_err() {
                debug!("{:?} send discovery msg GetNode fail", context.session.id)
            }

            addr_known.insert(&context.session.address);

            RemoteAddress::Listen(context.session.address.clone())
        } else {
            RemoteAddress::Init(context.session.address.clone())
        };

        SessionState {
            last_announce: None,
            addr_known,
            remote_addr,
            announce_multiaddrs: Vec::new(),
            received_get_nodes: false,
            received_nodes: false,
        }
    }

    /// Apply a peer-supplied `listen_port` to the remote address and return the
    /// rewritten `Listen` address candidate.
    ///
    /// The port is peer-controlled and unauthenticated, so `update_port` rejects
    /// obviously invalid values (e.g. port 0) and only promotes `Init` addresses
    /// to `Listen`. The returned candidate must still be validated by the
    /// address manager (see `mark_listen_addr_known`) before it is stored or
    /// announced, so a malicious peer cannot poison the store with an invalid
    /// endpoint for its observed source IP.
    ///
    /// Returns the rewritten `Listen` address, or `None` if the port was
    /// rejected or the address was not an `Init` address.
    pub(crate) fn apply_listen_port(&mut self, port: u16) -> Option<Multiaddr> {
        if !self.remote_addr.update_port(port) {
            return None;
        }
        match &self.remote_addr {
            RemoteAddress::Listen(addr) => Some(addr.clone()),
            RemoteAddress::Init(_) => None,
        }
    }

    /// Record a validated listen address in the per-session known-address set.
    pub(crate) fn mark_listen_addr_known(&mut self, addr: &Multiaddr) {
        self.addr_known.insert(addr);
    }

    pub(crate) fn check_timer(&mut self, now: Instant, interval: Duration) -> Option<&Multiaddr> {
        if self
            .last_announce
            .map(|time| now - time > interval)
            .unwrap_or(true)
        {
            self.last_announce = Some(now);
            if let RemoteAddress::Listen(addr) = &self.remote_addr {
                Some(addr)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub(crate) fn send_messages(&mut self, cx: &mut ProtocolContext, id: SessionId) {
        if !self.announce_multiaddrs.is_empty() {
            let items = self
                .announce_multiaddrs
                .drain(..)
                .map(|addr| Node {
                    addresses: vec![addr],
                })
                .collect::<Vec<_>>();
            let nodes = Nodes {
                announce: true,
                items,
            };
            let msg = encode(DiscoveryMessage::Nodes(nodes));
            if cx.send_message_to(id, cx.proto_id, msg).is_err() {
                debug!("{:?} send discovery msg Nodes fail", id)
            }
        }
    }
}

#[derive(Eq, PartialEq, Hash, Debug, Clone)]
pub(crate) enum RemoteAddress {
    /// Inbound init remote address
    Init(Multiaddr),
    /// Outbound init remote address or Inbound listen address
    Listen(Multiaddr),
}

impl RemoteAddress {
    pub(crate) fn to_inner(&self) -> &Multiaddr {
        match self {
            RemoteAddress::Init(ref addr) | RemoteAddress::Listen(ref addr) => addr,
        }
    }

    /// Rewrite the transport port with the peer-supplied listen port and mark
    /// the address as a `Listen` address.
    ///
    /// The `port` is peer-controlled and unauthenticated, so obviously invalid
    /// values are rejected here as a first line of defense before the address
    /// is stored or announced. Port `0` is never a valid listen endpoint (it
    /// means "any port" when binding and is not dialable), so it is dropped and
    /// the address is left untouched.
    ///
    /// Returns `true` when the address was rewritten to a `Listen` address.
    pub(crate) fn update_port(&mut self, port: u16) -> bool {
        if port == 0 {
            return false;
        }
        if let RemoteAddress::Init(ref addr) = self {
            let addr = addr
                .into_iter()
                .map(|proto| {
                    match proto {
                        // TODO: other transport, UDP for example
                        Protocol::Tcp(_) => Protocol::Tcp(port),
                        value => value,
                    }
                })
                .collect();
            *self = RemoteAddress::Listen(addr);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RemoteAddress, SessionState};
    use crate::addr::AddrKnown;
    use p2p::multiaddr::Multiaddr;

    fn addr(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    fn state_with(remote_addr: RemoteAddress) -> SessionState {
        SessionState {
            addr_known: AddrKnown::default(),
            remote_addr,
            last_announce: None,
            announce_multiaddrs: Vec::new(),
            received_get_nodes: false,
            received_nodes: false,
        }
    }

    // A peer-supplied listen port of 0 is not a valid dialable endpoint and
    // must be rejected: the address must stay `Init` and no rewrite happens.
    #[test]
    fn update_port_rejects_zero_port() {
        let mut remote = RemoteAddress::Init(addr("/ip4/198.51.100.66/tcp/49152"));
        assert!(!remote.update_port(0));
        assert_eq!(
            remote,
            RemoteAddress::Init(addr("/ip4/198.51.100.66/tcp/49152"))
        );
    }

    // A valid peer-supplied listen port rewrites the observed outbound port and
    // promotes the address to `Listen`, keeping the observed IP unchanged.
    #[test]
    fn update_port_rewrites_valid_port_and_marks_listen() {
        let mut remote = RemoteAddress::Init(addr("/ip4/198.51.100.66/tcp/49152"));
        assert!(remote.update_port(9));
        assert_eq!(
            remote,
            RemoteAddress::Listen(addr("/ip4/198.51.100.66/tcp/9"))
        );
    }

    // `update_port` only promotes `Init` addresses. An address that is already
    // `Listen` must not be rewritten again by a later peer-supplied port.
    #[test]
    fn update_port_does_not_rewrite_listen() {
        let mut remote = RemoteAddress::Listen(addr("/ip4/198.51.100.66/tcp/1337"));
        assert!(!remote.update_port(4444));
        assert_eq!(
            remote,
            RemoteAddress::Listen(addr("/ip4/198.51.100.66/tcp/1337"))
        );
    }

    // A rejected port (0) yields no candidate address to store, so the store
    // poisoning path is closed at the source.
    #[test]
    fn apply_listen_port_rejects_zero_port() {
        let mut state = state_with(RemoteAddress::Init(addr("/ip4/198.51.100.66/tcp/49152")));
        assert_eq!(state.apply_listen_port(0), None);
        // Address must remain the un-promoted Init address.
        assert_eq!(
            state.remote_addr,
            RemoteAddress::Init(addr("/ip4/198.51.100.66/tcp/49152"))
        );
    }

    // A valid port produces a Listen candidate that keeps the observed IP and
    // only differs in the peer-claimed port.
    #[test]
    fn apply_listen_port_returns_listen_candidate() {
        let mut state = state_with(RemoteAddress::Init(addr("/ip4/198.51.100.66/tcp/49152")));
        assert_eq!(
            state.apply_listen_port(9),
            Some(addr("/ip4/198.51.100.66/tcp/9"))
        );
        assert_eq!(
            state.remote_addr,
            RemoteAddress::Listen(addr("/ip4/198.51.100.66/tcp/9"))
        );
    }

    // Once an address is Listen, a later peer-supplied port cannot rewrite it,
    // so no new candidate is produced.
    #[test]
    fn apply_listen_port_no_candidate_when_already_listen() {
        let mut state = state_with(RemoteAddress::Listen(addr("/ip4/198.51.100.66/tcp/1337")));
        assert_eq!(state.apply_listen_port(4444), None);
        assert_eq!(
            state.remote_addr,
            RemoteAddress::Listen(addr("/ip4/198.51.100.66/tcp/1337"))
        );
    }
}
