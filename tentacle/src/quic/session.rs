//! Placeholder for the QUIC session main loop.
//!
//! At the current stage of the QUIC integration, only the
//! handshake-completed shell is implemented. The full session main loop
//! (event routing, protocol lifecycle, substream multiplexing) lands
//! together with the integration into `InnerService` in a follow-up change.
//!
//! For now this module exposes a thin wrapper around a `quinn::Connection`
//! plus the remote secio public key recovered from the peer certificate. It
//! is what `QuicEndpoint::dial()` returns and what `QuicListener::accept()`
//! yields.

use crate::secio::PublicKey;

/// A successfully-handshaken QUIC session.
///
/// Holds a `quinn::Connection` whose TLS handshake has already completed and
/// passed the [`crate::quic::verifier`] checks, together with the remote secio
/// public key recovered from the peer certificate's tentacle identity
/// extension.
///
/// The full session machinery (substream multiplexing, protocol open/close,
/// `SessionEvent` plumbing) is not implemented here yet. Callers can currently
/// inspect `remote_pubkey()` and access the underlying `quinn::Connection` via
/// [`QuicSession::into_inner`].
#[derive(Debug)]
pub struct QuicSession {
    conn: quinn::Connection,
    remote_pubkey: PublicKey,
}

impl QuicSession {
    /// Wrap a freshly-handshaken `quinn::Connection` together with the remote
    /// secio public key extracted from the peer certificate.
    pub(crate) fn new(conn: quinn::Connection, remote_pubkey: PublicKey) -> Self {
        Self {
            conn,
            remote_pubkey,
        }
    }

    /// Remote peer's secio public key, recovered from the tentacle identity
    /// extension on the TLS leaf cert.
    pub fn remote_pubkey(&self) -> &PublicKey {
        &self.remote_pubkey
    }

    /// Borrow the underlying `quinn::Connection`. Useful for inspection in
    /// tests; the eventual session main loop will own it directly.
    pub fn connection(&self) -> &quinn::Connection {
        &self.conn
    }

    /// Decompose the wrapper, returning the underlying `quinn::Connection`
    /// and remote `PublicKey`. The session main loop will use this when the
    /// full session machinery is implemented.
    pub fn into_inner(self) -> (quinn::Connection, PublicKey) {
        (self.conn, self.remote_pubkey)
    }
}
