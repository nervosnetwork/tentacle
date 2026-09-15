use std::time::Duration;

/// Configuration for Quic protocol service
#[derive(Clone)]
pub struct QuicConfig {
    /// Deadline for an inbound handshake, independent of connection idle time.
    /// Default to 10 seconds; must be nonzero.
    pub handshake_timeout: Duration,
    /// Maximum pending inbound handshakes, including results awaiting delivery.
    /// Shared by all QUIC listeners in a Service. Default to 128; must be
    /// between 1 and `tokio::sync::Semaphore::MAX_PERMITS` inclusive.
    /// This is separate from the established-session connection limit.
    pub max_pending_handshakes: usize,
    /// Max idle timeout, corresponding to quinn::TransportConfig::max_idle_timeout
    /// Default to 30 seconds
    pub max_idle_timeout: Duration,
    /// keep-alive ping interval. Set to None to disable.
    /// Default to Some(10s)
    pub keep_alive_interval: Option<Duration>,
    /// Max allowed bidi stream for a single quic connection.
    /// Default to 256
    pub max_concurrent_bidi_streams: u64,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(10),
            max_pending_handshakes: 128,
            max_idle_timeout: Duration::from_secs(30),
            keep_alive_interval: Some(Duration::from_secs(10)),
            max_concurrent_bidi_streams: 256,
        }
    }
}
