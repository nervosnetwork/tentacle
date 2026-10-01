use std::time::Duration;

/// Configuration for Quic protocol service
#[derive(Clone)]
pub struct QuicConfig {
    /// Absolute inbound handshake deadline, starting when the attempt is accepted.
    /// Independent of connection idle activity. Default to 10 seconds; must be nonzero.
    pub handshake_timeout: Duration,
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
            max_idle_timeout: Duration::from_secs(30),
            keep_alive_interval: Some(Duration::from_secs(10)),
            max_concurrent_bidi_streams: 256,
        }
    }
}
