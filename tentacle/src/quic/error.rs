/// Errors that can occur while building or validating QUIC identities.
#[derive(Debug, thiserror::Error)]
pub enum QuicErrorKind {
    /// Failed to build or parse the X.509 certificate.
    #[error("Certificate error: {0}")]
    CertificateError(String),

    /// Failed to sign the binding payload with the secio key.
    #[error("Secio signing error: {0}")]
    SigningError(String),

    /// Unable to find tentacle OID extension
    #[error("Certificate extension not found")]
    ExtensionNotFound,

    /// Unsupported identity version
    #[error("Unsupported identity version: {0}")]
    IdentityVersionUnsupported(u8),

    /// Multiple identity found
    #[error("Multiple identity found")]
    MultipleIdentityFound,
}
