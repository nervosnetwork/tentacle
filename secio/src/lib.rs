//! Aes Encrypted communication and handshake process implementation

#![deny(missing_docs)]
use rand::RngCore;

pub use crate::{handshake::handshake_struct::PublicKey, peer_id::PeerId};

/// Encrypted and decrypted codec implementation, and stream handle
pub mod codec;
/// Symmetric ciphers algorithms
pub mod crypto;
mod dh_compat;
/// Error type
pub mod error;
/// Implementation of the handshake process
pub mod handshake;
/// Peer id
pub mod peer_id;
/// A little encapsulation of secp256k1
mod secp256k1_compat;
mod sha256_compat;
/// Supported algorithms
mod support;

/// Public key generated temporarily during the handshake
pub type EphemeralPublicKey = Vec<u8>;

/// Key pair of asymmetric encryption algorithm
#[derive(Clone, Debug)]
pub struct SecioKeyPair {
    inner: KeyPairInner,
}

impl SecioKeyPair {
    /// Generates a new random sec256k1 key pair.
    pub fn secp256k1_generated() -> SecioKeyPair {
        loop {
            let mut key = [0; crate::secp256k1_compat::SECRET_KEY_SIZE];
            rand::thread_rng().fill_bytes(&mut key);
            if let Ok(private) = crate::secp256k1_compat::secret_key_from_slice(&key) {
                return SecioKeyPair {
                    inner: KeyPairInner::Secp256k1 { private },
                };
            }
        }
    }

    /// Builds a `SecioKeyPair` from a raw secp256k1 32 bytes private key.
    pub fn secp256k1_raw_key<K>(key: K) -> Result<SecioKeyPair, error::SecioError>
    where
        K: AsRef<[u8]>,
    {
        let private = crate::secp256k1_compat::secret_key_from_slice(key.as_ref())
            .map_err(|_| error::SecioError::SecretGenerationFailed)?;

        Ok(SecioKeyPair {
            inner: KeyPairInner::Secp256k1 { private },
        })
    }

    /// Returns the public key corresponding to this key pair.
    pub fn public_key(&self) -> PublicKey {
        match self.inner {
            KeyPairInner::Secp256k1 { ref private } => {
                let pubkey = crate::secp256k1_compat::from_secret_key(private);
                PublicKey {
                    key: crate::secp256k1_compat::serialize_pubkey(&pubkey),
                }
            }
        }
    }

    /// Generate Peer id
    pub fn peer_id(&self) -> PeerId {
        self.public_key().peer_id()
    }
}

#[derive(Clone)]
enum KeyPairInner {
    Secp256k1 {
        private: crate::secp256k1_compat::SecretKey,
    },
}

impl std::fmt::Debug for KeyPairInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair").finish()
    }
}

/// Possible digest algorithms.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Digest {
    /// Sha256 digest
    Sha256,
    /// Sha512 digest
    Sha512,
}

impl Digest {
    /// Returns the size in bytes of a digest of this kind.
    #[inline]
    pub fn num_bytes(self) -> usize {
        match self {
            Digest::Sha256 => 256 / 8,
            Digest::Sha512 => 512 / 8,
        }
    }
}

/// KeyProvider on ecdh procedure
#[cfg_attr(all(target_arch = "wasm32", feature = "async-trait"), async_trait::async_trait(?Send))]
#[cfg_attr(
    all(not(target_arch = "wasm32"), feature = "async-trait"),
    async_trait::async_trait
)]
pub trait KeyProvider: std::clone::Clone + Send + Sync + 'static {
    /// Error
    type Error: Into<crate::error::SecioError>;
    /// Public key
    type Pubkey: Pubkey;

    /// Constructs a signature for `msg` using the secret key `sk`
    #[cfg(feature = "async-trait")]
    async fn sign_ecdsa_async<T: AsRef<[u8]> + Send>(
        &self,
        message: T,
    ) -> Result<Vec<u8>, Self::Error> {
        self.sign_ecdsa(message)
    }

    /// Constructs a signature for `msg` using the secret key `sk`
    fn sign_ecdsa<T: AsRef<[u8]>>(&self, message: T) -> Result<Vec<u8>, Self::Error>;

    /// Creates a new public key from the [`KeyProvider`].
    fn pubkey(&self) -> Self::Pubkey;
}

/// Public key for KeyProvider
pub trait Pubkey: Send + Sync + 'static {
    /// Error
    type Error: Into<crate::error::SecioError>;
    /// Checks that `sig` is a valid ECDSA signature for `msg` using the public
    /// key `pubkey`.
    fn verify_ecdsa<T: AsRef<[u8]>, F: AsRef<[u8]>>(&self, message: T, signature: F) -> bool;

    /// serialized key into a bytes
    fn serialize(&self) -> Vec<u8>;

    /// Recover public key from slice
    fn from_slice<T: AsRef<[u8]>>(key: T) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

impl KeyProvider for SecioKeyPair {
    type Error = error::SecioError;
    type Pubkey = secp256k1_compat::PublicKey;

    fn sign_ecdsa<T: AsRef<[u8]>>(&self, message: T) -> Result<Vec<u8>, Self::Error> {
        let msg = match crate::secp256k1_compat::message_from_slice(message.as_ref()) {
            Ok(m) => m,
            Err(_) => {
                log::debug!("message has wrong format");
                return Err(error::SecioError::InvalidMessage);
            }
        };
        let signature = match self.inner {
            KeyPairInner::Secp256k1 { ref private } => crate::secp256k1_compat::sign(&msg, private),
        };

        Ok(crate::secp256k1_compat::signature_to_vec(signature))
    }

    fn pubkey(&self) -> Self::Pubkey {
        match self.inner {
            KeyPairInner::Secp256k1 { ref private } => {
                crate::secp256k1_compat::from_secret_key(private)
            }
        }
    }
}

impl Pubkey for secp256k1_compat::PublicKey {
    type Error = error::SecioError;
    fn verify_ecdsa<T: AsRef<[u8]>, F: AsRef<[u8]>>(&self, message: T, signature: F) -> bool {
        let signature = crate::secp256k1_compat::signature_from_der(signature.as_ref());
        let msg = crate::secp256k1_compat::message_from_slice(message.as_ref());

        if let (Ok(signature), Ok(message)) = (signature, msg) {
            if !crate::secp256k1_compat::verify(&message, &signature, self) {
                log::debug!("failed to verify the remote's signature");
                return false;
            }
        } else {
            log::debug!("remote's secp256k1 signature has wrong format");
            return false;
        }
        true
    }

    fn serialize(&self) -> Vec<u8> {
        crate::secp256k1_compat::serialize_pubkey(self)
    }

    fn from_slice<T: AsRef<[u8]>>(key: T) -> Result<Self, Self::Error> {
        crate::secp256k1_compat::pubkey_from_slice(key.as_ref())
            .map_err(|_| crate::error::SecioError::SecretGenerationFailed)
    }
}

impl KeyProvider for () {
    type Error = error::SecioError;
    type Pubkey = ();

    fn sign_ecdsa<T: AsRef<[u8]>>(&self, _message: T) -> Result<Vec<u8>, Self::Error> {
        Err(error::SecioError::NotSupportKeyProvider)
    }

    fn pubkey(&self) -> Self::Pubkey {
        ()
    }
}

impl Pubkey for () {
    type Error = error::SecioError;
    fn verify_ecdsa<T: AsRef<[u8]>, F: AsRef<[u8]>>(&self, _message: T, _signature: F) -> bool {
        false
    }

    fn serialize(&self) -> Vec<u8> {
        Vec::new()
    }

    fn from_slice<T: AsRef<[u8]>>(_key: T) -> Result<Self, Self::Error> {
        Ok(())
    }
}
