//! The installation's connect key: the [`InstanceSigner`] trait (the key may live in a secret store
//! the crate never sees), an `ed25519-dalek` signer, and the key id the platform derives.
//!
//! The signer is a key, not an identity: the Registry id goes into the assertion separately. Keep
//! the statistics key separate from the connect key: rotating the connect key then never touches
//! the statistics series.

use std::fmt;

use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::encoding::{b64url, from_b64url};

/// A signer that failed (a remote key store that did not answer, for example).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignError(pub String);

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "signing failed: {}", self.0)
    }
}

impl std::error::Error for SignError {}

/// Signs bytes with an Ed25519 key.
pub trait InstanceSigner: Send + Sync {
    /// `base64url(sha256(raw public key)[0:8])`: the key id the platform derives.
    fn kid(&self) -> String;
    /// The raw 32-byte public key (`public_jwk.x`, decoded).
    fn public_key_raw(&self) -> [u8; 32];
    /// An Ed25519 signature over `bytes`.
    ///
    /// # Errors
    /// [`SignError`] when the key cannot sign.
    fn sign(&self, bytes: &[u8]) -> Result<[u8; 64], SignError>;
}

/// The key id of a raw public key: base64url of the first 8 bytes of its SHA-256.
#[must_use]
pub fn key_id_from_raw(raw: &[u8; 32]) -> String {
    b64url(&Sha256::digest(raw)[..8])
}

/// The key id of a public JWK's `x` (`None` unless it is 32 bytes of base64url).
#[must_use]
pub fn key_id_from_x(x: &str) -> Option<String> {
    let raw: [u8; 32] = from_b64url(x)?.try_into().ok()?;
    Some(key_id_from_raw(&raw))
}

/// The public JWK of a signer (what the redeem and the key rotation send).
#[must_use]
pub fn public_jwk(signer: &dyn InstanceSigner) -> Value {
    json!({"kty": "OKP", "crv": "Ed25519", "x": b64url(signer.public_key_raw())})
}

/// An Ed25519 signer over a 32-byte seed. `Debug` shows the key id only.
pub struct Ed25519Signer {
    key: SigningKey,
    kid: String,
}

impl Ed25519Signer {
    /// The signer of a 32-byte seed (the private key; store it as a secret).
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let key = SigningKey::from_bytes(seed);
        let kid = key_id_from_raw(&key.verifying_key().to_bytes());
        Self { key, kid }
    }

    /// A new key: answers the signer and its seed (store the seed as a secret; the public JWK goes
    /// into the redeem).
    ///
    /// # Errors
    /// [`SignError`] when the operating system has no random source.
    pub fn generate() -> Result<(Self, [u8; 32]), SignError> {
        let mut seed = [0_u8; 32];
        getrandom::fill(&mut seed).map_err(|e| SignError(e.to_string()))?;
        Ok((Self::from_seed(&seed), seed))
    }
}

impl InstanceSigner for Ed25519Signer {
    fn kid(&self) -> String {
        self.kid.clone()
    }

    fn public_key_raw(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    fn sign(&self, bytes: &[u8]) -> Result<[u8; 64], SignError> {
        Ok(self.key.sign(bytes).to_bytes())
    }
}

impl fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519Signer({})", self.kid)
    }
}
