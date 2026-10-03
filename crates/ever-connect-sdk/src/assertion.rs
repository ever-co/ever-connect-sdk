//! The client assertion (RFC 7523) an installation signs with its connect key to get an instance
//! token, the proofs of a connect-key rotation, and the subject hash Ever Platform sends instead of
//! an Ever ID subject.

use std::fmt;

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::encoding::{b64url, hex, is_ulid};
use crate::keys::{InstanceSigner, SignError};

/// The longest life of an assertion, in seconds.
pub const MAX_TTL_S: i64 = 300;

/// Why an assertion cannot be built.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AssertionError {
    /// No Registry id yet (before the first redeem): `no_registry_instance_id`.
    NotConnected,
    /// The id is not a ULID (the anonymous statistics id, a UUID, never authenticates).
    NotARegistryId,
    /// The signer failed.
    Sign(SignError),
}

impl AssertionError {
    /// The code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NotConnected => "no_registry_instance_id",
            Self::NotARegistryId => "not_a_registry_id",
            Self::Sign(_) => "sign_failed",
        }
    }
}

impl fmt::Display for AssertionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "client assertion refused: {}", self.code())
    }
}

impl std::error::Error for AssertionError {}

fn registry_id(id: Option<&str>) -> Result<&str, AssertionError> {
    match id {
        None | Some("") => Err(AssertionError::NotConnected),
        Some(id) if !is_ulid(id) => Err(AssertionError::NotARegistryId),
        Some(id) => Ok(id),
    }
}

fn random_jti() -> Result<String, AssertionError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| AssertionError::Sign(SignError(e.to_string())))?;
    Ok(b64url(bytes))
}

/// Signs a compact JWS (`alg: EdDSA`); the header and payload are written in name order.
fn sign_jws(
    signer: &dyn InstanceSigner,
    header: &Value,
    payload: &Value,
) -> Result<String, AssertionError> {
    let input = format!(
        "{}.{}",
        b64url(header.to_string()),
        b64url(payload.to_string())
    );
    let signature = signer
        .sign(input.as_bytes())
        .map_err(AssertionError::Sign)?;
    Ok(format!("{input}.{}", b64url(signature)))
}

/// Options of [`sign_client_assertion`].
pub struct ClientAssertionOptions<'a> {
    /// The connect key.
    pub signer: &'a dyn InstanceSigner,
    /// The Registry id the redeem answered; `None` before the first redeem.
    pub registry_instance_id: Option<&'a str>,
    /// `<API origin>/v1/instances/token`.
    pub audience: &'a str,
    /// Lifetime, capped at 300 s (default 300).
    pub ttl_s: Option<i64>,
    /// Unix seconds (default now).
    pub now: Option<i64>,
    /// The assertion id (default 16 random bytes); fixed only in tests: the platform refuses a replay.
    pub jti: Option<&'a str>,
}

/// The RFC 7523 client assertion for the instance token: header `{alg: EdDSA, kid, typ: JWT}`,
/// claims `iss = sub =` the Registry id, `aud`, a random `jti`, `iat` and
/// `exp = iat + min(ttl, 300)`, in name order (the platform's own signer writes the same bytes).
///
/// # Errors
/// [`AssertionError::NotConnected`] before the first redeem, [`AssertionError::NotARegistryId`]
/// for an id that is not a ULID (both before anything is signed).
pub fn sign_client_assertion(o: &ClientAssertionOptions<'_>) -> Result<String, AssertionError> {
    let id = registry_id(o.registry_instance_id)?;
    let iat = o.now.unwrap_or_else(crate::manifest::now_s);
    let ttl = o.ttl_s.unwrap_or(MAX_TTL_S).clamp(1, MAX_TTL_S);
    let jti = match o.jti {
        Some(jti) => jti.to_owned(),
        None => random_jti()?,
    };
    // serde_json's map keeps keys in name order: the bytes equal the platform's.
    sign_jws(
        o.signer,
        &json!({"alg": "EdDSA", "kid": o.signer.kid(), "typ": "JWT"}),
        &json!({"aud": o.audience, "exp": iat + ttl, "iat": iat, "iss": id, "jti": jti, "sub": id}),
    )
}

/// The RFC 7638 thumbprint of an Ed25519 public key (`cnf.jkt` of a rotation proof).
#[must_use]
pub fn jwk_thumbprint(x: &str) -> String {
    b64url(Sha256::digest(format!(
        "{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{x}\"}}"
    )))
}

/// The body of a connect-key rotation: the new public key and two proofs, one signed with the
/// current key and one with the new key, each a client assertion for the rotation endpoint that
/// binds the new key (`cnf.jkt`). The statistics key is not involved.
///
/// # Errors
/// [`AssertionError`].
pub fn sign_key_rotation(
    current: &dyn InstanceSigner,
    next: &dyn InstanceSigner,
    registry_instance_id: Option<&str>,
    issuer_origin: &str,
    now: Option<i64>,
) -> Result<Value, AssertionError> {
    let id = registry_id(registry_instance_id)?;
    let x = b64url(next.public_key_raw());
    let iat = now.unwrap_or_else(crate::manifest::now_s);
    let aud = format!(
        "{}/v1/instances/me/keys",
        issuer_origin.trim_end_matches('/')
    );
    let proof = |signer: &dyn InstanceSigner| -> Result<String, AssertionError> {
        sign_jws(
            signer,
            &json!({"alg": "EdDSA", "kid": signer.kid(), "typ": "JWT"}),
            &json!({"aud": aud, "cnf": {"jkt": jwk_thumbprint(&x)}, "exp": iat + MAX_TTL_S, "iat": iat, "iss": id, "jti": random_jti()?, "sub": id}),
        )
    };
    Ok(json!({
        "public_jwk": {"kty": "OKP", "crv": "Ed25519", "x": x},
        "current_key_proof": proof(current)?,
        "new_key_proof": proof(next)?,
    }))
}

/// The hash Ever Platform sends instead of an Ever ID subject (`subject_hash` of
/// `ever.registry.person.deletion_requested`): lower-case hex SHA-256 of `<issuer>#<subject>`.
#[must_use]
pub fn subject_hash(issuer: &str, subject: &str) -> String {
    hex(&Sha256::digest(format!("{issuer}#{subject}").as_bytes()))
}
