//! Compact JWS (RFC 7515) with EdDSA over Ed25519 (RFC 8037) only.
//!
//! What a product uses outside the client: [`sign_compact_jws`] signs the statements a product
//! signs itself (the `stats_link` statement, with the statistics key), and
//! [`claims_of_verified_jws`] reads back the claims of a document the verifier accepted before it
//! was stored. The verifiers themselves are [`crate::manifest`] and [`crate::entitlement`].
//!
//! A JWS is decoded by one rule in both SDKs and on the platform: at most 64 KiB; three canonical
//! base64url parts; header and payload are JSON objects in valid UTF-8 (a leading byte-order mark
//! is not whitespace); no string or member name holds a lone surrogate; every number fits a double;
//! at most 127 nested arrays and objects (serde_json's own limits). Anything else is `malformed`.
//! How a number is written is checked where the value is read: the verifiers require the integer
//! claims they read to be I-JSON integers ([`first_non_integer`]). Signatures are verified
//! strictly: a small-order public key or `R` never verifies.

// The verifier helpers serve the `entitlement` feature; with `stats` alone only the public
// helpers are used.
#![cfg_attr(not(feature = "entitlement"), allow(dead_code))]

use std::fmt;

use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Map, Value};

use crate::encoding::{b64url, from_b64url};

/// The longest compact JWS a verifier reads.
pub const MAX_JWS_LENGTH: usize = 65_536;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// A decoded compact JWS.
pub(crate) struct DecodedJws {
    pub(crate) header: Map<String, Value>,
    pub(crate) payload: Map<String, Value>,
    /// `base64url(header) "." base64url(payload)`: the bytes the signature covers.
    pub(crate) signing_input: String,
    pub(crate) signature: Vec<u8>,
}

/// Whether a number is an I-JSON integer as written: no fraction, no exponent, not `-0`, within
/// plus or minus 2^53 - 1 (serde_json reads a fraction, an exponent, negative zero and an integer
/// past 64 bits as floating point).
pub(crate) fn ijson_integer(n: &serde_json::Number) -> bool {
    n.as_i64()
        .is_some_and(|i| i.unsigned_abs() <= MAX_SAFE_INTEGER)
}

/// The first of `pointers` (in the order given) whose value is a number that is not an I-JSON
/// integer as written; a pointer without a number is not checked here (the schema is).
pub(crate) fn first_non_integer<'a>(value: &Value, pointers: &[&'a str]) -> Option<&'a str> {
    pointers
        .iter()
        .copied()
        .find(|p| matches!(value.pointer(p), Some(Value::Number(n)) if !ijson_integer(n)))
}

fn object(part: &str) -> Option<Map<String, Value>> {
    let bytes = from_b64url(part)?;
    // serde_json refuses invalid UTF-8, a byte-order mark, lone surrogate escapes, a number past a
    // double and more than 127 levels, as the TypeScript decoder does.
    match serde_json::from_slice::<Value>(&bytes).ok()? {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

/// Splits and decodes a compact JWS; `None` unless it follows the decoding rule above.
pub(crate) fn decode(token: &str) -> Option<DecodedJws> {
    if token.len() > MAX_JWS_LENGTH {
        return None;
    }
    let mut parts = token.split('.');
    let (h, p, s) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let header = object(h)?;
    let payload = object(p)?;
    let signature = from_b64url(s)?;
    Some(DecodedJws {
        header,
        payload,
        signing_input: format!("{h}.{p}"),
        signature,
    })
}

/// A public key that is a curve point of large order (`None` otherwise).
pub(crate) fn strong_key(x: &str) -> Option<VerifyingKey> {
    let raw: [u8; 32] = from_b64url(x)?.try_into().ok()?;
    let key = VerifyingKey::from_bytes(&raw).ok()?;
    (!key.is_weak()).then_some(key)
}

/// Whether `signature` is a valid Ed25519 signature by the key `x` (base64url, 32 bytes) over
/// `message`, under the strict rule (`verify_strict`: no small-order key, no small-order `R`).
pub(crate) fn verify_ed25519(x: &str, message: &[u8], signature: &[u8]) -> bool {
    let Some(key) = strong_key(x) else {
        return false;
    };
    let Ok(sig) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    key.verify_strict(message, &Signature::from_bytes(&sig))
        .is_ok()
}

/// A header or payload member as a string.
pub(crate) fn str_of<'a>(map: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    map.get(name).and_then(Value::as_str)
}

/// Why [`sign_compact_jws`] signed nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum JwsSignError {
    /// The header or the payload is not a JSON object: `not_an_object`.
    NotAnObject,
    /// The header names an `alg` other than `EdDSA` (the algorithm is not a parameter):
    /// `alg_not_eddsa`.
    AlgNotEdDsa,
    /// The header names `crit` (no extension is understood on the other side):
    /// `crit_not_supported`.
    CritNotSupported,
    /// The result would not decode by the verifiers' rule (over 64 KiB, or nested deeper than 127
    /// levels): `not_decodable`.
    NotDecodable,
    /// The signer failed, with its message: `sign_failed`.
    Sign(String),
}

impl JwsSignError {
    /// The code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NotAnObject => "not_an_object",
            Self::AlgNotEdDsa => "alg_not_eddsa",
            Self::CritNotSupported => "crit_not_supported",
            Self::NotDecodable => "not_decodable",
            Self::Sign(_) => "sign_failed",
        }
    }
}

impl fmt::Display for JwsSignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "compact JWS not signed: {}", self.code())
    }
}

impl std::error::Error for JwsSignError {}

/// Signs a compact JWS (RFC 7515) with EdDSA over Ed25519 (RFC 8037), the only algorithm Ever
/// Platform reads. For the statements a product signs itself, such as the `stats_link` statement
/// (header `{"typ": contracts::constants()["stats_link_typ"]}`, signed with the statistics key);
/// the client assertion and the key rotation proofs have their own functions (`assertion`).
///
/// * The header always holds `alg: EdDSA`. A header that names another `alg` is refused
///   ([`JwsSignError::AlgNotEdDsa`]), never relabelled; so is a header with `crit`.
/// * The header and the payload are JSON objects, written with `serde_json` (members in the order
///   of its map).
/// * `sign` answers the 64-byte Ed25519 signature over exactly
///   `base64url(header) "." base64url(payload)`; the type holds the length. A key in a secret store
///   that fails answers its error, which becomes [`JwsSignError::Sign`].
///
/// ```
/// use std::convert::Infallible;
/// use ever_connect_sdk::jws::sign_compact_jws;
/// use ever_connect_sdk::stats::StatsKey;
/// use serde_json::json;
///
/// let key = StatsKey::from_seed(&[7; 32]);
/// let statement = sign_compact_jws(
///     &json!({"typ": "ever-stats-link+jwt"}),
///     &json!({"sub": "01JNE7V9J03J6XQ2WN8H0Z88R5", "iat": 1_793_613_600}),
///     |bytes| Ok::<_, Infallible>(key.sign(bytes)),
/// )
/// .unwrap();
/// assert_eq!(statement.split('.').count(), 3);
/// ```
///
/// Nothing about the result is verified: the signer is trusted to hold the key it claims.
///
/// # Errors
/// [`JwsSignError`], before anything is signed except for [`JwsSignError::Sign`] and
/// [`JwsSignError::NotDecodable`].
pub fn sign_compact_jws<E: fmt::Display>(
    header: &Value,
    payload: &Value,
    sign: impl FnOnce(&[u8]) -> Result<[u8; 64], E>,
) -> Result<String, JwsSignError> {
    let (Value::Object(header), Value::Object(_)) = (header, payload) else {
        return Err(JwsSignError::NotAnObject);
    };
    match header.get("alg") {
        None => {}
        Some(Value::String(alg)) if alg == "EdDSA" => {}
        Some(_) => return Err(JwsSignError::AlgNotEdDsa),
    }
    if header.contains_key("crit") {
        return Err(JwsSignError::CritNotSupported);
    }
    let mut header = header.clone();
    header.insert("alg".to_owned(), Value::String("EdDSA".to_owned()));
    let input = format!(
        "{}.{}",
        b64url(Value::Object(header).to_string()),
        b64url(payload.to_string())
    );
    let signature = sign(input.as_bytes()).map_err(|e| JwsSignError::Sign(e.to_string()))?;
    let jws = format!("{input}.{}", b64url(signature));
    if decode(&jws).is_none() {
        return Err(JwsSignError::NotDecodable);
    }
    Ok(jws)
}

/// The claims (the payload) of a compact JWS **you already verified**, to show them or to read a
/// value back from a document you stored. It **never verifies anything**: not the signature, not
/// the key, the issuer, the audience, the installation or the times. Call it only on a document
/// the crate's verifier accepted before it was stored (`entitlement::verify_entitlement`, the
/// client's `verify_entitlement_refreshing`); for a document just received, call the verifier,
/// which answers the claims itself. Never base a decision about access on what it answers for a
/// document that was not verified.
///
/// The document is read by the decoding rule of the verifiers (at most 64 KiB, three canonical
/// base64url parts, a header and a payload that are JSON objects in UTF-8); anything else answers
/// `None`.
#[must_use]
pub fn claims_of_verified_jws(jws: &str) -> Option<Map<String, Value>> {
    decode(jws).map(|d| d.payload)
}
