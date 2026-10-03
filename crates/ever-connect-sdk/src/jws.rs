//! Compact JWS (RFC 7515) with EdDSA over Ed25519 (RFC 8037) only.
//!
//! A JWS is decoded by one rule in both SDKs: at most 64 KiB; three canonical base64url parts;
//! header and payload are JSON objects in valid UTF-8 (a leading byte-order mark is not
//! whitespace); every number is an integer token (no fraction, no exponent, no negative zero)
//! within plus or minus 2^53 - 1; no string or member name holds a lone surrogate; at most 127
//! nested arrays and objects (serde_json's own limit). Anything else is `malformed`. Signatures
//! are verified strictly: a small-order public key or `R` never verifies.

use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Map, Value};

use crate::encoding::from_b64url;

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

/// Whether every number of `value` is a safe integer (serde_json keeps a fraction, an exponent and
/// negative zero as floating point, and reads an integer past 64 bits as one).
pub(crate) fn safe_integers(value: &Value) -> bool {
    match value {
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                u <= MAX_SAFE_INTEGER
            } else if let Some(i) = n.as_i64() {
                i.unsigned_abs() <= MAX_SAFE_INTEGER
            } else {
                false
            }
        }
        Value::Array(items) => items.iter().all(safe_integers),
        Value::Object(map) => map.values().all(safe_integers),
        _ => true,
    }
}

fn object(part: &str) -> Option<Map<String, Value>> {
    let bytes = from_b64url(part)?;
    // serde_json refuses invalid UTF-8, a byte-order mark, lone surrogate escapes and more than
    // 127 levels, as the TypeScript decoder does.
    match serde_json::from_slice::<Value>(&bytes).ok()? {
        Value::Object(map) if map.values().all(safe_integers) => Some(map),
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
