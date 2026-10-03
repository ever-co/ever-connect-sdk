//! Compact JWS (RFC 7515) with EdDSA over Ed25519 (RFC 8037) only.
//!
//! A JWS is decoded by one rule in both SDKs and on the platform: at most 64 KiB; three canonical
//! base64url parts; header and payload are JSON objects in valid UTF-8 (a leading byte-order mark
//! is not whitespace); no string or member name holds a lone surrogate; every number fits a double;
//! at most 127 nested arrays and objects (serde_json's own limits). Anything else is `malformed`.
//! How a number is written is checked where the value is read: the verifiers require the integer
//! claims they read to be I-JSON integers ([`first_non_integer`]). Signatures are verified
//! strictly: a small-order public key or `R` never verifies.

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
