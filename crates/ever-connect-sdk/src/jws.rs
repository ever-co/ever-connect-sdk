//! Compact JWS (RFC 7515) with EdDSA over Ed25519 (RFC 8037) only.

use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde_json::{Map, Value};

use crate::encoding::from_b64url;

/// A decoded compact JWS.
pub(crate) struct DecodedJws {
    pub(crate) header: Map<String, Value>,
    pub(crate) payload: Map<String, Value>,
    /// `base64url(header) "." base64url(payload)`: the bytes the signature covers.
    pub(crate) signing_input: String,
    pub(crate) signature: Vec<u8>,
}

fn object(part: &str) -> Option<Map<String, Value>> {
    let bytes = from_b64url(part)?;
    // serde_json refuses invalid UTF-8, as the TypeScript decoder (fatal) does.
    match serde_json::from_slice::<Value>(&bytes).ok()? {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

/// Splits and decodes a compact JWS; `None` unless it is exactly three canonical base64url parts
/// whose first two are JSON objects.
pub(crate) fn decode(token: &str) -> Option<DecodedJws> {
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

/// Whether `signature` is a valid Ed25519 signature by the key `x` (base64url, 32 bytes) over
/// `message`.
pub(crate) fn verify_ed25519(x: &str, message: &[u8], signature: &[u8]) -> bool {
    let Some(raw) = from_b64url(x) else {
        return false;
    };
    let (Ok(raw), Ok(sig)) = (
        <[u8; 32]>::try_from(raw.as_slice()),
        <[u8; 64]>::try_from(signature),
    ) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&raw) else {
        return false;
    };
    key.verify(message, &Signature::from_bytes(&sig)).is_ok()
}

/// A header or payload member as a string.
pub(crate) fn str_of<'a>(map: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    map.get(name).and_then(Value::as_str)
}
