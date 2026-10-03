//! Byte helpers shared by the signers and verifiers.

// Shared by several features: with only some of them, part of this module is unused.
#![cfg_attr(not(feature = "client"), allow(dead_code))]

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// base64url without padding.
pub(crate) fn b64url(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The bytes of a base64url string, or `None` when it is not canonical base64url without padding
/// (a stray trailing bit or a padding character is refused).
pub(crate) fn from_b64url(text: &str) -> Option<Vec<u8>> {
    if !text
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(text).ok()?;
    (URL_SAFE_NO_PAD.encode(&bytes) == text).then_some(bytes)
}

/// Lower-case hex.
#[cfg(any(feature = "entitlement", feature = "lookup", feature = "client"))]
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Whether `text` is a ULID (Crockford base32, 26 characters, upper case).
#[cfg(any(feature = "entitlement", feature = "client"))]
pub(crate) fn is_ulid(text: &str) -> bool {
    text.len() == 26
        && text.bytes().all(|b| {
            b.is_ascii_digit()
                || (b.is_ascii_uppercase() && !matches!(b, b'I' | b'L' | b'O' | b'U'))
        })
}
