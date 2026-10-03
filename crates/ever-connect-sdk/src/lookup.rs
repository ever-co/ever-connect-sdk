//! Counterparty lookup: identifier normalisation (version 1) and the salted hash an installation
//! sends instead of the identifier. An identifier that cannot be normalised is never hashed or sent
//! ([`LookupInputError`], "cannot be checked").
//!
//! * `vat`: trim, upper-case, drop spaces, dots, hyphens and slashes; a leading two-letter prefix
//!   is the country, otherwise the caller's country is prepended.
//! * `registration`: `<CC>:<number>`: the caller's country, then the number trimmed, upper-cased,
//!   without spaces, dots and hyphens.
//! * `email`: trim, Unicode NFC, lower-case, the part after the last `@` IDNA-encoded (UTS 46, as
//!   the URL standard does); no plus-tag or dot is removed.
//!
//! `hash = hex(sha256(salt bytes ‖ ":" ‖ kind ‖ ":" ‖ utf8(normalized)))`.
//!
//! This module needs only the `lookup` feature: `default-features = false, features = ["lookup"]`
//! pulls no HTTP client.

use std::fmt;

use serde_json::Value;
use sha2::{Digest as _, Sha256};
use unicode_normalization::UnicodeNormalization as _;

use crate::encoding::{from_b64url, hex};

/// The identifier kinds of normalisation version 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LookupKind {
    /// A VAT number.
    Vat,
    /// A company registration number (with its country).
    Registration,
    /// An e-mail address.
    Email,
}

impl LookupKind {
    /// `vat`, `registration` or `email`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Vat => "vat",
            Self::Registration => "registration",
            Self::Email => "email",
        }
    }

    /// The kind of a spelling.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "vat" => Some(Self::Vat),
            "registration" => Some(Self::Registration),
            "email" => Some(Self::Email),
            _ => None,
        }
    }
}

/// The normalisation version this module implements.
pub const NORMALIZATION_VERSION: u32 = 1;

/// Why an identifier cannot be checked (it is never hashed or sent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LookupInputError {
    /// Nothing is left after normalisation.
    Empty,
    /// A VAT number without a prefix, or a registration number, and no two-letter country.
    NoCountry,
    /// An e-mail address without `@`.
    NoAtSign,
    /// The part after the last `@` is not a domain.
    BadDomain,
}

impl LookupInputError {
    /// The reason.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::NoCountry => "no_country",
            Self::NoAtSign => "no_at_sign",
            Self::BadDomain => "bad_domain",
        }
    }

    /// The code products show: `cannot_be_checked`.
    #[must_use]
    pub const fn code(self) -> &'static str {
        "cannot_be_checked"
    }
}

impl fmt::Display for LookupInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "identifier cannot be checked ({})", self.reason())
    }
}

impl std::error::Error for LookupInputError {}

/// `String.prototype.trim` of ECMAScript (its white space and line terminators), so both SDKs
/// trim the same characters.
fn js_trim(text: &str) -> &str {
    text.trim_matches(|c: char| {
        matches!(
            c,
            '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
                ..='\u{200a}'
                    | '\u{2028}'
                    | '\u{2029}'
                    | '\u{202f}'
                    | '\u{205f}'
                    | '\u{3000}'
                    | '\u{feff}'
        )
    })
}

fn country(country: Option<&str>) -> Result<String, LookupInputError> {
    let cc = js_trim(country.unwrap_or("")).to_uppercase();
    if cc.len() == 2 && cc.bytes().all(|b| b.is_ascii_uppercase()) {
        Ok(cc)
    } else {
        Err(LookupInputError::NoCountry)
    }
}

/// Normalises an identifier (version 1).
///
/// # Errors
/// [`LookupInputError`] when it cannot be checked.
pub fn normalize_identifier(
    kind: LookupKind,
    value: &str,
    country_code: Option<&str>,
) -> Result<String, LookupInputError> {
    match kind {
        LookupKind::Vat => {
            let v: String = js_trim(value)
                .to_uppercase()
                .chars()
                .filter(|c| !matches!(c, ' ' | '.' | '-' | '/'))
                .collect();
            if v.is_empty() {
                return Err(LookupInputError::Empty);
            }
            let prefixed = v.chars().take(2).filter(char::is_ascii_uppercase).count() == 2;
            Ok(if prefixed {
                v
            } else {
                format!("{}{v}", country(country_code)?)
            })
        }
        LookupKind::Registration => {
            let n: String = js_trim(value)
                .to_uppercase()
                .chars()
                .filter(|c| !matches!(c, ' ' | '.' | '-'))
                .collect();
            if n.is_empty() {
                return Err(LookupInputError::Empty);
            }
            Ok(format!("{}:{n}", country(country_code)?))
        }
        LookupKind::Email => {
            let v: String = js_trim(value).nfc().collect::<String>().to_lowercase();
            if v.is_empty() {
                return Err(LookupInputError::Empty);
            }
            let at = v.rfind('@').ok_or(LookupInputError::NoAtSign)?;
            let domain =
                idna::domain_to_ascii(&v[at + 1..]).map_err(|_| LookupInputError::BadDomain)?;
            if domain.is_empty() {
                return Err(LookupInputError::BadDomain);
            }
            Ok(format!("{}@{domain}", &v[..at]))
        }
    }
}

/// One hashed identifier, as `POST /v1/lookup` and the identifier upload take it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupHash {
    /// The kind.
    pub kind: LookupKind,
    /// The salt version.
    pub salt_version: u32,
    /// 64 lower-case hex characters.
    pub hash: String,
}

/// A salt that is not 32 bytes of base64url.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadSalt;

impl fmt::Display for BadSalt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a lookup salt is 32 bytes, base64url")
    }
}

impl std::error::Error for BadSalt {}

/// The salted hash of a normalised identifier.
///
/// # Errors
/// [`BadSalt`].
pub fn lookup_hash(
    kind: LookupKind,
    normalized: &str,
    salt_version: u32,
    salt: &str,
) -> Result<LookupHash, BadSalt> {
    let salt_bytes = from_b64url(salt).filter(|b| b.len() == 32).ok_or(BadSalt)?;
    let mut h = Sha256::new();
    h.update(&salt_bytes);
    h.update(b":");
    h.update(kind.as_str().as_bytes());
    h.update(b":");
    h.update(normalized.as_bytes());
    Ok(LookupHash {
        kind,
        salt_version,
        hash: hex(&h.finalize()),
    })
}

/// A published test vector the crate does not reproduce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupVectorError {
    /// The index of the vector.
    pub index: usize,
    /// `normalized` or `hash`.
    pub field: &'static str,
}

impl fmt::Display for LookupVectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "lookup test vector {}: the {} differs",
            self.index, self.field
        )
    }
}

impl std::error::Error for LookupVectorError {}

/// Reproduces every published vector (`GET /v1/lookup/test-vectors`).
///
/// # Errors
/// [`LookupVectorError`] at the first vector that differs.
pub fn check_test_vectors(vectors: &Value) -> Result<(), LookupVectorError> {
    let Some(salt) = vectors.get("salt").and_then(Value::as_str) else {
        return Err(LookupVectorError {
            index: 0,
            field: "hash",
        });
    };
    let salt_version = vectors
        .get("salt_version")
        .and_then(Value::as_u64)
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(0);
    let rows = vectors
        .get("vectors")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    for (index, v) in rows.iter().enumerate() {
        let field = |name| v.get(name).and_then(Value::as_str);
        let normalized_error = LookupVectorError {
            index,
            field: "normalized",
        };
        let kind = field("kind")
            .and_then(LookupKind::parse)
            .ok_or_else(|| normalized_error.clone())?;
        let normalized = normalize_identifier(kind, field("input").unwrap_or(""), field("country"))
            .map_err(|_| normalized_error.clone())?;
        if Some(normalized.as_str()) != field("normalized") {
            return Err(normalized_error);
        }
        let hash =
            lookup_hash(kind, &normalized, salt_version, salt).map_err(|_| LookupVectorError {
                index,
                field: "hash",
            })?;
        if Some(hash.hash.as_str()) != field("hash") {
            return Err(LookupVectorError {
                index,
                field: "hash",
            });
        }
    }
    Ok(())
}
