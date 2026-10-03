//! The key manifest (`GET /.well-known/ever-keys.json`): the platform's signing keys, vouched for
//! by a compact JWS signed by a pinned root key. No key of a manifest is trusted unless every check
//! passes; they run in this order and the first failure is the answer:
//!
//! 1. the body is `{manifest, keys}` under the closed `ever.key-manifest.v1` schema: `schema_violation`
//! 2. `manifest` is three canonical base64url parts with JSON objects: `malformed`
//! 3. header `typ` is `ever-key-manifest+jwt`: `bad_typ`
//! 4. header `alg` is `EdDSA` and there is no `crit`: `bad_alg`
//! 5. header `kid` is a pinned root (pinned for this issuer when the root names one): `unknown_root`
//! 6. the root's Ed25519 signature over `header.payload`: `bad_signature`
//! 7. the payload is `{iss, iat, exp, keys_sha256, root_kid}`, `root_kid` = header `kid`: `malformed`
//! 8. payload `iss` is the expected issuer (an origin): `issuer_mismatch`
//! 9. `iat <= now + 300`: `manifest_not_yet_valid`
//! 10. `now < exp`: `manifest_expired`
//! 11. `keys_sha256` is the hex SHA-256 of the RFC 8785 canonical JSON of `keys`: `keys_sha256_mismatch`

use std::fmt;
use std::sync::OnceLock;

use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::encoding::hex;
use crate::jcs::canonical_json;
use crate::jws::{decode, str_of, verify_ed25519};
use crate::schema::violations;

/// Seconds of clock difference tolerated on `iat` and on a key's validity window.
pub const CLOCK_SKEW_S: i64 = 300;

/// Why a key manifest is refused, in the order the checks run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyManifestError {
    /// Not the closed `{manifest, keys}` shape.
    SchemaViolation,
    /// Not a compact JWS, or a payload of the wrong shape.
    Malformed,
    /// Another document type.
    BadTyp,
    /// Not EdDSA, or a `crit` header.
    BadAlg,
    /// Not signed by a pinned root (for this issuer).
    UnknownRoot,
    /// The root's signature does not verify.
    BadSignature,
    /// Another issuer.
    IssuerMismatch,
    /// Issued more than 300 s in the future.
    ManifestNotYetValid,
    /// Past its `exp`.
    ManifestExpired,
    /// The served keys are not the keys the root signed.
    KeysSha256Mismatch,
}

impl KeyManifestError {
    /// The code (the same in the TypeScript SDK).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SchemaViolation => "schema_violation",
            Self::Malformed => "malformed",
            Self::BadTyp => "bad_typ",
            Self::BadAlg => "bad_alg",
            Self::UnknownRoot => "unknown_root",
            Self::BadSignature => "bad_signature",
            Self::IssuerMismatch => "issuer_mismatch",
            Self::ManifestNotYetValid => "manifest_not_yet_valid",
            Self::ManifestExpired => "manifest_expired",
            Self::KeysSha256Mismatch => "keys_sha256_mismatch",
        }
    }
}

impl fmt::Display for KeyManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "key manifest refused: {}", self.code())
    }
}

impl std::error::Error for KeyManifestError {}

/// A pinned root public key (`root_keys` of the constants; `iss` pins it to one issuer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootKey {
    /// The key id.
    pub kid: String,
    /// The raw Ed25519 public key, base64url.
    pub x: String,
    /// The issuer it is pinned for.
    pub iss: Option<String>,
}

impl RootKey {
    /// A root from a JWKS entry (`kid`, `x`, optional `iss`).
    #[must_use]
    pub fn from_jwk(jwk: &Value) -> Option<Self> {
        Some(Self {
            kid: jwk.get("kid")?.as_str()?.to_owned(),
            x: jwk.get("x")?.as_str()?.to_owned(),
            iss: jwk.get("iss").and_then(Value::as_str).map(str::to_owned),
        })
    }
}

/// The pinned root keys of this SDK release (`root_keys` of the constants).
#[must_use]
pub fn pinned_root_keys() -> &'static [RootKey] {
    static ROOTS: OnceLock<Vec<RootKey>> = OnceLock::new();
    ROOTS.get_or_init(|| {
        ever_connect_contracts::constants()
            .get("root_keys")
            .and_then(Value::as_array)
            .map(|keys| keys.iter().filter_map(RootKey::from_jwk).collect())
            .unwrap_or_default()
    })
}

/// A signing key the manifest lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestKey {
    /// The key id.
    pub kid: String,
    /// The raw Ed25519 public key, base64url.
    pub x: String,
    /// `assertion`, `intent` or `entitlement`.
    pub purpose: String,
    /// `active` or `previous`.
    pub state: String,
    /// Unix seconds.
    pub not_before: Option<i64>,
    /// Unix seconds; `None` while the key has no end.
    pub not_after: Option<i64>,
}

/// A key manifest that passed every check.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedKeyManifest {
    /// The keys it vouches for.
    pub keys: Vec<ManifestKey>,
    /// The root that signed it.
    pub root_kid: String,
    /// The issuer origin it names.
    pub issuer: String,
    /// Unix seconds.
    pub issued_at: i64,
    /// Unix seconds; the manifest is not trusted from then on.
    pub expires_at: i64,
    /// The body as served, for the product to store and verify again offline.
    pub document: Value,
}

/// Options of [`verify_key_manifest`].
#[derive(Debug, Clone, Default)]
pub struct VerifyKeyManifestOptions<'a> {
    /// The roots to trust (default: [`pinned_root_keys`]). Passing roots replaces the pinned ones
    /// for this call (tests, offline tools); the client adds extra roots for a local base URL only.
    pub root_keys: Option<&'a [RootKey]>,
    /// The issuer the payload must name (default: the issuer the matched root is pinned to).
    pub issuer: Option<&'a str>,
    /// Unix seconds (default: now).
    pub now: Option<i64>,
}

fn manifest_schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        serde_json::from_str(ever_connect_contracts::schema_key_manifest_v1())
            .unwrap_or_else(|e| panic!("the embedded key manifest schema is not JSON: {e}"))
    })
}

/// The origin of an http(s) URL (`https://api.ever.co`), or `None`.
pub(crate) fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "https" && scheme != "http" {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let host = authority.to_ascii_lowercase();
    let default_port = if scheme == "https" { ":443" } else { ":80" };
    let host = host.strip_suffix(default_port).unwrap_or(&host);
    Some(format!("{scheme}://{host}"))
}

/// The current time in Unix seconds.
pub(crate) fn now_s() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Lower-case hex SHA-256 of the RFC 8785 canonical JSON of a key list (`keys_sha256`).
///
/// # Errors
/// [`KeyManifestError::Malformed`] when the list holds a number that is not an integer.
pub fn keys_sha256(keys: &Value) -> Result<String, KeyManifestError> {
    let text = canonical_json(keys).map_err(|_| KeyManifestError::Malformed)?;
    Ok(hex(&Sha256::digest(text.as_bytes())))
}

fn seconds(value: Option<&Value>) -> Option<i64> {
    let text = value?.as_str()?;
    parse_rfc3339(text)
}

/// Unix seconds of an RFC 3339 UTC time (`YYYY-MM-DDTHH:MM:SS[.fraction]Z`).
pub(crate) fn parse_rfc3339(text: &str) -> Option<i64> {
    let b = text.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> { text.get(r)?.parse().ok() };
    let (y, mo, d, h, mi, s) = (
        num(0..4)?,
        num(5..7)?,
        num(8..10)?,
        num(11..13)?,
        num(14..16)?,
        num(17..19)?,
    );
    let rest = &text[19..];
    let rest = rest
        .strip_prefix('.')
        .map_or(rest, |f| f.trim_start_matches(|c: char| c.is_ascii_digit()));
    if rest != "Z"
        || !(1..=12).contains(&mo)
        || !(1..=31).contains(&d)
        || h > 23
        || mi > 59
        || s > 60
    {
        return None;
    }
    // Days from the civil date (Howard Hinnant's algorithm).
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + mi * 60 + s)
}

/// Verifies a key manifest body. Answers the keys it vouches for, or the code of the first failed
/// check.
///
/// # Errors
/// [`KeyManifestError`].
pub fn verify_key_manifest(
    body: &Value,
    options: &VerifyKeyManifestOptions<'_>,
) -> Result<VerifiedKeyManifest, KeyManifestError> {
    let roots = options.root_keys.unwrap_or_else(|| pinned_root_keys());
    let now = options.now.unwrap_or_else(now_s);

    // 1. The closed schema of the served body.
    let schema = manifest_schema();
    if !violations(schema, body, schema).is_empty() {
        return Err(KeyManifestError::SchemaViolation);
    }
    let token = body
        .get("manifest")
        .and_then(Value::as_str)
        .ok_or(KeyManifestError::SchemaViolation)?;
    let keys = body.get("keys").ok_or(KeyManifestError::SchemaViolation)?;
    // 2. Three canonical base64url parts with JSON objects.
    let jws = decode(token).ok_or(KeyManifestError::Malformed)?;
    // 3-4. Type, then algorithm (before any key is looked at).
    if str_of(&jws.header, "typ") != Some("ever-key-manifest+jwt") {
        return Err(KeyManifestError::BadTyp);
    }
    if str_of(&jws.header, "alg") != Some("EdDSA") || jws.header.contains_key("crit") {
        return Err(KeyManifestError::BadAlg);
    }
    // 5. A pinned root, pinned to this issuer when the root names one.
    let expected = match options.issuer {
        Some(issuer) => Some(origin_of(issuer).ok_or(KeyManifestError::IssuerMismatch)?),
        None => None,
    };
    let header_kid = str_of(&jws.header, "kid");
    let root = roots
        .iter()
        .find(|r| {
            Some(r.kid.as_str()) == header_kid
                && match (&r.iss, &expected) {
                    (Some(iss), Some(expected)) => {
                        origin_of(iss).as_deref() == Some(expected.as_str())
                    }
                    _ => true,
                }
        })
        .ok_or(KeyManifestError::UnknownRoot)?;
    // 6. The root's signature.
    if !verify_ed25519(&root.x, jws.signing_input.as_bytes(), &jws.signature) {
        return Err(KeyManifestError::BadSignature);
    }
    // 7. The payload shape; the payload names the root that signed it.
    let payload = Value::Object(jws.payload);
    let payload_schema = schema
        .pointer("/$defs/payload")
        .ok_or(KeyManifestError::Malformed)?;
    if !violations(schema, &payload, payload_schema).is_empty()
        || payload.get("root_kid").and_then(Value::as_str) != header_kid
    {
        return Err(KeyManifestError::Malformed);
    }
    let int = |name: &str| {
        payload
            .get(name)
            .and_then(Value::as_i64)
            .ok_or(KeyManifestError::Malformed)
    };
    let (iat, exp) = (int("iat")?, int("exp")?);
    // 8. The issuer.
    let issuer = match expected {
        Some(expected) => expected,
        None => root
            .iss
            .as_deref()
            .and_then(origin_of)
            .ok_or(KeyManifestError::IssuerMismatch)?,
    };
    if payload.get("iss").and_then(Value::as_str) != Some(issuer.as_str()) {
        return Err(KeyManifestError::IssuerMismatch);
    }
    // 9-10. The validity window.
    if iat > now + CLOCK_SKEW_S {
        return Err(KeyManifestError::ManifestNotYetValid);
    }
    if now >= exp {
        return Err(KeyManifestError::ManifestExpired);
    }
    // 11. The served keys are the keys the root signed.
    if Some(keys_sha256(keys)?.as_str()) != payload.get("keys_sha256").and_then(Value::as_str) {
        return Err(KeyManifestError::KeysSha256Mismatch);
    }

    let keys = keys
        .as_array()
        .ok_or(KeyManifestError::SchemaViolation)?
        .iter()
        .map(|k| {
            let s = |name: &str| {
                k.get(name)
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or(KeyManifestError::SchemaViolation)
            };
            Ok(ManifestKey {
                kid: s("kid")?,
                x: s("x")?,
                purpose: s("ever_purpose")?,
                state: s("state")?,
                not_before: seconds(k.get("not_before")),
                not_after: seconds(k.get("not_after")),
            })
        })
        .collect::<Result<Vec<_>, KeyManifestError>>()?;
    Ok(VerifiedKeyManifest {
        keys,
        root_kid: root.kid.clone(),
        issuer,
        issued_at: iat,
        expires_at: exp,
        document: body.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::{origin_of, parse_rfc3339};

    #[test]
    fn origins_and_times() {
        assert_eq!(
            origin_of("https://API.ever.co/a/b").as_deref(),
            Some("https://api.ever.co")
        );
        assert_eq!(
            origin_of("https://api.ever.co:443").as_deref(),
            Some("https://api.ever.co")
        );
        assert_eq!(
            origin_of("http://127.0.0.1:8080/").as_deref(),
            Some("http://127.0.0.1:8080")
        );
        assert_eq!(origin_of("ftp://x"), None);
        assert_eq!(parse_rfc3339("2026-11-01T10:00:00Z"), Some(1_793_527_200));
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00.5Z"), Some(0));
        assert_eq!(parse_rfc3339("2026-11-01 10:00:00Z"), None);
    }
}
