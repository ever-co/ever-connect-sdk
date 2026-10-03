//! The key manifest (`GET /.well-known/ever-keys.json`): the platform's signing keys, vouched for
//! by a compact JWS signed by a root key pinned for the issuer. No key of a manifest is trusted
//! unless every check passes; they run in this order and the first failure is the answer:
//!
//! 1. the body is `{manifest, keys}` under the closed `ever.key-manifest.v1` schema, every key
//!    time is a UTC time that exists and every key is a curve point of large order:
//!    `schema_violation`
//! 2. `manifest` is a compact JWS (the decoding rule of the JWS module): `malformed`
//! 3. header `typ` is `ever-key-manifest+jwt`: `bad_typ`
//! 4. header `alg` is `EdDSA` and there is no `crit`: `bad_alg`
//! 5. header `kid` is a root pinned for the expected issuer: `unknown_root`
//! 6. the root's Ed25519 signature over `header.payload` (strict): `bad_signature`
//! 7. the payload is `{iss, iat, exp, keys_sha256, root_kid}`, `root_kid` = header `kid`: `malformed`
//! 8. payload `iss` is the expected issuer (an origin): `issuer_mismatch`
//! 9. `iat <= now + 300`: `manifest_not_yet_valid`
//! 10. `now < exp`: `manifest_expired`
//! 11. `keys_sha256` is the hex SHA-256 of the RFC 8785 canonical JSON of `keys`: `keys_sha256_mismatch`
//!
//! The issuer is always given: a manifest is verified for one issuer and the keys it vouches for
//! verify documents of that issuer only. A [`VerifiedKeyManifest`] can only come from
//! [`verify_key_manifest`]: its fields are private.
//!
//! ```compile_fail
//! // Not constructible outside the verifier.
//! let forged = ever_connect_sdk::manifest::VerifiedKeyManifest {
//!     keys: Vec::new(),
//!     root_kid: String::new(),
//!     issuer: String::new(),
//!     issued_at: 0,
//!     expires_at: i64::MAX,
//!     document: serde_json::Value::Null,
//! };
//! ```

use std::fmt;
use std::sync::OnceLock;

use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::encoding::hex;
use crate::jcs::canonical_json;
use crate::jws::{decode, str_of, strong_key, verify_ed25519};
use crate::schema::violations;

/// Seconds of clock difference tolerated on `iat` and on a key's validity window.
pub const CLOCK_SKEW_S: i64 = 300;

/// Why a key manifest is refused, in the order the checks run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyManifestError {
    /// Not the closed `{manifest, keys}` shape, a key time that is not a UTC time that exists, or
    /// a key that is not a curve point of large order.
    SchemaViolation,
    /// Not a compact JWS, or a payload of the wrong shape.
    Malformed,
    /// Another document type.
    BadTyp,
    /// Not EdDSA, or a `crit` header.
    BadAlg,
    /// Not signed by a root pinned for this issuer.
    UnknownRoot,
    /// The root's signature does not verify.
    BadSignature,
    /// Another issuer (or a key set of another issuer).
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

/// A root public key: `iss` pins it to one issuer; a root without `iss` vouches for nothing.
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
    /// A root from a JWKS entry (`kid`, `x`, `iss`).
    #[must_use]
    pub fn from_jwk(jwk: &Value) -> Option<Self> {
        Some(Self {
            kid: jwk.get("kid")?.as_str()?.to_owned(),
            x: jwk.get("x")?.as_str()?.to_owned(),
            iss: jwk.get("iss").and_then(Value::as_str).map(str::to_owned),
        })
    }
}

/// The pinned root keys of this SDK release (`root_keys` of the constants: one per issuer, no
/// TEST root).
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
    kid: String,
    x: String,
    purpose: String,
    state: String,
    not_before: i64,
    not_after: Option<i64>,
}

impl ManifestKey {
    /// The key id.
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }
    /// The raw Ed25519 public key, base64url.
    #[must_use]
    pub fn x(&self) -> &str {
        &self.x
    }
    /// `assertion`, `intent` or `entitlement`.
    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.purpose
    }
    /// `active` or `previous`.
    #[must_use]
    pub fn state(&self) -> &str {
        &self.state
    }
    /// Unix seconds.
    #[must_use]
    pub const fn not_before(&self) -> i64 {
        self.not_before
    }
    /// Unix seconds; `None` while the key has no end.
    #[must_use]
    pub const fn not_after(&self) -> Option<i64> {
        self.not_after
    }
}

/// A key manifest that passed every check, for one issuer. Only [`verify_key_manifest`] makes one.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedKeyManifest {
    keys: Vec<ManifestKey>,
    root_kid: String,
    issuer: String,
    issued_at: i64,
    expires_at: i64,
    document: Value,
}

impl VerifiedKeyManifest {
    /// The keys it vouches for.
    #[must_use]
    pub fn keys(&self) -> &[ManifestKey] {
        &self.keys
    }
    /// The root that signed it.
    #[must_use]
    pub fn root_kid(&self) -> &str {
        &self.root_kid
    }
    /// The issuer origin it was verified for (and names).
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    /// Unix seconds.
    #[must_use]
    pub const fn issued_at(&self) -> i64 {
        self.issued_at
    }
    /// Unix seconds; the manifest is not trusted from then on.
    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }
    /// The body as served, for the product to store and verify again offline.
    #[must_use]
    pub const fn document(&self) -> &Value {
        &self.document
    }
}

/// Options of [`verify_key_manifest`]: the issuer is required.
#[derive(Debug, Clone)]
pub struct VerifyKeyManifestOptions<'a> {
    /// The issuer the manifest is for: the API origin (`EVER_PLATFORM_API_URL`).
    pub issuer: &'a str,
    /// Roots that REPLACE the pinned [`pinned_root_keys`] for this call: for tests, local runs and
    /// offline tools only. A product passes `None`; the client adds extra roots for a local base
    /// URL only.
    pub unsafe_root_keys: Option<&'a [RootKey]>,
    /// Unix seconds (default: now).
    pub now: Option<i64>,
}

impl<'a> VerifyKeyManifestOptions<'a> {
    /// The pinned roots, the system clock, for `issuer`.
    #[must_use]
    pub const fn for_issuer(issuer: &'a str) -> Self {
        Self {
            issuer,
            unsafe_root_keys: None,
            now: None,
        }
    }
}

fn manifest_schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        serde_json::from_str(ever_connect_contracts::schema_key_manifest_v1())
            .unwrap_or_else(|e| panic!("the embedded key manifest schema is not JSON: {e}"))
    })
}

/// The origin of an http(s) URL (`https://api.ever.co`), or `None`. The rule both SDKs share
/// (vectors in `contracts/fixtures/keys/origins.json`): the authority holds only ASCII letters,
/// digits and `. _ - : [ ]` (so userinfo, percent-escapes, backslashes, spaces and hosts that are
/// not ASCII are refused); the scheme and host are lower-cased; the default port is dropped and a
/// port loses its leading zeros (past 65535 is refused); a host the URL standard would rewrite (an
/// IPv4 address not in dotted-decimal form, an IPv6 address not in its shortest form) is refused.
pub(crate) fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "https" && scheme != "http" {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?.to_ascii_lowercase();
    if !authority
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b".-_:[]".contains(&b))
    {
        return None;
    }
    let (host, port) = match authority.rfind(':') {
        Some(i) if !authority[i..].contains(']') => (&authority[..i], Some(&authority[i + 1..])),
        _ => (authority.as_str(), None),
    };
    if !canonical_host(host) {
        return None;
    }
    let port = match port {
        None | Some("") => None,
        Some(p) if p.bytes().all(|b| b.is_ascii_digit()) => {
            let digits = p.trim_start_matches('0');
            let n: u32 = if digits.is_empty() {
                0
            } else if digits.len() > 5 {
                return None;
            } else {
                digits.parse().ok()?
            };
            if n > 65_535 {
                return None;
            }
            let default = if scheme == "https" { 443 } else { 80 };
            (n != default).then_some(n)
        }
        Some(_) => return None,
    };
    Some(match port {
        Some(p) => format!("{scheme}://{host}:{p}"),
        None => format!("{scheme}://{host}"),
    })
}

/// Whether the URL standard keeps `host` (lower case, ASCII) as it is: a bracketed IPv6 address
/// in its shortest form, an IPv4 address in dotted-decimal form, or a name whose last label is not
/// a number.
fn canonical_host(host: &str) -> bool {
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return inner
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|a| ipv6_text(a) == inner);
    }
    if host.is_empty() || host.contains(['[', ']', ':']) {
        return false;
    }
    let labels = host.strip_suffix('.').unwrap_or(host);
    let last = labels.rsplit('.').next().unwrap_or("");
    let numeric = !last.is_empty()
        && (last.bytes().all(|b| b.is_ascii_digit())
            || last
                .strip_prefix("0x")
                .is_some_and(|h| h.bytes().all(|b| b.is_ascii_hexdigit())));
    !numeric
        || host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|a| a.to_string() == host)
}

/// An IPv6 address as the URL standard writes it: lower-case hex pieces, the first longest run of
/// two or more zero pieces compressed to `::`.
fn ipv6_text(address: std::net::Ipv6Addr) -> String {
    let s = address.segments();
    let mut best: Option<(usize, usize)> = None;
    let mut i = 0;
    while i < 8 {
        if s[i] == 0 {
            let start = i;
            while i < 8 && s[i] == 0 {
                i += 1;
            }
            let len = i - start;
            if len > 1 && best.is_none_or(|(_, l)| len > l) {
                best = Some((start, len));
            }
        } else {
            i += 1;
        }
    }
    let mut out = String::new();
    let mut i = 0;
    while i < 8 {
        if let Some((start, len)) = best
            && i == start
        {
            out.push_str(if i == 0 { "::" } else { ":" });
            i += len;
            continue;
        }
        out.push_str(&format!("{:x}", s[i]));
        if i < 7 {
            out.push(':');
        }
        i += 1;
    }
    out
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

/// Unix seconds (the fraction dropped) of a UTC time `YYYY-MM-DDTHH:MM:SS[.fraction]Z` naming a
/// day that exists (no leap second); `None` otherwise. The TypeScript package has the same rule.
#[must_use]
pub fn parse_utc_time(text: &str) -> Option<i64> {
    let b = text.as_bytes();
    let digits = |r: std::ops::Range<usize>| -> Option<i64> {
        let s = text.get(r)?;
        if s.bytes().all(|c| c.is_ascii_digit()) {
            s.parse().ok()
        } else {
            None
        }
    };
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let (y, mo, d, h, mi, s) = (
        digits(0..4)?,
        digits(5..7)?,
        digits(8..10)?,
        digits(11..13)?,
        digits(14..16)?,
        digits(17..19)?,
    );
    let rest = &text[19..];
    let rest = match rest.strip_prefix('.') {
        Some(fraction) => {
            let n = fraction.bytes().take_while(u8::is_ascii_digit).count();
            if !(1..=9).contains(&n) {
                return None;
            }
            &fraction[n..]
        }
        None => rest,
    };
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let days_in = match mo {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if rest != "Z" || !(1..=12).contains(&mo) || d < 1 || d > days_in || h > 23 || mi > 59 || s > 59
    {
        return None;
    }
    // Days from the civil date (Howard Hinnant's algorithm), as the TypeScript package computes them.
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + mi * 60 + s)
}

/// The keys of the body, when every one is well formed: times that exist, a key of large order.
fn well_formed_keys(keys: &Value) -> Option<Vec<ManifestKey>> {
    keys.as_array()?
        .iter()
        .map(|k| {
            let s = |name: &str| k.get(name).and_then(Value::as_str).map(str::to_owned);
            let x = s("x")?;
            strong_key(&x)?;
            let not_after = match k.get("not_after") {
                None | Some(Value::Null) => None,
                Some(Value::String(t)) => Some(parse_utc_time(t)?),
                Some(_) => return None,
            };
            Some(ManifestKey {
                kid: s("kid")?,
                x,
                purpose: s("ever_purpose")?,
                state: s("state")?,
                not_before: parse_utc_time(&s("not_before")?)?,
                not_after,
            })
        })
        .collect()
}

/// Verifies a key manifest body for one issuer. Answers the keys it vouches for, or the code of
/// the first failed check.
///
/// # Errors
/// [`KeyManifestError`].
pub fn verify_key_manifest(
    body: &Value,
    options: &VerifyKeyManifestOptions<'_>,
) -> Result<VerifiedKeyManifest, KeyManifestError> {
    let roots = options
        .unsafe_root_keys
        .unwrap_or_else(|| pinned_root_keys());
    let now = options.now.unwrap_or_else(now_s);
    let expected = origin_of(options.issuer);

    // 1. The closed schema of the served body, and the key rules it cannot say.
    let schema = manifest_schema();
    if !violations(schema, body, schema).is_empty() {
        return Err(KeyManifestError::SchemaViolation);
    }
    let token = body
        .get("manifest")
        .and_then(Value::as_str)
        .ok_or(KeyManifestError::SchemaViolation)?;
    let keys_value = body.get("keys").ok_or(KeyManifestError::SchemaViolation)?;
    let keys = well_formed_keys(keys_value).ok_or(KeyManifestError::SchemaViolation)?;
    // 2. A compact JWS.
    let jws = decode(token).ok_or(KeyManifestError::Malformed)?;
    // 3-4. Type, then algorithm (before any key is looked at).
    if str_of(&jws.header, "typ") != Some("ever-key-manifest+jwt") {
        return Err(KeyManifestError::BadTyp);
    }
    if str_of(&jws.header, "alg") != Some("EdDSA") || jws.header.contains_key("crit") {
        return Err(KeyManifestError::BadAlg);
    }
    // 5. A root pinned for this issuer: a root vouches only for the issuer it names.
    let header_kid = str_of(&jws.header, "kid");
    let expected = expected.ok_or(KeyManifestError::UnknownRoot)?;
    let root = roots
        .iter()
        .find(|r| {
            Some(r.kid.as_str()) == header_kid
                && r.iss.as_deref().and_then(origin_of).as_deref() == Some(expected.as_str())
                && strong_key(&r.x).is_some()
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
    if payload.get("iss").and_then(Value::as_str) != Some(expected.as_str()) {
        return Err(KeyManifestError::IssuerMismatch);
    }
    // 9-10. The validity window.
    if iat > now.saturating_add(CLOCK_SKEW_S) {
        return Err(KeyManifestError::ManifestNotYetValid);
    }
    if now >= exp {
        return Err(KeyManifestError::ManifestExpired);
    }
    // 11. The served keys are the keys the root signed.
    if Some(keys_sha256(keys_value)?.as_str()) != payload.get("keys_sha256").and_then(Value::as_str)
    {
        return Err(KeyManifestError::KeysSha256Mismatch);
    }

    Ok(VerifiedKeyManifest {
        keys,
        root_kid: root.kid.clone(),
        issuer: expected,
        issued_at: iat,
        expires_at: exp,
        document: body.clone(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{origin_of, parse_utc_time};

    #[test]
    fn the_shared_origin_vectors() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../contracts/fixtures/keys/origins.json");
        let file: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let vectors = file["vectors"].as_array().unwrap();
        assert!(vectors.len() > 50);
        for v in vectors {
            let url = v["url"].as_str().unwrap();
            assert_eq!(origin_of(url).as_deref(), v["origin"].as_str(), "{url:?}");
        }
    }

    #[test]
    fn origins_and_times() {
        assert_eq!(
            origin_of("https://API.ever.co/a/b?c#d").as_deref(),
            Some("https://api.ever.co")
        );
        assert_eq!(
            origin_of("https://api.ever.co:443").as_deref(),
            Some("https://api.ever.co")
        );
        assert_eq!(
            origin_of("https://api.ever.co:0443").as_deref(),
            Some("https://api.ever.co")
        );
        assert_eq!(
            origin_of("http://127.0.0.1:08080/").as_deref(),
            Some("http://127.0.0.1:8080")
        );
        assert_eq!(
            origin_of("http://[::1]:9/").as_deref(),
            Some("http://[::1]:9")
        );
        assert_eq!(origin_of("https://user@api.ever.co"), None);
        assert_eq!(origin_of("https://api.ever.co:70000"), None);
        assert_eq!(origin_of("https://bücher.example"), None);
        assert_eq!(origin_of("ftp://x"), None);
        assert_eq!(parse_utc_time("2026-11-01T10:00:00Z"), Some(1_793_527_200));
        assert_eq!(parse_utc_time("1970-01-01T00:00:00.5Z"), Some(0));
        assert_eq!(parse_utc_time("2024-02-29T00:00:00Z"), Some(1_709_164_800));
        for bad in [
            "2026-11-01 10:00:00Z",
            "2026-11-01T10:00:00+02:00",
            "2026-11-01T10:00:00z",
            "2026-06-30T23:59:60Z",
            "2026-02-31T00:00:00Z",
            "2026-02-29T00:00:00Z",
            "2026-11-01",
            "+2026-11-01T10:00:00Z",
            "2026-11-01T10:00:00.Z",
            "2026-11-01T10:00:00.1234567890Z",
            "soon",
        ] {
            assert_eq!(parse_utc_time(bad), None, "{bad}");
        }
    }
}
