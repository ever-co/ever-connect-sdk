//! The entitlement document verifier (`ever.entitlement.v1`), the one implementation every product
//! uses. The checks run in the order of the contract (the entitlement document format, section
//! 3.1) with its codes, the same as the platform's reference verifier, and fail closed at the first
//! one that does not pass:
//!
//! 1. a compact JWS (the decoding rule of the JWS module: 64 KiB, canonical parts, well-formed
//!    strings, numbers that fit a double, 127 levels): `malformed`
//! 2. header `typ` is `ever-entitlement+jwt`: `bad_typ`
//! 3. header `alg` is `EdDSA` and there is no `crit` (before any key lookup): `bad_alg`
//! 4. the key set's manifest is not past its `exp` (keys of an expired manifest verify no new
//!    document: refresh the key set): `manifest_expired`
//! 5. header `kid` is in the root-verified key set, purpose `entitlement`, state `active` or
//!    `previous`, inside its validity window: `unknown_kid`
//! 6. the Ed25519 signature over `header.payload` (strict: no small-order point): `bad_signature`
//! 7. `ever.schema` is `ever.entitlement.v1`: `schema_violation`
//! 8. `iss` is the origin of the expected issuer, and so is the issuer of the key set's manifest
//!    (a key set never verifies another issuer's document): `issuer_mismatch`
//! 9. `aud` is `ever-connect`: `audience_mismatch`
//! 10. the closed schema of the whole payload (with its I-JSON `maximum`s and the members each
//!     kind of subject carries), and `iat`, `nbf`, `exp`, `ever.seq` and `ever.grace_s` written
//!     as I-JSON integers (no fraction, no exponent, not `-0`): `schema_violation`
//! 11. `ever.instance_id` is this installation's Registry id: `instance_mismatch`
//! 12. `sub` is the expected subject (`instance:<id>` or `link:<id>`); a link document names
//!     its own link (`ever.tenant_link_id`): `subject_mismatch`
//! 13. `iat <= now + 300`: `iat_in_future`
//! 14. `nbf <= now + 300`: `nbf_in_future`
//! 15. against the cached document: a lower `seq`, or the same `seq` without a later `iat`:
//!     `entitlement_stale`
//!
//! `exp` is never a failure: it feeds [`entitlement_status`] only. No error carries the token or a
//! claim value.

use std::fmt;
use std::sync::OnceLock;

use serde_json::Value;

use crate::jws::{decode, first_non_integer, str_of, verify_ed25519};
use crate::keyset::KeySet;
use crate::manifest::{CLOCK_SKEW_S, now_s, origin_of};
use crate::schema::violations;

/// Why an entitlement document is refused, in the order the checks run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EntitlementErrorCode {
    /// Not a compact JWS of three canonical parts with JSON objects.
    Malformed,
    /// Another document type.
    BadTyp,
    /// Not EdDSA, or a `crit` header.
    BadAlg,
    /// The key set's manifest is past its `exp`: it vouches for no new document (refresh it).
    ManifestExpired,
    /// No trusted entitlement key of that id.
    UnknownKid,
    /// The signature does not verify.
    BadSignature,
    /// The payload breaks the closed `ever.entitlement.v1` schema.
    SchemaViolation,
    /// Another issuer.
    IssuerMismatch,
    /// Another audience.
    AudienceMismatch,
    /// Issued for another installation.
    InstanceMismatch,
    /// Another subject.
    SubjectMismatch,
    /// Issued more than 300 s in the future.
    IatInFuture,
    /// Not valid before more than 300 s in the future.
    NbfInFuture,
    /// Older than the cached document.
    EntitlementStale,
}

impl EntitlementErrorCode {
    /// The code (the same in the TypeScript SDK).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::BadTyp => "bad_typ",
            Self::BadAlg => "bad_alg",
            Self::ManifestExpired => "manifest_expired",
            Self::UnknownKid => "unknown_kid",
            Self::BadSignature => "bad_signature",
            Self::SchemaViolation => "schema_violation",
            Self::IssuerMismatch => "issuer_mismatch",
            Self::AudienceMismatch => "audience_mismatch",
            Self::InstanceMismatch => "instance_mismatch",
            Self::SubjectMismatch => "subject_mismatch",
            Self::IatInFuture => "iat_in_future",
            Self::NbfInFuture => "nbf_in_future",
            Self::EntitlementStale => "entitlement_stale",
        }
    }
}

/// A refused entitlement document: keep the previous one. With `refresh_suggested` (an unknown
/// `kid`), refresh the key set once (see [`KeySet::unknown_kid_refresh_allowed`]) and verify
/// again; a second `unknown_kid` is final.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntitlementError {
    /// The code.
    pub code: EntitlementErrorCode,
    /// Whether one key-set refresh may help.
    pub refresh_suggested: bool,
    /// For `schema_violation`: the JSON pointer of the first field that breaks the schema.
    pub path: Option<String>,
}

impl fmt::Display for EntitlementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "entitlement document refused: {}", self.code.as_str())
    }
}

impl std::error::Error for EntitlementError {}

/// The ladder status of a document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntitlementStatus {
    /// Before `exp`.
    Valid,
    /// Within `grace_s` after `exp`: Ever Platform features keep working.
    Stale,
    /// Past the grace, or no document: Ever Platform features pause; the product keeps working.
    Paused,
}

impl EntitlementStatus {
    /// `valid`, `stale` or `paused`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Stale => "stale",
            Self::Paused => "paused",
        }
    }
}

/// The last verified document of a subject, as the product stores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachedEntitlement {
    /// Its `ever.seq`.
    pub seq: i64,
    /// Its `iat`.
    pub iat: i64,
}

/// The expectations of [`verify_entitlement`].
#[derive(Debug, Clone)]
pub struct VerifyEntitlementOptions<'a> {
    /// The root-verified keys.
    pub key_set: &'a KeySet,
    /// The API origin (`EVER_PLATFORM_API_URL`); only its origin is compared.
    pub expected_issuer: &'a str,
    /// This installation's Registry id (a ULID).
    pub expected_instance_id: &'a str,
    /// `instance:<registry id>` or `link:<tenant link id>`.
    pub expected_subject: &'a str,
    /// The cached document of the same subject, when a newer one is verified; `None` to verify the
    /// stored document itself again.
    pub cached: Option<CachedEntitlement>,
    /// Unix seconds (default: now).
    pub now: Option<i64>,
}

/// A verified entitlement document.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedEntitlement {
    /// The claims (the JWS payload).
    pub claims: Value,
    /// The key that signed it.
    pub kid: String,
    /// `ever.seq`.
    pub seq: i64,
    /// The document exactly as received: store these bytes.
    pub jws: String,
    /// The ladder status at the verification time.
    pub status: EntitlementStatus,
}

/// The integer claims a verifier reads, which must be written as I-JSON integers.
const INTEGER_CLAIMS: &[&str] = &["/exp", "/ever/grace_s", "/ever/seq", "/iat", "/nbf"];

fn entitlement_schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        serde_json::from_str(ever_connect_contracts::schema_entitlement_v1())
            .unwrap_or_else(|e| panic!("the embedded entitlement schema is not JSON: {e}"))
    })
}

const fn fail(code: EntitlementErrorCode) -> EntitlementError {
    EntitlementError {
        code,
        refresh_suggested: false,
        path: None,
    }
}

/// Verifies an entitlement document.
///
/// # Errors
/// [`EntitlementError`] with the code of the first failed check.
pub fn verify_entitlement(
    jws: &str,
    o: &VerifyEntitlementOptions<'_>,
) -> Result<VerifiedEntitlement, EntitlementError> {
    use EntitlementErrorCode as C;
    let now = o.now.unwrap_or_else(now_s);
    let issuer = origin_of(o.expected_issuer);

    // 1. A compact JWS.
    let decoded = decode(jws).ok_or(fail(C::Malformed))?;
    // 2-3. Type, then algorithm, before any key is looked up.
    if str_of(&decoded.header, "typ") != Some("ever-entitlement+jwt") {
        return Err(fail(C::BadTyp));
    }
    if str_of(&decoded.header, "alg") != Some("EdDSA") || decoded.header.contains_key("crit") {
        return Err(fail(C::BadAlg));
    }
    // 4. Keys of an expired manifest verify no new document.
    if now >= o.key_set.manifest().expires_at() {
        return Err(fail(C::ManifestExpired));
    }
    // 5. A trusted entitlement key.
    let kid = str_of(&decoded.header, "kid");
    let Some(key) = kid.and_then(|kid| o.key_set.find(kid, "entitlement", now)) else {
        return Err(EntitlementError {
            code: C::UnknownKid,
            refresh_suggested: kid.is_some_and(|kid| !o.key_set.has(kid)),
            path: None,
        });
    };
    // 6. Its signature.
    if !verify_ed25519(
        key.x(),
        decoded.signing_input.as_bytes(),
        &decoded.signature,
    ) {
        return Err(fail(C::BadSignature));
    }
    // 7-9. Schema id, issuer, audience.
    let payload = Value::Object(decoded.payload);
    if payload.pointer("/ever/schema").and_then(Value::as_str) != Some("ever.entitlement.v1")
        || !payload.get("ever").is_some_and(Value::is_object)
    {
        return Err(EntitlementError {
            path: Some("/ever/schema".into()),
            ..fail(C::SchemaViolation)
        });
    }
    // The document's issuer is the expected one and the one whose manifest vouched for the key.
    if issuer.is_none()
        || issuer.as_deref() != Some(o.key_set.issuer())
        || payload.get("iss").and_then(Value::as_str) != issuer.as_deref()
    {
        return Err(fail(C::IssuerMismatch));
    }
    if payload.get("aud").and_then(Value::as_str) != Some("ever-connect") {
        return Err(fail(C::AudienceMismatch));
    }
    // 10. The closed schema, and the integer claims written as I-JSON integers.
    let schema = entitlement_schema();
    let mut paths: Vec<String> = violations(schema, &payload, schema)
        .into_iter()
        .map(|v| v.path)
        .collect();
    if let Some(written) = first_non_integer(&payload, INTEGER_CLAIMS) {
        paths.push(written.to_owned());
    }
    if let Some(first) = paths
        .into_iter()
        .min_by(|a, b| a.as_bytes().cmp(b.as_bytes()))
    {
        return Err(EntitlementError {
            path: Some(first),
            ..fail(C::SchemaViolation)
        });
    }
    // 11-12. This installation, this subject; a link document names its own link (the schema
    // already holds an instance document to no link member).
    if payload.pointer("/ever/instance_id").and_then(Value::as_str) != Some(o.expected_instance_id)
    {
        return Err(fail(C::InstanceMismatch));
    }
    let sub = payload.get("sub").and_then(Value::as_str);
    if sub != Some(o.expected_subject) {
        return Err(fail(C::SubjectMismatch));
    }
    let link_id = payload
        .pointer("/ever/tenant_link_id")
        .and_then(Value::as_str);
    let linked = link_id.is_some() || payload.pointer("/ever/tenant").is_some();
    let consistent = match o.expected_subject.strip_prefix("link:") {
        Some(id) => link_id == Some(id),
        None => !linked,
    };
    if !consistent {
        return Err(fail(C::SubjectMismatch));
    }
    // 13-14. Not from the future. Step 10 made these I-JSON integers, so a value that is not one
    // is a schema violation, never a sentinel.
    let int = |pointer: &str| {
        payload
            .pointer(pointer)
            .and_then(Value::as_i64)
            .ok_or(EntitlementError {
                path: Some(pointer.to_owned()),
                ..fail(C::SchemaViolation)
            })
    };
    let (iat, nbf, seq) = (int("/iat")?, int("/nbf")?, int("/ever/seq")?);
    if iat > now.saturating_add(CLOCK_SKEW_S) {
        return Err(fail(C::IatInFuture));
    }
    if nbf > now.saturating_add(CLOCK_SKEW_S) {
        return Err(fail(C::NbfInFuture));
    }
    // 15. Never older than the cached document.
    if let Some(cached) = o.cached
        && (seq < cached.seq || (seq == cached.seq && iat <= cached.iat))
    {
        return Err(fail(C::EntitlementStale));
    }
    let status = entitlement_status(Some(&payload), now, None);
    Ok(VerifiedEntitlement {
        claims: payload,
        kid: key.kid().to_owned(),
        seq,
        jws: jws.to_owned(),
        status,
    })
}

/// The status ladder, from the cached document only (never from the state of the connection):
/// `valid` while `now < exp`, `stale` while `now < exp + grace_s`, then `paused`; `paused` without a
/// document. `grace_s` defaults to the document's own `ever.grace_s`.
#[must_use]
pub fn entitlement_status(
    claims: Option<&Value>,
    now: i64,
    grace_s: Option<i64>,
) -> EntitlementStatus {
    let Some(exp) = claims.and_then(|c| c.get("exp")).and_then(Value::as_i64) else {
        return EntitlementStatus::Paused;
    };
    if now < exp {
        return EntitlementStatus::Valid;
    }
    let grace = grace_s
        .or_else(|| {
            claims
                .and_then(|c| c.pointer("/ever/grace_s"))
                .and_then(Value::as_i64)
        })
        .unwrap_or(2_592_000);
    if now < exp.saturating_add(grace) {
        EntitlementStatus::Stale
    } else {
        EntitlementStatus::Paused
    }
}
