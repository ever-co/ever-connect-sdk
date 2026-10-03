//! The entitlement document verifier (`ever.entitlement.v1`), the one implementation every product
//! uses. The checks run in this order and fail closed at the first one that does not pass:
//!
//! 0. the key set was verified for the expected issuer (a key set of one issuer never vouches for
//!    a document of another): `issuer_mismatch`
//! 1. a compact JWS (the decoding rule of the JWS module: 64 KiB, canonical parts, safe integers
//!    only, well-formed strings, 127 levels): `malformed`
//! 2. header `typ` is `ever-entitlement+jwt`: `bad_typ`
//! 3. header `alg` is `EdDSA` and there is no `crit` (before any key lookup): `bad_alg`
//! 4. header `kid` is in the root-verified key set, purpose `entitlement`, state `active` or
//!    `previous`, inside its validity window: `unknown_kid`
//! 5. the Ed25519 signature over `header.payload` (strict: no small-order point): `bad_signature`
//! 6. `ever.schema` is `ever.entitlement.v1`: `schema_violation`
//! 7. `iss` is the origin of the expected issuer: `issuer_mismatch`
//! 8. `aud` is `ever-connect`: `audience_mismatch`
//! 9. the closed schema of the whole payload: `schema_violation`
//! 10. `ever.instance_id` is this installation's Registry id: `instance_mismatch`
//! 11. `sub` is the expected subject (`instance:<id>` or `link:<id>`); a link document names
//!     its own link (`ever.tenant_link_id`), an instance document carries no link member:
//!     `subject_mismatch`
//! 12. `iat <= now + 300`: `iat_in_future`
//! 13. `nbf <= now + 300`: `nbf_in_future`
//! 14. against the cached document: a lower `seq`, or the same `seq` without a later `iat`:
//!     `entitlement_stale`
//!
//! `exp` is never a failure: it feeds [`entitlement_status`] only. No error carries the token or a
//! claim value.

use std::fmt;
use std::sync::OnceLock;

use serde_json::Value;

use crate::jws::{decode, str_of, verify_ed25519};
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

    // 0. The key set is the expected issuer's.
    if issuer.as_deref() != Some(o.key_set.issuer()) {
        return Err(fail(C::IssuerMismatch));
    }
    // 1. A compact JWS.
    let decoded = decode(jws).ok_or(fail(C::Malformed))?;
    // 2-3. Type, then algorithm, before any key is looked up.
    if str_of(&decoded.header, "typ") != Some("ever-entitlement+jwt") {
        return Err(fail(C::BadTyp));
    }
    if str_of(&decoded.header, "alg") != Some("EdDSA") || decoded.header.contains_key("crit") {
        return Err(fail(C::BadAlg));
    }
    // 4. A trusted entitlement key.
    let kid = str_of(&decoded.header, "kid");
    let Some(key) = kid.and_then(|kid| o.key_set.find(kid, "entitlement", now)) else {
        return Err(EntitlementError {
            code: C::UnknownKid,
            refresh_suggested: kid.is_some_and(|kid| !o.key_set.has(kid)),
            path: None,
        });
    };
    // 5. Its signature.
    if !verify_ed25519(
        key.x(),
        decoded.signing_input.as_bytes(),
        &decoded.signature,
    ) {
        return Err(fail(C::BadSignature));
    }
    // 6-8. Schema id, issuer, audience.
    let payload = Value::Object(decoded.payload);
    if payload.pointer("/ever/schema").and_then(Value::as_str) != Some("ever.entitlement.v1")
        || !payload.get("ever").is_some_and(Value::is_object)
    {
        return Err(EntitlementError {
            path: Some("/ever/schema".into()),
            ..fail(C::SchemaViolation)
        });
    }
    if payload.get("iss").and_then(Value::as_str) != issuer.as_deref() {
        return Err(fail(C::IssuerMismatch));
    }
    if payload.get("aud").and_then(Value::as_str) != Some("ever-connect") {
        return Err(fail(C::AudienceMismatch));
    }
    // 9. The closed schema.
    let schema = entitlement_schema();
    if let Some(first) = violations(schema, &payload, schema).into_iter().next() {
        return Err(EntitlementError {
            path: Some(first.path),
            ..fail(C::SchemaViolation)
        });
    }
    // 10-11. This installation, this subject.
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
    // 12-13. Not from the future. The decoder admits safe integers only and the schema made these
    // integers, so a value that is not one is a schema violation, never a sentinel.
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
    // 14. Never older than the cached document.
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
