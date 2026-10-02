//! Anonymous statistics: validate a report exactly as Ever Platform does, sign the bytes that are
//! sent, and read the answer.
//!
//! * [`sign_report`] serialises the report once, runs the platform's checks on those bytes
//!   ([`validate_report_bytes`]: the 16 384-byte limit, a strict JSON reader, the published
//!   `ever.stats.v1` schema, the calendar date) and signs them with the installation's statistics
//!   key. A refused report yields no bytes: [`StatsRefusal`] names each field and code, never a
//!   value, and its `Display` and `Debug` show an unknown key as `*`.
//! * The crate makes no request itself: send [`SignedStatsReport::body`] with
//!   [`SignedStatsReport::headers`] to [`reports_url`] with your HTTP client (no credential, no
//!   cookie, no redirect), then [`classify_answer`] says what to do next: accepted, retry later,
//!   reset the identity (`409 key_mismatch`), or dropped until the module is upgraded.
//! * [`walk_strings`] lists every string of a report (keys included) for the products' test that
//!   no seeded name, e-mail address or other text reaches the payload.
//!
//! The statistics key is an Ed25519 key pair the installation generates on first boot for
//! statistics only; it is never the key of an Ever Platform connection.

mod checks;

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer as _, SigningKey};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

pub use checks::{MAX_DEPTH, MAX_ERRORS, is_calendar_date};
pub use ever_connect_contracts::{STATS_HEADER_KEY, STATS_HEADER_KEY_ID, STATS_HEADER_SIGNATURE};

/// The largest report body, in bytes.
pub const MAX_REPORT_BYTES: usize = 16 * 1024;

/// The prefix of the `Ever-Stats-Signature` value.
pub const SIGNATURE_PREFIX: &str = "ed25519=";

/// The path of the report call, under the Ever Platform API origin.
pub const REPORTS_PATH: &str = "/v1/stats/reports";

/// The waits after a failed send (429, 5xx, no answer): +1 h, +4 h, +12 h, then the next day.
pub const RETRY_DELAYS_S: [u64; 4] = [3600, 14_400, 43_200, 86_400];

fn schema() -> &'static Value {
    static SCHEMA: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    SCHEMA.get_or_init(|| {
        serde_json::from_str(ever_connect_contracts::schema_stats_v1())
            .unwrap_or_else(|e| panic!("the embedded statistics schema is not JSON: {e}"))
    })
}

/// The field error codes of a refused report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ErrorCode {
    /// A key the schema does not allow at that place.
    UnknownField,
    /// The wrong JSON type (a number with a fraction included), or not JSON at all.
    Type,
    /// A string outside its pattern, enumeration or length.
    Pattern,
    /// A number, list or map outside its bounds, or a day that does not exist.
    Range,
    /// A required field is missing.
    Required,
    /// A key that appears twice in one object.
    DuplicateKey,
    /// `schema` names no published version.
    SchemaUnknown,
    /// The body is larger than [`MAX_REPORT_BYTES`].
    TooLarge,
}

impl ErrorCode {
    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownField => "unknown_field",
            Self::Type => "type",
            Self::Pattern => "pattern",
            Self::Range => "range",
            Self::Required => "required",
            Self::DuplicateKey => "duplicate_key",
            Self::SchemaUnknown => "schema_unknown",
            Self::TooLarge => "too_large",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One reason a report is refused.
#[derive(Clone, PartialEq, Eq)]
pub struct FieldError {
    /// The JSON pointer of the field (`""`: the whole body). An unknown key is its own path, as
    /// Ever Platform answers it: do not log it as it is ([`StatsRefusal`]'s `Display` redacts it).
    pub path: String,
    /// What is wrong.
    pub code: ErrorCode,
    /// A sentence that never repeats the value sent.
    pub message: String,
}

impl fmt::Debug for FieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FieldError")
            .field("path", &checks::redact_path(schema(), &self.path))
            .field("code", &self.code)
            .field("message", &self.message)
            .finish()
    }
}

/// A report the platform's checks refuse: no bytes were produced.
#[derive(Clone, PartialEq, Eq)]
pub struct StatsRefusal {
    status: u16,
    code: &'static str,
    errors: Vec<FieldError>,
}

impl StatsRefusal {
    fn new(status: u16, code: &'static str, errors: Vec<FieldError>) -> Self {
        Self {
            status,
            code,
            errors,
        }
    }

    /// The platform's status for these bytes: 413 (too large) or 422.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// The platform's problem code: `validation_failed` (413) or `schema_violation` (422).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Every field error with its exact path (sorted by path and code, at most [`MAX_ERRORS`]).
    #[must_use]
    pub fn errors(&self) -> &[FieldError] {
        &self.errors
    }
}

impl fmt::Display for StatsRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "statistics report refused ({} {}): ",
            self.status, self.code
        )?;
        for (i, e) in self.errors.iter().enumerate() {
            let path = checks::redact_path(schema(), &e.path);
            let shown = if path.is_empty() { "(body)" } else { &path };
            write!(f, "{}{shown} {}", if i == 0 { "" } else { ", " }, e.code)?;
        }
        Ok(())
    }
}

impl fmt::Debug for StatsRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatsRefusal")
            .field("status", &self.status)
            .field("code", &self.code)
            .field("errors", &self.errors)
            .finish()
    }
}

impl std::error::Error for StatsRefusal {}

/// The installation's statistics key (Ed25519). `Debug` shows the public key only.
#[derive(Clone)]
pub struct StatsKey(SigningKey);

impl StatsKey {
    /// The key of a 32-byte seed (the private key as the installation stores it).
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// A new random key.
    ///
    /// # Errors
    /// The operating system's random source failed.
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut seed = [0_u8; 32];
        getrandom::fill(&mut seed)?;
        let key = Self::from_seed(&seed);
        seed.fill(0);
        Ok(key)
    }

    /// The 32-byte seed, to store (secret).
    #[must_use]
    pub fn seed(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// The public key: base64url without padding of the 32 key bytes (43 characters).
    #[must_use]
    pub fn public_key(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0.verifying_key().as_bytes())
    }

    /// The key id the platform derives: base64url of the first 8 bytes of SHA-256 over the key.
    #[must_use]
    pub fn key_id(&self) -> String {
        URL_SAFE_NO_PAD.encode(&Sha256::digest(self.0.verifying_key().as_bytes())[..8])
    }

    /// The 64-byte signature over exactly `bytes`.
    #[must_use]
    pub fn sign(&self, bytes: &[u8]) -> [u8; 64] {
        self.0.sign(bytes).to_bytes()
    }
}

impl fmt::Debug for StatsKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatsKey")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

/// The key id of a public key given as base64url (43 characters), or `None` when it is not one.
#[must_use]
pub fn key_id(public_key: &str) -> Option<String> {
    let raw = URL_SAFE_NO_PAD.decode(public_key).ok()?;
    (raw.len() == 32 && public_key.len() == 43)
        .then(|| URL_SAFE_NO_PAD.encode(&Sha256::digest(&raw)[..8]))
}

/// A signed report: send `body` as it is, with `headers`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedStatsReport {
    /// The exact bytes that were checked and signed.
    pub body: Vec<u8>,
    /// `content-type`, `Ever-Stats-Key`, `Ever-Stats-Signature` and, when asked,
    /// `Ever-Stats-Key-Id`.
    pub headers: Vec<(&'static str, String)>,
}

/// Runs the platform's checks on report bytes, as they will be sent.
///
/// # Errors
/// [`StatsRefusal`]: what the platform would answer.
pub fn validate_report_bytes(body: &[u8]) -> Result<(), StatsRefusal> {
    checks::check_bytes(schema(), body).map(|_| ())
}

/// Serialises a report once (`serde_json::to_vec`) and runs the platform's checks on those bytes;
/// answers the bytes.
///
/// # Errors
/// [`StatsRefusal`]: what the platform would answer (a value JSON cannot carry is a `type` error).
pub fn validate_report<T: Serialize + ?Sized>(report: &T) -> Result<Vec<u8>, StatsRefusal> {
    let body = serde_json::to_vec(report).map_err(|_| {
        StatsRefusal::new(
            422,
            "schema_violation",
            vec![FieldError {
                path: String::new(),
                code: ErrorCode::Type,
                message: "the report is not a JSON value".into(),
            }],
        )
    })?;
    validate_report_bytes(&body)?;
    Ok(body)
}

/// Signs report bytes the checks accept.
///
/// # Errors
/// [`StatsRefusal`] when the platform would refuse them (no signature is made).
pub fn sign_report_bytes(
    body: Vec<u8>,
    key: &StatsKey,
    with_key_id: bool,
) -> Result<SignedStatsReport, StatsRefusal> {
    validate_report_bytes(&body)?;
    let signature = URL_SAFE_NO_PAD.encode(key.sign(&body));
    let mut headers = vec![
        ("content-type", "application/json".to_owned()),
        (STATS_HEADER_KEY, key.public_key()),
        (
            STATS_HEADER_SIGNATURE,
            format!("{SIGNATURE_PREFIX}{signature}"),
        ),
    ];
    if with_key_id {
        headers.push((STATS_HEADER_KEY_ID, key.key_id()));
    }
    Ok(SignedStatsReport { body, headers })
}

/// Validates a report, serialises it once and signs exactly those bytes.
///
/// # Errors
/// [`StatsRefusal`] when the platform would refuse it (no bytes are produced).
pub fn sign_report<T: Serialize + ?Sized>(
    report: &T,
    key: &StatsKey,
    with_key_id: bool,
) -> Result<SignedStatsReport, StatsRefusal> {
    let body = validate_report(report)?;
    sign_report_bytes(body, key, with_key_id)
}

/// Whether a string of a report is an object key or a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringKind {
    /// An object key.
    Key,
    /// A string value.
    Value,
}

/// Every string of a value, keys included, depth first, at its JSON pointer.
#[must_use]
pub fn walk_strings(value: &Value) -> Vec<(String, StringKind, String)> {
    fn visit(v: &Value, at: &str, out: &mut Vec<(String, StringKind, String)>) {
        match v {
            Value::String(s) => out.push((at.to_owned(), StringKind::Value, s.clone())),
            Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    visit(item, &format!("{at}/{i}"), out);
                }
            }
            Value::Object(map) => {
                for (k, item) in map {
                    let here = format!("{at}/{}", k.replace('~', "~0").replace('/', "~1"));
                    out.push((here.clone(), StringKind::Key, k.clone()));
                    visit(item, &here, out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    visit(value, "", &mut out);
    out
}

/// What to do after a send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatsOutcome {
    /// Stored; `superseded` when it replaced a report of the same month sent the same UTC day.
    Accepted {
        /// An earlier report of the same day was replaced.
        superseded: bool,
    },
    /// Try again later (429, 5xx, a failed connection or a timeout).
    Retry {
        /// The status, `None` when no answer came.
        status: Option<u16>,
        /// The problem code, when the answer had one.
        code: Option<String>,
        /// Seconds to wait.
        after_s: u64,
    },
    /// `409 key_mismatch`: the id is pinned to another key; reset the statistics identity (a new
    /// id and a new key).
    ResetIdentity,
    /// Refused for good (400, 413, 415, 422, any other answer): do not resend until the module is
    /// upgraded.
    Dropped {
        /// The status.
        status: u16,
        /// The problem code, when the answer had one.
        code: Option<String>,
        /// `(path, code)` of each field error the answer listed.
        errors: Vec<(String, String)>,
    },
}

fn retry_delay(attempt: usize) -> u64 {
    RETRY_DELAYS_S[attempt.min(RETRY_DELAYS_S.len() - 1)]
}

/// The outcome of a send that got no answer (a failed connection or a timeout). `attempt` counts the
/// failed sends before this one.
#[must_use]
pub fn no_answer(attempt: usize) -> StatsOutcome {
    StatsOutcome::Retry {
        status: None,
        code: None,
        after_s: retry_delay(attempt),
    }
}

/// Classifies an answer of `POST /v1/stats/reports`. `attempt` counts the failed sends before
/// this one and picks the wait of a retry; a longer `Retry-After` wins.
#[must_use]
pub fn classify_answer(
    status: u16,
    body: &[u8],
    retry_after: Option<&str>,
    attempt: usize,
) -> StatsOutcome {
    let doc: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let code = doc.get("code").and_then(Value::as_str).map(str::to_owned);
    if status == 202 {
        return StatsOutcome::Accepted {
            superseded: doc.get("superseded") == Some(&Value::Bool(true)),
        };
    }
    if status == 409 && code.as_deref() == Some("key_mismatch") {
        return StatsOutcome::ResetIdentity;
    }
    if status == 429 || status >= 500 {
        let asked = retry_after
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(0);
        return StatsOutcome::Retry {
            status: Some(status),
            code,
            after_s: retry_delay(attempt).max(asked),
        };
    }
    let errors = doc
        .get("errors")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|e| {
                    Some((
                        e.get("path")?.as_str()?.to_owned(),
                        e.get("code")?.as_str()?.to_owned(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    StatsOutcome::Dropped {
        status,
        code,
        errors,
    }
}

/// Why a statistics API URL is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidUrl;

impl fmt::Display for InvalidUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "the statistics API URL is an http(s) origin with no credential, query or fragment",
        )
    }
}

impl std::error::Error for InvalidUrl {}

/// The report endpoint under an Ever Platform API origin (`EVER_STATS_API_URL`).
///
/// # Errors
/// [`InvalidUrl`] for anything but `http(s)://host[:port][/path]` without a credential, a query or
/// a fragment.
pub fn reports_url(base_url: &str) -> Result<String, InvalidUrl> {
    let rest = base_url
        .strip_prefix("https://")
        .or_else(|| base_url.strip_prefix("http://"))
        .ok_or(InvalidUrl)?;
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty()
        || authority.contains('@')
        || base_url.contains('?')
        || base_url.contains('#')
        || base_url
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(InvalidUrl);
    }
    Ok(format!("{}{REPORTS_PATH}", base_url.trim_end_matches('/')))
}
