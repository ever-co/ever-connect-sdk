//! [`EverPlatformClient`]: every call an installation makes to Ever Platform, over the generated
//! operation table ([`generated::OPERATIONS`]). The client:
//!
//! * builds every URL from the base URL and a path of the table (the guard refuses anything else);
//! * refuses before any I/O: a write without its `Idempotency-Key`, a per-link call without its
//!   link id, a body that breaks its schema (unknown fields included), a statistics body over
//!   16 KiB or a mirror batch over 4 MiB;
//! * authenticates lazily: the first call that needs the instance token signs a client assertion
//!   with the connect key ([`Error::NotConnected`] before any I/O while there is no Registry id),
//!   keeps the token in memory, and on a 401 gets a new one and retries once; a
//!   `401 credential_revoked` is answered at once, never retried;
//! * sends `User-Agent: ever-connect-sdk/<version> (<product>/<version>)` and an `x-request-id`;
//! * answers [`Answer::NotModified`] for a 304 and [`Error::Problem`] for any other non-2xx answer.

pub mod error;
#[allow(missing_docs, clippy::all)]
pub mod generated;
mod guard;
mod token;

use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use serde_json::{Value, json};

pub use self::error::{Error, ProblemError, ProblemFieldError};
use self::generated::{HeaderRule, OPERATIONS, Operation, OperationAuth, REQUEST_SCHEMAS};
use self::guard::{Base, WireResponse, check_base_url, http_client, url_for};
use self::token::InstanceTokens;
use crate::assertion::{ClientAssertionOptions, sign_client_assertion};
use crate::encoding::is_ulid;
use crate::entitlement::{
    CachedEntitlement, VerifiedEntitlement, VerifyEntitlementOptions, verify_entitlement,
};
use crate::keys::InstanceSigner;
use crate::keyset::{KeySet, KeySetUpdate};
use crate::manifest::{
    RootKey, VerifiedKeyManifest, VerifyKeyManifestOptions, now_s, origin_of, pinned_root_keys,
    verify_key_manifest,
};
use crate::stats::SignedStatsReport;

/// The SDK version: the `User-Agent` names it.
pub const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The environment variable of the extra root keys file (local base URLs only).
pub const ROOT_KEYS_FILE_ENV: &str = "EVER_PLATFORM_ROOT_KEYS_FILE";

const MIRROR_MAX_BYTES: usize = 4 * 1024 * 1024;
const STATS_MAX_BYTES: usize = 16 * 1024;
const LONG_POLL_WAIT_S: u64 = 25;

type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;
type RegistryId = Arc<dyn Fn() -> Option<String> + Send + Sync>;

/// The options of [`EverPlatformClient::new`].
#[derive(Clone)]
pub struct ClientOptions {
    /// `EVER_PLATFORM_API_URL`: https, or http on a local host only.
    pub base_url: String,
    /// The product code (`gauzy`, `works`, …) for the `User-Agent`.
    pub product: String,
    /// The product version for the `User-Agent`.
    pub product_version: String,
    /// The connect key (never the statistics key); needed for every call with the instance token.
    pub signer: Option<Arc<dyn InstanceSigner>>,
    /// The Registry id the redeem answered; `None` before the first redeem.
    pub registry_instance_id: Option<RegistryId>,
    /// The read deadline (default 6 s).
    pub read_timeout: Duration,
    /// The write deadline (default 10 s).
    pub write_timeout: Duration,
    /// Extra root keys: honoured only when the base URL is a local host.
    pub root_keys: Vec<RootKey>,
    /// The JWKS file of extra root keys (default: `EVER_PLATFORM_ROOT_KEYS_FILE`); local hosts only.
    pub root_keys_file: Option<PathBuf>,
    /// The issuer documents name when it differs from the origin of the base URL (a mock or a local
    /// build behind another name): honoured only when the base URL is a local host.
    pub issuer: Option<String>,
    /// Unix seconds (tests); default the system clock.
    pub clock: Option<Clock>,
}

impl ClientOptions {
    /// Options with the defaults: no signer, no Registry id, 6 s / 10 s deadlines, the pinned roots.
    #[must_use]
    pub fn new(
        base_url: impl Into<String>,
        product: impl Into<String>,
        product_version: impl Into<String>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            product: product.into(),
            product_version: product_version.into(),
            signer: None,
            registry_instance_id: None,
            read_timeout: Duration::from_millis(6000),
            write_timeout: Duration::from_millis(10_000),
            root_keys: Vec::new(),
            root_keys_file: std::env::var_os(ROOT_KEYS_FILE_ENV).map(PathBuf::from),
            issuer: None,
            clock: None,
        }
    }
}

impl fmt::Debug for ClientOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientOptions")
            .field("base_url", &self.base_url)
            .field("product", &self.product)
            .field("signer", &self.signer.as_ref().map(|s| s.kid()))
            .finish_non_exhaustive()
    }
}

/// The input of one call.
#[derive(Debug, Clone, Default)]
pub struct CallInput<'a> {
    /// Path parameters by name.
    pub path: Vec<(&'a str, &'a str)>,
    /// Query parameters by name.
    pub query: Vec<(&'a str, String)>,
    /// The JSON body.
    pub body: Option<&'a Value>,
    /// The `Idempotency-Key` of a write.
    pub idempotency_key: Option<&'a str>,
    /// The tenant link (`Ever-Link-Id`) of a per-link call.
    pub link_id: Option<&'a str>,
    /// Sends `If-None-Match: "<seq>"`; a 304 answers [`Answer::NotModified`].
    pub if_none_match_seq: Option<i64>,
    /// The person's Ever ID token, for the calls a person makes through the product.
    pub person_token: Option<&'a str>,
    /// Long-poll seconds (the deadline becomes `wait_s + 5`).
    pub wait_s: Option<u64>,
}

/// A successful answer.
#[derive(Debug, Clone, PartialEq)]
pub enum Answer {
    /// A JSON body.
    Json(Value),
    /// No body (204, or an empty 2xx).
    Empty,
    /// A conditional read whose cached copy is current (304).
    NotModified,
}

impl Answer {
    /// The JSON body (`Value::Null` for no body or 304).
    #[must_use]
    pub fn into_json(self) -> Value {
        match self {
            Self::Json(v) => v,
            Self::Empty | Self::NotModified => Value::Null,
        }
    }
}

/// The Ever Platform client of one installation.
pub struct EverPlatformClient {
    base: Base,
    issuer: String,
    roots: Vec<RootKey>,
    http: guard::Http,
    user_agent: String,
    options: ClientOptions,
    tokens: InstanceTokens,
    secrets: Mutex<Vec<String>>,
}

impl fmt::Debug for EverPlatformClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EverPlatformClient {{ base_url: {}{} }}",
            self.base.origin, self.base.prefix
        )
    }
}

static WARNED: OnceLock<()> = OnceLock::new();
fn warn_once(message: &str) {
    if WARNED.set(()).is_ok() {
        eprintln!("ever-connect-sdk: {message}");
    }
}

fn request_schemas() -> &'static Value {
    static SCHEMAS: OnceLock<Value> = OnceLock::new();
    SCHEMAS.get_or_init(|| {
        serde_json::from_str(REQUEST_SCHEMAS)
            .unwrap_or_else(|e| panic!("the request schemas are not JSON: {e}"))
    })
}

/// `encodeURIComponent`: what the TypeScript client does to a path parameter.
fn encode_component(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn random_request_id() -> String {
    let mut b = [0_u8; 16];
    let _ = getrandom::fill(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = crate::encoding::hex(&b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

fn printable(text: &str, max: usize) -> bool {
    !text.is_empty() && text.len() <= max && text.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// A request checked against its operation, ready to send.
struct Prepared {
    op: &'static Operation,
    path: String,
    query: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    timeout: Duration,
}

impl EverPlatformClient {
    /// A client for `options`. Makes no request.
    ///
    /// # Errors
    /// [`Error::EgressRefused`] (`insecure_base_url`) for plain http to a host that is not local,
    /// [`Error::InvalidOptions`] for a base URL or product that cannot be used.
    pub fn new(options: ClientOptions) -> Result<Self, Error> {
        let base = check_base_url(&options.base_url)?;
        let products = ever_connect_contracts::PRODUCTS;
        if !products.contains(&options.product.as_str()) || !printable(&options.product_version, 64)
        {
            return Err(Error::InvalidOptions(
                "the product and its version name the User-Agent",
            ));
        }
        let user_agent = format!(
            "ever-connect-sdk/{SDK_VERSION} ({}/{})",
            options.product, options.product_version
        );
        let issuer = match (&options.issuer, base.local) {
            (Some(issuer), true) => {
                origin_of(issuer).ok_or(Error::InvalidOptions("issuer is not an origin"))?
            }
            (Some(_), false) => {
                warn_once("the issuer option is ignored: the base URL is not a local host");
                base.origin.clone()
            }
            (None, _) => base.origin.clone(),
        };
        let mut roots = pinned_root_keys().to_vec();
        let extra_file = options.root_keys_file.clone();
        if !options.root_keys.is_empty() || extra_file.is_some() {
            if base.local {
                roots.extend(options.root_keys.iter().cloned());
                if let Some(file) = extra_file {
                    let text = std::fs::read_to_string(&file)
                        .map_err(|_| Error::InvalidOptions("the root keys file cannot be read"))?;
                    let jwks: Value = serde_json::from_str(&text)
                        .map_err(|_| Error::InvalidOptions("the root keys file is not JSON"))?;
                    let keys = jwks
                        .get("keys")
                        .or(Some(&jwks))
                        .and_then(Value::as_array)
                        .ok_or(Error::InvalidOptions("the root keys file is not a JWKS"))?;
                    roots.extend(keys.iter().filter_map(RootKey::from_jwk));
                }
            } else {
                warn_once("extra root keys are ignored: the base URL is not a local host");
            }
        }
        let http = http_client(&user_agent)?;
        Ok(Self {
            base,
            issuer,
            roots,
            http,
            user_agent,
            options,
            tokens: InstanceTokens::default(),
            secrets: Mutex::new(Vec::new()),
        })
    }

    /// The issuer documents must name (the origin of the base URL, or the local override).
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The roots this client trusts.
    #[must_use]
    pub fn root_keys(&self) -> &[RootKey] {
        &self.roots
    }

    fn now(&self) -> i64 {
        self.options.clock.as_ref().map_or_else(now_s, |c| c())
    }

    fn registry_id(&self) -> Option<String> {
        self.options
            .registry_instance_id
            .as_ref()
            .and_then(|f| f())
            .filter(|s| !s.is_empty())
    }

    fn remember(&self, secret: String) {
        let mut secrets = self.secrets.lock().unwrap_or_else(PoisonError::into_inner);
        secrets.push(secret);
        if secrets.len() > 8 {
            secrets.remove(0);
        }
    }

    fn prepare(&self, id: &str, input: &CallInput<'_>) -> Result<Prepared, Error> {
        let op = OPERATIONS
            .iter()
            .find(|o| o.id == id)
            .ok_or(Error::Validation {
                code: "invalid_parameter",
                errors: vec![(id.to_owned(), "unknown_operation")],
            })?;
        let invalid = |path: &str, code: &'static str| Error::Validation {
            code: "invalid_parameter",
            errors: vec![(path.to_owned(), code)],
        };
        let mut path = op.path.to_owned();
        for name in op.path_params {
            let value = input
                .path
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| *v)
                .filter(|v| !v.is_empty() && v.len() <= 256)
                .ok_or_else(|| invalid(name, "required"))?;
            path = path.replace(&format!("{{{name}}}"), &encode_component(value));
        }
        let mut query = Vec::new();
        for (name, value) in &input.query {
            if !op.query.contains(name) {
                return Err(invalid(name, "unknown_field"));
            }
            query.push(((*name).to_owned(), value.clone()));
        }
        let mut headers = vec![
            (
                "accept".to_owned(),
                "application/json, application/problem+json".to_owned(),
            ),
            ("user-agent".to_owned(), self.user_agent.clone()),
        ];
        if op.idempotency_key != HeaderRule::None {
            match input.idempotency_key {
                None if op.idempotency_key == HeaderRule::Required => {
                    return Err(Error::Validation {
                        code: "idempotency_key_required",
                        errors: Vec::new(),
                    });
                }
                None => {}
                Some(key) if !printable(key, 255) => {
                    return Err(invalid("Idempotency-Key", "pattern"));
                }
                Some(key) => headers.push(("idempotency-key".to_owned(), key.to_owned())),
            }
        }
        if op.link_header != HeaderRule::None {
            match input.link_id {
                None if op.link_header == HeaderRule::Required => {
                    return Err(Error::Validation {
                        code: "link_required",
                        errors: Vec::new(),
                    });
                }
                None => {}
                Some(link) if !is_ulid(link) => return Err(invalid("Ever-Link-Id", "pattern")),
                Some(link) => headers.push(("ever-link-id".to_owned(), link.to_owned())),
            }
        }
        if op.conditional
            && let Some(seq) = input.if_none_match_seq
        {
            if seq < 0 {
                return Err(invalid("If-None-Match", "range"));
            }
            headers.push(("if-none-match".to_owned(), format!("\"{seq}\"")));
        }
        if op.auth == OperationAuth::Person && input.person_token.is_none_or(str::is_empty) {
            return Err(invalid("Authorization", "required"));
        }
        let mut body = None;
        match (op.body_schema, input.body) {
            (Some(_), None) if op.body_required => {
                return Err(Error::Validation {
                    code: "invalid_body",
                    errors: vec![(String::new(), "required")],
                });
            }
            (Some(schema), Some(value)) => {
                let schema: Value = serde_json::from_str(schema)
                    .map_err(|_| Error::InvalidOptions("operation schema"))?;
                let found = crate::schema::violations(request_schemas(), value, &schema);
                if !found.is_empty() {
                    return Err(Error::Validation {
                        code: "invalid_body",
                        errors: found
                            .into_iter()
                            .map(|v| (v.path, v.kind.as_str()))
                            .collect(),
                    });
                }
                let bytes = serde_json::to_vec(value).map_err(|_| Error::Validation {
                    code: "invalid_body",
                    errors: Vec::new(),
                })?;
                if op.id == "instanceMirrorApps" && bytes.len() > MIRROR_MAX_BYTES {
                    return Err(Error::Validation {
                        code: "body_too_large",
                        errors: Vec::new(),
                    });
                }
                headers.push(("content-type".to_owned(), "application/json".to_owned()));
                body = Some(bytes);
            }
            (None, Some(_)) => {
                return Err(Error::Validation {
                    code: "invalid_body",
                    errors: vec![(String::new(), "unknown_field")],
                });
            }
            _ => {}
        }
        let timeout = if op.id == "instancePollEvents" {
            Duration::from_secs(input.wait_s.unwrap_or(LONG_POLL_WAIT_S) + 5)
        } else if op.method == "GET" {
            self.options.read_timeout
        } else {
            self.options.write_timeout
        };
        Ok(Prepared {
            op,
            path,
            query,
            headers,
            body,
            timeout,
        })
    }

    fn problem(&self, res: &WireResponse) -> ProblemError {
        let secrets = self
            .secrets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let doc: Option<serde_json::Map<String, Value>> =
            serde_json::from_slice::<Value>(&res.body)
                .ok()
                .and_then(|v| match v {
                    Value::Object(m) => Some(m),
                    _ => None,
                });
        let text = |name: &str| {
            doc.as_ref()
                .and_then(|d| d.get(name))
                .and_then(Value::as_str)
        };
        let code = text("code")
            .filter(|c| {
                !c.is_empty()
                    && c.len() <= 64
                    && c.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            })
            .unwrap_or("unknown")
            .to_owned();
        let header = |name: &str| res.headers.get(name).and_then(|v| v.to_str().ok());
        let retry_after_s = header("retry-after")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .or_else(|| {
                doc.as_ref()
                    .and_then(|d| d.get("retry_after_s"))
                    .and_then(Value::as_u64)
            });
        let errors = doc
            .as_ref()
            .and_then(|d| d.get("errors"))
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(Value::as_object)
                    .map(|e| ProblemFieldError {
                        path: e
                            .get("path")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_owned(),
                        code: e
                            .get("code")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown")
                            .to_owned(),
                        message: error::redact(
                            e.get("message").and_then(Value::as_str).unwrap_or(""),
                            &secrets,
                        ),
                    })
                    .filter(|e| {
                        !e.path.contains("client_assertion") && !e.path.contains("client_secret")
                    })
                    .collect()
            })
            .unwrap_or_default();
        ProblemError {
            status: res.status,
            code,
            detail: text("detail").map(|d| error::redact(d, &secrets)),
            instance: text("instance")
                .map(str::to_owned)
                .or_else(|| header("x-request-id").map(str::to_owned)),
            errors,
            retry_after_s,
        }
    }

    fn answer(&self, op: &Operation, res: &WireResponse) -> Result<Answer, Error> {
        if res.status == 304 && op.conditional {
            return Ok(Answer::NotModified);
        }
        if res.status == 304 || !op.success.contains(&res.status) {
            return Err(Error::Problem(self.problem(res)));
        }
        if res.body.is_empty() {
            return Ok(Answer::Empty);
        }
        serde_json::from_slice(&res.body)
            .map(Answer::Json)
            .map_err(|_| Error::Transport("the answer is not JSON".into()))
    }

    async fn send_prepared(
        &self,
        p: &Prepared,
        authorization: Option<String>,
    ) -> Result<WireResponse, Error> {
        let url = url_for(&self.base, &p.path, &p.query)?;
        let mut headers = p.headers.clone();
        headers.push(("x-request-id".to_owned(), random_request_id()));
        if let Some(value) = authorization {
            headers.push(("authorization".to_owned(), value));
        }
        guard::send(
            &self.http,
            p.op.method,
            url,
            headers,
            p.body.clone(),
            p.timeout,
        )
        .await
    }

    async fn token(&self) -> Result<String, Error> {
        if let Some(token) = self.tokens.current(self.now()).await {
            return Ok(token);
        }
        let _acquiring = self.tokens.acquiring.lock().await;
        if let Some(token) = self.tokens.current(self.now()).await {
            return Ok(token);
        }
        let signer = self.options.signer.as_ref().ok_or(Error::InvalidOptions(
            "authenticated calls need the connect key (signer)",
        ))?;
        let registry = self.registry_id();
        let token_path = OPERATIONS
            .iter()
            .find(|o| o.id == "instanceToken")
            .map_or("", |o| o.path);
        let audience = format!("{}{token_path}", self.issuer);
        let assertion = sign_client_assertion(&ClientAssertionOptions {
            signer: signer.as_ref(),
            registry_instance_id: registry.as_deref(),
            audience: &audience,
            ttl_s: None,
            now: Some(self.now()),
            jti: None,
        })?;
        self.remember(assertion.clone());
        let body = json!({
            "grant_type": "client_credentials",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion,
        });
        let p = self.prepare(
            "instanceToken",
            &CallInput {
                body: Some(&body),
                ..CallInput::default()
            },
        )?;
        let res = self.send_prepared(&p, None).await?;
        let answer = self.answer(p.op, &res)?.into_json();
        let token = answer
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|t| t.starts_with("evit_"))
            .ok_or_else(|| {
                Error::Transport("the token endpoint answered no instance token".into())
            })?
            .to_owned();
        self.remember(token.clone());
        let expires_in = answer
            .get("expires_in")
            .and_then(Value::as_i64)
            .unwrap_or(3600);
        self.tokens
            .store(token.clone(), expires_in, self.now())
            .await;
        Ok(token)
    }

    /// Sends one operation of the table.
    ///
    /// # Errors
    /// [`Error`].
    pub async fn call(&self, operation_id: &str, input: CallInput<'_>) -> Result<Answer, Error> {
        let p = self.prepare(operation_id, &input)?;
        if p.op.auth == OperationAuth::Instance
            && !self.tokens.is_held().await
            && self.registry_id().is_none()
        {
            return Err(Error::NotConnected);
        }
        let mut attempt = 0;
        loop {
            let authorization = match p.op.auth {
                OperationAuth::Instance => Some(format!("Bearer {}", self.token().await?)),
                OperationAuth::Person => input.person_token.map(|t| format!("Bearer {t}")),
                OperationAuth::None => None,
            };
            let res = self.send_prepared(&p, authorization).await?;
            if res.status == 401 && p.op.auth == OperationAuth::Instance {
                let problem = self.problem(&res);
                self.tokens.invalidate().await;
                if problem.code == "credential_revoked" || attempt > 0 {
                    return Err(Error::Problem(problem));
                }
                attempt += 1;
                continue;
            }
            return self.answer(p.op, &res);
        }
    }

    async fn json(&self, operation_id: &str, input: CallInput<'_>) -> Result<Value, Error> {
        self.call(operation_id, input).await.map(Answer::into_json)
    }

    // ------------------------------------------------------------------------------ keys

    /// The key manifest, verified against the trusted roots before it is answered.
    ///
    /// # Errors
    /// [`Error`]; [`Error::KeyManifest`] for a manifest that does not verify.
    pub async fn key_manifest(&self) -> Result<VerifiedKeyManifest, Error> {
        let body = self.json("get_key_manifest", CallInput::default()).await?;
        Ok(verify_key_manifest(&body, &self.manifest_options())?)
    }

    fn manifest_options(&self) -> VerifyKeyManifestOptions<'_> {
        VerifyKeyManifestOptions {
            root_keys: Some(&self.roots),
            issuer: Some(&self.issuer),
            now: Some(self.now()),
        }
    }

    /// Fetches the manifest and builds the next key set; a refused manifest keeps `current`.
    ///
    /// # Errors
    /// [`Error`]; without `current`, [`Error::KeyManifest`] for a manifest that does not verify.
    pub async fn refresh_keys(&self, current: Option<&KeySet>) -> Result<KeySetUpdate, Error> {
        let body = self.json("get_key_manifest", CallInput::default()).await?;
        let options = self.manifest_options();
        Ok(match current {
            Some(set) => set.update(&body, &options),
            None => KeySetUpdate::Replaced(KeySet::verify(&body, &options)?),
        })
    }

    /// Verifies an entitlement document for this installation: this client's issuer, its Registry
    /// id, and the subject `instance:<id>` unless a link subject is given.
    ///
    /// # Errors
    /// [`Error::NotConnected`] without a Registry id; [`Error::Entitlement`].
    pub fn verify_entitlement(
        &self,
        jws: &str,
        key_set: &KeySet,
        subject: Option<&str>,
        cached: Option<CachedEntitlement>,
    ) -> Result<VerifiedEntitlement, Error> {
        let id = self.registry_id().ok_or(Error::NotConnected)?;
        let instance_subject = format!("instance:{id}");
        Ok(verify_entitlement(
            jws,
            &VerifyEntitlementOptions {
                key_set,
                expected_issuer: &self.issuer,
                expected_instance_id: &id,
                expected_subject: subject.unwrap_or(&instance_subject),
                cached,
                now: Some(self.now()),
            },
        )?)
    }

    // ------------------------------------------------------------------------------ connect

    /// The legal texts.
    ///
    /// # Errors
    /// [`Error`].
    pub async fn legal(&self) -> Result<Value, Error> {
        self.json("getConnectLegal", CallInput::default()).await
    }

    /// Redeems a connect code.
    ///
    /// # Errors
    /// [`Error`].
    pub async fn redeem(&self, body: &Value, idempotency_key: &str) -> Result<Value, Error> {
        self.json(
            "connectRedeem",
            CallInput {
                body: Some(body),
                idempotency_key: Some(idempotency_key),
                ..CallInput::default()
            },
        )
        .await
    }

    // ------------------------------------------------------------------------------ instance

    /// The installation as the platform sees it.
    ///
    /// # Errors
    /// [`Error`].
    pub async fn instance(&self) -> Result<Value, Error> {
        self.json("getInstanceSelf", CallInput::default()).await
    }

    /// The heartbeat.
    ///
    /// # Errors
    /// [`Error`].
    pub async fn heartbeat(&self, body: &Value) -> Result<Value, Error> {
        self.json(
            "instanceHeartbeat",
            CallInput {
                body: Some(body),
                ..CallInput::default()
            },
        )
        .await
    }

    /// A page of events after `after` (long poll up to `wait_s`).
    ///
    /// # Errors
    /// [`Error`].
    pub async fn events(&self, after: Option<&str>, wait_s: Option<u64>) -> Result<Value, Error> {
        let mut query = Vec::new();
        if let Some(after) = after {
            query.push(("after", after.to_owned()));
        }
        if let Some(wait) = wait_s {
            query.push(("wait", wait.to_string()));
        }
        self.json(
            "instancePollEvents",
            CallInput {
                query,
                wait_s,
                ..CallInput::default()
            },
        )
        .await
    }

    /// Acknowledges the events up to `last_id`.
    ///
    /// # Errors
    /// [`Error`].
    pub async fn ack_events(&self, last_id: &str) -> Result<Value, Error> {
        let body = json!({"last_id": last_id});
        self.json(
            "instanceAckEvents",
            CallInput {
                body: Some(&body),
                ..CallInput::default()
            },
        )
        .await
    }

    /// The installation's entitlement document (`If-None-Match` with the cached `seq`).
    ///
    /// # Errors
    /// [`Error`].
    pub async fn entitlement(&self, if_none_match_seq: Option<i64>) -> Result<Answer, Error> {
        self.call(
            "instanceGetEntitlement",
            CallInput {
                if_none_match_seq,
                ..CallInput::default()
            },
        )
        .await
    }

    /// A tenant link's entitlement document.
    ///
    /// # Errors
    /// [`Error`].
    pub async fn link_entitlement(
        &self,
        link_id: &str,
        if_none_match_seq: Option<i64>,
    ) -> Result<Answer, Error> {
        self.call(
            "instanceGetLinkEntitlement",
            CallInput {
                path: vec![("link", link_id)],
                if_none_match_seq,
                ..CallInput::default()
            },
        )
        .await
    }

    /// The integration states.
    ///
    /// # Errors
    /// [`Error`].
    pub async fn integrations(&self) -> Result<Value, Error> {
        self.json("instanceGetIntegrations", CallInput::default())
            .await
    }

    /// Links a tenant with a link code.
    ///
    /// # Errors
    /// [`Error`].
    pub async fn create_tenant_link(
        &self,
        body: &Value,
        idempotency_key: &str,
    ) -> Result<Value, Error> {
        self.json(
            "instanceCreateTenantLink",
            CallInput {
                body: Some(body),
                idempotency_key: Some(idempotency_key),
                ..CallInput::default()
            },
        )
        .await
    }

    /// Rotates the connect key (a body from [`crate::assertion::sign_key_rotation`]).
    ///
    /// # Errors
    /// [`Error`].
    pub async fn rotate_key(&self, body: &Value, idempotency_key: &str) -> Result<Value, Error> {
        let out = self
            .json(
                "instanceRotateKey",
                CallInput {
                    body: Some(body),
                    idempotency_key: Some(idempotency_key),
                    ..CallInput::default()
                },
            )
            .await?;
        self.tokens.invalidate().await;
        Ok(out)
    }

    /// Disconnects the installation; the token is dropped.
    ///
    /// # Errors
    /// [`Error`].
    pub async fn disconnect(&self, idempotency_key: &str) -> Result<Value, Error> {
        let out = self
            .json(
                "instanceDisconnect",
                CallInput {
                    idempotency_key: Some(idempotency_key),
                    ..CallInput::default()
                },
            )
            .await;
        self.tokens.invalidate().await;
        out
    }

    /// A usage report of a tenant link (`usage_reporting`).
    ///
    /// # Errors
    /// [`Error`].
    pub async fn report_usage(
        &self,
        link_id: &str,
        body: &Value,
        idempotency_key: &str,
    ) -> Result<Value, Error> {
        self.json(
            "instanceReportUsage",
            CallInput {
                body: Some(body),
                idempotency_key: Some(idempotency_key),
                link_id: Some(link_id),
                ..CallInput::default()
            },
        )
        .await
    }

    // ------------------------------------------------------------------------------ lookup

    /// The active lookup salts.
    ///
    /// # Errors
    /// [`Error`].
    pub async fn lookup_salt(&self) -> Result<Value, Error> {
        self.json("getLookupSalt", CallInput::default()).await
    }

    /// The published lookup test vectors.
    ///
    /// # Errors
    /// [`Error`].
    pub async fn lookup_test_vectors(&self) -> Result<Value, Error> {
        self.json("getLookupTestVectors", CallInput::default())
            .await
    }

    /// A counterparty lookup for a tenant link.
    ///
    /// # Errors
    /// [`Error`].
    pub async fn lookup(&self, link_id: &str, body: &Value) -> Result<Value, Error> {
        self.json(
            "lookupCounterparties",
            CallInput {
                body: Some(body),
                link_id: Some(link_id),
                ..CallInput::default()
            },
        )
        .await
    }

    // ------------------------------------------------------------------------------ stats

    /// Sends a signed statistics report: the exact bytes that were signed, no token, ever.
    ///
    /// # Errors
    /// [`Error`].
    pub async fn send_stats_report(&self, signed: &SignedStatsReport) -> Result<Value, Error> {
        if signed.body.len() > STATS_MAX_BYTES {
            return Err(Error::Validation {
                code: "body_too_large",
                errors: Vec::new(),
            });
        }
        let op = OPERATIONS
            .iter()
            .find(|o| o.id == "ingestStatsReport")
            .ok_or(Error::InvalidOptions("operation table"))?;
        let names = [
            "ever-stats-key",
            "ever-stats-signature",
            "ever-stats-key-id",
        ];
        let mut headers = vec![
            (
                "accept".to_owned(),
                "application/json, application/problem+json".to_owned(),
            ),
            ("user-agent".to_owned(), self.user_agent.clone()),
            ("content-type".to_owned(), "application/json".to_owned()),
        ];
        for (name, value) in &signed.headers {
            if names.contains(&name.to_ascii_lowercase().as_str()) {
                headers.push((name.to_ascii_lowercase(), value.clone()));
            }
        }
        let p = Prepared {
            op,
            path: op.path.to_owned(),
            query: Vec::new(),
            headers,
            body: Some(signed.body.clone()),
            timeout: self.options.write_timeout,
        };
        let res = self.send_prepared(&p, None).await?;
        self.answer(op, &res).map(Answer::into_json)
    }
}
