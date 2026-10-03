//! The client's errors. `Debug` and `Display` never carry a token, an assertion, a key or a
//! document: problem details are redacted before they are kept.

use std::fmt;

use crate::assertion::AssertionError;
use crate::entitlement::EntitlementError;
use crate::manifest::KeyManifestError;

/// One field error of a problem document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProblemFieldError {
    /// The JSON pointer.
    pub path: String,
    /// The code.
    pub code: String,
    /// The platform's sentence (redacted).
    pub message: String,
}

/// A non-2xx answer of Ever Platform, parsed from its `application/problem+json` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProblemError {
    /// The HTTP status.
    pub status: u16,
    /// The problem code, or `unknown` when the body is not a problem document.
    pub code: String,
    /// The platform's sentence (redacted).
    pub detail: Option<String>,
    /// The request id the platform echoes, for support requests.
    pub instance: Option<String>,
    /// Field errors (validation problems only); `client_assertion` and `client_secret` are dropped.
    pub errors: Vec<ProblemFieldError>,
    /// Seconds the platform asks to wait (`Retry-After`).
    pub retry_after_s: Option<u64>,
}

impl fmt::Display for ProblemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ever Platform answered {} {}", self.status, self.code)
    }
}

impl std::error::Error for ProblemError {}

/// Everything a client call can answer instead of a result.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A non-2xx answer.
    Problem(ProblemError),
    /// Refused before any I/O, or a redirect that was not followed: `absolute_url`,
    /// `insecure_base_url` or `redirect`.
    EgressRefused {
        /// The reason.
        code: &'static str,
    },
    /// The call needs the instance token and the installation has no Registry id yet.
    NotConnected,
    /// No answer within the deadline.
    Timeout {
        /// The deadline, in milliseconds.
        timeout_ms: u64,
    },
    /// Refused before any I/O: `idempotency_key_required`, `invalid_body`, `body_too_large`,
    /// `link_required` or `invalid_parameter`.
    Validation {
        /// The reason.
        code: &'static str,
        /// The fields at fault: JSON pointer (or parameter name) and code.
        errors: Vec<(String, &'static str)>,
    },
    /// An entitlement document that does not verify.
    Entitlement(EntitlementError),
    /// A key manifest that does not verify.
    KeyManifest(KeyManifestError),
    /// The client assertion could not be built.
    Assertion(AssertionError),
    /// The request did not complete (connection, TLS, an answer that is not JSON).
    Transport(String),
    /// An answer larger than the client reads (the read stopped at the limit).
    ResponseTooLarge {
        /// The limit, in bytes.
        limit_bytes: usize,
    },
    /// A call the client held back because the platform would refuse it for its rate class (the
    /// entitlement reads: `entitlement.max_reads_per_hour` per path, or a 429's `Retry-After`):
    /// nothing was sent.
    RateLimited {
        /// Seconds to wait before the call can go out.
        retry_after_s: u64,
    },
    /// The client options are not usable.
    InvalidOptions(&'static str),
}

impl Error {
    /// A short code for logs.
    #[must_use]
    pub fn code(&self) -> &str {
        match self {
            Self::Problem(p) => &p.code,
            Self::EgressRefused { code } | Self::Validation { code, .. } => code,
            Self::NotConnected => "no_registry_instance_id",
            Self::Timeout { .. } => "timeout",
            Self::Entitlement(e) => e.code.as_str(),
            Self::KeyManifest(e) => e.code(),
            Self::Assertion(e) => e.code(),
            Self::Transport(_) => "transport",
            Self::ResponseTooLarge { .. } => "response_too_large",
            Self::RateLimited { .. } => "rate_limited",
            Self::InvalidOptions(_) => "invalid_options",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Problem(p) => p.fmt(f),
            Self::EgressRefused { code } => write!(f, "request refused: {code}"),
            Self::NotConnected => {
                f.write_str("the installation is not connected yet (no Registry id)")
            }
            Self::Timeout { timeout_ms } => write!(f, "no answer within {timeout_ms} ms"),
            Self::Validation { code, errors } => {
                write!(f, "request refused before sending: {code}")?;
                for (path, c) in errors {
                    write!(
                        f,
                        " ({} {c})",
                        if path.is_empty() { "(body)" } else { path }
                    )?;
                }
                Ok(())
            }
            Self::Entitlement(e) => e.fmt(f),
            Self::KeyManifest(e) => e.fmt(f),
            Self::Assertion(e) => e.fmt(f),
            Self::Transport(m) => write!(f, "the request did not complete: {m}"),
            Self::ResponseTooLarge { limit_bytes } => {
                write!(f, "answer larger than {limit_bytes} bytes")
            }
            Self::RateLimited { retry_after_s } => write!(
                f,
                "held back before sending: rate_limited (retry after {retry_after_s} s)"
            ),
            Self::InvalidOptions(m) => write!(f, "invalid client options: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<EntitlementError> for Error {
    fn from(e: EntitlementError) -> Self {
        Self::Entitlement(e)
    }
}

impl From<KeyManifestError> for Error {
    fn from(e: KeyManifestError) -> Self {
        Self::KeyManifest(e)
    }
}

impl From<AssertionError> for Error {
    fn from(e: AssertionError) -> Self {
        match e {
            AssertionError::NotConnected => Self::NotConnected,
            other => Self::Assertion(other),
        }
    }
}

/// Replaces every instance token (`evit_…`) and every compact JWS (an assertion, a document) in
/// `text` with `[redacted]`. The client keeps no copy of a secret to look for: both are recognised
/// by their shape. Tokens first, anywhere (also inside something that looks like a document), then
/// documents: the same two rules, in the same order, as the TypeScript client.
pub(crate) fn redact(text: &str) -> String {
    redact_documents(&redact_tokens(text))
}

const fn token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// `evit_[A-Za-z0-9_-]+` becomes `[redacted]`.
fn redact_tokens(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut i = 0;
    while i < b.len() {
        if b[i..].starts_with(b"evit_") {
            let run = b[i + 5..].iter().take_while(|c| token_char(**c)).count();
            if run > 0 {
                out.push_str(&text[copied..i]);
                out.push_str("[redacted]");
                i += 5 + run;
                copied = i;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&text[copied..]);
    out
}

/// `eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*` becomes `[redacted]`.
fn redact_documents(text: &str) -> String {
    let b = text.as_bytes();
    let run = |from: usize| b[from..].iter().take_while(|c| token_char(**c)).count();
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut i = 0;
    while i < b.len() {
        if b[i..].starts_with(b"eyJ") {
            let first = i + 3 + run(i + 3);
            if b.get(first) == Some(&b'.') {
                let second = run(first + 1);
                if second > 0 && b.get(first + 1 + second) == Some(&b'.') {
                    let end = first + 2 + second + run(first + 2 + second);
                    out.push_str(&text[copied..i]);
                    out.push_str("[redacted]");
                    i = end;
                    copied = i;
                    continue;
                }
            }
        }
        i += 1;
    }
    out.push_str(&text[copied..]);
    out
}

#[cfg(test)]
mod tests {
    use super::redact;

    #[test]
    fn tokens_and_documents_are_redacted() {
        let out =
            redact("bad evit_abc-123 and eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJ4In0.sig and eyJnot");
        assert_eq!(out, "bad [redacted] and [redacted] and eyJnot");
        // A token glued to something that starts like a document is still a token.
        assert_eq!(redact("x eyJab_evit_SECRET y"), "x eyJab_[redacted] y");
        assert_eq!(
            redact("évit_ ünï evit_ eyJ..x eyJa.b.c"),
            "évit_ ünï evit_ eyJ..x [redacted]"
        );
    }
}
