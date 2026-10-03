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
/// by their shape.
pub(crate) fn redact(text: &str) -> String {
    let out = text.to_owned();
    let mut result = String::with_capacity(out.len());
    let mut rest = out.as_str();
    while !rest.is_empty() {
        let token_start = rest.find("evit_");
        let jws_start = rest.find("eyJ");
        let start = match (token_start, jws_start) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) | (None, Some(a)) => a,
            (None, None) => {
                result.push_str(rest);
                break;
            }
        };
        result.push_str(&rest[..start]);
        let tail = &rest[start..];
        let len = tail
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'))
            .unwrap_or(tail.len());
        let candidate = &tail[..len];
        let is_token = candidate.starts_with("evit_");
        let is_jws = candidate.starts_with("eyJ") && candidate.matches('.').count() >= 2;
        if is_token || is_jws {
            result.push_str("[redacted]");
        } else {
            result.push_str(candidate);
        }
        rest = &tail[len..];
        if len == 0 {
            // Not a secret and nothing consumed: keep one character and move on.
            let mut chars = rest.chars();
            if let Some(c) = chars.next() {
                result.push(c);
            }
            rest = chars.as_str();
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::redact;

    #[test]
    fn tokens_and_documents_are_redacted() {
        let out =
            redact("bad evit_abc-123 and eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJ4In0.sig and eyJnot");
        assert_eq!(out, "bad [redacted] and [redacted] and eyJnot");
    }
}
