//! `ever.usage.v1`: the counts an installation reports for apps priced per unit (employees, seats,
//! users, projects, transactions). Counts and timestamps only, closed at every level. The crate
//! adds no call of its own: the push goes through the client's usage operation, which needs the
//! `usage_reporting` integration (off by default on a self-hosted installation).

use std::fmt;
use std::sync::OnceLock;

use serde_json::Value;

/// One field error of a usage reading: a JSON pointer and a code, never a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageFieldError {
    /// The JSON pointer.
    pub path: String,
    /// `unknown_field`, `type`, `pattern`, `range`, `required` or `shape`.
    pub code: &'static str,
}

/// A usage reading that breaks `ever.usage.v1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageValidationError {
    /// Every field error, sorted by path.
    pub errors: Vec<UsageFieldError>,
}

impl fmt::Display for UsageValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("usage report refused:")?;
        for (i, e) in self.errors.iter().enumerate() {
            let path = if e.path.is_empty() { "(body)" } else { &e.path };
            write!(f, "{} {path} {}", if i == 0 { "" } else { "," }, e.code)?;
        }
        Ok(())
    }
}

impl std::error::Error for UsageValidationError {}

fn usage_schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        serde_json::from_str(ever_connect_contracts::schema_usage_v1())
            .unwrap_or_else(|e| panic!("the embedded usage schema is not JSON: {e}"))
    })
}

/// The field errors of a usage reading (empty when it is valid).
#[must_use]
pub fn usage_reading_errors(body: &Value) -> Vec<UsageFieldError> {
    let schema = usage_schema();
    crate::schema::violations(schema, body, schema)
        .into_iter()
        .map(|v| UsageFieldError {
            path: v.path,
            code: v.kind.as_str(),
        })
        .collect()
}

/// Checks a usage reading against `ever.usage.v1`.
///
/// # Errors
/// [`UsageValidationError`] with every field error.
pub fn validate_usage_reading(body: &Value) -> Result<(), UsageValidationError> {
    let errors = usage_reading_errors(body);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(UsageValidationError { errors })
    }
}
