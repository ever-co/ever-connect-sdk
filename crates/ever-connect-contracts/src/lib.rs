//! `ever-connect-contracts`: the wire contracts between an installation of an Ever product and
//! Ever Platform, for Rust.
//!
//! * [`openapi::components`]: request and response types of the instance-facing contract
//!   (`contracts/openapi/ever-platform.v1.yaml`), generated with typify.
//! * [`schemas`]: types of the JSON Schemas (statistics report, entitlement document, consent
//!   record, key manifest, usage report) and of the data of every instance-audience event type.
//! * [`constants`], [`integrations`], [`outbound_calls`] and the `schema_*` accessors: the
//!   contract files themselves, parsed on first use.
//! * [`step_up`]: the types and pure checks of the in-product consent dialog's fresh sign-in.
//!
//! Types are plain `serde` types: they carry no validation. Validate a document against its JSON
//! Schema (for example with the `jsonschema` crate) before trusting it; the schemas are closed,
//! so a type that deserializes may still be refused by the schema's patterns and limits.
#![forbid(unsafe_code)]

/// Generated contract types and the embedded contract files.
#[allow(missing_docs)]
mod generated {
    pub mod constants;
    pub mod openapi;
    pub mod schemas;
}

pub use generated::constants::{
    FEED_EVENT_TYPES, INTEGRATION_KEYS, PROBLEM_CODES, PRODUCTS, STATS_HEADER_KEY,
    STATS_HEADER_KEY_ID, STATS_HEADER_SIGNATURE,
};
pub use generated::openapi;
pub use generated::schemas;

pub mod step_up;

use std::sync::OnceLock;

use serde_json::Value;

fn parse(name: &str, text: &'static str) -> Value {
    // The embedded files are generated and checked in CI; a parse failure is a build defect.
    serde_json::from_str(text)
        .unwrap_or_else(|e| panic!("embedded contract file {name} is not JSON: {e}"))
}

/// `contracts/constants.json`.
pub fn constants() -> &'static Value {
    static CELL: OnceLock<Value> = OnceLock::new();
    CELL.get_or_init(|| parse("constants.json", generated::constants::CONSTANTS_JSON))
}

/// Every integration definition, by key (hidden catalog keys are never included).
pub fn integrations() -> &'static [(&'static str, Value)] {
    static CELL: OnceLock<Vec<(&'static str, Value)>> = OnceLock::new();
    CELL.get_or_init(|| {
        generated::constants::INTEGRATIONS_JSON
            .iter()
            .map(|(key, text)| (*key, parse(key, text)))
            .collect()
    })
}

/// One integration definition by key.
pub fn integration(key: &str) -> Option<&'static Value> {
    integrations()
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
}

/// The outbound-call table (`contracts/generated/outbound-calls.json`).
pub fn outbound_calls() -> &'static Value {
    static CELL: OnceLock<Value> = OnceLock::new();
    CELL.get_or_init(|| {
        parse(
            "outbound-calls.json",
            generated::constants::OUTBOUND_CALLS_JSON,
        )
    })
}

/// Every (row, status, problem code) the table documents (`contracts/generated/row-coverage.json`).
pub fn row_coverage() -> &'static Value {
    static CELL: OnceLock<Value> = OnceLock::new();
    CELL.get_or_init(|| parse("row-coverage.json", generated::constants::ROW_COVERAGE_JSON))
}

fn schema(file: &str) -> &'static str {
    generated::constants::SCHEMAS_JSON
        .iter()
        .find(|(name, _)| *name == file)
        .map(|(_, text)| *text)
        .unwrap_or_else(|| panic!("embedded schema {file} is missing"))
}

/// The `ever.stats.v1` JSON Schema, verbatim.
pub fn schema_stats_v1() -> &'static str {
    schema("ever.stats.v1.json")
}

/// The `ever.entitlement.v1` JSON Schema (the payload of an entitlement document), verbatim.
pub fn schema_entitlement_v1() -> &'static str {
    schema("ever.entitlement.v1.json")
}

/// The `ever.consent.v1` JSON Schema (a consent record), verbatim.
pub fn schema_consent_v1() -> &'static str {
    schema("ever.consent.v1.json")
}

/// The `ever.key-manifest.v1` JSON Schema (the body of `/.well-known/ever-keys.json`), verbatim.
pub fn schema_key_manifest_v1() -> &'static str {
    schema("ever.key-manifest.v1.json")
}

/// The `ever.usage.v1` JSON Schema (a usage report of the `usage_reporting` integration), verbatim.
pub fn schema_usage_v1() -> &'static str {
    schema("ever.usage.v1.json")
}

/// The event schemas: `envelope.schema.json`, `common.schema.json` and one data schema per
/// instance-audience event type, by file name.
pub fn event_schemas() -> &'static [(&'static str, &'static str)] {
    generated::constants::EVENT_SCHEMAS_JSON
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn the_embedded_files_parse_and_agree() {
        let c = constants();
        assert_eq!(c["stats_headers"]["key"], STATS_HEADER_KEY);
        assert_eq!(c["stats_headers"]["signature"], STATS_HEADER_SIGNATURE);
        assert_eq!(c["stats_headers"]["key_id"], STATS_HEADER_KEY_ID);
        let products: Vec<&str> = c["products"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(products, PRODUCTS);
        assert_eq!(integrations().len(), INTEGRATION_KEYS.len());
        for key in INTEGRATION_KEYS {
            assert_eq!(integration(key).unwrap()["key"], *key);
            assert_ne!(
                integration(key).unwrap()["status"],
                "hidden",
                "a hidden key never ships"
            );
        }
        assert_eq!(outbound_calls()["rows"].as_array().unwrap().len(), 34);
        for text in [
            schema_stats_v1(),
            schema_entitlement_v1(),
            schema_consent_v1(),
            schema_key_manifest_v1(),
            schema_usage_v1(),
        ] {
            let v: Value = serde_json::from_str(text).unwrap();
            assert_eq!(v["$schema"], "https://json-schema.org/draft/2020-12/schema");
        }
        assert_eq!(event_schemas().len(), FEED_EVENT_TYPES.len() + 2);
    }
}
