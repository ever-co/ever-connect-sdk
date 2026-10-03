//! `ever.usage.v1` readings carry counts only: every fixture gets its verdict and path.
#![cfg(feature = "usage")]
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::path::PathBuf;

use ever_connect_sdk::usage::{usage_reading_errors, validate_usage_reading};
use serde_json::Value;

fn fixture(p: &str) -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/fixtures/usage")
        .join(p);
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

#[test]
fn every_fixture_gets_its_verdict_and_path() {
    let expected = fixture("expected.json");
    for (file, e) in expected["fixtures"].as_object().unwrap() {
        let errors = usage_reading_errors(&fixture(file));
        if e["valid"] == true {
            assert!(errors.is_empty(), "{file}: {errors:?}");
            validate_usage_reading(&fixture(file)).unwrap();
        } else {
            let path = e["path"].as_str().unwrap();
            assert!(errors.iter().any(|x| x.path == path), "{file}: {errors:?}");
            let error = validate_usage_reading(&fixture(file)).unwrap_err();
            assert!(error.to_string().starts_with("usage report refused:"));
        }
    }
}

#[test]
fn an_error_names_paths_never_values() {
    let mut body = fixture("valid/employees.json");
    body["contact"] = Value::String("Jane Doe <jane@example.com>".into());
    let error = validate_usage_reading(&body).unwrap_err();
    assert_eq!(error.errors.len(), 1);
    assert_eq!(error.errors[0].path, "/contact");
    assert_eq!(error.errors[0].code, "unknown_field");
    assert!(!error.to_string().contains("Jane"));
    assert!(!format!("{error:?}").contains("Jane"));
}
