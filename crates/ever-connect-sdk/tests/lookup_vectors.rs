//! Lookup normalisation and hashing against the published vectors. Runs under
//! `--no-default-features --features lookup` (what the platform consumes).
#![cfg(feature = "lookup")]
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::path::PathBuf;

use ever_connect_sdk::lookup::{
    LookupInputError, LookupKind, check_test_vectors, lookup_hash, normalize_identifier,
};
use serde_json::Value;

fn vectors() -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/fixtures/lookup/test-vectors.json");
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

#[test]
fn every_published_vector_is_reproduced_and_every_refused_row_refused() {
    let v = vectors();
    assert_eq!(v["vectors"].as_array().unwrap().len(), 19);
    assert_eq!(v["refused"].as_array().unwrap().len(), 15);
    check_test_vectors(&v).unwrap();
    let salt = v["salt"].as_str().unwrap();
    let n = normalize_identifier(LookupKind::Vat, " bg 123 456 789 ", None).unwrap();
    assert_eq!(
        lookup_hash(LookupKind::Vat, &n, 0, salt).unwrap().hash,
        "12c9b8f891583acaea6dc0f86233ea527c32c31e0bd818c329a7105d3beaf366"
    );
}

#[test]
fn an_email_domain_is_never_percent_decoded_cut_or_read_as_ipv4() {
    for input in [
        "jane@%41.com",
        "jane@a/b.com",
        "jane@a／b.com",
        "jane@0x7f.1",
        "jane@1.2.3.",
        "jane@example.123",
        "jane@xn--a.com",
        "jane@a:1.com",
    ] {
        assert_eq!(
            normalize_identifier(LookupKind::Email, input, None),
            Err(LookupInputError::BadDomain),
            "{input}"
        );
    }
    assert_eq!(
        normalize_identifier(LookupKind::Email, "jane@Example.COM.", None).unwrap(),
        "jane@example.com."
    );
    // A refused row the crate would hash is reported at its index.
    let mut v = vectors();
    v["refused"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "kind": "email", "input": "jane@example.com", "reason": "bad_domain"
        }));
    let e = check_test_vectors(&v).unwrap_err();
    assert_eq!((e.index, e.field), (15, "refused"));
}

#[test]
fn one_changed_vector_fails_at_its_index() {
    let mut v = vectors();
    v["vectors"][4]["hash"] = Value::String("0".repeat(64));
    let e = check_test_vectors(&v).unwrap_err();
    assert_eq!((e.index, e.field), (4, "hash"));
}

#[test]
fn the_rules_and_what_cannot_be_checked() {
    assert_eq!(
        normalize_identifier(LookupKind::Email, "a.b+c@Bücher.example", None).unwrap(),
        "a.b+c@xn--bcher-kva.example"
    );
    assert_eq!(
        normalize_identifier(LookupKind::Email, "\"x@y\"@Example.COM", None).unwrap(),
        "\"x@y\"@example.com"
    );
    assert_eq!(
        normalize_identifier(LookupKind::Vat, "de 12.345.678/9", Some("BG")).unwrap(),
        "DE123456789"
    );
    assert_eq!(
        normalize_identifier(LookupKind::Registration, " hrb-12.345 ", Some("de")).unwrap(),
        "DE:HRB12345"
    );
    assert_eq!(
        normalize_identifier(LookupKind::Vat, " .-/ ", None),
        Err(LookupInputError::Empty)
    );
    assert_eq!(
        normalize_identifier(LookupKind::Vat, "123456789", None),
        Err(LookupInputError::NoCountry)
    );
    assert_eq!(
        normalize_identifier(LookupKind::Vat, "123456789", Some("Bulgaria")),
        Err(LookupInputError::NoCountry)
    );
    assert_eq!(
        normalize_identifier(LookupKind::Registration, "123", None),
        Err(LookupInputError::NoCountry)
    );
    assert_eq!(
        normalize_identifier(LookupKind::Email, "jane.example.com", None),
        Err(LookupInputError::NoAtSign)
    );
    assert_eq!(
        normalize_identifier(LookupKind::Email, "jane@", None),
        Err(LookupInputError::BadDomain)
    );
    assert_eq!(
        normalize_identifier(LookupKind::Email, "   ", None),
        Err(LookupInputError::Empty)
    );
    assert_eq!(LookupInputError::Empty.code(), "cannot_be_checked");
    // A salt that is not 32 bytes is refused (here: the test salt cut short).
    let v = vectors();
    let short = &v["salt"].as_str().unwrap()[..10];
    assert!(lookup_hash(LookupKind::Vat, "BG1", 1, short).is_err());
}
