//! The entitlement verifier over `contracts/fixtures/entitlement/expected.json`: the TypeScript
//! suite reads the same file, so the two languages cannot disagree silently.
#![cfg(feature = "entitlement")]
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::path::PathBuf;

use ever_connect_sdk::entitlement::{
    CachedEntitlement, EntitlementErrorCode, EntitlementStatus, VerifyEntitlementOptions,
    entitlement_status, verify_entitlement,
};
use ever_connect_sdk::keyset::KeySet;
use ever_connect_sdk::manifest::{RootKey, VerifyKeyManifestOptions};
use serde_json::{Value, json};

fn path(p: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/fixtures")
        .join(p)
}
fn fixture(p: &str) -> Value {
    serde_json::from_slice(&std::fs::read(path(p)).unwrap()).unwrap()
}
fn text(p: &str) -> String {
    std::fs::read_to_string(path(p)).unwrap().trim().to_owned()
}

fn key_set() -> KeySet {
    let ctx = fixture("keys/context.json");
    let roots: Vec<RootKey> = fixture("keys/roots.json")["keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(RootKey::from_jwk)
        .collect();
    KeySet::verify(
        &fixture("keys/manifest.valid.json"),
        &VerifyKeyManifestOptions {
            root_keys: Some(&roots),
            issuer: ctx["issuer"].as_str(),
            now: ctx["now"].as_i64(),
        },
    )
    .unwrap()
}

fn cached_of(v: &Value) -> Option<CachedEntitlement> {
    v.as_object().map(|_| CachedEntitlement {
        seq: v["seq"].as_i64().unwrap(),
        iat: v["iat"].as_i64().unwrap(),
    })
}

#[test]
fn every_fixture_answers_its_expected_code_or_status() {
    let ctx = fixture("entitlement/context.json");
    let set = key_set();
    let expected = fixture("entitlement/expected.json");
    let fixtures = expected["fixtures"].as_object().unwrap();
    for name in [
        "invalid/tampered-kid.jws",
        "invalid/tampered-seq.jws",
        "invalid/tampered-instance-id.jws",
        "invalid/alg-none.jws",
        "invalid/unmanifested-key.jws",
        "valid/expired-in-grace.jws",
        "valid/expired-past-grace.jws",
        "valid/skew-plus-299.jws",
    ] {
        assert!(fixtures.contains_key(name), "{name}");
    }
    for (file, e) in fixtures {
        let jws = text(&format!("entitlement/{file}"));
        let subject = ctx["expected_subject_by_file"][file]
            .as_str()
            .unwrap_or_else(|| ctx["expected_subject"].as_str().unwrap());
        let cached = match ctx["cached_by_file"].get(file) {
            Some(v) => cached_of(v),
            None => cached_of(&ctx["cached"]),
        };
        let result = verify_entitlement(
            &jws,
            &VerifyEntitlementOptions {
                key_set: &set,
                expected_issuer: ctx["expected_issuer"].as_str().unwrap(),
                expected_instance_id: ctx["expected_instance_id"].as_str().unwrap(),
                expected_subject: subject,
                cached,
                now: ctx["now"].as_i64(),
            },
        );
        if e["valid"] == true {
            let v = result.unwrap_or_else(|err| panic!("{file}: {err}"));
            assert_eq!(v.kid, e["kid"].as_str().unwrap(), "{file}");
            assert_eq!(v.seq, e["seq"].as_i64().unwrap(), "{file}");
            assert_eq!(v.claims["sub"], e["subject"], "{file}");
            assert_eq!(v.status.as_str(), e["status"].as_str().unwrap(), "{file}");
            assert_eq!(v.jws, jws);
            assert_eq!(
                v.claims,
                fixture(&format!(
                    "entitlement/{}",
                    file.replace(".jws", ".claims.json")
                )),
                "{file}"
            );
        } else {
            let err = result.err().unwrap_or_else(|| panic!("{file} verified"));
            assert_eq!(err.code.as_str(), e["code"].as_str().unwrap(), "{file}");
            assert!(!err.to_string().contains(&jws));
        }
    }
}

#[test]
fn an_unknown_kid_suggests_one_refresh_another_purpose_does_not() {
    let ctx = fixture("entitlement/context.json");
    let set = key_set();
    let verify = |file: &str| {
        verify_entitlement(
            &text(&format!("entitlement/{file}")),
            &VerifyEntitlementOptions {
                key_set: &set,
                expected_issuer: ctx["expected_issuer"].as_str().unwrap(),
                expected_instance_id: ctx["expected_instance_id"].as_str().unwrap(),
                expected_subject: ctx["expected_subject"].as_str().unwrap(),
                cached: None,
                now: ctx["now"].as_i64(),
            },
        )
        .unwrap_err()
    };
    let unknown = verify("invalid/unknown-kid.jws");
    assert_eq!(unknown.code, EntitlementErrorCode::UnknownKid);
    assert!(unknown.refresh_suggested);
    let purpose = verify("invalid/wrong-purpose.jws");
    assert_eq!(purpose.code, EntitlementErrorCode::UnknownKid);
    assert!(!purpose.refresh_suggested);
    let extra = verify("invalid/extra-claim.jws");
    assert_eq!(extra.code, EntitlementErrorCode::SchemaViolation);
    assert_eq!(extra.path.as_deref(), Some("/extra"));
    assert_eq!(
        extra.to_string(),
        "entitlement document refused: schema_violation"
    );
}

#[test]
fn the_ladder() {
    let c = json!({"exp": 1000, "ever": {"grace_s": 100}});
    assert_eq!(
        entitlement_status(Some(&c), 999, None),
        EntitlementStatus::Valid
    );
    assert_eq!(
        entitlement_status(Some(&c), 1000, None),
        EntitlementStatus::Stale
    );
    assert_eq!(
        entitlement_status(Some(&c), 1099, None),
        EntitlementStatus::Stale
    );
    assert_eq!(
        entitlement_status(Some(&c), 1100, None),
        EntitlementStatus::Paused
    );
    assert_eq!(entitlement_status(None, 0, None), EntitlementStatus::Paused);
    assert_eq!(
        entitlement_status(Some(&c), 1100, Some(1000)),
        EntitlementStatus::Stale
    );
}
