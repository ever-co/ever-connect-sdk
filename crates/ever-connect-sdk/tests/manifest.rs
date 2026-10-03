//! The key manifest verifier and the key set against the SDK fixtures (signed by the TEST root)
//! and the manifests Ever Platform serves (signed by the pinned development and staging roots).
#![cfg(feature = "entitlement")]
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::path::PathBuf;

use ever_connect_sdk::keyset::{KeySet, KeySetUpdate};
use ever_connect_sdk::manifest::{
    KeyManifestError, RootKey, VerifyKeyManifestOptions, keys_sha256, pinned_root_keys,
    verify_key_manifest,
};
use serde_json::Value;

fn fixture(path: &str) -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/fixtures")
        .join(path);
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn roots() -> Vec<RootKey> {
    fixture("keys/roots.json")["keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(RootKey::from_jwk)
        .collect()
}

fn code(result: Result<impl Sized, KeyManifestError>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(e) => e.code(),
    }
}

#[test]
fn every_sdk_fixture_answers_its_expected_code() {
    let ctx = fixture("keys/context.json");
    let issuer = ctx["issuer"].as_str().unwrap();
    let now = ctx["now"].as_i64().unwrap();
    let roots = roots();
    let expected = fixture("keys/expected.json");
    let fixtures = expected["fixtures"].as_object().unwrap();
    assert!(fixtures.len() >= 7);
    for (file, e) in fixtures {
        let body = fixture(&format!("keys/{file}"));
        let options = VerifyKeyManifestOptions {
            root_keys: Some(&roots),
            issuer: Some(issuer),
            now: Some(now),
        };
        let result = verify_key_manifest(&body, &options);
        if e["valid"] == true {
            let m = result.unwrap();
            let kids: Vec<&str> = m.keys.iter().map(|k| k.kid.as_str()).collect();
            let trusted: Vec<&str> = e["trusted_kids"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            assert_eq!(kids, trusted, "{file}");
            assert_eq!(m.root_kid, "test-root-1");
        } else {
            assert_eq!(code(result), e["code"].as_str().unwrap(), "{file}");
        }
    }
}

#[test]
fn jcs_of_the_served_keys_is_the_signed_hash() {
    let valid = fixture("keys/manifest.valid.json");
    let token = valid["manifest"].as_str().unwrap();
    let payload: Value = serde_json::from_slice(
        &base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            token.split('.').nth(1).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        keys_sha256(&valid["keys"]).unwrap(),
        payload["keys_sha256"].as_str().unwrap()
    );
}

#[test]
fn the_platform_manifests_verify_with_the_pinned_root_of_their_issuer_only() {
    let expected = fixture("keys-platform/expected.json");
    for (file, e) in expected["fixtures"].as_object().unwrap() {
        let body = fixture(&format!("keys-platform/{file}"));
        let issuer = e["issuer"].as_str().unwrap();
        let at = e["verify_at"].as_i64().unwrap();
        let m = verify_key_manifest(
            &body,
            &VerifyKeyManifestOptions {
                issuer: Some(issuer),
                now: Some(at),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(m.root_kid, e["root_kid"].as_str().unwrap());
        let kids: Vec<&str> = m.keys.iter().map(|k| k.kid.as_str()).collect();
        let trusted: Vec<&str> = e["trusted_kids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(kids, trusted);
        // Without an issuer, the one the root is pinned to.
        assert_eq!(
            verify_key_manifest(
                &body,
                &VerifyKeyManifestOptions {
                    now: Some(at),
                    ..Default::default()
                }
            )
            .unwrap()
            .issuer,
            issuer
        );
        assert_eq!(
            code(verify_key_manifest(
                &body,
                &VerifyKeyManifestOptions {
                    issuer: Some("https://api.ever.co"),
                    now: Some(at),
                    ..Default::default()
                }
            )),
            "unknown_root"
        );
        let expired = e["expired_at"].as_i64().unwrap();
        assert_eq!(
            code(verify_key_manifest(
                &body,
                &VerifyKeyManifestOptions {
                    issuer: Some(issuer),
                    now: Some(expired),
                    ..Default::default()
                }
            )),
            "manifest_expired"
        );
    }
    assert!(pinned_root_keys()[0].kid.starts_with("test-"));
}

#[test]
fn the_key_set_answers_by_purpose_window_and_refresh_rules() {
    let ctx = fixture("keys/context.json");
    let issuer = ctx["issuer"].as_str().unwrap();
    let now = ctx["now"].as_i64().unwrap();
    let roots = roots();
    let options = VerifyKeyManifestOptions {
        root_keys: Some(&roots),
        issuer: Some(issuer),
        now: Some(now),
    };
    let set = KeySet::verify(&fixture("keys/manifest.valid.json"), &options).unwrap();
    assert_eq!(
        set.find("test-entitlement-1", "entitlement", now)
            .unwrap()
            .kid,
        "test-entitlement-1"
    );
    assert!(set.find("test-assertion-1", "entitlement", now).is_none());
    assert!(set.find("test-intent-1", "entitlement", now).is_none());
    assert!(set.find("test-entitlement-9", "entitlement", now).is_none());
    let not_before = set
        .find("test-entitlement-1", "entitlement", now)
        .unwrap()
        .not_before
        .unwrap();
    assert!(
        set.find("test-entitlement-1", "entitlement", not_before - 300)
            .is_some()
    );
    assert!(
        set.find("test-entitlement-1", "entitlement", not_before - 301)
            .is_none()
    );
    assert!(!set.needs_refresh(now + 86_399));
    assert!(set.needs_refresh(now + 86_400));
    assert!(!set.unknown_kid_refresh_allowed(now + 599));
    assert!(set.unknown_kid_refresh_allowed(now + 600));
    assert!(!set.unknown_kid_refresh_allowed(now + 1199));
    assert!(set.unknown_kid_refresh_allowed(now + 1200));

    match set.update(
        &fixture("keys/manifest.keys-sha256-mismatch.json"),
        &options,
    ) {
        KeySetUpdate::Refused(e) => assert_eq!(e.code(), "keys_sha256_mismatch"),
        other => panic!("{other:?}"),
    }
    match set.update(&fixture("keys/manifest.valid.json"), &options) {
        KeySetUpdate::Replaced(next) => {
            assert_eq!(next.manifest().issued_at, set.manifest().issued_at)
        }
        other => panic!("{other:?}"),
    }
    let stored = set.stored();
    assert_eq!(stored["document"], fixture("keys/manifest.valid.json"));
    let back = KeySet::restore(&stored, &options).unwrap();
    assert!(
        back.find("test-entitlement-1", "entitlement", now)
            .is_some()
    );
}
