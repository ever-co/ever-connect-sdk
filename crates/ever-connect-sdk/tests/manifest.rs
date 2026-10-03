//! The key manifest verifier and the key set against the SDK fixtures (signed by the TEST root)
//! and the manifests Ever Platform serves (signed by the pinned development and staging roots).
#![cfg(feature = "entitlement")]
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::VerifyingKey;
use ever_connect_sdk::keyset::{KeySet, KeySetUpdate};
use ever_connect_sdk::manifest::{
    KeyManifestError, RootKey, VerifyKeyManifestOptions, keys_sha256, pinned_root_keys,
    verify_key_manifest,
};
use serde_json::{Value, json};

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

fn ctx() -> (String, i64) {
    let ctx = fixture("keys/context.json");
    (
        ctx["issuer"].as_str().unwrap().to_owned(),
        ctx["now"].as_i64().unwrap(),
    )
}

#[test]
fn every_sdk_fixture_answers_its_expected_code() {
    let (issuer, now) = ctx();
    let roots = roots();
    let expected = fixture("keys/expected.json");
    let fixtures = expected["fixtures"].as_object().unwrap();
    assert!(fixtures.len() >= 7);
    for (file, e) in fixtures {
        let body = fixture(&format!("keys/{file}"));
        let options = VerifyKeyManifestOptions {
            issuer: &issuer,
            unsafe_root_keys: Some(&roots),
            now: Some(now),
        };
        let result = verify_key_manifest(&body, &options);
        if e["valid"] == true {
            let m = result.unwrap();
            let kids: Vec<&str> = m.keys().iter().map(|k| k.kid()).collect();
            let trusted: Vec<&str> = e["trusted_kids"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            assert_eq!(kids, trusted, "{file}");
            assert_eq!(m.root_kid(), "test-root-1");
            assert_eq!(m.issuer(), issuer);
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
        &URL_SAFE_NO_PAD
            .decode(token.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        keys_sha256(&valid["keys"]).unwrap(),
        payload["keys_sha256"].as_str().unwrap()
    );
}

#[test]
fn a_root_vouches_only_for_the_issuer_it_names_and_no_test_root_is_pinned() {
    let (issuer, now) = ctx();
    let valid = fixture("keys/manifest.valid.json");
    let elsewhere: Vec<RootKey> = roots()
        .into_iter()
        .map(|r| RootKey {
            iss: Some("https://api.example.com".into()),
            ..r
        })
        .collect();
    let anywhere: Vec<RootKey> = roots()
        .into_iter()
        .map(|r| RootKey { iss: None, ..r })
        .collect();
    for set in [&elsewhere, &anywhere] {
        let o = VerifyKeyManifestOptions {
            issuer: &issuer,
            unsafe_root_keys: Some(set),
            now: Some(now),
        };
        assert_eq!(code(verify_key_manifest(&valid, &o)), "unknown_root");
    }
    // The pinned roots of this release hold no TEST root.
    let pinned = VerifyKeyManifestOptions {
        now: Some(now),
        ..VerifyKeyManifestOptions::for_issuer(&issuer)
    };
    assert_eq!(code(verify_key_manifest(&valid, &pinned)), "unknown_root");
    assert!(
        pinned_root_keys()
            .iter()
            .all(|r| !r.kid.starts_with("test-")
                && r.iss.as_deref().is_some_and(|i| i.starts_with("https://")))
    );
}

#[test]
fn key_times_that_do_not_exist_and_weak_keys_refuse_the_manifest() {
    let (issuer, now) = ctx();
    let roots = roots();
    let valid = fixture("keys/manifest.valid.json");
    let o = VerifyKeyManifestOptions {
        issuer: &issuer,
        unsafe_root_keys: Some(&roots),
        now: Some(now),
    };
    let with_key = |edit: Value| {
        let mut key = valid["keys"][1].clone();
        for (k, v) in edit.as_object().unwrap() {
            key[k] = v.clone();
        }
        json!({"manifest": valid["manifest"], "keys": [key]})
    };
    for t in [
        "2026-11-01T12:00:00+02:00",
        "2026-11-01 10:00:00Z",
        "2026-06-30T23:59:60Z",
        "2026-02-31T00:00:00Z",
        "2026-11-01",
    ] {
        assert_eq!(
            code(verify_key_manifest(&with_key(json!({"not_before": t})), &o)),
            "schema_violation",
            "{t}"
        );
    }
    assert_eq!(
        code(verify_key_manifest(
            &with_key(json!({"not_after": "soon"})),
            &o
        )),
        "schema_violation"
    );
    let identity = URL_SAFE_NO_PAD.encode(
        [1_u8]
            .iter()
            .chain([0_u8; 31].iter())
            .copied()
            .collect::<Vec<u8>>(),
    );
    assert_eq!(
        code(verify_key_manifest(&with_key(json!({"x": identity})), &o)),
        "schema_violation"
    );
}

#[test]
fn the_small_order_encodings_are_weak_keys_as_the_typescript_check_says() {
    let encodings = fixture("keys/small-order.json")["encodings"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(encodings.len(), 14);
    for h in encodings {
        let h = h.as_str().unwrap();
        let bytes: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        let key = VerifyingKey::from_bytes(&bytes.try_into().unwrap()).unwrap();
        assert!(key.is_weak(), "{h}");
    }
}

#[test]
fn the_platform_manifests_verify_with_the_pinned_root_of_their_issuer_only() {
    let expected = fixture("keys-platform/expected.json");
    for (file, e) in expected["fixtures"].as_object().unwrap() {
        let body = fixture(&format!("keys-platform/{file}"));
        let issuer = e["issuer"].as_str().unwrap();
        let at = e["verify_at"].as_i64().unwrap();
        let o = |issuer, now| VerifyKeyManifestOptions {
            now: Some(now),
            ..VerifyKeyManifestOptions::for_issuer(issuer)
        };
        let m = verify_key_manifest(&body, &o(issuer, at)).unwrap();
        assert_eq!(m.root_kid(), e["root_kid"].as_str().unwrap());
        let kids: Vec<&str> = m.keys().iter().map(|k| k.kid()).collect();
        let trusted: Vec<&str> = e["trusted_kids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(kids, trusted);
        assert_eq!(
            code(verify_key_manifest(&body, &o("https://api.ever.co", at))),
            "unknown_root"
        );
        let expired = e["expired_at"].as_i64().unwrap();
        assert_eq!(
            code(verify_key_manifest(&body, &o(issuer, expired))),
            "manifest_expired"
        );
    }
}

#[test]
fn the_key_set_answers_by_purpose_window_and_refresh_rules() {
    let (issuer, now) = ctx();
    let roots = roots();
    let options = VerifyKeyManifestOptions {
        issuer: &issuer,
        unsafe_root_keys: Some(&roots),
        now: Some(now),
    };
    let set = KeySet::verify(&fixture("keys/manifest.valid.json"), &options).unwrap();
    assert_eq!(set.issuer(), issuer);
    assert_eq!(
        set.find("test-entitlement-1", "entitlement", now)
            .unwrap()
            .kid(),
        "test-entitlement-1"
    );
    assert!(set.find("test-assertion-1", "entitlement", now).is_none());
    assert!(set.find("test-intent-1", "entitlement", now).is_none());
    assert!(set.find("test-entitlement-9", "entitlement", now).is_none());
    let not_before = set
        .find("test-entitlement-1", "entitlement", now)
        .unwrap()
        .not_before();
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
    let other_issuer = VerifyKeyManifestOptions {
        issuer: "https://api.ever.co",
        ..options.clone()
    };
    match set.update(&fixture("keys/manifest.valid.json"), &other_issuer) {
        KeySetUpdate::Refused(e) => assert_eq!(e.code(), "issuer_mismatch"),
        other => panic!("{other:?}"),
    }
    match set.update(&fixture("keys/manifest.valid.json"), &options) {
        KeySetUpdate::Replaced(next) => {
            assert_eq!(next.manifest().issued_at(), set.manifest().issued_at());
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
    assert_eq!(
        code(KeySet::restore(&stored, &other_issuer)),
        "unknown_root"
    );
    let mut future = stored.clone();
    future["fetchedAt"] = json!(now + 1_000_000_000);
    let restored = KeySet::restore(
        &future,
        &VerifyKeyManifestOptions {
            now: Some(now + 60),
            ..options.clone()
        },
    )
    .unwrap();
    assert_eq!(restored.fetched_at(), now + 60);
    let mut floor = stored;
    floor["fetchedAt"] = json!(i64::MIN);
    assert_eq!(KeySet::restore(&floor, &options).unwrap().fetched_at(), 0);
}

#[test]
fn of_two_threads_one_gets_the_unknown_kid_refresh() {
    let (issuer, now) = ctx();
    let roots = roots();
    let options = VerifyKeyManifestOptions {
        issuer: &issuer,
        unsafe_root_keys: Some(&roots),
        now: Some(now),
    };
    let set = std::sync::Arc::new(
        KeySet::verify(&fixture("keys/manifest.valid.json"), &options).unwrap(),
    );
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let s = std::sync::Arc::clone(&set);
            std::thread::spawn(move || s.unknown_kid_refresh_allowed(now + 700))
        })
        .collect();
    let granted = handles
        .into_iter()
        .filter(|_| true)
        .map(|h| h.join().unwrap())
        .filter(|g| *g)
        .count();
    assert_eq!(granted, 1);
}
