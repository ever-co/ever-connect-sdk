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
            unsafe_root_keys: Some(&roots),
            issuer: ctx["issuer"].as_str().unwrap(),
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

/// The forgery of the security review: the TEST root's private key comes from a public seed
/// label, so anyone can sign a key manifest with it listing their own key, and a document for any
/// issuer with that key. Every path must refuse it.
mod review_forgery {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signer as _, SigningKey};
    use ever_connect_sdk::entitlement::{
        EntitlementErrorCode, VerifyEntitlementOptions, verify_entitlement,
    };
    use ever_connect_sdk::keyset::{KeySet, KeySetUpdate};
    use ever_connect_sdk::manifest::{
        KeyManifestError, RootKey, VerifyKeyManifestOptions, keys_sha256,
    };
    use serde_json::{Value, json};
    use sha2::{Digest as _, Sha256};

    use super::fixture;

    const PROD: &str = "https://api.ever.co";

    fn test_key(label: &str) -> SigningKey {
        let seed: [u8; 32] = Sha256::digest(format!("ever-connect-sdk/{label}")).into();
        SigningKey::from_bytes(&seed)
    }

    fn sign(label: &str, header: &Value, payload: &Value) -> String {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(payload.to_string())
        );
        let signature = test_key(label).sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    fn roots() -> Vec<RootKey> {
        fixture("keys/roots.json")["keys"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(RootKey::from_jwk)
            .collect()
    }

    /// A manifest signed by the TEST root for `issuer`, listing the attacker's key.
    fn forged_manifest(issuer: &str, now: i64) -> Value {
        let mut keys = fixture("keys/manifest.valid.json")["keys"]
            .as_array()
            .unwrap()
            .clone();
        let mut attacker = keys[1].clone();
        attacker["kid"] = json!("attacker-1");
        attacker["x"] =
            json!(URL_SAFE_NO_PAD.encode(test_key("test-stranger/1").verifying_key().to_bytes()));
        keys.push(attacker);
        let keys = Value::Array(keys);
        let payload = json!({
            "iss": issuer, "iat": now, "exp": now + 2_592_000,
            "keys_sha256": keys_sha256(&keys).unwrap(), "root_kid": "test-root-1",
        });
        let header = json!({"alg": "EdDSA", "kid": "test-root-1", "typ": "ever-key-manifest+jwt"});
        json!({"manifest": sign("test-root/1", &header, &payload), "keys": keys})
    }

    fn forged_document() -> String {
        let mut claims = fixture("entitlement/valid/instance.claims.json");
        claims["iss"] = json!(PROD);
        claims["ever"]["tier"] = json!("bundle");
        let header = json!({"alg": "EdDSA", "kid": "attacker-1", "typ": "ever-entitlement+jwt"});
        sign("test-stranger/1", &header, &claims)
    }

    fn code<T>(r: Result<T, KeyManifestError>) -> &'static str {
        r.map_or_else(|e| e.code(), |_| "ok")
    }

    #[test]
    fn a_test_root_manifest_for_the_production_issuer_is_refused_on_every_path() {
        let now = fixture("keys/context.json")["now"].as_i64().unwrap();
        let forged = forged_manifest(PROD, now);
        let pinned = VerifyKeyManifestOptions {
            now: Some(now),
            ..VerifyKeyManifestOptions::for_issuer(PROD)
        };
        let roots = roots();
        let with_test_root = VerifyKeyManifestOptions {
            unsafe_root_keys: Some(&roots),
            ..pinned.clone()
        };
        assert_eq!(code(KeySet::verify(&forged, &pinned)), "unknown_root");
        assert_eq!(
            code(KeySet::verify(&forged, &with_test_root)),
            "unknown_root"
        );
        let stored = json!({"document": forged, "fetchedAt": now});
        assert_eq!(code(KeySet::restore(&stored, &pinned)), "unknown_root");
        assert_eq!(
            code(KeySet::restore(&stored, &with_test_root)),
            "unknown_root"
        );
    }

    #[test]
    fn a_key_set_of_the_test_issuer_never_vouches_for_a_production_document() {
        let ctx = fixture("entitlement/context.json");
        let keys_ctx = fixture("keys/context.json");
        let (issuer, now) = (
            keys_ctx["issuer"].as_str().unwrap(),
            keys_ctx["now"].as_i64().unwrap(),
        );
        let roots = roots();
        let options = VerifyKeyManifestOptions {
            issuer,
            unsafe_root_keys: Some(&roots),
            now: Some(now),
        };
        let set = KeySet::verify(&forged_manifest(issuer, now), &options).unwrap();
        let result = verify_entitlement(
            &forged_document(),
            &VerifyEntitlementOptions {
                key_set: &set,
                expected_issuer: PROD,
                expected_instance_id: ctx["expected_instance_id"].as_str().unwrap(),
                expected_subject: ctx["expected_subject"].as_str().unwrap(),
                cached: None,
                now: ctx["now"].as_i64(),
            },
        );
        assert_eq!(
            result.unwrap_err().code,
            EntitlementErrorCode::IssuerMismatch
        );
        // Nor can it be turned into a production key set by an update.
        let prod = VerifyKeyManifestOptions {
            issuer: PROD,
            ..options
        };
        match set.update(&forged_manifest(PROD, now), &prod) {
            KeySetUpdate::Refused(e) => assert_eq!(e.code(), "issuer_mismatch"),
            other => panic!("{other:?}"),
        }
    }
}
