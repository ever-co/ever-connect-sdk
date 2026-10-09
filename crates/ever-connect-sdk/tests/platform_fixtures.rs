//! The platform's own signed entitlement fixtures (`contracts/fixtures/entitlement-platform/`,
//! vendored byte for byte from ever-co/platform): the issuer signs them with its TEST keys, and
//! every document must reach the platform's expected outcome here, as in the TypeScript suite.
#![cfg(feature = "entitlement")]
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::path::PathBuf;

use ever_connect_sdk::entitlement::{
    CachedEntitlement, VerifyEntitlementOptions, verify_entitlement,
};
use ever_connect_sdk::keyset::KeySet;
use ever_connect_sdk::manifest::{RootKey, VerifyKeyManifestOptions};
use serde_json::{Value, json};

fn path(p: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/fixtures/entitlement-platform")
        .join(p)
}
fn fixture(p: &str) -> Value {
    serde_json::from_slice(&std::fs::read(path(p)).unwrap()).unwrap()
}

#[test]
fn every_platform_document_reaches_its_expected_outcome() {
    let ctx = fixture("context.json");
    let issuer = ctx["expected_issuer"].as_str().unwrap();
    let now = ctx["now"].as_i64().unwrap();
    // The platform names each root's issuer as `issuer`; the SDK's roots carry it as `iss`.
    let roots: Vec<RootKey> = fixture(ctx["roots_file"].as_str().unwrap())
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| {
            RootKey::from_jwk(&json!({"kid": r["kid"], "x": r["x"], "iss": r["issuer"], "kty": "OKP", "crv": "Ed25519"}))
        })
        .collect();
    assert_eq!(roots.len(), 1);
    let set = KeySet::verify(
        &fixture(ctx["manifest"].as_str().unwrap()),
        &VerifyKeyManifestOptions {
            issuer,
            unsafe_root_keys: Some(&roots),
            now: Some(now),
        },
    )
    .unwrap();
    let expected = fixture("expected.json");
    let fixtures = expected["fixtures"].as_object().unwrap();
    assert_eq!(fixtures.values().filter(|e| e["valid"] == true).count(), 3);
    assert_eq!(
        fixtures.values().filter(|e| e["valid"] == false).count(),
        14
    );
    for (file, e) in fixtures {
        let jws = std::fs::read_to_string(path(file)).unwrap();
        let cached = ctx["cached_by_file"].get(file).map(|c| CachedEntitlement {
            seq: c["seq"].as_i64().unwrap(),
            iat: c["iat"].as_i64().unwrap(),
        });
        let result = verify_entitlement(
            jws.trim(),
            &VerifyEntitlementOptions {
                key_set: &set,
                expected_issuer: issuer,
                expected_instance_id: ctx["expected_instance_id_by_file"][file].as_str().unwrap(),
                expected_subject: ctx["expected_subject_by_file"][file].as_str().unwrap(),
                cached,
                now: Some(
                    ctx["now_by_file"]
                        .get(file)
                        .and_then(Value::as_i64)
                        .unwrap_or(now),
                ),
            },
        );
        if e["valid"] == true {
            let v = result.unwrap_or_else(|err| panic!("{file}: {}", err.code.as_str()));
            assert_eq!(v.kid, e["kid"].as_str().unwrap(), "{file}");
            assert_eq!(v.seq, e["seq"].as_i64().unwrap(), "{file}");
            assert_eq!(v.claims["sub"], e["subject"], "{file}");
            assert_eq!(
                v.claims,
                fixture(&file.replace(".jws", ".claims.json")),
                "{file}"
            );
        } else {
            let code = result.map_or_else(|err| err.code.as_str(), |_| "ok");
            assert_eq!(code, e["code"].as_str().unwrap(), "{file}");
        }
    }
}

/// The roots of a platform root file, as the SDK pins them (`iss` from the platform's `issuer`).
fn roots_of(file: &str) -> Vec<RootKey> {
    fixture(file)
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| {
            RootKey::from_jwk(&json!({"kid": r["kid"], "x": r["x"], "iss": r["issuer"], "kty": "OKP", "crv": "Ed25519"}))
        })
        .collect()
}

#[test]
fn every_platform_key_manifest_reaches_its_expected_outcome() {
    let ctx = &fixture("context.json")["manifests"];
    let issuer = ctx["issuer"].as_str().unwrap();
    let now = ctx["now"].as_i64().unwrap();
    let expected = fixture("expected.json");
    let manifests = expected["manifests"].as_object().unwrap();
    assert_eq!(manifests.values().filter(|e| e["valid"] == true).count(), 1);
    assert_eq!(
        manifests.values().filter(|e| e["valid"] == false).count(),
        10
    );
    for (file, e) in manifests {
        let roots_file = ctx["roots_file_by_file"]
            .get(file)
            .and_then(Value::as_str)
            .unwrap_or_else(|| ctx["roots_file"].as_str().unwrap());
        let roots = roots_of(roots_file);
        let result = KeySet::verify(
            &fixture(file),
            &VerifyKeyManifestOptions {
                issuer,
                unsafe_root_keys: Some(&roots),
                now: Some(now),
            },
        );
        if e["valid"] == true {
            let set = result.unwrap_or_else(|err| panic!("{file}: {}", err.code()));
            assert_eq!(
                set.manifest().keys().len(),
                usize::try_from(e["keys"].as_u64().unwrap()).unwrap(),
                "{file}"
            );
        } else {
            let code = result.map_or_else(|err| err.code(), |_| "ok");
            assert_eq!(code, e["code"].as_str().unwrap(), "{file}");
        }
    }
}
