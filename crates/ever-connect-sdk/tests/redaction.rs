//! No secret in `Debug`, `Display` or errors: the instance token, the client assertion, a client
//! secret, the private key, and the claims of a refused document.
#![cfg(feature = "client")]
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

mod support;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ever_connect_sdk::client::{ClientOptions, Error, EverPlatformClient};
use ever_connect_sdk::entitlement::{VerifyEntitlementOptions, verify_entitlement};
use ever_connect_sdk::keys::Ed25519Signer;
use ever_connect_sdk::keyset::KeySet;
use ever_connect_sdk::manifest::{RootKey, VerifyKeyManifestOptions};
use serde_json::{Value, json};
use support::{Reply, Server};

const INSTANCE: &str = "01JNE7V9J03J6XQ2WN8H0Z88R5";
const TOKEN: &str = "evit_secret-token-value-0004";
const SEED: [u8; 32] = [11; 32];

#[tokio::test]
async fn a_problem_that_echoes_secrets_keeps_none_of_them() {
    let assertion: Arc<Mutex<String>> = Arc::default();
    let seen = Arc::clone(&assertion);
    let server = Server::start(move |r| {
        if r.path == "/v1/instances/token" {
            let body: Value = serde_json::from_slice(&r.body).unwrap();
            *seen.lock().unwrap() = body["client_assertion"].as_str().unwrap().to_owned();
            return Reply::json(
                200,
                &json!({"access_token": TOKEN, "token_type": "Bearer", "expires_in": 3600}),
            );
        }
        let a = seen.lock().unwrap().clone();
        Reply::json(
            422,
            &json!({
                "code": "validation_failed",
                "detail": format!("validation_failed: {TOKEN} {a}"),
                "errors": [
                    {"path": "/client_assertion", "code": "pattern", "message": a},
                    {"path": "/client_secret", "code": "pattern", "message": "cs_live_0123456789"},
                    {"path": "/version", "code": "pattern", "message": format!("bad {TOKEN}")}
                ]
            }),
        )
    });
    let mut o = ClientOptions::new(&server.url, "works", "1.0.0");
    o.signer = Some(Arc::new(Ed25519Signer::from_seed(&SEED)));
    o.registry_instance_id = Some(Arc::new(|| Some(INSTANCE.to_owned())));
    o.root_keys_file = None;
    let client = EverPlatformClient::new(o.clone()).unwrap();
    let error = client
        .heartbeat(&json!({"version": "1.0.0"}))
        .await
        .unwrap_err();
    let Error::Problem(problem) = &error else {
        panic!("{error}")
    };
    assert_eq!(
        problem
            .errors
            .iter()
            .map(|e| e.path.as_str())
            .collect::<Vec<_>>(),
        ["/version"]
    );
    let text = format!("{error} {error:?} {client:?} {o:?}");
    let a = assertion.lock().unwrap().clone();
    assert!(!a.is_empty());
    assert!(!text.contains(TOKEN));
    assert!(!text.contains(&a));
    assert!(!text.contains("cs_live_0123456789"));
    assert!(text.contains("[redacted]"));
    let seed_hex: String = SEED.iter().map(|b| format!("{b:02x}")).collect();
    assert!(!text.contains(&seed_hex));
}

#[test]
fn a_refused_document_names_the_code_never_a_claim_value() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/fixtures");
    let read = |p: &str| -> Value {
        serde_json::from_slice(&std::fs::read(dir.join(p)).unwrap()).unwrap()
    };
    let ctx = read("entitlement/context.json");
    let roots: Vec<RootKey> = read("keys/roots.json")["keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(RootKey::from_jwk)
        .collect();
    let set = KeySet::verify(
        &read("keys/manifest.valid.json"),
        &VerifyKeyManifestOptions {
            root_keys: Some(&roots),
            issuer: ctx["expected_issuer"].as_str(),
            now: ctx["now"].as_i64(),
        },
    )
    .unwrap();
    for file in [
        "wrong-instance",
        "wrong-subject",
        "extra-claim",
        "stale-seq",
        "wrong-issuer",
    ] {
        let jws = std::fs::read_to_string(dir.join(format!("entitlement/invalid/{file}.jws")))
            .unwrap()
            .trim()
            .to_owned();
        let error = verify_entitlement(
            &jws,
            &VerifyEntitlementOptions {
                key_set: &set,
                expected_issuer: ctx["expected_issuer"].as_str().unwrap(),
                expected_instance_id: ctx["expected_instance_id"].as_str().unwrap(),
                expected_subject: ctx["expected_subject"].as_str().unwrap(),
                cached: Some(ever_connect_sdk::entitlement::CachedEntitlement {
                    seq: 3,
                    iat: ctx["cached"]["iat"].as_i64().unwrap(),
                }),
                now: ctx["now"].as_i64(),
            },
        )
        .unwrap_err();
        let text = format!("{error} {error:?}");
        assert!(!text.contains(&jws));
        assert!(!text.contains("01JNE7V9J0"));
        assert!(!text.contains("acme"));
        assert!(!text.contains("api.example.com"));
    }
}
