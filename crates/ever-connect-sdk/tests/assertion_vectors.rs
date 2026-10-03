//! The client assertion against the platform's vectors (`contracts/fixtures/connect/vectors`,
//! vendored byte for byte): the key id, the assertion byte for byte with the vector key, clock and
//! jti, and the refusals before signing.
#![cfg(feature = "client")]
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ever_connect_sdk::assertion::{
    AssertionError, ClientAssertionOptions, jwk_thumbprint, sign_client_assertion,
    sign_key_rotation, subject_hash,
};
use ever_connect_sdk::keys::{Ed25519Signer, InstanceSigner, key_id_from_x, public_jwk};
use serde_json::Value;

fn vector(name: &str) -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/fixtures/connect/vectors")
        .join(name);
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn claims(token: &str) -> Value {
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(token.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn the_key_id_is_the_platforms() {
    let v = vector("assertion-valid.json");
    let c = &v["context"];
    for key in ["current_key", "previous_key"] {
        assert_eq!(
            key_id_from_x(c[key]["x"].as_str().unwrap()).unwrap(),
            c[key]["kid"].as_str().unwrap()
        );
    }
    let current = Ed25519Signer::from_seed(&[11; 32]);
    assert_eq!(current.kid(), c["current_key"]["kid"].as_str().unwrap());
    assert_eq!(public_jwk(&current)["x"], c["current_key"]["x"]);
}

#[test]
fn with_the_vector_key_clock_and_jti_the_assertion_is_the_vector_byte_for_byte() {
    let v = vector("assertion-valid.json");
    let c = &v["context"];
    let expected = v["assertion"].as_str().unwrap();
    let jti = claims(expected)["jti"].as_str().unwrap().to_owned();
    let token = sign_client_assertion(&ClientAssertionOptions {
        signer: &Ed25519Signer::from_seed(&[11; 32]),
        registry_instance_id: c["instance_id"].as_str(),
        audience: c["audience"].as_str().unwrap(),
        ttl_s: None,
        now: c["now"].as_i64(),
        jti: Some(&jti),
    })
    .unwrap();
    assert_eq!(token, expected);
}

#[test]
fn a_built_assertion_has_the_contract_claims_and_a_random_jti() {
    let v = vector("assertion-valid.json");
    let c = &v["context"];
    let signer = Ed25519Signer::from_seed(&[12; 32]);
    let token = sign_client_assertion(&ClientAssertionOptions {
        signer: &signer,
        registry_instance_id: c["instance_id"].as_str(),
        audience: c["audience"].as_str().unwrap(),
        ttl_s: Some(3600),
        now: Some(10),
        jti: None,
    })
    .unwrap();
    let header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(token.split('.').next().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        header,
        serde_json::json!({"alg": "EdDSA", "kid": signer.kid(), "typ": "JWT"})
    );
    let cl = claims(&token);
    assert_eq!(cl["iss"], c["instance_id"]);
    assert_eq!(cl["sub"], c["instance_id"]);
    assert_eq!(cl["exp"], 310);
    assert_eq!(cl["jti"].as_str().unwrap().len(), 22);
}

#[test]
fn no_registry_id_or_a_uuid_is_refused_before_signing() {
    let signer = Ed25519Signer::from_seed(&[11; 32]);
    let uuid_vector = vector("assertion-uuid-issuer.json");
    let uuid = claims(uuid_vector["assertion"].as_str().unwrap())["iss"]
        .as_str()
        .unwrap()
        .to_owned();
    for (id, expected) in [
        (None, "no_registry_instance_id"),
        (Some(""), "no_registry_instance_id"),
        (Some(uuid.as_str()), "not_a_registry_id"),
    ] {
        let error = sign_client_assertion(&ClientAssertionOptions {
            signer: &signer,
            registry_instance_id: id,
            audience: "a",
            ttl_s: None,
            now: None,
            jti: None,
        })
        .unwrap_err();
        assert_eq!(error.code(), expected);
    }
    assert_eq!(
        sign_key_rotation(&signer, &signer, Some(&uuid), "https://api.ever.test", None)
            .unwrap_err(),
        AssertionError::NotARegistryId
    );
}

#[test]
fn a_rotation_binds_the_new_key_in_both_proofs() {
    let current = Ed25519Signer::from_seed(&[11; 32]);
    let next = Ed25519Signer::from_seed(&[13; 32]);
    let body = sign_key_rotation(
        &current,
        &next,
        Some("01JNE7V9J03J6XQ2WN8H0Z88R5"),
        "https://api.ever.test/",
        Some(100),
    )
    .unwrap();
    let x = body["public_jwk"]["x"].as_str().unwrap();
    for proof in ["current_key_proof", "new_key_proof"] {
        let cl = claims(body[proof].as_str().unwrap());
        assert_eq!(cl["aud"], "https://api.ever.test/v1/instances/me/keys");
        assert_eq!(cl["cnf"]["jkt"], jwk_thumbprint(x));
    }
    assert_ne!(
        claims(body["current_key_proof"].as_str().unwrap())["jti"],
        claims(body["new_key_proof"].as_str().unwrap())["jti"]
    );
}

#[test]
fn the_subject_hash_is_the_platforms() {
    assert_eq!(
        subject_hash("https://auth.ever.co", "3300"),
        "9934771655649d0033a8169970eae18571059176b896eee2c56db921c866c471"
    );
}

#[test]
fn a_signer_shows_its_key_id_only() {
    let signer = Ed25519Signer::from_seed(&[11; 32]);
    assert_eq!(
        format!("{signer:?}"),
        format!("Ed25519Signer({})", signer.kid())
    );
}
