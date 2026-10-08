//! The compact JWS helpers a product uses outside the client: `sign_compact_jws` (EdDSA over
//! Ed25519 only) and `claims_of_verified_jws` (the claims of a document already verified; it never
//! verifies). The TypeScript suite (`test/jws.test.ts`) holds the same rules.
#![cfg(all(feature = "entitlement", feature = "stats"))]
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::convert::Infallible;
use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, VerifyingKey};
use ever_connect_sdk::entitlement::{VerifyEntitlementOptions, verify_entitlement};
use ever_connect_sdk::jws::{
    JwsSignError, MAX_JWS_LENGTH, claims_of_verified_jws, sign_compact_jws,
};
use ever_connect_sdk::keyset::KeySet;
use ever_connect_sdk::manifest::{RootKey, VerifyKeyManifestOptions};
use ever_connect_sdk::stats::StatsKey;
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
fn part(jws: &str, i: usize) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(jws.split('.').nth(i).unwrap())
        .unwrap()
}

fn stats_key() -> StatsKey {
    StatsKey::from_seed(&[7; 32])
}

/// Whether `jws` verifies with `key` (strictly) over its signing input.
fn verifies(jws: &str, key: &StatsKey) -> bool {
    let raw: [u8; 32] = URL_SAFE_NO_PAD
        .decode(key.public_key())
        .unwrap()
        .try_into()
        .unwrap();
    let input = jws.rsplit_once('.').unwrap().0;
    let sig: [u8; 64] = part(jws, 2).try_into().unwrap();
    VerifyingKey::from_bytes(&raw)
        .unwrap()
        .verify_strict(input.as_bytes(), &Signature::from_bytes(&sig))
        .is_ok()
}

fn sign_with(key: &StatsKey, header: &Value, payload: &Value) -> Result<String, JwsSignError> {
    sign_compact_jws(header, payload, |bytes| {
        Ok::<_, Infallible>(key.sign(bytes))
    })
}

#[test]
fn signs_the_stats_link_statement_with_the_statistics_key() {
    let key = stats_key();
    let typ = ever_connect_sdk::contracts::constants()["stats_link_typ"].clone();
    let claims = json!({
        "stats_instance_id": "5f0c6f4e-2a4b-4c7e-9a51-3d2b1f0e9c11",
        "stats_public_jwk": {"kty": "OKP", "crv": "Ed25519", "x": key.public_key()},
        "sub": "01JNE7V9J03J6XQ2WN8H0Z88R5",
        "iat": 1_793_613_600,
    });
    let jws = sign_with(&key, &json!({"typ": typ}), &claims).unwrap();
    let header: Value = serde_json::from_slice(&part(&jws, 0)).unwrap();
    assert_eq!(
        header,
        json!({"alg": "EdDSA", "typ": "ever-stats-link+jwt"})
    );
    let payload: Value = serde_json::from_slice(&part(&jws, 1)).unwrap();
    assert_eq!(payload, claims);
    assert!(verifies(&jws, &key));
    assert!(!verifies(&jws, &StatsKey::from_seed(&[8; 32])));
}

#[test]
fn alg_is_always_eddsa_and_another_is_refused() {
    let key = stats_key();
    let jws = sign_with(
        &key,
        &json!({"typ": "JWT", "alg": "EdDSA", "kid": "k"}),
        &json!({}),
    )
    .unwrap();
    let header: Value = serde_json::from_slice(&part(&jws, 0)).unwrap();
    assert_eq!(header, json!({"alg": "EdDSA", "kid": "k", "typ": "JWT"}));
    for alg in [
        json!("none"),
        json!("HS256"),
        json!("RS256"),
        json!("eddsa"),
        json!(""),
        json!(null),
        json!(0),
    ] {
        assert_eq!(
            sign_with(&key, &json!({"alg": alg}), &json!({})),
            Err(JwsSignError::AlgNotEdDsa),
            "{alg}"
        );
    }
    assert_eq!(
        sign_with(&key, &json!({"crit": ["b64"], "b64": false}), &json!({})),
        Err(JwsSignError::CritNotSupported)
    );
}

#[test]
fn refuses_what_a_verifier_would_not_read() {
    let key = stats_key();
    for (h, p) in [
        (json!([]), json!({})),
        (json!({}), json!([])),
        (json!(null), json!({})),
        (json!({}), json!("claims")),
    ] {
        assert_eq!(sign_with(&key, &h, &p), Err(JwsSignError::NotAnObject));
    }
    let big = json!({"blob": "x".repeat(MAX_JWS_LENGTH)});
    assert_eq!(
        sign_with(&key, &json!({}), &big),
        Err(JwsSignError::NotDecodable)
    );
    let mut deep = json!({});
    for _ in 0..130 {
        deep = json!({"d": deep});
    }
    assert_eq!(
        sign_with(&key, &json!({}), &deep),
        Err(JwsSignError::NotDecodable)
    );
}

#[test]
fn a_failing_signer_fails_the_call() {
    let error =
        sign_compact_jws(&json!({}), &json!({}), |_| Err("key store unavailable")).unwrap_err();
    assert_eq!(error, JwsSignError::Sign("key store unavailable".into()));
    assert_eq!(error.code(), "sign_failed");
    assert_eq!(error.to_string(), "compact JWS not signed: sign_failed");
}

fn verified_instance_document() -> (String, Value) {
    let keys_ctx = fixture("keys/context.json");
    let roots: Vec<RootKey> = fixture("keys/roots.json")["keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(RootKey::from_jwk)
        .collect();
    let key_set = KeySet::verify(
        &fixture("keys/manifest.valid.json"),
        &VerifyKeyManifestOptions {
            unsafe_root_keys: Some(&roots),
            issuer: keys_ctx["issuer"].as_str().unwrap(),
            now: keys_ctx["now"].as_i64(),
        },
    )
    .unwrap();
    let ctx = fixture("entitlement/context.json");
    let verified = verify_entitlement(
        &text("entitlement/valid/instance.jws"),
        &VerifyEntitlementOptions {
            key_set: &key_set,
            expected_issuer: ctx["expected_issuer"].as_str().unwrap(),
            expected_instance_id: ctx["expected_instance_id"].as_str().unwrap(),
            expected_subject: ctx["expected_subject"].as_str().unwrap(),
            cached: None,
            now: ctx["now"].as_i64(),
        },
    )
    .unwrap();
    (verified.jws, verified.claims)
}

#[test]
fn claims_of_a_verified_document() {
    let (jws, claims) = verified_instance_document();
    let read = Value::Object(claims_of_verified_jws(&jws).unwrap());
    assert_eq!(read, claims);
    assert_eq!(read, fixture("entitlement/valid/instance.claims.json"));
}

#[test]
fn claims_of_verified_jws_never_verifies() {
    // This is why it is only for documents the verifier accepted before: it checks nothing.
    let (jws, claims) = verified_instance_document();
    let (input, _) = jws.rsplit_once('.').unwrap();
    let forged = format!("{input}.{}", URL_SAFE_NO_PAD.encode([1_u8; 64]));
    assert_eq!(
        claims_of_verified_jws(&forged).map(Value::Object),
        Some(claims)
    );
    assert!(claims_of_verified_jws(&text("entitlement/invalid/alg-none.jws")).is_some());
}

#[test]
fn claims_of_verified_jws_reads_by_the_decoding_rule_only() {
    let jws = text("entitlement/valid/instance.jws");
    let parts: Vec<&str> = jws.split('.').collect();
    let (h, p, s) = (parts[0], parts[1], parts[2]);
    let b64 = |v: &str| URL_SAFE_NO_PAD.encode(v);
    let big = b64(&json!({"blob": "x".repeat(MAX_JWS_LENGTH)}).to_string());
    for bad in [
        String::new(),
        format!("{h}.{p}"),
        format!("{h}.{p}.{s}.{s}"),
        format!("{h}.{p}=.{s}"),
        format!("{h}.{}+.{s}", &p[..p.len() - 1]),
        format!("{h}.{}.{s}", b64("[1,2]")),
        format!("{h}.{}.{s}", b64("not json")),
        format!("{}.{p}.{s}", b64("[]")),
        format!("{h}.{big}.{s}"),
    ] {
        assert!(claims_of_verified_jws(&bad).is_none(), "{bad:.40}");
    }
}
