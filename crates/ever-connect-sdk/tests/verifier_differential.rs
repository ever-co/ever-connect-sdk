//! The seeded mutation corpus (the generator of `tools/fixtures/mutations.mjs`, written again
//! here): every case flips one bit of a valid document. None may verify, and every answer must
//! equal the committed one, which the TypeScript verifier reproduces too.
#![cfg(feature = "entitlement")]
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ever_connect_sdk::entitlement::{VerifyEntitlementOptions, verify_entitlement};
use ever_connect_sdk::keyset::KeySet;
use ever_connect_sdk::manifest::{RootKey, VerifyKeyManifestOptions};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

fn path(p: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/fixtures")
        .join(p)
}
fn fixture(p: &str) -> Value {
    serde_json::from_slice(&std::fs::read(path(p)).unwrap()).unwrap()
}

/// mulberry32, as `tools/fixtures/mutations.mjs` writes it.
struct Mulberry32(u32);

impl Mulberry32 {
    fn next(&mut self) -> u32 {
        self.0 = self.0.wrapping_add(0x6d2b_79f5);
        let mut t = self.0;
        t = (t ^ (t >> 15)).wrapping_mul(t | 1);
        t = (t.wrapping_add((t ^ (t >> 7)).wrapping_mul(t | 61))) ^ t;
        t ^ (t >> 14)
    }
}

fn corpus(bases: &[String], count: usize, seed: u32) -> Vec<(usize, String)> {
    let mut rng = Mulberry32(seed);
    (0..count)
        .map(|i| {
            let base = i % bases.len();
            let mut parts: Vec<String> = bases[base].split('.').map(str::to_owned).collect();
            let part = (rng.next() % 3) as usize;
            let mut bytes = URL_SAFE_NO_PAD.decode(&parts[part]).unwrap();
            let bit = rng.next() as usize % (bytes.len() * 8);
            bytes[bit >> 3] ^= 1 << (bit & 7);
            parts[part] = URL_SAFE_NO_PAD.encode(&bytes);
            (base, parts.join("."))
        })
        .collect()
}

#[test]
fn no_mutated_document_verifies_and_every_answer_is_the_committed_one() {
    let committed = fixture("entitlement/mutations.json");
    let bases: Vec<String> = committed["bases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| {
            std::fs::read_to_string(path(&format!("entitlement/{}", b.as_str().unwrap())))
                .unwrap()
                .trim()
                .to_owned()
        })
        .collect();
    let count = usize::try_from(committed["count"].as_u64().unwrap()).unwrap();
    let seed = u32::try_from(committed["seed"].as_u64().unwrap()).unwrap();
    let cases = corpus(&bases, count, seed);
    assert_eq!(cases.len(), 10_000);
    let mut h = Sha256::new();
    for (_, jws) in &cases {
        h.update(jws.as_bytes());
        h.update(b"\n");
    }
    let digest: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        digest,
        committed["corpus_sha256"].as_str().unwrap(),
        "the same corpus as the TypeScript generator"
    );

    let ctx = fixture("entitlement/context.json");
    let keys_ctx = fixture("keys/context.json");
    let roots: Vec<RootKey> = fixture("keys/roots.json")["keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(RootKey::from_jwk)
        .collect();
    let set = KeySet::verify(
        &fixture("keys/manifest.valid.json"),
        &VerifyKeyManifestOptions {
            root_keys: Some(&roots),
            issuer: keys_ctx["issuer"].as_str(),
            now: keys_ctx["now"].as_i64(),
        },
    )
    .unwrap();
    let subjects = [
        ctx["expected_subject"].as_str().unwrap(),
        ctx["expected_subject_by_file"]["valid/link.jws"]
            .as_str()
            .unwrap(),
    ];
    let letters = committed["letters"].as_object().unwrap();
    let answers: Vec<char> = committed["answers"].as_str().unwrap().chars().collect();
    for (i, (base, jws)) in cases.iter().enumerate() {
        let result = verify_entitlement(
            jws,
            &VerifyEntitlementOptions {
                key_set: &set,
                expected_issuer: ctx["expected_issuer"].as_str().unwrap(),
                expected_instance_id: ctx["expected_instance_id"].as_str().unwrap(),
                expected_subject: subjects[*base],
                cached: None,
                now: ctx["now"].as_i64(),
            },
        );
        let error = result.err().unwrap_or_else(|| panic!("case {i} verified"));
        let letter = letters[error.code.as_str()]
            .as_str()
            .unwrap()
            .chars()
            .next()
            .unwrap();
        assert_eq!(letter, answers[i], "case {i}: {}", error.code.as_str());
    }
}
