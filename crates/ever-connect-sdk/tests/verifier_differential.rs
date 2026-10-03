//! The seeded mutation corpus (the generator of `tools/fixtures/mutations.mjs`, written again
//! here): every case flips one bit of a valid document. None may verify, and every answer must
//! equal the committed one, which the TypeScript verifier reproduces too. Then the structured
//! corpus (`tools/fixtures/structured.mjs`): documents and manifests built on purpose, each answer
//! equal to the reference verifier's.
#![cfg(feature = "entitlement")]
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ever_connect_sdk::entitlement::{
    CachedEntitlement, VerifyEntitlementOptions, verify_entitlement,
};
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
            unsafe_root_keys: Some(&roots),
            issuer: keys_ctx["issuer"].as_str().unwrap(),
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

/// The answer of the SDK for one structured case (`entitlement/structured.json`), in the corpus's
/// notation: `manifest:<code>`, `<code>` (`+refresh`), `ok:<status>`.
fn structured_answer(defaults: &Value, case: &Value, fixture_roots: &[RootKey]) -> String {
    let get = |k: &str| case.get(k).unwrap_or(&defaults[k]);
    let body = case
        .get("manifest")
        .cloned()
        .unwrap_or_else(|| fixture(defaults["manifest"].as_str().unwrap()));
    let listed: Vec<RootKey>;
    let unsafe_root_keys = match get("roots") {
        Value::Array(list) => {
            listed = list.iter().filter_map(RootKey::from_jwk).collect();
            assert_eq!(
                listed.len(),
                list.len(),
                "{}: every listed root reads",
                case["name"]
            );
            Some(listed.as_slice())
        }
        Value::String(s) if s == "fixture" => Some(fixture_roots),
        Value::String(s) if s == "pinned" => None,
        other => panic!("roots {other}"),
    };
    let set = match KeySet::verify(
        &body,
        &VerifyKeyManifestOptions {
            issuer: get("manifest_issuer").as_str().unwrap(),
            unsafe_root_keys,
            now: get("manifest_now").as_i64(),
        },
    ) {
        Ok(set) => set,
        Err(e) => return format!("manifest:{}", e.code()),
    };
    let cached = get("cached").as_object().map(|c| CachedEntitlement {
        seq: c["seq"].as_i64().unwrap(),
        iat: c["iat"].as_i64().unwrap(),
    });
    match verify_entitlement(
        case["jws"].as_str().unwrap(),
        &VerifyEntitlementOptions {
            key_set: &set,
            expected_issuer: get("expected_issuer").as_str().unwrap(),
            expected_instance_id: get("expected_instance_id").as_str().unwrap(),
            expected_subject: get("expected_subject").as_str().unwrap(),
            cached,
            now: get("now").as_i64(),
        },
    ) {
        Ok(v) => format!("ok:{}", v.status.as_str()),
        Err(e) => format!(
            "{}{}",
            e.code.as_str(),
            if e.refresh_suggested { "+refresh" } else { "" }
        ),
    }
}

#[test]
fn every_structured_case_answers_as_the_reference_verifier() {
    let corpus = fixture("entitlement/structured.json");
    let cases = corpus["cases"].as_array().unwrap();
    assert!(cases.len() >= 118);
    let roots: Vec<RootKey> = fixture("keys/roots.json")["keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(RootKey::from_jwk)
        .collect();
    let mut differences = Vec::new();
    for case in cases {
        let answer = structured_answer(&corpus["defaults"], case, &roots);
        if answer != case["expect"].as_str().unwrap() {
            differences.push(format!(
                "{}: {answer} (reference {})",
                case["name"], case["expect"]
            ));
        }
    }
    assert!(differences.is_empty(), "{differences:#?}");
}
