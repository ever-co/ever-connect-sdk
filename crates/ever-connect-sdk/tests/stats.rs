//! The statistics checks and signer against the platform's fixtures, the shared signing vector
//! (the TypeScript signer gives the same headers), the canary and the answer classification.
#![cfg(feature = "stats")]
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, VerifyingKey};
use ever_connect_sdk::stats::{
    ErrorCode, MAX_REPORT_BYTES, STATS_HEADER_KEY, STATS_HEADER_KEY_ID, STATS_HEADER_SIGNATURE,
    StatsKey, StatsOutcome, StringKind, classify_answer, is_calendar_date, key_id, no_answer,
    reports_url, sign_report, sign_report_bytes, validate_report, validate_report_bytes,
    walk_strings,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const CANARY: &str = "Jane Doe <jane@example.com>";
const VECTOR_KEY: &str = "lxnswCzOKr-SXURHbwO3utNZKbsjn3XpqslZ3kuQw6M";
const VECTOR_KEY_ID: &str = "fIrSg8WJjiY";
const VECTOR_SIGNATURE: &str = "ed25519=VHq-yNMEasHuMwgKw7ZzTco7J-8ZjglKKuaPYi1aORjNEa_qcGh6tHWGfNUWn8gURIDKu87ymAT3b6_WEQLVCw";

fn stats_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/fixtures/stats")
}

fn raw(file: &str) -> Vec<u8> {
    std::fs::read(stats_dir().join(file)).unwrap()
}

fn golden(product: &str) -> Value {
    serde_json::from_slice(&raw(&format!("valid/{product}.json"))).unwrap()
}

/// A key from a public seed: it signs nothing anyone trusts.
fn test_key() -> StatsKey {
    let seed: [u8; 32] = Sha256::digest(b"ever-connect-sdk/stats/test-key").into();
    StatsKey::from_seed(&seed)
}

fn header<'a>(headers: &'a [(&'static str, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, v)| v.as_str())
}

fn verifies(public_key: &str, body: &[u8], signature: &str) -> bool {
    let key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(public_key)
        .unwrap()
        .try_into()
        .unwrap();
    let sig: [u8; 64] = URL_SAFE_NO_PAD
        .decode(signature.strip_prefix("ed25519=").unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    VerifyingKey::from_bytes(&key)
        .unwrap()
        .verify_strict(body, &Signature::from_bytes(&sig))
        .is_ok()
}

#[test]
fn every_fixture_gets_the_platforms_answer() {
    let expected: Value = serde_json::from_slice(&raw("expected.json")).unwrap();
    let fixtures = expected["fixtures"].as_object().unwrap();
    assert_eq!(fixtures.len(), 18);
    for (file, e) in fixtures {
        let verdict = validate_report_bytes(&raw(file));
        if e["status"] == 202 {
            assert!(verdict.is_ok(), "{file}: {verdict:?}");
            continue;
        }
        let refusal = verdict.expect_err(file);
        let first = &refusal.errors()[0];
        assert_eq!(
            (
                json!(refusal.status()),
                json!(refusal.code()),
                json!(first.path),
                json!(first.code.as_str())
            ),
            (
                e["status"].clone(),
                e["code"].clone(),
                e["path"].clone(),
                e["error"].clone()
            ),
            "{file}"
        );
    }
}

#[test]
fn the_shared_vector_signs_the_gauzy_golden_file_as_typescript_does() {
    let signed = sign_report_bytes(raw("valid/gauzy.json"), &test_key(), true).unwrap();
    assert_eq!(
        signed.headers,
        vec![
            ("content-type", "application/json".to_owned()),
            ("Ever-Stats-Key", VECTOR_KEY.to_owned()),
            ("Ever-Stats-Signature", VECTOR_SIGNATURE.to_owned()),
            ("Ever-Stats-Key-Id", VECTOR_KEY_ID.to_owned()),
        ]
    );
    assert_eq!(key_id(VECTOR_KEY).as_deref(), Some(VECTOR_KEY_ID));
    assert_eq!(key_id("short"), None);
    assert_eq!(
        (
            STATS_HEADER_KEY,
            STATS_HEADER_SIGNATURE,
            STATS_HEADER_KEY_ID
        ),
        (
            "Ever-Stats-Key",
            "Ever-Stats-Signature",
            "Ever-Stats-Key-Id"
        )
    );
}

#[test]
fn every_golden_is_signed_over_exactly_the_bytes_returned() {
    let key = test_key();
    for product in ["gauzy", "teams", "works", "rec", "traduora"] {
        let report = golden(product);
        let signed = sign_report(&report, &key, false).unwrap();
        assert_eq!(signed.body, serde_json::to_vec(&report).unwrap());
        assert_eq!(header(&signed.headers, STATS_HEADER_KEY_ID), None);
        let signature = header(&signed.headers, STATS_HEADER_SIGNATURE).unwrap();
        assert!(
            verifies(&key.public_key(), &signed.body, signature),
            "{product}"
        );
    }
}

fn set(report: &mut Value, path: &str, value: Value) {
    *report.pointer_mut(path).unwrap() = value;
}

#[test]
fn a_poisoned_report_yields_no_bytes_and_never_shows_the_canary() {
    let report = golden("gauzy");
    let positions: Vec<String> = walk_strings(&report)
        .into_iter()
        .filter(|(_, kind, _)| *kind == StringKind::Value)
        .map(|(path, _, _)| path)
        .collect();
    assert!(positions.contains(&"/country".to_owned()));
    for path in positions {
        let mut poisoned = report.clone();
        set(&mut poisoned, &path, json!(CANARY));
        let refusal = sign_report(&poisoned, &test_key(), true).expect_err(&path);
        assert_eq!(refusal.errors()[0].path, path);
        for text in [refusal.to_string(), format!("{refusal:?}")] {
            assert!(
                !text.contains("Jane") && !text.contains("jane@"),
                "{path}: {text}"
            );
        }
    }
}

#[test]
fn a_canary_key_is_named_exactly_in_errors_and_as_a_star_in_logs() {
    let cases = [
        (String::new(), format!("/{CANARY}")),
        (
            "/counts/integrations_in_use".to_owned(),
            format!("/counts/integrations_in_use/{CANARY}"),
        ),
        (
            "/aggregates/invoiced_minor".to_owned(),
            format!("/aggregates/invoiced_minor/{CANARY}"),
        ),
    ];
    for (parent, path) in cases {
        let mut report = golden("gauzy");
        report
            .pointer_mut(&parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(CANARY.to_owned(), json!(1));
        let refusal = validate_report(&report).unwrap_err();
        assert_eq!(refusal.errors().len(), 1);
        assert_eq!(refusal.errors()[0].path, path);
        assert_eq!(refusal.errors()[0].code, ErrorCode::UnknownField);
        for text in [refusal.to_string(), format!("{refusal:?}")] {
            assert!(!text.contains("Jane"), "{text}");
            assert!(text.contains(&path.replace(CANARY, "*")), "{text}");
        }
    }
}

#[test]
fn size_fractions_days_and_versions_are_refused_as_the_platform_does() {
    let mut big = golden("gauzy");
    big["padding"] = json!("x".repeat(MAX_REPORT_BYTES));
    let refusal = validate_report(&big).unwrap_err();
    assert_eq!(
        (refusal.status(), refusal.code()),
        (413, "validation_failed")
    );
    assert_eq!(refusal.errors()[0].path, "");
    assert_eq!(refusal.errors()[0].code, ErrorCode::TooLarge);

    let mut fraction = golden("gauzy");
    fraction["aggregates"]["invoices"] = json!(214.0);
    let refusal = validate_report(&fraction).unwrap_err();
    assert_eq!(
        (refusal.errors()[0].path.as_str(), refusal.errors()[0].code),
        ("/aggregates/invoices", ErrorCode::Type)
    );

    let mut feb = golden("gauzy");
    feb["sent_at"] = json!("2026-02-30");
    let refusal = validate_report(&feb).unwrap_err();
    assert_eq!(
        (refusal.errors()[0].path.as_str(), refusal.errors()[0].code),
        ("/sent_at", ErrorCode::Range)
    );
    let mut leap = golden("gauzy");
    leap["sent_at"] = json!("2028-02-29");
    assert!(validate_report(&leap).is_ok());

    let mut v2 = golden("gauzy");
    v2["schema"] = json!("ever.stats.v2");
    assert_eq!(
        validate_report(&v2).unwrap_err().errors()[0].code,
        ErrorCode::SchemaUnknown
    );

    let mut many = golden("gauzy");
    for i in 0..30 {
        many[format!("extra_{i:02}")] = json!(1);
    }
    let refusal = validate_report(&many).unwrap_err();
    assert_eq!(refusal.errors().len(), 20);
    assert!(refusal.errors().windows(2).all(|w| w[0].path <= w[1].path));
}

#[test]
fn strict_json_names_the_offence_where_it_stands() {
    let deep = format!("{}1{}", "[".repeat(18), "]".repeat(18));
    let cases: Vec<(&[u8], &str, ErrorCode)> = vec![
        (
            br#"{"aggregates": {"invoices": 214.0}}"#,
            "/aggregates/invoices",
            ErrorCode::Type,
        ),
        (br#"{"a": [1, 2E3]}"#, "/a/1", ErrorCode::Type),
        (br#"{"a": 99999999999999999999}"#, "/a", ErrorCode::Range),
        (
            br#"{"country": "ZZ", "country": "BG"}"#,
            "/country",
            ErrorCode::DuplicateKey,
        ),
        (
            br#"{"a": {"x/y": 1, "x/y": 2}}"#,
            "/a/x~1y",
            ErrorCode::DuplicateKey,
        ),
        (b"", "", ErrorCode::Type),
        (b"{\"a\":1,}", "", ErrorCode::Type),
        ("\u{feff}{}".as_bytes(), "", ErrorCode::Type),
        (br#""\ud800""#, "", ErrorCode::Type),
        // Four hex digits exactly, never a sign.
        (br#""\u+041""#, "", ErrorCode::Type),
        (br#""\ud83d\u+e00""#, "", ErrorCode::Type),
        (&[0xff, b'{', b'}'], "", ErrorCode::Type),
        (
            deep.as_bytes(),
            "/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0",
            ErrorCode::Type,
        ),
    ];
    for (body, path, code) in cases {
        let refusal = validate_report_bytes(body).unwrap_err();
        assert_eq!(
            (refusal.errors()[0].path.as_str(), refusal.errors()[0].code),
            (path, code),
            "{}",
            String::from_utf8_lossy(body)
        );
    }
}

#[test]
fn walk_strings_lists_keys_and_values() {
    let found = walk_strings(&json!({"a": "x", "b/c": [{"d": "y"}, 3], "e": true}));
    let flat: Vec<(&str, StringKind, &str)> = found
        .iter()
        .map(|(p, k, v)| (p.as_str(), *k, v.as_str()))
        .collect();
    assert_eq!(
        flat,
        vec![
            ("/a", StringKind::Key, "a"),
            ("/a", StringKind::Value, "x"),
            ("/b~1c", StringKind::Key, "b/c"),
            ("/b~1c/0/d", StringKind::Key, "d"),
            ("/b~1c/0/d", StringKind::Value, "y"),
            ("/e", StringKind::Key, "e"),
        ]
    );
}

#[test]
fn keys_show_their_public_half_only() {
    let key = StatsKey::generate().unwrap();
    let seed = key.seed();
    assert_eq!(StatsKey::from_seed(&seed).public_key(), key.public_key());
    let debug = format!("{key:?}");
    assert!(debug.contains(&key.public_key()));
    assert!(!debug.contains(&URL_SAFE_NO_PAD.encode(seed)));
    assert!(!debug.contains(&format!("{seed:?}")));
    assert_eq!(key.key_id(), key_id(&key.public_key()).unwrap());
}

#[test]
fn answers_are_classified() {
    assert_eq!(
        classify_answer(202, br#"{"accepted":true}"#, None, 0),
        StatsOutcome::Accepted { superseded: false }
    );
    assert_eq!(
        classify_answer(202, br#"{"accepted":true,"superseded":true}"#, None, 0),
        StatsOutcome::Accepted { superseded: true }
    );
    assert_eq!(
        classify_answer(429, br#"{"code":"rate_limited"}"#, Some("50000"), 0),
        StatsOutcome::Retry {
            status: Some(429),
            code: Some("rate_limited".into()),
            after_s: 50_000
        }
    );
    assert_eq!(
        classify_answer(503, b"", None, 9),
        StatsOutcome::Retry {
            status: Some(503),
            code: None,
            after_s: 86_400
        }
    );
    assert_eq!(
        no_answer(2),
        StatsOutcome::Retry {
            status: None,
            code: None,
            after_s: 43_200
        }
    );
    assert_eq!(
        classify_answer(409, br#"{"code":"key_mismatch"}"#, None, 0),
        StatsOutcome::ResetIdentity
    );
    assert_eq!(
        classify_answer(
            422,
            br#"{"code":"schema_violation","errors":[{"path":"/country","code":"pattern","message":"m"}]}"#,
            None,
            0
        ),
        StatsOutcome::Dropped {
            status: 422,
            code: Some("schema_violation".into()),
            errors: vec![("/country".into(), "pattern".into())]
        }
    );
    for (status, code) in [
        (400, "signature_invalid"),
        (400, "validation_failed"),
        (413, "validation_failed"),
        (415, "unsupported_media_type"),
    ] {
        let body = format!(r#"{{"code":"{code}"}}"#);
        assert!(matches!(
            classify_answer(status, body.as_bytes(), None, 0),
            StatsOutcome::Dropped { status: s, code: Some(c), .. } if s == status && c == code
        ));
    }
}

#[test]
fn the_report_url_is_an_http_origin_without_credentials() {
    assert_eq!(
        reports_url("http://127.0.0.1:8080").unwrap(),
        "http://127.0.0.1:8080/v1/stats/reports"
    );
    assert_eq!(
        reports_url("https://api.ever.co/").unwrap(),
        "https://api.ever.co/v1/stats/reports"
    );
    for bad in [
        "ftp://x.test",
        "https://u:p@x.test",
        "https://x.test/?a=1",
        "https://x.test/#f",
        "https://",
    ] {
        assert!(reports_url(bad).is_err(), "{bad}");
    }
    assert!(is_calendar_date("2024-02-29") && !is_calendar_date("2023-02-29"));
}
