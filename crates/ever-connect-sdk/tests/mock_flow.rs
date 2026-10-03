//! The sample flow of an installation through the Rust client against the mock platform
//! (`EVER_MOCK_PLATFORM_URL`; CI starts `ever-mock-platform` with the issuer
//! `https://mock-platform.test` and the real clock): manifest -> redeem -> token -> entitlement
//! verified -> integrations -> heartbeat -> events and ack -> tenant link -> lookup vectors ->
//! key rotation of the platform and a reissued document -> connect-key rotation -> disconnect ->
//! `401 credential_revoked`. The mock's call log must equal the documented rows. Without the
//! variable the test says so and passes (local runs without a mock).
#![cfg(feature = "client")]
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ever_connect_sdk::assertion::sign_key_rotation;
use ever_connect_sdk::client::{Answer, ClientOptions, Error, EverPlatformClient};
use ever_connect_sdk::entitlement::{CachedEntitlement, EntitlementErrorCode};
use ever_connect_sdk::keys::{Ed25519Signer, InstanceSigner, public_jwk};
use ever_connect_sdk::keyset::KeySetUpdate;
use ever_connect_sdk::lookup::check_test_vectors;
use serde_json::{Value, json};

const ISSUER: &str = "https://mock-platform.test";

async fn admin(url: &str, path: &str, body: Value) -> Value {
    let res = reqwest::Client::new()
        .post(format!("{url}/__mock/{path}"))
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success(), "{path}: {}", res.status());
    serde_json::from_slice(&res.bytes().await.unwrap()).unwrap()
}

#[tokio::test]
async fn the_sample_flow_through_the_rust_client() {
    let Ok(url) = std::env::var("EVER_MOCK_PLATFORM_URL") else {
        eprintln!(
            "mock_flow: EVER_MOCK_PLATFORM_URL is not set; start ever-mock-platform to run the sample flow"
        );
        return;
    };
    let url = url.trim_end_matches('/').to_owned();
    admin(&url, "reset", json!({})).await;

    let registry: Arc<Mutex<Option<String>>> = Arc::default();
    let roots =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/fixtures/keys/roots.json");
    let make = |signer: Arc<dyn InstanceSigner>| {
        let mut o = ClientOptions::new(&url, "gauzy", "96.2.1");
        o.issuer = Some(ISSUER.into());
        o.root_keys_file = Some(roots.clone());
        o.signer = Some(signer);
        let id = Arc::clone(&registry);
        o.registry_instance_id = Some(Arc::new(move || id.lock().unwrap().clone()));
        EverPlatformClient::new(o).unwrap()
    };
    let (signer, _seed) = Ed25519Signer::generate().unwrap();
    let signer: Arc<dyn InstanceSigner> = Arc::new(signer);
    let mut client = make(Arc::clone(&signer));

    // Row 1: the manifest, verified against the TEST root.
    let KeySetUpdate::Replaced(mut keys) = client.refresh_keys(None).await.unwrap() else {
        panic!()
    };

    // Row 3: redeem.
    let redeemed = client
        .redeem(
            &json!({
                "code": "EVC-TEST-0000-0001", "product": "gauzy", "version": "96.2.1", "install_source": "self-hosted",
                "kind": "self_hosted", "public_jwk": public_jwk(signer.as_ref()),
                "tenant": {"product_tenant_id": "tenant-1", "product_org_id": "org-1"}
            }),
            "redeem-rust-0001",
        )
        .await
        .unwrap();
    *registry.lock().unwrap() = Some(redeemed["instance_id"].as_str().unwrap().to_owned());

    // Rows 4 and 8: the token comes lazily; the document verifies.
    let Answer::Json(doc) = client.entitlement(None).await.unwrap() else {
        panic!()
    };
    let first = client
        .verify_entitlement(doc["document"].as_str().unwrap(), &keys, None, None)
        .unwrap();
    assert_eq!(first.status.as_str(), "valid");
    assert_eq!(
        client.entitlement(Some(first.seq)).await.unwrap(),
        Answer::NotModified
    );

    // Rows 9, 6, 7, 5, 13.
    let states = client.integrations().await.unwrap();
    assert_eq!(states["instance"]["stats_link"]["state"], "available");
    client
        .heartbeat(&json!({"version": "96.2.1", "serves_products": ["gauzy"]}))
        .await
        .unwrap();
    let page = client.events(None, Some(0)).await.unwrap();
    assert!(
        page["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["type"] == "ever.registry.instance.connected")
    );
    client
        .ack_events(page["last_id"].as_str().unwrap())
        .await
        .unwrap();
    let link = client
        .create_tenant_link(&json!({"link_code": "EVL-TEST-0000-0002", "product": "gauzy", "product_tenant_id": "tenant-2"}), "link-rust-0002")
        .await
        .unwrap();
    assert_eq!(link["id"].as_str().unwrap().len(), 26);
    assert_eq!(
        client.lookup_salt().await.unwrap()["normalization_version"],
        1
    );
    check_test_vectors(&client.lookup_test_vectors().await.unwrap()).unwrap();

    // The platform's entitlement key rotates: the previous key still verifies the old document;
    // the reissued one has a higher seq; the old one is stale against it.
    admin(&url, "keys/rotate", json!({})).await;
    let KeySetUpdate::Replaced(next) = client.refresh_keys(Some(&keys)).await.unwrap() else {
        panic!()
    };
    keys = next;
    assert_eq!(
        client
            .verify_entitlement(&first.jws, &keys, None, None)
            .unwrap()
            .kid,
        "test-entitlement-1"
    );
    let id = registry.lock().unwrap().clone().unwrap();
    admin(&url, "entitlement/reissue", json!({"instance_id": id})).await;
    let Answer::Json(doc) = client.entitlement(Some(first.seq)).await.unwrap() else {
        panic!()
    };
    let cached = CachedEntitlement {
        seq: first.seq,
        iat: first.claims["iat"].as_i64().unwrap(),
    };
    let second = client
        .verify_entitlement(doc["document"].as_str().unwrap(), &keys, None, Some(cached))
        .unwrap();
    assert_eq!(second.seq, first.seq + 1);
    assert_eq!(second.kid, "test-entitlement-2");
    let newer = CachedEntitlement {
        seq: second.seq,
        iat: second.claims["iat"].as_i64().unwrap(),
    };
    let Err(Error::Entitlement(stale)) =
        client.verify_entitlement(&first.jws, &keys, None, Some(newer))
    else {
        panic!()
    };
    assert_eq!(stale.code, EntitlementErrorCode::EntitlementStale);

    // Row 16: the connect key rotates; the next token is signed with the new key.
    let (next_key, _seed) = Ed25519Signer::generate().unwrap();
    let next_key: Arc<dyn InstanceSigner> = Arc::new(next_key);
    let rotation =
        sign_key_rotation(signer.as_ref(), next_key.as_ref(), Some(&id), ISSUER, None).unwrap();
    client
        .rotate_key(&rotation, &format!("rotate-{}", next_key.kid()))
        .await
        .unwrap();
    client = make(next_key);
    admin(&url, "clock", json!({"advance": 120})).await; // one heartbeat a minute at most
    client
        .heartbeat(&json!({"version": "96.2.1"}))
        .await
        .unwrap();

    // Row 16: disconnect; the next call (its token request) is 401 credential_revoked.
    client.disconnect("disconnect-rust-0001").await.unwrap();
    let Err(Error::Problem(revoked)) = client.instance().await else {
        panic!()
    };
    assert_eq!(
        (revoked.status, revoked.code.as_str()),
        (401, "credential_revoked")
    );

    // The call log: exactly these rows, each on a documented endpoint of its row.
    let log: Vec<Value> = serde_json::from_slice(
        &reqwest::get(format!("{url}/__mock/requests"))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    let rows: Vec<i64> = log.iter().map(|e| e["row"].as_i64().unwrap()).collect();
    assert_eq!(
        rows,
        [1, 3, 4, 8, 8, 9, 6, 7, 7, 5, 13, 13, 1, 8, 16, 4, 6, 16, 4]
    );
    let table = ever_connect_sdk::contracts::outbound_calls();
    for entry in &log {
        let row = table["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["row"] == entry["row"])
            .unwrap();
        let documented = row["endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["method"] == entry["method"] && e["path"] == entry["path_template"]);
        assert!(documented, "{entry}");
        assert!(
            entry["user_agent"]
                .as_str()
                .unwrap()
                .ends_with("(gauzy/96.2.1)")
        );
        assert_ne!(entry["status"], 422, "{entry}");
    }
}
