//! The behaviour items of the client against a recording local server: the egress guard, no
//! redirects, the token lifecycle (one retry on 401, none on `credential_revoked`), the headers,
//! refusals before any I/O, 304, problem mapping, timeouts and body limits.
#![cfg(feature = "client")]
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ever_connect_sdk::client::{
    Answer, CallInput, ClientOptions, Error, EverPlatformClient, SDK_VERSION,
};
use ever_connect_sdk::keys::Ed25519Signer;
use ever_connect_sdk::stats::SignedStatsReport;
use serde_json::json;
use support::{Recorded, Reply, Server};

const INSTANCE: &str = "01JNE7V9J03J6XQ2WN8H0Z88R5";
const LINK: &str = "01JHGF4PAY0P5JJ7J2A56VSRZM";
const TOKEN: &str = "evit_secret-token-value-0003";

fn options(url: &str) -> ClientOptions {
    let mut o = ClientOptions::new(url, "gauzy", "1.2.3");
    o.signer = Some(Arc::new(Ed25519Signer::from_seed(&[11; 32])));
    o.registry_instance_id = Some(Arc::new(|| Some(INSTANCE.to_owned())));
    o.root_keys_file = None;
    o
}

/// A platform that issues tokens and answers everything else with `answer`.
fn platform(answer: impl Fn(&Recorded) -> Reply + Send + Sync + 'static) -> Server {
    Server::start(move |r| {
        if r.path == "/v1/instances/token" {
            Reply::json(
                200,
                &json!({"access_token": TOKEN, "token_type": "Bearer", "expires_in": 3600}),
            )
        } else {
            answer(r)
        }
    })
}

fn paths(server: &Server) -> Vec<String> {
    server.calls().into_iter().map(|c| c.path).collect()
}

#[tokio::test]
async fn http_is_refused_unless_the_host_is_local() {
    let error = EverPlatformClient::new(ClientOptions::new("http://api.ever.test", "gauzy", "1"))
        .unwrap_err();
    assert_eq!(
        error,
        Error::EgressRefused {
            code: "insecure_base_url"
        }
    );
    for ok in [
        "http://localhost:8080",
        "http://127.0.0.1",
        "http://10.1.2.3",
        "http://172.20.0.1",
        "http://192.168.1.1",
        "http://mock.localhost",
        "http://[::1]:9",
        "https://api.ever.test",
    ] {
        assert!(
            EverPlatformClient::new(ClientOptions::new(ok, "gauzy", "1")).is_ok(),
            "{ok}"
        );
    }
    assert!(
        EverPlatformClient::new(ClientOptions::new("http://172.32.0.1", "gauzy", "1")).is_err()
    );
    assert!(
        EverPlatformClient::new(ClientOptions::new("https://api.ever.test", "nobody", "1"))
            .is_err()
    );
}

#[tokio::test]
async fn a_path_parameter_cannot_leave_the_operation_path() {
    let server = platform(|_| Reply::empty(204));
    let client = EverPlatformClient::new(options(&server.url)).unwrap();
    client
        .call(
            "instanceUnlinkTenantLink",
            CallInput {
                path: vec![("link", "../../../v1/other")],
                ..CallInput::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        paths(&server).last().unwrap(),
        "/v1/instances/me/tenant-links/..%2F..%2F..%2Fv1%2Fother"
    );
}

#[tokio::test]
async fn a_redirect_is_not_followed() {
    let server = platform(|_| Reply::empty(302).header("location", "https://elsewhere.test/"));
    let client = EverPlatformClient::new(options(&server.url)).unwrap();
    assert_eq!(
        client.legal().await.unwrap_err(),
        Error::EgressRefused { code: "redirect" }
    );
    assert_eq!(
        client.integrations().await.unwrap_err(),
        Error::EgressRefused { code: "redirect" }
    );
    // The legal texts once; the token, then the integrations once: no second request anywhere.
    assert_eq!(
        paths(&server),
        [
            "/v1/connect/legal",
            "/v1/instances/token",
            "/v1/instances/me/integrations"
        ]
    );
}

#[tokio::test]
async fn the_token_is_lazy_and_bound_to_the_registry_id() {
    let server = platform(|_| Reply::json(200, &json!({"instance": {}})));
    let client = EverPlatformClient::new(options(&server.url)).unwrap();
    assert!(server.calls().is_empty());
    client.integrations().await.unwrap();
    client.integrations().await.unwrap();
    let calls = server.calls();
    assert_eq!(
        paths(&server),
        [
            "/v1/instances/token",
            "/v1/instances/me/integrations",
            "/v1/instances/me/integrations"
        ]
    );
    let body: serde_json::Value = serde_json::from_slice(&calls[0].body).unwrap();
    assert_eq!(body["grant_type"], "client_credentials");
    let assertion = body["client_assertion"].as_str().unwrap();
    let claims: serde_json::Value = serde_json::from_slice(
        &base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            assertion.split('.').nth(1).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(claims["iss"], INSTANCE);
    assert_eq!(claims["aud"], format!("{}/v1/instances/token", server.url));
    assert_eq!(calls[1].headers["authorization"], format!("Bearer {TOKEN}"));
}

#[tokio::test]
async fn without_a_registry_id_nothing_is_sent() {
    let server = platform(|_| Reply::json(200, &json!({})));
    let mut o = options(&server.url);
    o.registry_instance_id = Some(Arc::new(|| None));
    let client = EverPlatformClient::new(o).unwrap();
    assert_eq!(
        client.integrations().await.unwrap_err(),
        Error::NotConnected
    );
    assert!(server.calls().is_empty());
}

#[tokio::test]
async fn a_401_gets_a_new_token_and_exactly_one_retry() {
    let n = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&n);
    let server = platform(move |_| {
        if seen.fetch_add(1, Ordering::SeqCst) < 2 {
            Reply::json(401, &json!({"code": "unauthenticated"}))
        } else {
            Reply::json(200, &json!({}))
        }
    });
    let client = EverPlatformClient::new(options(&server.url)).unwrap();
    let Error::Problem(p) = client.integrations().await.unwrap_err() else {
        panic!()
    };
    assert_eq!((p.status, p.code.as_str()), (401, "unauthenticated"));
    assert_eq!(
        paths(&server),
        [
            "/v1/instances/token",
            "/v1/instances/me/integrations",
            "/v1/instances/token",
            "/v1/instances/me/integrations"
        ]
    );
}

#[tokio::test]
async fn credential_revoked_is_never_retried() {
    let server = platform(|_| {
        Reply::json(
            401,
            &json!({"code": "credential_revoked", "detail": "credential_revoked: disconnected"}),
        )
    });
    let client = EverPlatformClient::new(options(&server.url)).unwrap();
    let Error::Problem(p) = client.integrations().await.unwrap_err() else {
        panic!()
    };
    assert_eq!(p.code, "credential_revoked");
    assert_eq!(server.calls().len(), 2);
}

#[tokio::test]
async fn headers_conditional_reads_and_link_ids() {
    let server = platform(|r| {
        if r.path.ends_with("/entitlement") {
            Reply::empty(304)
        } else {
            Reply::json(202, &json!({}))
        }
    });
    let client = EverPlatformClient::new(options(&server.url)).unwrap();
    let body = json!({"items": [{"meter_key": "instances.connected", "quantity": 1, "period": "2026-11"}]});
    client.report_usage(LINK, &body, "idem-0001").await.unwrap();
    let usage = server.calls().last().unwrap().clone();
    assert_eq!(
        usage.headers["user-agent"],
        format!("ever-connect-sdk/{SDK_VERSION} (gauzy/1.2.3)")
    );
    assert_eq!(
        usage.headers["accept"],
        "application/json, application/problem+json"
    );
    assert_eq!(usage.headers["x-request-id"].len(), 36);
    assert_eq!(usage.headers["content-type"], "application/json");
    assert_eq!(usage.headers["idempotency-key"], "idem-0001");
    assert_eq!(usage.headers["ever-link-id"], LINK);
    assert!(!usage.headers.contains_key("cookie"));
    assert_eq!(
        client.entitlement(Some(7)).await.unwrap(),
        Answer::NotModified
    );
    assert_eq!(
        server.calls().last().unwrap().headers["if-none-match"],
        "\"7\""
    );
}

#[tokio::test]
async fn refusals_happen_before_any_io() {
    let server = platform(|_| Reply::json(200, &json!({})));
    let client = EverPlatformClient::new(options(&server.url)).unwrap();
    let err = client
        .call("instanceDisconnect", CallInput::default())
        .await
        .unwrap_err();
    assert_eq!(
        err,
        Error::Validation {
            code: "idempotency_key_required",
            errors: Vec::new()
        }
    );
    let err = client
        .heartbeat(&json!({"version": "1.0.0", "surprise": true}))
        .await
        .unwrap_err();
    assert_eq!(
        err,
        Error::Validation {
            code: "invalid_body",
            errors: vec![("/surprise".into(), "unknown_field")]
        }
    );
    let err = client
        .call(
            "instanceGetIntegrations",
            CallInput {
                query: vec![("secret", "x".into())],
                ..CallInput::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), "invalid_parameter");
    let err = client
        .lookup(
            "not-a-link",
            &json!({"salt_version": 1, "hashes": ["0".repeat(64)]}),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), "invalid_parameter");
    let big = SignedStatsReport {
        body: vec![b' '; 16_385],
        headers: Vec::new(),
    };
    assert_eq!(
        client.send_stats_report(&big).await.unwrap_err().code(),
        "body_too_large"
    );
    let op = json!({"op": "upsert", "kind": "app", "external_id": "x", "external_version": 1, "data": {"name": "x".repeat(4096)}});
    let huge = json!({"ops": vec![op; 500]});
    assert!(
        client
            .call(
                "instanceMirrorApps",
                CallInput {
                    body: Some(&huge),
                    ..CallInput::default()
                }
            )
            .await
            .is_err()
    );
    assert!(server.calls().is_empty());
}

#[tokio::test]
async fn problems_are_mapped() {
    let server = platform(|r| {
        if r.path == "/v1/connect/legal" {
            Reply::json(429, &json!({"code": "rate_limited", "detail": "rate_limited: slow down", "instance": "req-1", "retry_after_s": 30})).header("retry-after", "12")
        } else {
            Reply {
                status: 502,
                headers: Vec::new(),
                body: b"<html>bad gateway</html>".to_vec(),
                delay_ms: 0,
            }
        }
    });
    let client = EverPlatformClient::new(options(&server.url)).unwrap();
    let Error::Problem(p) = client.legal().await.unwrap_err() else {
        panic!()
    };
    assert_eq!(
        (
            p.status,
            p.code.as_str(),
            p.detail.as_deref(),
            p.instance.as_deref(),
            p.retry_after_s
        ),
        (
            429,
            "rate_limited",
            Some("rate_limited: slow down"),
            Some("req-1"),
            Some(12)
        )
    );
    let Error::Problem(p) = client.lookup_salt().await.unwrap_err() else {
        panic!()
    };
    assert_eq!((p.status, p.code.as_str()), (502, "unknown"));
}

#[tokio::test]
async fn a_read_past_its_deadline_is_a_timeout() {
    let server = platform(|_| Reply::json(200, &json!({})).delayed(1500));
    let mut o = options(&server.url);
    o.read_timeout = Duration::from_millis(200);
    let client = EverPlatformClient::new(o).unwrap();
    assert_eq!(
        client.legal().await.unwrap_err(),
        Error::Timeout { timeout_ms: 200 }
    );
}

#[tokio::test]
async fn overrides_are_honoured_for_a_local_base_url_only() {
    let mut o = ClientOptions::new("https://api.ever.test", "gauzy", "1");
    o.issuer = Some("https://elsewhere.test".into());
    o.root_keys = vec![ever_connect_sdk::manifest::RootKey {
        kid: "test-root-9".into(),
        x: "A".repeat(43),
        iss: None,
    }];
    o.root_keys_file = None;
    let client = EverPlatformClient::new(o).unwrap();
    assert_eq!(client.issuer(), "https://api.ever.test");
    assert!(!client.root_keys().iter().any(|k| k.kid == "test-root-9"));
    let mut o = ClientOptions::new("http://127.0.0.1:4010", "gauzy", "1");
    o.issuer = Some("https://mock-platform.test".into());
    o.root_keys = vec![ever_connect_sdk::manifest::RootKey {
        kid: "test-root-9".into(),
        x: "A".repeat(43),
        iss: None,
    }];
    o.root_keys_file = None;
    let client = EverPlatformClient::new(o).unwrap();
    assert_eq!(client.issuer(), "https://mock-platform.test");
    assert!(client.root_keys().iter().any(|k| k.kid == "test-root-9"));
}
