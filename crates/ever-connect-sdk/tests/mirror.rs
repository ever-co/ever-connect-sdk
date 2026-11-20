//! The apps mirror (row 15) and the install status report (row 28) against a recording local
//! server: the tenant link goes out as `Ever-Link-Id` (optional on the mirror, Ever Platform's
//! any_link gate; required on the install status), and the mirror's open vocabularies (statuses,
//! environments, owners, outcomes) pass through as strings, as the platform's contract leaves them.
#![cfg(feature = "client")]
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

mod support;

use std::sync::Arc;

use ever_connect_sdk::client::generated::{HeaderRule, OPERATIONS};
use ever_connect_sdk::client::{CallInput, ClientOptions, EverPlatformClient};
use ever_connect_sdk::contracts::openapi::components::{MirrorAppData, MirrorDeploymentData};
use ever_connect_sdk::keys::Ed25519Signer;
use serde_json::{Value, json};
use support::{Recorded, Reply, Server};

const INSTANCE: &str = "01JNE7V9J03J6XQ2WN8H0Z88R5";
const LINK: &str = "01JHGF4PAY0P5JJ7J2A56VSRZM";
const INSTALL: &str = "01JMQCK0INSTA11000000000A1";
const TOKEN: &str = "evit_secret-token-value-0007";
const MIRROR: &str = "/v1/instances/me/mirror/apps";

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

fn client(server: &Server) -> EverPlatformClient {
    let mut o = ClientOptions::new(&server.url, "works", "1.2.3");
    o.signer = Some(Arc::new(Ed25519Signer::from_seed(&[11; 32])));
    o.registry_instance_id = Some(Arc::new(|| Some(INSTANCE.to_owned())));
    o.root_keys_file = None;
    EverPlatformClient::new(o).unwrap()
}

fn calls(server: &Server) -> Vec<Recorded> {
    server
        .calls()
        .into_iter()
        .filter(|c| c.path != "/v1/instances/token")
        .collect()
}

fn app(extra: &Value) -> Value {
    let mut data = json!({
        "product_tenant_id": "tenant-1",
        "kind": "app",
        "name": "Cal",
        "slug": "cal",
        "base_kind": "none",
        "status": "live"
    });
    for (k, v) in extra.as_object().unwrap() {
        data[k] = v.clone();
    }
    data
}

fn batch(ops: &[Value]) -> Value {
    json!({ "ops": ops })
}

fn upsert(kind: &str, data: Value) -> Value {
    let mut op = json!({
        "op": "upsert",
        "kind": kind,
        "external_id": format!("{kind}-1"),
        "external_version": 1,
        "occurred_at": "2026-11-20T10:00:00Z",
        "data": data
    });
    if kind == "deployment" {
        op["app_external_id"] = json!("app-1");
    }
    op
}

#[tokio::test]
async fn the_mirror_sends_the_link_it_is_given_and_none_without_one() {
    let server = platform(|r| {
        if r.method == "GET" {
            Reply::json(200, &json!({"items": [], "next_cursor": null}))
        } else {
            Reply::json(200, &json!({"results": []}))
        }
    });
    let client = client(&server);
    let body = batch(&[upsert("app", app(&json!({})))]);
    for link_id in [Some(LINK), None] {
        client
            .call(
                "instanceMirrorApps",
                CallInput {
                    body: Some(&body),
                    link_id,
                    ..CallInput::default()
                },
            )
            .await
            .unwrap();
    }
    client
        .call(
            "instanceListMirroredApps",
            CallInput {
                query: vec![("link", LINK.to_owned())],
                link_id: Some(LINK),
                ..CallInput::default()
            },
        )
        .await
        .unwrap();
    let seen: Vec<(String, String, Option<String>)> = calls(&server)
        .into_iter()
        .map(|c| (c.method, c.path, c.headers.get("ever-link-id").cloned()))
        .collect();
    assert_eq!(
        seen,
        vec![
            ("POST".into(), MIRROR.into(), Some(LINK.into())),
            ("POST".into(), MIRROR.into(), None),
            (
                "GET".into(),
                format!("{MIRROR}?link={LINK}"),
                Some(LINK.into())
            ),
        ]
    );
}

#[tokio::test]
async fn the_install_status_report_needs_its_link() {
    let server =
        platform(|_| Reply::json(200, &json!({"install_id": INSTALL, "state": "installing"})));
    let client = client(&server);
    let body = json!({"state": "installing"});
    let refused = client
        .call(
            "instanceReportInstallStatus",
            CallInput {
                path: vec![("install", INSTALL)],
                body: Some(&body),
                ..CallInput::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(refused.code(), "link_required");
    assert!(calls(&server).is_empty());
    client
        .call(
            "instanceReportInstallStatus",
            CallInput {
                path: vec![("install", INSTALL)],
                body: Some(&body),
                link_id: Some(LINK),
                ..CallInput::default()
            },
        )
        .await
        .unwrap();
    let sent = calls(&server);
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].headers.get("ever-link-id").map(String::as_str),
        Some(LINK)
    );
}

#[test]
fn the_table_declares_the_link_header() {
    let rule = |id: &str| {
        OPERATIONS
            .iter()
            .find(|o| o.id == id)
            .map(|o| o.link_header)
            .unwrap()
    };
    assert_eq!(rule("instanceMirrorApps"), HeaderRule::Optional);
    assert_eq!(rule("instanceListMirroredApps"), HeaderRule::Optional);
    assert_eq!(rule("instanceReportInstallStatus"), HeaderRule::Required);
}

#[tokio::test]
async fn statuses_the_sdk_does_not_list_are_sent_and_outcomes_pass_through() {
    let results = json!({"results": [
        {"external_id": "app-1", "outcome": "deferred", "app_id": null, "code": null},
        {"external_id": "deployment-1", "outcome": "rejected", "app_id": null, "code": "quota_exceeded"}
    ]});
    let answer = results.clone();
    let server = platform(move |_| Reply::json(200, &answer));
    let client = client(&server);
    let body = batch(&[
        upsert(
            "app",
            app(
                &json!({"status": "active", "kind": "work", "base_kind": "fork", "work_kind": "portfolio"}),
            ),
        ),
        upsert(
            "deployment",
            json!({"target": "vercel", "managed_by": "partner", "environment": "staging", "status": "INITIALIZING"}),
        ),
    ]);
    let out = client
        .call(
            "instanceMirrorApps",
            CallInput {
                body: Some(&body),
                link_id: Some(LINK),
                ..CallInput::default()
            },
        )
        .await
        .unwrap()
        .into_json();
    assert_eq!(out, results);
    let sent = calls(&server);
    assert_eq!(sent.len(), 1);
    assert_eq!(
        serde_json::from_slice::<Value>(&sent[0].body).unwrap(),
        body
    );
}

#[test]
fn the_typed_mirror_data_keeps_any_status_as_a_string() {
    let data: MirrorAppData =
        serde_json::from_value(app(&json!({"status": "active", "base_kind": "fork"}))).unwrap();
    assert_eq!(
        (data.status.as_str(), data.base_kind.as_str()),
        ("active", "fork")
    );
    let deployment: MirrorDeploymentData = serde_json::from_value(json!({
        "target": "vercel", "managed_by": "partner", "environment": "staging", "status": "INITIALIZING"
    }))
    .unwrap();
    assert_eq!(
        (
            deployment.status.as_str(),
            deployment.environment.as_str(),
            deployment.managed_by.as_str()
        ),
        ("INITIALIZING", "staging", "partner")
    );
}
