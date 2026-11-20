//! A tenant link's members (row 38) against a recording local server: one page, every page
//! (bounded, stopped on a repeated cursor or an answer that is not a page), the problem of a
//! deployment that sends no membership events, and the operation as products registered it
//! before the SDK shipped it.
#![cfg(feature = "client")]
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

mod support;

use std::sync::Arc;

use ever_connect_sdk::client::generated::{HeaderRule, OPERATIONS, OperationAuth};
use ever_connect_sdk::client::{ClientOptions, Error, EverPlatformClient, Pager};
use ever_connect_sdk::keys::Ed25519Signer;
use serde_json::{Value, json};
use support::{Recorded, Reply, Server};

const INSTANCE: &str = "01JNE7V9J03J6XQ2WN8H0Z88R5";
const LINK: &str = "01JHGF4PAY0P5JJ7J2A56VSRZM";
const TOKEN: &str = "evit_secret-token-value-0005";

fn path() -> String {
    format!("/v1/instances/me/tenant-links/{LINK}/memberships")
}

fn member(subject: &str) -> Value {
    json!({"identity_issuer": "https://auth.ever.test", "identity_subject": subject, "role": "member"})
}

fn page(items: &[Value], next: Option<&str>) -> Reply {
    Reply::json(
        200,
        &json!({"tenant_link_id": LINK, "items": items, "next_cursor": next}),
    )
}

/// The cursor a request carries (`""` for the first page).
fn cursor_of(r: &Recorded) -> String {
    r.path
        .split_once('?')
        .map(|(_, q)| q)
        .unwrap_or_default()
        .split('&')
        .find_map(|kv| kv.strip_prefix("cursor="))
        .unwrap_or_default()
        .to_owned()
}

/// A platform that issues tokens and answers the member list with `answer`.
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

fn member_calls(server: &Server) -> Vec<Recorded> {
    server
        .calls()
        .into_iter()
        .filter(|c| c.path != "/v1/instances/token")
        .collect()
}

#[tokio::test]
async fn one_page_carries_the_instance_token_the_cursor_and_the_limit() {
    let server = platform(|_| page(&[member("s-2")], None));
    let answer = client(&server)
        .link_memberships(LINK, Some("c1"), Some(50))
        .await
        .unwrap();
    assert_eq!(
        answer,
        json!({"tenant_link_id": LINK, "items": [member("s-2")], "next_cursor": null})
    );
    let calls = member_calls(&server);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].method, "GET");
    assert_eq!(calls[0].path, format!("{}?cursor=c1&limit=50", path()));
    assert_eq!(
        calls[0].headers.get("authorization").map(String::as_str),
        Some(format!("Bearer {TOKEN}").as_str())
    );
}

#[tokio::test]
async fn every_page_is_read_in_order_one_hundred_a_page() {
    let server = platform(|r| match cursor_of(r).as_str() {
        "" => page(&[member("s-1"), member("s-2")], Some("c1")),
        "c1" => page(&[member("s-3")], Some("c2")),
        _ => page(&[], None),
    });
    let all = client(&server)
        .all_link_memberships(LINK, None)
        .await
        .unwrap();
    assert_eq!(all, vec![member("s-1"), member("s-2"), member("s-3")]);
    let paths: Vec<String> = member_calls(&server).into_iter().map(|c| c.path).collect();
    assert_eq!(
        paths,
        vec![
            format!("{}?limit=100", path()),
            format!("{}?cursor=c1&limit=100", path()),
            format!("{}?cursor=c2&limit=100", path()),
        ]
    );
}

#[tokio::test]
async fn a_cursor_handed_out_before_stops_the_read() {
    let server = platform(|r| match cursor_of(r).as_str() {
        "" => page(&[member("s-1")], Some("c1")),
        _ => page(&[member("s-2")], Some("c1")),
    });
    let error = client(&server)
        .all_link_memberships(LINK, None)
        .await
        .unwrap_err();
    assert_eq!(
        error,
        Error::Paging {
            code: "cursor_repeated",
            pages: 2
        }
    );
    assert_eq!(error.code(), "cursor_repeated");
    assert_eq!(member_calls(&server).len(), 2);
}

#[tokio::test]
async fn the_page_bound_stops_an_endless_list() {
    let server = platform(|r| {
        let n = cursor_of(r)
            .trim_start_matches('c')
            .parse::<u32>()
            .unwrap_or(0)
            + 1;
        page(&[member(&format!("s-{n}"))], Some(format!("c{n}").as_str()))
    });
    let error = client(&server)
        .all_link_memberships(LINK, Some(3))
        .await
        .unwrap_err();
    assert_eq!(
        error,
        Error::Paging {
            code: "too_many_pages",
            pages: 3
        }
    );
    assert_eq!(member_calls(&server).len(), 3);
}

#[tokio::test]
async fn an_answer_that_is_not_a_page_stops_the_read() {
    for body in [
        json!({"next_cursor": null}),
        json!({"items": [], "next_cursor": 7}),
        json!([]),
    ] {
        let server = platform(move |_| Reply::json(200, &body));
        assert_eq!(
            client(&server)
                .all_link_memberships(LINK, None)
                .await
                .unwrap_err(),
            Error::Paging {
                code: "malformed_page",
                pages: 1
            }
        );
    }
}

#[tokio::test]
async fn module_disabled_is_a_problem() {
    let server = platform(|_| {
        Reply::json(
            404,
            &json!({"type": "https://api.ever.co/problems/module_disabled", "code": "module_disabled", "status": 404}),
        )
    });
    let Error::Problem(p) = client(&server)
        .all_link_memberships(LINK, None)
        .await
        .unwrap_err()
    else {
        panic!("a problem")
    };
    assert_eq!((p.status, p.code.as_str()), (404, "module_disabled"));
}

#[test]
fn the_pager_ends_on_an_empty_cursor_and_reads_nothing_with_no_pages() {
    let mut pager = Pager::new(5);
    pager.before_page().unwrap();
    let (items, next) = pager
        .accept(json!({"items": [1], "next_cursor": ""}))
        .unwrap();
    assert_eq!((items, next), (vec![json!(1)], None));
    assert_eq!(pager.pages(), 1);
    assert_eq!(
        Pager::new(0).before_page().unwrap_err(),
        Error::Paging {
            code: "too_many_pages",
            pages: 0
        }
    );
}

#[test]
fn the_operation_is_the_one_products_registered() {
    let op = OPERATIONS
        .iter()
        .find(|o| o.id == "instanceListLinkMemberships")
        .unwrap();
    assert_eq!(
        (op.method, op.path, op.path_params, op.query),
        (
            "GET",
            "/v1/instances/me/tenant-links/{link}/memberships",
            &["link"][..],
            &["cursor", "limit"][..]
        )
    );
    assert_eq!(op.auth, OperationAuth::Instance);
    assert_eq!(
        (op.idempotency_key, op.link_header),
        (HeaderRule::None, HeaderRule::None)
    );
    assert_eq!((op.body_schema, op.success, op.row), (None, &[200][..], 38));
}
