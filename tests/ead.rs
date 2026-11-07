//! EAD against a mock server: authentication, request bodies, response parsing and errors.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use euclid_rdk::ead::{AuditEvent, CountEventsRequest, ListEventsRequest};
use euclid_rdk::{Ead, Eam, Error};
use serde_json::{json, Value};
use wiremock::matchers::{header, method};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

type Seen = Arc<std::sync::Mutex<Vec<(Value, String)>>>;

fn jwt() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{}}}"#, now + 3600));
    format!("{}.{payload}.sig", URL_SAFE_NO_PAD.encode(b"{}"))
}

async fn ead(server: &MockServer, with_access_key: bool) -> Ead {
    let mut login = json!({
        "token": jwt(),
        "metadata": { "region": "eu-central-1", "accountId": "000000000000", "user": "jvo" }
    });
    if with_access_key {
        login["accessKeyId"] = json!("AKIATEST");
        login["secretAccessKey"] = json!("secret");
    }
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(login))
        .mount(server)
        .await;
    Eam::for_server(server.uri())
        .credentials("jvo", "pw")
        .no_cache()
        .no_ca_cert()
        .login()
        .await
        .unwrap()
        .ead()
}

/// Mounts `action` answering `answer`, recording each request's body and authorization header.
async fn mount(server: &MockServer, action: &str, status: u16, answer: Value) -> Seen {
    let seen: Seen = Arc::default();
    let record = seen.clone();
    Mock::given(method("POST"))
        .and(header("x-euclid-target", "ead"))
        .and(header("x-euclid-action", action))
        .respond_with(move |req: &Request| {
            let auth = req
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            record
                .lock()
                .unwrap()
                .push((serde_json::from_slice(&req.body).unwrap(), auth));
            ResponseTemplate::new(status).set_body_json(answer.clone())
        })
        .mount(server)
        .await;
    seen
}

fn last(seen: &Seen) -> (Value, String) {
    seen.lock().unwrap().last().expect("a request").clone()
}

#[tokio::test]
async fn requests_are_sigv4_signed_with_an_access_key() {
    let server = MockServer::start().await;
    let ead = ead(&server, true).await;
    let seen = mount(&server, "count-events", 200, json!({ "count": 0 })).await;
    ead.count_events(&CountEventsRequest::default()).await.unwrap();
    assert!(last(&seen).1.starts_with("AWS4-HMAC-SHA256 "));
}

#[tokio::test]
async fn requests_carry_the_bearer_token_without_an_access_key() {
    let server = MockServer::start().await;
    let ead = ead(&server, false).await;
    let seen = mount(&server, "count-events", 200, json!({ "count": 0 })).await;
    ead.count_events(&CountEventsRequest::default()).await.unwrap();
    assert!(last(&seen).1.starts_with("Bearer "));
}

#[tokio::test]
async fn list_events_sends_only_the_filters_that_are_set() {
    let server = MockServer::start().await;
    let ead = ead(&server, false).await;
    let seen = mount(
        &server,
        "list-events",
        200,
        json!({ "events": [], "total": 0, "totalExact": true }),
    )
    .await;

    ead.list_events(&ListEventsRequest::default()).await.unwrap();
    assert_eq!(last(&seen).0, json!({ "pageSize": 10, "pageIndex": 0 }));

    ead.list_events(&ListEventsRequest {
        user_id: Some("jvo".into()),
        module: Some("esm".into()),
        command: Some("create-bucket".into()),
        page_size: 50,
        page_index: 2,
    })
    .await
    .unwrap();
    assert_eq!(
        last(&seen).0,
        json!({ "userId": "jvo", "module": "esm", "command": "create-bucket", "pageSize": 50, "pageIndex": 2 })
    );
}

#[tokio::test]
async fn list_events_parses_events_and_a_capped_total() {
    let server = MockServer::start().await;
    let ead = ead(&server, false).await;
    mount(
        &server,
        "list-events",
        200,
        json!({
            "events": [{
                "accountId": "000000000000", "namespace": "prod", "userId": "jvo", "module": "esm",
                "command": "create-bucket", "parameters": "{\"name\":\"b1\"}", "status": 200,
                "created": "2026-11-07T10:00:00Z"
            }],
            "total": 100000,
            "totalExact": false
        }),
    )
    .await;

    let listing = ead.list_events(&ListEventsRequest::default()).await.unwrap();
    assert_eq!(listing.total, 100000);
    assert!(!listing.total_exact);
    assert_eq!(
        listing.events,
        vec![AuditEvent {
            account_id: Some("000000000000".into()),
            namespace: Some("prod".into()),
            user_id: Some("jvo".into()),
            module: Some("esm".into()),
            command: Some("create-bucket".into()),
            parameters: Some("{\"name\":\"b1\"}".into()),
            status: 200,
            created: Some("2026-11-07T10:00:00Z".into()),
        }]
    );
}

#[tokio::test]
async fn a_missing_total_exact_reads_as_exact() {
    let server = MockServer::start().await;
    let ead = ead(&server, false).await;
    mount(&server, "list-events", 200, json!({ "events": [], "total": 3 })).await;
    let listing = ead.list_events(&ListEventsRequest::default()).await.unwrap();
    assert!(listing.total_exact);
    assert_eq!(listing.total, 3);
}

#[tokio::test]
async fn count_events_sends_filters_and_reads_the_count() {
    let server = MockServer::start().await;
    let ead = ead(&server, false).await;
    let seen = mount(&server, "count-events", 200, json!({ "count": 1234567 })).await;
    let count = ead
        .count_events(&CountEventsRequest {
            module: Some("eqs".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(count, 1234567);
    assert_eq!(last(&seen).0, json!({ "module": "eqs" }));
}

#[tokio::test]
async fn purge_events_sends_the_window_and_reads_what_was_removed() {
    let server = MockServer::start().await;
    let ead = ead(&server, false).await;
    let seen = mount(&server, "purge-events", 200, json!({ "removed": 42 })).await;
    assert_eq!(ead.purge_events(30).await.unwrap(), 42);
    assert_eq!(last(&seen).0, json!({ "olderThanDays": 30 }));
}

#[tokio::test]
async fn a_refused_purge_is_a_service_error() {
    let server = MockServer::start().await;
    let ead = ead(&server, false).await;
    mount(
        &server,
        "purge-events",
        400,
        json!({ "message": "olderThanDays is required and must be positive" }),
    )
    .await;
    let err = ead.purge_events(0).await.unwrap_err();
    assert_eq!(err.status(), Some(400));
    assert!(matches!(err, Error::Service { .. }));
}
