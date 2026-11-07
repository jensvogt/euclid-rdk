//! EES against a mock server: authentication, request bodies, response parsing, errors.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use euclid_rdk::ees::{DeliveryMode, ReceiveEventsRequest, SubscribeEventsRequest};
use euclid_rdk::{Eam, Ees, Error};
use serde_json::{json, Value};
use wiremock::matchers::{header, method};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

fn jwt() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{}}}"#, now + 3600));
    format!("{}.{payload}.sig", URL_SAFE_NO_PAD.encode(b"{}"))
}

async fn ees(server: &MockServer, with_access_key: bool) -> Ees {
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
        .ees()
}

type Seen = Arc<Mutex<Vec<(Value, String)>>>;

/// Mounts `action` answering `answer`, and records each request (body, authorization header).
async fn mount(server: &MockServer, action: &str, answer: Value) -> Seen {
    let seen: Seen = Arc::default();
    let record = seen.clone();
    Mock::given(method("POST"))
        .and(header("x-euclid-target", "ees"))
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
            ResponseTemplate::new(200).set_body_json(answer.clone())
        })
        .mount(server)
        .await;
    seen
}

fn body(seen: &Seen) -> Value {
    seen.lock().unwrap().last().expect("a request").0.clone()
}

fn subscription_json() -> Value {
    json!({
        "subscriber": "indexer", "eventType": "esm.object.created", "filter": { "bucket": "inbox" },
        "accountId": "000000000000", "mode": "durable", "created": "2026-11-01T10:00:00Z",
        "lastSeen": "2026-11-07T08:00:00Z"
    })
}

#[tokio::test]
async fn requests_are_sigv4_signed_with_an_access_key_and_bearer_without() {
    let server = MockServer::start().await;
    let seen = mount(&server, "list-subscriptions", json!({ "subscriptions": [] })).await;
    ees(&server, true).await.list_subscriptions("indexer").await.unwrap();
    let auth = seen.lock().unwrap()[0].1.clone();
    assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIATEST/"));
    assert!(auth.contains("/ees/aws4_request"));

    let server = MockServer::start().await;
    let seen = mount(&server, "list-subscriptions", json!({ "subscriptions": [] })).await;
    ees(&server, false).await.list_subscriptions("indexer").await.unwrap();
    assert!(seen.lock().unwrap()[0].1.starts_with("Bearer "));
}

#[tokio::test]
async fn subscribe_sends_durable_defaults_and_parses_subscriptions() {
    let server = MockServer::start().await;
    let ees = ees(&server, true).await;
    let seen = mount(
        &server,
        "subscribe-events",
        json!({ "subscriptions": [subscription_json()] }),
    )
    .await;

    let answer = ees.subscribe_events("indexer", &["esm.object.created"]).await.unwrap();
    assert_eq!(
        body(&seen),
        json!({ "name": "indexer", "eventTypes": ["esm.object.created"], "filter": {}, "mode": "durable" })
    );
    let subscription = &answer.subscriptions[0];
    assert_eq!(subscription.subscriber.as_deref(), Some("indexer"));
    assert_eq!(subscription.event_type.as_deref(), Some("esm.object.created"));
    assert_eq!(subscription.filter.get("bucket"), Some(&json!("inbox")));
    assert_eq!(subscription.mode, DeliveryMode::Durable);
    assert_eq!(subscription.last_seen.as_deref(), Some("2026-11-07T08:00:00Z"));

    let mut filter = serde_json::Map::new();
    filter.insert("bucket".into(), json!("inbox"));
    ees.subscribe_events_with(&SubscribeEventsRequest {
        name: "view".into(),
        event_types: vec!["esm.object.created".into(), "esm.object.deleted".into()],
        filter,
        mode: DeliveryMode::Live,
    })
    .await
    .unwrap();
    assert_eq!(
        body(&seen),
        json!({ "name": "view", "eventTypes": ["esm.object.created", "esm.object.deleted"],
                "filter": { "bucket": "inbox" }, "mode": "live" })
    );
}

#[tokio::test]
async fn unsubscribe_and_list() {
    let server = MockServer::start().await;
    let ees = ees(&server, true).await;
    let unsubscribe = mount(
        &server,
        "unsubscribe-events",
        json!({ "subscriber": "indexer", "removed": 2 }),
    )
    .await;
    let list = mount(
        &server,
        "list-subscriptions",
        json!({ "subscriptions": [subscription_json()], "waiting": 17 }),
    )
    .await;

    assert_eq!(ees.unsubscribe_events("indexer").await.unwrap().removed, 2);
    assert_eq!(body(&unsubscribe), json!({ "name": "indexer", "eventType": "" }));
    ees.unsubscribe_event_type("indexer", "esm.object.created")
        .await
        .unwrap();
    assert_eq!(
        body(&unsubscribe),
        json!({ "name": "indexer", "eventType": "esm.object.created" })
    );

    let listed = ees.list_subscriptions("indexer").await.unwrap();
    assert_eq!(body(&list), json!({ "name": "indexer" }));
    assert_eq!(listed.waiting, 17);
    assert_eq!(listed.subscriptions.len(), 1);
}

#[tokio::test]
async fn receive_and_acknowledge_events() {
    let server = MockServer::start().await;
    let ees = ees(&server, true).await;
    let receive = mount(
        &server,
        "receive-events",
        json!({ "events": [{ "eventId": "e-1", "eventType": "esm.object.created", "sourceModule": "esm",
                             "payload": { "key": "a.xml", "size": 12 }, "attempts": 2,
                             "created": "2026-11-07T08:00:00Z" }],
                "total": 1 }),
    )
    .await;
    let ack = mount(
        &server,
        "ack-events",
        json!({ "subscriber": "indexer", "acknowledged": 1 }),
    )
    .await;

    let received = ees.receive_events("indexer").await.unwrap();
    assert_eq!(
        body(&receive),
        json!({ "name": "indexer", "maxEvents": 10, "waitTime": 0, "visibilityTimeout": 300 })
    );
    assert_eq!(received.total, 1);
    let event = &received.events[0];
    assert_eq!(event.event_id.as_deref(), Some("e-1"));
    assert_eq!(event.source_module.as_deref(), Some("esm"));
    assert_eq!(event.payload.get("size"), Some(&json!(12)));
    assert_eq!(event.attempts, 2);

    ees.receive_events_with(&ReceiveEventsRequest {
        name: "indexer".into(),
        max_events: 50,
        wait_time: 20,
        visibility_timeout: 60,
    })
    .await
    .unwrap();
    assert_eq!(
        body(&receive),
        json!({ "name": "indexer", "maxEvents": 50, "waitTime": 20, "visibilityTimeout": 60 })
    );

    let acked = ees.ack_event("indexer", "e-1").await.unwrap();
    assert_eq!(body(&ack), json!({ "name": "indexer", "eventIds": ["e-1"] }));
    assert_eq!(acked.acknowledged, 1);
    ees.ack_events("indexer", &["e-1", "e-2"]).await.unwrap();
    assert_eq!(body(&ack), json!({ "name": "indexer", "eventIds": ["e-1", "e-2"] }));
}

#[tokio::test]
async fn service_errors_carry_status() {
    let server = MockServer::start().await;
    let ees = ees(&server, true).await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "subscribe-events"))
        .respond_with(ResponseTemplate::new(400).set_body_string(r#"{"message":"eventTypes is required"}"#))
        .mount(&server)
        .await;

    let err = ees.subscribe_events("indexer", &[]).await.unwrap_err();
    assert!(matches!(err, Error::Service { status: 400, .. }));
}
