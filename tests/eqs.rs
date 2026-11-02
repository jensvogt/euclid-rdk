//! EQS against a mock server: authentication, request bodies, response parsing, polling.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use euclid_rdk::eqs::{CreateQueueRequest, ListQueuesRequest, SendMessageBatchRequest, SendMessageRequest, Variant};
use euclid_rdk::{Eam, Eqs, Error};
use serde_json::{json, Value};
use wiremock::matchers::{body_json, header, method};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const QUEUE: &str = "ern:eqs:eu-central-1:000000000000:development:queue:orders";

fn jwt() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{}}}"#, now + 3600));
    format!("{}.{payload}.sig", URL_SAFE_NO_PAD.encode(b"{}"))
}

async fn eqs(server: &MockServer, with_access_key: bool) -> Eqs {
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
        .eqs()
}

/// Mounts `action` answering `answer`, and records each request body it receives.
async fn mount(server: &MockServer, action: &str, answer: Value) -> Arc<std::sync::Mutex<Vec<Value>>> {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let record = seen.clone();
    Mock::given(method("POST"))
        .and(header("x-euclid-target", "eqs"))
        .and(header("x-euclid-action", action))
        .respond_with(move |req: &Request| {
            record.lock().unwrap().push(serde_json::from_slice(&req.body).unwrap());
            ResponseTemplate::new(200).set_body_json(answer.clone())
        })
        .mount(server)
        .await;
    seen
}

#[tokio::test]
async fn requests_are_sigv4_signed_with_an_access_key() {
    let server = MockServer::start().await;
    let eqs = eqs(&server, true).await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "list-queues"))
        .and(header("x-euclid-region", "eu-central-1"))
        .and(header("x-euclid-account-id", "000000000000"))
        .and(header("x-euclid-user-id", "jvo"))
        .respond_with(|req: &Request| {
            let auth = req.headers.get("authorization").unwrap().to_str().unwrap();
            assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIATEST/"), "{auth}");
            assert!(auth.contains("/eu-central-1/eqs/aws4_request"), "{auth}");
            assert!(req.headers.contains_key("x-amz-date"));
            assert!(req.headers.contains_key("x-amz-content-sha256"));
            ResponseTemplate::new(200).set_body_json(json!({ "queues": [], "total": 0 }))
        })
        .expect(1)
        .mount(&server)
        .await;

    eqs.list_queues(&ListQueuesRequest::default()).await.unwrap();
}

#[tokio::test]
async fn requests_use_bearer_without_an_access_key() {
    let server = MockServer::start().await;
    let eqs = eqs(&server, false).await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "list-queues"))
        .respond_with(|req: &Request| {
            let auth = req.headers.get("authorization").unwrap().to_str().unwrap();
            assert!(auth.starts_with("Bearer "), "{auth}");
            assert!(!req.headers.contains_key("x-amz-date"));
            ResponseTemplate::new(200).set_body_json(json!({ "queues": [], "total": 0 }))
        })
        .expect(1)
        .mount(&server)
        .await;

    eqs.list_queues(&ListQueuesRequest::default()).await.unwrap();
}

#[tokio::test]
async fn internal_client_marks_requests() {
    let server = MockServer::start().await;
    let eqs = eqs(&server, true).await.as_internal();
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "get-queue-ern"))
        .and(header("x-euclid-internal", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "name": "orders", "ern": QUEUE })))
        .expect(1)
        .mount(&server)
        .await;

    let ern = eqs.get_queue_ern("orders").await.unwrap();
    assert_eq!(ern.ern.as_deref(), Some(QUEUE));
}

#[tokio::test]
async fn list_queues_sends_defaults_and_parses_queues() {
    let server = MockServer::start().await;
    let eqs = eqs(&server, true).await;
    let seen = mount(
        &server,
        "list-queues",
        json!({
            "metadata": { "accountId": "000000000000", "region": "eu-central-1", "user": "jvo" },
            "queues": [{
                "available": 2, "created": "2026-10-07T20:53:22.994000000Z", "deadLetterQueueArn": "",
                "delay": 0, "delayed": 0, "ern": QUEUE, "internal": false, "invisible": 1,
                "maxMessageLength": 1048576, "maxReceiveCount": 3, "name": "orders", "owner": "eap",
                "priority": "MEDIUM", "size": "17", "status": "AVAILABLE",
                "tags": { "euclid:application": "transformation" }, "visibility": 300
            }],
            "total": 1
        }),
    )
    .await;

    let response = eqs.list_queues(&ListQueuesRequest::default()).await.unwrap();
    assert_eq!(
        seen.lock().unwrap()[0],
        json!({ "prefix": "", "pageSize": 10, "pageIndex": 0, "sortColumn": "name",
                "sortDirection": "asc", "includeInternal": false })
    );
    assert_eq!(response.total, 1);
    assert_eq!(response.metadata.unwrap().user.as_deref(), Some("jvo"));
    let queue = &response.queues[0];
    assert_eq!(queue.name.as_deref(), Some("orders"));
    assert_eq!(queue.available, 2);
    assert_eq!(queue.size, 17);
    assert_eq!(queue.visibility, 300);
    assert_eq!(queue.status.as_deref(), Some("AVAILABLE"));
    assert_eq!(queue.tag("euclid:application").as_deref(), Some("transformation"));
}

#[tokio::test]
async fn queue_defaults_apply_when_fields_are_missing() {
    let server = MockServer::start().await;
    let eqs = eqs(&server, true).await;
    let seen = mount(&server, "get-queue", json!({ "queue": { "name": "orders" } })).await;

    let queue = eqs.get_queue("orders").await.unwrap();
    assert_eq!(seen.lock().unwrap()[0], json!({ "ern": null, "name": "orders" }));
    assert_eq!(queue.visibility, 30);
    assert_eq!(queue.max_message_length, 1024 * 1024);
    assert_eq!(queue.max_receive_count, 3);

    eqs.get_queue(QUEUE).await.unwrap();
    assert_eq!(seen.lock().unwrap()[1], json!({ "ern": QUEUE, "name": null }));
}

#[tokio::test]
async fn create_queue_sends_jdk_defaults() {
    let server = MockServer::start().await;
    let eqs = eqs(&server, true).await;
    let seen = mount(&server, "create-queue", json!({ "name": "orders", "ern": QUEUE })).await;

    let created = eqs.create_queue("orders").await.unwrap();
    assert_eq!(created.ern.as_deref(), Some(QUEUE));
    assert_eq!(
        seen.lock().unwrap()[0],
        json!({ "name": "orders", "visibility": 30, "maxRetries": 3, "maxMessageLength": 1048576,
                "dlqName": "", "delay": 0, "priority": "MEDIUM", "internal": false })
    );

    eqs.create_queue_with(&CreateQueueRequest {
        name: "orders".into(),
        dlq_name: "orders-dlq".into(),
        priority: "HIGH".into(),
        ..Default::default()
    })
    .await
    .unwrap();
    let body = &seen.lock().unwrap()[1];
    assert_eq!(body["dlqName"], "orders-dlq");
    assert_eq!(body["priority"], "HIGH");
}

#[tokio::test]
async fn send_message_with_attributes() {
    let server = MockServer::start().await;
    let eqs = eqs(&server, true).await;
    let seen = mount(&server, "send-message", json!({ "messageId": "m-1" })).await;

    let sent = eqs.send_message(QUEUE, "{\"hello\":1}").await.unwrap();
    assert_eq!(sent.message_id.as_deref(), Some("m-1"));
    assert_eq!(
        seen.lock().unwrap()[0],
        json!({ "ern": QUEUE, "body": "{\"hello\":1}", "attributes": {}, "priority": "MEDIUM" })
    );

    let mut attributes = HashMap::new();
    attributes.insert("kind".to_owned(), Variant::string("greeting"));
    attributes.insert("count".to_owned(), Variant::new("number", 3));
    eqs.send_message_with(&SendMessageRequest {
        ern: QUEUE.into(),
        body: "x".into(),
        attributes,
        priority: "HIGH".into(),
    })
    .await
    .unwrap();
    let body = &seen.lock().unwrap()[1];
    assert_eq!(
        body["attributes"]["kind"],
        json!({ "type": "string", "value": "greeting" })
    );
    assert_eq!(body["attributes"]["count"], json!({ "type": "number", "value": 3 }));
    assert_eq!(body["priority"], "HIGH");
}

#[tokio::test]
async fn send_message_batch_reports_failures() {
    let server = MockServer::start().await;
    let eqs = eqs(&server, true).await;
    let seen = mount(
        &server,
        "send-message-batch",
        json!({ "ern": QUEUE, "asked": 2, "sent": 1, "messageIds": ["m-1"],
                "failed": [{ "index": 1, "reason": "too large" }] }),
    )
    .await;

    let response = eqs
        .send_message_batch(
            &SendMessageBatchRequest::new(QUEUE)
                .message("a")
                .message_with("b", HashMap::new(), "LOW"),
        )
        .await
        .unwrap();
    assert_eq!(
        seen.lock().unwrap()[0],
        json!({ "ern": QUEUE, "messages": [
            { "body": "a", "attributes": {}, "systemAttributes": {}, "priority": "" },
            { "body": "b", "attributes": {}, "systemAttributes": {}, "priority": "LOW" }
        ]})
    );
    assert_eq!(response.sent, 1);
    assert_eq!(response.message_ids, vec!["m-1"]);
    assert_eq!(response.failed[0].index, 1);
    assert_eq!(response.failed[0].reason, "too large");
}

fn message(id: &str) -> Value {
    json!({
        "messageId": id, "queueErn": QUEUE, "body": "hi", "receiptHandle": format!("rh-{id}"),
        "receivedCount": 1, "attributes": { "kind": { "type": "string", "value": "greeting" } },
        "created": 1730548800
    })
}

#[tokio::test]
async fn short_poll_trusts_a_zero_count_only_for_a_while() {
    let server = MockServer::start().await;
    let eqs = eqs(&server, true).await.zero_count_trust(Duration::from_millis(200));
    mount(&server, "get-message-count", json!({ "ern": QUEUE, "available": 0 })).await;
    let received = mount(&server, "receive-messages", json!({ "messages": [message("m-1")] })).await;

    // Zero count: answered empty without receiving, twice within the trust window.
    assert!(eqs.receive_messages(QUEUE, 10, 0).await.unwrap().messages.is_empty());
    assert!(eqs.receive_messages(QUEUE, 10, 0).await.unwrap().messages.is_empty());
    assert_eq!(received.lock().unwrap().len(), 0);

    // Past the window, one real receive asks the queue itself.
    tokio::time::sleep(Duration::from_millis(250)).await;
    let response = eqs.receive_messages(QUEUE, 10, 0).await.unwrap();
    assert_eq!(
        received.lock().unwrap()[0],
        json!({ "ern": QUEUE, "maxCount": 10, "waitTime": 0 })
    );
    let message = &response.messages[0];
    assert_eq!(message.receipt_handle.as_deref(), Some("rh-m-1"));
    assert_eq!(message.attributes["kind"].as_text().as_deref(), Some("greeting"));
    assert_eq!(message.created.as_deref(), Some("1730548800"));
}

#[tokio::test]
async fn short_poll_receives_when_count_is_positive() {
    let server = MockServer::start().await;
    let eqs = eqs(&server, true).await;
    mount(&server, "get-message-count", json!({ "ern": QUEUE, "available": 3 })).await;
    mount(
        &server,
        "receive-messages",
        json!({ "messages": [message("m-1"), message("m-2")] }),
    )
    .await;

    let response = eqs.receive_messages(QUEUE, 10, 0).await.unwrap();
    assert_eq!(response.messages.len(), 2);
}

#[tokio::test]
async fn long_poll_repeats_until_messages_arrive() {
    let server = MockServer::start().await;
    let eqs = eqs(&server, true).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "receive-messages"))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            assert!(body["waitTime"].as_u64().unwrap() >= 1);
            // Two empty answers (receive slots busy), then a message.
            let messages = if counter.fetch_add(1, Ordering::SeqCst) < 2 {
                json!([])
            } else {
                json!([message("m-1")])
            };
            ResponseTemplate::new(200).set_body_json(json!({ "messages": messages }))
        })
        .mount(&server)
        .await;

    let response = eqs.receive_messages(QUEUE, 1, 5).await.unwrap();
    assert_eq!(response.messages.len(), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn long_poll_outlives_the_default_request_timeout() {
    let server = MockServer::start().await;
    let eqs = eqs(&server, true).await;
    // The server holds the request past the client-wide 10 s default; the long poll's own
    // timeout (wait 2 s + 10 s margin) must cover it.
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "receive-messages"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "messages": [message("m-1")] }))
                .set_delay(Duration::from_millis(10_500)),
        )
        .mount(&server)
        .await;

    let started = Instant::now();
    let response = eqs.receive_messages(QUEUE, 1, 2).await.unwrap();
    assert_eq!(response.messages.len(), 1);
    assert!(started.elapsed() >= Duration::from_secs(10));
}

#[tokio::test]
async fn delete_message_by_handle_and_by_id() {
    let server = MockServer::start().await;
    let eqs = eqs(&server, true).await;
    let seen = mount(&server, "delete-message", json!({})).await;

    eqs.delete_message("rh-1").await.unwrap();
    eqs.delete_message_by_id("m-1").await.unwrap();
    let seen = seen.lock().unwrap();
    assert_eq!(seen[0], json!({ "receiptHandle": "rh-1", "messageId": "" }));
    assert_eq!(seen[1], json!({ "receiptHandle": "", "messageId": "m-1" }));
}

#[tokio::test]
async fn exists_queue_maps_404_to_false() {
    let server = MockServer::start().await;
    let eqs = eqs(&server, true).await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "get-queue-ern"))
        .and(body_json(json!({ "name": "missing" })))
        .respond_with(ResponseTemplate::new(404).set_body_string("queue not found"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "get-queue-ern"))
        .and(body_json(json!({ "name": "broken" })))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;

    assert!(!eqs.exists_queue("missing").await.unwrap());
    let err = eqs.exists_queue("broken").await.unwrap_err();
    assert!(matches!(err, Error::Service { status: 500, .. }));
    assert_eq!(err.to_string(), "eqs get-queue-ern failed with status 500: boom");
}

#[tokio::test]
async fn max_message_length_effective_falls_back() {
    let server = MockServer::start().await;
    let eqs = eqs(&server, true).await;
    mount(
        &server,
        "set-queue-max-message-length",
        json!({ "ern": QUEUE, "maxMessageLength": 0 }),
    )
    .await;

    let response = eqs.set_queue_max_message_length(QUEUE, 0).await.unwrap();
    assert_eq!(response.max_message_length, 0);
    assert_eq!(response.effective_max_message_length, 1024 * 1024);
}

#[tokio::test]
async fn purge_all_queues_defaults_to_own_account() {
    let server = MockServer::start().await;
    let eqs = eqs(&server, true).await;
    let seen = mount(&server, "purge-all-queues", json!({})).await;

    eqs.purge_all_queues().await.unwrap();
    assert_eq!(
        seen.lock().unwrap()[0],
        json!({ "region": "eu-central-1", "accountId": "000000000000", "nameSpace": "" })
    );
}

#[tokio::test]
async fn message_attribute_and_redrive_parse() {
    let server = MockServer::start().await;
    let eqs = eqs(&server, true).await;
    let seen = mount(
        &server,
        "set-message-attribute",
        json!({ "messageId": "m-1", "name": "kind", "value": { "type": "string", "value": "x" } }),
    )
    .await;
    mount(
        &server,
        "redrive-dlq",
        json!({ "ern": QUEUE, "messages": 4, "remaining": 0,
                "targets": [{ "queueErn": "ern:q", "messages": 4 }], "note": "ok" }),
    )
    .await;

    let attribute = eqs
        .set_message_attribute("m-1", "kind", &Variant::string("x"))
        .await
        .unwrap();
    assert_eq!(
        seen.lock().unwrap()[0],
        json!({ "messageId": "m-1", "key": "kind", "value": { "type": "string", "value": "x" } })
    );
    assert_eq!(attribute.value.unwrap().kind, "string");

    let redrive = eqs.redrive_dlq(QUEUE).await.unwrap();
    assert_eq!(redrive.messages, 4);
    assert_eq!(redrive.targets[0].queue_ern.as_deref(), Some("ern:q"));
}
