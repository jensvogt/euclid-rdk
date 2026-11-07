//! ENS against a mock server: authentication, request bodies, response parsing, errors.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use euclid_rdk::ens::{ListMessagesRequest, ListTopicsRequest, PublishMessageRequest, Variant, RETENTION_FOREVER};
use euclid_rdk::{Eam, Ens, Error};
use serde_json::{json, Value};
use wiremock::matchers::{header, method};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const TOPIC: &str = "ern:ens:eu-central-1:000000000000:development:topic:orders";
const QUEUE: &str = "ern:eqs:eu-central-1:000000000000:development:queue:orders";

fn jwt() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{}}}"#, now + 3600));
    format!("{}.{payload}.sig", URL_SAFE_NO_PAD.encode(b"{}"))
}

async fn ens(server: &MockServer, with_access_key: bool) -> Ens {
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
        .ens()
}

/// Mounts `action` answering `answer`, and records each request (body, authorization header).
async fn mount(server: &MockServer, action: &str, answer: Value) -> Arc<std::sync::Mutex<Vec<(Value, String)>>> {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let record = seen.clone();
    Mock::given(method("POST"))
        .and(header("x-euclid-target", "ens"))
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

fn body(seen: &Arc<std::sync::Mutex<Vec<(Value, String)>>>) -> Value {
    seen.lock().unwrap().last().expect("a request").0.clone()
}

#[tokio::test]
async fn requests_are_sigv4_signed_with_an_access_key() {
    let server = MockServer::start().await;
    let ens = ens(&server, true).await;
    let seen = mount(&server, "list-topics", json!({ "topics": [], "total": 0 })).await;
    ens.list_topics(&ListTopicsRequest::default()).await.unwrap();
    let auth = seen.lock().unwrap()[0].1.clone();
    assert!(
        auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIATEST/") && auth.contains("/eu-central-1/ens/aws4_request"),
        "{auth}"
    );
}

#[tokio::test]
async fn requests_use_bearer_without_an_access_key() {
    let server = MockServer::start().await;
    let ens = ens(&server, false).await;
    let seen = mount(&server, "list-topics", json!({ "topics": [], "total": 0 })).await;
    ens.list_topics(&ListTopicsRequest::default()).await.unwrap();
    assert!(seen.lock().unwrap()[0].1.starts_with("Bearer "));
}

#[tokio::test]
async fn list_topics_sends_defaults_and_parses_topics() {
    let server = MockServer::start().await;
    let ens = ens(&server, true).await;
    let seen = mount(
        &server,
        "list-topics",
        json!({
            "topics": [{
                "name": "orders", "owner": "jvo", "ern": TOPIC, "tags": { "team": "shop" },
                "size": 12, "messages": "3", "status": "AVAILABLE", "retentionPeriod": -1,
                "created": "2026-11-02T10:00:00Z", "modified": 1762077600
            }, { "name": "bare" }],
            "total": 2
        }),
    )
    .await;

    let response = ens.list_topics(&ListTopicsRequest::default()).await.unwrap();
    assert_eq!(
        body(&seen),
        json!({ "prefix": "", "pageSize": 10, "pageIndex": 0, "sortColumn": "name", "sortDirection": "asc" })
    );
    assert_eq!(response.total, 2);
    let topic = &response.topics[0];
    assert_eq!(topic.ern.as_deref(), Some(TOPIC));
    assert_eq!(topic.messages, 3);
    assert_eq!(topic.retention_period, RETENTION_FOREVER);
    assert_eq!(topic.tag("team").as_deref(), Some("shop"));
    assert_eq!(topic.modified.as_deref(), Some("1762077600"));
    // Fields the server leaves out fall back like the JDK's.
    assert_eq!(response.topics[1].max_message_length, 1024 * 1024);
}

#[tokio::test]
async fn create_and_get_topic_bodies() {
    let server = MockServer::start().await;
    let ens = ens(&server, true).await;
    let create = mount(&server, "create-topic", json!({ "name": "orders", "ern": TOPIC })).await;
    let get = mount(
        &server,
        "get-topic",
        json!({ "topic": { "name": "orders", "ern": TOPIC } }),
    )
    .await;

    let created = ens.create_topic("orders").await.unwrap();
    assert_eq!(created.ern.as_deref(), Some(TOPIC));
    assert_eq!(body(&create), json!({ "name": "orders", "maxMessageLength": 1048576 }));

    ens.create_topic_with_max_length("small", 1024).await.unwrap();
    assert_eq!(body(&create), json!({ "name": "small", "maxMessageLength": 1024 }));

    ens.get_topic("orders").await.unwrap();
    assert_eq!(body(&get), json!({ "ern": null, "name": "orders" }));
    let topic = ens.get_topic(TOPIC).await.unwrap();
    assert_eq!(body(&get), json!({ "ern": TOPIC, "name": null }));
    assert_eq!(topic.name.as_deref(), Some("orders"));
}

#[tokio::test]
async fn publish_message_defaults_to_medium_and_carries_attributes() {
    let server = MockServer::start().await;
    let ens = ens(&server, true).await;
    let seen = mount(&server, "publish-message", json!({ "messageId": "m-1" })).await;

    let published = ens.publish_message(TOPIC, "hello").await.unwrap();
    assert_eq!(published.message_id.as_deref(), Some("m-1"));
    assert_eq!(
        body(&seen),
        json!({ "ern": TOPIC, "body": "hello", "attributes": {}, "priority": "MEDIUM" })
    );

    let mut attributes = HashMap::new();
    attributes.insert("kind".to_owned(), Variant::string("order"));
    ens.publish_message_with(&PublishMessageRequest {
        ern: TOPIC.into(),
        body: "{}".into(),
        attributes,
        priority: "HIGH".into(),
    })
    .await
    .unwrap();
    assert_eq!(
        body(&seen),
        json!({ "ern": TOPIC, "body": "{}", "attributes": { "kind": { "type": "string", "value": "order" } }, "priority": "HIGH" })
    );
}

#[tokio::test]
async fn list_messages_and_count_parse() {
    let server = MockServer::start().await;
    let ens = ens(&server, true).await;
    let list = mount(
        &server,
        "list-messages",
        json!({
            "messages": [{
                "messageId": "m-1", "topicErn": TOPIC, "body": "hello", "status": "SEND",
                "attributes": { "kind": { "type": "string", "value": "order" } }, "contentType": "text/plain"
            }],
            "total": 1
        }),
    )
    .await;
    let count = mount(
        &server,
        "get-message-count",
        json!({ "ern": TOPIC, "available": 4, "send": 3, "resend": 1 }),
    )
    .await;

    let messages = ens
        .list_messages(&ListMessagesRequest {
            topic_ern: TOPIC.into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        body(&list),
        json!({ "topicErn": TOPIC, "pageSize": 10, "pageIndex": 0, "sortColumn": "created", "sortDirection": "asc" })
    );
    assert_eq!(messages.total, 1);
    let message = &messages.messages[0];
    assert_eq!(message.attributes["kind"].as_text().as_deref(), Some("order"));
    assert_eq!(message.content_type.as_deref(), Some("text/plain"));

    let counted = ens.get_message_count(TOPIC).await.unwrap();
    assert_eq!(body(&count), json!({ "ern": TOPIC }));
    assert_eq!((counted.available, counted.send, counted.resend), (4, 3, 1));
}

#[tokio::test]
async fn message_attribute_body_and_get_message() {
    let server = MockServer::start().await;
    let ens = ens(&server, true).await;
    let set = mount(
        &server,
        "set-message-attribute",
        json!({ "messageId": "m-1", "key": "kind", "value": { "type": "string", "value": "x" } }),
    )
    .await;
    let get = mount(
        &server,
        "get-message-attribute",
        json!({ "messageId": "m-1", "key": "kind", "value": { "type": "number", "value": 7 } }),
    )
    .await;
    let update = mount(
        &server,
        "update-message-body",
        json!({ "messageId": "m-1", "topicErn": TOPIC, "size": 3, "previousSize": 5, "contentType": "text/plain" }),
    )
    .await;
    let message = mount(
        &server,
        "get-message",
        json!({ "message": { "messageId": "m-1", "body": "new" } }),
    )
    .await;

    let attribute = ens
        .set_message_attribute("m-1", "kind", &Variant::string("x"))
        .await
        .unwrap();
    assert_eq!(
        body(&set),
        json!({ "messageId": "m-1", "key": "kind", "value": { "type": "string", "value": "x" } })
    );
    assert_eq!(attribute.value.unwrap().kind, "string");

    let attribute = ens.get_message_attribute("m-1", "kind").await.unwrap();
    assert_eq!(body(&get), json!({ "messageId": "m-1", "key": "kind" }));
    assert_eq!(attribute.value.unwrap().as_text().as_deref(), Some("7"));

    let updated = ens.update_message_body("m-1", "new").await.unwrap();
    assert_eq!(body(&update), json!({ "messageId": "m-1", "body": "new" }));
    assert_eq!((updated.size, updated.previous_size), (3, 5));

    let got = ens.get_message("m-1").await.unwrap();
    assert_eq!(body(&message), json!({ "messageId": "m-1" }));
    assert_eq!(got.body.as_deref(), Some("new"));
}

#[tokio::test]
async fn topic_settings_and_status() {
    let server = MockServer::start().await;
    let ens = ens(&server, true).await;
    let retention = mount(
        &server,
        "set-topic-retention",
        json!({ "ern": TOPIC, "retentionPeriod": -1 }),
    )
    .await;
    let length = mount(
        &server,
        "set-topic-max-message-length",
        json!({ "ern": TOPIC, "maxMessageLength": 2048 }),
    )
    .await;
    let stop = mount(&server, "stop-topic", json!({ "ern": TOPIC, "status": "STOPPED" })).await;
    mount(
        &server,
        "start-topic",
        json!({ "ern": TOPIC, "status": "AVAILABLE", "released": 5 }),
    )
    .await;
    let metadata = mount(
        &server,
        "get-topic-metadata",
        json!({ "ern": TOPIC, "nameSpace": "development", "messages": 9, "held": 2, "retentionPeriod": 3600 }),
    )
    .await;

    let set = ens.set_topic_retention(TOPIC, RETENTION_FOREVER).await.unwrap();
    assert_eq!(body(&retention), json!({ "ern": TOPIC, "retentionPeriod": -1 }));
    assert_eq!(set.retention_period, -1);

    let set = ens.set_topic_max_message_length(TOPIC, 2048).await.unwrap();
    assert_eq!(body(&length), json!({ "ern": TOPIC, "maxMessageLength": 2048 }));
    assert_eq!(set.max_message_length, 2048);

    assert_eq!(ens.stop_topic(TOPIC).await.unwrap().status.as_deref(), Some("STOPPED"));
    assert_eq!(body(&stop), json!({ "ern": TOPIC }));
    assert_eq!(ens.start_topic(TOPIC).await.unwrap().released, 5);

    let meta = ens.get_topic_metadata(TOPIC).await.unwrap();
    assert_eq!(body(&metadata), json!({ "ern": TOPIC }));
    assert_eq!((meta.messages, meta.held, meta.retention_period), (9, 2, 3600));
    assert_eq!(meta.name_space.as_deref(), Some("development"));
}

#[tokio::test]
async fn tags_purge_and_resend_bodies() {
    let server = MockServer::start().await;
    let ens = ens(&server, true).await;
    let add = mount(&server, "add-topic-tag", json!({})).await;
    let set = mount(&server, "set-topic-tag", json!({})).await;
    let delete = mount(&server, "delete-topic-tag", json!({})).await;
    let purge_all = mount(&server, "purge-all-topics", json!({})).await;
    let resend = mount(
        &server,
        "resend-messages",
        json!({ "ern": TOPIC, "resent": 0, "held": 0, "messages": 42, "async": true }),
    )
    .await;

    ens.add_topic_tag(TOPIC, "team", "shop").await.unwrap();
    assert_eq!(body(&add), json!({ "ern": TOPIC, "key": "team", "value": "shop" }));
    ens.set_topic_tag(TOPIC, "team", "ops").await.unwrap();
    assert_eq!(body(&set), json!({ "ern": TOPIC, "key": "team", "value": "ops" }));
    ens.delete_topic_tag(TOPIC, "team").await.unwrap();
    assert_eq!(body(&delete), json!({ "ern": TOPIC, "key": "team" }));

    ens.purge_all_topics().await.unwrap();
    assert_eq!(
        body(&purge_all),
        json!({ "region": "eu-central-1", "accountId": "000000000000", "nameSpace": "" })
    );

    ens.resend_messages(TOPIC).await.unwrap();
    assert_eq!(body(&resend), json!({ "ern": TOPIC, "messageId": "", "async": false }));
    let taken = ens.resend_messages_with(TOPIC, "", true).await.unwrap();
    assert_eq!(body(&resend), json!({ "ern": TOPIC, "messageId": "", "async": true }));
    assert!(taken.is_async);
    assert_eq!(taken.messages, 42);
}

#[tokio::test]
async fn subscriptions() {
    let server = MockServer::start().await;
    let ens = ens(&server, true).await;
    let sub = mount(
        &server,
        "subscribe",
        json!({ "ern": "ern:sub", "sourceErn": TOPIC, "type": "SQS", "targetErn": QUEUE }),
    )
    .await;
    let list = mount(
        &server,
        "list-subscriptions",
        json!({ "subscriptions": [{ "ern": "ern:sub", "sourceErn": TOPIC, "type": "SQS", "targetErn": QUEUE }], "total": 1 }),
    )
    .await;
    let unsub = mount(&server, "unsubscribe", json!({})).await;

    let subscription = ens.subscribe(TOPIC, QUEUE).await.unwrap();
    assert_eq!(
        body(&sub),
        json!({ "sourceErn": TOPIC, "type": "SQS", "targetErn": QUEUE })
    );
    assert_eq!(subscription.kind.as_deref(), Some("SQS"));

    let listed = ens.list_subscriptions(TOPIC).await.unwrap();
    assert_eq!(body(&list), json!({ "topicErn": TOPIC }));
    assert_eq!(listed.subscriptions[0].target_ern.as_deref(), Some(QUEUE));

    ens.unsubscribe("ern:sub").await.unwrap();
    assert_eq!(body(&unsub), json!({ "ern": "ern:sub" }));
}

#[tokio::test]
async fn errors_and_exists_topic() {
    let server = MockServer::start().await;
    let ens = ens(&server, true).await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "get-topic-ern"))
        .respond_with(ResponseTemplate::new(404).set_body_string("Topic not found"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "publish-message"))
        .respond_with(ResponseTemplate::new(400).set_body_string("message too large"))
        .mount(&server)
        .await;

    assert!(!ens.exists_topic("nope").await.unwrap());
    let err = ens.publish_message(TOPIC, "x").await.unwrap_err();
    assert!(matches!(err, Error::Service { status: 400, .. }));
    assert_eq!(
        err.to_string(),
        "ens publish-message failed with status 400: message too large"
    );
}

#[tokio::test]
async fn delete_after_delivery_setting_and_topic_fields() {
    let server = MockServer::start().await;
    let ens = ens(&server, true).await;
    let set = mount(
        &server,
        "set-topic-delete-after-delivery",
        json!({ "ern": TOPIC, "deleteAfterDelivery": true }),
    )
    .await;
    mount(
        &server,
        "get-topic-metadata",
        json!({ "ern": TOPIC, "deleteAfterDelivery": true, "held": 1 }),
    )
    .await;
    mount(
        &server,
        "get-topic",
        json!({ "topic": { "ern": TOPIC, "deleteAfterDelivery": true, "send": 12, "resend": "3" } }),
    )
    .await;

    let answer = ens.set_topic_delete_after_delivery(TOPIC, true).await.unwrap();
    assert_eq!(body(&set), json!({ "ern": TOPIC, "deleteAfterDelivery": true }));
    assert!(answer.delete_after_delivery);
    assert_eq!(answer.ern.as_deref(), Some(TOPIC));

    assert!(ens.get_topic_metadata(TOPIC).await.unwrap().delete_after_delivery);

    let topic = ens.get_topic(TOPIC).await.unwrap();
    assert!(topic.delete_after_delivery);
    assert_eq!((topic.send, topic.resend), (12, 3));
}

#[tokio::test]
async fn topic_fields_default_when_an_older_server_leaves_them_out() {
    let server = MockServer::start().await;
    let ens = ens(&server, true).await;
    mount(&server, "get-topic", json!({ "topic": { "ern": TOPIC } })).await;
    mount(&server, "get-topic-metadata", json!({ "ern": TOPIC })).await;

    let topic = ens.get_topic(TOPIC).await.unwrap();
    assert!(!topic.delete_after_delivery);
    assert_eq!((topic.send, topic.resend), (0, 0));
    assert!(!ens.get_topic_metadata(TOPIC).await.unwrap().delete_after_delivery);
}

#[tokio::test]
async fn purge_topic_asynchronously() {
    let server = MockServer::start().await;
    let ens = ens(&server, true).await;
    let purge = mount(
        &server,
        "purge-topic",
        json!({ "ern": TOPIC, "async": true, "messages": 42 }),
    )
    .await;

    let answer = ens.purge_topic_with(TOPIC, true).await.unwrap();
    assert_eq!(body(&purge), json!({ "ern": TOPIC, "async": true }));
    assert!(answer.is_async);
    assert_eq!(answer.messages, 42);
}
