//! EDS against a mock server: authentication, request bodies, response parsing and errors.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use euclid_rdk::eds::*;
use euclid_rdk::{Eam, Eds, Error};
use serde_json::{json, Value};
use wiremock::matchers::{header, method};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

type Seen = Arc<std::sync::Mutex<Vec<(Value, String)>>>;

fn jwt() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{}}}"#, now + 3600));
    format!("{}.{payload}.sig", URL_SAFE_NO_PAD.encode(b"{}"))
}

async fn eds(server: &MockServer, with_access_key: bool) -> Eds {
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
        .eds()
}

/// Mounts `action` answering `answer`, recording each request's body and authorization header.
async fn mount(server: &MockServer, action: &str, status: u16, answer: Value) -> Seen {
    let seen: Seen = Arc::default();
    let record = seen.clone();
    Mock::given(method("POST"))
        .and(header("x-euclid-target", "eds"))
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

fn zone_json() -> Value {
    json!({
        "name": "corp.example", "ern": "ern:eds:eu-central-1:000000000000:default:zone:corp.example",
        "namespace": "default", "ttl": 3600, "description": "corp", "recordCount": 2,
        "serial": 1795000000, "created": "2026-11-22T10:00:00Z", "modified": "2026-11-22T11:00:00Z"
    })
}

#[tokio::test]
async fn requests_are_signed_or_carry_the_bearer_token() {
    let server = MockServer::start().await;
    let signed = eds(&server, true).await;
    let seen = mount(&server, "get-zone", 200, zone_json()).await;
    signed.get_zone("corp.example").await.unwrap();
    assert!(last(&seen).1.starts_with("AWS4-HMAC-SHA256 "));

    let server = MockServer::start().await;
    let bearer = eds(&server, false).await;
    let seen = mount(&server, "get-zone", 200, zone_json()).await;
    bearer.get_zone("corp.example").await.unwrap();
    assert!(last(&seen).1.starts_with("Bearer "));
}

#[tokio::test]
async fn create_zone_sends_the_description_only_when_set_and_parses_the_zone() {
    let server = MockServer::start().await;
    let eds = eds(&server, false).await;
    let seen = mount(&server, "create-zone", 200, zone_json()).await;

    let zone = eds.create_zone(&CreateZoneRequest::new("corp.example")).await.unwrap();
    assert_eq!(last(&seen).0, json!({ "name": "corp.example", "ttl": 0 }));
    assert_eq!(
        zone,
        HostedZone {
            name: Some("corp.example".into()),
            ern: Some("ern:eds:eu-central-1:000000000000:default:zone:corp.example".into()),
            namespace: Some("default".into()),
            ttl: 3600,
            description: Some("corp".into()),
            record_count: 2,
            serial: 1795000000,
            created: Some("2026-11-22T10:00:00Z".into()),
            modified: Some("2026-11-22T11:00:00Z".into()),
        }
    );

    eds.create_zone(&CreateZoneRequest {
        ttl: 300,
        description: Some("corp".into()),
        ..CreateZoneRequest::new("corp.example")
    })
    .await
    .unwrap();
    assert_eq!(
        last(&seen).0,
        json!({ "name": "corp.example", "ttl": 300, "description": "corp" })
    );
}

#[tokio::test]
async fn list_zones_sends_the_prefix_only_when_set() {
    let server = MockServer::start().await;
    let eds = eds(&server, false).await;
    let seen = mount(
        &server,
        "list-zones",
        200,
        json!({ "zones": [zone_json()], "total": 7 }),
    )
    .await;

    let listing = eds.list_zones(&ListZonesRequest::default()).await.unwrap();
    assert_eq!(last(&seen).0, json!({ "pageSize": 0, "pageIndex": 0 }));
    assert_eq!(listing.total, 7);
    assert_eq!(listing.zones[0].name.as_deref(), Some("corp.example"));

    eds.list_zones(&ListZonesRequest {
        prefix: Some("corp".into()),
        page_size: 5,
        page_index: 1,
    })
    .await
    .unwrap();
    assert_eq!(
        last(&seen).0,
        json!({ "prefix": "corp", "pageSize": 5, "pageIndex": 1 })
    );
}

#[tokio::test]
async fn delete_zone_returns_the_deleted_record_count() {
    let server = MockServer::start().await;
    let eds = eds(&server, false).await;
    let seen = mount(&server, "delete-zone", 200, json!({ "deletedRecords": 3 })).await;
    assert_eq!(eds.delete_zone("corp.example").await.unwrap(), 3);
    assert_eq!(last(&seen).0, json!({ "name": "corp.example" }));
}

#[tokio::test]
async fn put_record_sends_the_type_and_values_and_parses_the_record_set() {
    let server = MockServer::start().await;
    let eds = eds(&server, false).await;
    let seen = mount(
        &server,
        "put-record",
        200,
        json!({
            "zone": "corp.example", "name": "www.corp.example", "type": "A", "ttl": 0,
            "values": ["10.0.0.5", "10.0.0.6"], "created": "2026-11-22T10:00:00Z", "modified": "2026-11-22T10:00:00Z"
        }),
    )
    .await;

    let set = eds
        .put_record(&PutRecordRequest::new(
            "corp.example",
            "www",
            "A",
            ["10.0.0.5", "10.0.0.6"],
        ))
        .await
        .unwrap();
    assert_eq!(
        last(&seen).0,
        json!({ "zone": "corp.example", "name": "www", "type": "A", "ttl": 0, "values": ["10.0.0.5", "10.0.0.6"] })
    );
    assert_eq!(set.record_type.as_deref(), Some("A"));
    assert_eq!(set.values, vec!["10.0.0.5", "10.0.0.6"]);

    // The default owner name is the apex.
    eds.put_record(&PutRecordRequest {
        zone: "corp.example".into(),
        record_type: "TXT".into(),
        ttl: 60,
        values: vec!["v=spf1 -all".into()],
        ..Default::default()
    })
    .await
    .unwrap();
    assert_eq!(last(&seen).0["name"], "@");
    assert_eq!(last(&seen).0["ttl"], 60);
}

#[tokio::test]
async fn delete_record_defaults_the_name_to_the_apex() {
    let server = MockServer::start().await;
    let eds = eds(&server, false).await;
    let seen = mount(&server, "delete-record", 200, json!({})).await;

    eds.delete_record("corp.example", None, "MX").await.unwrap();
    assert_eq!(
        last(&seen).0,
        json!({ "zone": "corp.example", "name": "@", "type": "MX" })
    );

    eds.delete_record("corp.example", Some("www"), "A").await.unwrap();
    assert_eq!(
        last(&seen).0,
        json!({ "zone": "corp.example", "name": "www", "type": "A" })
    );
}

#[tokio::test]
async fn list_records_sends_only_the_filters_that_are_set() {
    let server = MockServer::start().await;
    let eds = eds(&server, false).await;
    let seen = mount(
        &server,
        "list-records",
        200,
        json!({ "records": [{ "zone": "corp.example", "name": "www.corp.example", "type": "A", "values": ["10.0.0.5"] }], "total": 1 }),
    )
    .await;

    let listing = eds
        .list_records(&ListRecordsRequest::new("corp.example"))
        .await
        .unwrap();
    assert_eq!(
        last(&seen).0,
        json!({ "zone": "corp.example", "pageSize": 0, "pageIndex": 0 })
    );
    assert_eq!(listing.total, 1);
    assert_eq!(listing.records[0].values, vec!["10.0.0.5"]);

    eds.list_records(&ListRecordsRequest {
        name: Some("www".into()),
        record_type: Some("A".into()),
        page_size: 10,
        ..ListRecordsRequest::new("corp.example")
    })
    .await
    .unwrap();
    assert_eq!(
        last(&seen).0,
        json!({ "zone": "corp.example", "name": "www", "type": "A", "pageSize": 10, "pageIndex": 0 })
    );
}

#[tokio::test]
async fn get_answer_parses_both_sections() {
    let server = MockServer::start().await;
    let eds = eds(&server, false).await;
    let seen = mount(
        &server,
        "get-answer",
        200,
        json!({
            "name": "nope.corp.example", "type": "A", "authoritative": true, "zone": "corp.example",
            "rcode": "NXDOMAIN", "answers": [],
            "authority": [{ "name": "corp.example", "type": "SOA", "ttl": 3600, "value": "ns.corp.example. hostmaster 1 2 3 4 5" }]
        }),
    )
    .await;

    let answer = eds.get_answer("nope.corp.example", None).await.unwrap();
    assert_eq!(last(&seen).0, json!({ "name": "nope.corp.example" }));
    assert!(answer.authoritative);
    assert_eq!(answer.zone.as_deref(), Some("corp.example"));
    assert_eq!(answer.rcode.as_deref(), Some("NXDOMAIN"));
    assert!(answer.answers.is_empty());
    assert_eq!(
        answer.authority,
        vec![AnswerRecord {
            name: Some("corp.example".into()),
            record_type: Some("SOA".into()),
            ttl: 3600,
            value: Some("ns.corp.example. hostmaster 1 2 3 4 5".into()),
        }]
    );

    eds.get_answer("www.corp.example", Some("AAAA")).await.unwrap();
    assert_eq!(last(&seen).0, json!({ "name": "www.corp.example", "type": "AAAA" }));
}

#[tokio::test]
async fn a_refused_answer_has_no_zone() {
    let server = MockServer::start().await;
    let eds = eds(&server, false).await;
    mount(
        &server,
        "get-answer",
        200,
        json!({ "name": "example.org", "type": "A", "authoritative": false, "zone": "", "rcode": "REFUSED", "answers": [] }),
    )
    .await;

    let answer = eds.get_answer("example.org", None).await.unwrap();
    assert!(!answer.authoritative);
    assert_eq!(answer.zone, None);
    assert_eq!(answer.rcode.as_deref(), Some("REFUSED"));
    assert!(answer.authority.is_empty());
}

#[tokio::test]
async fn errors_carry_the_status() {
    let server = MockServer::start().await;
    let eds = eds(&server, false).await;
    mount(&server, "create-zone", 409, json!({ "message": "zone exists" })).await;

    let err = eds
        .create_zone(&CreateZoneRequest::new("corp.example"))
        .await
        .unwrap_err();
    assert_eq!(err.status(), Some(409));
    assert!(matches!(err, Error::Service { .. }));
}
