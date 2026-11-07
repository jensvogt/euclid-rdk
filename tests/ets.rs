//! ETS against a mock server: authentication, request bodies, response parsing, errors.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use euclid_rdk::ets::{CreateServerRequest, Protocol, UpdateServerRequest};
use euclid_rdk::{Eam, Error, Ets};
use serde_json::{json, Value};
use wiremock::matchers::{header, method};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

fn jwt() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{}}}"#, now + 3600));
    format!("{}.{payload}.sig", URL_SAFE_NO_PAD.encode(b"{}"))
}

async fn ets(server: &MockServer, with_access_key: bool) -> Ets {
    let mut login = json!({
        "token": jwt(),
        "isAdmin": true,
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
        .ets()
}

type Seen = Arc<Mutex<Vec<(Value, String)>>>;

/// Mounts `action` answering `status`/`answer`, and records each request (body, authorization).
async fn mount_status(server: &MockServer, action: &str, status: u16, answer: Value) -> Seen {
    let seen: Seen = Arc::default();
    let record = seen.clone();
    Mock::given(method("POST"))
        .and(header("x-euclid-target", "ets"))
        .and(header("x-euclid-action", action))
        .respond_with(move |req: &Request| {
            let auth = req
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            let body = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            record.lock().unwrap().push((body, auth));
            ResponseTemplate::new(status).set_body_json(answer.clone())
        })
        .mount(server)
        .await;
    seen
}

async fn mount(server: &MockServer, action: &str, answer: Value) -> Seen {
    mount_status(server, action, 200, answer).await
}

fn server_json() -> Value {
    json!({
        "serverId": "inbound", "runtimeName": "ets-7f3a", "ern": "ern:ets:eu-central-1:000000000000::server:inbound",
        "accountId": "000000000000", "namespace": "", "region": "eu-central-1", "protocol": "SFTP",
        "address": "0.0.0.0", "port": 2222, "bucketName": "uploads",
        "bucketErn": "ern:esm:eu-central-1:000000000000::bucket:uploads", "homeDirectory": "{user}",
        "userIds": ["jvo"], "userGroups": ["ops"], "directories": ["incoming", "feedback"],
        "desiredState": "RUNNING", "state": "STOPPED", "hostKey": "/usr/local/euclid/etc/ets_host_key",
        "pasvMin": 0, "pasvMax": "0", "created": "2026-11-02T10:00:00Z", "modified": 1762077600
    })
}

#[tokio::test]
async fn requests_are_sigv4_signed_with_an_access_key() {
    let server = MockServer::start().await;
    let ets = ets(&server, true).await;
    let seen = mount(&server, "list-servers", json!({ "servers": [] })).await;
    ets.list_servers().await.unwrap();
    let (_, auth) = &seen.lock().unwrap()[0];
    assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIATEST/"), "{auth}");
    assert!(auth.contains("/eu-central-1/ets/aws4_request"), "{auth}");
}

#[tokio::test]
async fn requests_use_bearer_without_an_access_key() {
    let server = MockServer::start().await;
    let ets = ets(&server, false).await;
    let seen = mount(&server, "list-servers", json!({ "servers": [] })).await;
    ets.list_servers().await.unwrap();
    assert!(seen.lock().unwrap()[0].1.starts_with("Bearer "));
}

#[tokio::test]
async fn list_servers_sends_prefix_and_parses_servers() {
    let server = MockServer::start().await;
    let ets = ets(&server, true).await;
    let seen = mount(&server, "list-servers", json!({ "servers": [server_json(), {}] })).await;

    let all = ets.list_servers().await.unwrap();
    let some = ets.list_servers_with_prefix("in").await.unwrap();
    let bodies: Vec<Value> = seen.lock().unwrap().iter().map(|(b, _)| b.clone()).collect();
    assert_eq!(bodies, [json!({ "prefix": "" }), json!({ "prefix": "in" })]);
    assert_eq!(some.len(), 2);

    let s = &all[0];
    assert_eq!(s.server_id.as_deref(), Some("inbound"));
    assert_eq!(s.runtime_name.as_deref(), Some("ets-7f3a"));
    assert_eq!(s.protocol.as_deref(), Some("SFTP"));
    assert_eq!(s.port, 2222);
    assert_eq!(s.pasv_max, 0);
    assert_eq!(s.user_ids, ["jvo"]);
    assert_eq!(s.user_groups, ["ops"]);
    assert_eq!(s.directories, ["incoming", "feedback"]);
    assert_eq!(s.desired_state.as_deref(), Some("RUNNING"));
    assert_eq!(s.state.as_deref(), Some("STOPPED"));
    assert_eq!(s.modified.as_deref(), Some("1762077600"));
    // A server with nothing set still parses.
    assert_eq!(all[1].port, 0);
    assert!(all[1].user_ids.is_empty());
}

#[tokio::test]
async fn create_server_sends_defaults_and_omits_unset_fields() {
    let server = MockServer::start().await;
    let ets = ets(&server, true).await;
    let seen = mount(&server, "create-server", server_json()).await;

    let created = ets
        .create_server(&CreateServerRequest {
            server_id: "inbound".into(),
            port: Some(2222),
            bucket: Some("uploads".into()),
            user_ids: Some(vec!["jvo".into()]),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        created.bucket_ern.as_deref(),
        Some("ern:esm:eu-central-1:000000000000::bucket:uploads")
    );
    assert_eq!(
        seen.lock().unwrap()[0].0,
        json!({ "serverId": "inbound", "protocol": "SFTP", "port": 2222, "bucket": "uploads",
                "address": "0.0.0.0", "userIds": ["jvo"] })
    );

    ets.create_server(&CreateServerRequest {
        server_id: "ftp".into(),
        protocol: Protocol::Ftp,
        user_groups: Some(vec!["ops".into()]),
        pasv_min: Some(6000),
        pasv_max: Some(6100),
        ..Default::default()
    })
    .await
    .unwrap();
    assert_eq!(
        seen.lock().unwrap()[1].0,
        json!({ "serverId": "ftp", "protocol": "FTP", "address": "0.0.0.0", "userGroups": ["ops"],
                "pasvMin": 6000, "pasvMax": 6100 })
    );
}

#[tokio::test]
async fn create_server_without_users_is_refused_locally() {
    let server = MockServer::start().await;
    let ets = ets(&server, true).await;
    let seen = mount(&server, "create-server", server_json()).await;

    let err = ets
        .create_server(&CreateServerRequest {
            server_id: "nobody".into(),
            user_ids: Some(vec![]),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InvalidArgument(_)), "{err:?}");
    assert!(seen.lock().unwrap().is_empty(), "nothing must be sent");
}

#[tokio::test]
async fn update_server_sends_only_what_is_set() {
    let server = MockServer::start().await;
    let ets = ets(&server, true).await;
    let seen = mount(&server, "update-server", server_json()).await;

    ets.update_server(&UpdateServerRequest {
        server_id: "inbound".into(),
        user_ids: Some(vec!["jvo".into(), "oju".into()]),
        home_directory: Some(String::new()),
        ..Default::default()
    })
    .await
    .unwrap();
    assert_eq!(
        seen.lock().unwrap()[0].0,
        json!({ "serverId": "inbound", "homeDirectory": "", "userIds": ["jvo", "oju"] })
    );
}

#[tokio::test]
async fn server_id_operations() {
    let server = MockServer::start().await;
    let ets = ets(&server, true).await;
    for action in ["get-server", "start-server", "stop-server"] {
        mount(&server, action, server_json()).await;
    }
    let deleted = mount(&server, "delete-server", Value::Null).await;

    assert_eq!(ets.get_server("inbound").await.unwrap().port, 2222);
    assert_eq!(
        ets.start_server("inbound").await.unwrap().desired_state.as_deref(),
        Some("RUNNING")
    );
    ets.stop_server("inbound").await.unwrap();
    ets.delete_server("inbound").await.unwrap();
    assert_eq!(deleted.lock().unwrap()[0].0, json!({ "serverId": "inbound" }));
}

#[tokio::test]
async fn delete_server_accepts_an_empty_answer() {
    let server = MockServer::start().await;
    let ets = ets(&server, true).await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "delete-server"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    ets.delete_server("inbound").await.unwrap();
}

#[tokio::test]
async fn non_admin_gets_a_service_error_with_403() {
    let server = MockServer::start().await;
    let ets = ets(&server, true).await;
    mount_status(
        &server,
        "list-servers",
        403,
        json!({ "error": "administrator privileges required" }),
    )
    .await;

    let err = ets.list_servers().await.unwrap_err();
    assert_eq!(err.status(), Some(403));
    match err {
        Error::Service { service, action, .. } => {
            assert_eq!((service.as_str(), action.as_str()), ("ets", "list-servers"))
        }
        other => panic!("unexpected error {other:?}"),
    }
}

#[tokio::test]
async fn port_conflict_is_a_409() {
    let server = MockServer::start().await;
    let ets = ets(&server, true).await;
    mount_status(&server, "create-server", 409, json!({ "error": "port 2222 in use" })).await;
    let err = ets
        .create_server(&CreateServerRequest {
            server_id: "dup".into(),
            port: Some(2222),
            user_ids: Some(vec!["jvo".into()]),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.status(), Some(409));
}

#[tokio::test]
async fn user_count_is_read_and_defaults_to_zero() {
    let server = MockServer::start().await;
    let older_server = MockServer::start().await;
    let current = ets(&server, true).await;
    let older = ets(&older_server, true).await;

    let mut with_count = server_json();
    with_count["userCount"] = json!(4);
    mount(&server, "get-server", with_count).await;
    mount(&older_server, "get-server", server_json()).await;

    assert_eq!(current.get_server("inbound").await.unwrap().user_count, 4);
    assert_eq!(older.get_server("inbound").await.unwrap().user_count, 0);
}
