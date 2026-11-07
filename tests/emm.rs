//! EMM against a mock server: authentication, request bodies, response parsing, the sealed
//! export/import round trip, client-side validation and errors.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use euclid_rdk::emm::{ExportRequest, ImportRequest, ImportedCollection, SetInstancesRequest};
use euclid_rdk::{Eam, Emm, Error};
use serde_json::{json, Value};
use wiremock::matchers::{header, method};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

type Seen = Arc<std::sync::Mutex<Vec<(Value, String)>>>;

fn jwt() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{}}}"#, now + 3600));
    format!("{}.{payload}.sig", URL_SAFE_NO_PAD.encode(b"{}"))
}

async fn emm(server: &MockServer, with_access_key: bool) -> Emm {
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
        .emm()
}

/// Mounts `action` answering through `answer`, recording each request's body and authorization.
async fn mount_with<F>(server: &MockServer, action: &str, answer: F) -> Seen
where
    F: Fn(&Value) -> ResponseTemplate + Send + Sync + 'static,
{
    let seen: Seen = Arc::default();
    let record = seen.clone();
    Mock::given(method("POST"))
        .and(header("x-euclid-target", "emm"))
        .and(header("x-euclid-action", action))
        .respond_with(move |req: &Request| {
            let auth = req
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            let response = answer(&body);
            record.lock().unwrap().push((body, auth));
            response
        })
        .mount(server)
        .await;
    seen
}

async fn mount(server: &MockServer, action: &str, answer: Value) -> Seen {
    mount_with(server, action, move |_| {
        ResponseTemplate::new(200).set_body_json(answer.clone())
    })
    .await
}

fn bodies(seen: &Seen) -> Vec<Value> {
    seen.lock().unwrap().iter().map(|(b, _)| b.clone()).collect()
}

fn body(seen: &Seen) -> Value {
    bodies(seen).pop().expect("a request")
}

#[tokio::test]
async fn requests_are_sigv4_signed_with_an_access_key() {
    let server = MockServer::start().await;
    let emm = emm(&server, true).await;
    let seen = mount(&server, "list-modules", json!({ "modules": [], "total": 0 })).await;
    emm.list_modules().await.unwrap();
    assert!(seen.lock().unwrap()[0].1.starts_with("AWS4-HMAC-SHA256 "));
}

#[tokio::test]
async fn requests_carry_the_bearer_token_without_an_access_key() {
    let server = MockServer::start().await;
    let emm = emm(&server, false).await;
    let seen = mount(&server, "list-modules", json!({ "modules": [], "total": 0 })).await;
    emm.list_modules().await.unwrap();
    assert!(seen.lock().unwrap()[0].1.starts_with("Bearer "));
}

#[tokio::test]
async fn list_modules_parses_modules_and_instances() {
    let server = MockServer::start().await;
    let emm = emm(&server, false).await;
    mount(
        &server,
        "list-modules",
        json!({
            "modules": [{
                "name": "esm", "executable": "/opt/euclid/bin/euclid-esm", "socketPath": "/run/esm.sock",
                "active": true, "core": true, "desiredStopped": false, "autoRestart": true,
                "maxRestarts": 5, "minInstances": 1, "maxInstances": 4,
                "desiredMinInstances": -1, "desiredMaxInstances": 6, "desiredThreads": -1,
                "logLevel": "", "created": "2026-11-01T00:00:00Z", "modified": "2026-11-07T00:00:00Z",
                "lastStartTime": null,
                "instances": [{
                    "instanceId": "esm-1", "pid": 4711, "host": "", "state": "RUNNING",
                    "socketPath": "/run/esm-1.sock", "httpPort": 0, "restartCount": 2,
                    "utilisation": 0.25, "backlog": 3, "loadReportedAt": "2026-11-07T10:00:00Z",
                    "backgroundTasks": 1, "started": "2026-11-07T09:00:00Z",
                    "created": "2026-11-01T00:00:00Z", "modified": "2026-11-07T10:00:00Z"
                }, {
                    "instanceId": "esm-2", "pid": -1, "state": "STOPPED", "utilisation": -1, "backlog": -1
                }]
            }],
            "total": 1
        }),
    )
    .await;

    let listing = emm.list_modules().await.unwrap();
    assert_eq!(listing.total, 1);
    let module = &listing.modules[0];
    assert_eq!(module.name.as_deref(), Some("esm"));
    assert!(module.active && module.core && module.auto_restart && !module.desired_stopped);
    assert_eq!((module.min_instances, module.max_instances), (1, 4));
    assert_eq!((module.desired_min_instances, module.desired_max_instances), (-1, 6));
    assert_eq!(module.desired_threads, -1);
    assert_eq!(module.last_start_time, None);
    let first = &module.instances[0];
    assert_eq!(first.pid, 4711);
    assert_eq!(first.state.as_deref(), Some("RUNNING"));
    assert_eq!(first.utilisation, 0.25);
    assert_eq!((first.backlog, first.background_tasks, first.restart_count), (3, 1, 2));
    let second = &module.instances[1];
    assert_eq!((second.pid, second.backlog, second.utilisation), (-1, -1, -1.0));
}

#[tokio::test]
async fn missing_pending_limits_read_as_nothing_pending() {
    let server = MockServer::start().await;
    let emm = emm(&server, false).await;
    mount(
        &server,
        "list-modules",
        json!({ "modules": [{ "name": "eqs", "instances": [{}] }] }),
    )
    .await;
    let module = emm.list_modules().await.unwrap().modules.remove(0);
    assert_eq!(module.desired_min_instances, -1);
    assert_eq!(module.desired_max_instances, -1);
    assert_eq!(module.desired_threads, -1);
    assert_eq!(module.instances[0].pid, -1);
    assert_eq!(module.instances[0].utilisation, -1.0);
}

#[tokio::test]
async fn start_stop_and_restart_send_the_module_name() {
    let server = MockServer::start().await;
    let emm = emm(&server, false).await;
    let start = mount(
        &server,
        "start-module",
        json!({ "name": "eqs", "stopped": false, "runningInstances": 0 }),
    )
    .await;
    let stop = mount(
        &server,
        "stop-module",
        json!({ "name": "eqs", "stopped": true, "runningInstances": 2 }),
    )
    .await;
    let restart = mount(
        &server,
        "restart-module",
        json!({ "name": "eqs", "runningInstances": 2 }),
    )
    .await;

    let started = emm.start_module("eqs").await.unwrap();
    assert!(!started.stopped);
    let stopped = emm.stop_module("eqs").await.unwrap();
    assert!(stopped.stopped);
    assert_eq!(stopped.running_instances, 2);
    assert_eq!(emm.restart_module("eqs").await.unwrap().running_instances, 2);

    for seen in [&start, &stop, &restart] {
        assert_eq!(body(seen), json!({ "name": "eqs" }));
    }
}

#[tokio::test]
async fn set_instances_leaves_out_a_limit_not_given() {
    let server = MockServer::start().await;
    let emm = emm(&server, false).await;
    let seen = mount(
        &server,
        "set-instances",
        json!({ "name": "esm", "minInstances": 1, "maxInstances": 8, "runningInstances": 2 }),
    )
    .await;

    emm.set_instances("esm", 1, 8).await.unwrap();
    assert_eq!(
        body(&seen),
        json!({ "name": "esm", "minInstances": 1, "maxInstances": 8 })
    );

    let answer = emm
        .set_instances_with(&SetInstancesRequest {
            name: "esm".into(),
            max_instances: Some(8),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(body(&seen), json!({ "name": "esm", "maxInstances": 8 }));
    assert_eq!(
        (answer.min_instances, answer.max_instances, answer.running_instances),
        (1, 8, 2)
    );
}

#[tokio::test]
async fn set_threads_and_log_level() {
    let server = MockServer::start().await;
    let emm = emm(&server, false).await;
    let threads = mount(
        &server,
        "set-threads",
        json!({ "name": "esm", "threads": 16, "runningInstances": 3 }),
    )
    .await;
    let level = mount(
        &server,
        "set-log-level",
        json!({ "name": "esm", "logLevel": "debug", "channel": "module.esm" }),
    )
    .await;

    let answer = emm.set_threads("esm", 16).await.unwrap();
    assert_eq!((answer.threads, answer.running_instances), (16, 3));
    assert_eq!(body(&threads), json!({ "name": "esm", "threads": 16 }));

    let answer = emm.set_log_level("esm", "DEBUG").await.unwrap();
    assert_eq!(answer.log_level.as_deref(), Some("debug"));
    assert_eq!(answer.channel.as_deref(), Some("module.esm"));
    assert_eq!(body(&level), json!({ "name": "esm", "level": "DEBUG" }));

    emm.set_log_level("esm", "default").await.unwrap();
    assert_eq!(body(&level), json!({ "name": "esm", "level": "" }));
}

#[tokio::test]
async fn backups_are_listed_and_created() {
    let server = MockServer::start().await;
    let emm = emm(&server, false).await;
    mount(
        &server,
        "list-backups",
        json!({
            "directory": "/var/euclid/backup", "enabled": true, "schedule": "0 1 * * *", "keep": 7,
            "full": false, "encrypted": true,
            "backups": [{
                "name": "euclid-20261107.zip", "path": "/var/euclid/backup/euclid-20261107.zip",
                "accountId": "", "namespace": "", "startedAt": "2026-11-07T01:00:00Z",
                "modified": "2026-11-07T01:02:00Z", "size": 123456, "complete": true
            }]
        }),
    )
    .await;
    let create = mount_with(&server, "create-backup", |_| {
        ResponseTemplate::new(202).set_body_json(json!({
            "name": "euclid-20261107-1200.zip", "directory": "/var/euclid/backup",
            "startedAt": "2026-11-07T12:00:00Z", "full": true, "encrypted": false
        }))
    })
    .await;

    let listing = emm.list_backups().await.unwrap();
    assert!(listing.enabled && listing.encrypted && !listing.full);
    assert_eq!(listing.keep, 7);
    assert_eq!(listing.schedule.as_deref(), Some("0 1 * * *"));
    assert_eq!(listing.backups[0].size, 123456);
    assert!(listing.backups[0].complete);

    let started = emm.create_backup(None).await.unwrap();
    assert_eq!(started.name.as_deref(), Some("euclid-20261107-1200.zip"));
    assert!(started.full);
    assert_eq!(body(&create), json!({}));
    emm.create_backup(Some(true)).await.unwrap();
    assert_eq!(body(&create), json!({ "full": true }));
}

#[tokio::test]
async fn a_plain_export_returns_the_server_document_verbatim() {
    let server = MockServer::start().await;
    let emm = emm(&server, false).await;
    let document =
        r#"{"modules":["esm"],"full":false,"exportedAt":"2026-11-07T12:00:00Z","collections":{"esm_bucket":[]}}"#;
    let seen = mount_with(&server, "export", move |_| {
        ResponseTemplate::new(200).set_body_raw(document, "application/json")
    })
    .await;

    assert_eq!(emm.export(&["esm"]).await.unwrap(), document);
    assert_eq!(body(&seen), json!({ "full": false, "modules": ["esm"] }));

    emm.export_with(&ExportRequest {
        all: true,
        full: true,
        ..Default::default()
    })
    .await
    .unwrap();
    assert_eq!(body(&seen), json!({ "full": true, "all": true }));
}

#[tokio::test]
async fn export_needs_exactly_one_of_all_and_modules() {
    let server = MockServer::start().await;
    let emm = emm(&server, false).await;
    let neither = emm.export_with(&ExportRequest::default()).await.unwrap_err();
    assert!(matches!(neither, Error::InvalidArgument(_)));
    let both = emm
        .export_with(&ExportRequest {
            all: true,
            modules: vec!["esm".into()],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(matches!(both, Error::InvalidArgument(_)));
}

#[tokio::test]
async fn a_sealed_export_asks_per_module_with_one_salt_and_collects_the_frames() {
    let server = MockServer::start().await;
    let emm = emm(&server, false).await;
    let seen = mount_with(&server, "export", |body| {
        let module = body["modules"][0].as_str().unwrap().to_owned();
        ResponseTemplate::new(200).set_body_json(json!({
            "encrypted": true, "modules": [module.clone()], "full": false,
            "exportedAt": "2026-11-07T12:00:00Z", "kdf": "pbkdf2-sha256", "iterations": 600000,
            "salt": "c2FsdA", "cipher": "aes-256-gcm", "data": format!("sealed-{module}")
        }))
    })
    .await;

    let document = emm
        .export_with(&ExportRequest {
            modules: vec!["ekm".into(), "ess".into()],
            passphrase: Some("open sesame".into()),
            ..Default::default()
        })
        .await
        .unwrap();

    let sent = bodies(&seen);
    assert_eq!(
        sent,
        vec![
            json!({ "full": false, "modules": ["ekm"], "passphrase": "open sesame" }),
            json!({ "full": false, "modules": ["ess"], "passphrase": "open sesame", "salt": "c2FsdA" }),
        ]
    );
    let document: Value = serde_json::from_str(&document).unwrap();
    assert_eq!(document["modules"], json!(["ekm", "ess"]));
    assert_eq!(document["frames"], json!(["sealed-ekm", "sealed-ess"]));
    assert_eq!(document["salt"], json!("c2FsdA"));
    assert_eq!(document["encrypted"], json!(true));
    assert!(document.get("data").is_none());
}

#[tokio::test]
async fn import_sends_the_document_with_filter_and_parses_the_answer() {
    let server = MockServer::start().await;
    let emm = emm(&server, false).await;
    let seen = mount(
        &server,
        "import",
        json!({
            "imported": { "esm_bucket": { "imported": 3 }, "esm_object": { "imported": 10, "failed": 1 } },
            "skipped": [{ "collection": "nope", "reason": "unknown collection" }]
        }),
    )
    .await;

    let answer = emm
        .import_with(&ImportRequest {
            document: r#"{"collections":{"esm_bucket":[]}}"#.into(),
            modules: vec!["esm".into()],
            passphrase: None,
        })
        .await
        .unwrap();
    assert_eq!(
        body(&seen),
        json!({ "collections": { "esm_bucket": [] }, "modules": ["esm"] })
    );
    assert_eq!(
        answer.imported["esm_bucket"],
        ImportedCollection { imported: 3, failed: 0 }
    );
    assert_eq!(
        answer.imported["esm_object"],
        ImportedCollection {
            imported: 10,
            failed: 1
        }
    );
    assert_eq!(answer.skipped[0].reason.as_deref(), Some("unknown collection"));
}

#[tokio::test]
async fn a_sealed_import_carries_the_passphrase() {
    let server = MockServer::start().await;
    let emm = emm(&server, false).await;
    let seen = mount(&server, "import", json!({ "imported": {}, "skipped": [] })).await;
    emm.import_with(&ImportRequest {
        document: r#"{"encrypted":true,"salt":"c2FsdA","frames":["a","b"]}"#.into(),
        passphrase: Some("open sesame".into()),
        ..Default::default()
    })
    .await
    .unwrap();
    assert_eq!(
        body(&seen),
        json!({ "encrypted": true, "salt": "c2FsdA", "frames": ["a", "b"], "passphrase": "open sesame" })
    );
}

#[tokio::test]
async fn import_refuses_what_cannot_work_without_sending() {
    let server = MockServer::start().await;
    let emm = emm(&server, false).await;
    let seen = mount(&server, "import", json!({})).await;

    for request in [
        ImportRequest {
            document: "not json".into(),
            ..Default::default()
        },
        ImportRequest {
            document: "[]".into(),
            ..Default::default()
        },
        ImportRequest {
            document: r#"{"something":"else"}"#.into(),
            ..Default::default()
        },
        ImportRequest {
            document: r#"{"frames":[]}"#.into(),
            ..Default::default()
        },
        ImportRequest {
            document: r#"{"collections":{}}"#.into(),
            passphrase: Some("pw".into()),
            ..Default::default()
        },
    ] {
        let err = emm.import_with(&request).await.unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "{err:?}");
    }
    assert!(bodies(&seen).is_empty());
}

#[tokio::test]
async fn passphrases_and_documents_stay_out_of_debug_output() {
    let export = ExportRequest {
        all: true,
        passphrase: Some("open sesame".into()),
        ..Default::default()
    };
    let import = ImportRequest {
        document: r#"{"collections":{"ess_secret":[{"value":"hunter2"}]}}"#.into(),
        passphrase: Some("open sesame".into()),
        ..Default::default()
    };
    let printed = format!("{export:?} {import:?}");
    assert!(!printed.contains("open sesame"));
    assert!(!printed.contains("hunter2"));
    assert!(printed.contains("<redacted>"));
}

#[tokio::test]
async fn a_non_admin_gets_a_403_service_error() {
    let server = MockServer::start().await;
    let emm = emm(&server, false).await;
    mount_with(&server, "list-modules", |_| {
        ResponseTemplate::new(403).set_body_json(json!({ "message": "administrator privileges required" }))
    })
    .await;
    let err = emm.list_modules().await.unwrap_err();
    assert_eq!(err.status(), Some(403));
    assert!(matches!(err, Error::Service { .. }));
}
