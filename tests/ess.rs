//! ESS against a mock server: authentication, request bodies, response parsing, errors, and that
//! secret values never show up in `Debug` output.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use euclid_rdk::ess::{CreateSecretRequest, ListSecretsRequest, UpdateSecretRequest};
use euclid_rdk::{Eam, Error, Ess};
use serde_json::{json, Value};
use wiremock::matchers::{header, method};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

type Seen = Arc<std::sync::Mutex<Vec<(Value, String)>>>;

fn jwt() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{}}}"#, now + 3600));
    format!("{}.{payload}.sig", URL_SAFE_NO_PAD.encode(b"{}"))
}

async fn ess(server: &MockServer, with_access_key: bool) -> Ess {
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
        .ess()
}

/// Mounts `action` answering `answer`, recording each request's body and authorization header.
async fn mount(server: &MockServer, action: &str, answer: Value) -> Seen {
    let seen: Seen = Arc::default();
    let record = seen.clone();
    Mock::given(method("POST"))
        .and(header("x-euclid-target", "ess"))
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

fn secret_json() -> Value {
    json!({
        "name": "db-password", "ern": "ern:ess:eu-central-1:000000000000::secret:db-password",
        "description": "prod db", "encryptionKeyErn": "ern:ekm:eu-central-1:000000000000::key:k1",
        "version": 3, "rotated": "2026-11-02T10:00:00Z", "tags": { "team": "data", "tier": 1 },
        "created": "2026-11-01T10:00:00Z", "modified": "2026-11-02T10:00:00Z"
    })
}

#[tokio::test]
async fn requests_are_sigv4_signed_with_an_access_key() {
    let server = MockServer::start().await;
    let ess = ess(&server, true).await;
    let seen = mount(&server, "list-secrets", json!({ "secrets": [], "total": 0 })).await;
    ess.list_secrets(&ListSecretsRequest::default()).await.unwrap();
    let auth = seen.lock().unwrap()[0].1.clone();
    assert!(
        auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIATEST/") && auth.contains("/eu-central-1/ess/aws4_request"),
        "{auth}"
    );
}

#[tokio::test]
async fn requests_use_bearer_without_an_access_key() {
    let server = MockServer::start().await;
    let ess = ess(&server, false).await;
    let seen = mount(&server, "list-secrets", json!({ "secrets": [], "total": 0 })).await;
    ess.list_secrets(&ListSecretsRequest::default()).await.unwrap();
    assert!(seen.lock().unwrap()[0].1.starts_with("Bearer "));
}

#[tokio::test]
async fn create_secret_sends_jdk_defaults_and_parses_secret() {
    let server = MockServer::start().await;
    let ess = ess(&server, true).await;
    let seen = mount(&server, "create-secret", json!({ "secret": secret_json() })).await;

    let secret = ess.create_secret("db-password", "s3cr3t").await.unwrap();
    assert_eq!(
        body(&seen),
        json!({ "name": "db-password", "description": "", "value": "s3cr3t", "keyErn": "" })
    );
    assert_eq!(secret.name.as_deref(), Some("db-password"));
    assert_eq!(secret.version, 3);
    assert_eq!(secret.tags["team"], "data");
    assert_eq!(secret.tags["tier"], "1", "non-string tag values read as text");
    assert_eq!(
        secret.encryption_key_ern.as_deref(),
        Some("ern:ekm:eu-central-1:000000000000::key:k1")
    );
}

#[tokio::test]
async fn get_secret_returns_value() {
    let server = MockServer::start().await;
    let ess = ess(&server, true).await;
    let seen = mount(
        &server,
        "get-secret",
        json!({ "secret": secret_json(), "value": "s3cr3t" }),
    )
    .await;

    let got = ess.get_secret("db-password").await.unwrap();
    assert_eq!(body(&seen), json!({ "name": "db-password" }));
    assert_eq!(got.value.as_deref(), Some("s3cr3t"));
    assert_eq!(got.secret.unwrap().version, 3);
}

#[tokio::test]
async fn update_secret_omits_absent_fields() {
    let server = MockServer::start().await;
    let ess = ess(&server, true).await;
    let seen = mount(&server, "update-secret", json!({ "secret": secret_json() })).await;

    ess.rotate_secret("db-password", "new").await.unwrap();
    assert_eq!(body(&seen), json!({ "name": "db-password", "value": "new" }));

    // Clearing the description is `Some("")`, leaving it alone is `None`.
    ess.update_secret(&UpdateSecretRequest {
        name: "db-password".into(),
        description: Some(String::new()),
        ..Default::default()
    })
    .await
    .unwrap();
    assert_eq!(body(&seen), json!({ "name": "db-password", "description": "" }));
}

#[tokio::test]
async fn list_and_exists() {
    let server = MockServer::start().await;
    let ess = ess(&server, true).await;
    let seen = mount(
        &server,
        "list-secrets",
        json!({ "secrets": [secret_json()], "total": 1 }),
    )
    .await;

    let listing = ess.list_secrets(&ListSecretsRequest::default()).await.unwrap();
    assert_eq!(
        body(&seen),
        json!({ "prefix": "", "pageSize": 10, "pageIndex": 0, "sortColumn": "name", "sortDirection": "asc" })
    );
    assert_eq!(listing.total, 1);
    assert_eq!(listing.secrets.len(), 1);

    assert!(ess.exists_secret("db-password").await.unwrap());
    assert_eq!(body(&seen)["prefix"], "db-password");
    assert_eq!(body(&seen)["pageSize"], 0);
    // A prefix match is not an exact match.
    assert!(!ess.exists_secret("db-pass").await.unwrap());
}

#[tokio::test]
async fn tags_and_delete() {
    let server = MockServer::start().await;
    let ess = ess(&server, true).await;
    let add = mount(&server, "add-secret-tag", json!({ "secret": secret_json() })).await;
    let del = mount(&server, "delete-secret-tag", json!({ "secret": secret_json() })).await;
    let gone = mount(
        &server,
        "delete-secret",
        json!({ "ern": "ern:ess:x::secret:db-password", "name": "db-password" }),
    )
    .await;

    ess.add_secret_tag("db-password", "team", "data").await.unwrap();
    assert_eq!(
        body(&add),
        json!({ "name": "db-password", "key": "team", "value": "data" })
    );
    ess.delete_secret_tag("db-password", "team").await.unwrap();
    assert_eq!(body(&del), json!({ "name": "db-password", "key": "team" }));
    let deleted = ess.delete_secret("db-password").await.unwrap();
    assert_eq!(body(&gone), json!({ "name": "db-password" }));
    assert_eq!(deleted.name.as_deref(), Some("db-password"));
}

#[tokio::test]
async fn errors_carry_service_and_status() {
    let server = MockServer::start().await;
    let ess = ess(&server, true).await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "create-secret"))
        .respond_with(ResponseTemplate::new(409).set_body_string("secret already exists"))
        .mount(&server)
        .await;
    let err = ess.create_secret("db-password", "x").await.unwrap_err();
    assert!(matches!(&err, Error::Service { service, action, status: 409, .. }
        if service == "ess" && action == "create-secret"));
}

#[tokio::test]
async fn debug_output_redacts_secret_values() {
    let server = MockServer::start().await;
    let ess = ess(&server, true).await;
    mount(
        &server,
        "get-secret",
        json!({ "secret": secret_json(), "value": "s3cr3t" }),
    )
    .await;
    let got = ess.get_secret("db-password").await.unwrap();
    let printed = format!("{got:?}");
    assert!(
        !printed.contains("s3cr3t") && printed.contains("<redacted>"),
        "{printed}"
    );

    let create = CreateSecretRequest {
        name: "n".into(),
        value: "s3cr3t".into(),
        ..Default::default()
    };
    assert!(!format!("{create:?}").contains("s3cr3t"));
    let update = UpdateSecretRequest {
        name: "n".into(),
        value: Some("s3cr3t".into()),
        ..Default::default()
    };
    assert!(!format!("{update:?}").contains("s3cr3t"));
}
