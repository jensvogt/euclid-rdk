//! EAM against a mock server: login, caching, request headers and a few typed operations.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use euclid_rdk::eam::{GrantRoleRequest, ListUsersRequest};
use euclid_rdk::{Eam, Error};
use serde_json::{json, Value};
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

fn jwt(exp_offset: i64) -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"sub":"jens","exp":{}}}"#, now + exp_offset));
    format!("{header}.{payload}.sig")
}

fn login_body(token: &str) -> Value {
    json!({
        "token": token,
        "accessKeyId": "AKIATEST",
        "secretAccessKey": "secret-key",
        "createdAt": "2026-11-02T12:00:00Z",
        "isAdmin": true,
        "metadata": { "region": "eu-central-1", "accountId": "863459426936", "user": "jens" }
    })
}

async fn mount_login(server: &MockServer, token: &str, expected_calls: u64) {
    Mock::given(method("POST"))
        .and(path("/"))
        .and(header("x-euclid-target", "eam"))
        .and(header("x-euclid-action", "login"))
        .and(body_json(
            json!({ "userId": "jens", "password": "secret", "email": "" }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(login_body(token)))
        .expect(expected_calls)
        .mount(server)
        .await;
}

#[tokio::test]
async fn login_returns_session_and_caches_it() {
    let server = MockServer::start().await;
    let token = jwt(3600);
    mount_login(&server, &token, 1).await;
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("credentials");

    let session = Eam::for_server(format!("{}/", server.uri()))
        .credentials("jens", "secret")
        .credentials_file(&cache)
        .no_ca_cert()
        .login()
        .await
        .unwrap();

    assert_eq!(session.token(), token);
    assert_eq!(session.user_id(), Some("jens"));
    assert_eq!(session.account_id(), Some("863459426936"));
    assert_eq!(session.region(), Some("eu-central-1"));
    assert_eq!(session.access_key_id(), Some("AKIATEST"));
    assert!(session.is_admin());
    assert_eq!(session.namespace(), None);

    let cached: Value = serde_json::from_str(&std::fs::read_to_string(&cache).unwrap()).unwrap();
    assert_eq!(cached["token"], token.as_str());
    assert_eq!(cached["baseUrl"], server.uri().as_str());
    assert_eq!(cached["namespace"], "");

    // Second login is served from the cache: the mock expects exactly one login call.
    let again = Eam::for_server(server.uri())
        .credentials_file(&cache)
        .no_ca_cert()
        .login()
        .await
        .unwrap();
    assert_eq!(again.token(), token);
    assert_eq!(again.user_id(), Some("jens"));
}

#[tokio::test]
async fn expired_cache_forces_fresh_login() {
    let server = MockServer::start().await;
    mount_login(&server, &jwt(3600), 1).await;
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("credentials");
    std::fs::write(
        &cache,
        json!({ "token": jwt(-10), "userId": "jens", "baseUrl": server.uri(), "namespace": "" }).to_string(),
    )
    .unwrap();

    let eam = Eam::for_server(server.uri()).credentials_file(&cache).no_ca_cert();
    // Nothing valid cached and no credentials given.
    assert!(matches!(eam.clone().login().await, Err(Error::InvalidArgument(_))));

    eam.credentials("jens", "secret").login().await.unwrap();
}

#[tokio::test]
async fn rejected_login_is_an_authentication_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "login"))
        .respond_with(ResponseTemplate::new(401).set_body_string("invalid credentials"))
        .mount(&server)
        .await;

    let err = Eam::for_server(server.uri())
        .credentials("jens", "wrong")
        .no_cache()
        .no_ca_cert()
        .login()
        .await
        .unwrap_err();
    match err {
        Error::Authentication { status, body } => {
            assert_eq!(status, 401);
            assert_eq!(body, "invalid credentials");
        }
        other => panic!("unexpected error {other:?}"),
    }
}

#[tokio::test]
async fn email_login_sends_only_the_email() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_json(
            json!({ "userId": "", "password": "secret", "email": "jens@example.com" }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(login_body(&jwt(3600))))
        .expect(1)
        .mount(&server)
        .await;

    Eam::for_server(server.uri())
        .email("jens@example.com")
        .password("secret")
        .no_cache()
        .no_ca_cert()
        .login()
        .await
        .unwrap();
}

#[tokio::test]
async fn namespace_is_applied_and_sent_on_later_requests() {
    let server = MockServer::start().await;
    let token = jwt(3600);
    mount_login(&server, &token, 1).await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "change-namespace"))
        .and(header("authorization", format!("Bearer {token}").as_str()))
        .and(body_json(json!({ "namespace": "prod" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "list-users"))
        .and(header("x-euclid-namespace", "prod"))
        .and(header("x-euclid-account-id", "863459426936"))
        .and(header("x-euclid-region", "eu-central-1"))
        .and(header("x-euclid-user-id", "jens"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "users": [{ "userId": "jens", "email": "jens@example.com", "created": 1730548800 }],
            "total": 1
        })))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("credentials");
    let session = Eam::for_server(server.uri())
        .credentials("jens", "secret")
        .namespace("prod")
        .credentials_file(&cache)
        .no_ca_cert()
        .login()
        .await
        .unwrap();
    assert_eq!(session.namespace(), Some("prod"));

    let cached: Value = serde_json::from_str(&std::fs::read_to_string(&cache).unwrap()).unwrap();
    assert_eq!(cached["namespace"], "prod");

    let users = session.list_users(&ListUsersRequest::default()).await.unwrap();
    assert_eq!(users.total, 1);
    assert_eq!(users.users[0].user_id.as_deref(), Some("jens"));
    // A numeric timestamp is read as text rather than failing the response.
    assert_eq!(users.users[0].created.as_deref(), Some("1730548800"));
}

#[tokio::test]
async fn service_errors_carry_action_and_status() {
    let server = MockServer::start().await;
    mount_login(&server, &jwt(3600), 1).await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "get-user"))
        .respond_with(ResponseTemplate::new(404).set_body_string("user not found"))
        .mount(&server)
        .await;

    let session = Eam::for_server(server.uri())
        .credentials("jens", "secret")
        .no_cache()
        .no_ca_cert()
        .login()
        .await
        .unwrap();
    let err = session.get_user("nobody").await.unwrap_err();
    assert_eq!(err.status(), Some(404));
    assert_eq!(err.to_string(), "eam get-user failed with status 404: user not found");
}

#[tokio::test]
async fn grant_role_defaults_to_account_wide_scope() {
    let server = MockServer::start().await;
    mount_login(&server, &jwt(3600), 1).await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "grant-role"))
        .respond_with(|req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            assert_eq!(body["namespaces"], json!(["*"]));
            assert_eq!(body["resources"], json!(["*"]));
            ResponseTemplate::new(200).set_body_json(json!({
                "grant": { "grantId": "g-1", "role": body["role"], "principal": body["principal"],
                           "namespaces": ["*"], "resources": ["*"], "unknownField": 1 }
            }))
        })
        .mount(&server)
        .await;

    let session = Eam::for_server(server.uri())
        .credentials("jens", "secret")
        .no_cache()
        .no_ca_cert()
        .login()
        .await
        .unwrap();
    let grant = session
        .grant_role(&GrantRoleRequest {
            role: "operator".into(),
            principal: "bob".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(grant.grant_id.as_deref(), Some("g-1"));
    assert_eq!(grant.role.as_deref(), Some("operator"));
}

#[tokio::test]
async fn reset_password_refuses_own_user() {
    let server = MockServer::start().await;
    mount_login(&server, &jwt(3600), 1).await;
    let session = Eam::for_server(server.uri())
        .credentials("jens", "secret")
        .no_cache()
        .no_ca_cert()
        .login()
        .await
        .unwrap();
    assert!(matches!(
        session.reset_password("jens", "x").await,
        Err(Error::InvalidArgument(_))
    ));
}
