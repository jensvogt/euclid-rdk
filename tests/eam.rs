//! EAM against a mock server: login, caching, request headers, federated login and a few typed
//! operations.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use euclid_rdk::eam::{
    GrantRoleRequest, ListAccountsRequest, ListNamespacesRequest, ListRolesRequest, ListUserGroupsRequest,
    ListUsersRequest, MatchType, OidcAuthorizeRequest, RegisterRequest, SamlAcsRequest, SamlAuthorizeRequest,
};
use euclid_rdk::{Eam, Error};
use serde_json::{json, Value};
use wiremock::matchers::{body_json, body_partial_json, header, method, path};
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

fn my_accounts() -> Value {
    json!({
        "accounts": [
            { "accountId": "408066031601", "name": "development", "ern": "ern:eam::408066031601:account" },
            { "accountId": "863459426936", "name": "home" },
            { "accountId": "999", "name": "999" }
        ],
        "total": 3,
        "homeAccountId": "863459426936"
    })
}

async fn mount_my_accounts(server: &MockServer, expected_calls: u64) {
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "list-my-accounts"))
        .and(body_json(json!({})))
        .respond_with(ResponseTemplate::new(200).set_body_json(my_accounts()))
        .expect(expected_calls)
        .mount(server)
        .await;
}

#[tokio::test]
async fn change_userid_and_email_name_the_user_and_return_it() {
    let server = MockServer::start().await;
    mount_login(&server, &jwt(3600), 1).await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "change-userid"))
        .and(body_json(json!({ "userId": "bob", "newUserId": "robert" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "user": { "userId": "robert", "ern": "ern:eam::863459426936:user/robert", "email": "bob@example.com" }
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "change-email"))
        .and(body_json(json!({ "userId": "robert", "email": "robert@example.com" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "user": { "userId": "robert", "email": "robert@example.com" }
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "change-email"))
        .and(body_json(json!({ "userId": "robert", "email": "taken@example.com" })))
        .respond_with(ResponseTemplate::new(409).set_body_string("Email address already in use by user: alice"))
        .mount(&server)
        .await;

    let session = Eam::for_server(server.uri())
        .credentials("jens", "secret")
        .no_cache()
        .no_ca_cert()
        .login()
        .await
        .unwrap();
    let renamed = session.change_userid("bob", "robert").await.unwrap();
    assert_eq!(renamed.user_id.as_deref(), Some("robert"));
    assert_eq!(renamed.ern.as_deref(), Some("ern:eam::863459426936:user/robert"));

    let changed = session.change_email("robert", "robert@example.com").await.unwrap();
    assert_eq!(changed.email.as_deref(), Some("robert@example.com"));

    let err = session.change_email("robert", "taken@example.com").await.unwrap_err();
    assert_eq!(err.status(), Some(409));
}

#[tokio::test]
async fn list_my_accounts_parses_and_resolves_by_id_then_name() {
    let server = MockServer::start().await;
    mount_login(&server, &jwt(3600), 1).await;
    mount_my_accounts(&server, 1).await;
    let session = Eam::for_server(server.uri())
        .credentials("jens", "secret")
        .no_cache()
        .no_ca_cert()
        .login()
        .await
        .unwrap();

    let mine = session.list_my_accounts().await.unwrap();
    assert_eq!(mine.total, 3);
    assert_eq!(mine.home_account_id.as_deref(), Some("863459426936"));
    assert_eq!(mine.accounts[0].name.as_deref(), Some("development"));
    assert_eq!(mine.resolve("408066031601"), Some("408066031601"));
    assert_eq!(mine.resolve("development"), Some("408066031601"));
    assert_eq!(mine.resolve("999"), Some("999"));
    assert_eq!(mine.resolve("nope"), None);
    assert_eq!(mine.resolve(""), None);
}

#[tokio::test]
async fn login_with_account_works_in_it_before_choosing_the_namespace() {
    let server = MockServer::start().await;
    let token = jwt(3600);
    mount_login(&server, &token, 1).await;
    mount_my_accounts(&server, 1).await;
    // The namespace is checked against the account switched to, so the request must carry it.
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "change-namespace"))
        .and(header("x-euclid-account-id", "408066031601"))
        .and(body_json(json!({ "namespace": "dev" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "list-users"))
        .and(header("x-euclid-account-id", "408066031601"))
        .and(header("x-euclid-namespace", "dev"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "users": [], "total": 0 })))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("credentials");
    let session = Eam::for_server(server.uri())
        .credentials("jens", "secret")
        .account("development")
        .namespace("dev")
        .credentials_file(&cache)
        .no_ca_cert()
        .login()
        .await
        .unwrap();
    assert_eq!(session.account_id(), Some("408066031601"));
    assert_eq!(session.namespace(), Some("dev"));
    session.list_users(&ListUsersRequest::default()).await.unwrap();

    let cached: Value = serde_json::from_str(&std::fs::read_to_string(&cache).unwrap()).unwrap();
    assert_eq!(cached["accountId"], "408066031601");
    assert_eq!(cached["namespace"], "dev");

    // Reusing the cache with the same account asks nothing more of the server: list-my-accounts
    // and login are each expected exactly once.
    let again = Eam::for_server(server.uri())
        .account("408066031601")
        .credentials_file(&cache)
        .no_ca_cert()
        .login()
        .await
        .unwrap();
    assert_eq!(again.account_id(), Some("408066031601"));
    assert_eq!(again.namespace(), Some("dev"));
}

#[tokio::test]
async fn login_with_a_foreign_account_fails_but_keeps_the_home_session() {
    let server = MockServer::start().await;
    mount_login(&server, &jwt(3600), 1).await;
    mount_my_accounts(&server, 1).await;
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("credentials");

    let err = Eam::for_server(server.uri())
        .credentials("jens", "secret")
        .account("production")
        .namespace("prod")
        .credentials_file(&cache)
        .no_ca_cert()
        .login()
        .await
        .unwrap_err();
    match err {
        Error::InvalidArgument(message) => {
            assert!(
                message.starts_with("'production' is not an account you may work in"),
                "{message}"
            );
            assert!(message.contains("408066031601 (development)"), "{message}");
            assert!(message.contains("863459426936 (home)"), "{message}");
            // Named after itself: shown by id alone.
            assert!(message.ends_with(", 999"), "{message}");
        }
        other => panic!("unexpected error {other:?}"),
    }

    let cached: Value = serde_json::from_str(&std::fs::read_to_string(&cache).unwrap()).unwrap();
    assert_eq!(cached["accountId"], "863459426936");
    assert_eq!(cached["namespace"], "");
}

#[tokio::test]
async fn switch_account_clears_the_namespace_and_updates_the_cache() {
    let server = MockServer::start().await;
    mount_login(&server, &jwt(3600), 1).await;
    mount_my_accounts(&server, 2).await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "change-namespace"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("credentials");
    let mut session = Eam::for_server(server.uri())
        .credentials("jens", "secret")
        .namespace("prod")
        .credentials_file(&cache)
        .no_ca_cert()
        .login()
        .await
        .unwrap();
    assert_eq!(session.namespace(), Some("prod"));

    session.switch_account("development").await.unwrap();
    assert_eq!(session.account_id(), Some("408066031601"));
    assert_eq!(session.namespace(), None);
    let cached: Value = serde_json::from_str(&std::fs::read_to_string(&cache).unwrap()).unwrap();
    assert_eq!(cached["accountId"], "408066031601");
    assert_eq!(cached["namespace"], "");

    assert!(matches!(
        session.switch_account("elsewhere").await,
        Err(Error::InvalidArgument(_))
    ));
    assert_eq!(session.account_id(), Some("408066031601"));
}

#[tokio::test]
async fn refresh_session_adopts_the_new_token_and_keeps_account_and_namespace() {
    let server = MockServer::start().await;
    let old = jwt(3600);
    let new = jwt(7200);
    mount_login(&server, &old, 1).await;
    mount_my_accounts(&server, 1).await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "change-namespace"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "refresh-session"))
        .and(header("authorization", format!("Bearer {old}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(login_body(&new)))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "get-user"))
        .and(header("authorization", format!("Bearer {new}").as_str()))
        .and(header("x-euclid-account-id", "408066031601"))
        .and(header("x-euclid-namespace", "dev"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "user": { "userId": "jens" } })))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("credentials");
    let mut session = Eam::for_server(server.uri())
        .credentials("jens", "secret")
        .account("408066031601")
        .namespace("dev")
        .credentials_file(&cache)
        .no_ca_cert()
        .login()
        .await
        .unwrap();

    session.refresh_session().await.unwrap();
    assert_eq!(session.token(), new);
    assert_eq!(session.account_id(), Some("408066031601"));
    assert_eq!(session.namespace(), Some("dev"));
    session.get_user("jens").await.unwrap();

    let cached: Value = serde_json::from_str(&std::fs::read_to_string(&cache).unwrap()).unwrap();
    assert_eq!(cached["token"], new.as_str());
    assert_eq!(cached["accountId"], "408066031601");
}

// ---------------------------------------------------------------------------------------------
// Federated login
// ---------------------------------------------------------------------------------------------

/// A login response as EAM answers every way in with it.
fn federated_login_body() -> Value {
    json!({
        "token": "fed-token",
        "accessKeyId": "AKIAFED",
        "secretAccessKey": "s3cr3t",
        "createdAt": "2026-01-01T00:00:00Z",
        "isAdmin": false,
        "metadata": { "region": "eu-central-1", "accountId": "863459426936", "user": "carol" }
    })
}

/// Plays the browser: follows the URL to wherever it points - in these tests the listener's own
/// callback - from a task of its own, since the listener only answers once the hook has returned.
fn visit(url: &str) {
    let url = url.to_owned();
    tokio::spawn(async move {
        let _ = reqwest::get(url).await;
    });
}

fn body_of(request: &Request) -> Value {
    serde_json::from_slice(&request.body).unwrap_or(Value::Null)
}

/// Answers `oidc-authorize` with an authorization URL that is the listener's own redirect URI with
/// `query` on it - what a provider's redirect amounts to once the person has signed in - and
/// records the redirect URI it was given.
async fn mount_oidc_authorize(server: &MockServer, query: &'static str, state: &'static str) -> Arc<Mutex<String>> {
    let redirect_uri = Arc::new(Mutex::new(String::new()));
    let seen = redirect_uri.clone();
    Mock::given(method("POST"))
        .and(header("x-euclid-target", "eam"))
        .and(header("x-euclid-action", "oidc-authorize"))
        .respond_with(move |request: &Request| {
            let uri = body_of(request)["redirectUri"].as_str().unwrap_or_default().to_owned();
            *seen.lock().unwrap() = uri.clone();
            ResponseTemplate::new(200).set_body_json(json!({
                "authorizationUrl": format!("{uri}?{query}"),
                "state": state
            }))
        })
        .mount(server)
        .await;
    redirect_uri
}

#[tokio::test]
async fn login_with_oidc_redeems_the_code_the_browser_brought_back() {
    let server = MockServer::start().await;
    let redirect_uri = mount_oidc_authorize(&server, "code=c0de&state=s3aled", "s3aled").await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "oidc-login"))
        .and(body_json(json!({ "code": "c0de", "state": "s3aled" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(federated_login_body()))
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("credentials");

    let session = Eam::for_server(server.uri())
        .credentials_file(&cache)
        .no_ca_cert()
        .browser(visit)
        .login_with_oidc()
        .await
        .unwrap();

    let redirect_uri = redirect_uri.lock().unwrap().clone();
    assert!(
        redirect_uri.starts_with("http://127.0.0.1:"),
        "the code has to come back to this machine"
    );
    assert!(redirect_uri.ends_with("/callback"));
    assert_eq!(session.token(), "fed-token");
    assert_eq!(session.user_id(), Some("carol"));
    assert_eq!(session.access_key_id(), Some("AKIAFED"));

    let cached: Value = serde_json::from_str(&std::fs::read_to_string(&cache).unwrap()).unwrap();
    assert_eq!(
        cached["token"], "fed-token",
        "a federated session is cached like any other"
    );
}

// EAM would refuse a state it did not seal anyway, but the code must not even be spent on a
// callback that belongs to some other login attempt.
#[tokio::test]
async fn login_with_oidc_refuses_a_callback_from_another_attempt() {
    let server = MockServer::start().await;
    mount_oidc_authorize(&server, "code=c0de&state=somebody-elses", "mine").await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "oidc-login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(federated_login_body()))
        .expect(0)
        .mount(&server)
        .await;

    let err = Eam::for_server(server.uri())
        .no_cache()
        .no_ca_cert()
        .browser(visit)
        .login_with_oidc()
        .await
        .unwrap_err();

    match err {
        Error::Authentication { status, body } => {
            assert_eq!(status, 401);
            assert!(body.contains("does not belong to this login attempt"), "{body}");
        }
        other => panic!("expected an authentication error, got {other:?}"),
    }
}

#[tokio::test]
async fn login_with_oidc_surfaces_the_providers_refusal() {
    let server = MockServer::start().await;
    mount_oidc_authorize(&server, "error=access_denied&error_description=not+for+you", "s").await;

    let err = Eam::for_server(server.uri())
        .no_cache()
        .no_ca_cert()
        .browser(visit)
        .login_with_oidc()
        .await
        .unwrap_err();

    assert!(
        matches!(&err, Error::Authentication { body, .. } if body.contains("access_denied (not for you)")),
        "{err:?}"
    );
}

#[tokio::test]
async fn login_with_oidc_gives_up_when_the_browser_never_comes_back() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "oidc-authorize"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "authorizationUrl": "https://idp.example.com/authorize",
            "state": "s"
        })))
        .mount(&server)
        .await;

    let err = Eam::for_server(server.uri())
        .no_cache()
        .no_ca_cert()
        .browser(|_| {})
        .callback_timeout(Duration::from_millis(200))
        .login_with_oidc()
        .await
        .unwrap_err();

    assert!(
        matches!(&err, Error::Io(e) if e.kind() == std::io::ErrorKind::TimedOut),
        "{err:?}"
    );
}

#[tokio::test]
async fn login_with_oidc_surfaces_a_server_that_cannot_start_the_flow() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "oidc-authorize"))
        .respond_with(ResponseTemplate::new(404).set_body_string(r#"{"error":"OIDC is not enabled"}"#))
        .mount(&server)
        .await;

    let err = Eam::for_server(server.uri())
        .no_cache()
        .no_ca_cert()
        .browser(|_| panic!("the browser must not be needed"))
        .login_with_oidc()
        .await
        .unwrap_err();

    assert!(
        matches!(&err, Error::Service { action, status: 404, .. } if action == "oidc-authorize"),
        "{err:?}"
    );
}

// A stray request - a browser asking for the favicon - must not consume the login.
#[tokio::test]
async fn the_callback_listener_ignores_requests_that_are_not_the_callback() {
    let server = MockServer::start().await;
    mount_oidc_authorize(&server, "code=c&state=s", "s").await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "oidc-login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(federated_login_body()))
        .mount(&server)
        .await;
    let favicon_status = Arc::new(Mutex::new(None));
    let seen = favicon_status.clone();

    let session = Eam::for_server(server.uri())
        .no_cache()
        .no_ca_cert()
        .browser(move |url| {
            let url = url.to_owned();
            let seen = seen.clone();
            tokio::spawn(async move {
                let favicon = format!("{}/favicon.ico", &url[..url.find("/callback").unwrap()]);
                let status = reqwest::get(favicon).await.map(|r| r.status().as_u16()).ok();
                *seen.lock().unwrap() = status;
                let _ = reqwest::get(url).await;
            });
        })
        .login_with_oidc()
        .await
        .unwrap();

    assert_eq!(*favicon_status.lock().unwrap(), Some(404));
    assert_eq!(session.token(), "fed-token");
}

// The SAML leg ends differently: EAM posts the finished session to the listener in a form, so there
// is nothing left to redeem.
#[tokio::test]
async fn login_with_saml_takes_the_session_euclid_posts_to_the_listener() {
    let server = MockServer::start().await;
    let return_to = Arc::new(Mutex::new(String::new()));
    let seen = return_to.clone();
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "saml-authorize"))
        .respond_with(move |request: &Request| {
            *seen.lock().unwrap() = body_of(request)["returnTo"].as_str().unwrap_or_default().to_owned();
            ResponseTemplate::new(200).set_body_json(json!({
                "authenticationUrl": "https://idp.example.com/sso?SAMLRequest=x",
                "relayState": "rs"
            }))
        })
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("credentials");

    let target = return_to.clone();
    let session = Eam::for_server(server.uri())
        .credentials_file(&cache)
        .no_ca_cert()
        .browser(move |url| {
            assert!(url.starts_with("https://idp.example.com/sso"));
            // What EAM's hand-off page submits: the login response, base64url-encoded, unpadded.
            let encoded = URL_SAFE_NO_PAD.encode(federated_login_body().to_string());
            let target = target.lock().unwrap().clone();
            tokio::spawn(async move {
                let _ = reqwest::Client::new()
                    .post(target)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(format!("session={encoded}"))
                    .send()
                    .await;
            });
        })
        .login_with_saml()
        .await
        .unwrap();

    assert!(return_to.lock().unwrap().starts_with("http://127.0.0.1:"));
    assert_eq!(session.token(), "fed-token");
    assert_eq!(session.account_id(), Some("863459426936"));
    assert!(std::fs::read_to_string(&cache).unwrap().contains("fed-token"));
}

#[tokio::test]
async fn login_with_saml_refuses_a_hand_off_without_a_token() {
    let server = MockServer::start().await;
    let return_to = Arc::new(Mutex::new(String::new()));
    let seen = return_to.clone();
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "saml-authorize"))
        .respond_with(move |request: &Request| {
            *seen.lock().unwrap() = body_of(request)["returnTo"].as_str().unwrap_or_default().to_owned();
            ResponseTemplate::new(200)
                .set_body_json(json!({ "authenticationUrl": "https://idp/sso", "relayState": "rs" }))
        })
        .mount(&server)
        .await;

    let err = Eam::for_server(server.uri())
        .no_cache()
        .no_ca_cert()
        .browser(move |_| {
            let encoded = URL_SAFE_NO_PAD.encode(r#"{"metadata":{}}"#);
            let target = return_to.lock().unwrap().clone();
            tokio::spawn(async move {
                let _ = reqwest::Client::new()
                    .post(target)
                    .body(format!("session={encoded}"))
                    .send()
                    .await;
            });
        })
        .login_with_saml()
        .await
        .unwrap_err();

    assert!(
        matches!(&err, Error::Authentication { status: 401, body } if body.contains("did not contain a token")),
        "{err:?}"
    );
}

#[tokio::test]
async fn login_with_saml_assertion_hands_the_assertion_to_the_consumer_service() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(header("x-euclid-target", "eam"))
        .and(header("x-euclid-action", "saml-acs"))
        .and(body_json(json!({ "samlResponse": "PHNhbWw+", "relayState": "" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(federated_login_body()))
        .expect(1)
        .mount(&server)
        .await;

    let session = Eam::for_server(server.uri())
        .no_cache()
        .no_ca_cert()
        .login_with_saml_assertion(&SamlAcsRequest {
            saml_response: "PHNhbWw+".into(),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(session.token(), "fed-token");
}

#[tokio::test]
async fn login_with_saml_assertion_surfaces_a_refused_assertion() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "saml-acs"))
        .respond_with(ResponseTemplate::new(401).set_body_string(r#"{"error":"Unsolicited logins are not enabled"}"#))
        .mount(&server)
        .await;

    let err = Eam::for_server(server.uri())
        .no_cache()
        .no_ca_cert()
        .login_with_saml_assertion(&SamlAcsRequest {
            saml_response: "x".into(),
            ..Default::default()
        })
        .await
        .unwrap_err();

    assert!(matches!(err, Error::Authentication { status: 401, .. }), "{err:?}");
}

#[tokio::test]
async fn federated_building_blocks_speak_the_wire_format() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "oidc-authorize"))
        .and(body_json(
            json!({ "redirectUri": "", "returnTo": "https://app.example.com/" }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "authorizationUrl": "https://idp.example.com/authorize?state=st",
            "state": "st"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "saml-authorize"))
        .and(body_json(json!({ "returnTo": "" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "authenticationUrl": "https://idp.example.com/sso",
            "relayState": "rs"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let eam = Eam::for_server(server.uri()).no_cache().no_ca_cert();

    let oidc = eam
        .oidc_authorize(&OidcAuthorizeRequest {
            return_to: "https://app.example.com/".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(oidc.state.as_deref(), Some("st"));
    assert_eq!(
        oidc.authorization_url.as_deref(),
        Some("https://idp.example.com/authorize?state=st")
    );

    let saml = eam.saml_authorize(&SamlAuthorizeRequest::default()).await.unwrap();
    assert_eq!(saml.relay_state.as_deref(), Some("rs"));
    assert_eq!(saml.authentication_url.as_deref(), Some("https://idp.example.com/sso"));
}

// Going through the browser again within the hour is exactly what the cache is for.
#[tokio::test]
async fn federated_login_reuses_a_still_valid_cached_session() {
    let server = MockServer::start().await;
    let token = jwt(3600);
    mount_login(&server, &token, 1).await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "oidc-authorize"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("credentials");
    Eam::for_server(server.uri())
        .credentials("jens", "secret")
        .credentials_file(&cache)
        .no_ca_cert()
        .login()
        .await
        .unwrap();

    let session = Eam::for_server(server.uri())
        .credentials_file(&cache)
        .no_ca_cert()
        .browser(|_| panic!("the browser must not be needed"))
        .login_with_oidc()
        .await
        .unwrap();

    assert_eq!(session.token(), token);
}

// ---------------------------------------------------------------------------------------------
// Refreshing
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn refresh_session_leaves_somebody_elses_cached_session_alone() {
    let server = MockServer::start().await;
    mount_login(&server, &jwt(3600), 1).await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "refresh-session"))
        .respond_with(ResponseTemplate::new(200).set_body_json(login_body(&jwt(7200))))
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("credentials");
    let mut session = Eam::for_server(server.uri())
        .credentials("jens", "secret")
        .credentials_file(&cache)
        .no_ca_cert()
        .login()
        .await
        .unwrap();
    let theirs = json!({ "token": "theirs", "userId": "dave", "baseUrl": server.uri() }).to_string();
    std::fs::write(&cache, &theirs).unwrap();

    session.refresh_session().await.unwrap();

    assert_eq!(std::fs::read_to_string(&cache).unwrap(), theirs);
}

#[tokio::test]
async fn refresh_session_surfaces_an_expired_token() {
    let server = MockServer::start().await;
    mount_login(&server, &jwt(3600), 1).await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "refresh-session"))
        .respond_with(ResponseTemplate::new(401).set_body_string(r#"{"error":"Bearer token expired"}"#))
        .mount(&server)
        .await;
    let mut session = login_without_cache(&server).await;

    let err = session.refresh_session().await.unwrap_err();

    assert!(
        matches!(&err, Error::Service { action, status: 401, .. } if action == "refresh-session"),
        "{err:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// Match types, and the fields added alongside them
// ---------------------------------------------------------------------------------------------

async fn login_without_cache(server: &MockServer) -> euclid_rdk::Session {
    Eam::for_server(server.uri())
        .credentials("jens", "secret")
        .no_cache()
        .no_ca_cert()
        .login()
        .await
        .unwrap()
}

// Absent is "prefix" server-side, so a listing that names no match type keeps meaning what it did.
#[tokio::test]
async fn listings_without_a_match_type_leave_it_out() {
    let server = MockServer::start().await;
    mount_login(&server, &jwt(3600), 1).await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "list-users"))
        .and(|request: &Request| body_of(request).get("matchType").is_none())
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "users": [], "total": 0 })))
        .expect(1)
        .mount(&server)
        .await;
    let session = login_without_cache(&server).await;

    session.list_users(&ListUsersRequest::default()).await.unwrap();
}

#[tokio::test]
async fn every_listing_carries_the_match_type_it_was_given() {
    let server = MockServer::start().await;
    mount_login(&server, &jwt(3600), 1).await;
    for (action, expected) in [
        ("list-users", json!({ "prefix": "ob", "matchType": "endsWith" })),
        ("list-user-groups", json!({ "prefix": "ops", "matchType": "contains" })),
        ("list-accounts", json!({ "prefix": "^86", "matchType": "regex" })),
        (
            "list-namespaces",
            json!({ "accountId": "863459426936", "prefix": "pro", "matchType": "prefix", "pageSize": 0 }),
        ),
        ("list-roles", json!({ "prefix": "read", "matchType": "contains" })),
    ] {
        Mock::given(method("POST"))
            .and(header("x-euclid-action", action))
            .and(body_partial_json(expected))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "total": 0 })))
            .expect(1)
            .mount(&server)
            .await;
    }
    let session = login_without_cache(&server).await;

    session
        .list_users(&ListUsersRequest {
            prefix: "ob".into(),
            match_type: Some(MatchType::EndsWith),
            ..Default::default()
        })
        .await
        .unwrap();
    session
        .list_user_groups(&ListUserGroupsRequest {
            prefix: "ops".into(),
            match_type: Some(MatchType::Contains),
            ..Default::default()
        })
        .await
        .unwrap();
    session
        .list_accounts(&ListAccountsRequest {
            prefix: "^86".into(),
            match_type: Some(MatchType::Regex),
            ..Default::default()
        })
        .await
        .unwrap();
    session
        .list_namespaces(&ListNamespacesRequest {
            account_id: "863459426936".into(),
            prefix: "pro".into(),
            match_type: Some(MatchType::Prefix),
            page_size: 0,
            ..Default::default()
        })
        .await
        .unwrap();
    session
        .list_roles(&ListRolesRequest {
            prefix: "read".into(),
            match_type: Some(MatchType::Contains),
            ..Default::default()
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn a_match_type_the_server_cannot_use_is_surfaced() {
    let server = MockServer::start().await;
    mount_login(&server, &jwt(3600), 1).await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "list-users"))
        .respond_with(ResponseTemplate::new(400).set_body_string(r#"{"error":"Invalid regular expression"}"#))
        .mount(&server)
        .await;
    let session = login_without_cache(&server).await;

    let err = session
        .list_users(&ListUsersRequest {
            prefix: "(".into(),
            match_type: Some(MatchType::Regex),
            ..Default::default()
        })
        .await
        .unwrap_err();

    assert!(
        matches!(&err, Error::Service { action, status: 400, .. } if action == "list-users"),
        "{err:?}"
    );
}

#[tokio::test]
async fn register_returns_the_user_as_stored() {
    let server = MockServer::start().await;
    mount_login(&server, &jwt(3600), 1).await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "register"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "user": { "userId": "bob", "ern": "ern:eam::863459426936:user/bob", "password": "" },
            "metadata": { "region": "eu-central-1", "accountId": "863459426936", "user": "jens" }
        })))
        .expect(1)
        .mount(&server)
        .await;
    let session = login_without_cache(&server).await;

    let response = session
        .register(&RegisterRequest {
            user_id: "bob".into(),
            password: "s3cret".into(),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(response.user.user_id.as_deref(), Some("bob"));
    assert_eq!(
        response.user.ern.as_deref(),
        Some("ern:eam::863459426936:user/bob"),
        "the ERN is built server-side and only known from here"
    );
    assert_eq!(response.metadata.unwrap().user.as_deref(), Some("jens"));
}

#[tokio::test]
async fn describe_permissions_keeps_the_modules_a_list_of_names_drops() {
    let server = MockServer::start().await;
    mount_login(&server, &jwt(3600), 1).await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "list-permissions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "permissions": ["eqs:send-message", "ens:publish-message"],
            "modules": ["ens", "eqs"],
            "unbindableModules": ["emd", "emm"],
            "metadata": {}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let session = login_without_cache(&server).await;

    let response = session.describe_permissions().await.unwrap();

    assert_eq!(response.permissions, ["eqs:send-message", "ens:publish-message"]);
    assert_eq!(response.modules, ["ens", "eqs"]);
    assert_eq!(response.unbindable_modules, ["emd", "emm"]);
}
