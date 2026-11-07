//! EAG against a mock server: authentication, request bodies, response parsing, errors.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use euclid_rdk::eag::{Protocol, RouteAuthentication, RouteRequest, RouteType, UploadSpec};
use euclid_rdk::{Eag, Eam, Error};
use serde_json::{json, Value};
use wiremock::matchers::{header, method};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

type Seen = Arc<Mutex<Vec<(Value, String)>>>;

fn jwt() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{}}}"#, now + 3600));
    format!("{}.{payload}.sig", URL_SAFE_NO_PAD.encode(b"{}"))
}

async fn eag(server: &MockServer, with_access_key: bool) -> Eag {
    let mut login = json!({
        "token": jwt(),
        "isAdmin": true,
        "metadata": { "region": "eu-central-1", "accountId": "000000000000", "user": "admin" }
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
        .credentials("admin", "pw")
        .no_cache()
        .no_ca_cert()
        .login()
        .await
        .unwrap()
        .eag()
}

/// Mounts `action` answering `answer`, recording each request's body and authorization header.
async fn mount(server: &MockServer, action: &str, answer: Value) -> Seen {
    let seen: Seen = Arc::default();
    let record = seen.clone();
    Mock::given(method("POST"))
        .and(header("x-euclid-target", "eag"))
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

fn last(seen: &Seen) -> (Value, String) {
    seen.lock().unwrap().last().expect("a request").clone()
}

fn route_json() -> Value {
    json!({
        "routeId": "produkte", "ern": "ern:eag:eu-central-1:000000000000:development:route:produkte",
        "accountId": "000000000000", "region": "eu-central-1", "namespace": "development",
        "path": "/api/produkte", "applicationId": "app-1", "moduleTarget": "", "moduleAction": "",
        "methods": ["GET", "POST"], "authentication": "euclid", "active": false,
        "created": "2026-11-01T10:00:00Z", "modified": 1762000000
    })
}

#[tokio::test]
async fn requests_are_sigv4_signed_with_an_access_key_and_bearer_without() {
    let server = MockServer::start().await;
    let seen = mount(&server, "list-routes", json!({ "routes": [] })).await;
    eag(&server, true).await.list_routes("").await.unwrap();
    assert!(last(&seen).1.starts_with("AWS4-HMAC-SHA256 Credential=AKIATEST/"));
    assert!(last(&seen).1.contains("/eag/aws4_request"));

    let server = MockServer::start().await;
    let seen = mount(&server, "list-routes", json!({ "routes": [] })).await;
    eag(&server, false).await.list_routes("").await.unwrap();
    assert!(last(&seen).1.starts_with("Bearer "));
}

#[tokio::test]
async fn create_route_sends_only_what_was_given() {
    let server = MockServer::start().await;
    let seen = mount(&server, "create-route", route_json()).await;
    let eag = eag(&server, true).await;

    let route = eag.create_route("produkte", "/api/produkte", "app-1").await.unwrap();
    assert_eq!(
        last(&seen).0,
        json!({ "routeId": "produkte", "path": "/api/produkte", "applicationId": "app-1" })
    );
    assert_eq!(route.route_id.as_deref(), Some("produkte"));
    assert_eq!(route.methods, ["GET", "POST"]);
    assert_eq!(route.authentication, RouteAuthentication::Euclid);
    assert!(!route.active);
    assert!(!route.is_module_route());
    assert_eq!(route.modified.as_deref(), Some("1762000000"));

    eag.create_module_route("login", "/api/login", "eam", "login")
        .await
        .unwrap();
    assert_eq!(
        last(&seen).0,
        json!({ "routeId": "login", "path": "/api/login", "moduleTarget": "eam", "moduleAction": "login" })
    );

    eag.create_route_with(&RouteRequest {
        route_id: Some("r".into()),
        path: Some("/p".into()),
        application_id: Some("a".into()),
        methods: Some(vec!["GET".into()]),
        namespace: Some("development".into()),
        authentication: Some(RouteAuthentication::None),
        active: Some(true),
        ..Default::default()
    })
    .await
    .unwrap();
    assert_eq!(
        last(&seen).0,
        json!({ "routeId": "r", "path": "/p", "applicationId": "a", "methods": ["GET"],
                "namespace": "development", "authentication": "NONE", "active": true })
    );
}

#[tokio::test]
async fn set_route_active_updates_only_the_flag() {
    let server = MockServer::start().await;
    let seen = mount(&server, "update-route", route_json()).await;
    let route = eag(&server, true)
        .await
        .set_route_active("produkte", false)
        .await
        .unwrap();
    assert_eq!(last(&seen).0, json!({ "routeId": "produkte", "active": false }));
    assert_eq!(route.path.as_deref(), Some("/api/produkte"));
}

#[tokio::test]
async fn list_get_and_delete_routes() {
    let server = MockServer::start().await;
    let list = mount(
        &server,
        "list-routes",
        json!({ "routes": [route_json(), { "routeId": "bare" }] }),
    )
    .await;
    let get = mount(&server, "get-route", route_json()).await;
    let delete = mount(&server, "delete-route", json!({})).await;
    let eag = eag(&server, true).await;

    let routes = eag.list_routes("/api").await.unwrap();
    assert_eq!(last(&list).0, json!({ "prefix": "/api" }));
    assert_eq!(routes.len(), 2);
    // A route the server describes without these fields reads as active, with unknown auth.
    assert!(routes[1].active);
    assert_eq!(routes[1].authentication, RouteAuthentication::Unknown);
    assert!(routes[1].methods.is_empty());

    let route = eag.get_route("produkte").await.unwrap();
    assert_eq!(last(&get).0, json!({ "routeId": "produkte" }));
    assert_eq!(route.application_id.as_deref(), Some("app-1"));

    eag.delete_route("produkte").await.unwrap();
    assert_eq!(last(&delete).0, json!({ "routeId": "produkte" }));
}

#[tokio::test]
async fn module_route_is_recognised() {
    let server = MockServer::start().await;
    mount(
        &server,
        "get-route",
        json!({ "routeId": "login", "moduleTarget": "eam", "moduleAction": "login", "authentication": "NONE" }),
    )
    .await;
    let route = eag(&server, true).await.get_route("login").await.unwrap();
    assert!(route.is_module_route());
    assert_eq!(route.authentication, RouteAuthentication::None);
}

#[tokio::test]
async fn listeners_unflatten_their_certificate() {
    let server = MockServer::start().await;
    let seen = mount(
        &server,
        "list-listeners",
        json!({
            "serving": true,
            "listeners": [
                { "namespace": "development", "port": 8443, "protocol": "HTTPS", "serving": true,
                  "certificate": "eag-development", "certificateConfigured": "",
                  "certificateFound": true, "certificateErn": "ern:ekm:cert", "certificateSubject": "CN=gw",
                  "certificateIssuer": "CN=gw", "certificateSerialNumber": "01",
                  "certificateFingerprint": "AB:CD", "certificateSubjectAltNames": ["DNS:gw", "IP:10.0.0.1"],
                  "certificateGenerated": true, "certificateNotBefore": "2026-01-01T00:00:00Z",
                  "certificateNotAfter": "2027-01-01T00:00:00Z", "certificateExpired": false },
                { "namespace": "", "port": "8080", "protocol": "http", "serving": true,
                  "certificate": "", "certificateFound": false }
            ]
        }),
    )
    .await;
    let response = eag(&server, true).await.list_listeners().await.unwrap();
    assert_eq!(last(&seen).0, json!({}));
    assert!(response.serving);
    // No total from the server: the number of listeners.
    assert_eq!(response.total, 2);

    let https = &response.listeners[0];
    assert_eq!(https.port, 8443);
    assert_eq!(https.protocol, Protocol::Https);
    assert!(!https.names_certificate());
    let cert = https.certificate.as_ref().expect("certificate");
    assert_eq!(cert.subject.as_deref(), Some("CN=gw"));
    assert_eq!(cert.subject_alt_names, ["DNS:gw", "IP:10.0.0.1"]);
    assert!(cert.generated);
    assert!(!cert.expired);

    let http = &response.listeners[1];
    assert_eq!(http.port, 8080);
    assert_eq!(http.protocol, Protocol::Http);
    assert!(http.certificate.is_none());
}

#[tokio::test]
async fn listeners_total_comes_from_the_server_when_sent() {
    let server = MockServer::start().await;
    mount(&server, "list-listeners", json!({ "total": 5, "listeners": [] })).await;
    let response = eag(&server, true).await.list_listeners().await.unwrap();
    assert_eq!(response.total, 5);
    assert!(!response.serving);
    assert!(response.listeners.is_empty());
}

#[tokio::test]
async fn errors_carry_service_action_and_status() {
    let server = MockServer::start().await;
    eag(&server, true).await; // mounts login
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "get-route"))
        .respond_with(ResponseTemplate::new(403).set_body_string("administrator only"))
        .mount(&server)
        .await;
    let err = eag(&server, true).await.get_route("x").await.unwrap_err();
    assert_eq!(err.status(), Some(403));
    assert!(matches!(err, Error::Service { ref service, ref action, .. } if service == "eag" && action == "get-route"));
}

#[test]
fn enum_wire_values_round_trip() {
    for a in [
        RouteAuthentication::None,
        RouteAuthentication::Euclid,
        RouteAuthentication::Basic,
    ] {
        assert_eq!(RouteAuthentication::from_wire_value(&a.wire_value().to_lowercase()), a);
    }
    assert_eq!(
        RouteAuthentication::from_wire_value("oauth"),
        RouteAuthentication::Unknown
    );
    assert_eq!(RouteAuthentication::from_wire_value(""), RouteAuthentication::Unknown);
    assert_eq!(Protocol::from_wire_value("HTTPS"), Protocol::Https);
    assert_eq!(Protocol::from_wire_value("ftp"), Protocol::Http);
    assert_eq!(
        serde_json::to_value(RouteAuthentication::Basic).unwrap(),
        json!("BASIC")
    );
}

#[tokio::test]
async fn upload_routes_send_type_bucket_and_limits() {
    const BUCKET: &str = "ern:esm:eu-central-1:000000000000:development:bucket:inbox";
    let server = MockServer::start().await;
    let mut answer = route_json();
    answer["type"] = json!("UPLOAD");
    answer["applicationId"] = json!("");
    answer["timeout"] = json!(600);
    answer["upload"] = json!({ "bucket": BUCKET, "keyPrefix": "onix/", "maxBytes": 12_000_000_000_u64,
                               "partSize": 5_242_880, "contentTypes": ["application/xml"] });
    let seen = mount(&server, "create-route", answer).await;
    let eag = eag(&server, true).await;

    let route = eag
        .create_upload_route("onix", "/upload/onix", BUCKET, RouteAuthentication::Basic)
        .await
        .unwrap();
    assert_eq!(
        last(&seen).0,
        json!({ "routeId": "onix", "path": "/upload/onix", "type": "UPLOAD", "bucket": BUCKET,
                "authentication": "BASIC" })
    );
    assert_eq!(route.kind, RouteType::Upload);
    assert_eq!(route.timeout, 600);
    assert_eq!(route.upload.bucket.as_deref(), Some(BUCKET));
    assert_eq!(route.upload.key_prefix.as_deref(), Some("onix/"));
    assert_eq!(route.upload.max_bytes, 12_000_000_000);
    assert_eq!(route.upload.part_size, 5_242_880);
    assert_eq!(route.upload.content_types, ["application/xml"]);

    eag.create_route_with(&RouteRequest {
        route_id: Some("onix".into()),
        path: Some("/upload/onix".into()),
        kind: Some(RouteType::Upload),
        bucket: Some(BUCKET.into()),
        key_prefix: Some("onix/".into()),
        max_bytes: Some(1024),
        part_size: Some(512),
        content_types: Some(vec!["application/xml".into()]),
        timeout: Some(600),
        authentication: Some(RouteAuthentication::Euclid),
        ..Default::default()
    })
    .await
    .unwrap();
    assert_eq!(
        last(&seen).0,
        json!({ "routeId": "onix", "path": "/upload/onix", "type": "UPLOAD", "bucket": BUCKET,
                "keyPrefix": "onix/", "maxBytes": 1024, "partSize": 512,
                "contentTypes": ["application/xml"], "timeout": 600, "authentication": "EUCLID" })
    );
}

#[tokio::test]
async fn route_type_and_upload_default_when_an_older_server_leaves_them_out() {
    let server = MockServer::start().await;
    mount(&server, "get-route", route_json()).await;
    let route = eag(&server, true).await.get_route("produkte").await.unwrap();
    assert_eq!(route.kind, RouteType::Unknown);
    assert_eq!(route.timeout, 0);
    assert_eq!(route.upload, UploadSpec::default());
    assert_eq!(RouteType::from_wire_value("proxy"), RouteType::Proxy);
}
