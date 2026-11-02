//! EKM against a mock server: authentication, request bodies, binary encrypt/decrypt, response
//! parsing, errors, and that private keys and data never show up in `Debug` output.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use euclid_rdk::ekm::{
    CreateCertificateRequest, CreateKeyRequest, ImportCertificateRequest, ListKeysRequest, Sensitive,
};
use euclid_rdk::{Eam, Ekm, Error};
use serde_json::{json, Value};
use wiremock::matchers::{header, method};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

type Seen = Arc<std::sync::Mutex<Vec<(Value, String)>>>;

fn jwt() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{}}}"#, now + 3600));
    format!("{}.{payload}.sig", URL_SAFE_NO_PAD.encode(b"{}"))
}

async fn ekm(server: &MockServer, with_access_key: bool) -> Ekm {
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
        .ekm()
}

/// Mounts `action` answering `answer`, recording each request's JSON body and authorization header.
async fn mount(server: &MockServer, action: &str, answer: Value) -> Seen {
    let seen: Seen = Arc::default();
    let record = seen.clone();
    Mock::given(method("POST"))
        .and(header("x-euclid-target", "ekm"))
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

fn key_json() -> Value {
    json!({
        "name": "k1", "ern": "ern:ekm:eu-central-1:000000000000:key:k1", "description": "orders",
        "algorithm": "AES", "length": 256, "status": "AVAILABLE", "tags": { "team": "data", "tier": 1 },
        "created": "2026-11-01T10:00:00Z", "modified": "2026-11-02T10:00:00Z"
    })
}

fn certificate_json() -> Value {
    json!({
        "name": "c1", "ern": "ern:ekm:eu-central-1:000000000000:certificate:c1", "description": "",
        "certificate": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        "subject": "CN=example", "issuer": "CN=example", "serialNumber": 12345, "fingerprint": "AB:CD",
        "subjectAltNames": ["example.com", "localhost"], "generated": true,
        "notBefore": "2026-11-02T00:00:00Z", "notAfter": "2029-02-04T00:00:00Z", "tags": {}
    })
}

#[tokio::test]
async fn requests_are_sigv4_signed_with_an_access_key() {
    let server = MockServer::start().await;
    let ekm = ekm(&server, true).await;
    let seen = mount(&server, "list-keys", json!({ "keys": [], "total": 0 })).await;
    ekm.list_keys(&ListKeysRequest::default()).await.unwrap();
    let auth = seen.lock().unwrap()[0].1.clone();
    assert!(
        auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIATEST/") && auth.contains("/eu-central-1/ekm/aws4_request"),
        "{auth}"
    );
}

#[tokio::test]
async fn requests_use_bearer_without_an_access_key() {
    let server = MockServer::start().await;
    let ekm = ekm(&server, false).await;
    let seen = mount(&server, "list-keys", json!({ "keys": [], "total": 0 })).await;
    ekm.list_keys(&ListKeysRequest::default()).await.unwrap();
    assert!(seen.lock().unwrap()[0].1.starts_with("Bearer "));
}

#[tokio::test]
async fn create_key_sends_jdk_defaults() {
    let server = MockServer::start().await;
    let ekm = ekm(&server, true).await;
    let seen = mount(
        &server,
        "create-key",
        json!({ "ern": "ern:ekm:x:key:k1", "name": "k1", "description": "", "algorithm": "AES",
                "length": "128", "status": "AVAILABLE" }),
    )
    .await;

    let key = ekm.create_key().await.unwrap();
    assert_eq!(
        body(&seen),
        json!({ "algorithm": "AES", "length": 128, "description": "" })
    );
    assert_eq!(key.name.as_deref(), Some("k1"));
    assert_eq!(key.length, 128, "a numeric string is read as a number");

    ekm.create_key_with(&CreateKeyRequest {
        length: 256,
        description: "orders".into(),
        ..Default::default()
    })
    .await
    .unwrap();
    assert_eq!(
        body(&seen),
        json!({ "algorithm": "AES", "length": 256, "description": "orders" })
    );
}

#[tokio::test]
async fn list_and_get_keys_parse_and_address_by_name_or_ern() {
    let server = MockServer::start().await;
    let ekm = ekm(&server, true).await;
    let list = mount(&server, "list-keys", json!({ "keys": [key_json()], "total": 1 })).await;
    let get = mount(&server, "get-key", json!({ "key": key_json() })).await;

    let keys = ekm.list_keys(&ListKeysRequest::default()).await.unwrap();
    assert_eq!(
        body(&list),
        json!({ "prefix": "", "pageSize": 10, "pageIndex": 0, "sortColumn": "name", "sortDirection": "asc" })
    );
    assert_eq!(keys.total, 1);
    let key = &keys.keys[0];
    assert_eq!(key.length, 256);
    assert_eq!(key.tags["tier"], "1", "tag values are read as text");
    assert_eq!(key.deletion_date, None);

    ekm.get_key("k1").await.unwrap();
    assert_eq!(body(&get), json!({ "ern": null, "name": "k1" }));
    let by_ern = ekm.get_key("ern:ekm:eu-central-1:000000000000:key:k1").await.unwrap();
    assert_eq!(
        body(&get),
        json!({ "ern": "ern:ekm:eu-central-1:000000000000:key:k1", "name": null })
    );
    assert_eq!(by_ern.status.as_deref(), Some("AVAILABLE"));
}

#[tokio::test]
async fn exists_key_maps_404_to_false() {
    let server = MockServer::start().await;
    let ekm = ekm(&server, true).await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "get-key"))
        .respond_with(ResponseTemplate::new(404).set_body_string("Key not found"))
        .mount(&server)
        .await;
    assert!(!ekm.exists_key("nope").await.unwrap());
}

#[tokio::test]
async fn delete_revoke_describe_and_tag_send_jdk_bodies() {
    let server = MockServer::start().await;
    let ekm = ekm(&server, true).await;
    let delete = mount(
        &server,
        "delete-key",
        json!({ "ern": "e", "name": "k1", "deletionDate": "2026-11-09T10:00:00Z", "status": "PENDING_DELETION" }),
    )
    .await;
    let revoke = mount(
        &server,
        "revoke-key",
        json!({ "ern": "e", "name": "k1", "status": "REVOKED" }),
    )
    .await;
    let describe = mount(
        &server,
        "set-key-description",
        json!({ "ern": "e", "description": "d" }),
    )
    .await;
    let add = mount(&server, "add-key-tag", json!({})).await;
    let remove = mount(&server, "delete-key-tag", json!({})).await;

    let deleted = ekm.delete_key("k1").await.unwrap();
    assert_eq!(body(&delete), json!({ "keyId": "k1", "pendingWindowInDays": 7 }));
    assert_eq!(deleted.status.as_deref(), Some("PENDING_DELETION"));
    ekm.delete_key_after("k1", 1).await.unwrap();
    assert_eq!(body(&delete), json!({ "keyId": "k1", "pendingWindowInDays": 1 }));

    let revoked = ekm.revoke_key("e").await.unwrap();
    assert_eq!(body(&revoke), json!({ "ern": "e" }));
    assert_eq!(revoked.status.as_deref(), Some("REVOKED"));

    let described = ekm.set_key_description("e", "d").await.unwrap();
    assert_eq!(body(&describe), json!({ "ern": "e", "description": "d" }));
    assert_eq!(described.description.as_deref(), Some("d"));

    ekm.add_key_tag("e", "team", "data").await.unwrap();
    assert_eq!(body(&add), json!({ "ern": "e", "key": "team", "value": "data" }));
    ekm.delete_key_tag("e", "team").await.unwrap();
    assert_eq!(body(&remove), json!({ "ern": "e", "key": "team" }));
}

#[tokio::test]
async fn encrypt_and_decrypt_send_raw_bytes_with_bearer() {
    let server = MockServer::start().await;
    let ekm = ekm(&server, true).await;
    for (action, answer) in [("encrypt", b"CIPHER".to_vec()), ("decrypt", b"plain".to_vec())] {
        Mock::given(method("POST"))
            .and(header("x-euclid-target", "ekm"))
            .and(header("x-euclid-action", action))
            .and(header("x-euclid-key-id", "k1"))
            .and(header("content-type", "application/octet-stream"))
            .respond_with(move |req: &Request| {
                let auth = req.headers.get("authorization").unwrap().to_str().unwrap();
                assert!(auth.starts_with("Bearer "), "binary bodies are never signed: {auth}");
                assert!(req.headers.get("x-euclid-account-id").is_some());
                ResponseTemplate::new(200).set_body_bytes(answer.clone())
            })
            .expect(1)
            .mount(&server)
            .await;
    }

    let cipher = ekm.encrypt("k1", b"plain").await.unwrap();
    assert_eq!(cipher.expose(), b"CIPHER");
    let plain = ekm.decrypt("k1", cipher.expose()).await.unwrap();
    assert_eq!(plain.into_inner(), b"plain");
}

#[tokio::test]
async fn encrypt_failure_is_a_service_error() {
    let server = MockServer::start().await;
    let ekm = ekm(&server, true).await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "encrypt"))
        .respond_with(ResponseTemplate::new(409).set_body_string("Key is revoked"))
        .mount(&server)
        .await;
    let err = ekm.encrypt("k1", b"x").await.unwrap_err();
    assert!(
        matches!(&err, Error::Service { service, action, status: 409, body }
            if service == "ekm" && action == "encrypt" && body == "Key is revoked"),
        "{err:?}"
    );
}

#[tokio::test]
async fn certificates_send_jdk_bodies_and_parse() {
    let server = MockServer::start().await;
    let ekm = ekm(&server, true).await;
    let create = mount(
        &server,
        "create-certificate",
        json!({ "certificate": certificate_json() }),
    )
    .await;
    let import = mount(
        &server,
        "import-certificate",
        json!({ "certificate": certificate_json() }),
    )
    .await;
    let get = mount(&server, "get-certificate", json!({ "certificate": certificate_json() })).await;
    let list = mount(
        &server,
        "list-certificates",
        json!({ "certificates": [certificate_json()], "total": 1 }),
    )
    .await;
    let delete = mount(&server, "delete-certificate", json!({ "ern": "e", "name": "c1" })).await;

    let certificate = ekm.create_certificate("c1").await.unwrap();
    assert_eq!(
        body(&create),
        json!({ "name": "c1", "description": "", "commonName": "", "subjectAltNames": [],
                "validDays": 825, "keyBits": 2048 })
    );
    assert_eq!(certificate.serial_number.as_deref(), Some("12345"));
    assert_eq!(certificate.subject_alt_names, ["example.com", "localhost"]);
    assert!(certificate.generated);

    ekm.create_certificate_with(&CreateCertificateRequest {
        name: "c2".into(),
        common_name: "example.com".into(),
        subject_alt_names: vec!["example.com".into()],
        valid_days: 30,
        ..Default::default()
    })
    .await
    .unwrap();
    assert_eq!(body(&create)["validDays"], 30);
    assert_eq!(body(&create)["commonName"], "example.com");

    ekm.import_certificate(&ImportCertificateRequest {
        name: "c1".into(),
        description: "imported".into(),
        certificate: "CERT-PEM".into(),
        private_key: "KEY-PEM".into(),
    })
    .await
    .unwrap();
    assert_eq!(
        body(&import),
        json!({ "name": "c1", "description": "imported", "certificate": "CERT-PEM", "privateKey": "KEY-PEM" })
    );

    ekm.get_certificate("c1").await.unwrap();
    assert_eq!(body(&get), json!({ "name": "c1" }));
    let listed = ekm.list_certificates(&Default::default()).await.unwrap();
    assert_eq!(body(&list)["sortColumn"], "name");
    assert_eq!(listed.total, 1);
    assert_eq!(listed.certificates[0].name.as_deref(), Some("c1"));
    let deleted = ekm.delete_certificate("c1").await.unwrap();
    assert_eq!(body(&delete), json!({ "name": "c1" }));
    assert_eq!(deleted.name.as_deref(), Some("c1"));
}

#[test]
fn debug_output_redacts_private_keys_and_data() {
    let import = ImportCertificateRequest {
        name: "c1".into(),
        private_key: "-----BEGIN PRIVATE KEY-----TOPSECRET".into(),
        ..Default::default()
    };
    let printed = format!("{import:?}");
    assert!(!printed.contains("TOPSECRET"), "{printed}");
    assert!(printed.contains("<redacted>"));

    let data = Sensitive::new(b"TOPSECRET".to_vec());
    let printed = format!("{data:?}");
    assert!(!printed.contains("TOPSECRET"), "{printed}");
    assert_eq!(printed, "Sensitive(<redacted 9 bytes>)");
}
