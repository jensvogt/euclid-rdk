//! ESM against a mock server: signing vs bearer, wire shapes, binary bodies and multipart
//! transfers.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use euclid_rdk::esm::{Attributes, ListBucketsRequest, TransferOptions, Variant};
use euclid_rdk::{Eam, Error, Esm};
use serde_json::{json, Value};
use wiremock::matchers::{body_bytes, body_json, header, header_exists, method};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const BUCKET: &str = "ern:esm:eu-central-1:000000000000:development:bucket:b";

fn jwt() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256"}"#);
    let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{}}}"#, now + 3600));
    format!("{header}.{payload}.sig")
}

/// A session against `server` holding an access key, so JSON calls are SigV4-signed.
async fn esm(server: &MockServer) -> Esm {
    Mock::given(header("x-euclid-action", "login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "token": jwt(),
            "accessKeyId": "AKIATEST",
            "secretAccessKey": "secret-key",
            "metadata": { "region": "eu-central-1", "accountId": "000000000000", "user": "jvo" }
        })))
        .mount(server)
        .await;
    Eam::for_server(server.uri())
        .credentials("jvo", "pw")
        .no_cache()
        .no_ca_cert()
        .login()
        .await
        .unwrap()
        .esm()
}

fn header_of(req: &Request, name: &str) -> String {
    req.headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

#[tokio::test]
async fn json_calls_are_signed_and_buckets_parse() {
    let server = MockServer::start().await;
    let esm = esm(&server).await;
    Mock::given(method("POST"))
        .and(header("x-euclid-target", "esm"))
        .and(header("x-euclid-action", "list-buckets"))
        .and(header("x-euclid-account-id", "000000000000"))
        .and(header_exists("x-amz-date"))
        .and(header_exists("x-amz-content-sha256"))
        .and(body_json(json!({
            "prefix": "", "pageSize": 10, "pageIndex": 0, "sortColumn": "name", "sortDirection": "asc"
        })))
        .respond_with(|req: &Request| {
            assert!(header_of(req, "authorization").starts_with("AWS4-HMAC-SHA256 Credential=AKIATEST/"));
            ResponseTemplate::new(200).set_body_json(json!({
                "buckets": [{
                    "created": "2026-10-02T20:53:44.600000000Z", "directories": 0, "encrypted": false,
                    "encryptionKeyErn": "", "ern": BUCKET, "internal": false, "name": "b",
                    "objects": 5712858, "owner": "eap", "priority": "", "size": 1291967880515u64,
                    "stopped": false, "tags": { "euclid:application": "file-copy" }
                }],
                "total": 1
            }))
        })
        .expect(1)
        .mount(&server)
        .await;

    let listed = esm.list_buckets(&ListBucketsRequest::default()).await.unwrap();
    assert_eq!(listed.total, 1);
    let bucket = &listed.buckets[0];
    assert_eq!(bucket.objects, 5_712_858);
    assert_eq!(bucket.size, 1_291_967_880_515);
    assert_eq!(bucket.tags["euclid:application"], "file-copy");
}

#[tokio::test]
async fn create_bucket_omits_an_unset_priority() {
    let server = MockServer::start().await;
    let esm = esm(&server).await;
    Mock::given(header("x-euclid-action", "create-bucket"))
        .and(body_json(json!({ "name": "b" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "name": "b", "ern": BUCKET })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(header("x-euclid-action", "create-bucket"))
        .and(body_json(json!({ "name": "c", "priority": "HIGH" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "name": "c" })))
        .expect(1)
        .mount(&server)
        .await;

    assert_eq!(esm.create_bucket("b", None).await.unwrap().ern.as_deref(), Some(BUCKET));
    esm.create_bucket("c", Some("HIGH")).await.unwrap();
}

#[tokio::test]
async fn delete_and_purge_read_both_answer_shapes() {
    let server = MockServer::start().await;
    let esm = esm(&server).await;
    Mock::given(header("x-euclid-action", "delete-bucket"))
        .and(body_json(json!({ "ern": BUCKET, "async": false })))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    Mock::given(header("x-euclid-action", "purge-bucket"))
        .and(body_json(json!({ "ern": BUCKET, "prefix": "tmp/", "async": true })))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "ern": BUCKET, "objects": 42, "jobId": "j1", "async": true })),
        )
        .mount(&server)
        .await;

    let deleted = esm.delete_bucket(BUCKET, false).await.unwrap();
    assert_eq!(deleted.count, 0);
    assert!(!deleted.is_async);

    let purged = esm.purge_bucket(BUCKET, "tmp/", true).await.unwrap();
    assert_eq!(purged.count, 42);
    assert_eq!(purged.job_id.as_deref(), Some("j1"));
    assert!(purged.is_async);
}

#[tokio::test]
async fn exists_bucket_is_false_on_404_only() {
    let server = MockServer::start().await;
    let esm = esm(&server).await;
    Mock::given(header("x-euclid-action", "get-bucket-ern"))
        .and(body_json(json!({ "name": "missing" })))
        .respond_with(ResponseTemplate::new(404).set_body_string("bucket not found"))
        .mount(&server)
        .await;
    Mock::given(header("x-euclid-action", "get-bucket-ern"))
        .and(body_json(json!({ "name": "broken" })))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;

    assert!(!esm.exists_bucket("missing").await.unwrap());
    let err = esm.exists_bucket("broken").await.unwrap_err();
    assert_eq!(err.to_string(), "esm get-bucket-ern failed with status 500: boom");
}

#[tokio::test]
async fn put_object_sends_raw_bytes_with_bearer_and_attributes() {
    let server = MockServer::start().await;
    let esm = esm(&server).await;
    Mock::given(header("x-euclid-action", "put-object"))
        .and(header("x-euclid-bucket-ern", BUCKET))
        .and(header("x-euclid-key", "dir/hello.bin"))
        .and(header("content-type", "application/octet-stream"))
        .and(body_bytes(vec![0u8, 1, 2, 255]))
        .respond_with(|req: &Request| {
            assert!(header_of(req, "authorization").starts_with("Bearer "));
            assert!(req.headers.get("x-amz-date").is_none());
            let attrs: Value = serde_json::from_str(&header_of(req, "x-euclid-attributes")).unwrap();
            assert_eq!(attrs, json!({ "kind": { "type": "string", "value": "Grüße" } }));
            assert!(req.headers.get("x-euclid-system-attributes").is_none());
            ResponseTemplate::new(200).set_body_json(json!({
                "ern": "ern:obj", "bucketErn": BUCKET, "key": "dir/hello.bin", "size": 4,
                "status": "UPLOADED", "contentType": "application/octet-stream", "md5Sum": "abc"
            }))
        })
        .expect(1)
        .mount(&server)
        .await;

    let mut attributes = Attributes::new();
    attributes.insert("kind".into(), Variant::string("Grüße"));
    let put = esm
        .put_object_with(
            BUCKET,
            "dir/hello.bin",
            vec![0u8, 1, 2, 255],
            &attributes,
            &Attributes::new(),
        )
        .await
        .unwrap();
    assert_eq!(put.size, 4);
    assert_eq!(put.md5_sum.as_deref(), Some("abc"));
}

#[tokio::test]
async fn get_object_returns_bytes_and_maps_errors() {
    let server = MockServer::start().await;
    let esm = esm(&server).await;
    Mock::given(header("x-euclid-action", "get-object"))
        .and(header("x-euclid-key", "a"))
        .and(header("x-euclid-part-size", "1024"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![9u8, 8, 7]))
        .mount(&server)
        .await;
    Mock::given(header("x-euclid-action", "get-object"))
        .and(header("x-euclid-key", "missing"))
        .respond_with(ResponseTemplate::new(404).set_body_string("object not found"))
        .mount(&server)
        .await;

    assert_eq!(esm.get_object(BUCKET, "a", 1024).await.unwrap(), vec![9u8, 8, 7]);
    match esm.get_object(BUCKET, "missing", 1024).await.unwrap_err() {
        Error::Service { action, status, .. } => assert_eq!((action.as_str(), status), ("get-object", 404)),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn small_file_goes_up_in_one_put() {
    let server = MockServer::start().await;
    let esm = esm(&server).await;
    Mock::given(header("x-euclid-action", "put-object"))
        .and(body_bytes(b"tiny".to_vec()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "size": 4 })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(header("x-euclid-action", "create-upload"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("tiny.txt");
    std::fs::write(&file, b"tiny").unwrap();
    let done = esm
        .upload_file(BUCKET, "tiny.txt", &file, &TransferOptions::default())
        .await
        .unwrap();
    assert_eq!(done.size, 4);
}

#[tokio::test]
async fn large_file_goes_up_in_parts_with_retry() {
    let server = MockServer::start().await;
    let esm = esm(&server).await;
    let content: Vec<u8> = (0..25u8).collect();

    Mock::given(header("x-euclid-action", "create-upload"))
        .and(header("x-euclid-expected-concurrency", "2"))
        .and(body_json(json!({ "bucketErn": BUCKET, "key": "big" })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "uploadId": "u1", "bucketErn": BUCKET, "key": "big" })),
        )
        .expect(1)
        .mount(&server)
        .await;
    // Part 2 fails once with a 503 and must be retried.
    Mock::given(header("x-euclid-action", "upload-part"))
        .and(header("x-euclid-part-number", "2"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    type Parts = Arc<Mutex<Vec<(u64, Vec<u8>)>>>;
    let parts: Parts = Arc::default();
    let seen = parts.clone();
    Mock::given(header("x-euclid-action", "upload-part"))
        .and(header("x-euclid-upload-id", "u1"))
        .and(header("content-type", "application/octet-stream"))
        .respond_with(move |req: &Request| {
            assert!(header_of(req, "authorization").starts_with("Bearer "));
            let number = header_of(req, "x-euclid-part-number").parse().unwrap();
            seen.lock().unwrap().push((number, req.body.clone()));
            ResponseTemplate::new(200).set_body_json(json!({ "uploadId": "u1", "partNumber": number }))
        })
        .with_priority(2)
        .mount(&server)
        .await;
    Mock::given(header("x-euclid-action", "complete-upload"))
        .and(body_json(json!({ "uploadId": "u1" })))
        .respond_with(|req: &Request| {
            assert!(header_of(req, "authorization").starts_with("AWS4-HMAC-SHA256"));
            let system: Value = serde_json::from_str(&header_of(req, "x-euclid-system-attributes")).unwrap();
            assert_eq!(system["priority"]["value"], "HIGH");
            ResponseTemplate::new(200).set_body_json(json!({ "ern": "ern:obj", "size": 25, "status": "UPLOADED" }))
        })
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("big.bin");
    std::fs::write(&file, &content).unwrap();
    let mut options = TransferOptions {
        part_size: 10,
        concurrency: 2,
        ..Default::default()
    };
    options
        .system_attributes
        .insert("priority".into(), Variant::string("HIGH"));

    let done = esm.upload_file(BUCKET, "big", &file, &options).await.unwrap();
    assert_eq!(done.size, 25);

    let mut parts = parts.lock().unwrap().clone();
    parts.sort();
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0], (1, content[0..10].to_vec()));
    assert_eq!(parts[1], (2, content[10..20].to_vec()));
    assert_eq!(parts[2], (3, content[20..25].to_vec()));
}

#[tokio::test]
async fn failed_part_aborts_the_upload() {
    let server = MockServer::start().await;
    let esm = esm(&server).await;
    Mock::given(header("x-euclid-action", "create-upload"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "uploadId": "u2" })))
        .mount(&server)
        .await;
    Mock::given(header("x-euclid-action", "upload-part"))
        .respond_with(ResponseTemplate::new(400).set_body_string("bad part"))
        .mount(&server)
        .await;
    Mock::given(header("x-euclid-action", "abort-upload"))
        .and(body_json(json!({ "uploadId": "u2" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "uploadId": "u2", "parts": 0 })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(header("x-euclid-action", "complete-upload"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("f");
    std::fs::write(&file, [1u8; 30]).unwrap();
    let options = TransferOptions {
        part_size: 10,
        ..Default::default()
    };
    let err = esm.upload_file(BUCKET, "f", &file, &options).await.unwrap_err();
    assert_eq!(err.status(), Some(400));
}

#[tokio::test]
async fn download_file_inline_and_in_parts() {
    let server = MockServer::start().await;
    let esm = esm(&server).await;
    let content: Vec<u8> = (100..125u8).collect();

    Mock::given(header("x-euclid-action", "get-object"))
        .and(header("x-euclid-key", "small"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"inline".to_vec()))
        .mount(&server)
        .await;
    Mock::given(header("x-euclid-action", "get-object"))
        .and(header("x-euclid-key", "big"))
        .and(header("x-euclid-part-size", "10"))
        .respond_with(ResponseTemplate::new(413).set_body_string("too large"))
        .mount(&server)
        .await;
    Mock::given(header("x-euclid-action", "create-download"))
        .and(header("x-euclid-expected-concurrency", "3"))
        .and(body_json(json!({ "bucketErn": BUCKET, "key": "big" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "downloadId": "d1", "size": 25 })))
        .expect(1)
        .mount(&server)
        .await;
    let served = content.clone();
    Mock::given(header("x-euclid-action", "download-part"))
        .and(header("x-euclid-download-id", "d1"))
        .and(header("x-euclid-part-size", "10"))
        .respond_with(move |req: &Request| {
            assert!(header_of(req, "authorization").starts_with("Bearer "));
            let number: usize = header_of(req, "x-euclid-part-number").parse().unwrap();
            let start = (number - 1) * 10;
            let end = (start + 10).min(served.len());
            ResponseTemplate::new(200).set_body_bytes(served[start..end].to_vec())
        })
        .expect(3)
        .mount(&server)
        .await;
    Mock::given(header("x-euclid-action", "complete-download"))
        .and(body_json(json!({ "downloadId": "d1" })))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let options = TransferOptions {
        part_size: 10,
        concurrency: 3,
        ..Default::default()
    };

    let small = dir.path().join("nested/small");
    assert_eq!(esm.download_file(BUCKET, "small", &small, &options).await.unwrap(), 6);
    assert_eq!(std::fs::read(&small).unwrap(), b"inline");

    let big = dir.path().join("big");
    assert_eq!(esm.download_file(BUCKET, "big", &big, &options).await.unwrap(), 25);
    assert_eq!(std::fs::read(&big).unwrap(), content);
}

#[tokio::test]
async fn download_bucket_refuses_escaping_keys() {
    let server = MockServer::start().await;
    let esm = esm(&server).await;
    Mock::given(header("x-euclid-action", "list-objects"))
        .and(body_json(json!({
            "bucketErn": BUCKET, "prefix": "p/", "pageSize": 1000, "pageIndex": 0,
            "sortColumn": "key", "sortDirection": "asc", "includeDirectories": false
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "objects": [{ "key": "p/../../evil", "size": 1 }], "total": 1
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let err = esm
        .download_bucket(BUCKET, dir.path(), "p/", true, &TransferOptions::default())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InvalidArgument(_)), "{err:?}");
}

#[tokio::test]
async fn attributes_and_subscriptions_round_trip() {
    let server = MockServer::start().await;
    let esm = esm(&server).await;
    Mock::given(header("x-euclid-action", "set-object-attribute"))
        .and(body_json(
            json!({ "ern": "ern:obj", "name": "n", "value": { "type": "number", "value": 3 } }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ern": "ern:obj", "name": "n", "value": { "type": "number", "value": 3 }
        })))
        .mount(&server)
        .await;
    Mock::given(header("x-euclid-action", "subscribe"))
        .and(body_json(json!({
            "sourceErn": BUCKET, "type": "EQS", "targetErn": "ern:q",
            "eventTypes": [], "prefix": "", "directories": false
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ern": "ern:sub", "sourceErn": BUCKET, "type": "EQS", "targetErn": "ern:q"
        })))
        .mount(&server)
        .await;

    let attr = esm
        .set_object_attribute("ern:obj", "n", &Variant::new("number", 3))
        .await
        .unwrap();
    assert_eq!(attr.value.unwrap().as_text().as_deref(), Some("3"));

    let sub = esm
        .subscribe(&euclid_rdk::esm::SubscribeRequest {
            source_ern: BUCKET.into(),
            kind: "EQS".into(),
            target_ern: "ern:q".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(sub.kind.as_deref(), Some("EQS"));

    let event =
        euclid_rdk::esm::BucketEvent::parse(r#"{"eventType":"OBJECT_CREATED","bucketErn":"b","key":"k","size":"12"}"#)
            .unwrap();
    assert_eq!(event.size, 12);
    assert_eq!(event.event_type.as_deref(), Some("OBJECT_CREATED"));
}
