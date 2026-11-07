//! ESM against a mock server: signing vs bearer, wire shapes, binary bodies and multipart
//! transfers.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use euclid_rdk::esm::{Attributes, LifecycleRule, ListBucketsRequest, TransferOptions, Variant};
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

#[tokio::test]
async fn bucket_versioning_sends_only_what_is_set() {
    let server = MockServer::start().await;
    let esm = esm(&server).await;
    Mock::given(header("x-euclid-action", "set-bucket-versioning"))
        .and(body_json(json!({ "ern": BUCKET, "enabled": true })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ern": BUCKET, "name": "b", "versioning": true, "maxVersions": 0
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(header("x-euclid-action", "set-bucket-versioning"))
        .and(body_json(json!({ "ern": BUCKET, "maxVersions": 5 })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ern": BUCKET, "name": "b", "versioning": true, "maxVersions": 5
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(header("x-euclid-action", "get-bucket"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "bucket": { "ern": BUCKET, "name": "b", "versioning": true, "maxVersions": 5 }
        })))
        .mount(&server)
        .await;

    let on = esm.set_bucket_versioning(BUCKET, Some(true), None).await.unwrap();
    assert!(on.versioning);
    assert_eq!(on.max_versions, 0);
    let limited = esm.set_bucket_versioning(BUCKET, None, Some(5)).await.unwrap();
    assert_eq!(limited.max_versions, 5);
    let bucket = esm.get_bucket(BUCKET).await.unwrap();
    assert!(bucket.versioning);
    assert_eq!(bucket.max_versions, 5);
}

#[tokio::test]
async fn object_versions_list_delete_and_download() {
    let server = MockServer::start().await;
    let esm = esm(&server).await;
    let object = format!("{BUCKET}/k");
    Mock::given(header("x-euclid-action", "list-object-versions"))
        .and(body_json(json!({ "bucketErn": BUCKET, "key": "k" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "bucketErn": BUCKET, "key": "k", "ern": object, "versioning": true, "maxVersions": 3,
            "versions": [
                { "versionId": "v2", "latest": true, "size": 4, "md5Sum": "m2", "contentType": "text/plain",
                  "status": "COMPLETED", "lifecycleState": "STANDARD", "owner": "jvo",
                  "modified": "2026-11-06T10:00:00Z" },
                { "versionId": "v1", "latest": false, "size": 3, "status": "COMPLETED",
                  "lifecycleState": "ARCHIVED" }
            ],
            "total": 2
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(header("x-euclid-action", "delete-object"))
        .and(body_json(json!({ "ern": object, "versionId": "v1" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ern": object, "versionId": "v1", "currentVersionId": "v2"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(header("x-euclid-action", "delete-object"))
        .and(body_json(json!({ "ern": object, "versionId": "v2" })))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(header("x-euclid-action", "get-object"))
        .and(header("x-euclid-version-id", "v1"))
        .respond_with(ResponseTemplate::new(413).set_body_string("too large"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(header("x-euclid-action", "create-download"))
        .and(body_json(json!({ "bucketErn": BUCKET, "key": "k", "versionId": "v1" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "downloadId": "d1", "size": 3 })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(header("x-euclid-action", "download-part"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"old".to_vec()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(header("x-euclid-action", "complete-download"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let listed = esm.list_object_versions(BUCKET, "k").await.unwrap();
    assert_eq!((listed.total, listed.max_versions), (2, 3));
    assert!(listed.versions[0].latest);
    assert_eq!(listed.versions[1].version_id.as_deref(), Some("v1"));
    assert_eq!(listed.versions[1].lifecycle_state.as_deref(), Some("ARCHIVED"));

    let deleted = esm.delete_object_version(&object, "v1").await.unwrap();
    assert_eq!(deleted.current_version_id.as_deref(), Some("v2"));
    // The last version left goes with the object, which answers with no body.
    let last = esm.delete_object_version(&object, "v2").await.unwrap();
    assert_eq!(
        (last.version_id.as_deref(), last.current_version_id),
        (Some("v2"), None)
    );
    assert!(matches!(
        esm.delete_object_version(&object, "").await,
        Err(Error::InvalidArgument(_))
    ));

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("k");
    let options = TransferOptions {
        part_size: 10,
        version_id: Some("v1".into()),
        ..Default::default()
    };
    assert_eq!(esm.download_file(BUCKET, "k", &file, &options).await.unwrap(), 3);
    assert_eq!(std::fs::read(&file).unwrap(), b"old");
}

#[tokio::test]
async fn versioned_upload_and_object_fields_parse() {
    let server = MockServer::start().await;
    let esm = esm(&server).await;
    Mock::given(header("x-euclid-action", "put-object"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ern": "e", "bucketErn": BUCKET, "key": "k", "size": 4, "status": "UPLOADED",
            "versionId": "v3", "unchanged": true
        })))
        .mount(&server)
        .await;
    Mock::given(header("x-euclid-action", "list-objects"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "objects": [{
                "ern": "e", "key": "k", "versionId": "v3", "encrypted": true,
                "lastAccessed": "2026-11-01T00:00:00Z", "lifecycleState": "ARCHIVED",
                "restoredUntil": "2026-12-01T00:00:00Z"
            }],
            "total": 1
        })))
        .mount(&server)
        .await;

    let put = esm.put_object(BUCKET, "k", b"data".to_vec()).await.unwrap();
    assert_eq!(put.version_id.as_deref(), Some("v3"));
    assert!(put.unchanged);

    let objects = esm.list_all_objects(BUCKET, "").await.unwrap();
    let object = &objects[0];
    assert_eq!(object.version_id.as_deref(), Some("v3"));
    assert!(object.encrypted);
    assert_eq!(object.last_accessed.as_deref(), Some("2026-11-01T00:00:00Z"));
    assert_eq!(object.lifecycle_state.as_deref(), Some("ARCHIVED"));
    assert_eq!(object.restored_until.as_deref(), Some("2026-12-01T00:00:00Z"));
}

#[tokio::test]
async fn bucket_lifecycle_round_trips() {
    let server = MockServer::start().await;
    let esm = esm(&server).await;
    Mock::given(header("x-euclid-action", "set-bucket-lifecycle"))
        .and(body_json(json!({ "ern": BUCKET, "rules": [
            { "id": "logs", "prefix": "logs/", "archiveAfterDays": 30, "restoreDays": 7, "enabled": true },
            { "id": "off", "prefix": "", "archiveAfterDays": 90, "restoreDays": 1, "enabled": false }
        ]})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ern": BUCKET, "name": "b", "rules": [
                { "id": "logs", "prefix": "logs/", "archiveAfterDays": 30, "restoreDays": 7, "enabled": true },
                { "id": "off", "prefix": "", "archiveAfterDays": 90, "restoreDays": 1, "enabled": false }
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(header("x-euclid-action", "get-bucket-lifecycle"))
        .and(body_json(json!({ "ern": BUCKET })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ern": BUCKET, "name": "b",
            "rules": [{ "id": "logs", "prefix": "logs/", "archiveAfterDays": 30, "restoreDays": 7 }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(header("x-euclid-action", "delete-bucket-lifecycle"))
        .and(body_json(json!({ "ern": BUCKET })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ern": BUCKET, "name": "b", "rules": [] })))
        .expect(1)
        .mount(&server)
        .await;

    let logs = LifecycleRule::new("logs", "logs/", 30, 7);
    let off = LifecycleRule {
        enabled: false,
        ..LifecycleRule::new("off", "", 90, 1)
    };
    let set = esm
        .set_bucket_lifecycle(BUCKET, &[logs.clone(), off.clone()])
        .await
        .unwrap();
    assert_eq!(set.rules, vec![logs.clone(), off]);
    // A rule without "enabled" is enabled.
    assert_eq!(esm.get_bucket_lifecycle(BUCKET).await.unwrap().rules, vec![logs]);
    assert!(esm.delete_bucket_lifecycle(BUCKET).await.unwrap().rules.is_empty());
}

#[tokio::test]
async fn archive_and_restore_by_key_or_ern() {
    let server = MockServer::start().await;
    let esm = esm(&server).await;
    let object = format!("{BUCKET}/k");
    Mock::given(header("x-euclid-action", "archive-object"))
        .and(body_json(json!({ "bucketErn": BUCKET, "key": "k" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ern": object, "bucketErn": BUCKET, "key": "k", "lifecycleState": "ARCHIVED",
            "archivedAt": "2026-11-06T10:00:00Z", "archiveFile": "a.tar"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(header("x-euclid-action", "archive-object"))
        .and(body_json(json!({ "ern": object })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ern": object, "lifecycleState": "ARCHIVED" })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(header("x-euclid-action", "restore-object"))
        .and(body_json(json!({ "bucketErn": BUCKET, "key": "k", "days": 3 })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ern": object, "lifecycleState": "STANDARD",
            "restoredAt": "2026-11-06T11:00:00Z", "restoredUntil": "2026-11-09T11:00:00Z"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(header("x-euclid-action", "restore-object"))
        .and(body_json(json!({ "ern": object })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ern": object, "lifecycleState": "STANDARD" })))
        .expect(1)
        .mount(&server)
        .await;

    let archived = esm.archive_object(BUCKET, "k").await.unwrap();
    assert_eq!(archived.lifecycle_state.as_deref(), Some("ARCHIVED"));
    assert_eq!(archived.archive_file.as_deref(), Some("a.tar"));
    esm.archive_object_by_ern(&object).await.unwrap();
    let restored = esm.restore_object(BUCKET, "k", Some(3)).await.unwrap();
    assert_eq!(restored.restored_until.as_deref(), Some("2026-11-09T11:00:00Z"));
    let restored = esm.restore_object_by_ern(&object, None).await.unwrap();
    assert_eq!(restored.lifecycle_state.as_deref(), Some("STANDARD"));
}

#[tokio::test]
async fn verify_objects_pages_and_reports_problems() {
    let server = MockServer::start().await;
    let esm = esm(&server).await;
    Mock::given(header("x-euclid-action", "verify-objects"))
        .and(body_json(json!({ "bucketErn": BUCKET, "afterKey": "", "limit": 2 })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "bucketErn": BUCKET, "afterKey": "", "scanned": 2, "checked": 1, "skipped": 1,
            "problems": [{
                "key": "a", "ern": "e", "problem": "short", "recordedSize": 10, "fileSize": 4,
                "expectedFileSize": 10, "internalName": "n", "internalDir": "d",
                "created": "2026-11-06T10:00:00Z"
            }],
            "nextKey": "b"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(header("x-euclid-action", "verify-objects"))
        .and(body_json(json!({ "bucketErn": BUCKET, "afterKey": "b" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "bucketErn": BUCKET, "afterKey": "b", "scanned": 0, "checked": 0, "skipped": 0,
            "problems": [], "nextKey": ""
        })))
        .expect(1)
        .mount(&server)
        .await;

    let page = esm.verify_objects(BUCKET, "", Some(2)).await.unwrap();
    assert_eq!((page.scanned, page.checked, page.skipped), (2, 1, 1));
    let problem = &page.problems[0];
    assert_eq!(problem.problem.as_deref(), Some("short"));
    assert_eq!((problem.recorded_size, problem.file_size), (10, 4));
    assert_eq!(page.next_key.as_deref(), Some("b"));
    let end = esm.verify_objects(BUCKET, "b", None).await.unwrap();
    assert_eq!(end.next_key.as_deref(), Some(""));
}
