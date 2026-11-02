//! Round trips against a real euclid server. Ignored by default; run with
//!
//! ```sh
//! EUCLID_LIVE_URL=https://localhost:5566 cargo test --test live -- --ignored --nocapture
//! ```
//!
//! Uses the cached session in `~/.euclid/credentials`, or `EUCLID_USER`/`EUCLID_PASSWORD` when
//! set; `EUCLID_LIVE_NAMESPACE` activates a namespace. Every test creates its own uniquely named
//! queue or bucket and deletes it again, also when the test fails.

use std::collections::HashMap;
use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use euclid_rdk::eqs::{ListMessagesRequest, SendMessageBatchRequest, SendMessageRequest};
use euclid_rdk::esm::{Attributes, ListObjectsRequest, TransferOptions};
use euclid_rdk::{Eam, Session, Variant};

async fn session() -> Option<Session> {
    let Ok(url) = std::env::var("EUCLID_LIVE_URL") else {
        eprintln!("EUCLID_LIVE_URL not set - skipping");
        return None;
    };
    let mut eam = Eam::for_server(url);
    if let (Ok(user), Ok(password)) = (std::env::var("EUCLID_USER"), std::env::var("EUCLID_PASSWORD")) {
        eam = eam.credentials(user, password);
    }
    if let Ok(namespace) = std::env::var("EUCLID_LIVE_NAMESPACE") {
        eam = eam.namespace(namespace);
    }
    Some(eam.login().await.expect("login"))
}

fn unique_name(kind: &str) -> String {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("rdk-live-{kind}-{}-{}", std::process::id(), nanos % 1_000_000_000)
}

/// Runs `body`, then `cleanup` whatever happened, then re-raises a failure of `body`.
async fn with_cleanup<B, C>(body: B, cleanup: C)
where
    B: Future<Output = ()> + Send + 'static,
    C: Future<Output = ()>,
{
    let outcome = tokio::spawn(body).await;
    cleanup.await;
    if let Err(e) = outcome {
        std::panic::resume_unwind(e.into_panic());
    }
}

/// Deterministic pseudo-random bytes, so a corrupted or reordered part shows up in the comparison.
fn pseudo_random(len: usize) -> Vec<u8> {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

/// Polls the message count until it reads `expected` or 30 s have passed; returns the last count.
async fn wait_for_count(eqs: &euclid_rdk::Eqs, ern: &str, expected: u64) -> u64 {
    let started = std::time::Instant::now();
    loop {
        let total = eqs.get_message_count(ern).await.expect("count").total;
        if total == expected || started.elapsed() > Duration::from_secs(30) {
            println!("count {total} after {:?}", started.elapsed());
            if total != expected {
                println!("  breakdown: {:?}", eqs.get_message_count(ern).await.expect("count"));
                println!("  queue: {:?}", eqs.get_queue(ern).await.expect("queue"));
            }
            return total;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Polls the listing until the object is COMPLETED, failing after 60 s.
async fn wait_for_completed(esm: &euclid_rdk::Esm, bucket: &str, key: &str) -> euclid_rdk::esm::EsmObject {
    let started = std::time::Instant::now();
    loop {
        let listing = esm
            .list_objects(&ListObjectsRequest {
                bucket_ern: bucket.into(),
                prefix: key.into(),
                ..Default::default()
            })
            .await
            .expect("list objects");
        let object = listing.objects.into_iter().find(|o| o.key.as_deref() == Some(key));
        let status = object.as_ref().and_then(|o| o.status.clone()).unwrap_or_default();
        if status == "COMPLETED" {
            println!("{key} COMPLETED after {:?}", started.elapsed());
            return object.unwrap();
        }
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "{key} still {status:?} after 60 s"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

#[tokio::test]
#[ignore = "needs a live euclid server (EUCLID_LIVE_URL)"]
async fn eqs_round_trip() {
    let Some(session) = session().await else { return };
    let eqs = session.eqs();
    let name = unique_name("queue");
    let ern = eqs
        .create_queue(&name)
        .await
        .expect("create queue")
        .ern
        .expect("queue ern");
    println!("created queue {ern}");

    let test_eqs = eqs.clone();
    let test_ern = ern.clone();
    let body = async move {
        let (eqs, ern) = (test_eqs, test_ern);
        let queue = eqs.get_queue(&ern).await.expect("get queue");
        assert_eq!(queue.ern.as_deref(), Some(ern.as_str()));

        // One message with an attribute, three more in a batch.
        let mut attributes = HashMap::new();
        attributes.insert("kind".to_owned(), Variant::string("greeting"));
        eqs.send_message_with(&SendMessageRequest {
            ern: ern.clone(),
            body: r#"{"hello":"world"}"#.into(),
            attributes,
            ..Default::default()
        })
        .await
        .expect("send message");
        let batch = eqs
            .send_message_batch(
                &SendMessageBatchRequest::new(&ern)
                    .message("b1")
                    .message("b2")
                    .message("b3"),
            )
            .await
            .expect("send batch");
        assert_eq!(batch.sent, 3, "batch failures: {:?}", batch.failed);

        // The count is a counter EQS keeps beside the messages; it trails them.
        let count = wait_for_count(&eqs, &ern, 4).await;
        assert_eq!(count, 4, "count after sending");

        // Peeking does not consume.
        let peeked = eqs
            .list_messages(&ListMessagesRequest {
                queue_ern: ern.clone(),
                ..Default::default()
            })
            .await
            .expect("list messages");
        assert_eq!(peeked.messages.len(), 4);

        // Long poll until all four have arrived, deleting each.
        let mut bodies = Vec::new();
        for _ in 0..5 {
            let received = eqs.receive_messages(&ern, 10, 5).await.expect("receive");
            for message in received.messages {
                if message.body.as_deref() == Some(r#"{"hello":"world"}"#) {
                    let kind = message.attributes.get("kind").and_then(Variant::as_text);
                    assert_eq!(kind.as_deref(), Some("greeting"));
                }
                bodies.push(message.body.clone().unwrap_or_default());
                eqs.delete_message(message.receipt_handle.as_deref().expect("receipt handle"))
                    .await
                    .expect("delete message");
            }
            if bodies.len() >= 4 {
                break;
            }
        }
        bodies.sort();
        assert_eq!(bodies, ["b1", "b2", "b3", r#"{"hello":"world"}"#]);

        // What is really left is what list-messages shows; the counter only catches up with it.
        let left = eqs
            .list_messages(&ListMessagesRequest {
                queue_ern: ern.clone(),
                ..Default::default()
            })
            .await
            .expect("list messages");
        assert!(
            left.messages.is_empty(),
            "messages left after deleting: {:?}",
            left.messages
        );
        // Known server issue (2026-11-02): deleting by receipt handle intermittently leaves the
        // queue's `invisible` counter un-decremented, although the messages themselves are gone.
        let count = wait_for_count(&eqs, &ern, 0).await;
        assert_eq!(
            count, 0,
            "message count did not return to 0 although list-messages is empty - server counter drift"
        );
    };

    with_cleanup(body, async {
        match eqs.delete_queue(&ern).await {
            Ok(()) => println!("deleted queue {ern}"),
            Err(e) => eprintln!("CLEANUP FAILED - delete queue {ern} by hand: {e}"),
        }
    })
    .await;
}

#[tokio::test]
#[ignore = "needs a live euclid server (EUCLID_LIVE_URL)"]
async fn esm_round_trip() {
    let Some(session) = session().await else { return };
    let esm = session.esm();
    let name = unique_name("bucket");
    let ern = esm
        .create_bucket(&name, None)
        .await
        .expect("create bucket")
        .ern
        .expect("bucket ern");
    println!("created bucket {ern}");

    let test_esm = esm.clone();
    let test_ern = ern.clone();
    let body = async move {
        let (esm, ern) = (test_esm, test_ern);

        // Small object with an attribute, in one request.
        let mut attributes = Attributes::new();
        attributes.insert("kind".into(), Variant::string("Grüße"));
        esm.put_object_with(
            &ern,
            "hello.txt",
            b"hello euclid".to_vec(),
            &attributes,
            &Attributes::new(),
        )
        .await
        .expect("put object");
        wait_for_completed(&esm, &ern, "hello.txt").await;
        let bytes = esm
            .get_object(&ern, "hello.txt", 1024 * 1024)
            .await
            .expect("get object");
        assert_eq!(bytes, b"hello euclid");
        let size = esm.get_object_size(&ern, "hello.txt").await.expect("object size");
        assert_eq!(size.size, 12);

        // 12 MiB file: three 5 MiB-sized parts up, and down again.
        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("source.bin");
        let target = dir.path().join("target.bin");
        let data = pseudo_random(12 * 1024 * 1024 + 123);
        std::fs::write(&source, &data).expect("write source");
        let options = TransferOptions::default();
        esm.upload_file(&ern, "dir/big.bin", &source, &options)
            .await
            .expect("upload file");
        // complete-upload answers once every part is in (UPLOADED); the server then assembles
        // and hashes the object in the background before it turns COMPLETED and can be read.
        let object = wait_for_completed(&esm, &ern, "dir/big.bin").await;
        assert_eq!(object.size, data.len() as u64);
        let written = esm
            .download_file(&ern, "dir/big.bin", &target, &options)
            .await
            .expect("download file");
        assert_eq!(written, data.len() as u64);
        assert!(
            std::fs::read(&target).expect("read target") == data,
            "downloaded bytes differ"
        );

        let copy = esm
            .copy_object(&ern, "hello.txt", &ern, "hello-copy.txt")
            .await
            .expect("copy object");
        assert_eq!(copy.key.as_deref(), Some("hello-copy.txt"));

        let listing = esm
            .list_objects(&ListObjectsRequest {
                bucket_ern: ern.clone(),
                ..Default::default()
            })
            .await
            .expect("list objects");
        let mut keys: Vec<_> = listing.objects.iter().filter_map(|o| o.key.clone()).collect();
        keys.sort();
        assert_eq!(keys, ["dir/big.bin", "hello-copy.txt", "hello.txt"]);
        let hello = listing
            .objects
            .iter()
            .find(|o| o.key.as_deref() == Some("hello.txt"))
            .unwrap();
        let kind = hello.attributes.get("kind").and_then(Variant::as_text);
        assert_eq!(kind.as_deref(), Some("Grüße"));
    };

    with_cleanup(body, async {
        // Give the server a moment to settle uploads before removing the bucket.
        tokio::time::sleep(Duration::from_millis(200)).await;
        match esm.delete_bucket(&ern, false).await {
            Ok(_) => println!("deleted bucket {ern}"),
            Err(e) => eprintln!("CLEANUP FAILED - delete bucket {ern} by hand: {e}"),
        }
    })
    .await;
}
