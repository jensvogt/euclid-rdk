//! EES round trip against a real euclid server. Ignored by default; run with
//!
//! ```sh
//! EUCLID_LIVE_URL=https://localhost:5566 cargo test --test live_ees -- --ignored --nocapture
//! EUCLID_LIVE_URL=https://localhost:5566 cargo test --features ws --test live_ees -- --ignored --nocapture
//! ```
//!
//! Uses the cached session in `~/.euclid/credentials`, or `EUCLID_USER`/`EUCLID_PASSWORD` when
//! set; `EUCLID_LIVE_NAMESPACE` activates a namespace. Creates a uniquely named bucket and
//! subscriber and removes both again, also when the test fails.

use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use euclid_rdk::ees::{self, DeliveryMode, SubscribeEventsRequest, ESM_OBJECT_CREATED};
use euclid_rdk::{Eam, Ees, Session};

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

/// Long-polls `name` until an event for `key` arrives (or 30 s pass), acknowledging what it claims.
async fn claim_key(ees: &Ees, name: &str, key: &str) -> ees::EsmObjectEvent {
    let started = std::time::Instant::now();
    loop {
        let received = ees.receive_events_with(name, 10, 10, 60).await.expect("receive events");
        let mut found = None;
        let ids: Vec<String> = received.events.iter().filter_map(|e| e.event_id.clone()).collect();
        for event in &received.events {
            assert_eq!(event.event_type.as_deref(), Some(ESM_OBJECT_CREATED));
            let object = event.esm_object().expect("an ESM object payload");
            if object.key.as_deref() == Some(key) {
                found = Some(object);
            }
        }
        if !ids.is_empty() {
            let acked = ees.ack_events(name, &ids).await.expect("ack events");
            assert_eq!(acked.acknowledged, ids.len() as u64);
        }
        if let Some(object) = found {
            println!("{key}: event claimed after {:?}", started.elapsed());
            return object;
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "no event for {key} within 30 s"
        );
    }
}

#[tokio::test]
#[ignore = "needs a live euclid server (EUCLID_LIVE_URL)"]
async fn ees_round_trip() {
    let Some(session) = session().await else { return };
    let (ees, esm) = (session.ees(), session.esm());
    let subscriber = unique_name("subscriber");
    let bucket = esm
        .create_bucket(&unique_name("bucket"), None)
        .await
        .expect("create bucket")
        .ern
        .expect("bucket ern");
    println!("created bucket {bucket}, subscriber {subscriber}");

    let (test_ees, test_esm, test_bucket, test_subscriber) =
        (ees.clone(), esm.clone(), bucket.clone(), subscriber.clone());
    let body = async move {
        let (ees, esm, bucket, name) = (test_ees, test_esm, test_bucket, test_subscriber);

        // Durable subscription, filtered to the scratch bucket.
        let subscribed = ees
            .subscribe_events_with(&SubscribeEventsRequest {
                name: name.clone(),
                event_types: vec![ESM_OBJECT_CREATED.into()],
                filter: ees::filter([("bucketErn", bucket.as_str())]),
                mode: Some(DeliveryMode::Durable),
            })
            .await
            .expect("subscribe");
        assert_eq!(subscribed.subscriptions.len(), 1);
        let listed = ees.list_subscriptions(&name).await.expect("list subscriptions");
        let subscription = &listed.subscriptions[0];
        assert_eq!(subscription.mode, DeliveryMode::Durable);
        assert_eq!(subscription.filter["bucketErn"], bucket.as_str());

        // Pull: put an object, claim its event, acknowledge it.
        esm.put_object(&bucket, "a.txt", b"hello".to_vec())
            .await
            .expect("put object");
        let object = claim_key(&ees, &name, "a.txt").await;
        assert_eq!(object.bucket_ern.as_deref(), Some(bucket.as_str()));
        assert_eq!(object.size, 5);

        #[cfg(feature = "ws")]
        push_round_trip(&ees, &esm, &bucket, &name).await;
    };

    with_cleanup(body, async {
        match ees.unsubscribe_events(&subscriber).await {
            Ok(r) => println!("unsubscribed {subscriber} ({} removed)", r.removed),
            Err(e) => eprintln!("CLEANUP FAILED - unsubscribe {subscriber} by hand: {e}"),
        }
        match esm.delete_bucket(&bucket, false).await {
            Ok(_) => println!("deleted bucket {bucket}"),
            Err(e) => eprintln!("CLEANUP FAILED - delete bucket {bucket} by hand: {e}"),
        }
    })
    .await;
}

/// Push: a listener attached over the WebSocket is notified, claims and handles the next event.
#[cfg(feature = "ws")]
async fn push_round_trip(ees: &Ees, esm: &euclid_rdk::Esm, bucket: &str, name: &str) {
    use euclid_rdk::ees::{EventListener, StreamFrame};

    let stream = ees.event_stream();
    let mut frames = stream.frames();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let listener = EventListener::builder()
        .ees(ees.clone())
        .stream(stream.clone())
        .name(name)
        .event_types([ESM_OBJECT_CREATED])
        .filter(ees::filter([("bucketErn", bucket)]))
        .handler(move |event| {
            let tx = tx.clone();
            async move {
                tx.send(event).unwrap();
                Ok::<_, std::convert::Infallible>(())
            }
        })
        .build()
        .expect("listener");
    listener.start().await.expect("start listener");
    assert!(stream.is_connected());

    esm.put_object(bucket, "b.txt", b"pushed".to_vec())
        .await
        .expect("put object");
    let started = std::time::Instant::now();
    let notified = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Ok(StreamFrame::Notify { topic }) = frames.recv().await {
                return topic;
            }
        }
    })
    .await
    .expect("a notify frame within 15 s");
    assert_eq!(notified, ESM_OBJECT_CREATED);
    let event = tokio::time::timeout(Duration::from_secs(15), rx.recv())
        .await
        .expect("the handler called within 15 s")
        .unwrap();
    println!("b.txt: pushed and handled after {:?}", started.elapsed());
    assert_eq!(event.esm_object().and_then(|o| o.key).as_deref(), Some("b.txt"));

    listener.close().await;
    stream.close();
    // Handled events are acknowledged, so nothing is left waiting.
    let mut waiting = u64::MAX;
    for _ in 0..20 {
        waiting = ees.list_subscriptions(name).await.expect("list").waiting;
        if waiting == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(waiting, 0, "events left unacknowledged");
}
