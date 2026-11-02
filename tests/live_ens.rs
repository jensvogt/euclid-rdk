//! ENS round trip against a real euclid server. Ignored by default; run with
//!
//! ```sh
//! EUCLID_LIVE_URL=https://localhost:5566 cargo test --test live_ens -- --ignored --nocapture
//! ```
//!
//! Uses the cached session in `~/.euclid/credentials`, or `EUCLID_USER`/`EUCLID_PASSWORD` when
//! set; `EUCLID_LIVE_NAMESPACE` activates a namespace. Creates its own uniquely named topic and
//! queue and deletes both again, also when the test fails.

use std::collections::HashMap;
use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use euclid_rdk::ens::{ListMessagesRequest, PublishMessageRequest};
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

#[tokio::test]
#[ignore = "needs a live euclid server (EUCLID_LIVE_URL)"]
async fn ens_round_trip() {
    let Some(session) = session().await else { return };
    let ens = session.ens();
    let eqs = session.eqs();

    let topic = ens
        .create_topic(&unique_name("topic"))
        .await
        .expect("create topic")
        .ern
        .expect("topic ern");
    println!("created topic {topic}");
    let queue = match eqs.create_queue(&unique_name("queue")).await {
        Ok(created) => created.ern.expect("queue ern"),
        Err(e) => {
            let _ = ens.delete_topic(&topic).await;
            panic!("create queue: {e}");
        }
    };
    println!("created queue {queue}");

    let (test_ens, test_eqs, test_topic, test_queue) = (ens.clone(), eqs.clone(), topic.clone(), queue.clone());
    let body = async move {
        let (ens, eqs, topic, queue) = (test_ens, test_eqs, test_topic, test_queue);

        let fetched = ens.get_topic(&topic).await.expect("get topic");
        assert_eq!(fetched.ern.as_deref(), Some(topic.as_str()));

        let subscription = ens.subscribe(&topic, &queue).await.expect("subscribe");
        let subscription_ern = subscription.ern.clone().expect("subscription ern");
        let listed = ens.list_subscriptions(&topic).await.expect("list subscriptions");
        assert!(
            listed
                .subscriptions
                .iter()
                .any(|s| s.target_ern.as_deref() == Some(queue.as_str())),
            "subscription not listed: {listed:?}"
        );

        let mut attributes = HashMap::new();
        attributes.insert("kind".to_owned(), Variant::string("order"));
        let published = ens
            .publish_message_with(&PublishMessageRequest {
                ern: topic.clone(),
                body: r#"{"orderId":"4711"}"#.into(),
                attributes,
                priority: "HIGH".into(),
            })
            .await
            .expect("publish");
        let message_id = published.message_id.clone().expect("message id");

        // The publish fanned out to the queue; receive it there (long poll) and delete it.
        let mut delivered = None;
        for _ in 0..4 {
            let received = eqs.receive_messages(&queue, 10, 5).await.expect("receive");
            if let Some(message) = received.messages.into_iter().next() {
                delivered = Some(message);
                break;
            }
        }
        let delivered = delivered.expect("published message never reached the subscribed queue");
        assert_eq!(delivered.body.as_deref(), Some(r#"{"orderId":"4711"}"#));
        assert_eq!(
            delivered.attributes.get("kind").and_then(Variant::as_text).as_deref(),
            Some("order")
        );
        assert_eq!(
            delivered.priority.as_deref(),
            Some("HIGH"),
            "priority carried to the queue"
        );
        eqs.delete_message(delivered.receipt_handle.as_deref().expect("receipt handle"))
            .await
            .expect("delete queue message");

        // The topic keeps a record of what was published.
        let stored = ens
            .list_messages(&ListMessagesRequest {
                topic_ern: topic.clone(),
                ..Default::default()
            })
            .await
            .expect("list topic messages");
        assert_eq!(stored.messages.len(), 1, "stored: {stored:?}");
        assert_eq!(stored.messages[0].message_id.as_deref(), Some(message_id.as_str()));
        let message = ens.get_message(&message_id).await.expect("get message");
        assert_eq!(message.body.as_deref(), Some(r#"{"orderId":"4711"}"#));
        let attribute = ens.get_message_attribute(&message_id, "kind").await.expect("attribute");
        assert_eq!(attribute.value.and_then(|v| v.as_text()).as_deref(), Some("order"));
        let count = ens.get_message_count(&topic).await.expect("count");
        println!("topic count: {count:?}");

        ens.unsubscribe(&subscription_ern).await.expect("unsubscribe");
        let listed = ens.list_subscriptions(&topic).await.expect("list subscriptions");
        assert!(listed.subscriptions.is_empty(), "still subscribed: {listed:?}");
    };

    with_cleanup(body, async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        match ens.delete_topic(&topic).await {
            Ok(()) => println!("deleted topic {topic}"),
            Err(e) => eprintln!("CLEANUP FAILED - delete topic {topic} by hand: {e}"),
        }
        match eqs.delete_queue(&queue).await {
            Ok(()) => println!("deleted queue {queue}"),
            Err(e) => eprintln!("CLEANUP FAILED - delete queue {queue} by hand: {e}"),
        }
    })
    .await;
}
