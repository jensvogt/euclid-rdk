//! EES against a mock server: authentication, request bodies, response parsing, errors - and,
//! with the `ws` feature, the WebSocket stream and listener against a local WebSocket server.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use euclid_rdk::ees::{self, DeliveryMode, SubscribeEventsRequest, ESM_OBJECT_CREATED};
use euclid_rdk::{Eam, Ees, Error};
use serde_json::{json, Value};
use wiremock::matchers::{header, method};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

fn jwt() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{}}}"#, now + 3600));
    format!("{}.{payload}.sig", URL_SAFE_NO_PAD.encode(b"{}"))
}

async fn ees(server: &MockServer, with_access_key: bool) -> Ees {
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
        .ees()
}

type Seen = Arc<std::sync::Mutex<Vec<(Value, String)>>>;

/// Mounts `action` answering `answer`, and records each request (body, authorization header).
async fn mount(server: &MockServer, action: &str, answer: Value) -> Seen {
    let seen: Seen = Arc::default();
    let record = seen.clone();
    Mock::given(method("POST"))
        .and(header("x-euclid-target", "ees"))
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

fn subscription_json(mode: &str) -> Value {
    json!({
        "subscriber": "invoice-import", "eventType": ESM_OBJECT_CREATED,
        "filter": { "bucketName": "inbox" }, "accountId": "000000000000", "mode": mode,
        "created": "2026-11-02T10:00:00Z", "lastSeen": "2026-11-02T11:00:00Z"
    })
}

#[tokio::test]
async fn requests_are_sigv4_signed_with_an_access_key_and_bearer_without() {
    let signed_server = MockServer::start().await;
    let signed = ees(&signed_server, true).await;
    let seen = mount(
        &signed_server,
        "list-subscriptions",
        json!({ "subscriptions": [], "waiting": 0 }),
    )
    .await;
    signed.list_subscriptions("n").await.unwrap();
    assert!(last(&seen).1.starts_with("AWS4-HMAC-SHA256 Credential=AKIATEST/"));
    assert!(last(&seen).1.contains("/ees/aws4_request"));

    let bearer_server = MockServer::start().await;
    let bearer = ees(&bearer_server, false).await;
    let seen = mount(
        &bearer_server,
        "list-subscriptions",
        json!({ "subscriptions": [], "waiting": 0 }),
    )
    .await;
    bearer.list_subscriptions("n").await.unwrap();
    assert!(last(&seen).1.starts_with("Bearer "));
}

#[tokio::test]
async fn subscribe_sends_jdk_defaults_and_parses_subscriptions() {
    let server = MockServer::start().await;
    let ees = ees(&server, true).await;
    let seen = mount(
        &server,
        "subscribe-events",
        json!({ "subscriptions": [subscription_json("live"), subscription_json("bogus")] }),
    )
    .await;

    let response = ees
        .subscribe_events("invoice-import", &[ESM_OBJECT_CREATED])
        .await
        .unwrap();
    assert_eq!(
        last(&seen).0,
        json!({ "name": "invoice-import", "eventTypes": [ESM_OBJECT_CREATED], "filter": {}, "mode": "durable" })
    );
    let first = &response.subscriptions[0];
    assert_eq!(first.subscriber.as_deref(), Some("invoice-import"));
    assert_eq!(first.mode, DeliveryMode::Live);
    assert_eq!(first.filter["bucketName"], "inbox");
    assert_eq!(first.last_seen.as_deref(), Some("2026-11-02T11:00:00Z"));
    // An unknown mode reads as durable rather than failing.
    assert_eq!(response.subscriptions[1].mode, DeliveryMode::Durable);

    ees.subscribe_events_with(&SubscribeEventsRequest {
        name: "view".into(),
        event_types: vec!["esm.object.deleted".into()],
        filter: ees::filter([("bucketName", "inbox")]),
        mode: None,
    })
    .await
    .unwrap();
    assert_eq!(
        last(&seen).0,
        json!({ "name": "view", "eventTypes": ["esm.object.deleted"], "filter": { "bucketName": "inbox" }, "mode": null })
    );
}

#[tokio::test]
async fn unsubscribe_and_list_subscriptions() {
    let server = MockServer::start().await;
    let ees = ees(&server, true).await;
    let unsub = mount(
        &server,
        "unsubscribe-events",
        json!({ "subscriber": "n", "removed": 2 }),
    )
    .await;
    let list = mount(
        &server,
        "list-subscriptions",
        json!({ "subscriptions": [subscription_json("durable")], "waiting": 7 }),
    )
    .await;

    let removed = ees.unsubscribe_events("n").await.unwrap();
    assert_eq!(last(&unsub).0, json!({ "name": "n", "eventType": "" }));
    assert_eq!(removed.removed, 2);
    ees.unsubscribe_event_type("n", ESM_OBJECT_CREATED).await.unwrap();
    assert_eq!(last(&unsub).0, json!({ "name": "n", "eventType": ESM_OBJECT_CREATED }));

    let listed = ees.list_subscriptions("n").await.unwrap();
    assert_eq!(last(&list).0, json!({ "name": "n" }));
    assert_eq!(listed.waiting, 7);
    assert_eq!(listed.subscriptions.len(), 1);
}

#[tokio::test]
async fn receive_parses_events_and_typed_esm_payloads() {
    let server = MockServer::start().await;
    let ees = ees(&server, true).await;
    let seen = mount(
        &server,
        "receive-events",
        json!({
            "events": [
                { "eventId": "e-1", "eventType": ESM_OBJECT_CREATED, "sourceModule": "esm", "attempts": 1,
                  "created": "2026-11-02T10:00:00Z",
                  "payload": { "bucketName": "inbox", "key": "a/b.txt", "prefix": "a/", "directory": false,
                               "size": 12, "md5Sum": "abc", "owner": "jvo", "userId": "op" } },
                { "eventId": "e-2", "eventType": "eqs.message.sent", "payload": null }
            ],
            "total": 2
        }),
    )
    .await;

    let received = ees.receive_events("n").await.unwrap();
    assert_eq!(
        last(&seen).0,
        json!({ "name": "n", "maxEvents": 10, "waitTime": 0, "visibilityTimeout": 300 })
    );
    assert_eq!(received.total, 2);
    let object = received.events[0].esm_object().expect("an ESM object event");
    assert_eq!(object.key.as_deref(), Some("a/b.txt"));
    assert_eq!(object.size, 12);
    assert_eq!(object.owner.as_deref(), Some("jvo"));
    assert_eq!(object.user_id.as_deref(), Some("op"));
    assert!(!object.directory);
    assert_eq!(received.events[0].attempts, 1);
    assert!(received.events[1].payload.is_empty());
    assert!(received.events[1].esm_object().is_none());

    ees.receive_events_with("n", 5, 20, 60).await.unwrap();
    assert_eq!(
        last(&seen).0,
        json!({ "name": "n", "maxEvents": 5, "waitTime": 20, "visibilityTimeout": 60 })
    );
}

#[tokio::test]
async fn ack_sends_event_ids() {
    let server = MockServer::start().await;
    let ees = ees(&server, true).await;
    let seen = mount(&server, "ack-events", json!({ "subscriber": "n", "acknowledged": 2 })).await;

    let acked = ees.ack_events("n", &["e-1", "e-2"]).await.unwrap();
    assert_eq!(last(&seen).0, json!({ "name": "n", "eventIds": ["e-1", "e-2"] }));
    assert_eq!(acked.acknowledged, 2);
    ees.ack_event("n", "e-3").await.unwrap();
    assert_eq!(last(&seen).0, json!({ "name": "n", "eventIds": ["e-3"] }));
}

#[tokio::test]
async fn failures_carry_action_and_status() {
    let server = MockServer::start().await;
    let ees = ees(&server, true).await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "ack-events"))
        .respond_with(ResponseTemplate::new(400).set_body_string("eventIds is required"))
        .mount(&server)
        .await;
    let err = ees.ack_events::<&str>("n", &[]).await.unwrap_err();
    assert!(matches!(&err, Error::Service { action, status: 400, .. } if action == "ack-events"));
    assert_eq!(
        err.to_string(),
        "ees ack-events failed with status 400: eventIds is required"
    );
}

#[cfg(feature = "ws")]
mod ws {
    use std::sync::Mutex;
    use std::time::Duration;

    use euclid_rdk::ees::{DeliveryMode, EventListener, EventStream, EventStreamListener, StreamFrame};
    use futures_util::{SinkExt, StreamExt};
    use tokio::net::TcpListener;
    use tokio::sync::broadcast;
    use tokio_tungstenite::tungstenite::handshake::server::{Request as WsRequest, Response as WsResponse};
    use tokio_tungstenite::tungstenite::Message;

    use super::*;

    enum Command {
        Push(String),
        Drop,
    }

    /// The headers of each handshake, in connection order.
    type Handshakes = Arc<Mutex<Vec<Vec<(String, String)>>>>;

    /// A WebSocket server that acknowledges control frames the way the gateway does, records
    /// handshakes and frames, and pushes or drops on command.
    struct WsServer {
        url: String,
        handshakes: Handshakes,
        frames: Arc<Mutex<Vec<Value>>>,
        commands: broadcast::Sender<Arc<Command>>,
    }

    impl WsServer {
        // The handshake callback's signature, large error type included, is tungstenite's.
        #[allow(clippy::result_large_err)]
        async fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let handshakes: Handshakes = Arc::default();
            let frames: Arc<Mutex<Vec<Value>>> = Arc::default();
            let (commands, _) = broadcast::channel::<Arc<Command>>(64);
            let (h, f, c) = (handshakes.clone(), frames.clone(), commands.clone());
            tokio::spawn(async move {
                loop {
                    let Ok((tcp, _)) = listener.accept().await else { return };
                    let (h, f, mut c) = (h.clone(), f.clone(), c.subscribe());
                    tokio::spawn(async move {
                        let callback = |req: &WsRequest, res: WsResponse| {
                            let headers = req
                                .headers()
                                .iter()
                                .map(|(n, v)| (n.as_str().to_owned(), v.to_str().unwrap_or_default().to_owned()))
                                .collect();
                            h.lock().unwrap().push(headers);
                            Ok(res)
                        };
                        let Ok(socket) = tokio_tungstenite::accept_hdr_async(tcp, callback).await else {
                            return;
                        };
                        let (mut sink, mut source) = socket.split();
                        loop {
                            tokio::select! {
                                message = source.next() => {
                                    let Some(Ok(Message::Text(text))) = message else { return };
                                    let frame: Value = serde_json::from_str(text.as_str()).unwrap();
                                    f.lock().unwrap().push(frame.clone());
                                    let kind = frame["type"].as_str().unwrap_or_default();
                                    let ack = if kind == "subscribe" { "subscribed" } else { "unsubscribed" };
                                    let name = frame["name"].as_str().unwrap_or("ws-generated");
                                    let reply = json!({ "type": ack, "id": frame["id"], "name": name });
                                    if sink.send(Message::Text(reply.to_string().into())).await.is_err() { return; }
                                }
                                command = c.recv() => {
                                    match command.as_deref() {
                                        Ok(Command::Push(text)) => {
                                            if sink.send(Message::Text(text.clone().into())).await.is_err() { return; }
                                        }
                                        Ok(Command::Drop) | Err(_) => return,
                                    }
                                }
                            }
                        }
                    });
                }
            });
            Self {
                url,
                handshakes,
                frames,
                commands,
            }
        }

        fn push(&self, frame: Value) {
            let _ = self.commands.send(Arc::new(Command::Push(frame.to_string())));
        }

        fn drop_connections(&self) {
            let _ = self.commands.send(Arc::new(Command::Drop));
        }

        fn frames(&self) -> Vec<Value> {
            self.frames.lock().unwrap().clone()
        }

        fn header(&self, connection: usize, name: &str) -> Option<String> {
            self.handshakes.lock().unwrap()[connection]
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
        }
    }

    /// An `Ees` whose base URL is the WebSocket server, from a cached session (no HTTP login).
    async fn ees_at(url: &str, with_access_key: bool, dir: &tempfile::TempDir) -> Ees {
        let path = dir.path().join("credentials");
        let mut creds = json!({
            "token": jwt(), "userId": "jvo", "accountId": "000000000000", "region": "eu-central-1",
            "isAdmin": true, "baseUrl": url, "namespace": "development"
        });
        if with_access_key {
            creds["accessKeyId"] = json!("AKIATEST");
            creds["secretAccessKey"] = json!("secret");
        }
        std::fs::write(&path, creds.to_string()).unwrap();
        Eam::for_server(url)
            .credentials_file(path)
            .no_ca_cert()
            .login()
            .await
            .unwrap()
            .ees()
    }

    async fn eventually(mut check: impl FnMut() -> bool) {
        for _ in 0..200 {
            if check() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("condition not met in time");
    }

    #[derive(Default)]
    struct Recorder(Mutex<Vec<String>>);

    impl EventStreamListener for Recorder {
        fn on_event(&self, topic: &str, body: &Value) {
            self.0.lock().unwrap().push(format!("event {topic} {body}"));
        }
        fn on_notify(&self, topic: &str) {
            self.0.lock().unwrap().push(format!("notify {topic}"));
        }
        fn on_lag(&self, dropped: u64) {
            self.0.lock().unwrap().push(format!("lag {dropped}"));
        }
        fn on_reconnected(&self) {
            self.0.lock().unwrap().push("reconnected".into());
        }
    }

    #[tokio::test]
    async fn handshake_is_signed_as_a_get_or_carries_the_bearer_token() {
        let server = WsServer::start().await;
        let dir = tempfile::tempdir().unwrap();

        let signed = ees_at(&server.url, true, &dir).await.event_stream();
        signed.attach("n").await.unwrap();
        assert_eq!(server.header(0, "x-euclid-target").as_deref(), Some("ees"));
        assert_eq!(server.header(0, "x-euclid-action").as_deref(), Some("event-stream"));
        assert_eq!(server.header(0, "x-euclid-account-id").as_deref(), Some("000000000000"));
        assert_eq!(server.header(0, "x-euclid-region").as_deref(), Some("eu-central-1"));
        assert_eq!(server.header(0, "x-euclid-user-id").as_deref(), Some("jvo"));
        assert_eq!(server.header(0, "x-euclid-namespace").as_deref(), Some("development"));
        let authorization = server.header(0, "authorization").unwrap();
        assert!(authorization.starts_with("AWS4-HMAC-SHA256 Credential=AKIATEST/"));
        assert!(authorization.contains("/eu-central-1/ees/aws4_request"));
        assert!(server.header(0, "x-amz-date").is_some());
        assert_eq!(
            server.header(0, "x-amz-content-sha256").as_deref(),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") // sha256("")
        );
        signed.close();

        let dir = tempfile::tempdir().unwrap();
        let bearer = ees_at(&server.url, false, &dir).await.event_stream();
        bearer.attach("n").await.unwrap();
        assert!(server.header(1, "authorization").unwrap().starts_with("Bearer "));
    }

    #[tokio::test]
    async fn control_frames_and_acknowledged_names() {
        let server = WsServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let stream = ees_at(&server.url, true, &dir).await.event_stream();
        assert!(!stream.is_connected());

        stream
            .subscribe("eqs.message.sent", &[("queueErn", "q")])
            .await
            .unwrap();
        assert!(stream.is_connected());
        assert_eq!(stream.subscriber_name().as_deref(), Some("ws-generated"));
        // The same topic and filter again is a no-op without a round trip.
        stream
            .subscribe("eqs.message.sent", &[("queueErn", "q")])
            .await
            .unwrap();
        stream
            .subscribe_named("view", ESM_OBJECT_CREATED, &[], Some(DeliveryMode::Live))
            .await
            .unwrap();
        stream.attach("importer").await.unwrap();
        stream.detach("importer").await.unwrap();
        assert_eq!(stream.subscriber_name(), None);

        let frames: Vec<Value> = server
            .frames()
            .into_iter()
            .map(|mut f| {
                f.as_object_mut().unwrap().remove("id");
                f
            })
            .collect();
        assert_eq!(
            frames,
            vec![
                json!({ "type": "subscribe", "topic": "eqs.message.sent", "filter": { "queueErn": "q" } }),
                json!({ "type": "subscribe", "topic": ESM_OBJECT_CREATED, "filter": {}, "name": "view", "mode": "live" }),
                json!({ "type": "subscribe", "name": "importer" }),
                json!({ "type": "unsubscribe", "name": "importer" }),
            ]
        );
    }

    #[tokio::test]
    async fn frames_reach_listeners_channels_and_waiters() {
        let server = WsServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let stream = ees_at(&server.url, true, &dir).await.event_stream();
        let recorder = Arc::new(Recorder::default());
        stream.add_listener(recorder.clone());
        let mut frames = stream.frames();

        stream.subscribe("eqs.message.sent", &[]).await.unwrap();
        server.push(json!({ "type": "event", "topic": "t", "body": { "delivery": "notify" } }));
        server.push(json!({ "type": "lag", "dropped": 3 }));
        server.push(json!({ "type": "event", "topic": "t", "body": { "k": "v" } }));

        assert_eq!(frames.recv().await.unwrap(), StreamFrame::Notify { topic: "t".into() });
        assert_eq!(frames.recv().await.unwrap(), StreamFrame::Lag { dropped: 3 });
        assert_eq!(
            frames.recv().await.unwrap(),
            StreamFrame::Event {
                topic: "t".into(),
                body: json!({ "k": "v" })
            }
        );
        assert_eq!(
            *recorder.0.lock().unwrap(),
            vec![
                "notify t".to_owned(),
                "lag 3".to_owned(),
                r#"event t {"k":"v"}"#.to_owned()
            ]
        );

        // await_event: a non-matching event does not complete it, a matching one does.
        let waiting = {
            let stream = stream.clone();
            tokio::spawn(async move {
                stream
                    .await_event(
                        "eqs.message.sent",
                        &[("queueErn", "q"), ("n", "12")],
                        Duration::from_secs(5),
                    )
                    .await
            })
        };
        eventually(|| server.frames().len() == 2).await;
        server.push(json!({ "type": "event", "topic": "eqs.message.sent", "body": { "queueErn": "other", "n": 12 } }));
        server.push(json!({ "type": "event", "topic": "eqs.message.sent", "body": { "queueErn": "q", "n": 12 } }));
        assert!(waiting.await.unwrap().unwrap());

        let timed_out = stream
            .await_event(
                "eqs.message.sent",
                &[("queueErn", "q"), ("n", "12")],
                Duration::from_millis(100),
            )
            .await
            .unwrap();
        assert!(!timed_out);
    }

    #[tokio::test]
    async fn a_dropped_connection_reconnects_and_replays_its_subscriptions() {
        let server = WsServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let stream = ees_at(&server.url, true, &dir).await.event_stream();
        let recorder = Arc::new(Recorder::default());
        let id = stream.add_listener(recorder.clone());
        let mut frames = stream.frames();

        stream.subscribe("t", &[("a", "b")]).await.unwrap();
        stream.subscribe_named("view", "u", &[], None).await.unwrap();
        stream.unsubscribe("t", &[("a", "b")]).await.unwrap();
        stream.subscribe("t2", &[]).await.unwrap();
        assert_eq!(server.frames().len(), 4);

        server.drop_connections();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), frames.recv())
                .await
                .unwrap()
                .unwrap(),
            StreamFrame::Reconnected
        );
        assert!(stream.is_connected());
        assert_eq!(server.handshakes.lock().unwrap().len(), 2);
        let replayed: Vec<Value> = server.frames()[4..]
            .iter()
            .map(|f| json!({ "topic": f["topic"], "name": f["name"] }))
            .collect();
        // What was unsubscribed is not resurrected; the rest comes back in order.
        assert_eq!(
            replayed,
            vec![
                json!({ "topic": "u", "name": "view" }),
                json!({ "topic": "t2", "name": null })
            ]
        );
        assert_eq!(*recorder.0.lock().unwrap(), vec!["reconnected".to_owned()]);

        stream.remove_listener(id);
        stream.close();
        eventually(|| !stream.is_connected()).await;
        assert!(stream.attach("n").await.is_err(), "a closed stream does not reconnect");
    }

    #[tokio::test]
    async fn connecting_to_nothing_fails_so_callers_can_poll() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let dir = tempfile::tempdir().unwrap();
        let stream = ees_at(&url, false, &dir).await.event_stream();
        assert!(matches!(stream.attach("n").await, Err(Error::Io(_))));
    }

    #[tokio::test]
    async fn durable_listener_drains_handles_and_acks_only_what_succeeded() {
        let http = MockServer::start().await;
        let ees_http = ees(&http, true).await;
        let subscribed = mount(&http, "subscribe-events", json!({ "subscriptions": [] })).await;
        let acked = mount(
            &http,
            "ack-events",
            json!({ "subscriber": "importer", "acknowledged": 1 }),
        )
        .await;
        let claims = Arc::new(Mutex::new(0usize));
        let counter = claims.clone();
        Mock::given(method("POST"))
            .and(header("x-euclid-action", "receive-events"))
            .respond_with(move |req: &Request| {
                let body: Value = serde_json::from_slice(&req.body).unwrap();
                assert_eq!(body["maxEvents"], 32);
                let mut n = counter.lock().unwrap();
                *n += 1;
                let events = match *n {
                    1 => json!([
                        { "eventId": "ok-1", "eventType": ESM_OBJECT_CREATED, "payload": { "key": "good" } },
                        { "eventId": "bad-1", "eventType": ESM_OBJECT_CREATED, "payload": { "key": "bad" } }
                    ]),
                    3 => json!([{ "eventId": "ok-2", "eventType": ESM_OBJECT_CREATED, "payload": { "key": "later" } }]),
                    _ => json!([]),
                };
                ResponseTemplate::new(200).set_body_json(json!({ "events": events, "total": 0 }))
            })
            .mount(&http)
            .await;

        let server = WsServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let stream = ees_at(&server.url, true, &dir).await.event_stream();
        let handled = Arc::new(Mutex::new(Vec::<String>::new()));
        let seen = handled.clone();
        let listener = EventListener::builder()
            .ees(ees_http)
            .stream(stream)
            .name("importer")
            .event_types([ESM_OBJECT_CREATED])
            .filter(ees::filter([("bucketName", "inbox")]))
            .handler(move |event| {
                let seen = seen.clone();
                async move {
                    let key = event.esm_object().and_then(|o| o.key).unwrap_or_default();
                    seen.lock().unwrap().push(key.clone());
                    if key == "bad" {
                        Err("cannot import")
                    } else {
                        Ok(())
                    }
                }
            })
            .build()
            .unwrap();

        listener.start().await.unwrap();
        assert_eq!(
            last(&subscribed).0,
            json!({ "name": "importer", "eventTypes": [ESM_OBJECT_CREATED], "filter": { "bucketName": "inbox" }, "mode": "durable" })
        );
        eventually(|| acked.lock().unwrap().len() == 1).await;
        assert_eq!(last(&acked).0, json!({ "name": "importer", "eventIds": ["ok-1"] }));
        assert_eq!(server.frames()[0]["name"], "importer");
        assert!(
            server.frames()[0].get("topic").is_none(),
            "start attaches without redefining"
        );

        // A notification triggers the next drain.
        server.push(json!({ "type": "event", "topic": ESM_OBJECT_CREATED, "body": { "delivery": "notify" } }));
        eventually(|| acked.lock().unwrap().len() == 2).await;
        assert_eq!(last(&acked).0, json!({ "name": "importer", "eventIds": ["ok-2"] }));
        assert_eq!(*handled.lock().unwrap(), vec!["good", "bad", "later"]);

        listener.close().await;
        eventually(|| server.frames().len() == 2).await;
        assert_eq!(server.frames()[1]["type"], "unsubscribe");
        assert_eq!(server.frames()[1]["name"], "importer");
    }

    #[tokio::test]
    async fn live_listener_hands_pushed_events_straight_to_the_handler() {
        let http = MockServer::start().await;
        let ees_http = ees(&http, true).await;
        mount(&http, "subscribe-events", json!({ "subscriptions": [] })).await;
        let claims = mount(&http, "receive-events", json!({ "events": [], "total": 0 })).await;

        let server = WsServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let stream: EventStream = ees_at(&server.url, true, &dir).await.event_stream();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let listener = EventListener::builder()
            .ees(ees_http)
            .stream(stream)
            .name("view")
            .event_types(["esm.object.deleted"])
            .mode(DeliveryMode::Live)
            .handler(move |event| {
                let tx = tx.clone();
                async move {
                    tx.send(event).unwrap();
                    Ok::<_, std::convert::Infallible>(())
                }
            })
            .build()
            .unwrap();
        listener.start().await.unwrap();

        server.push(json!({ "type": "event", "topic": "esm.object.deleted", "body": { "key": "gone", "size": 3 } }));
        let event = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(event.event_type.as_deref(), Some("esm.object.deleted"));
        assert_eq!(event.payload["key"], "gone");
        assert_eq!(event.event_id, None);
        assert!(claims.lock().unwrap().is_empty(), "a live listener never claims");
        listener.close().await;
    }

    #[tokio::test]
    async fn listener_requires_its_parts() {
        let err = EventListener::builder().name("n").build().unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));
    }
}
