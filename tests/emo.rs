//! EMO against a mock server: the push body, authentication, errors and - with the `metrics`
//! feature - the recorder's aggregation, scheduled pushes and flush on shutdown.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use euclid_rdk::emo::{Metric, MetricType};
use euclid_rdk::{Eam, Emo, Error};
use serde_json::{json, Value};
use wiremock::matchers::{header, method};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

type Seen = Arc<std::sync::Mutex<Vec<(Value, String)>>>;

fn jwt() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{}}}"#, now + 3600));
    format!("{}.{payload}.sig", URL_SAFE_NO_PAD.encode(b"{}"))
}

async fn emo(server: &MockServer, with_access_key: bool) -> Emo {
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
        .emo()
}

/// Mounts `push-metrics` answering 200 with an empty body, recording each body and authorization.
async fn mount(server: &MockServer) -> Seen {
    let seen: Seen = Arc::default();
    let record = seen.clone();
    Mock::given(method("POST"))
        .and(header("x-euclid-target", "emo"))
        .and(header("x-euclid-action", "push-metrics"))
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
            ResponseTemplate::new(200)
        })
        .mount(server)
        .await;
    seen
}

fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

#[tokio::test]
async fn push_metrics_sends_module_and_items_signed() {
    let server = MockServer::start().await;
    let emo = emo(&server, true).await;
    let seen = mount(&server).await;

    emo.push_metrics(
        "parser-dev",
        &[
            Metric::gauge("application-utilisation", labels(&[("instance", "i-1")]), 42.5),
            Metric::rate("messages", BTreeMap::new(), 7.0),
        ],
    )
    .await
    .unwrap();

    let seen = seen.lock().unwrap();
    let (body, auth) = &seen[0];
    assert_eq!(
        body,
        &json!({
            "module": "parser-dev",
            "items": [
                { "name": "application-utilisation", "labels": { "instance": "i-1" }, "value": 42.5, "type": "gauge" },
                { "name": "messages", "labels": {}, "value": 7.0, "type": "rate" }
            ]
        })
    );
    assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIATEST/"), "{auth}");
}

#[tokio::test]
async fn push_metrics_uses_bearer_without_access_key() {
    let server = MockServer::start().await;
    let emo = emo(&server, false).await;
    let seen = mount(&server).await;

    emo.push_metrics("m", &[Metric::rate("x", BTreeMap::new(), 1.0)])
        .await
        .unwrap();
    assert!(seen.lock().unwrap()[0].1.starts_with("Bearer "));
}

#[tokio::test]
async fn empty_push_sends_nothing() {
    let server = MockServer::start().await;
    let emo = emo(&server, true).await;
    Mock::given(header("x-euclid-action", "push-metrics"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;

    emo.push_metrics("m", &[]).await.unwrap();
}

#[tokio::test]
async fn push_errors_carry_action_and_status() {
    let server = MockServer::start().await;
    let emo = emo(&server, true).await;
    Mock::given(header("x-euclid-action", "push-metrics"))
        .respond_with(ResponseTemplate::new(400).set_body_string("unknown metric type"))
        .mount(&server)
        .await;

    let err = emo
        .push_metrics("m", &[Metric::gauge("x", BTreeMap::new(), 1.0)])
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Service { status: 400, .. }));
    assert_eq!(
        err.to_string(),
        "emo push-metrics failed with status 400: unknown metric type"
    );
}

#[test]
fn metric_constructors_and_first_dimension() {
    let single = Metric::labelled("cpu", "instance", "i-1", 0.5, MetricType::Gauge);
    assert_eq!(single.label_name(), "instance");
    assert_eq!(single.label_value(), "i-1");

    let unlabelled = Metric::labelled("cpu", "  ", "ignored", 0.5, MetricType::Rate);
    assert!(unlabelled.labels.is_empty());
    assert_eq!(unlabelled.label_name(), "");

    let many = Metric::gauge("heap", labels(&[("id", "eden"), ("area", "heap")]), 1.0);
    assert_eq!(many.label_name(), "area");
    assert_eq!(serde_json::to_value(&many).unwrap()["type"], "gauge");
}

#[cfg(feature = "metrics")]
mod recorder {
    use std::time::Duration;

    use metrics::Unit;

    use super::*;

    fn find<'a>(items: &'a [Value], name: &str) -> &'a Value {
        items
            .iter()
            .find(|i| i["name"] == name)
            .unwrap_or_else(|| panic!("{name} missing in {items:?}"))
    }

    #[tokio::test]
    async fn flush_publishes_the_step_and_shutdown_the_rest() {
        let server = MockServer::start().await;
        let emo = emo(&server, true).await;
        let seen = mount(&server).await;
        let (recorder, handle) = emo
            .recorder("parser-dev")
            .step(Duration::from_secs(3600))
            .build()
            .unwrap();

        metrics::with_local_recorder(&recorder, || {
            metrics::describe_histogram!("request.latency", Unit::Seconds, "time per request");
            metrics::counter!("messages", "queue" => "orders").increment(3);
            metrics::counter!("messages", "queue" => "orders").increment(2);
            metrics::gauge!("queue.depth").set(12.0);
            metrics::histogram!("request.latency").record(0.2);
            metrics::histogram!("request.latency").record(0.4);
        });
        handle.flush().await.unwrap();

        metrics::with_local_recorder(&recorder, || {
            metrics::counter!("messages", "queue" => "orders").increment(1);
        });
        handle.shutdown().await.unwrap();

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        let first = &seen[0].0;
        assert_eq!(first["module"], "parser-dev");
        let items = first["items"].as_array().unwrap();
        let messages = find(items, "messages");
        assert_eq!(messages["value"], 5.0);
        assert_eq!(messages["type"], "rate");
        assert_eq!(messages["labels"], json!({ "queue": "orders" }));
        assert_eq!(find(items, "queue.depth")["value"], 12.0);
        assert_eq!(find(items, "queue.depth")["type"], "gauge");
        // Seconds are published as milliseconds, like every duration euclid records.
        assert_eq!(find(items, "request.latency.count")["value"], 2.0);
        let total = find(items, "request.latency.total")["value"].as_f64().unwrap();
        assert!((total - 600.0).abs() < 1e-9, "{total}");
        assert_eq!(find(items, "request.latency.max")["value"], 400.0);
        assert_eq!(find(items, "request.latency.max")["type"], "gauge");

        // The partial step published on shutdown counts only what came after the flush.
        let rest = seen[1].0["items"].as_array().unwrap();
        assert_eq!(find(rest, "messages")["value"], 1.0);
        assert_eq!(find(rest, "request.latency.count")["value"], 0.0);
    }

    #[tokio::test]
    async fn publishes_every_step_and_survives_a_failed_push() {
        let server = MockServer::start().await;
        let emo = emo(&server, true).await;
        let pushes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = pushes.clone();
        Mock::given(header("x-euclid-action", "push-metrics"))
            .respond_with(move |_: &Request| {
                // The first scheduled push fails; the schedule must carry on regardless.
                match counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst) {
                    0 => ResponseTemplate::new(503),
                    _ => ResponseTemplate::new(200),
                }
            })
            .mount(&server)
            .await;

        let (recorder, handle) = emo.recorder("m").step(Duration::from_millis(100)).build().unwrap();
        metrics::with_local_recorder(&recorder, || metrics::gauge!("up").set(1.0));

        let started = std::time::Instant::now();
        while pushes.load(std::sync::atomic::Ordering::SeqCst) < 3 {
            assert!(started.elapsed() < Duration::from_secs(5), "scheduled pushes stopped");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        drop(handle);
    }

    #[tokio::test]
    async fn nothing_recorded_sends_nothing() {
        let server = MockServer::start().await;
        let emo = emo(&server, true).await;
        Mock::given(header("x-euclid-action", "push-metrics"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        let (_recorder, handle) = emo.recorder("m").step(Duration::from_millis(50)).build().unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn zero_step_is_refused() {
        let server = MockServer::start().await;
        let emo = emo(&server, true).await;
        let err = emo.recorder("m").step(Duration::ZERO).build().unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));
    }

    #[test]
    fn building_outside_a_runtime_is_refused() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let (_server, emo) = runtime.block_on(async {
            let server = MockServer::start().await;
            let emo = emo(&server, true).await;
            (server, emo)
        });
        let err = emo.recorder("m").build().unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "{err:?}");
    }

    #[tokio::test]
    async fn install_sets_the_global_recorder_once() {
        let server = MockServer::start().await;
        let emo = emo(&server, true).await;
        let handle = emo.recorder("m").install().unwrap();
        let err = emo.recorder("m").install().unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));
        drop(handle);
    }
}
