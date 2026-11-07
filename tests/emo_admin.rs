//! EMO's read, alerting and dashboard actions against a mock server: request bodies as the
//! backend parses them, and responses as the backend writes them.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use euclid_rdk::emo::{
    AlertComparison, AlertSeverity, AlertState, AlertStatistic, CreateAlertRuleRequest, ListAlertHistoryRequest,
    ListAlertsRequest, ListMetricsRequest, MetricQuery, MetricType, Resolution, UpdateAlertRuleRequest,
};
use euclid_rdk::{Eam, Emo, Error};
use serde_json::{json, Value};
use wiremock::matchers::{header, method};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

type Seen = Arc<Mutex<Vec<Value>>>;

fn jwt() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{}}}"#, now + 3600));
    format!("{}.{payload}.sig", URL_SAFE_NO_PAD.encode(b"{}"))
}

async fn emo(server: &MockServer) -> Emo {
    let login = json!({
        "token": jwt(),
        "metadata": { "region": "eu-central-1", "accountId": "000000000000", "user": "jvo" }
    });
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

/// Mounts `action` answering `status` with `body` (no body when `Null`), recording each request body.
async fn mount(server: &MockServer, action: &str, status: u16, body: Value) -> Seen {
    let seen: Seen = Arc::default();
    let record = seen.clone();
    Mock::given(method("POST"))
        .and(header("x-euclid-target", "emo"))
        .and(header("x-euclid-action", action))
        .respond_with(move |req: &Request| {
            record.lock().unwrap().push(serde_json::from_slice(&req.body).unwrap());
            let response = ResponseTemplate::new(status);
            if body.is_null() {
                response
            } else {
                response.set_body_json(body.clone())
            }
        })
        .mount(server)
        .await;
    seen
}

fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn rule_json() -> Value {
    json!({
        "ruleId": "disk-full", "name": "disk-used-percent", "labels": { "path": "/data" },
        "resolution": "RAW", "statistic": "max", "comparison": "above",
        "warning": 85.0, "critical": null, "forPeriods": 2, "clearPeriods": 1, "noDataAfterPeriods": 0,
        "enabled": true, "description": "", "accountId": "000000000000", "namespace": "",
        "created": "2026-11-07T10:00:00Z", "modified": ""
    })
}

#[tokio::test]
async fn list_sends_only_the_filters_set_and_reads_rows() {
    let server = MockServer::start().await;
    let emo = emo(&server).await;
    let seen = mount(
        &server,
        "list",
        200,
        json!({ "items": [{
            "name": "disk-used-percent", "labels": { "path": "/data" }, "labelName": "path", "labelValue": "/data",
            "value": 42.5, "minValue": 40.0, "maxValue": 45.0, "samples": 5, "type": "GAUGE",
            "resolution": "HOUR", "timestamp": "2026-11-07T10:00:00Z"
        }]}),
    )
    .await;

    let rows = emo
        .list(&MetricQuery {
            labels: labels(&[("path", "/data")]),
            resolution: Some(Resolution::Hour),
            limit: Some(10),
            ..MetricQuery::named("disk-used-percent")
        })
        .await
        .unwrap();

    assert_eq!(
        seen.lock().unwrap()[0],
        json!({ "name": "disk-used-percent", "labels": { "path": "/data" }, "resolution": "HOUR", "limit": 10 })
    );
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.labels, labels(&[("path", "/data")]));
    assert_eq!(row.label_value, "/data");
    assert_eq!(
        (row.value, row.min_value, row.max_value, row.samples),
        (42.5, 40.0, 45.0, 5)
    );
    assert_eq!(row.kind, Some(MetricType::Gauge));
    assert_eq!(row.resolution, Resolution::Hour);
    assert_eq!(row.timestamp.as_deref(), Some("2026-11-07T10:00:00Z"));
}

#[tokio::test]
async fn average_reads_the_figure() {
    let server = MockServer::start().await;
    let emo = emo(&server).await;
    let seen = mount(&server, "average", 200, json!({ "average": 0.75 })).await;

    let average = emo.average(&MetricQuery::named("system-cpu-usage")).await.unwrap();

    assert_eq!(average, 0.75);
    assert_eq!(seen.lock().unwrap()[0], json!({ "name": "system-cpu-usage" }));
}

#[tokio::test]
async fn list_metrics_defaults_to_a_day_and_reads_infos() {
    let server = MockServer::start().await;
    let emo = emo(&server).await;
    let seen = mount(
        &server,
        "list-metrics",
        200,
        json!({ "items": [{
            "name": "disk-used-percent", "type": "GAUGE", "series": 2, "labelNames": ["path"],
            "lastSeen": "2026-11-07T10:00:00Z"
        }, { "name": "odd", "type": "UNKNOWN" }], "total": 2 }),
    )
    .await;

    let metrics = emo.list_metrics().await.unwrap();
    emo.list_metrics_with(&ListMetricsRequest {
        prefix: Some("disk-".into()),
        hours: 2,
    })
    .await
    .unwrap();

    let seen = seen.lock().unwrap();
    assert_eq!(seen[0], json!({ "hours": 24 }));
    assert_eq!(seen[1], json!({ "prefix": "disk-", "hours": 2 }));
    assert_eq!(metrics[0].name, "disk-used-percent");
    assert_eq!(metrics[0].kind, Some(MetricType::Gauge));
    assert_eq!(metrics[0].series, 2);
    assert_eq!(metrics[0].label_names, vec!["path".to_string()]);
    assert_eq!(metrics[1].kind, None);
}

#[tokio::test]
async fn create_alert_rule_leaves_unset_fields_to_the_server() {
    let server = MockServer::start().await;
    let emo = emo(&server).await;
    let seen = mount(&server, "create-alert-rule", 200, rule_json()).await;

    let rule = emo
        .create_alert_rule(&CreateAlertRuleRequest {
            labels: labels(&[("path", "/data")]),
            statistic: Some(AlertStatistic::Max),
            warning: Some(85.0),
            for_periods: Some(2),
            ..CreateAlertRuleRequest::new("disk-full", "disk-used-percent")
        })
        .await
        .unwrap();

    assert_eq!(
        seen.lock().unwrap()[0],
        json!({
            "ruleId": "disk-full", "name": "disk-used-percent", "labels": { "path": "/data" },
            "statistic": "max", "warning": 85.0, "forPeriods": 2
        })
    );
    assert_eq!(rule.rule_id, "disk-full");
    assert_eq!(rule.resolution, Resolution::Raw);
    assert_eq!(rule.statistic, AlertStatistic::Max);
    assert_eq!(rule.comparison, AlertComparison::Above);
    assert_eq!((rule.warning, rule.critical), (Some(85.0), None));
    assert_eq!(
        (rule.for_periods, rule.clear_periods, rule.no_data_after_periods),
        (2, 1, 0)
    );
    assert!(rule.enabled);
    assert_eq!(rule.created.as_deref(), Some("2026-11-07T10:00:00Z"));
    assert_eq!(rule.modified, None, "an empty time reads as absent");
}

#[tokio::test]
async fn update_alert_rule_sends_removals_as_null() {
    let server = MockServer::start().await;
    let emo = emo(&server).await;
    let seen = mount(&server, "update-alert-rule", 200, rule_json()).await;

    emo.update_alert_rule(&UpdateAlertRuleRequest {
        warning: Some(Some(90.0)),
        critical: Some(None),
        labels: Some(BTreeMap::new()),
        enabled: Some(false),
        ..UpdateAlertRuleRequest::new("disk-full")
    })
    .await
    .unwrap();

    assert_eq!(
        seen.lock().unwrap()[0],
        json!({ "ruleId": "disk-full", "labels": {}, "warning": 90.0, "critical": null, "enabled": false })
    );
}

#[tokio::test]
async fn delete_and_list_alert_rules() {
    let server = MockServer::start().await;
    let emo = emo(&server).await;
    let deleted = mount(&server, "delete-alert-rule", 200, Value::Null).await;
    let listed = mount(&server, "list-alert-rules", 200, json!({ "items": [rule_json()] })).await;

    emo.delete_alert_rule("disk-full").await.unwrap();
    let rules = emo.list_alert_rules().await.unwrap();
    let one = emo.get_alert_rule("disk-full").await.unwrap();
    let none = emo.get_alert_rule("other").await.unwrap();

    assert_eq!(deleted.lock().unwrap()[0], json!({ "ruleId": "disk-full" }));
    let listed = listed.lock().unwrap();
    assert_eq!(listed[0], json!({}));
    assert_eq!(listed[1], json!({ "ruleId": "disk-full" }));
    assert_eq!(rules.len(), 1);
    assert_eq!(one.unwrap().name, "disk-used-percent");
    assert!(none.is_none());
}

#[tokio::test]
async fn list_alerts_filters_and_reads_states() {
    let server = MockServer::start().await;
    let emo = emo(&server).await;
    let seen = mount(
        &server,
        "list-alerts",
        200,
        json!({ "items": [{
            "ruleId": "disk-full", "name": "disk-used-percent", "labels": { "path": "/data" },
            "state": "NO_DATA", "severity": "nodata", "since": "2026-11-07T10:00:00Z", "value": 97.0,
            "lastSeen": "", "statistic": "max", "comparison": "above", "warning": 85.0, "critical": 95.0,
            "description": "data volume", "namespace": "prod"
        }]}),
    )
    .await;

    let alerts = emo
        .list_alerts(&ListAlertsRequest {
            state: Some(AlertState::NoData),
            active: Some(true),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(seen.lock().unwrap()[0], json!({ "state": "NO_DATA", "active": true }));
    let alert = &alerts[0];
    assert_eq!(alert.state, AlertState::NoData);
    assert_eq!(alert.severity, AlertSeverity::Nodata);
    assert_eq!(alert.last_seen, None);
    assert_eq!((alert.warning, alert.critical), (Some(85.0), Some(95.0)));
    assert_eq!(alert.namespace, "prod");
}

#[tokio::test]
async fn list_alert_history_reads_transitions() {
    let server = MockServer::start().await;
    let emo = emo(&server).await;
    let seen = mount(
        &server,
        "list-alert-history",
        200,
        json!({ "items": [{
            "ruleId": "disk-full", "name": "disk-used-percent", "labels": { "path": "/data" },
            "previous": "CRITICAL", "state": "OK", "severity": "ok", "value": 50.0, "threshold": null,
            "statistic": "max", "reason": "rule-deleted", "timestamp": "2026-11-07T10:05:00Z",
            "accountId": "000000000000", "namespace": ""
        }, { "previous": "SOMETHING_NEW", "state": "WARNING", "reason": "" }]}),
    )
    .await;

    let history = emo
        .list_alert_history(&ListAlertHistoryRequest {
            rule_id: Some("disk-full".into()),
            limit: Some(5),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(seen.lock().unwrap()[0], json!({ "ruleId": "disk-full", "limit": 5 }));
    assert_eq!(history[0].previous, AlertState::Critical);
    assert_eq!(history[0].state, AlertState::Ok);
    assert_eq!(history[0].threshold, None);
    assert_eq!(history[0].reason.as_deref(), Some("rule-deleted"));
    assert_eq!(history[1].previous, AlertState::Unknown);
    assert_eq!(history[1].reason, None);
}

#[tokio::test]
async fn alert_actions_surface_forbidden() {
    let server = MockServer::start().await;
    let emo = emo(&server).await;
    mount(
        &server,
        "list-alert-rules",
        403,
        json!({ "message": "Administrator privileges required" }),
    )
    .await;

    let err = emo.list_alert_rules().await.unwrap_err();
    assert!(matches!(err, Error::Service { .. }));
    assert_eq!(err.status(), Some(403));
}

#[tokio::test]
async fn dashboards_round_trip() {
    let server = MockServer::start().await;
    let emo = emo(&server).await;
    let layout = json!({ "panels": [{ "metric": "disk-used-percent" }] });
    let saved = mount(
        &server,
        "save-dashboard",
        200,
        json!({ "name": "ops", "userId": "jvo", "modified": "2026-11-07T10:00:00Z" }),
    )
    .await;
    let got = mount(
        &server,
        "get-dashboard",
        200,
        json!({ "name": "ops", "dashboard": layout, "created": "2026-11-01T00:00:00Z", "modified": "2026-11-07T10:00:00Z" }),
    )
    .await;
    let listed = mount(
        &server,
        "list-dashboards",
        200,
        json!({ "userId": "jvo", "items": [{ "name": "ops", "created": "2026-11-01T00:00:00Z", "modified": "2026-11-07T10:00:00Z" }] }),
    )
    .await;
    let deleted = mount(&server, "delete-dashboard", 200, Value::Null).await;

    let result = emo.save_dashboard("ops", &layout).await.unwrap();
    let dashboard = emo.get_dashboard("ops").await.unwrap();
    let list = emo.list_dashboards().await.unwrap();
    emo.delete_dashboard("ops").await.unwrap();

    assert_eq!(saved.lock().unwrap()[0], json!({ "name": "ops", "dashboard": layout }));
    assert_eq!(result.user_id, "jvo");
    assert_eq!(got.lock().unwrap()[0], json!({ "name": "ops" }));
    assert_eq!(dashboard.dashboard, layout);
    assert_eq!(dashboard.created.as_deref(), Some("2026-11-01T00:00:00Z"));
    assert_eq!(listed.lock().unwrap()[0], json!({}));
    assert_eq!(list.user_id, "jvo");
    assert_eq!(list.items[0].name, "ops");
    assert_eq!(deleted.lock().unwrap()[0], json!({ "name": "ops" }));
}

#[tokio::test]
async fn missing_dashboard_is_not_found() {
    let server = MockServer::start().await;
    let emo = emo(&server).await;
    mount(
        &server,
        "get-dashboard",
        404,
        json!({ "message": "No dashboard called 'x'" }),
    )
    .await;

    assert_eq!(emo.get_dashboard("x").await.unwrap_err().status(), Some(404));
}
