//! EAP against a mock server: authentication, request bodies, response parsing, errors, and the
//! egress limiter.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use euclid_rdk::eap::{
    ApplicationType, CreateApplicationRequest, EgressLimiter, EgressTimeout, ScaleApplicationRequest,
    SetApplicationLimitsRequest, UpdateApplicationRequest,
};
use euclid_rdk::{Eam, Eap, Error};
use serde_json::{json, Value};
use wiremock::matchers::{header, method};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

fn jwt() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{}}}"#, now + 3600));
    format!("{}.{payload}.sig", URL_SAFE_NO_PAD.encode(b"{}"))
}

async fn eap(server: &MockServer, with_access_key: bool) -> Eap {
    let mut login = json!({
        "token": jwt(),
        "isAdmin": true,
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
        .eap()
}

type Seen = Arc<Mutex<Vec<(Value, String)>>>;

/// Mounts `action` answering `status`/`answer`, and records each request (body, authorization).
async fn mount_status(server: &MockServer, action: &str, status: u16, answer: Value) -> Seen {
    let seen: Seen = Arc::default();
    let record = seen.clone();
    Mock::given(method("POST"))
        .and(header("x-euclid-target", "eap"))
        .and(header("x-euclid-action", action))
        .respond_with(move |req: &Request| {
            let auth = req
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            let body = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            record.lock().unwrap().push((body, auth));
            ResponseTemplate::new(status).set_body_json(answer.clone())
        })
        .mount(server)
        .await;
    seen
}

async fn mount(server: &MockServer, action: &str, answer: Value) -> Seen {
    mount_status(server, action, 200, answer).await
}

fn bodies(seen: &Seen) -> Vec<Value> {
    seen.lock().unwrap().iter().map(|(b, _)| b.clone()).collect()
}

fn application_json() -> Value {
    json!({
        "applicationId": "billing", "runtimeName": "eap-billing-7f3a",
        "ern": "ern:eap:eu-central-1:000000000000:development:application:billing",
        "accountId": "000000000000", "namespace": "development", "region": "eu-central-1",
        "runtime": "java25", "bucketErn": "ern:esm:eu-central-1:000000000000:development:bucket:apps",
        "artifactKey": "billing-1.2.0.jar", "version": "1.2.0", "md5Sum": "abc", "command": "",
        "arguments": ["--port", 8080], "environment": { "DB_PASSWORD": "hunter2", "WORKERS": 4 },
        "resources": ["ern:eqs:eu-central-1:000000000000:development:queue:orders"],
        "userId": "app-billing", "userExists": true, "logLevel": "INFO",
        "minInstances": 1, "maxInstances": 4, "readyTimeoutMs": 30000,
        "memoryLimitMb": 512, "cpuLimit": 0.5, "artifactSize": 1048576,
        "nodeLabels": { "zone": "a" }, "type": "PROCESS", "schedule": "", "nextRunAt": "",
        "desiredState": "RUNNING", "state": "RUNNING", "instances": 2,
        "endpoints": [{ "instanceId": "i-1", "pid": 4711, "httpPort": 8081 }, { "instanceId": "i-2" }],
        "created": "2026-11-01T10:00:00Z", "modified": "2026-11-02T10:00:00Z"
    })
}

#[tokio::test]
async fn requests_are_signed_or_carry_the_bearer_token() {
    let server = MockServer::start().await;
    let signed = eap(&server, true).await;
    let seen = mount(&server, "list-applications", json!({ "applications": [] })).await;
    signed.list_applications().await.unwrap();
    let bearer = MockServer::start().await;
    let plain = eap(&bearer, false).await;
    let seen_plain = mount(&bearer, "list-applications", json!({})).await;
    assert!(plain.list_applications().await.unwrap().is_empty());

    let (body, auth) = seen.lock().unwrap()[0].clone();
    assert_eq!(body, json!({ "prefix": "" }));
    assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIATEST/"), "{auth}");
    assert!(auth.contains("/eu-central-1/eap/aws4_request"));
    assert!(seen_plain.lock().unwrap()[0].1.starts_with("Bearer "));
}

#[tokio::test]
async fn applications_parse_like_the_jdk() {
    let server = MockServer::start().await;
    let eap = eap(&server, true).await;
    mount(
        &server,
        "list-applications",
        json!({ "applications": [application_json()] }),
    )
    .await;
    let seen = mount(&server, "get-application", application_json()).await;

    let apps = eap.list_applications().await.unwrap();
    assert_eq!(apps.len(), 1);
    let app = eap.get_application("billing").await.unwrap();
    assert_eq!(bodies(&seen), [json!({ "applicationId": "billing" })]);
    assert_eq!(app, apps[0]);
    assert_eq!(app.application_type, ApplicationType::Process);
    assert!(!app.application_type.is_job());
    assert_eq!(app.arguments, ["--port", "8080"]);
    assert_eq!(app.environment["WORKERS"], "4");
    assert_eq!(app.next_run_at, None);
    assert_eq!(app.endpoints[0].pid, 4711);
    assert_eq!(app.endpoints[1].pid, -1);
    assert_eq!(app.endpoints[1].http_port, 0);
    assert_eq!(app.min_instances, 1);
    assert_eq!(app.memory_limit_mb, 512);
    assert_eq!(app.cpu_limit, 0.5);
    assert_eq!(app.artifact_size, 1_048_576);
    assert!(app.user_exists);

    // Environment values never show in Debug output.
    let debug = format!("{app:?}");
    assert!(debug.contains("DB_PASSWORD"));
    assert!(!debug.contains("hunter2"), "{debug}");
}

#[tokio::test]
async fn unknown_application_type_reads_as_unknown() {
    let server = MockServer::start().await;
    let eap = eap(&server, false).await;
    mount(
        &server,
        "get-application",
        json!({ "applicationId": "x", "type": "job" }),
    )
    .await;
    assert_eq!(
        eap.get_application("x").await.unwrap().application_type,
        ApplicationType::Unknown
    );
    assert_eq!(ApplicationType::from_wire_value("JOB"), ApplicationType::Job);
    assert_eq!(ApplicationType::Job.wire_value(), "JOB");
}

#[tokio::test]
async fn create_and_update_send_only_what_is_set() {
    let server = MockServer::start().await;
    let eap = eap(&server, true).await;
    let created = mount(&server, "create-application", application_json()).await;
    let updated = mount(&server, "update-application", application_json()).await;
    let scaled = mount(&server, "scale-application", application_json()).await;

    let mut environment = BTreeMap::new();
    environment.insert("DB_PASSWORD".to_owned(), "hunter2".to_owned());
    let request = CreateApplicationRequest {
        application_id: Some("billing".into()),
        runtime: Some("java25".into()),
        bucket: Some("apps".into()),
        artifact: Some("billing-1.2.0.jar".into()),
        environment: Some(environment),
        queues: Some(vec!["orders".into()]),
        min_instances: Some(1),
        application_type: Some(ApplicationType::Job.wire_value().into()),
        schedule: Some("0 * * * *".into()),
        ..Default::default()
    };
    assert!(!format!("{request:?}").contains("hunter2"));
    eap.create_application(&request).await.unwrap();
    eap.update_application(&UpdateApplicationRequest {
        application_id: Some("billing".into()),
        max_instances: Some(8),
        ..Default::default()
    })
    .await
    .unwrap();
    eap.scale_application(&ScaleApplicationRequest {
        application_id: Some("billing".into()),
        min_instances: Some(2),
        max_instances: None,
    })
    .await
    .unwrap();

    assert_eq!(
        bodies(&created),
        [json!({
            "applicationId": "billing", "runtime": "java25", "bucket": "apps",
            "artifact": "billing-1.2.0.jar", "environment": { "DB_PASSWORD": "hunter2" },
            "queues": ["orders"], "minInstances": 1, "type": "JOB", "schedule": "0 * * * *"
        })]
    );
    assert_eq!(
        bodies(&updated),
        [json!({ "applicationId": "billing", "maxInstances": 8 })]
    );
    assert_eq!(
        bodies(&scaled),
        [json!({ "applicationId": "billing", "minInstances": 2 })]
    );
}

#[tokio::test]
async fn set_application_limits_sends_only_the_limits_given() {
    let server = MockServer::start().await;
    let eap = eap(&server, true).await;
    let limits = mount(&server, "set-application-limits", application_json()).await;

    let app = eap
        .set_application_limits(&SetApplicationLimitsRequest {
            application_id: Some("billing".into()),
            memory_limit_mb: Some(512),
            cpu_limit: Some(0.5),
        })
        .await
        .unwrap();
    assert_eq!(app.memory_limit_mb, 512);
    assert_eq!(app.cpu_limit, 0.5);

    // A limit not given stays out of the body: the server would refuse one sent as null.
    eap.set_application_limits(&SetApplicationLimitsRequest {
        application_id: Some("billing".into()),
        cpu_limit: Some(2.0),
        ..Default::default()
    })
    .await
    .unwrap();

    assert_eq!(
        bodies(&limits),
        [
            json!({ "applicationId": "billing", "memoryLimitMb": 512, "cpuLimit": 0.5 }),
            json!({ "applicationId": "billing", "cpuLimit": 2.0 }),
        ]
    );
}

#[tokio::test]
async fn set_application_limits_surfaces_a_refused_admission() {
    let server = MockServer::start().await;
    let eap = eap(&server, true).await;
    mount_status(
        &server,
        "set-application-limits",
        409,
        json!({ "error": "the account's nodes cannot hold 2 instances of 64000 MiB" }),
    )
    .await;
    let err = eap
        .set_application_limits(&SetApplicationLimitsRequest {
            application_id: Some("billing".into()),
            memory_limit_mb: Some(64000),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.status(), Some(409));
    assert!(err
        .to_string()
        .starts_with("eap set-application-limits failed with status 409"));
}

#[tokio::test]
async fn lifecycle_actions_send_the_application_id() {
    let server = MockServer::start().await;
    let eap = eap(&server, true).await;
    let start = mount(&server, "start-application", application_json()).await;
    let delete = mount(&server, "delete-application", json!({})).await;
    let restart = mount(
        &server,
        "restart-application",
        json!({ "applicationId": "billing", "restarting": true, "instances": 2 }),
    )
    .await;
    let rebalance = mount(
        &server,
        "rebalance-application",
        json!({ "applicationId": "billing", "rebalancing": false, "instances": "3" }),
    )
    .await;
    let log = mount(
        &server,
        "set-log-level",
        json!({ "applicationId": "billing", "logLevel": "", "channel": "eap-billing" }),
    )
    .await;

    eap.start_application("billing").await.unwrap();
    eap.delete_application("billing").await.unwrap();
    let r = eap.restart_application("billing").await.unwrap();
    assert!(r.restarting);
    assert_eq!(r.instances, 2);
    let b = eap.rebalance_application("billing").await.unwrap();
    assert_eq!(b.instances, 3);
    let l = eap.reset_log_level("billing").await.unwrap();
    assert_eq!(l.channel.as_deref(), Some("eap-billing"));

    for seen in [&start, &delete, &restart, &rebalance] {
        assert_eq!(bodies(seen), [json!({ "applicationId": "billing" })]);
    }
    assert_eq!(bodies(&log), [json!({ "applicationId": "billing", "level": "" })]);
}

#[tokio::test]
async fn infrastructure_and_platform_bodies() {
    let server = MockServer::start().await;
    let eap = eap(&server, true).await;
    let answer = json!({
        "applicationId": "billing", "declared": true, "dryRun": true, "created": ["ern:a"],
        "updated": [{ "ern": "ern:b", "changes": ["visibility"] }],
        "kept": [{ "ern": "ern:c", "reason": "not empty" }]
    });
    let apply = mount(&server, "apply-infrastructure", answer.clone()).await;
    let plan = mount(&server, "plan-infrastructure", answer.clone()).await;
    let platform = mount(&server, "plan-platform", answer).await;
    let get = mount(
        &server,
        "get-platform",
        json!({ "name": "platform", "owns": ["ern:x"], "declaration": { "queues": [] } }),
    )
    .await;

    eap.apply_infrastructure("billing", true).await.unwrap();
    let declaration = json!({ "queues": [{ "name": "orders" }] });
    let planned = eap
        .plan_infrastructure("billing", Some(&declaration), false)
        .await
        .unwrap();
    assert!(planned.dry_run);
    assert_eq!(planned.updated[0].changes, ["visibility"]);
    assert_eq!(planned.kept[0].reason.as_deref(), Some("not empty"));
    eap.plan_platform("", &declaration, true).await.unwrap();
    let p = eap.get_platform("").await.unwrap();
    assert_eq!(p.declaration, Some(json!({ "queues": [] })));

    assert_eq!(bodies(&apply), [json!({ "applicationId": "billing", "prune": true })]);
    assert_eq!(
        bodies(&plan),
        [json!({ "applicationId": "billing", "prune": false, "declaration": declaration })]
    );
    assert_eq!(
        bodies(&platform),
        [json!({ "name": "platform", "prune": true, "declaration": declaration })]
    );
    assert_eq!(bodies(&get), [json!({ "name": "platform" })]);
}

#[tokio::test]
async fn nodes_and_egress_sites() {
    let server = MockServer::start().await;
    let eap = eap(&server, true).await;
    mount(
        &server,
        "list-nodes",
        json!({ "nodes": [
            { "name": "n1", "cpuCount": 8, "memoryMb": 12288, "memoryTotalMb": 16384, "memoryUsedMb": 4096, "live": true },
            { "name": "n2" }
        ] }),
    )
    .await;
    mount(
        &server,
        "get-node",
        json!({ "name": "n1", "applications": [{ "applicationId": "billing", "instances": 2, "running": 1 }] }),
    )
    .await;
    let sites = mount(
        &server,
        "list-egress-sites",
        json!({
            "defaultLimits": { "requestsPerSecond": 1.5, "burst": 3, "concurrent": 2 },
            "sites": [{ "applicationId": "billing", "site": "api.example.com", "limitsSet": true,
                        "limits": { "requestsPerSecond": 5 }, "tokens": 2.5, "inFlight": 1,
                        "blockedUntil": "", "lastUsed": "2026-11-02T10:00:00Z" }]
        }),
    )
    .await;
    let limit = mount(
        &server,
        "set-egress-limit",
        json!({ "applicationId": "billing", "site": "api.example.com", "limits": { "concurrent": 3 } }),
    )
    .await;

    let nodes = eap.list_nodes().await.unwrap();
    assert_eq!(nodes.total, 2, "total falls back to the number of nodes");
    assert_eq!(nodes.nodes[0].cpu_count, 8);
    assert_eq!(nodes.nodes[0].memory_mb, 12288);
    assert_eq!(nodes.nodes[0].memory_total_mb, 16384);
    assert_eq!(nodes.nodes[0].memory_used_mb, 4096);
    assert_eq!(nodes.nodes[1].memory_total_mb, 0);
    assert_eq!(nodes.nodes[0].applications, None);
    let node = eap.get_node("n1").await.unwrap();
    assert_eq!(node.applications.unwrap()[0].running, 1);

    let all = eap.list_egress_sites(None).await.unwrap();
    assert_eq!(all.default_limits.burst, 3.0);
    assert_eq!(all.sites[0].limits.requests_per_second, 5.0);
    assert_eq!(all.sites[0].blocked_until, None);
    eap.list_egress_sites(Some("billing")).await.unwrap();
    assert_eq!(bodies(&sites), [json!({}), json!({ "applicationId": "billing" })]);

    let set = eap
        .set_egress_limit("billing", "api.example.com", None, None, Some(3))
        .await
        .unwrap();
    assert_eq!(set.limits.concurrent, 3);
    assert_eq!(
        bodies(&limit),
        [json!({ "applicationId": "billing", "site": "api.example.com", "concurrent": 3 })]
    );
}

#[tokio::test]
async fn refusals_map_to_service_errors() {
    let server = MockServer::start().await;
    let eap = eap(&server, true).await;
    mount_status(
        &server,
        "get-application",
        403,
        json!({ "error": "administrator only" }),
    )
    .await;
    match eap.get_application("billing").await.unwrap_err() {
        Error::Service {
            service,
            action,
            status,
            ..
        } => {
            assert_eq!(
                (service.as_str(), action.as_str(), status),
                ("eap", "get-application", 403)
            );
        }
        other => panic!("unexpected {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// Egress limiter
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn limiter_waits_for_a_permit_and_releases_it() {
    let server = MockServer::start().await;
    let eap = eap(&server, true).await;
    let asked = Arc::new(AtomicUsize::new(0));
    let count = asked.clone();
    let acquired: Seen = Arc::default();
    let record = acquired.clone();
    Mock::given(header("x-euclid-action", "acquire-egress-permit"))
        .respond_with(move |req: &Request| {
            record
                .lock()
                .unwrap()
                .push((serde_json::from_slice(&req.body).unwrap(), String::new()));
            if count.fetch_add(1, Ordering::SeqCst) < 2 {
                ResponseTemplate::new(200).set_body_json(json!({
                    "site": "api.example.com", "granted": false, "reason": "rate", "retryAfterMs": 20
                }))
            } else {
                ResponseTemplate::new(200).set_body_json(json!({
                    "site": "api.example.com", "granted": true, "permitId": "p-1"
                }))
            }
        })
        .mount(&server)
        .await;
    let released = mount(&server, "release-egress-permit", json!({ "released": true })).await;

    let limiter = EgressLimiter::new(eap, "billing")
        .unwrap()
        .lease_time(Duration::from_secs(60));
    let permit = limiter.acquire(" API.Example.com. ").await.unwrap();
    assert_eq!(asked.load(Ordering::SeqCst), 3);
    assert_eq!(permit.site(), "api.example.com");
    assert_eq!(permit.id(), Some("p-1"));
    assert!(!permit.is_local());
    permit.release().await;

    assert_eq!(
        bodies(&acquired)[0],
        json!({ "applicationId": "billing", "site": "api.example.com", "leaseSeconds": 60 })
    );
    assert_eq!(
        bodies(&released),
        [json!({ "applicationId": "billing", "site": "api.example.com", "permitId": "p-1" })]
    );
}

#[tokio::test]
async fn limiter_gives_up_after_max_wait() {
    let server = MockServer::start().await;
    let eap = eap(&server, true).await;
    mount(
        &server,
        "acquire-egress-permit",
        json!({ "site": "api.example.com", "granted": false, "reason": "blocked", "retryAfterMs": 30 }),
    )
    .await;

    let limiter = EgressLimiter::new(eap, "billing")
        .unwrap()
        .max_wait(Duration::from_millis(150));
    let started = Instant::now();
    let err = limiter.acquire("api.example.com").await.unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(2));
    let timeout = EgressTimeout::from_error(&err).expect("an egress timeout");
    assert_eq!(timeout.site, "api.example.com");
    assert_eq!(timeout.reason.as_deref(), Some("blocked"));
    assert!(timeout.waited <= Duration::from_millis(150));
    match &err {
        Error::Io(io) => assert_eq!(io.kind(), std::io::ErrorKind::TimedOut),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn limiter_falls_back_to_local_pacing_when_euclid_cannot_be_asked() {
    let server = MockServer::start().await;
    let eap = eap(&server, true).await;
    mount_status(&server, "acquire-egress-permit", 503, json!({ "error": "restarting" })).await;
    let released = mount(&server, "release-egress-permit", json!({ "released": true })).await;

    let limiter = EgressLimiter::new(eap, "billing")
        .unwrap()
        .fallback_interval(Duration::from_millis(200));
    let started = Instant::now();
    let first = limiter.acquire("api.example.com").await.unwrap();
    let second = limiter.clone().acquire("api.example.com").await.unwrap();
    let other_site = limiter.acquire("other.example.com").await.unwrap();
    let elapsed = started.elapsed();
    assert!(first.is_local() && second.is_local() && other_site.is_local());
    assert!(
        elapsed >= Duration::from_millis(190),
        "second permit not spaced: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(390),
        "other site waited too: {elapsed:?}"
    );
    first.release().await;
    second.release().await;
    other_site.release().await;
    assert!(
        released.lock().unwrap().is_empty(),
        "a local permit has nothing to release"
    );
}

#[tokio::test]
async fn limiter_run_releases_and_throttled_never_fails() {
    let server = MockServer::start().await;
    let eap = eap(&server, true).await;
    mount(
        &server,
        "acquire-egress-permit",
        json!({ "granted": true, "permitId": "p-9" }),
    )
    .await;
    let released = mount(&server, "release-egress-permit", json!({ "released": true })).await;
    mount_status(&server, "report-egress-throttled", 500, json!({ "error": "down" })).await;

    let limiter = EgressLimiter::new(eap, "billing").unwrap();
    let out = limiter.run("api.example.com", async { 42 }).await.unwrap();
    assert_eq!(out, 42);
    assert_eq!(released.lock().unwrap().len(), 1);
    limiter.throttled("api.example.com", Duration::from_millis(10)).await;
    assert!(matches!(
        EgressLimiter::new(limiter_eap(&server).await, " "),
        Err(Error::InvalidArgument(_))
    ));
}

async fn limiter_eap(server: &MockServer) -> Eap {
    eap(server, false).await
}
