//! EAP - Euclid Application Platform (applications, nodes, egress). Every action is
//! administrator-only, except those an application calls about itself (load reports, egress
//! permits).
//!
//! An application is an artifact in an ESM bucket that euclid runs as a pool of processes.
//! Start, stop and the like only record `desired_state`; euclid-mgr's reconciler launches or tears
//! down the processes, so [`Application::state`] can lag briefly.

mod egress;
pub mod model;

use serde_json::{json, Map, Value};

pub use egress::{parse_retry_after, EgressLimiter, EgressTimeout, Permit};
pub use model::*;

use crate::service::ServiceClient;
use crate::Result;

/// Name a platform is stored under when none is given.
const DEFAULT_PLATFORM: &str = "platform";

/// EAP operations, obtained from [`Session::eap`](crate::Session::eap).
///
/// Requests are SigV4-signed with the session's access key when it has one, otherwise
/// authenticated with the bearer token. Cloning is cheap.
#[derive(Debug, Clone)]
pub struct Eap {
    client: ServiceClient,
}

fn application_body(application_id: &str) -> Value {
    json!({ "applicationId": application_id })
}

fn platform_name(name: &str) -> &str {
    if name.is_empty() {
        DEFAULT_PLATFORM
    } else {
        name
    }
}

impl Eap {
    pub(crate) fn new(client: ServiceClient) -> Self {
        Self { client }
    }

    // -----------------------------------------------------------------------------------------
    // Applications
    // -----------------------------------------------------------------------------------------

    /// Defines (deploys) an application. It is created stopped; see
    /// [`CreateApplicationRequest`] for how names are resolved.
    ///
    /// The infrastructure declaration stored beside the artifact, if there is one, is applied as
    /// part of the deployment, and what that did comes back as [`Application::infrastructure`]. A
    /// declaration that could not be applied does not fail the call, so look at its
    /// [`error`](ApplyInfrastructureResponse::error) before relying on what it declares.
    pub async fn create_application(&self, request: &CreateApplicationRequest) -> Result<Application> {
        let mut application: Application = self.client.call("create-application", request).await?;
        // The report is nested in the application and sent without its id; fill it in, so every
        // ApplyInfrastructureResponse handed out names its application or its platform.
        if let Some(report) = application.infrastructure.as_mut() {
            report.application_id = application.application_id.clone();
        }
        Ok(application)
    }

    /// Changes an application's definition; only the fields that are `Some` change.
    pub async fn update_application(&self, request: &UpdateApplicationRequest) -> Result<Application> {
        self.client.call("update-application", request).await
    }

    /// Defines the same application again in another namespace - how a build is promoted. The copy
    /// is created stopped and the original keeps running.
    pub async fn copy_application(&self, request: &CopyApplicationRequest) -> Result<Application> {
        self.client.call("copy-application", request).await
    }

    /// Changes an application's instance bounds.
    pub async fn scale_application(&self, request: &ScaleApplicationRequest) -> Result<Application> {
        self.client.call("scale-application", request).await
    }

    /// Sets an application's per-instance memory and/or CPU limit without restarting anything; the
    /// limits apply to instances as they start (use
    /// [`restart_application`](Self::restart_application) to give them to running ones). A limit
    /// left `None` is not sent and stays as it is. Refused with 400 when neither is set or a value
    /// is out of range, and with 409 when the account's nodes cannot hold the application at the
    /// new memory limit.
    pub async fn set_application_limits(&self, request: &SetApplicationLimitsRequest) -> Result<Application> {
        self.client.call("set-application-limits", request).await
    }

    /// Deploys a new build already uploaded to the application's bucket; running instances are
    /// restarted onto it, a stopped application comes up on it when next started.
    ///
    /// Refused with 409 when the artifact is byte for byte the build already deployed (unless
    /// [`force`](RedeployApplicationRequest::force) is set) or is still being uploaded, and with
    /// 404 when it is not in the bucket. [`update_application`](Self::update_application) applies
    /// no such check.
    pub async fn redeploy_application(&self, request: &RedeployApplicationRequest) -> Result<Application> {
        self.client.call("redeploy-application", request).await
    }

    /// Every application in the session's namespace.
    pub async fn list_applications(&self) -> Result<Vec<Application>> {
        self.list_applications_with_prefix("").await
    }

    /// The applications whose id starts with `prefix`.
    pub async fn list_applications_with_prefix(&self, prefix: &str) -> Result<Vec<Application>> {
        self.list_applications_with(&ListApplicationsRequest {
            prefix: prefix.into(),
            match_type: None,
        })
        .await
    }

    /// The applications whose id matches the request's search text the way it asks - as a
    /// prefix, a suffix, a substring or a regular expression. Only the session's namespace is
    /// searched. An unknown match type or a regular expression that does not compile is refused
    /// with 400.
    pub async fn list_applications_with(&self, request: &ListApplicationsRequest) -> Result<Vec<Application>> {
        self.client
            .call_field::<Option<Vec<Application>>>("list-applications", request, "applications")
            .await
            .map(Option::unwrap_or_default)
    }

    pub async fn get_application(&self, application_id: &str) -> Result<Application> {
        self.client
            .call("get-application", &application_body(application_id))
            .await
    }

    /// Deletes an application's definition, which also stops it; a principal EAP minted for it is
    /// removed with it.
    pub async fn delete_application(&self, application_id: &str) -> Result<()> {
        self.client
            .call_unit("delete-application", &application_body(application_id))
            .await
    }

    /// Records that the application should run; `state` follows once the reconciler has acted.
    pub async fn start_application(&self, application_id: &str) -> Result<Application> {
        self.client
            .call("start-application", &application_body(application_id))
            .await
    }

    /// Records that the application should stop, keeping its definition.
    pub async fn stop_application(&self, application_id: &str) -> Result<Application> {
        self.client
            .call("stop-application", &application_body(application_id))
            .await
    }

    /// Restarts a running application's instances without changing anything about it; the desired
    /// state stays `RUNNING` throughout. A stopped application is refused with 400.
    pub async fn restart_application(&self, application_id: &str) -> Result<RestartApplicationResponse> {
        self.client
            .call("restart-application", &application_body(application_id))
            .await
    }

    /// Spreads an application's instances over the nodes again, one move at a time. A JOB is
    /// refused with 400.
    pub async fn rebalance_application(&self, application_id: &str) -> Result<RebalanceApplicationResponse> {
        self.client
            .call("rebalance-application", &application_body(application_id))
            .await
    }

    /// Sets an application's log level (e.g. `"DEBUG"`).
    pub async fn set_log_level(&self, application_id: &str, level: &str) -> Result<SetLogLevelResponse> {
        let body = json!({ "applicationId": application_id, "level": level });
        self.client.call("set-log-level", &body).await
    }

    /// Returns an application to its default log level.
    pub async fn reset_log_level(&self, application_id: &str) -> Result<SetLogLevelResponse> {
        self.set_log_level(application_id, "").await
    }

    // -----------------------------------------------------------------------------------------
    // Infrastructure and platforms
    // -----------------------------------------------------------------------------------------

    /// Makes the installation match the application's infrastructure declaration
    /// (`<applicationId>.euclid.json` beside its artifact): creates what is missing, updates
    /// declared settings, grants access, and with `prune` deletes what it owned and no longer
    /// declares - but only when empty (see [`ApplyInfrastructureResponse::kept`]).
    pub async fn apply_infrastructure(&self, application_id: &str, prune: bool) -> Result<ApplyInfrastructureResponse> {
        let body = infrastructure_body(application_id, None, prune);
        self.client.call("apply-infrastructure", &body).await
    }

    /// What [`apply_infrastructure`](Self::apply_infrastructure) would do, changing nothing.
    /// `declaration` checks a declaration that is not stored yet.
    pub async fn plan_infrastructure(
        &self,
        application_id: &str,
        declaration: Option<&Value>,
        prune: bool,
    ) -> Result<ApplyInfrastructureResponse> {
        let body = infrastructure_body(application_id, declaration, prune);
        self.client.call("plan-infrastructure", &body).await
    }

    /// Applies a platform declaration - shared infrastructure of the namespace. An empty `name`
    /// means the default platform, `"platform"`.
    pub async fn apply_platform(
        &self,
        name: &str,
        declaration: &Value,
        prune: bool,
    ) -> Result<ApplyInfrastructureResponse> {
        let body = json!({ "name": platform_name(name), "prune": prune, "declaration": declaration });
        self.client.call("apply-platform", &body).await
    }

    /// What [`apply_platform`](Self::apply_platform) would do, changing nothing.
    pub async fn plan_platform(
        &self,
        name: &str,
        declaration: &Value,
        prune: bool,
    ) -> Result<ApplyInfrastructureResponse> {
        let body = json!({ "name": platform_name(name), "prune": prune, "declaration": declaration });
        self.client.call("plan-platform", &body).await
    }

    /// A platform by name (empty for the default one).
    pub async fn get_platform(&self, name: &str) -> Result<Platform> {
        self.client
            .call("get-platform", &json!({ "name": platform_name(name) }))
            .await
    }

    pub async fn list_platforms(&self) -> Result<Vec<Platform>> {
        self.client
            .call_field::<Option<Vec<Platform>>>("list-platforms", &json!({}), "platforms")
            .await
            .map(Option::unwrap_or_default)
    }

    // -----------------------------------------------------------------------------------------
    // Nodes
    // -----------------------------------------------------------------------------------------

    pub async fn list_nodes(&self) -> Result<ListNodesResponse> {
        let root = self.client.call_value("list-nodes", &json!({})).await?;
        let nodes: Vec<Node> = match root.get("nodes") {
            Some(Value::Array(_)) => serde_json::from_value(root["nodes"].clone())?,
            _ => Vec::new(),
        };
        let total = root.get("total").and_then(Value::as_u64).unwrap_or(nodes.len() as u64);
        Ok(ListNodesResponse { nodes, total })
    }

    /// One node, including what it is running.
    pub async fn get_node(&self, node: &str) -> Result<Node> {
        self.client.call("get-node", &json!({ "node": node })).await
    }

    pub async fn delete_node(&self, node: &str) -> Result<()> {
        self.client.call_unit("delete-node", &json!({ "node": node })).await
    }

    /// Drains a worker node: no new instances are placed on it, and the ones it has leave as they
    /// are replaced. Not a stop - the node keeps running what it has and keeps renewing; draining
    /// and then stopping the worker is how a machine is taken out of service. A drained node still
    /// counts as live ([`Node::drained`] says which state it is in). 404 if no node of that name is
    /// registered to the account.
    pub async fn drain_node(&self, node: &str) -> Result<DrainNodeResponse> {
        self.set_node_drained(node, true).await
    }

    /// Drains a worker node (`true`) or puts a drained one back into service (`false`). The flag
    /// is always sent, since the server reads its absence as "drain". Undraining moves nothing onto
    /// the node by itself; it only lets placement choose it again.
    pub async fn set_node_drained(&self, node: &str, drained: bool) -> Result<DrainNodeResponse> {
        let answer = self
            .client
            .call_value("drain-node", &json!({ "node": node, "drained": drained }))
            .await?;
        Ok(DrainNodeResponse {
            node: answer.get("node").and_then(Value::as_str).map(str::to_owned),
            // An answer without the flag reads as what was asked for, as euclid-jdk does.
            drained: answer.get("drained").and_then(Value::as_bool).unwrap_or(drained),
        })
    }

    /// Gives one instance slot to a worker node by hand, with a lease on the claim - or takes it
    /// back to the manager's own host when [`node`](AssignInstanceRequest::node) is empty.
    ///
    /// Placement does this by itself; this is the operator's override for moving one instance
    /// somewhere specific. The claim lasts one lease period; a node that does not renew it in time
    /// loses the slot to placement again. 400 if the runtime name or instance id is missing, 404 if
    /// the node is not registered or the pool has no such slot, 409 if the node is drained.
    pub async fn assign_instance(&self, request: &AssignInstanceRequest) -> Result<AssignInstanceResponse> {
        self.client.call("assign-instance", request).await
    }

    // -----------------------------------------------------------------------------------------
    // Load and egress (called by an application about itself)
    // -----------------------------------------------------------------------------------------

    /// Reports an instance's load for the autoscaler: `utilisation` (0..1), work waiting
    /// (`backlog`) and work in progress (`active`). `application_id` may be empty when the caller
    /// is the application's own principal.
    pub async fn report_load(
        &self,
        instance_id: &str,
        utilisation: f64,
        backlog: u64,
        active: u64,
        application_id: &str,
    ) -> Result<()> {
        let body = json!({
            "instanceId": instance_id,
            "utilisation": utilisation,
            "backlog": backlog,
            "active": active,
            "applicationId": application_id,
        });
        self.client.call_unit("report-load", &body).await
    }

    /// Asks for a permit to call `site`, held for at most `lease_seconds` if never released.
    /// Usually reached through [`EgressLimiter`], which waits and retries.
    pub async fn acquire_egress_permit(
        &self,
        application_id: &str,
        site: &str,
        lease_seconds: u64,
    ) -> Result<EgressPermitResponse> {
        let body = json!({ "applicationId": application_id, "site": site, "leaseSeconds": lease_seconds });
        self.client.call("acquire-egress-permit", &body).await
    }

    /// Gives a permit's slot back. `true` if it was still held.
    pub async fn release_egress_permit(&self, application_id: &str, site: &str, permit_id: &str) -> Result<bool> {
        let body = json!({ "applicationId": application_id, "site": site, "permitId": permit_id });
        let answer = self.client.call_value("release-egress-permit", &body).await?;
        Ok(answer.get("released").and_then(Value::as_bool).unwrap_or(false))
    }

    /// Reports that `site` refused a request (429/503), so no instance calls it for
    /// `retry_after_seconds` (euclid caps one report at an hour and floors it at a second).
    /// Answers until when the site is now left alone - never earlier than a block already in force.
    pub async fn report_egress_throttled(
        &self,
        application_id: &str,
        site: &str,
        retry_after_seconds: u64,
    ) -> Result<EgressThrottledResponse> {
        let body = json!({ "applicationId": application_id, "site": site, "retryAfterSeconds": retry_after_seconds });
        self.client.call("report-egress-throttled", &body).await
    }

    /// The sites applications call, with limits and current use; `application_id` narrows it to
    /// one application.
    pub async fn list_egress_sites(&self, application_id: Option<&str>) -> Result<ListEgressSitesResponse> {
        let body = match application_id.filter(|id| !id.is_empty()) {
            Some(id) => application_body(id),
            None => json!({}),
        };
        self.client.call("list-egress-sites", &body).await
    }

    /// Sets an application's limits for one site; a `None` limit is left out (the server keeps
    /// its default for it).
    pub async fn set_egress_limit(
        &self,
        application_id: &str,
        site: &str,
        requests_per_second: Option<f64>,
        burst: Option<f64>,
        concurrent: Option<u64>,
    ) -> Result<EgressLimitResponse> {
        let mut body = Map::new();
        body.insert("applicationId".into(), application_id.into());
        body.insert("site".into(), site.into());
        if let Some(v) = requests_per_second {
            body.insert("requestsPerSecond".into(), v.into());
        }
        if let Some(v) = burst {
            body.insert("burst".into(), v.into());
        }
        if let Some(v) = concurrent {
            body.insert("concurrent".into(), v.into());
        }
        self.client.call("set-egress-limit", &Value::Object(body)).await
    }

    /// Removes an application's own limits for a site, so the defaults apply again.
    pub async fn delete_egress_limit(&self, application_id: &str, site: &str) -> Result<EgressLimitResponse> {
        let body = json!({ "applicationId": application_id, "site": site });
        self.client.call("delete-egress-limit", &body).await
    }

    /// Forgets a site an application called, with its limits and state.
    pub async fn delete_egress_site(&self, application_id: &str, site: &str) -> Result<()> {
        let body = json!({ "applicationId": application_id, "site": site });
        self.client.call_unit("delete-egress-site", &body).await
    }
}

fn infrastructure_body(application_id: &str, declaration: Option<&Value>, prune: bool) -> Value {
    let mut body = Map::new();
    body.insert("applicationId".into(), application_id.into());
    body.insert("prune".into(), prune.into());
    if let Some(declaration) = declaration {
        // Embedded as an object, not a string: EAP reads the field as the declaration itself.
        body.insert("declaration".into(), declaration.clone());
    }
    Value::Object(body)
}
