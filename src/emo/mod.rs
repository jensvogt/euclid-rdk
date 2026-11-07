//! EMO - Euclid Monitoring: pushing metrics, reading them back, alerting on them, and the
//! caller's saved dashboards.
//!
//! Pushing is for metrics an application has measured about itself. Everything euclid knows
//! about a process from the outside - is it running, is it answering - the manager already sees;
//! what it cannot see is how hard the process is working, and for an application that consumes
//! messages rather than serving requests that is the only signal there is.
//!
//! Samples are accumulated by EMO into the same bucket-aligned rows its own collectors write, so
//! they roll up and graph alongside CPU, memory and the module gauges. Pushing is cheap and meant
//! to be periodic: one call carrying every metric of one tick, not a call per measurement. With
//! the `metrics` cargo feature, `EmoRecorder` does exactly that for anything recorded through
//! the [`metrics`](https://docs.rs/metrics) crate.
//!
//! Reading the rows back ([`Emo::list`], [`Emo::average`], [`Emo::list_metrics`]) and the alerting
//! actions - threshold rules on a metric, where every judged series stands, and how it got there -
//! read the whole installation's metrics and so are an administrator's: anyone else gets HTTP 403.
//! Among the metrics EMO records itself are `disk-capacity`, `disk-free`, `disk-available` and
//! `disk-used-percent` per watched volume (labelled `path`); the last, 0 to 100 with the root
//! reserve counted as used, is the one an alert rule fits volumes of any size with.
//!
//! Dashboards are the authenticated user's own saved layouts and need no special privilege.

pub mod model;
#[cfg(feature = "metrics")]
mod recorder;

pub use model::*;
#[cfg(feature = "metrics")]
pub use recorder::{EmoRecorder, EmoRecorderBuilder, EmoRecorderHandle, DEFAULT_STEP};

use serde::Serialize;
use serde_json::json;

use crate::service::ServiceClient;
use crate::Result;

/// EMO operations, obtained from [`Session::emo`](crate::Session::emo).
///
/// Pushing is meant for ordinary principals: an application reporting its own load holds no more
/// privilege than any other application. Reading and alerting need an administrator. Requests are SigV4-signed with the session's access key when it has
/// one, otherwise authenticated with the bearer token. Cloning is cheap.
#[derive(Debug, Clone)]
pub struct Emo {
    client: ServiceClient,
}

impl Emo {
    pub(crate) fn new(client: ServiceClient) -> Self {
        Self { client }
    }

    /// Pushes one tick's worth of measurements.
    ///
    /// `module` names the reporting process and is recorded with the samples so EMO can tell
    /// which pusher a batch came from - an application's own id is the useful value. An empty
    /// `metrics` slice sends nothing.
    pub async fn push_metrics(&self, module: &str, metrics: &[Metric]) -> Result<()> {
        if metrics.is_empty() {
            return Ok(());
        }
        let request = PushMetricsRequest { module, items: metrics };
        self.client.call_unit("push-metrics", &request).await
    }

    // -----------------------------------------------------------------------------------------
    // Reading metrics (administrator only)
    // -----------------------------------------------------------------------------------------

    /// Lists stored rows - one bucket of one series each - matching `query`, at most 100 unless
    /// [`MetricQuery::limit`] says otherwise.
    ///
    /// Administrator only: anyone else gets HTTP 403.
    pub async fn list(&self, query: &MetricQuery) -> Result<Vec<MetricRow>> {
        let answer: Items<MetricRow> = self.client.call("list", query).await?;
        Ok(answer.items)
    }

    /// The sample-weighted average of the rows matching `query`, across every series regardless
    /// of labels. 0 when nothing matches.
    ///
    /// Administrator only: anyone else gets HTTP 403.
    pub async fn average(&self, query: &MetricQuery) -> Result<f64> {
        let answer: AverageResponse = self.client.call("average", query).await?;
        Ok(answer.average)
    }

    /// Every metric EMO has recorded in the last 24 hours, sorted by name - the names to query,
    /// graph or write an alert rule on.
    ///
    /// Administrator only: anyone else gets HTTP 403.
    pub async fn list_metrics(&self) -> Result<Vec<MetricInfo>> {
        self.list_metrics_with(&ListMetricsRequest::default()).await
    }

    /// The metrics EMO has recorded in the last [`hours`](ListMetricsRequest::hours), optionally
    /// only those starting with a prefix. `hours` below 1 is HTTP 400.
    pub async fn list_metrics_with(&self, request: &ListMetricsRequest) -> Result<Vec<MetricInfo>> {
        let answer: Items<MetricInfo> = self.client.call("list-metrics", request).await?;
        Ok(answer.items)
    }

    // -----------------------------------------------------------------------------------------
    // Alerting (administrator only)
    // -----------------------------------------------------------------------------------------

    /// Creates a threshold rule on one metric and returns it with every default filled in.
    ///
    /// From the next period on, EMO judges every series the rule's labels match and publishes each
    /// change of state as `emo.alert.raised` or `emo.alert.cleared` on the event bus. An invalid
    /// rule, or one matching more series than `euclid.modules.emo.alert.max-series-per-rule`, is
    /// HTTP 400; an existing `rule_id` is HTTP 409.
    pub async fn create_alert_rule(&self, request: &CreateAlertRuleRequest) -> Result<AlertRule> {
        self.client.call("create-alert-rule", request).await
    }

    /// Changes the fields set on `request` and returns the rule as stored afterwards. An unknown
    /// rule is HTTP 404.
    pub async fn update_alert_rule(&self, request: &UpdateAlertRuleRequest) -> Result<AlertRule> {
        self.client.call("update-alert-rule", request).await
    }

    /// Deletes a rule, clearing (and announcing) every series of it that was not OK. Its history
    /// is kept until it expires. An unknown rule is HTTP 404.
    pub async fn delete_alert_rule(&self, rule_id: &str) -> Result<()> {
        self.client
            .call_unit("delete-alert-rule", &json!({ "ruleId": rule_id }))
            .await
    }

    /// Every threshold rule in the account.
    pub async fn list_alert_rules(&self) -> Result<Vec<AlertRule>> {
        let answer: Items<AlertRule> = self.client.call("list-alert-rules", &json!({})).await?;
        Ok(answer.items)
    }

    /// One rule by id, or `None` when the account has no such rule.
    pub async fn get_alert_rule(&self, rule_id: &str) -> Result<Option<AlertRule>> {
        let answer: Items<AlertRule> = self
            .client
            .call("list-alert-rules", &json!({ "ruleId": rule_id }))
            .await?;
        Ok(answer.items.into_iter().find(|rule| rule.rule_id == rule_id))
    }

    /// Where every series matching `request` stands now. A series a rule has not yet seen a row
    /// of is not listed.
    pub async fn list_alerts(&self, request: &ListAlertsRequest) -> Result<Vec<Alert>> {
        let answer: Items<Alert> = self.client.call("list-alerts", request).await?;
        Ok(answer.items)
    }

    /// The recorded alert state changes matching `request`, newest first. Kept for
    /// `euclid.modules.emo.alert.history-retention` days (90 as shipped), outliving their rule.
    pub async fn list_alert_history(&self, request: &ListAlertHistoryRequest) -> Result<Vec<AlertTransition>> {
        let answer: Items<AlertTransition> = self.client.call("list-alert-history", request).await?;
        Ok(answer.items)
    }

    // -----------------------------------------------------------------------------------------
    // Dashboards (the caller's own)
    // -----------------------------------------------------------------------------------------

    /// Saves `dashboard` - a layout that must serialize to a JSON object - as the caller's
    /// dashboard `name`, replacing one of that name but keeping its creation time.
    ///
    /// Dashboards belong to the authenticated user and need no administrator privileges; there is
    /// no way to name another user's.
    pub async fn save_dashboard(&self, name: &str, dashboard: &impl Serialize) -> Result<SavedDashboard> {
        let body = json!({ "name": name, "dashboard": serde_json::to_value(dashboard)? });
        self.client.call("save-dashboard", &body).await
    }

    /// The caller's dashboard `name`, layout included. An unknown name is HTTP 404.
    pub async fn get_dashboard(&self, name: &str) -> Result<Dashboard> {
        self.client.call("get-dashboard", &json!({ "name": name })).await
    }

    /// The caller's dashboards, names and times only.
    pub async fn list_dashboards(&self) -> Result<ListDashboardsResponse> {
        self.client.call("list-dashboards", &json!({})).await
    }

    /// Deletes the caller's dashboard `name`. An unknown name is HTTP 404.
    pub async fn delete_dashboard(&self, name: &str) -> Result<()> {
        self.client
            .call_unit("delete-dashboard", &json!({ "name": name }))
            .await
    }

    /// Starts building a [`metrics`](https://docs.rs/metrics) recorder that pushes everything
    /// recorded through it to EMO once per step, as `module`.
    #[cfg(feature = "metrics")]
    pub fn recorder(&self, module: impl Into<String>) -> EmoRecorderBuilder {
        EmoRecorderBuilder::new(self.clone(), module.into())
    }
}
