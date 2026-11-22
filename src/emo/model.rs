//! Request and response types of the EMO (Euclid Monitoring) module.
//!
//! Field names are the wire names in camelCase. Response types default every field, so a field
//! the server leaves out reads as empty/zero instead of failing the whole response, and an enum
//! value this client does not know reads as `Unknown`.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};

use crate::serde_util::{lenient_string, lenient_u64};

/// How a metric's value is to be read across the samples EMO accumulates into one bucket.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MetricType {
    /// A level measured at a moment - a percentage, a queue depth, a byte count. Averaged across
    /// the samples in a bucket. Sent as `"gauge"`.
    #[default]
    Gauge,
    /// A quantity accumulating over time, to be read as a per-second rate. Sent as `"rate"`.
    Rate,
}

/// One measurement pushed to EMO: a name, its dimensions, a value and a type.
///
/// The dimensions are a map because a meter carries however many the application gave it -
/// `{"area": "heap", "id": "G1 Eden Space"}`, `{"method": "GET", "status": "200"}` - and EMO
/// stores them as a map for the same reason. Empty for a metric with a single series.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Metric {
    /// Metric name, e.g. `application-utilisation`.
    pub name: String,
    /// The dimensions the value is broken down by.
    pub labels: BTreeMap<String, String>,
    /// The measurement itself.
    pub value: f64,
    /// How the value should be read over time.
    #[serde(rename = "type")]
    pub kind: MetricType,
}

impl Metric {
    pub fn new(name: impl Into<String>, labels: BTreeMap<String, String>, value: f64, kind: MetricType) -> Self {
        Self {
            name: name.into(),
            labels,
            value,
            kind,
        }
    }

    /// A metric with a single dimension, which is every metric euclid records about itself. A
    /// blank `label_name` gives a metric with a single series.
    pub fn labelled(
        name: impl Into<String>,
        label_name: &str,
        label_value: &str,
        value: f64,
        kind: MetricType,
    ) -> Self {
        let mut labels = BTreeMap::new();
        if !label_name.trim().is_empty() {
            labels.insert(label_name.to_owned(), label_value.to_owned());
        }
        Self::new(name, labels, value, kind)
    }

    /// A gauge with however many dimensions it was measured by.
    pub fn gauge(name: impl Into<String>, labels: BTreeMap<String, String>, value: f64) -> Self {
        Self::new(name, labels, value, MetricType::Gauge)
    }

    /// A rate with however many dimensions it was measured by.
    pub fn rate(name: impl Into<String>, labels: BTreeMap<String, String>, value: f64) -> Self {
        Self::new(name, labels, value, MetricType::Rate)
    }

    /// The first dimension's name in key order, or `""` when there are none. For one-dimensional
    /// metrics; anything that cares about a particular dimension should read `labels` by name.
    pub fn label_name(&self) -> &str {
        self.labels.keys().next().map(String::as_str).unwrap_or_default()
    }

    /// The first dimension's value, or `""` when there are none. See [`label_name`](Self::label_name).
    pub fn label_value(&self) -> &str {
        self.labels.values().next().map(String::as_str).unwrap_or_default()
    }
}

/// Body of `push-metrics`: one tick's worth of measurements from one reporting process.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct PushMetricsRequest<'a> {
    pub module: &'a str,
    pub items: &'a [Metric],
}

// ---------------------------------------------------------------------------------------------
// Shared enums
// ---------------------------------------------------------------------------------------------

/// Reads an optional string, taking an empty one - how EMO writes a time or a reason it does not
/// have - as absent.
fn non_empty_string<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Ok(lenient_string(d)?.filter(|s| !s.is_empty()))
}

/// Reads a floating-point figure that may arrive as a number, a numeric string or `null` (how a
/// JSON writer spells a NaN); anything unreadable is 0, as Jackson's `asDouble(0)` reads it.
fn lenient_f64<'de, D: Deserializer<'de>>(d: D) -> Result<f64, D::Error> {
    Ok(match Option::<serde_json::Value>::deserialize(d)? {
        Some(serde_json::Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(serde_json::Value::String(s)) => s.trim().parse().unwrap_or(0.0),
        _ => 0.0,
    })
}

/// Reads a dashboard layout, taking anything but a JSON object - which EMO never stores - as an
/// empty one, so [`Dashboard::dashboard`] is always an object however the answer was written.
fn layout_object<'de, D: Deserializer<'de>>(d: D) -> Result<serde_json::Value, D::Error> {
    Ok(match Option::<serde_json::Value>::deserialize(d)? {
        Some(value @ serde_json::Value::Object(_)) => value,
        _ => empty_layout(),
    })
}

fn empty_layout() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

/// Reads a metric type the way a listing spells it (`"GAUGE"`, `"RATE"`), or the way it is pushed
/// (`"gauge"`, `"rate"`). Anything else - `"UNKNOWN"` included - reads as `None`.
fn lenient_metric_type<'de, D: Deserializer<'de>>(d: D) -> Result<Option<MetricType>, D::Error> {
    Ok(match lenient_string(d)?.map(|s| s.to_ascii_lowercase()).as_deref() {
        Some("gauge") => Some(MetricType::Gauge),
        Some("rate") => Some(MetricType::Rate),
        _ => None,
    })
}

/// One of EMO's three resolution tiers: what a series was recorded or rolled up at.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Resolution {
    /// Buckets of the configured averaging period (five minutes as shipped), kept for 7 days.
    /// Sent as `"RAW"`.
    Raw,
    /// Hourly roll-ups, kept for 90 days. Sent as `"HOUR"`.
    Hour,
    /// Daily roll-ups, kept for 5 years. Sent as `"DAY"`.
    Day,
    /// A tier this client does not know, or none given.
    #[default]
    #[serde(other)]
    Unknown,
}

/// Which figure of a row an alert rule judges.
///
/// A row's `value` is a period's mean for a gauge and its sum for a rate, so a rule on the mean of
/// a service time never sees a stall inside a bucket; a rule on `max` does.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertStatistic {
    /// The row's value (mean or sum). Sent as `"value"`; the server's default.
    Value,
    /// The largest sample in the bucket. Sent as `"max"`.
    Max,
    /// The smallest sample in the bucket. Sent as `"min"`.
    Min,
    /// A statistic this client does not know, or none given.
    #[default]
    #[serde(other)]
    Unknown,
}

/// Which side of a threshold is the wrong one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertComparison {
    /// Bad above the lines - queue depth, latency, disk used. Sent as `"above"`; the server's
    /// default.
    Above,
    /// Bad below the lines - free disk, a heartbeat rate. Sent as `"below"`.
    Below,
    /// A comparison this client does not know, or none given.
    #[default]
    #[serde(other)]
    Unknown,
}

/// Where one series stands against its rule.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AlertState {
    /// Within its lines. Sent as `"OK"`.
    Ok,
    /// Past the warning line. Sent as `"WARNING"`.
    Warning,
    /// Past the critical line. Sent as `"CRITICAL"`.
    Critical,
    /// Stopped reporting, for a rule with `noDataAfterPeriods`. Sent as `"NO_DATA"`.
    NoData,
    /// A state this client does not know, or none given.
    #[default]
    #[serde(other)]
    Unknown,
}

/// The lower-case word events and clients use for an [`AlertState`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    /// `"ok"`.
    Ok,
    /// `"warning"`.
    Warning,
    /// `"critical"`.
    Critical,
    /// `"nodata"`.
    Nodata,
    /// A severity this client does not know, or none given.
    #[default]
    #[serde(other)]
    Unknown,
}

// ---------------------------------------------------------------------------------------------
// Reading metrics
// ---------------------------------------------------------------------------------------------

/// Filters of [`Emo::list`](crate::Emo::list) and [`Emo::average`](crate::Emo::average), which
/// the server parses alike.
///
/// Every field is optional and left out of the request when unset, so the server applies its own
/// defaults: every metric, the `RAW` tier, no time bounds, and for `list` the 100 newest rows. An
/// empty query is therefore valid, but on a busy installation it mostly shows the last few seconds
/// of everything; name a metric.
///
/// The dimensions can be narrowed two ways. [`labels`](Self::labels) is the map form: every entry
/// must match, and a row may carry more dimensions than were asked for, so `{"area": "heap"}`
/// finds the heap series whatever else labels them. [`label_name`](Self::label_name) and
/// [`label_value`](Self::label_value) are the older one-pair form: given together they are one
/// more entry of the map, `label_name` alone finds the rows carrying that dimension at all, and
/// `label_value` alone the rows where any dimension has that value.
///
/// ```
/// use euclid_rdk::emo::{MetricQuery, Resolution};
///
/// // A day of hourly load figures.
/// let query = MetricQuery {
///     resolution: Some(Resolution::Hour),
///     from: Some("2026-11-06T00:00:00Z".into()),
///     to: Some("2026-11-07T00:00:00Z".into()),
///     ..MetricQuery::named("system-load-per-core")
/// };
/// # let _ = query;
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricQuery {
    /// Only this metric, e.g. `disk-used-percent`; unset reads every metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Only rows carrying every one of these dimensions with these values; left out when empty.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// Only rows carrying this dimension - with `label_value`, carrying it with that value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label_name: Option<String>,
    /// Only rows where some dimension - `label_name`, if given - has this value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label_value: Option<String>,
    /// The tier to read; `RAW` when unset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution: Option<Resolution>,
    /// Only rows at or after this time, ISO 8601, e.g. `2026-11-06T08:00:00Z`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// Only rows before this time (exclusive), ISO 8601.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// How many rows `list` returns at most, newest first: 100 when unset, and `0` means no limit.
    /// `average` ignores it and always reads every matching row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
}

impl MetricQuery {
    /// A query for one metric by name, every other filter unset.
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            ..Self::default()
        }
    }
}

/// One stored row of one series, as `list` returns it - what a graph draws a point from.
///
/// A row is not a sample but a bucket: every sample of the series that arrived during one period
/// of the row's [`resolution`](Self::resolution) folded into a mean, a minimum, a maximum and a
/// count. That is why a short spike is visible only in [`max_value`](Self::max_value), and why
/// the count is there at all - an average across rows has to weight each by its samples.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct MetricRow {
    /// Metric name.
    pub name: String,
    /// The series' dimensions.
    pub labels: BTreeMap<String, String>,
    /// The first dimension's name, flattened out for single-dimension readers.
    pub label_name: String,
    /// The first dimension's value.
    pub label_value: String,
    /// The bucket's mean for a gauge, its sum for a rate.
    #[serde(deserialize_with = "lenient_f64")]
    pub value: f64,
    /// The smallest sample in the bucket.
    #[serde(deserialize_with = "lenient_f64")]
    pub min_value: f64,
    /// The largest sample in the bucket.
    #[serde(deserialize_with = "lenient_f64")]
    pub max_value: f64,
    /// How many samples went into the bucket.
    #[serde(deserialize_with = "lenient_u64")]
    pub samples: u64,
    /// How the value reads over time; `None` for a type this client does not know.
    #[serde(rename = "type", deserialize_with = "lenient_metric_type")]
    pub kind: Option<MetricType>,
    /// The tier the row belongs to.
    pub resolution: Resolution,
    /// Start of the bucket, ISO 8601.
    #[serde(deserialize_with = "lenient_string")]
    pub timestamp: Option<String>,
}

/// Body of `list-metrics`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListMetricsRequest {
    /// Only metrics whose name starts with this, e.g. `system-`; `None` for every metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// Only metrics with data in this many hours; at least 1, 24 by default.
    pub hours: u64,
}

impl Default for ListMetricsRequest {
    fn default() -> Self {
        Self {
            prefix: None,
            hours: 24,
        }
    }
}

/// A metric EMO has recorded recently, as `list-metrics` describes it.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct MetricInfo {
    /// Metric name - what [`MetricQuery::name`] and [`CreateAlertRuleRequest::name`] take.
    pub name: String,
    /// How its values read over time; `None` for a type this client does not know.
    #[serde(rename = "type", deserialize_with = "lenient_metric_type")]
    pub kind: Option<MetricType>,
    /// How many distinct series (label combinations) it has.
    #[serde(deserialize_with = "lenient_u64")]
    pub series: u64,
    /// The dimension names its series carry - what an alert rule's labels can select on.
    pub label_names: Vec<String>,
    /// When it last reported, ISO 8601.
    #[serde(deserialize_with = "lenient_string")]
    pub last_seen: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// Alert rules
// ---------------------------------------------------------------------------------------------

/// Body of `create-alert-rule`. Unset fields are left out and take the server's defaults:
/// resolution `RAW`, statistic `value`, comparison `above`, one period to raise and to clear, no
/// no-data detection, enabled.
///
/// ```
/// use euclid_rdk::emo::{AlertStatistic, CreateAlertRuleRequest};
///
/// // Any watched volume over 85% full, whatever its size.
/// let rule = CreateAlertRuleRequest {
///     statistic: Some(AlertStatistic::Max),
///     warning: Some(85.0),
///     critical: Some(95.0),
///     ..CreateAlertRuleRequest::new("disk-full", "disk-used-percent")
/// };
/// # let _ = rule;
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAlertRuleRequest {
    /// The rule's own id, unique in the account: letters, digits, `-`, `_` and `.`, at most 128.
    pub rule_id: String,
    /// The metric it judges, e.g. `system-load-per-core`.
    pub name: String,
    /// Equality on a subset of a series' labels; empty judges every series of the metric.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// The tier it reads; only `RAW` is accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution: Option<Resolution>,
    /// Which figure of a row it judges.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statistic: Option<AlertStatistic>,
    /// Which side of the lines is the wrong one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comparison: Option<AlertComparison>,
    /// The warning line. At least one of `warning` and `critical` is required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<f64>,
    /// The critical line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub critical: Option<f64>,
    /// Consecutive periods past a line before the state changes (1..=1000).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub for_periods: Option<u32>,
    /// Consecutive periods back within the lines before it clears (1..=1000).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clear_periods: Option<u32>,
    /// Periods without a row before a series goes `NO_DATA` (0..=1000; 0 never).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_data_after_periods: Option<u32>,
    /// Whether the rule is judged at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Free text shown beside its alerts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl CreateAlertRuleRequest {
    /// A rule `rule_id` on metric `name`, everything else unset. Needs a threshold before the
    /// server accepts it.
    pub fn new(rule_id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            rule_id: rule_id.into(),
            name: name.into(),
            ..Self::default()
        }
    }
}

/// Body of `update-alert-rule`: only `rule_id` is required, and only the fields set are sent and
/// changed.
///
/// A threshold is removed with `Some(None)`, which is sent as an explicit `null`; `None` leaves it
/// alone. A changed metric or label selector, or disabling the rule, clears every series it was
/// judging.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateAlertRuleRequest {
    /// The rule to change.
    pub rule_id: String,
    /// A new metric to judge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// A new label selector; `Some` of an empty map judges every series of the metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
    /// A new tier; only `RAW` is accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution: Option<Resolution>,
    /// A new statistic.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statistic: Option<AlertStatistic>,
    /// A new comparison.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comparison: Option<AlertComparison>,
    /// `Some(Some(x))` moves the warning line, `Some(None)` removes it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<Option<f64>>,
    /// `Some(Some(x))` moves the critical line, `Some(None)` removes it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub critical: Option<Option<f64>>,
    /// New periods to raise (1..=1000).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub for_periods: Option<u32>,
    /// New periods to clear (1..=1000).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clear_periods: Option<u32>,
    /// New no-data periods (0..=1000).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_data_after_periods: Option<u32>,
    /// Enables or disables the rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// A new description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl UpdateAlertRuleRequest {
    /// A change to `rule_id` that changes nothing yet.
    pub fn new(rule_id: impl Into<String>) -> Self {
        Self {
            rule_id: rule_id.into(),
            ..Self::default()
        }
    }
}

/// A stored threshold rule, as `create-alert-rule`, `update-alert-rule` and `list-alert-rules`
/// answer with it.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AlertRule {
    /// The rule's id.
    pub rule_id: String,
    /// The metric it judges.
    pub name: String,
    /// Its label selector.
    pub labels: BTreeMap<String, String>,
    /// The tier it reads.
    pub resolution: Resolution,
    /// Which figure of a row it judges.
    pub statistic: AlertStatistic,
    /// Which side of the lines is the wrong one.
    pub comparison: AlertComparison,
    /// The warning line, if it has one.
    pub warning: Option<f64>,
    /// The critical line, if it has one.
    pub critical: Option<f64>,
    /// Consecutive periods past a line before the state changes.
    #[serde(deserialize_with = "lenient_u64")]
    pub for_periods: u64,
    /// Consecutive periods back within the lines before it clears.
    #[serde(deserialize_with = "lenient_u64")]
    pub clear_periods: u64,
    /// Periods without a row before a series goes `NO_DATA`; 0 never.
    #[serde(deserialize_with = "lenient_u64")]
    pub no_data_after_periods: u64,
    /// Whether it is judged.
    pub enabled: bool,
    /// Its description.
    pub description: String,
    /// The account it belongs to.
    pub account_id: String,
    /// The namespace it was written in.
    pub namespace: String,
    /// When it was created, ISO 8601.
    #[serde(deserialize_with = "non_empty_string")]
    pub created: Option<String>,
    /// When it was last changed, ISO 8601.
    #[serde(deserialize_with = "non_empty_string")]
    pub modified: Option<String>,
}

/// Filters of `list-alerts`; unset ones list every series of every rule.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListAlertsRequest {
    /// Only this rule's series.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Only series in this state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<AlertState>,
    /// Only series not `OK`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
}

/// Where one series a rule judges stands now, with the rule's lines beside it.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Alert {
    /// The rule judging it.
    pub rule_id: String,
    /// The rule's metric.
    pub name: String,
    /// The series' labels.
    pub labels: BTreeMap<String, String>,
    /// Its state.
    pub state: AlertState,
    /// Its state as a severity word.
    pub severity: AlertSeverity,
    /// Since when it has been in that state, ISO 8601.
    #[serde(deserialize_with = "non_empty_string")]
    pub since: Option<String>,
    /// The last figure judged.
    pub value: f64,
    /// When a row of it was last judged, ISO 8601.
    #[serde(deserialize_with = "non_empty_string")]
    pub last_seen: Option<String>,
    /// The rule's statistic.
    pub statistic: AlertStatistic,
    /// The rule's comparison.
    pub comparison: AlertComparison,
    /// The rule's warning line.
    pub warning: Option<f64>,
    /// The rule's critical line.
    pub critical: Option<f64>,
    /// The rule's description.
    pub description: String,
    /// The rule's namespace.
    pub namespace: String,
}

/// Filters of `list-alert-history`; unset ones return the 100 most recent changes of every rule.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListAlertHistoryRequest {
    /// Only this rule's changes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// At most this many; 100 by default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    /// Only changes from this time on, ISO 8601.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// Only changes up to this time, ISO 8601.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
}

/// One recorded change of a series' alert state.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AlertTransition {
    /// The rule that made it.
    pub rule_id: String,
    /// The rule's metric.
    pub name: String,
    /// The series' labels.
    pub labels: BTreeMap<String, String>,
    /// The state it left.
    pub previous: AlertState,
    /// The state it entered.
    pub state: AlertState,
    /// The state it entered, as a severity word.
    pub severity: AlertSeverity,
    /// The figure that decided it.
    pub value: f64,
    /// The line that decided it, if any.
    pub threshold: Option<f64>,
    /// The rule's statistic.
    pub statistic: AlertStatistic,
    /// Why, for a change the rule itself made: `rule-changed`, `rule-disabled`, `rule-deleted`.
    #[serde(deserialize_with = "non_empty_string")]
    pub reason: Option<String>,
    /// When, ISO 8601.
    #[serde(deserialize_with = "lenient_string")]
    pub timestamp: Option<String>,
    /// The rule's account.
    pub account_id: String,
    /// The rule's namespace.
    pub namespace: String,
}

// ---------------------------------------------------------------------------------------------
// Dashboards
// ---------------------------------------------------------------------------------------------

/// What `save-dashboard` answers: which dashboard was stored, for whom, and when.
///
/// The owner is never part of the request - EMO files a dashboard under the user it
/// authenticated - so [`user_id`](Self::user_id) is where a caller signing with an access key
/// sees whose dashboard it just wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SavedDashboard {
    /// The dashboard's name.
    pub name: String,
    /// The user it belongs to - always the caller.
    pub user_id: String,
    /// When it was saved, ISO 8601.
    #[serde(deserialize_with = "lenient_string")]
    pub modified: Option<String>,
}

/// One of the caller's saved dashboards, layout included, as `get-dashboard` returns it.
///
/// EMO does not interpret the layout: it stores whatever JSON object it was given and hands it
/// back as JSON, so the layout's shape belongs to whoever drew it - the RUI, or an application
/// keeping its own views. Read it as a [`serde_json::Value`], or into a type of your own with
/// `serde_json::from_value`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Dashboard {
    /// The dashboard's name, unique among the caller's own dashboards.
    pub name: String,
    /// The layout exactly as it was saved, nulls included. Always a JSON object: anything else in
    /// the answer reads as an empty one.
    #[serde(deserialize_with = "layout_object")]
    pub dashboard: serde_json::Value,
    /// When it was first saved, ISO 8601 - kept across re-saves, so a layout edited every day
    /// still says how old it is.
    #[serde(deserialize_with = "lenient_string")]
    pub created: Option<String>,
    /// When it was last saved, ISO 8601.
    #[serde(deserialize_with = "lenient_string")]
    pub modified: Option<String>,
}

impl Default for Dashboard {
    fn default() -> Self {
        Self {
            name: String::new(),
            dashboard: empty_layout(),
            created: None,
            modified: None,
        }
    }
}

/// A saved dashboard in a listing: its name and times, without the layout - a chooser needs the
/// names, not every panel of every dashboard. Fetch the one chosen with
/// [`Emo::get_dashboard`](crate::Emo::get_dashboard).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DashboardSummary {
    /// The dashboard's name.
    pub name: String,
    /// When it was first saved, ISO 8601.
    #[serde(deserialize_with = "lenient_string")]
    pub created: Option<String>,
    /// When it was last saved, ISO 8601.
    #[serde(deserialize_with = "lenient_string")]
    pub modified: Option<String>,
}

/// What `list-dashboards` answers: the caller's own dashboards. There is no way to list another
/// user's - EMO takes the owner from the authenticated identity.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListDashboardsResponse {
    /// The user they belong to - always the caller.
    pub user_id: String,
    /// The caller's dashboards.
    pub items: Vec<DashboardSummary>,
}

/// A response carrying a list under `items`.
#[derive(Debug, Deserialize)]
#[serde(bound = "T: Deserialize<'de>")]
pub(crate) struct Items<T> {
    #[serde(default = "Vec::new")]
    pub items: Vec<T>,
}

/// The answer of `average`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub(crate) struct AverageResponse {
    #[serde(deserialize_with = "lenient_f64")]
    pub average: f64,
}
