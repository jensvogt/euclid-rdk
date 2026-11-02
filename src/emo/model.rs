//! Request types of the EMO (Euclid Monitoring) module.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

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
