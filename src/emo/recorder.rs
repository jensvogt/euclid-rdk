//! A [`metrics`] recorder that publishes an application's meters to EMO - the Rust counterpart of
//! euclid-jdk's Micrometer `EuclidMeterRegistry`.
//!
//! Whatever is recorded through the `metrics` macros is accumulated over a step and pushed with
//! [`Emo::push_metrics`] at the end of it, landing in the same bucket-aligned rows EMO's own
//! collectors write. Push rather than scrape: an application euclid runs need not serve HTTP at
//! all, and only the application knows what is worth publishing.
//!
//! Cardinality is the caller's to control: every distinct name and label set becomes a stored row
//! per step.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::future::{select, Either};
use metrics::{
    Counter, CounterFn, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata, Recorder, SharedString, Unit,
};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use super::{Emo, Metric};
use crate::{Error, Result};

/// The default step: one minute. Short enough that a value is never much older than EMO's own
/// averaging period (five minutes by default), long enough that publishing is not a per-second
/// network call. A step longer than EMO's period leaves buckets without a sample, which reads as
/// a gap rather than a flat line.
pub const DEFAULT_STEP: Duration = Duration::from_secs(60);

/// Configures and starts an [`EmoRecorder`]; obtained from [`Emo::recorder`].
#[derive(Debug, Clone)]
pub struct EmoRecorderBuilder {
    emo: Emo,
    module: String,
    step: Duration,
}

impl EmoRecorderBuilder {
    pub(crate) fn new(emo: Emo, module: String) -> Self {
        Self {
            emo,
            module,
            step: DEFAULT_STEP,
        }
    }

    /// How long a step is - how often the accumulated values are pushed. Defaults to
    /// [`DEFAULT_STEP`].
    pub fn step(mut self, step: Duration) -> Self {
        self.step = step;
        self
    }

    /// Starts publishing and returns the recorder together with the handle that flushes and stops
    /// it. Install the recorder yourself (e.g. `metrics::set_global_recorder`) or use
    /// [`install`](Self::install).
    ///
    /// Must be called inside a Tokio runtime: publishing runs on a task of its own, so a slow
    /// gateway never becomes the latency of whatever records a metric.
    pub fn build(self) -> Result<(EmoRecorder, EmoRecorderHandle)> {
        if self.step.is_zero() {
            return Err(Error::invalid("step must be longer than zero"));
        }
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| Error::invalid("an EMO recorder must be built inside a Tokio runtime"))?;

        let registry = Arc::new(Registry::default());
        let stop = Arc::new(Notify::new());
        let publisher = Publisher {
            registry: registry.clone(),
            emo: self.emo,
            module: self.module,
        };
        let task = runtime.spawn(run(publisher.clone(), self.step, stop.clone()));
        Ok((
            EmoRecorder { registry },
            EmoRecorderHandle {
                publisher,
                stop,
                task: Some(task),
            },
        ))
    }

    /// [`build`](Self::build)s the recorder and installs it as the process-wide `metrics`
    /// recorder. Fails if another recorder is already installed.
    pub fn install(self) -> Result<EmoRecorderHandle> {
        let (recorder, handle) = self.build()?;
        metrics::set_global_recorder(recorder)
            .map_err(|_| Error::invalid("a global metrics recorder is already installed"))?;
        Ok(handle)
    }
}

/// A [`metrics::Recorder`] that accumulates per step and is published to EMO by the task its
/// [`EmoRecorderHandle`] controls.
///
/// How meters become EMO metrics, as in euclid-jdk's registry:
/// - a **counter** is a `rate` carrying what was counted during the step (zero included);
/// - a **gauge** is a `gauge` carrying its current level;
/// - a **histogram** is three metrics - `<name>.count` and `<name>.total` as `rate`s and
///   `<name>.max` as a `gauge` over the step - because those survive being rolled up and a
///   percentile does not.
///
/// Durations are published in milliseconds, like every other duration euclid records: a gauge or
/// histogram described with a time unit (`describe_histogram!(name, Unit::Seconds, ..)`) is
/// converted; one without a unit is published as recorded. Labels become EMO's dimensions.
/// Non-finite values (NaN, infinity) are never published, and negative histogram samples are
/// ignored.
#[derive(Clone)]
pub struct EmoRecorder {
    registry: Arc<Registry>,
}

impl fmt::Debug for EmoRecorder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmoRecorder")
            .field("counters", &lock(&self.registry.counters).len())
            .field("gauges", &lock(&self.registry.gauges).len())
            .field("histograms", &lock(&self.registry.histograms).len())
            .finish()
    }
}

impl Recorder for EmoRecorder {
    fn describe_counter(&self, key: KeyName, unit: Option<Unit>, _description: SharedString) {
        self.registry.describe(key, unit);
    }

    fn describe_gauge(&self, key: KeyName, unit: Option<Unit>, _description: SharedString) {
        self.registry.describe(key, unit);
    }

    fn describe_histogram(&self, key: KeyName, unit: Option<Unit>, _description: SharedString) {
        self.registry.describe(key, unit);
    }

    fn register_counter(&self, key: &Key, _metadata: &Metadata<'_>) -> Counter {
        Counter::from_arc(cell(&self.registry.counters, key))
    }

    fn register_gauge(&self, key: &Key, _metadata: &Metadata<'_>) -> Gauge {
        Gauge::from_arc(cell(&self.registry.gauges, key))
    }

    fn register_histogram(&self, key: &Key, _metadata: &Metadata<'_>) -> Histogram {
        Histogram::from_arc(cell(&self.registry.histograms, key))
    }
}

/// Controls the publishing task of an [`EmoRecorder`].
///
/// Dropping the handle stops publishing without a final push; call
/// [`shutdown`](Self::shutdown) to publish the partial step first.
#[derive(Debug)]
pub struct EmoRecorderHandle {
    publisher: Publisher,
    stop: Arc<Notify>,
    task: Option<JoinHandle<()>>,
}

impl EmoRecorderHandle {
    /// Publishes what has accumulated since the last push right now, and starts a new step.
    /// Unlike the scheduled push, a failure is returned rather than logged.
    pub async fn flush(&self) -> Result<()> {
        self.publisher.publish().await
    }

    /// Stops the schedule and publishes the partial step, so nothing measured since the last push
    /// is lost.
    pub async fn shutdown(mut self) -> Result<()> {
        self.stop.notify_one();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
        self.publisher.publish().await
    }
}

impl Drop for EmoRecorderHandle {
    fn drop(&mut self) {
        self.stop.notify_one();
    }
}

// ---------------------------------------------------------------------------------------------
// Publishing
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Publisher {
    registry: Arc<Registry>,
    emo: Emo,
    module: String,
}

impl Publisher {
    async fn publish(&self) -> Result<()> {
        let batch = self.registry.drain();
        self.emo.push_metrics(&self.module, &batch).await
    }

    /// The scheduled push: a failure is logged and the step dropped rather than retried - the next
    /// step is along shortly, and a queue of stale samples would land in the wrong buckets.
    async fn publish_logged(&self) {
        let batch = self.registry.drain();
        if let Err(e) = self.emo.push_metrics(&self.module, &batch).await {
            log::warn!(
                "Pushing metrics to EMO failed, module: {}, metrics: {}: {e}",
                self.module,
                batch.len()
            );
        }
    }
}

/// Publishes at every step boundary - aligned to multiples of the step since the epoch, as
/// Micrometer's step registries do - until told to stop.
async fn run(publisher: Publisher, step: Duration, stop: Arc<Notify>) {
    let mut next = tokio::time::Instant::now() + until_next_boundary(step);
    loop {
        let sleep = std::pin::pin!(tokio::time::sleep_until(next));
        let stopped = std::pin::pin!(stop.notified());
        match select(sleep, stopped).await {
            Either::Left(_) => {
                publisher.publish_logged().await;
                next += step;
                let now = tokio::time::Instant::now();
                if next <= now {
                    // A push that outlasted the step: skip the boundaries it missed.
                    next = now + until_next_boundary(step);
                }
            }
            Either::Right(_) => break,
        }
    }
}

fn until_next_boundary(step: Duration) -> Duration {
    let step_nanos = step.as_nanos().max(1);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let remaining = step_nanos - now % step_nanos;
    Duration::from_nanos(u64::try_from(remaining).unwrap_or(u64::MAX))
}

// ---------------------------------------------------------------------------------------------
// Accumulation
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Default)]
struct Registry {
    counters: Mutex<HashMap<Key, Arc<CounterCell>>>,
    gauges: Mutex<HashMap<Key, Arc<GaugeCell>>>,
    histograms: Mutex<HashMap<Key, Arc<HistogramCell>>>,
    units: Mutex<HashMap<String, Unit>>,
}

impl Registry {
    fn describe(&self, key: KeyName, unit: Option<Unit>) {
        if let Some(unit) = unit {
            lock(&self.units).insert(key.as_str().to_owned(), unit);
        }
    }

    /// Factor from the unit a metric was described with to milliseconds, for time units.
    fn time_factor(&self, name: &str) -> f64 {
        match lock(&self.units).get(name) {
            Some(Unit::Seconds) => 1_000.0,
            Some(Unit::Microseconds) => 0.001,
            Some(Unit::Nanoseconds) => 0.000_001,
            _ => 1.0,
        }
    }

    /// Everything accumulated in the step that just ended, in a stable order, and a fresh step.
    fn drain(&self) -> Vec<Metric> {
        let mut batch = Vec::new();

        for (key, cell) in lock(&self.counters).iter() {
            batch.push(Metric::rate(key.name(), labels(key), cell.take() as f64));
        }
        for (key, cell) in lock(&self.gauges).iter() {
            let value = cell.get() * self.time_factor(key.name());
            if value.is_finite() {
                batch.push(Metric::gauge(key.name(), labels(key), value));
            }
        }
        for (key, cell) in lock(&self.histograms).iter() {
            let factor = self.time_factor(key.name());
            let (count, total, max) = cell.take();
            let (name, labels) = (key.name(), labels(key));
            batch.push(Metric::rate(format!("{name}.count"), labels.clone(), count as f64));
            if (total * factor).is_finite() {
                batch.push(Metric::rate(format!("{name}.total"), labels.clone(), total * factor));
            }
            if (max * factor).is_finite() {
                batch.push(Metric::gauge(format!("{name}.max"), labels, max * factor));
            }
        }

        batch.sort_by(|a, b| (&a.name, &a.labels).cmp(&(&b.name, &b.labels)));
        batch
    }
}

/// A meter's labels as EMO's dimensions; sorted, so the same label set is always the same series.
fn labels(key: &Key) -> BTreeMap<String, String> {
    key.labels()
        .map(|l| (l.key().to_owned(), l.value().to_owned()))
        .collect()
}

fn cell<T: Default>(map: &Mutex<HashMap<Key, Arc<T>>>, key: &Key) -> Arc<T> {
    lock(map).entry(key.clone()).or_default().clone()
}

/// A poisoned lock only means another thread panicked while holding it; the counts inside are
/// still the best there is.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

#[derive(Debug, Default)]
struct CounterCell {
    /// Counted in the current step.
    pending: AtomicU64,
    /// The last value passed to `absolute`, to turn absolute readings into per-step counts.
    last_absolute: AtomicU64,
}

impl CounterCell {
    fn take(&self) -> u64 {
        self.pending.swap(0, Ordering::Relaxed)
    }
}

impl CounterFn for CounterCell {
    fn increment(&self, value: u64) {
        self.pending.fetch_add(value, Ordering::Relaxed);
    }

    fn absolute(&self, value: u64) {
        let previous = self.last_absolute.swap(value, Ordering::Relaxed);
        // A reading below the previous one means the source restarted counting from zero.
        let delta = if value >= previous { value - previous } else { value };
        self.pending.fetch_add(delta, Ordering::Relaxed);
    }
}

#[derive(Debug, Default)]
struct GaugeCell {
    bits: AtomicU64,
}

impl GaugeCell {
    fn get(&self) -> f64 {
        f64::from_bits(self.bits.load(Ordering::Relaxed))
    }

    fn update(&self, f: impl Fn(f64) -> f64) {
        // A compare-exchange loop rather than `fetch_update`, which newer toolchains deprecate in
        // favour of a method the MSRV does not have yet.
        let mut current = self.bits.load(Ordering::Relaxed);
        loop {
            let next = f(f64::from_bits(current)).to_bits();
            match self
                .bits
                .compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }
}

impl GaugeFn for GaugeCell {
    fn increment(&self, value: f64) {
        self.update(|v| v + value);
    }

    fn decrement(&self, value: f64) {
        self.update(|v| v - value);
    }

    fn set(&self, value: f64) {
        self.bits.store(value.to_bits(), Ordering::Relaxed);
    }
}

#[derive(Debug, Default)]
struct HistogramCell {
    /// Count, total and max of the current step.
    step: Mutex<(u64, f64, f64)>,
}

impl HistogramCell {
    fn take(&self) -> (u64, f64, f64) {
        std::mem::take(&mut *lock(&self.step))
    }
}

impl HistogramFn for HistogramCell {
    fn record(&self, value: f64) {
        // As Micrometer's summaries: a negative amount is not a measurement of anything.
        if !value.is_finite() || value < 0.0 {
            return;
        }
        let mut step = lock(&self.step);
        step.0 += 1;
        step.1 += value;
        step.2 = step.2.max(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use metrics::Label;

    fn key(name: &'static str, labels: &[(&'static str, &'static str)]) -> Key {
        Key::from_parts(name, labels.iter().map(|(k, v)| Label::new(*k, *v)).collect::<Vec<_>>())
    }

    #[test]
    fn drain_maps_meters_and_resets_the_step() {
        let registry = Registry::default();
        cell(&registry.counters, &key("jobs", &[("queue", "a")])).increment(3);
        cell(&registry.counters, &key("jobs", &[("queue", "a")])).increment(2);
        cell(&registry.gauges, &key("depth", &[])).set(7.5);
        let latency = cell(&registry.histograms, &key("latency", &[]));
        registry.describe(KeyName::from("latency"), Some(Unit::Seconds));
        latency.record(0.25);
        latency.record(0.5);
        latency.record(-1.0);
        latency.record(f64::NAN);

        let batch = registry.drain();
        let find = |n: &str| batch.iter().find(|m| m.name == n).unwrap().clone();
        assert_eq!(find("jobs").value, 5.0);
        assert_eq!(find("jobs").label_value(), "a");
        assert_eq!(find("depth").value, 7.5);
        assert_eq!(find("latency.count").value, 2.0);
        assert_eq!(find("latency.total").value, 750.0);
        assert_eq!(find("latency.max").value, 500.0);
        let names: Vec<_> = batch.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(
            names,
            ["depth", "jobs", "latency.count", "latency.max", "latency.total"]
        );

        // A new step: counters and histograms start over, gauges keep their level.
        let batch = registry.drain();
        let find = |n: &str| batch.iter().find(|m| m.name == n).unwrap().clone();
        assert_eq!(find("jobs").value, 0.0);
        assert_eq!(find("depth").value, 7.5);
        assert_eq!(find("latency.count").value, 0.0);
        assert_eq!(find("latency.max").value, 0.0);
    }

    #[test]
    fn absolute_counters_publish_per_step_deltas() {
        let counter = CounterCell::default();
        counter.absolute(10);
        assert_eq!(counter.take(), 10);
        counter.absolute(15);
        assert_eq!(counter.take(), 5);
        counter.absolute(3); // restarted
        assert_eq!(counter.take(), 3);
    }

    #[test]
    fn non_finite_gauges_are_not_published() {
        let registry = Registry::default();
        cell(&registry.gauges, &key("broken", &[])).set(f64::NAN);
        assert!(registry.drain().is_empty());
    }

    #[test]
    fn boundary_is_within_one_step() {
        let step = Duration::from_millis(250);
        let wait = until_next_boundary(step);
        assert!(wait > Duration::ZERO && wait <= step);
    }
}
