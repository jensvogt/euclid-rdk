//! Client side of EAP's egress limits: waiting for a permit before calling an outside site.

use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::fmt;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::Eap;
use crate::{Error, Result};

/// The longest single wait between two requests for a permit, whatever euclid suggested: a slot
/// freed early is noticed within this.
const MAX_POLL: Duration = Duration::from_secs(5);

/// No egress permit for a site came free within [`EgressLimiter::max_wait`].
///
/// Returned as [`Error::Io`] with kind [`std::io::ErrorKind::TimedOut`] - like euclid-jdk's
/// `EuclidEgressTimeoutException`, an I/O failure to the caller: the request it was about to make
/// cannot be made now. Recover the details with [`EgressTimeout::from_error`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressTimeout {
    /// The site no permit was granted for.
    pub site: String,
    /// How long the caller waited.
    pub waited: Duration,
    /// Why the last answer was a refusal: `blocked`, `concurrency` or `rate`.
    pub reason: Option<String>,
}

impl fmt::Display for EgressTimeout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "no egress permit for {} after {}s (last refusal: {})",
            self.site,
            self.waited.as_secs(),
            self.reason.as_deref().unwrap_or("null")
        )
    }
}

impl std::error::Error for EgressTimeout {}

impl EgressTimeout {
    /// The egress timeout an [`Error`] carries, if it is one.
    pub fn from_error(error: &Error) -> Option<&EgressTimeout> {
        match error {
            Error::Io(io) => io.get_ref().and_then(|inner| inner.downcast_ref::<EgressTimeout>()),
            _ => None,
        }
    }

    fn into_error(self) -> Error {
        Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, self))
    }
}

/// Holds an application's calls to outside sites to the limits euclid keeps for it, per site -
/// for all of its instances together.
///
/// A site defending itself against denial of service counts per source address, and every
/// instance reaches it from the same one; a limiter inside each instance would count per instance,
/// which the autoscaler multiplies just when there is most to fetch. So the limit lives in EAP and
/// this asks it for a permit before each request:
///
/// ```no_run
/// # async fn run(eap: euclid_rdk::Eap) -> euclid_rdk::Result<()> {
/// use euclid_rdk::eap::EgressLimiter;
///
/// let limiter = EgressLimiter::from_environment(eap)?;   // EUCLID_APPLICATION_ID
/// let permit = limiter.acquire("api.example.com").await?;
/// // ... make the request; on a 429/503:
/// // limiter.throttled("api.example.com", retry_after).await;
/// permit.release().await;
/// # Ok(())
/// # }
/// ```
///
/// [`acquire`](Self::acquire) polls with jitter until a permit is granted, so a crowd of
/// instances does not ask in step, and fails with an [`EgressTimeout`] after
/// [`max_wait`](Self::max_wait). Release the permit when the request is done; one never released
/// (the instance died, or the [`Permit`] was dropped) comes back when its lease runs out.
/// [`run`](Self::run) does acquire-and-release around a future.
///
/// If euclid cannot be asked at all, the limiter does not stop the application: it falls back to
/// one request per [`fallback_interval`](Self::fallback_interval) per site for this instance alone
/// ([`Permit::is_local`] tells). Cloning is cheap; clones share the fallback pacing.
#[derive(Debug, Clone)]
pub struct EgressLimiter {
    eap: Eap,
    application_id: String,
    lease: Duration,
    max_wait: Duration,
    fallback_interval: Duration,
    /// When this instance next lets a request through to a site on its own, without euclid.
    next_fallback: Arc<Mutex<HashMap<String, Instant>>>,
}

impl EgressLimiter {
    /// A limiter for `application_id`, asking `eap` - a client authenticated as the identity the
    /// application runs as.
    pub fn new(eap: Eap, application_id: impl Into<String>) -> Result<Self> {
        let application_id = application_id.into();
        if application_id.trim().is_empty() {
            return Err(Error::invalid("applicationId is required"));
        }
        Ok(Self {
            eap,
            application_id,
            lease: Duration::from_secs(15 * 60),
            max_wait: Duration::from_secs(30 * 60),
            fallback_interval: Duration::from_secs(2),
            next_fallback: Arc::default(),
        })
    }

    /// A limiter for the application this process runs as: the one named by
    /// `EUCLID_APPLICATION_ID`, which euclid sets for every application it starts.
    pub fn from_environment(eap: Eap) -> Result<Self> {
        match std::env::var("EUCLID_APPLICATION_ID") {
            Ok(id) if !id.trim().is_empty() => Self::new(eap, id),
            _ => Err(Error::invalid(
                "EUCLID_APPLICATION_ID is not set - this process was not started by euclid; pass the application id explicitly",
            )),
        }
    }

    /// How long a permit's slot is held if it is never released. Longer than any request takes.
    /// Default 15 minutes; the server allows at most six hours.
    pub fn lease_time(mut self, lease: Duration) -> Self {
        self.lease = lease;
        self
    }

    /// How long [`acquire`](Self::acquire) waits before giving up with an [`EgressTimeout`].
    /// Default 30 minutes - a site blocked after a 429 can keep everyone waiting that long.
    pub fn max_wait(mut self, max_wait: Duration) -> Self {
        self.max_wait = max_wait;
        self
    }

    /// How far apart this instance spaces its requests to one site while euclid cannot be asked.
    /// Default 2 seconds.
    pub fn fallback_interval(mut self, interval: Duration) -> Self {
        self.fallback_interval = interval;
        self
    }

    pub fn application_id(&self) -> &str {
        &self.application_id
    }

    /// Waits for a permit to call `site` (a host name; case and trailing dots are ignored).
    ///
    /// # Errors
    ///
    /// An [`EgressTimeout`] (as [`Error::Io`]) if none came free within
    /// [`max_wait`](Self::max_wait); [`Error::InvalidArgument`] for an empty site. Failing to
    /// reach euclid is not an error - see the fallback in the type's description.
    pub async fn acquire(&self, site: &str) -> Result<Permit> {
        let key = normalize(site)?;
        let started = Instant::now();
        let lease_seconds = self.lease.as_secs().max(1);
        loop {
            let answer = match self
                .eap
                .acquire_egress_permit(&self.application_id, &key, lease_seconds)
                .await
            {
                Ok(answer) => answer,
                Err(_) => return Ok(self.fallback(key).await),
            };
            if answer.granted {
                return Ok(self.permit(key, answer.permit_id));
            }
            let waited = started.elapsed();
            let wait = jittered(answer.retry_after_ms);
            if waited + wait > self.max_wait {
                return Err(EgressTimeout {
                    site: key,
                    waited,
                    reason: answer.reason,
                }
                .into_error());
            }
            tokio::time::sleep(wait).await;
        }
    }

    /// Acquires a permit for `site`, runs `work`, and releases the permit whatever `work` returned.
    pub async fn run<F, T>(&self, site: &str, work: F) -> Result<T>
    where
        F: std::future::Future<Output = T>,
    {
        let permit = self.acquire(site).await?;
        let out = work.await;
        permit.release().await;
        Ok(out)
    }

    /// Reports that `site` refused a request - a 429 or 503 - so that no instance of this
    /// application calls it until `retry_after` has passed. Never fails: a report that cannot be
    /// delivered is dropped, and the caller goes on handling the refusal it got.
    pub async fn throttled(&self, site: &str, retry_after: Duration) {
        let Ok(key) = normalize(site) else { return };
        let _ = self
            .eap
            .report_egress_throttled(&self.application_id, &key, retry_after.as_secs().max(1))
            .await;
    }

    fn permit(&self, site: String, id: Option<String>) -> Permit {
        Permit {
            eap: self.eap.clone(),
            application_id: self.application_id.clone(),
            site,
            id,
        }
    }

    /// One request per interval per site, for this instance: reserve the next free moment under
    /// the lock, so tasks of the same instance queue up rather than all going at once.
    async fn fallback(&self, site: String) -> Permit {
        let now = Instant::now();
        let slot = {
            let mut next = self.next_fallback.lock().unwrap_or_else(|e| e.into_inner());
            let slot = match next.get(&site) {
                Some(last) => (*last + self.fallback_interval).max(now),
                None => now,
            };
            next.insert(site.clone(), slot);
            slot
        };
        if slot > now {
            tokio::time::sleep(slot - now).await;
        }
        self.permit(site, None)
    }
}

/// Permission to make one request to a site. [`release`](Self::release) it when the request is
/// done; dropping it unreleased leaves its slot taken until the lease runs out.
#[derive(Debug)]
#[must_use = "release the permit when the request is done"]
pub struct Permit {
    eap: Eap,
    application_id: String,
    site: String,
    id: Option<String>,
}

impl Permit {
    /// The site the permit is for: the lower-cased host name.
    pub fn site(&self) -> &str {
        &self.site
    }

    /// The permit's id, `None` for a [local](Self::is_local) one.
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    /// Whether this permit was granted by this instance alone because euclid could not be asked.
    pub fn is_local(&self) -> bool {
        self.id.is_none()
    }

    /// Gives the slot back. Never fails: a release that cannot be delivered is dropped, and the
    /// slot comes back when its lease runs out.
    pub async fn release(self) {
        if let Some(id) = &self.id {
            let _ = self
                .eap
                .release_egress_permit(&self.application_id, &self.site, id)
                .await;
        }
    }
}

fn normalize(site: &str) -> Result<String> {
    let s = site.trim().to_lowercase();
    let s = s.trim_end_matches('.');
    if s.is_empty() {
        return Err(Error::invalid("site is required: the host name to be called"));
    }
    Ok(s.to_owned())
}

fn jittered(retry_after_ms: u64) -> Duration {
    let base = retry_after_ms.clamp(10, MAX_POLL.as_millis() as u64);
    Duration::from_millis(base + random_below(base / 5 + 1))
}

/// A random number in `0..bound` - enough to keep instances from polling in step.
fn random_below(bound: u64) -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    hasher.finish() % bound.max(1)
}

/// Reads an HTTP `Retry-After` value in either of its forms: a number of seconds, or an HTTP date
/// (`Sun, 06 Nov 1994 08:49:37 GMT`). A date in the past is zero; anything else is `None`.
pub fn parse_retry_after(value: &str) -> Option<Duration> {
    let v = value.trim();
    if let Ok(seconds) = v.parse::<i64>() {
        return Some(Duration::from_secs(seconds.max(0) as u64));
    }
    let at = parse_http_date(v)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
    Some(Duration::from_secs((at - now).max(0) as u64))
}

/// Seconds since the epoch of an RFC 1123 date, `[Day, ]DD Mon YYYY HH:MM:SS GMT|UT|Z|+hhmm`.
fn parse_http_date(value: &str) -> Option<i64> {
    let rest = match value.split_once(',') {
        Some((_, rest)) => rest,
        None => value,
    };
    let parts: Vec<&str> = rest.split_whitespace().collect();
    let [day, month, year, time, zone] = parts.as_slice() else {
        return None;
    };
    let day: i64 = day.parse().ok()?;
    let month = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ]
    .iter()
    .position(|m| m.eq_ignore_ascii_case(month))? as i64
        + 1;
    let year: i64 = year.parse().ok()?;
    let hms: Vec<i64> = time.split(':').map(|p| p.parse().ok()).collect::<Option<_>>()?;
    let [h, m, s] = hms.as_slice() else { return None };
    let offset = match *zone {
        "GMT" | "UT" | "UTC" | "Z" => 0,
        z if z.len() == 5 && (z.starts_with('+') || z.starts_with('-')) => {
            let hours: i64 = z[1..3].parse().ok()?;
            let minutes: i64 = z[3..5].parse().ok()?;
            let sign = if z.starts_with('-') { -1 } else { 1 };
            sign * (hours * 3600 + minutes * 60)
        }
        _ => return None,
    };
    if !(1..=31).contains(&day) || *h > 23 || *m > 59 || *s > 60 {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + h * 3600 + m * 60 + s - offset)
}

/// Howard Hinnant's civil-to-days algorithm.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_seconds_and_dates() {
        assert_eq!(parse_retry_after(" 120 "), Some(Duration::from_secs(120)));
        assert_eq!(parse_retry_after("-5"), Some(Duration::ZERO));
        assert_eq!(parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT"), Some(Duration::ZERO));
        assert_eq!(parse_retry_after("soon"), None);
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"), Some(784_111_777));
        assert_eq!(parse_http_date("06 Nov 1994 09:49:37 +0100"), Some(784_111_777));
        let future = parse_retry_after("Fri, 01 Jan 2100 00:00:00 GMT").unwrap();
        assert!(future > Duration::from_secs(365 * 86_400));
    }

    #[test]
    fn sites_are_normalized() {
        assert_eq!(normalize(" API.Example.COM. ").unwrap(), "api.example.com");
        assert!(normalize("  ").is_err());
        assert!(normalize(".").is_err());
    }

    #[test]
    fn jitter_stays_within_bounds() {
        for _ in 0..200 {
            let d = jittered(1_000).as_millis();
            assert!((1_000..=1_200).contains(&d), "{d}");
        }
        assert!(jittered(0).as_millis() >= 10);
        assert!(jittered(60_000).as_millis() <= 6_000);
    }

    #[test]
    fn timeout_round_trips_through_error() {
        let error = EgressTimeout {
            site: "a.example".into(),
            waited: Duration::from_secs(3),
            reason: Some("rate".into()),
        }
        .into_error();
        let timeout = EgressTimeout::from_error(&error).unwrap();
        assert_eq!(timeout.site, "a.example");
        assert!(error
            .to_string()
            .contains("no egress permit for a.example after 3s (last refusal: rate)"));
    }
}
