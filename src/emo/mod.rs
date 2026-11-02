//! EMO - Euclid Monitoring (pushing metrics a process measured about itself).
//!
//! One action: pushing metrics an application has measured about itself. Everything euclid knows
//! about a process from the outside - is it running, is it answering - the manager already sees;
//! what it cannot see is how hard the process is working, and for an application that consumes
//! messages rather than serving requests that is the only signal there is.
//!
//! Samples are accumulated by EMO into the same bucket-aligned rows its own collectors write, so
//! they roll up and graph alongside CPU, memory and the module gauges. Pushing is cheap and meant
//! to be periodic: one call carrying every metric of one tick, not a call per measurement. With
//! the `metrics` cargo feature, `EmoRecorder` does exactly that for anything recorded through
//! the [`metrics`](https://docs.rs/metrics) crate.

pub mod model;
#[cfg(feature = "metrics")]
mod recorder;

pub use model::*;
#[cfg(feature = "metrics")]
pub use recorder::{EmoRecorder, EmoRecorderBuilder, EmoRecorderHandle, DEFAULT_STEP};

use crate::service::ServiceClient;
use crate::Result;

/// EMO operations, obtained from [`Session::emo`](crate::Session::emo).
///
/// Meant for ordinary principals: an application reporting its own load holds no more privilege
/// than any other application. Requests are SigV4-signed with the session's access key when it has
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

    /// Starts building a [`metrics`](https://docs.rs/metrics) recorder that pushes everything
    /// recorded through it to EMO once per step, as `module`.
    #[cfg(feature = "metrics")]
    pub fn recorder(&self, module: impl Into<String>) -> EmoRecorderBuilder {
        EmoRecorderBuilder::new(self.clone(), module.into())
    }
}
