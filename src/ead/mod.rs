//! EAD - Euclid Audit.
//!
//! The audit trail: every command a module was asked to carry out, by whom, with what, and how it
//! was answered. Reads are always confined to the caller's own account - whatever a request asks
//! for, one account never sees another's trail.

pub mod model;

pub use model::*;
use serde_json::json;

use crate::service::ServiceClient;
use crate::Result;

/// EAD operations, obtained from [`Session::ead`](crate::Session::ead).
///
/// Requests are SigV4-signed with the session's access key when it has one, otherwise
/// authenticated with the bearer token. Cloning is cheap.
#[derive(Debug, Clone)]
pub struct Ead {
    client: ServiceClient,
}

impl Ead {
    pub(crate) fn new(client: ServiceClient) -> Self {
        Self { client }
    }

    /// Lists one page of the caller's account's audit trail, newest first, filtered as asked.
    ///
    /// The `total` is counted only up to a ceiling; `total_exact` says whether it was reached.
    pub async fn list_events(&self, request: &ListEventsRequest) -> Result<ListEventsResponse> {
        self.client.call("list-events", request).await
    }

    /// Counts the matching entries exactly, without listing them.
    pub async fn count_events(&self, request: &CountEventsRequest) -> Result<u64> {
        let count: Count = self.client.call("count-events", request).await?;
        Ok(count.count)
    }

    /// Removes every entry older than `older_than_days` days and returns how many went.
    ///
    /// The window must be positive: the server refuses 0 with 400 rather than empty the whole
    /// trail.
    pub async fn purge_events(&self, older_than_days: u64) -> Result<u64> {
        let removed: Removed = self
            .client
            .call("purge-events", &json!({ "olderThanDays": older_than_days }))
            .await?;
        Ok(removed.removed)
    }
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct Count {
    #[serde(deserialize_with = "crate::serde_util::lenient_u64")]
    count: u64,
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct Removed {
    #[serde(deserialize_with = "crate::serde_util::lenient_u64")]
    removed: u64,
}
