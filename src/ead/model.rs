//! Request and response types of the EAD (Euclid Audit) module.
//!
//! Field names are the wire names in camelCase. Response types default every field, so a field
//! the server leaves out reads as `None`/zero instead of failing the whole response.

use serde::{Deserialize, Serialize};

use crate::serde_util::{default_true, lenient_string, lenient_u64};

/// One entry of the audit trail: a command some module was asked to carry out.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AuditEvent {
    pub account_id: Option<String>,
    pub namespace: Option<String>,
    pub user_id: Option<String>,
    /// The module the command was addressed to, e.g. `"esm"`.
    pub module: Option<String>,
    /// The action, e.g. `"create-bucket"`.
    pub command: Option<String>,
    /// The parameters the command carried, as the server recorded them (secrets redacted).
    pub parameters: Option<String>,
    /// The HTTP status the command was answered with - what tells an attempt from a success.
    #[serde(deserialize_with = "lenient_u64")]
    pub status: u64,
    #[serde(deserialize_with = "lenient_string")]
    pub created: Option<String>,
}

/// Filters and paging for `list-events`. Each filter is sent only when set.
///
/// The trail read is always the caller's own account's, whatever is asked for.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListEventsRequest {
    /// Only entries of this user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// Only entries addressed to this module, e.g. `"esm"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    /// Only entries of this action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    pub page_size: u64,
    pub page_index: u64,
}

impl Default for ListEventsRequest {
    fn default() -> Self {
        Self {
            user_id: None,
            module: None,
            command: None,
            page_size: 10,
            page_index: 0,
        }
    }
}

/// Answer to `list-events`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListEventsResponse {
    pub events: Vec<AuditEvent>,
    /// The number of matching entries - counted only up to a ceiling (100 000); see
    /// [`total_exact`](Self::total_exact).
    #[serde(deserialize_with = "lenient_u64")]
    pub total: u64,
    /// `false` when [`total`](Self::total) hit the ceiling and means "at least this many". Ask
    /// [`Ead::count_events`](super::Ead::count_events) for the real number.
    #[serde(default = "default_true")]
    pub total_exact: bool,
}

impl Default for ListEventsResponse {
    fn default() -> Self {
        Self {
            events: Vec::new(),
            total: 0,
            total_exact: true,
        }
    }
}

/// Filters for `count-events`: the same as [`ListEventsRequest`]'s, without paging.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CountEventsRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}
