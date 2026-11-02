//! Request and response types of the ESS (Euclid Secrets Service) module.
//!
//! Field names are the wire names in camelCase. Response types default every field, so a field
//! the server leaves out reads as `None`/zero instead of failing the whole response.
//!
//! Secret values never appear in `Debug` output: every type that carries one redacts it.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

pub use crate::eam::SortDirection;
use crate::serde_util::{lenient_string, lenient_u64};

const REDACTED: &str = "<redacted>";

fn redact(value: &Option<String>) -> Option<&'static str> {
    value.as_ref().map(|_| REDACTED)
}

/// Reads a JSON object as text values, the way the JDK's `asText()` does; anything else is empty.
fn text_map<'de, D: Deserializer<'de>>(d: D) -> Result<BTreeMap<String, String>, D::Error> {
    Ok(match Option::<serde_json::Value>::deserialize(d)? {
        Some(serde_json::Value::Object(map)) => map
            .into_iter()
            .map(|(k, v)| {
                let text = match v {
                    serde_json::Value::String(s) => s,
                    serde_json::Value::Null => String::new(),
                    other => other.to_string(),
                };
                (k, text)
            })
            .collect(),
        _ => BTreeMap::new(),
    })
}

/// A secret's description - everything about it except its value, which only
/// [`Ess::get_secret`](super::Ess::get_secret) returns.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Secret {
    pub name: Option<String>,
    pub ern: Option<String>,
    pub description: Option<String>,
    /// The EKM key the value is encrypted under.
    pub encryption_key_ern: Option<String>,
    /// Bumped by every rotation (a new value).
    #[serde(deserialize_with = "lenient_u64")]
    pub version: u64,
    /// When the value was last replaced.
    #[serde(deserialize_with = "lenient_string")]
    pub rotated: Option<String>,
    #[serde(deserialize_with = "text_map")]
    pub tags: BTreeMap<String, String>,
    #[serde(deserialize_with = "lenient_string")]
    pub created: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub modified: Option<String>,
}

/// Body of `create-secret`.
#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSecretRequest {
    /// The name to store the secret under. Refused with 409 if it is already taken.
    pub name: String,
    /// What the secret is for.
    pub description: String,
    /// The secret itself.
    pub value: String,
    /// The EKM key to encrypt under; empty for the namespace's own key.
    pub key_ern: String,
}

impl fmt::Debug for CreateSecretRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateSecretRequest")
            .field("name", &self.name)
            .field("description", &self.description)
            .field("value", &REDACTED)
            .field("key_ern", &self.key_ern)
            .finish()
    }
}

/// Body of `update-secret`: only what is `Some` changes.
///
/// Absent and empty mean different things: `description: None` leaves the stored description
/// alone, `Some("")` clears it. A request naming none of `value`, `description` and `key_ern` is
/// refused with 400, as is an empty `value`.
#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateSecretRequest {
    pub name: String,
    /// The new value. Setting one is a rotation and bumps the version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Another EKM key to move the secret to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ern: Option<String>,
}

impl fmt::Debug for UpdateSecretRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpdateSecretRequest")
            .field("name", &self.name)
            .field("value", &redact(&self.value))
            .field("description", &self.description)
            .field("key_ern", &self.key_ern)
            .finish()
    }
}

/// Answer to `get-secret`: the description and the decrypted value.
///
/// The value is the one thing in this module worth stealing - do not log it. `Debug` redacts it.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct GetSecretResponse {
    pub secret: Option<Secret>,
    pub value: Option<String>,
}

impl fmt::Debug for GetSecretResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GetSecretResponse")
            .field("secret", &self.secret)
            .field("value", &redact(&self.value))
            .finish()
    }
}

/// Paging and sorting for `list-secrets`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListSecretsRequest {
    pub prefix: String,
    pub page_size: u64,
    pub page_index: u64,
    pub sort_column: String,
    pub sort_direction: SortDirection,
}

impl Default for ListSecretsRequest {
    fn default() -> Self {
        Self {
            prefix: String::new(),
            page_size: 10,
            page_index: 0,
            sort_column: "name".into(),
            sort_direction: SortDirection::Asc,
        }
    }
}

/// Answer to `list-secrets`. No values come back.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListSecretsResponse {
    pub secrets: Vec<Secret>,
    #[serde(deserialize_with = "lenient_u64")]
    pub total: u64,
}

/// Answer to `delete-secret`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DeleteSecretResponse {
    pub ern: Option<String>,
    pub name: Option<String>,
}
