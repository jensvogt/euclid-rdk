//! ESS - Euclid Secrets Service.
//!
//! Secrets are stored encrypted under an EKM key - the namespace's own unless another is named.
//! Only [`Ess::get_secret`] decrypts anything; listings and every other answer describe a secret
//! without its value.

pub mod model;

pub use model::*;
use serde_json::{json, Value};

use crate::service::ServiceClient;
use crate::Result;

/// ESS operations, obtained from [`Session::ess`](crate::Session::ess).
///
/// Requests are SigV4-signed with the session's access key when it has one, otherwise
/// authenticated with the bearer token. Cloning is cheap.
#[derive(Debug, Clone)]
pub struct Ess {
    client: ServiceClient,
}

impl Ess {
    pub(crate) fn new(client: ServiceClient) -> Self {
        Self { client }
    }

    /// Stores a new secret under the namespace's own encryption key.
    pub async fn create_secret(&self, name: &str, value: &str) -> Result<Secret> {
        self.create_secret_with(&CreateSecretRequest {
            name: name.into(),
            value: value.into(),
            ..Default::default()
        })
        .await
    }

    /// Stores a new secret. Refused with 409 if one of that name already exists - creating never
    /// quietly replaces; use [`rotate_secret`](Self::rotate_secret) for that.
    pub async fn create_secret_with(&self, request: &CreateSecretRequest) -> Result<Secret> {
        self.client.call_field("create-secret", request, "secret").await
    }

    /// Reads a secret together with its decrypted value. Do not log the result's `value`.
    pub async fn get_secret(&self, name: &str) -> Result<GetSecretResponse> {
        let mut root = self.client.call_value("get-secret", &json!({ "name": name })).await?;
        let value = root.get("value").and_then(text);
        let secret = match root.get_mut("secret").map(Value::take) {
            None | Some(Value::Null) => None,
            Some(node) => Some(serde_json::from_value(node)?),
        };
        Ok(GetSecretResponse { secret, value })
    }

    /// Lists the secrets of the session's account and namespace. No values come back, and a
    /// principal restricted to particular secrets sees only those.
    pub async fn list_secrets(&self, request: &ListSecretsRequest) -> Result<ListSecretsResponse> {
        self.client.call("list-secrets", request).await
    }

    /// Whether a secret of exactly that name exists (and is visible to the caller).
    pub async fn exists_secret(&self, name: &str) -> Result<bool> {
        let matching = self
            .list_secrets(&ListSecretsRequest {
                prefix: name.into(),
                page_size: 0,
                ..Default::default()
            })
            .await?;
        Ok(matching.secrets.iter().any(|s| s.name.as_deref() == Some(name)))
    }

    /// Replaces a secret's value - a rotation, which bumps its version.
    pub async fn rotate_secret(&self, name: &str, value: &str) -> Result<Secret> {
        self.update_secret(&UpdateSecretRequest {
            name: name.into(),
            value: Some(value.into()),
            ..Default::default()
        })
        .await
    }

    /// Changes a secret: only the fields that are `Some` change (see [`UpdateSecretRequest`]).
    pub async fn update_secret(&self, request: &UpdateSecretRequest) -> Result<Secret> {
        self.client.call_field("update-secret", request, "secret").await
    }

    pub async fn delete_secret(&self, name: &str) -> Result<DeleteSecretResponse> {
        self.client.call("delete-secret", &json!({ "name": name })).await
    }

    /// Sets a tag, overwriting one of the same key.
    pub async fn add_secret_tag(&self, name: &str, key: &str, value: &str) -> Result<Secret> {
        let body = json!({ "name": name, "key": key, "value": value });
        self.client.call_field("add-secret-tag", &body, "secret").await
    }

    pub async fn delete_secret_tag(&self, name: &str, key: &str) -> Result<Secret> {
        let body = json!({ "name": name, "key": key });
        self.client.call_field("delete-secret-tag", &body, "secret").await
    }
}

/// A JSON value as text, the way Jackson's `asText()` reads it; `None` for null.
fn text(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}
