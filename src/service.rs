//! The authenticated request path every module client shares.
//!
//! A request carries the caller's identity headers and is authenticated one of two ways, the same
//! as euclid-jdk and euclid-cli: SigV4-signed with the session's access key when it has one,
//! otherwise with the bearer token. EAM always uses the bearer token.

use std::sync::Arc;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

use crate::auth::sigv4;
use crate::http::{HttpClient, Response};
use crate::{Error, Result};

/// Who a request is made as.
#[derive(Debug, Clone, Default)]
pub(crate) struct Identity {
    pub token: String,
    pub user_id: Option<String>,
    pub account_id: Option<String>,
    pub region: Option<String>,
    pub namespace: Option<String>,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
}

impl Identity {
    fn signing_key(&self) -> Option<(&str, &str)> {
        match (self.access_key_id.as_deref(), self.secret_access_key.as_deref()) {
            (Some(id), Some(secret)) if !id.is_empty() && !secret.is_empty() => Some((id, secret)),
            _ => None,
        }
    }
}

/// How a single request deviates from a plain signed JSON call.
#[derive(Debug, Clone, Default)]
pub(crate) struct CallOptions {
    /// Overrides the default request timeout, e.g. for a long poll.
    pub timeout: Option<Duration>,
    /// Authenticate with the bearer token even when an access key is available. Used for raw
    /// binary bodies, which euclid-cli never signs.
    pub bearer_only: bool,
    /// Content type of the body; `application/json` when `None`.
    pub content_type: Option<&'static str>,
    /// Further request headers, e.g. ESM's `x-euclid-bucket-ern`.
    pub headers: Vec<(String, String)>,
}

/// A module client: one euclid target (`eqs`, `esm`, ...) on behalf of one identity.
#[derive(Debug, Clone)]
pub(crate) struct ServiceClient {
    http: HttpClient,
    base_url: String,
    identity: Arc<Identity>,
    target: String,
    bearer_only: bool,
    internal: bool,
}

impl ServiceClient {
    pub fn new(http: HttpClient, base_url: String, identity: Identity, target: impl Into<String>) -> Self {
        Self {
            http,
            base_url,
            identity: Arc::new(identity),
            target: target.into(),
            bearer_only: false,
            internal: false,
        }
    }

    /// Never sign, always present the bearer token (EAM's convention).
    pub fn bearer_only(mut self) -> Self {
        self.bearer_only = true;
        self
    }

    /// Mark requests `x-euclid-internal: true`.
    pub fn internal(mut self) -> Self {
        self.internal = true;
        self
    }

    /// The server's base URL, without a trailing slash.
    #[cfg_attr(not(feature = "ws"), allow(dead_code))]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// The extra CA certificate the HTTP client trusts, if any.
    #[cfg_attr(not(feature = "ws"), allow(dead_code))]
    pub fn ca_cert_path(&self) -> Option<&std::path::Path> {
        self.http.ca_cert_path()
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// `host[:port]` exactly as the HTTP client will send it - a default port is left out - so the
    /// signature covers the Host header the server actually receives.
    fn host_header(&self) -> String {
        match reqwest::Url::parse(&self.base_url) {
            Ok(url) => match (url.host_str(), url.port()) {
                (Some(host), Some(port)) => format!("{host}:{port}"),
                (Some(host), None) => host.to_owned(),
                _ => String::new(),
            },
            Err(_) => String::new(),
        }
    }

    fn headers(&self, action: &str, body: &[u8], options: &CallOptions) -> Vec<(String, String)> {
        let id = &*self.identity;
        let mut headers: Vec<(String, String)> = vec![(
            "content-type".into(),
            options.content_type.unwrap_or("application/json").into(),
        )];
        if let Some(v) = &id.region {
            headers.push(("x-euclid-region".into(), v.clone()));
        }
        if let Some(v) = &id.account_id {
            headers.push(("x-euclid-account-id".into(), v.clone()));
        }
        if let Some(v) = &id.user_id {
            headers.push(("x-euclid-user-id".into(), v.clone()));
        }
        if let Some(v) = id.namespace.as_deref().filter(|n| !n.is_empty()) {
            headers.push(("x-euclid-namespace".into(), v.to_owned()));
        }
        if self.internal {
            headers.push(("x-euclid-internal".into(), "true".into()));
        }
        headers.extend(options.headers.iter().cloned());

        match id.signing_key().filter(|_| !self.bearer_only && !options.bearer_only) {
            Some((key_id, secret)) => {
                let host = self.host_header();
                let mut signable: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
                signable.push(("host", &host));
                signable.push(("x-euclid-target", &self.target));
                signable.push(("x-euclid-action", action));
                let signature = sigv4::sign(
                    "POST",
                    "/",
                    &signable,
                    body,
                    key_id,
                    secret,
                    id.region.as_deref().unwrap_or_default(),
                    &self.target,
                    &sigv4::amz_date_now(),
                );
                headers.push(("x-amz-date".into(), signature.amz_date));
                headers.push(("x-amz-content-sha256".into(), signature.content_sha256));
                headers.push(("authorization".into(), signature.authorization));
            }
            None => headers.push(("authorization".into(), format!("Bearer {}", id.token))),
        }
        headers
    }

    /// Sends one request and returns the response whatever its status.
    ///
    /// A signed request answered `401 ... expired` is signed afresh and sent once more: a signature
    /// is only good around the moment it was made, and one that went stale in flight says nothing
    /// about the request. A bearer token cannot be refreshed here, so that answer stands.
    pub async fn send(&self, action: &str, body: Vec<u8>, options: &CallOptions) -> Result<Response> {
        let url = format!("{}/", self.base_url);
        let headers = self.headers(action, &body, options);
        let signed = headers
            .iter()
            .any(|(n, v)| n == "authorization" && v.starts_with("AWS4"));
        let response = self
            .http
            .post(&url, body.clone(), &self.target, action, &headers, options.timeout)
            .await?;
        if signed && response.status == 401 && response.text().to_lowercase().contains("expired") {
            let headers = self.headers(action, &body, options);
            return self
                .http
                .post(&url, body, &self.target, action, &headers, options.timeout)
                .await;
        }
        Ok(response)
    }

    /// Sends `body` and fails with [`Error::Service`] on a non-2xx answer.
    pub async fn send_ok(&self, action: &str, body: Vec<u8>, options: &CallOptions) -> Result<Response> {
        let response = self.send(action, body, options).await?;
        if !response.is_success() {
            return Err(Error::service(&self.target, action, response.status, response.text()));
        }
        Ok(response)
    }

    /// Calls `action` with a JSON body and returns the JSON answer (`Null` for an empty one).
    pub async fn call_value_with(&self, action: &str, body: &impl Serialize, options: &CallOptions) -> Result<Value> {
        let response = self.send_ok(action, serde_json::to_vec(body)?, options).await?;
        if response.body.iter().all(u8::is_ascii_whitespace) {
            return Ok(Value::Null);
        }
        Ok(serde_json::from_slice(&response.body)?)
    }

    pub async fn call_value(&self, action: &str, body: &impl Serialize) -> Result<Value> {
        self.call_value_with(action, body, &CallOptions::default()).await
    }

    /// Calls `action` and decodes the whole answer.
    pub async fn call<R: DeserializeOwned>(&self, action: &str, body: &impl Serialize) -> Result<R> {
        Ok(serde_json::from_value(self.call_value(action, body).await?)?)
    }

    /// Calls `action` and decodes the value under `field` in the answer (`null` if absent).
    pub async fn call_field<R: DeserializeOwned>(&self, action: &str, body: &impl Serialize, field: &str) -> Result<R> {
        let mut value = self.call_value(action, body).await?;
        let nested = value.get_mut(field).map(Value::take).unwrap_or(Value::Null);
        Ok(serde_json::from_value(nested)?)
    }

    /// Calls `action` for its effect only.
    pub async fn call_unit(&self, action: &str, body: &impl Serialize) -> Result<()> {
        self.call_value(action, body).await.map(|_| ())
    }
}
