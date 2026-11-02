//! Thin wrapper around [`reqwest::Client`] that speaks euclid's request convention: every call is
//! a `POST` naming the module in `x-euclid-target` and the operation in `x-euclid-action`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

use crate::{Error, Result};

pub(crate) const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// A status and body, read in full.
#[derive(Debug, Clone)]
pub(crate) struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Response {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// The body as text, for JSON answers and error messages.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HttpClient {
    client: reqwest::Client,
    /// The extra CA certificate this client trusts, kept so that other connections made on the
    /// same session (the EES WebSocket stream) can trust the same one.
    ca_cert_path: Option<PathBuf>,
}

impl HttpClient {
    /// Builds a client trusting the system roots and, if given, one extra PEM CA certificate -
    /// alongside the system trust store, not instead of it, mirroring euclid-cli's `--ca-cert`.
    pub fn new(ca_cert_path: Option<&Path>) -> Result<Self> {
        let mut builder = reqwest::Client::builder();
        if let Some(path) = ca_cert_path {
            let pem = std::fs::read(path)?;
            for cert in reqwest::Certificate::from_pem_bundle(&pem)? {
                builder = builder.add_root_certificate(cert);
            }
        }
        Ok(Self {
            client: builder.build()?,
            ca_cert_path: ca_cert_path.map(Path::to_path_buf),
        })
    }

    /// The extra CA certificate this client trusts, if any.
    #[cfg_attr(not(feature = "ws"), allow(dead_code))]
    pub fn ca_cert_path(&self) -> Option<&Path> {
        self.ca_cert_path.as_deref()
    }

    /// POSTs `body` to `url` as `target`/`action`, with `headers` added on top. `timeout`
    /// defaults to [`DEFAULT_REQUEST_TIMEOUT`]; a long poll passes its own.
    pub async fn post(
        &self,
        url: &str,
        body: Vec<u8>,
        target: &str,
        action: &str,
        headers: &[(String, String)],
        timeout: Option<Duration>,
    ) -> Result<Response> {
        let mut map = HeaderMap::new();
        map.insert("x-euclid-target", header_value(target)?);
        map.insert("x-euclid-action", header_value(action)?);
        for (name, value) in headers {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|e| Error::invalid(format!("invalid header name {name:?}: {e}")))?;
            map.insert(name, header_value(value)?);
        }

        let response = self
            .client
            .post(url)
            .headers(map)
            .timeout(timeout.unwrap_or(DEFAULT_REQUEST_TIMEOUT))
            .body(body)
            .send()
            .await?;
        let status = response.status().as_u16();
        let body = response.bytes().await?.to_vec();
        Ok(Response { status, body })
    }
}

fn header_value(value: &str) -> Result<HeaderValue> {
    HeaderValue::from_str(value).map_err(|e| Error::invalid(format!("invalid header value: {e}")))
}
