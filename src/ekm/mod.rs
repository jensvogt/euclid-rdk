//! EKM - Euclid Key Management (encryption keys and certificates).
//!
//! Keys are server-side only: their material never leaves EKM, and data is encrypted and decrypted
//! by sending it to [`Ekm::encrypt`]/[`Ekm::decrypt`]. The server names a key itself (a UUID);
//! `get`, `revoke`, description and tag calls take its ERN (`get_key` also its name), while
//! `encrypt`, `decrypt` and `delete_key` take its id - the name. Certificates are X.509 certificates EKM
//! generates (self-signed) or that are imported with their private key; only the public PEM comes
//! back.

pub mod model;

pub use model::*;
use serde_json::{json, Value};

use crate::service::{CallOptions, ServiceClient};
use crate::{Error, Result};

/// Days a deleted key stays in `PENDING_DELETION` before it is gone, unless told otherwise.
pub const DEFAULT_PENDING_WINDOW_DAYS: u64 = 7;

/// EKM operations, obtained from [`Session::ekm`](crate::Session::ekm).
///
/// Requests are SigV4-signed with the session's access key when it has one, otherwise
/// authenticated with the bearer token. `encrypt`/`decrypt` carry raw bytes and always use the
/// bearer token, as in euclid-cli. Cloning is cheap.
#[derive(Debug, Clone)]
pub struct Ekm {
    client: ServiceClient,
}

impl Ekm {
    pub(crate) fn new(client: ServiceClient) -> Self {
        Self { client }
    }

    // -----------------------------------------------------------------------------------------
    // Keys
    // -----------------------------------------------------------------------------------------

    /// Creates an `AES`/128 key with no description. The server names it.
    pub async fn create_key(&self) -> Result<CreateKeyResponse> {
        self.create_key_with(&CreateKeyRequest::default()).await
    }

    pub async fn create_key_with(&self, request: &CreateKeyRequest) -> Result<CreateKeyResponse> {
        self.client.call("create-key", request).await
    }

    pub async fn list_keys(&self, request: &ListKeysRequest) -> Result<ListKeysResponse> {
        self.client.call("list-keys", request).await
    }

    /// Reads one key by name, or by ERN if `name_or_ern` starts with `ern:`.
    pub async fn get_key(&self, name_or_ern: &str) -> Result<Key> {
        let body = if name_or_ern.starts_with("ern:") {
            json!({ "ern": name_or_ern, "name": null })
        } else {
            json!({ "ern": null, "name": name_or_ern })
        };
        let key: Option<Key> = self.client.call_field("get-key", &body, "key").await?;
        Ok(key.unwrap_or_default())
    }

    /// Whether the key exists: `false` on a 404, any other failure is an error.
    pub async fn exists_key(&self, name_or_ern: &str) -> Result<bool> {
        match self.get_key(name_or_ern).await {
            Ok(_) => Ok(true),
            Err(Error::Service { status: 404, .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Schedules a key for deletion after [`DEFAULT_PENDING_WINDOW_DAYS`]. `key_id` is the key's
    /// id - its `name` - not its ERN, which the server answers with 404.
    pub async fn delete_key(&self, key_id: &str) -> Result<DeleteKeyResponse> {
        self.delete_key_after(key_id, DEFAULT_PENDING_WINDOW_DAYS).await
    }

    /// Schedules a key (by id, see [`delete_key`](Self::delete_key)) for deletion after
    /// `pending_window_in_days`, at least 1. Until then it is `PENDING_DELETION` and can no longer
    /// be used.
    pub async fn delete_key_after(&self, key_id: &str, pending_window_in_days: u64) -> Result<DeleteKeyResponse> {
        let body = json!({ "keyId": key_id, "pendingWindowInDays": pending_window_in_days });
        self.client.call("delete-key", &body).await
    }

    /// Revokes a key: it can no longer encrypt or decrypt.
    pub async fn revoke_key(&self, ern: &str) -> Result<RevokeKeyResponse> {
        self.client.call("revoke-key", &json!({ "ern": ern })).await
    }

    pub async fn set_key_description(&self, ern: &str, description: &str) -> Result<SetKeyDescriptionResponse> {
        let body = json!({ "ern": ern, "description": description });
        self.client.call("set-key-description", &body).await
    }

    /// Sets a tag on a key, overwriting one of the same key.
    pub async fn add_key_tag(&self, ern: &str, key: &str, value: &str) -> Result<()> {
        let body = json!({ "ern": ern, "key": key, "value": value });
        self.client.call_unit("add-key-tag", &body).await
    }

    pub async fn delete_key_tag(&self, ern: &str, key: &str) -> Result<()> {
        self.client
            .call_unit("delete-key-tag", &json!({ "ern": ern, "key": key }))
            .await
    }

    // -----------------------------------------------------------------------------------------
    // Encryption
    // -----------------------------------------------------------------------------------------

    /// Encrypts `plaintext` with the key `key_id` and returns the ciphertext. `key_id` is the key's
    /// id - its `name` - not its ERN.
    pub async fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> Result<Sensitive> {
        self.transform("encrypt", key_id, plaintext).await
    }

    /// Decrypts a ciphertext produced by [`encrypt`](Self::encrypt) with the same key (by id).
    pub async fn decrypt(&self, key_id: &str, ciphertext: &[u8]) -> Result<Sensitive> {
        self.transform("decrypt", key_id, ciphertext).await
    }

    async fn transform(&self, action: &str, key_id: &str, data: &[u8]) -> Result<Sensitive> {
        let options = CallOptions {
            bearer_only: true,
            content_type: Some("application/octet-stream"),
            headers: vec![("x-euclid-key-id".into(), key_id.into())],
            ..Default::default()
        };
        let response = self.client.send_ok(action, data.to_vec(), &options).await?;
        Ok(Sensitive::new(response.body))
    }

    // -----------------------------------------------------------------------------------------
    // Certificates
    // -----------------------------------------------------------------------------------------

    /// Generates a self-signed certificate called `name` (825 days, 2048-bit key).
    pub async fn create_certificate(&self, name: &str) -> Result<Certificate> {
        self.create_certificate_with(&CreateCertificateRequest {
            name: name.into(),
            ..Default::default()
        })
        .await
    }

    pub async fn create_certificate_with(&self, request: &CreateCertificateRequest) -> Result<Certificate> {
        self.certificate("create-certificate", request).await
    }

    /// Imports a certificate together with its private key, both PEM.
    pub async fn import_certificate(&self, request: &ImportCertificateRequest) -> Result<Certificate> {
        self.certificate("import-certificate", request).await
    }

    pub async fn list_certificates(&self, request: &ListCertificatesRequest) -> Result<ListCertificatesResponse> {
        self.client.call("list-certificates", request).await
    }

    pub async fn get_certificate(&self, name: &str) -> Result<Certificate> {
        self.certificate("get-certificate", &json!({ "name": name })).await
    }

    pub async fn delete_certificate(&self, name: &str) -> Result<DeleteCertificateResponse> {
        self.client.call("delete-certificate", &json!({ "name": name })).await
    }

    async fn certificate(&self, action: &str, body: &impl serde::Serialize) -> Result<Certificate> {
        let mut root = self.client.call_value(action, body).await?;
        match root.get_mut("certificate").map(Value::take) {
            None | Some(Value::Null) => Ok(Certificate::default()),
            Some(node) => Ok(serde_json::from_value(node)?),
        }
    }
}
