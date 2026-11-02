//! Request and response types of the EKM (Euclid Key Management) module.
//!
//! Field names are the wire names in camelCase. Response types default every field, so a field
//! the server leaves out reads as `None`/zero/empty instead of failing the whole response. Request
//! types send every field, `null` included, the way euclid-jdk's default mapper does.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

pub use crate::eam::SortDirection;
use crate::serde_util::{lenient_string, lenient_u64};

const REDACTED: &str = "<redacted>";

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

/// Reads a JSON array as text values; anything else is empty.
fn text_list<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    Ok(match Option::<serde_json::Value>::deserialize(d)? {
        Some(serde_json::Value::Array(values)) => values
            .into_iter()
            .map(|v| match v {
                serde_json::Value::String(s) => s,
                other => other.to_string(),
            })
            .collect(),
        _ => Vec::new(),
    })
}

// ---------------------------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------------------------

/// An encryption key as EKM describes it. The key material itself never leaves the server.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Key {
    pub name: Option<String>,
    pub ern: Option<String>,
    /// Empty for a key whose creator gave none; absent from a server too old to know descriptions.
    pub description: Option<String>,
    pub algorithm: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub length: u64,
    /// E.g. `AVAILABLE`, `REVOKED`, `PENDING_DELETION`.
    pub status: Option<String>,
    #[serde(deserialize_with = "text_map")]
    pub tags: BTreeMap<String, String>,
    /// Only set on a key scheduled for deletion.
    #[serde(deserialize_with = "lenient_string")]
    pub deletion_date: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub created: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub modified: Option<String>,
}

/// Body of `create-key`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateKeyRequest {
    /// E.g. `AES`.
    pub algorithm: String,
    /// Key length in bits.
    pub length: u64,
    pub description: String,
}

impl Default for CreateKeyRequest {
    /// `AES`/128 with no description, as euclid-jdk's `createKey()`.
    fn default() -> Self {
        Self {
            algorithm: "AES".into(),
            length: 128,
            description: String::new(),
        }
    }
}

/// Answer to `create-key`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CreateKeyResponse {
    pub ern: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub algorithm: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub length: u64,
    pub status: Option<String>,
}

/// Paging and sorting for `list-keys` and `list-certificates`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListRequest {
    pub prefix: String,
    pub page_size: u64,
    pub page_index: u64,
    pub sort_column: String,
    pub sort_direction: SortDirection,
}

impl Default for ListRequest {
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

/// Paging and sorting for `list-keys`.
pub type ListKeysRequest = ListRequest;
/// Paging and sorting for `list-certificates`.
pub type ListCertificatesRequest = ListRequest;

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListKeysResponse {
    pub keys: Vec<Key>,
    #[serde(deserialize_with = "lenient_u64")]
    pub total: u64,
}

/// Answer to `delete-key`: the deletion is scheduled, not immediate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DeleteKeyResponse {
    pub ern: Option<String>,
    pub name: Option<String>,
    /// When the key will actually be deleted.
    #[serde(deserialize_with = "lenient_string")]
    pub deletion_date: Option<String>,
    pub status: Option<String>,
}

/// Answer to `revoke-key`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RevokeKeyResponse {
    pub ern: Option<String>,
    pub name: Option<String>,
    pub status: Option<String>,
}

/// Answer to `set-key-description`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SetKeyDescriptionResponse {
    pub ern: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------------------------

/// An X.509 certificate held by EKM. `certificate` is the public PEM; the private key never comes
/// back.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Certificate {
    pub name: Option<String>,
    pub ern: Option<String>,
    pub description: Option<String>,
    /// The certificate as PEM.
    pub certificate: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub serial_number: Option<String>,
    pub fingerprint: Option<String>,
    #[serde(deserialize_with = "text_list")]
    pub subject_alt_names: Vec<String>,
    /// Whether EKM generated it (self-signed) rather than it being imported.
    pub generated: bool,
    #[serde(deserialize_with = "lenient_string")]
    pub not_before: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub not_after: Option<String>,
    #[serde(deserialize_with = "text_map")]
    pub tags: BTreeMap<String, String>,
    #[serde(deserialize_with = "lenient_string")]
    pub created: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub modified: Option<String>,
}

/// Body of `create-certificate`: a self-signed certificate EKM generates, key pair included.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCertificateRequest {
    pub name: String,
    pub description: String,
    /// Subject CN; empty lets the server choose.
    pub common_name: String,
    pub subject_alt_names: Vec<String>,
    pub valid_days: u64,
    pub key_bits: u64,
}

impl Default for CreateCertificateRequest {
    /// 825 days, 2048-bit key, as euclid-jdk's builder.
    fn default() -> Self {
        Self {
            name: String::new(),
            description: String::new(),
            common_name: String::new(),
            subject_alt_names: Vec::new(),
            valid_days: 825,
            key_bits: 2048,
        }
    }
}

/// Body of `import-certificate`. `Debug` output redacts the private key.
#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportCertificateRequest {
    pub name: String,
    pub description: String,
    /// The certificate as PEM.
    pub certificate: String,
    /// Its private key as PEM.
    pub private_key: String,
}

impl fmt::Debug for ImportCertificateRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImportCertificateRequest")
            .field("name", &self.name)
            .field("description", &self.description)
            .field("certificate", &self.certificate)
            .field("private_key", &REDACTED)
            .finish()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListCertificatesResponse {
    pub certificates: Vec<Certificate>,
    #[serde(deserialize_with = "lenient_u64")]
    pub total: u64,
}

/// Answer to `delete-certificate`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DeleteCertificateResponse {
    pub ern: Option<String>,
    pub name: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------------------------

/// Bytes that must not end up in logs - a plaintext or ciphertext from `encrypt`/`decrypt`.
/// `Debug` prints only the length; [`Sensitive::expose`] or `into_inner` gets the bytes.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Sensitive(Vec<u8>);

impl Sensitive {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for Sensitive {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for Sensitive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sensitive(<redacted {} bytes>)", self.0.len())
    }
}
