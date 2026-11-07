//! Request and response types of the ETS (Euclid Transfer Service) module.
//!
//! Field names are the wire names in camelCase. Requests leave out every field that is not set -
//! the server keeps its default (create) or the current value (update) for those. Responses
//! default every field, so one the server leaves out reads as `None`/zero/empty.

use serde::{Deserialize, Serialize};

use crate::serde_util::{lenient_string, lenient_u64};

/// Transfer protocol of a server.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Protocol {
    Ftp,
    #[default]
    Sftp,
}

/// An FTP or SFTP listener fronting an ESM bucket. Clients authenticate with their EAM
/// credentials and are admitted if `user_ids` names them or they belong to one of `user_groups`;
/// whatever they upload becomes an object in the bucket.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TransferServer {
    /// Name identifying the server, unique within its account and namespace.
    pub server_id: Option<String>,
    /// Installation-wide name euclid runs the server under: what to look for in a module list,
    /// `ps` output or a log channel.
    pub runtime_name: Option<String>,
    pub ern: Option<String>,
    pub account_id: Option<String>,
    /// Empty for a server at the account root.
    pub namespace: Option<String>,
    pub region: Option<String>,
    /// `"FTP"` or `"SFTP"`.
    pub protocol: Option<String>,
    /// Address the server binds to.
    pub address: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub port: u64,
    pub bucket_name: Option<String>,
    pub bucket_ern: Option<String>,
    /// Key prefix template each session is rooted at (`{user}` = the EAM user ID), or empty for
    /// the bucket root.
    pub home_directory: Option<String>,
    /// EAM user IDs allowed to log in.
    pub user_ids: Vec<String>,
    /// EAM user groups whose members may log in.
    pub user_groups: Vec<String>,
    /// How many people may log in: the union of `user_ids` and the members of `user_groups`,
    /// each counted once (a group that does not exist admits nobody). 0 from a server that
    /// predates the figure.
    #[serde(deserialize_with = "lenient_u64")]
    pub user_count: u64,
    /// Directories every session finds under its home, created at login.
    pub directories: Vec<String>,
    /// `"RUNNING"` or `"STOPPED"` as last asked for.
    pub desired_state: Option<String>,
    /// The state euclid-mgr's reconciler last observed; can lag `desired_state` briefly.
    pub state: Option<String>,
    /// SFTP only: path of the private SSH host key file.
    pub host_key: Option<String>,
    /// FTP only: lowest passive data port.
    #[serde(deserialize_with = "lenient_u64")]
    pub pasv_min: u64,
    /// FTP only: highest passive data port.
    #[serde(deserialize_with = "lenient_u64")]
    pub pasv_max: u64,
    #[serde(deserialize_with = "lenient_string")]
    pub created: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub modified: Option<String>,
}

/// Body of `create-server`. At least one of `user_ids` and `user_groups` is required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateServerRequest {
    pub server_id: String,
    pub protocol: Protocol,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u64>,
    /// Name of the ESM bucket to front, resolved when the server is defined (404 if none matches).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    /// Address to bind to; `0.0.0.0` by default.
    pub address: String,
    /// Key prefix template, e.g. `"{user}"`, or empty for the bucket root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home_directory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_groups: Option<Vec<String>>,
    /// Paths relative to the home prefix, created at login.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub directories: Option<Vec<String>>,
    /// SFTP only: private SSH host key file, generated on first start if absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_key: Option<String>,
    /// FTP only: lowest passive data port; the server defaults to 6000.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pasv_min: Option<u64>,
    /// FTP only: highest passive data port; the server defaults to 6100.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pasv_max: Option<u64>,
}

impl Default for CreateServerRequest {
    fn default() -> Self {
        Self {
            server_id: String::new(),
            protocol: Protocol::Sftp,
            port: None,
            bucket: None,
            address: "0.0.0.0".into(),
            home_directory: None,
            user_ids: None,
            user_groups: None,
            directories: None,
            host_key: None,
            pasv_min: None,
            pasv_max: None,
        }
    }
}

/// Body of `update-server`. Only the fields that are set are sent, and each one replaces the
/// current value outright - `user_ids` substitutes the whole access list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateServerRequest {
    pub server_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home_directory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_groups: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub directories: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pasv_min: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pasv_max: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct ListServersResponse {
    pub servers: Vec<TransferServer>,
}
