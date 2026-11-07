//! Request and response types of the EMM (Euclid Module Manager) module.
//!
//! Field names are the wire names in camelCase. Response types default every field, so a field
//! the server leaves out reads as `None`/zero instead of failing the whole response. Where the
//! server uses `-1` for "unknown" or "nothing pending", the field is signed and defaults to `-1`.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use crate::serde_util::{lenient_string, lenient_u64};

const REDACTED: &str = "<redacted>";

/// Reads a signed integer; anything that is not a number reads as `-1` ("unknown").
fn signed<'de, D: Deserializer<'de>>(d: D) -> Result<i64, D::Error> {
    Ok(match Option::<serde_json::Value>::deserialize(d)? {
        Some(serde_json::Value::Number(n)) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)).unwrap_or(-1),
        Some(serde_json::Value::String(s)) => s.trim().parse().unwrap_or(-1),
        _ => -1,
    })
}

/// Reads a floating-point number; anything that is not a number reads as `-1.0` ("unknown").
fn float<'de, D: Deserializer<'de>>(d: D) -> Result<f64, D::Error> {
    Ok(match Option::<serde_json::Value>::deserialize(d)? {
        Some(serde_json::Value::Number(n)) => n.as_f64().unwrap_or(-1.0),
        Some(serde_json::Value::String(s)) => s.trim().parse().unwrap_or(-1.0),
        _ => -1.0,
    })
}

/// Reads a bool; anything else is `false`.
fn flag<'de, D: Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
    Ok(matches!(
        Option::<serde_json::Value>::deserialize(d)?,
        Some(serde_json::Value::Bool(true))
    ))
}

// -----------------------------------------------------------------------------------------------
// Modules
// -----------------------------------------------------------------------------------------------

/// One process slot of a module's pool.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ModuleInstance {
    pub instance_id: Option<String>,
    /// The process id; `-1` when unknown.
    #[serde(deserialize_with = "signed")]
    pub pid: i64,
    /// The machine the process runs on; empty on a single-host installation.
    #[serde(deserialize_with = "lenient_string")]
    pub host: Option<String>,
    /// The slot's state as the manager reports it, e.g. `"RUNNING"`.
    #[serde(deserialize_with = "lenient_string")]
    pub state: Option<String>,
    pub socket_path: Option<String>,
    /// The port of the instance's own HTTP listener; 0 for a module that has none.
    #[serde(deserialize_with = "lenient_u64")]
    pub http_port: u64,
    #[serde(deserialize_with = "lenient_u64")]
    pub restart_count: u64,
    /// The load the instance last reported, 0..1; `-1` if it never reported one.
    #[serde(deserialize_with = "float")]
    pub utilisation: f64,
    /// Work waiting at the instance's last report; `-1` if it never reported one.
    #[serde(deserialize_with = "signed")]
    pub backlog: i64,
    /// When the load was last reported; empty if never.
    #[serde(deserialize_with = "lenient_string")]
    pub load_reported_at: Option<String>,
    /// Work no request is waiting on (an async purge, say); scale-down passes over such instances.
    #[serde(deserialize_with = "lenient_u64")]
    pub background_tasks: u64,
    /// When the running process started - what uptime counts from; empty if nothing runs.
    #[serde(deserialize_with = "lenient_string")]
    pub started: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub created: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub modified: Option<String>,
}

impl Default for ModuleInstance {
    fn default() -> Self {
        Self {
            instance_id: None,
            pid: -1,
            host: None,
            state: None,
            socket_path: None,
            http_port: 0,
            restart_count: 0,
            utilisation: -1.0,
            backlog: -1,
            load_reported_at: None,
            background_tasks: 0,
            started: None,
            created: None,
            modified: None,
        }
    }
}

/// A module the manager runs, with its limits, desired state and process pool.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ManagedModule {
    pub name: Option<String>,
    pub executable: Option<String>,
    pub socket_path: Option<String>,
    #[serde(deserialize_with = "flag")]
    pub active: bool,
    /// Whether this is a euclid module proper. Only those can be started and stopped through EMM;
    /// applications and transfer servers belong to EAP and ETS.
    #[serde(deserialize_with = "flag")]
    pub core: bool,
    /// Whether the module was stopped through `stop-module`.
    #[serde(deserialize_with = "flag")]
    pub desired_stopped: bool,
    #[serde(deserialize_with = "flag")]
    pub auto_restart: bool,
    #[serde(deserialize_with = "signed")]
    pub max_restarts: i64,
    #[serde(deserialize_with = "signed")]
    pub min_instances: i64,
    #[serde(deserialize_with = "signed")]
    pub max_instances: i64,
    /// A floor set through `set-instances` and not yet reconciled; `-1` for nothing pending.
    #[serde(deserialize_with = "signed")]
    pub desired_min_instances: i64,
    /// A ceiling set through `set-instances` and not yet reconciled; `-1` for nothing pending.
    #[serde(deserialize_with = "signed")]
    pub desired_max_instances: i64,
    /// A thread count set through `set-threads` and not yet reconciled; `-1` for nothing pending.
    #[serde(deserialize_with = "signed")]
    pub desired_threads: i64,
    /// The level set through `set-log-level`; empty for the configured default.
    #[serde(deserialize_with = "lenient_string")]
    pub log_level: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub created: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub modified: Option<String>,
    /// When the module was last started; `None` if never.
    #[serde(deserialize_with = "lenient_string")]
    pub last_start_time: Option<String>,
    pub instances: Vec<ModuleInstance>,
}

impl Default for ManagedModule {
    fn default() -> Self {
        Self {
            name: None,
            executable: None,
            socket_path: None,
            active: false,
            core: false,
            desired_stopped: false,
            auto_restart: false,
            max_restarts: -1,
            min_instances: 0,
            max_instances: 0,
            desired_min_instances: -1,
            desired_max_instances: -1,
            desired_threads: -1,
            log_level: None,
            created: None,
            modified: None,
            last_start_time: None,
            instances: Vec::new(),
        }
    }
}

/// Answer to `list-modules`.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListModulesResponse {
    pub modules: Vec<ManagedModule>,
    #[serde(deserialize_with = "lenient_u64")]
    pub total: u64,
}

/// Body of `set-instances`: only the limits that are `Some` change - at least one is required.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetInstancesRequest {
    pub name: String,
    /// The floor; 0 lets the module scale away entirely when idle.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_instances: Option<u32>,
    /// The ceiling; at least 1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_instances: Option<u32>,
}

/// Answer to `set-instances`: the limits now in force, and the pool as it stands before the
/// manager has reconciled toward them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SetInstancesResponse {
    pub name: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub min_instances: u64,
    #[serde(deserialize_with = "lenient_u64")]
    pub max_instances: u64,
    #[serde(deserialize_with = "lenient_u64")]
    pub running_instances: u64,
}

/// Answer to `set-threads`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SetThreadsResponse {
    pub name: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub threads: u64,
    /// How many instances still have to be cycled before all run with the new count.
    #[serde(deserialize_with = "lenient_u64")]
    pub running_instances: u64,
}

/// Answer to `set-log-level`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SetLogLevelResponse {
    /// The module, in the spelling the server matched (names are lower case).
    pub name: Option<String>,
    /// The canonical level now set; empty when the module is back on the configured default.
    pub log_level: Option<String>,
    /// The log channel the level applies to, e.g. `"module.esm"`.
    pub channel: Option<String>,
}

/// Answer to `stop-module` and `start-module`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ModuleStoppedResponse {
    pub name: Option<String>,
    /// The desired state now recorded.
    #[serde(deserialize_with = "flag")]
    pub stopped: bool,
    /// The pool before the manager has acted on the change.
    #[serde(deserialize_with = "lenient_u64")]
    pub running_instances: u64,
}

/// Answer to `restart-module`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RestartModuleResponse {
    pub name: Option<String>,
    /// How many instances the manager will cycle through, one per reconcile tick.
    #[serde(deserialize_with = "lenient_u64")]
    pub running_instances: u64,
}

// -----------------------------------------------------------------------------------------------
// Backups
// -----------------------------------------------------------------------------------------------

/// One archive in the backup directory.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct BackupFile {
    pub name: Option<String>,
    pub path: Option<String>,
    /// The account the archive holds; empty for the installation-wide one.
    pub account_id: Option<String>,
    /// The namespace the archive holds; empty for an account's own or the installation-wide one.
    pub namespace: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub started_at: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub modified: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub size: u64,
    /// `false` while the archive is being written, or for one whose backup was interrupted.
    #[serde(deserialize_with = "flag")]
    pub complete: bool,
}

/// Answer to `list-backups`: the configured backup and what it has written.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListBackupsResponse {
    /// The backup directory on the host EMM runs on.
    pub directory: Option<String>,
    #[serde(deserialize_with = "flag")]
    pub enabled: bool,
    /// The cron expression of the nightly backup, evaluated in UTC.
    pub schedule: Option<String>,
    /// How many archives are retained.
    #[serde(deserialize_with = "lenient_u64")]
    pub keep: u64,
    /// Whether the next backup includes messages and objects (never when encrypted).
    #[serde(deserialize_with = "flag")]
    pub full: bool,
    #[serde(deserialize_with = "flag")]
    pub encrypted: bool,
    pub backups: Vec<BackupFile>,
}

/// Answer to `create-backup`: the archive that is being written in the background.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CreateBackupResponse {
    /// The archive's file name - the same in every scope's directory.
    pub name: Option<String>,
    pub directory: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub started_at: Option<String>,
    #[serde(deserialize_with = "flag")]
    pub full: bool,
    #[serde(deserialize_with = "flag")]
    pub encrypted: bool,
}

// -----------------------------------------------------------------------------------------------
// Export and import
// -----------------------------------------------------------------------------------------------

/// What [`Emm::export_with`](super::Emm::export_with) exports.
///
/// Exactly one of `all` and `modules` must be given. Exporting `ekm` - alone or through `all` -
/// requires a passphrase, because it carries the key material itself.
#[derive(Clone, Default)]
pub struct ExportRequest {
    /// The modules to export, e.g. `["esm", "eqs"]`.
    pub modules: Vec<String>,
    /// Export every module.
    pub all: bool,
    /// Include messages and objects, not just the top-level resources.
    pub full: bool,
    /// Seals the export: each module's data is encrypted under a key derived from it.
    pub passphrase: Option<String>,
}

impl fmt::Debug for ExportRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExportRequest")
            .field("modules", &self.modules)
            .field("all", &self.all)
            .field("full", &self.full)
            .field("passphrase", &self.passphrase.as_ref().map(|_| REDACTED))
            .finish()
    }
}

/// What [`Emm::import_with`](super::Emm::import_with) imports.
#[derive(Clone, Default)]
pub struct ImportRequest {
    /// An export document as [`Emm::export`](super::Emm::export) returned it.
    pub document: String,
    /// Only import the collections of these modules; empty for everything the document holds.
    pub modules: Vec<String>,
    /// The passphrase a sealed document was exported with. Required for one, refused for a plain
    /// one.
    pub passphrase: Option<String>,
}

impl fmt::Debug for ImportRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImportRequest")
            .field("document", &format_args!("<{} bytes>", self.document.len()))
            .field("modules", &self.modules)
            .field("passphrase", &self.passphrase.as_ref().map(|_| REDACTED))
            .finish()
    }
}

/// How one collection fared in an import.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ImportedCollection {
    #[serde(deserialize_with = "lenient_u64")]
    pub imported: u64,
    #[serde(deserialize_with = "lenient_u64")]
    pub failed: u64,
}

/// A collection the import left alone, and why.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SkippedCollection {
    pub collection: Option<String>,
    pub reason: Option<String>,
}

/// Answer to `import`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ImportResponse {
    /// Per collection name, how many documents were written.
    pub imported: BTreeMap<String, ImportedCollection>,
    pub skipped: Vec<SkippedCollection>,
}
