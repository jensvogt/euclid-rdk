//! EMM - Euclid Module Manager.
//!
//! The process pools of every euclid module - their limits, desired state and log levels - and
//! the backup, export and import of the installation's data.
//!
//! The control actions record desired state rather than acting directly: the manager picks up
//! what was recorded on its next reconcile, within a few seconds. So an answer describes the pool
//! as it stood when the request was answered, not after the change has been carried out.

pub mod model;

use std::time::Duration;

pub use model::*;
use serde_json::{json, Map, Value};

use crate::service::{CallOptions, ServiceClient};
use crate::{Error, Result};

/// How long an export or import may take: they move whole collections, not a single resource.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(300);

/// EMM operations, obtained from [`Session::emm`](crate::Session::emm).
///
/// Every EMM action is administrator-only server-side: a non-admin session gets 403 from all of
/// them. Requests are SigV4-signed with the session's access key when it has one, otherwise
/// authenticated with the bearer token. Cloning is cheap.
#[derive(Debug, Clone)]
pub struct Emm {
    client: ServiceClient,
}

impl Emm {
    pub(crate) fn new(client: ServiceClient) -> Self {
        Self { client }
    }

    // -------------------------------------------------------------------------------------------
    // Modules
    // -------------------------------------------------------------------------------------------

    /// Lists every module the manager runs, with its pool of instances.
    pub async fn list_modules(&self) -> Result<ListModulesResponse> {
        self.client.call("list-modules", &json!({})).await
    }

    /// Starts a stopped euclid module. Only core modules can be started here (400 for an
    /// application or a transfer server - use EAP or ETS); 404 for an unknown name.
    pub async fn start_module(&self, name: &str) -> Result<ModuleStoppedResponse> {
        self.client.call("start-module", &json!({ "name": name })).await
    }

    /// Stops a euclid module and keeps it stopped. Only core modules can be stopped here, and
    /// `emm` itself cannot be.
    pub async fn stop_module(&self, name: &str) -> Result<ModuleStoppedResponse> {
        self.client.call("stop-module", &json!({ "name": name })).await
    }

    /// Cycles a module's instances one per reconcile tick. Refused with 400 for a stopped module.
    pub async fn restart_module(&self, name: &str) -> Result<RestartModuleResponse> {
        self.client.call("restart-module", &json!({ "name": name })).await
    }

    /// Sets both instance limits of a module.
    pub async fn set_instances(
        &self,
        name: &str,
        min_instances: u32,
        max_instances: u32,
    ) -> Result<SetInstancesResponse> {
        self.set_instances_with(&SetInstancesRequest {
            name: name.into(),
            min_instances: Some(min_instances),
            max_instances: Some(max_instances),
        })
        .await
    }

    /// Sets the instance limits the autoscaler works within; a limit left `None` stays as it is.
    /// The pair can never be left crossed: a floor above the ceiling is refused with 400.
    pub async fn set_instances_with(&self, request: &SetInstancesRequest) -> Result<SetInstancesResponse> {
        self.client.call("set-instances", request).await
    }

    /// Sets a module's worker thread count (1..=256). Applied by cycling the instances, since a
    /// thread count is fixed when a process starts.
    pub async fn set_threads(&self, name: &str, threads: u32) -> Result<SetThreadsResponse> {
        self.client
            .call("set-threads", &json!({ "name": name, "threads": threads }))
            .await
    }

    /// Sets the level a module's own output is logged at - `"trace"`, `"debug"`, `"info"`,
    /// `"warning"`, `"error"`, `"fatal"` or `"off"`. An empty level or `"default"` puts the module
    /// back on the configured level. Applied without a restart.
    pub async fn set_log_level(&self, name: &str, level: &str) -> Result<SetLogLevelResponse> {
        let level = if level == "default" { "" } else { level };
        self.client
            .call("set-log-level", &json!({ "name": name, "level": level }))
            .await
    }

    // -------------------------------------------------------------------------------------------
    // Backups
    // -------------------------------------------------------------------------------------------

    /// Lists the archives in the backup directory, and how the nightly backup is set up.
    pub async fn list_backups(&self) -> Result<ListBackupsResponse> {
        self.client.call("list-backups", &json!({})).await
    }

    /// Starts a backup now, exactly as the nightly run would write it. It runs in the background:
    /// [`list_backups`](Self::list_backups) shows the archive incomplete until it is done. 409 if a
    /// backup is already running.
    ///
    /// `full` overrides the configured choice for this one backup; it is dropped when the backup
    /// is encrypted.
    pub async fn create_backup(&self, full: Option<bool>) -> Result<CreateBackupResponse> {
        let body = match full {
            Some(full) => json!({ "full": full }),
            None => json!({}),
        };
        self.client.call("create-backup", &body).await
    }

    // -------------------------------------------------------------------------------------------
    // Export and import
    // -------------------------------------------------------------------------------------------

    /// Exports the named modules' data unencrypted and returns the export document.
    pub async fn export(&self, modules: &[&str]) -> Result<String> {
        self.export_with(&ExportRequest {
            modules: modules.iter().map(|m| (*m).to_owned()).collect(),
            ..Default::default()
        })
        .await
    }

    /// Exports module data and returns the export document, ready to be stored and later passed
    /// to [`import`](Self::import).
    ///
    /// With a passphrase the export is sealed: one request per named module (or one for `all`),
    /// sharing one salt, assembled into one document whose `frames` hold the encrypted data - the
    /// same file euclid-cli and euclid-jdk write. [`Error::InvalidArgument`] without sending
    /// anything unless exactly one of `all` and `modules` is given.
    pub async fn export_with(&self, request: &ExportRequest) -> Result<String> {
        if request.all == !request.modules.is_empty() {
            return Err(Error::invalid("exactly one of all or modules is required"));
        }
        let options = transfer_options();
        let passphrase = request.passphrase.as_deref().unwrap_or_default();
        if passphrase.is_empty() {
            let body = export_body(request.all, &request.modules, request.full);
            let response = self
                .client
                .send_ok("export", serde_json::to_vec(&body)?, &options)
                .await?;
            return Ok(response.text());
        }

        let batches: Vec<Vec<String>> = if request.all {
            vec![Vec::new()]
        } else {
            request.modules.iter().map(|m| vec![m.clone()]).collect()
        };
        let mut frames = Vec::new();
        let mut exported = Vec::new();
        let mut envelope: Option<Map<String, Value>> = None;
        let mut salt: Option<String> = None;
        for modules in &batches {
            let mut body = export_body(request.all, modules, request.full);
            body.insert("passphrase".into(), passphrase.into());
            if let Some(salt) = &salt {
                body.insert("salt".into(), salt.clone().into());
            }
            let response = self.client.call_value_with("export", &body, &options).await?;
            frames.push(response.get("data").cloned().unwrap_or(Value::Null));
            // Which modules the archive holds is the server's answer: with `all` none were named.
            if let Some(Value::Array(names)) = response.get("modules") {
                exported.extend(names.iter().cloned());
            }
            if salt.is_none() {
                salt = Some(match response.get("salt") {
                    Some(Value::String(s)) => s.clone(),
                    _ => String::new(),
                });
                envelope = match response {
                    Value::Object(map) => Some(map),
                    _ => Some(Map::new()),
                };
            }
        }
        let mut envelope = envelope.unwrap_or_default();
        envelope.remove("data");
        envelope.insert("modules".into(), Value::Array(exported));
        envelope.insert("frames".into(), Value::Array(frames));
        Ok(serde_json::to_string(&envelope)?)
    }

    /// Imports an unencrypted export document, every collection it holds.
    pub async fn import(&self, document: &str) -> Result<ImportResponse> {
        self.import_with(&ImportRequest {
            document: document.into(),
            ..Default::default()
        })
        .await
    }

    /// Imports an export document, optionally restricted to some modules' collections.
    ///
    /// A sealed document needs the passphrase it was exported with; a plain one must not be given
    /// one. Either mistake - or a document that is not an export at all - is an
    /// [`Error::InvalidArgument`] without sending anything. Collections the server does not know
    /// are skipped and reported, not written.
    pub async fn import_with(&self, request: &ImportRequest) -> Result<ImportResponse> {
        let mut document = match serde_json::from_str::<Value>(&request.document) {
            Ok(Value::Object(map)) => map,
            Ok(_) => return Err(Error::invalid("the document is not a JSON object - not an emm export?")),
            Err(e) => return Err(Error::invalid(format!("the document is not valid JSON: {e}"))),
        };
        let sealed = document.contains_key("frames");
        if !sealed && !document.contains_key("collections") {
            return Err(Error::invalid(
                "the document has neither a \"collections\" object nor \"frames\" - not an emm export?",
            ));
        }
        let passphrase = request.passphrase.as_deref().unwrap_or_default();
        if sealed {
            if passphrase.is_empty() {
                return Err(Error::invalid(
                    "the document is encrypted - a passphrase is required to open it",
                ));
            }
            document.insert("passphrase".into(), passphrase.into());
        } else if !passphrase.is_empty() {
            return Err(Error::invalid(
                "the document is not encrypted - no passphrase is needed",
            ));
        }
        if !request.modules.is_empty() {
            document.insert("modules".into(), json!(request.modules));
        }
        let answer = self
            .client
            .call_value_with("import", &document, &transfer_options())
            .await?;
        Ok(serde_json::from_value(answer)?)
    }
}

fn transfer_options() -> CallOptions {
    CallOptions {
        timeout: Some(TRANSFER_TIMEOUT),
        ..Default::default()
    }
}

fn export_body(all: bool, modules: &[String], full: bool) -> Map<String, Value> {
    let mut body = Map::new();
    body.insert("full".into(), full.into());
    if all {
        body.insert("all".into(), true.into());
    } else {
        body.insert("modules".into(), json!(modules));
    }
    body
}
