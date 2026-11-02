//! Request and response types of the EAP (Euclid Application Platform) module.
//!
//! Field names are the wire names in camelCase. Requests leave out every field that is not set,
//! as euclid-jdk's non-null mapper does - on an update that means "keep the current value".
//! Responses default every field, so one the server leaves out reads as `None`/zero/empty.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::serde_util::{lenient_string, lenient_u64};

/// Reads a map whose values may be any scalar, as text - Jackson's `asText()` on each value.
fn lenient_string_map<'de, D: Deserializer<'de>>(d: D) -> Result<BTreeMap<String, String>, D::Error> {
    Ok(match Option::<Value>::deserialize(d)? {
        Some(Value::Object(map)) => map
            .into_iter()
            .map(|(k, v)| {
                let text = match v {
                    Value::String(s) => s,
                    Value::Null => String::new(),
                    other => other.to_string(),
                };
                (k, text)
            })
            .collect(),
        _ => BTreeMap::new(),
    })
}

/// Reads a list whose elements may be any scalar, as text.
fn lenient_string_list<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    Ok(match Option::<Value>::deserialize(d)? {
        Some(Value::Array(items)) => items
            .into_iter()
            .map(|v| match v {
                Value::String(s) => s,
                other => other.to_string(),
            })
            .collect(),
        _ => Vec::new(),
    })
}

/// Reads a string where an empty one means "none".
fn empty_as_none<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Ok(lenient_string(d)?.filter(|s| !s.is_empty()))
}

fn lenient_f64<'de, D: Deserializer<'de>>(d: D) -> Result<f64, D::Error> {
    Ok(match Option::<Value>::deserialize(d)? {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(Value::String(s)) => s.trim().parse().unwrap_or(0.0),
        _ => 0.0,
    })
}

fn lenient_bool<'de, D: Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
    Ok(match Option::<Value>::deserialize(d)? {
        Some(Value::Bool(b)) => b,
        Some(Value::String(s)) => s.eq_ignore_ascii_case("true"),
        _ => false,
    })
}

fn minus_one() -> i64 {
    -1
}

fn lenient_i64_or_minus_one<'de, D: Deserializer<'de>>(d: D) -> Result<i64, D::Error> {
    Ok(match Option::<Value>::deserialize(d)? {
        Some(Value::Number(n)) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)).unwrap_or(-1),
        Some(Value::String(s)) => s.trim().parse().unwrap_or(-1),
        _ => -1,
    })
}

/// Environment variables shown by name only: values often carry credentials.
struct RedactedEnv<'a>(&'a BTreeMap<String, String>);

impl fmt::Debug for RedactedEnv<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.0.keys().map(|k| (k, "<redacted>"))).finish()
    }
}

struct RedactedOptEnv<'a>(&'a Option<BTreeMap<String, String>>);

impl fmt::Debug for RedactedOptEnv<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(env) => write!(f, "Some({:?})", RedactedEnv(env)),
            None => f.write_str("None"),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Applications
// ---------------------------------------------------------------------------------------------

/// Whether an application runs continuously or as a scheduled run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ApplicationType {
    /// A long-running pool of processes.
    Process,
    /// A run on a schedule (`schedule`), started at `next_run_at`.
    Job,
    /// Absent, empty or a type this client does not know.
    #[default]
    Unknown,
}

impl ApplicationType {
    /// The wire spelling: `PROCESS`, `JOB` or `UNKNOWN`.
    pub fn wire_value(self) -> &'static str {
        match self {
            ApplicationType::Process => "PROCESS",
            ApplicationType::Job => "JOB",
            ApplicationType::Unknown => "UNKNOWN",
        }
    }

    /// Reads the wire spelling exactly (case-sensitive, as the JDK); anything else is `Unknown`.
    pub fn from_wire_value(value: &str) -> Self {
        match value {
            "PROCESS" => ApplicationType::Process,
            "JOB" => ApplicationType::Job,
            _ => ApplicationType::Unknown,
        }
    }

    pub fn is_job(self) -> bool {
        self == ApplicationType::Job
    }
}

impl<'de> Deserialize<'de> for ApplicationType {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(lenient_string(d)?
            .map(|s| ApplicationType::from_wire_value(&s))
            .unwrap_or_default())
    }
}

/// One running instance of an application, as far as the gateway reaches it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationEndpoint {
    #[serde(default, deserialize_with = "lenient_string")]
    pub instance_id: Option<String>,
    /// Process id, `-1` if unknown.
    #[serde(default = "minus_one", deserialize_with = "lenient_i64_or_minus_one")]
    pub pid: i64,
    /// Port the instance serves HTTP on, `0` for none.
    #[serde(default, deserialize_with = "lenient_u64")]
    pub http_port: u64,
}

/// An application: an artifact in an ESM bucket that euclid runs as a pool of processes.
///
/// `state` is what euclid-mgr's reconciler last observed and can lag `desired_state` briefly
/// after a start or stop. `Debug` output shows environment variable names only.
#[derive(Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Application {
    pub application_id: Option<String>,
    /// Installation-wide name euclid runs the application under.
    pub runtime_name: Option<String>,
    pub ern: Option<String>,
    pub account_id: Option<String>,
    pub namespace: Option<String>,
    pub region: Option<String>,
    pub runtime: Option<String>,
    pub bucket_ern: Option<String>,
    pub artifact_key: Option<String>,
    pub version: Option<String>,
    pub md5_sum: Option<String>,
    pub command: Option<String>,
    #[serde(deserialize_with = "lenient_string_list")]
    pub arguments: Vec<String>,
    #[serde(deserialize_with = "lenient_string_map")]
    pub environment: BTreeMap<String, String>,
    /// ERNs of the resources the application is granted.
    #[serde(deserialize_with = "lenient_string_list")]
    pub resources: Vec<String>,
    /// The principal the application runs as.
    pub user_id: Option<String>,
    #[serde(deserialize_with = "lenient_bool")]
    pub user_exists: bool,
    pub log_level: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub min_instances: u64,
    #[serde(deserialize_with = "lenient_u64")]
    pub max_instances: u64,
    #[serde(deserialize_with = "lenient_u64")]
    pub ready_timeout_ms: u64,
    #[serde(deserialize_with = "lenient_string_map")]
    pub node_labels: BTreeMap<String, String>,
    #[serde(rename = "type")]
    pub application_type: ApplicationType,
    /// Cron schedule of a JOB.
    pub schedule: Option<String>,
    /// When a JOB runs next; `None` when not scheduled.
    #[serde(deserialize_with = "empty_as_none")]
    pub next_run_at: Option<String>,
    /// `"RUNNING"` or `"STOPPED"` as last asked for.
    pub desired_state: Option<String>,
    pub state: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub instances: u64,
    pub endpoints: Vec<ApplicationEndpoint>,
    #[serde(deserialize_with = "lenient_string")]
    pub created: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub modified: Option<String>,
}

impl fmt::Debug for Application {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Application")
            .field("application_id", &self.application_id)
            .field("runtime_name", &self.runtime_name)
            .field("ern", &self.ern)
            .field("account_id", &self.account_id)
            .field("namespace", &self.namespace)
            .field("region", &self.region)
            .field("runtime", &self.runtime)
            .field("bucket_ern", &self.bucket_ern)
            .field("artifact_key", &self.artifact_key)
            .field("version", &self.version)
            .field("md5_sum", &self.md5_sum)
            .field("command", &self.command)
            .field("arguments", &self.arguments)
            .field("environment", &RedactedEnv(&self.environment))
            .field("resources", &self.resources)
            .field("user_id", &self.user_id)
            .field("user_exists", &self.user_exists)
            .field("log_level", &self.log_level)
            .field("min_instances", &self.min_instances)
            .field("max_instances", &self.max_instances)
            .field("ready_timeout_ms", &self.ready_timeout_ms)
            .field("node_labels", &self.node_labels)
            .field("application_type", &self.application_type)
            .field("schedule", &self.schedule)
            .field("next_run_at", &self.next_run_at)
            .field("desired_state", &self.desired_state)
            .field("state", &self.state)
            .field("instances", &self.instances)
            .field("endpoints", &self.endpoints)
            .field("created", &self.created)
            .field("modified", &self.modified)
            .finish()
    }
}

/// Body of `create-application`. Fields left `None` are not sent.
///
/// Everything named is resolved at once: a bucket, artifact, granted resource or user that does
/// not exist is a 404; an application id already used in the account and namespace is a 409.
/// Leaving `user` unset lets EAP mint a technical principal granted exactly `buckets` and
/// `queues`. `Debug` output shows environment variable names only.
#[derive(Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateApplicationRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    /// Name of the ESM bucket the artifact is in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    /// Key of the artifact within the bucket.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Command to run the artifact with; empty for the runtime default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<BTreeMap<String, String>>,
    /// Names of ESM buckets the application is granted access to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buckets: Option<Vec<String>>,
    /// Names of EQS queues the application is granted access to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queues: Option<Vec<String>>,
    /// An existing user to run as (it needs an access key); usually left unset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_instances: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_instances: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ready_timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_labels: Option<BTreeMap<String, String>>,
    /// `"PROCESS"` or `"JOB"` (see [`ApplicationType::wire_value`]).
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub application_type: Option<String>,
    /// Cron schedule of a JOB.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,
}

impl fmt::Debug for CreateApplicationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateApplicationRequest")
            .field("application_id", &self.application_id)
            .field("runtime", &self.runtime)
            .field("bucket", &self.bucket)
            .field("artifact", &self.artifact)
            .field("version", &self.version)
            .field("command", &self.command)
            .field("arguments", &self.arguments)
            .field("environment", &RedactedOptEnv(&self.environment))
            .field("buckets", &self.buckets)
            .field("queues", &self.queues)
            .field("user", &self.user)
            .field("min_instances", &self.min_instances)
            .field("max_instances", &self.max_instances)
            .field("ready_timeout_ms", &self.ready_timeout_ms)
            .field("node_labels", &self.node_labels)
            .field("application_type", &self.application_type)
            .field("schedule", &self.schedule)
            .finish()
    }
}

/// Body of `update-application`. Only fields that are `Some` change, and each replaces the stored
/// value as a whole (a list is substituted, not appended to). Changing `buckets` or `queues` also
/// rewrites the grants of an EAP-minted principal. `Debug` output shows environment variable
/// names only.
#[derive(Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateApplicationRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buckets: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queues: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_instances: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_instances: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ready_timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_labels: Option<BTreeMap<String, String>>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub application_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,
}

impl fmt::Debug for UpdateApplicationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpdateApplicationRequest")
            .field("application_id", &self.application_id)
            .field("runtime", &self.runtime)
            .field("artifact", &self.artifact)
            .field("version", &self.version)
            .field("command", &self.command)
            .field("arguments", &self.arguments)
            .field("environment", &RedactedOptEnv(&self.environment))
            .field("buckets", &self.buckets)
            .field("queues", &self.queues)
            .field("min_instances", &self.min_instances)
            .field("max_instances", &self.max_instances)
            .field("ready_timeout_ms", &self.ready_timeout_ms)
            .field("node_labels", &self.node_labels)
            .field("application_type", &self.application_type)
            .field("schedule", &self.schedule)
            .finish()
    }
}

/// Body of `copy-application`: define the same application again in another namespace (the
/// copy is created stopped, with its own runtime name and principal).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CopyApplicationRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_namespace: Option<String>,
    /// Id in the target namespace; the original's when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_application_id: Option<String>,
}

/// Body of `scale-application`. At least one bound is required; a floor of zero is refused
/// (stop the application instead).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScaleApplicationRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_instances: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_instances: Option<u64>,
}

/// Body of `redeploy-application`: make a new build (already uploaded to the application's
/// bucket) the deployed one. Refused unless both version and bytes differ from what is deployed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedeployApplicationRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Answer to `restart-application`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RestartApplicationResponse {
    pub application_id: Option<String>,
    #[serde(deserialize_with = "lenient_bool")]
    pub restarting: bool,
    #[serde(deserialize_with = "lenient_u64")]
    pub instances: u64,
}

/// Answer to `rebalance-application`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RebalanceApplicationResponse {
    pub application_id: Option<String>,
    #[serde(deserialize_with = "lenient_bool")]
    pub rebalancing: bool,
    #[serde(deserialize_with = "lenient_u64")]
    pub instances: u64,
}

/// Answer to `set-log-level`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SetLogLevelResponse {
    pub application_id: Option<String>,
    /// The level now in force; empty after a reset to the default.
    pub log_level: Option<String>,
    /// The log channel the level applies to.
    pub channel: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// Infrastructure and platforms
// ---------------------------------------------------------------------------------------------

/// A resource whose declared settings were brought into line.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UpdatedResource {
    pub ern: Option<String>,
    #[serde(deserialize_with = "lenient_string_list")]
    pub changes: Vec<String>,
}

/// A resource the declaration no longer names but that was kept - because it is not empty.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct KeptResource {
    pub ern: Option<String>,
    pub reason: Option<String>,
}

/// What applying (or, with `dry_run`, planning) an infrastructure declaration did. The lists hold
/// ERNs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ApplyInfrastructureResponse {
    pub application_id: Option<String>,
    pub platform: Option<String>,
    /// Whether a declaration was found at all.
    #[serde(deserialize_with = "lenient_bool")]
    pub declared: bool,
    /// A plan: nothing was changed.
    #[serde(deserialize_with = "lenient_bool")]
    pub dry_run: bool,
    #[serde(deserialize_with = "lenient_string_list")]
    pub created: Vec<String>,
    #[serde(deserialize_with = "lenient_string_list")]
    pub adopted: Vec<String>,
    pub updated: Vec<UpdatedResource>,
    #[serde(deserialize_with = "lenient_string_list")]
    pub deleted: Vec<String>,
    pub kept: Vec<KeptResource>,
    #[serde(deserialize_with = "lenient_string_list")]
    pub granted: Vec<String>,
    #[serde(deserialize_with = "lenient_string_list")]
    pub revoked: Vec<String>,
}

/// A platform: shared infrastructure declared once for a namespace.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Platform {
    pub name: Option<String>,
    pub namespace: Option<String>,
    /// ERNs of the resources the platform owns.
    #[serde(deserialize_with = "lenient_string_list")]
    pub owns: Vec<String>,
    /// The stored declaration, as JSON; `None` if there is none.
    pub declaration: Option<Value>,
    #[serde(deserialize_with = "lenient_string")]
    pub modified: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// Nodes
// ---------------------------------------------------------------------------------------------

/// What one node is running of one application.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct NodeApplication {
    pub application_id: Option<String>,
    pub runtime_name: Option<String>,
    pub namespace: Option<String>,
    pub runtime: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub instances: u64,
    #[serde(deserialize_with = "lenient_u64")]
    pub running: u64,
}

/// A node applications run on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Node {
    pub name: Option<String>,
    pub address: Option<String>,
    pub principal: Option<String>,
    #[serde(deserialize_with = "lenient_string_map")]
    pub labels: BTreeMap<String, String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub cpu_count: u64,
    pub version: Option<String>,
    pub os: Option<String>,
    pub arch: Option<String>,
    #[serde(deserialize_with = "lenient_bool")]
    pub drained: bool,
    #[serde(deserialize_with = "lenient_bool")]
    pub live: bool,
    #[serde(deserialize_with = "lenient_string")]
    pub last_seen: Option<String>,
    /// What the node runs - `None` in a listing, which does not report it (rather than an empty
    /// list, which would read as "running nothing"); filled in by `get-node`.
    pub applications: Option<Vec<NodeApplication>>,
}

/// Answer to `list-nodes`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListNodesResponse {
    pub nodes: Vec<Node>,
    pub total: u64,
}

// ---------------------------------------------------------------------------------------------
// Egress
// ---------------------------------------------------------------------------------------------

/// Limits on an application's calls to one outside site, for all its instances together.
#[derive(Debug, Clone, Copy, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EgressLimits {
    #[serde(deserialize_with = "lenient_f64")]
    pub requests_per_second: f64,
    #[serde(deserialize_with = "lenient_f64")]
    pub burst: f64,
    #[serde(deserialize_with = "lenient_u64")]
    pub concurrent: u64,
}

/// One site an application calls, with its limits and current use.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EgressSite {
    pub application_id: Option<String>,
    pub site: Option<String>,
    pub limits: EgressLimits,
    /// Whether `limits` were set for this site rather than being the defaults.
    #[serde(deserialize_with = "lenient_bool")]
    pub limits_set: bool,
    #[serde(deserialize_with = "lenient_f64")]
    pub tokens: f64,
    #[serde(deserialize_with = "lenient_u64")]
    pub in_flight: u64,
    /// Until when the site is left alone after it refused a request; `None` if not blocked.
    #[serde(deserialize_with = "empty_as_none")]
    pub blocked_until: Option<String>,
    #[serde(deserialize_with = "empty_as_none")]
    pub last_used: Option<String>,
}

/// Answer to `list-egress-sites`.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListEgressSitesResponse {
    /// Limits applying to a site that has none of its own.
    pub default_limits: EgressLimits,
    pub sites: Vec<EgressSite>,
}

/// Answer to `set-egress-limit` / `delete-egress-limit`.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EgressLimitResponse {
    pub application_id: Option<String>,
    pub site: Option<String>,
    pub limits: EgressLimits,
}

/// Answer to `acquire-egress-permit`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EgressPermitResponse {
    pub site: Option<String>,
    #[serde(deserialize_with = "lenient_bool")]
    pub granted: bool,
    /// Present when granted; release it when the request is done.
    pub permit_id: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub expires_at: Option<String>,
    /// Why a refusal: `blocked`, `concurrency` or `rate`.
    pub reason: Option<String>,
    /// When to ask again, after a refusal.
    #[serde(deserialize_with = "lenient_u64")]
    pub retry_after_ms: u64,
}
