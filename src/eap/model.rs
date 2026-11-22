//! Request and response types of the EAP (Euclid Application Platform) module.
//!
//! Field names are the wire names in camelCase. Requests leave out every field that is not set,
//! as euclid-jdk's non-null mapper does - on an update that means "keep the current value".
//! Responses default every field, so one the server leaves out reads as `None`/zero/empty.

use crate::MatchType;
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

/// Reads an embedded infrastructure report: `None` unless the field is a JSON object.
fn lenient_infrastructure<'de, D: Deserializer<'de>>(d: D) -> Result<Option<ApplyInfrastructureResponse>, D::Error> {
    match Option::<Value>::deserialize(d)? {
        Some(v @ Value::Object(_)) => serde_json::from_value(v).map(Some).map_err(serde::de::Error::custom),
        _ => Ok(None),
    }
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
    /// How the artifact is executed: `"JAVA"`, `"JAVA21"`, `"JAVA25"`, `"PYTHON"`, `"NODEJS"`,
    /// `"BINARY"` or `"RUST"`.
    pub runtime: Option<String>,
    pub bucket_ern: Option<String>,
    pub artifact_key: Option<String>,
    pub version: Option<String>,
    pub md5_sum: Option<String>,
    /// Size of the deployed artifact in bytes; `0` for one deployed before this was recorded.
    #[serde(deserialize_with = "lenient_u64")]
    pub artifact_size: u64,
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
    /// Memory each instance may use, in MiB; `0` for no limit.
    #[serde(deserialize_with = "lenient_u64")]
    pub memory_limit_mb: u64,
    /// CPU each instance may use, in cores; `0.0` for no limit.
    #[serde(deserialize_with = "lenient_f64")]
    pub cpu_limit: f64,
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
    /// What applying the application's own infrastructure declaration did as part of the
    /// deployment. Only [`create_application`](crate::Eap::create_application) answers with it -
    /// `None` from every other action. A declaration that cannot be applied never fails a
    /// deployment whose artifact is fine, so check [`ApplyInfrastructureResponse::error`] rather
    /// than assuming a created application also got the resources it declared.
    #[serde(deserialize_with = "lenient_infrastructure")]
    pub infrastructure: Option<ApplyInfrastructureResponse>,
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
            .field("artifact_size", &self.artifact_size)
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
            .field("memory_limit_mb", &self.memory_limit_mb)
            .field("cpu_limit", &self.cpu_limit)
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
            .field("infrastructure", &self.infrastructure)
            .finish()
    }
}

/// Body of `create-application`. Fields left `None` are not sent.
///
/// Everything named is resolved at once: a bucket, artifact, granted resource or user that does
/// not exist is a 404; an application id already used in the account and namespace is a 409.
/// Leaving `user` unset lets EAP mint a technical principal granted exactly `buckets`, `queues`,
/// `topics` and `secrets`. `Debug` output shows environment variable names only.
#[derive(Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateApplicationRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    /// How the artifact is executed: `"JAVA"`, `"JAVA21"`, `"JAVA25"`, `"PYTHON"`, `"NODEJS"`,
    /// `"BINARY"` or `"RUST"`.
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
    /// Names of ENS topics the application is granted access to, resolved now in the namespace
    /// deployed into: a topic that does not exist is a 404 here rather than a refused publish later.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topics: Option<Vec<String>>,
    /// Names of ESS secrets the application is granted access to. Resolved now, so a missing
    /// secret is a deployment refused with 404 naming it rather than a crash in the application's
    /// startup.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Vec<String>>,
    /// An existing user to run as (it needs an access key); usually left unset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_instances: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_instances: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ready_timeout_ms: Option<u64>,
    /// Memory each instance may use, in MiB: `0` for no limit, otherwise at least 64. The
    /// account's nodes have to be able to hold `min_instances` instances at this limit, or the
    /// deployment is refused with 409 - checked now, though the application is created stopped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_limit_mb: Option<u64>,
    /// CPU each instance may use, in cores (e.g. `1.5`): `0` for no limit, otherwise at least
    /// 0.01. Over it an instance is throttled, never stopped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_limit: Option<f64>,
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
            .field("topics", &self.topics)
            .field("secrets", &self.secrets)
            .field("user", &self.user)
            .field("min_instances", &self.min_instances)
            .field("max_instances", &self.max_instances)
            .field("ready_timeout_ms", &self.ready_timeout_ms)
            .field("memory_limit_mb", &self.memory_limit_mb)
            .field("cpu_limit", &self.cpu_limit)
            .field("node_labels", &self.node_labels)
            .field("application_type", &self.application_type)
            .field("schedule", &self.schedule)
            .finish()
    }
}

/// Body of `update-application`. Only fields that are `Some` change, and each replaces the stored
/// value as a whole (a list is substituted, not appended to). `Debug` output shows environment
/// variable names only.
///
/// The four resource lists - `buckets`, `queues`, `topics` and `secrets` - are one setting, not
/// four: setting *any* of them replaces the application's whole resource list with what the four
/// together name, so a request setting only `buckets` takes away its queues, topics and secrets.
/// Send all four together when changing one. Doing so also rewrites the grants of an EAP-minted
/// principal (a user named at creation is the caller's to grant).
#[derive(Clone, Default, PartialEq, Serialize)]
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
    /// Names of ENS topics the application may reach, replacing the current grants (see above).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topics: Option<Vec<String>>,
    /// Names of ESS secrets the application may reach, replacing the current grants (see above).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Vec<String>>,
    /// Moves the application to this namespace, `Some("")` for the account root - so empty and
    /// `None` mean different things here. A move, not a copy: its row, ERN and the grants of an
    /// EAP-minted principal follow it, and it stops running where it was. Refused with 409 if the
    /// target already has an application of this name; use
    /// [`copy_application`](crate::Eap::copy_application) to leave the original running.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// An existing user with an access key for the application to run as instead - the way out
    /// of a definition whose user was deleted (see [`Application::user_exists`]). A principal EAP
    /// had minted is deleted with its grants. Cannot be emptied: `""` is refused with 400.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_instances: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_instances: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ready_timeout_ms: Option<u64>,
    /// Memory each instance may use, in MiB: `0` removes the limit, otherwise at least 64.
    /// Through this request the change restarts the pool;
    /// [`set_application_limits`](crate::Eap::set_application_limits) sets it without a restart.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_limit_mb: Option<u64>,
    /// CPU each instance may use, in cores: `0` removes the limit, otherwise at least 0.01.
    /// Restarts the pool, as `memory_limit_mb` does.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_limit: Option<f64>,
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
            .field("topics", &self.topics)
            .field("secrets", &self.secrets)
            .field("namespace", &self.namespace)
            .field("user", &self.user)
            .field("min_instances", &self.min_instances)
            .field("max_instances", &self.max_instances)
            .field("ready_timeout_ms", &self.ready_timeout_ms)
            .field("memory_limit_mb", &self.memory_limit_mb)
            .field("cpu_limit", &self.cpu_limit)
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

/// Body of `set-application-limits`: an application's per-instance resource limits. A limit left
/// `None` is not sent and stays as it is (the server would refuse one sent as `null`); at least
/// one has to be set. `0` removes a limit.
///
/// The limits reach instances as they start - restart the application to give them to running
/// ones. Over its memory limit an instance is killed by the kernel (`OOM_KILLED`); over its CPU
/// limit it is only throttled.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetApplicationLimitsRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    /// Memory each instance may use, in MiB: `0` for no limit, otherwise at least 64. Raising it
    /// is refused with 409 if the account's nodes cannot hold the application's floor at that size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_limit_mb: Option<u64>,
    /// CPU each instance may use, in cores (e.g. `0.5`): `0` for no limit, otherwise at least 0.01.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_limit: Option<f64>,
}

/// Body of `redeploy-application`: make a new build (already uploaded, and settled, in the
/// application's bucket) the deployed one.
///
/// Refused with 409 when the artifact's bytes are the build already deployed - the artifact, not
/// its version, decides, so the same version rebuilt goes through. `force` overrides that, and so
/// does an artifact whose bytes are missing from storage. An artifact still being uploaded is
/// also a 409; one not in the bucket is a 404.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedeployApplicationRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    /// Key of the artifact; the one the application already uses when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact: Option<String>,
    /// Version this build is - recorded, not checked; read from the artifact's name when `None`
    /// (and refused if the name carries none).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// `Some(true)` deploys even an artifact that is byte for byte the build already deployed
    /// (the server logs that it overrode). [`restart_application`](crate::Eap::restart_application)
    /// is the better tool when nothing about the artifact needs fixing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force: Option<bool>,
}

/// Body of `list-applications`: the applications of the session's namespace whose id matches
/// `prefix` the way `match_type` says.
///
/// Every match type but `"regex"` treats the text as a literal, so `"a.b"` does not also find
/// `"aXb"`. An unknown match type, or a regular expression that does not compile, is refused
/// with 400.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListApplicationsRequest {
    /// The search text; empty lists every application. Only a prefix under the default match type.
    pub prefix: String,
    /// How `prefix` is matched; `None` is not sent and means [`MatchType::Prefix`], as every
    /// listing did before the field existed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_type: Option<MatchType>,
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
    /// Why the declaration could not be read or applied; `None` if it was. Only ever set on the
    /// report embedded in [`Application::infrastructure`] by `create-application`, which never
    /// refuses a deployment over its declaration: the infrastructure and platform actions refuse
    /// with 400 instead.
    #[serde(deserialize_with = "empty_as_none")]
    pub error: Option<String>,
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
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Node {
    pub name: Option<String>,
    pub address: Option<String>,
    pub principal: Option<String>,
    #[serde(deserialize_with = "lenient_string_map")]
    pub labels: BTreeMap<String, String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub cpu_count: u64,
    /// Memory the node offers applications, in MiB - less than it has installed.
    #[serde(deserialize_with = "lenient_u64")]
    pub memory_mb: u64,
    /// Installed memory, in MiB; `0` for a node that has not said.
    #[serde(deserialize_with = "lenient_u64")]
    pub memory_total_mb: u64,
    /// Memory in use at the node's last renewal, in MiB; `0` for a node that has not said.
    #[serde(deserialize_with = "lenient_u64")]
    pub memory_used_mb: u64,
    /// One-minute load average from the node's last heartbeat. `0.0` both for an idle machine and
    /// for a heartbeat that carried no reading - placement does not tell them apart either.
    #[serde(deserialize_with = "lenient_f64")]
    pub load_average: f64,
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
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ListNodesResponse {
    pub nodes: Vec<Node>,
    pub total: u64,
}

/// Answer to `drain-node`. Nothing has moved yet when this is answered: a drained node keeps
/// running what it has and keeps renewing; it is only refused *new* assignments.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DrainNodeResponse {
    pub node: Option<String>,
    /// `true` if the node is now refused new assignments, `false` if it was put back into service.
    #[serde(deserialize_with = "lenient_bool")]
    pub drained: bool,
}

/// Body of `assign-instance`: give one instance slot of an application's pool to a worker node by
/// hand. Slots are named the way the manager names them - by the pool (the application's
/// [`runtime_name`](Application::runtime_name), not its id) and the instance id.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssignInstanceRequest {
    /// The pool the slot belongs to - the application's runtime name. Required.
    pub runtime_name: String,
    /// The slot to assign, as an endpoint reports it. Required.
    pub instance_id: String,
    /// The registered, undrained node to give it to; empty takes the slot back to the manager's
    /// own host, which is how an assignment is undone. Always sent.
    pub node: String,
}

/// Answer to `assign-instance`: which slot went where, and until when the claim holds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AssignInstanceResponse {
    pub runtime_name: Option<String>,
    pub instance_id: Option<String>,
    /// The node it now belongs to; empty if it was taken back to the manager's own host.
    pub node: Option<String>,
    /// When the claim lapses unless the node renews it (ISO 8601); a node that does not renew in
    /// time loses the slot to placement.
    #[serde(deserialize_with = "lenient_string")]
    pub lease_expires_at: Option<String>,
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

/// Reads embedded egress limits: `None` unless the field is a JSON object - all-zero limits would
/// read as "nothing is allowed", which is not what an older EAP that sent none meant.
fn optional_limits<'de, D: Deserializer<'de>>(d: D) -> Result<Option<EgressLimits>, D::Error> {
    match Option::<Value>::deserialize(d)? {
        Some(v @ Value::Object(_)) => serde_json::from_value(v).map(Some).map_err(serde::de::Error::custom),
        _ => Ok(None),
    }
}

/// Answer to `acquire-egress-permit`.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EgressPermitResponse {
    /// The application the permit was asked for, as euclid resolved it.
    pub application_id: Option<String>,
    /// The site, as euclid stores it (lower-cased host).
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
    /// The limits the decision was made under - the site's own, the application's `"*"` default,
    /// or the installation's - sent with every answer, granted or not. `None` only from an EAP too
    /// old to send them.
    #[serde(deserialize_with = "optional_limits")]
    pub limits: Option<EgressLimits>,
}

/// Answer to `report-egress-throttled`: until when every instance of the application now leaves
/// the site alone. Worth reading rather than assuming `now + retry_after`: euclid caps one report
/// at an hour, floors it at a second, and keeps a block that already ran longer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EgressThrottledResponse {
    pub application_id: Option<String>,
    /// The site, as euclid stores it (lower-cased host).
    pub site: Option<String>,
    /// Until when no permit for the site is granted (ISO 8601).
    #[serde(deserialize_with = "empty_as_none")]
    pub blocked_until: Option<String>,
}
