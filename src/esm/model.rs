//! Request and response types of the ESM (Euclid Storage Manager) module.
//!
//! Field names are the wire names in camelCase. Response types default every field, so a field
//! the server leaves out reads as `None`/zero/empty instead of failing the whole response.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::eam::SortDirection;
use crate::serde_util::{default_true, lenient_string, lenient_u64};

// ---------------------------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------------------------

pub use crate::variant::Variant;

/// Object attributes by name, as `x-euclid-attributes` / `x-euclid-system-attributes` carry them.
pub type Attributes = BTreeMap<String, Variant>;

// ---------------------------------------------------------------------------------------------
// Buckets
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Bucket {
    pub owner: Option<String>,
    pub name: Option<String>,
    pub ern: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub size: u64,
    #[serde(deserialize_with = "lenient_u64")]
    pub objects: u64,
    #[serde(deserialize_with = "lenient_u64")]
    pub directories: u64,
    pub tags: BTreeMap<String, String>,
    pub encrypted: bool,
    pub encryption_key_ern: Option<String>,
    pub internal: bool,
    pub priority: Option<String>,
    pub stopped: bool,
    /// Whether the bucket keeps earlier versions of an object when it is overwritten.
    pub versioning: bool,
    /// Non-current versions kept per key; 0 keeps every version.
    #[serde(deserialize_with = "lenient_u64")]
    pub max_versions: u64,
    #[serde(deserialize_with = "lenient_string")]
    pub created: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub modified: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CreateBucketResponse {
    pub name: Option<String>,
    pub ern: Option<String>,
}

/// Answer to `delete-bucket`. An inline delete answers with no body, so everything is empty;
/// a background delete reports the job.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DeleteBucketResponse {
    pub ern: Option<String>,
    /// Objects removed (or to be removed), from the answer's `objects`.
    #[serde(rename = "objects", deserialize_with = "lenient_u64")]
    pub count: u64,
    pub job_id: Option<String>,
    #[serde(rename = "async")]
    pub is_async: bool,
}

/// Paging and sorting for `list-buckets`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListBucketsRequest {
    pub prefix: String,
    pub page_size: u64,
    pub page_index: u64,
    pub sort_column: String,
    pub sort_direction: SortDirection,
}

impl Default for ListBucketsRequest {
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

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListBucketsResponse {
    pub buckets: Vec<Bucket>,
    #[serde(deserialize_with = "lenient_u64")]
    pub total: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GetBucketSizeResponse {
    pub ern: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub size: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RenameBucketResponse {
    pub name: Option<String>,
    pub ern: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub objects: u64,
    #[serde(deserialize_with = "lenient_u64")]
    pub subscriptions: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SetBucketInternalResponse {
    pub ern: Option<String>,
    pub name: Option<String>,
    pub internal: bool,
}

/// Answer to `stop-bucket` / `start-bucket`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct BucketStoppedResponse {
    pub ern: Option<String>,
    pub name: Option<String>,
    pub stopped: bool,
    /// Events held back while stopped.
    #[serde(deserialize_with = "lenient_u64")]
    pub held: u64,
    /// Held events released on start.
    #[serde(deserialize_with = "lenient_u64")]
    pub released: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SetBucketPriorityResponse {
    pub ern: Option<String>,
    pub name: Option<String>,
    pub priority: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EnableEncryptionResponse {
    pub ern: Option<String>,
    pub name: Option<String>,
    pub key_ern: Option<String>,
    pub key_id: Option<String>,
    pub algorithm: Option<String>,
    /// Whether the server created a new key because none was named.
    pub key_created: bool,
    /// Objects already in the bucket, which stay unencrypted.
    #[serde(deserialize_with = "lenient_u64")]
    pub existing_objects: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DisableEncryptionResponse {
    pub ern: Option<String>,
    pub name: Option<String>,
    pub previous_key_ern: Option<String>,
    pub previous_key_id: Option<String>,
    /// Objects that stay encrypted with the previous key.
    #[serde(deserialize_with = "lenient_u64")]
    pub encrypted_objects: u64,
}

/// Answer to `set-bucket-versioning`: the bucket's versioning settings as they are now.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SetBucketVersioningResponse {
    pub ern: Option<String>,
    pub name: Option<String>,
    pub versioning: bool,
    /// Non-current versions kept per key; 0 keeps every version.
    #[serde(deserialize_with = "lenient_u64")]
    pub max_versions: u64,
}

/// A bucket lifecycle rule: objects under `prefix` not read for `archive_after_days` days are
/// archived; a restored object stays online for `restore_days` days.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleRule {
    /// Unique within the bucket.
    #[serde(default)]
    pub id: String,
    /// Keys the rule covers; empty for all.
    #[serde(default)]
    pub prefix: String,
    #[serde(default, deserialize_with = "lenient_u64")]
    pub archive_after_days: u64,
    #[serde(default, deserialize_with = "lenient_u64")]
    pub restore_days: u64,
    /// A disabled rule is kept but archives nothing. Defaults to `true` when absent.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl LifecycleRule {
    /// An enabled rule.
    pub fn new(id: impl Into<String>, prefix: impl Into<String>, archive_after_days: u64, restore_days: u64) -> Self {
        Self {
            id: id.into(),
            prefix: prefix.into(),
            archive_after_days,
            restore_days,
            enabled: true,
        }
    }
}

/// Answer to `set-bucket-lifecycle`, `get-bucket-lifecycle` and `delete-bucket-lifecycle`: the
/// bucket's rules as they are now (empty when it has none).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct BucketLifecycleResponse {
    pub ern: Option<String>,
    pub name: Option<String>,
    pub rules: Vec<LifecycleRule>,
}

/// Answer to `purge-bucket`: `count` is the number of objects purged inline, or taken on by a
/// background job (`is_async`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PurgeBucketResponse {
    pub ern: Option<String>,
    pub count: u64,
    pub job_id: Option<String>,
    pub is_async: bool,
}

// ---------------------------------------------------------------------------------------------
// Objects
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EsmObject {
    pub ern: Option<String>,
    pub bucket_ern: Option<String>,
    pub key: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub size: u64,
    pub status: Option<String>,
    pub content_type: Option<String>,
    pub md5_sum: Option<String>,
    /// The current version, in a bucket with versioning on; empty otherwise.
    pub version_id: Option<String>,
    pub encrypted: bool,
    pub attributes: Attributes,
    #[serde(deserialize_with = "lenient_string")]
    pub created: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub modified: Option<String>,
    /// When the object was last read, which is what lifecycle rules go by.
    #[serde(deserialize_with = "lenient_string")]
    pub last_accessed: Option<String>,
    /// `"STANDARD"` or `"ARCHIVED"`.
    pub lifecycle_state: Option<String>,
    /// Until when a restored object stays online before it is archived again.
    #[serde(deserialize_with = "lenient_string")]
    pub restored_until: Option<String>,
}

/// One version of an object, as `list-object-versions` lists it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ObjectVersion {
    pub version_id: Option<String>,
    /// Whether this is the current version, the one the key reads as.
    pub latest: bool,
    #[serde(deserialize_with = "lenient_u64")]
    pub size: u64,
    pub md5_sum: Option<String>,
    pub content_type: Option<String>,
    pub status: Option<String>,
    pub lifecycle_state: Option<String>,
    pub owner: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub modified: Option<String>,
}

/// Answer to `list-object-versions`: the current version first, then the older ones.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListObjectVersionsResponse {
    pub bucket_ern: Option<String>,
    pub key: Option<String>,
    pub ern: Option<String>,
    pub versioning: bool,
    /// Non-current versions the bucket keeps per key; 0 keeps every version.
    #[serde(deserialize_with = "lenient_u64")]
    pub max_versions: u64,
    pub versions: Vec<ObjectVersion>,
    #[serde(deserialize_with = "lenient_u64")]
    pub total: u64,
}

/// Answer to a `delete-object` naming a version.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DeleteObjectVersionResponse {
    pub ern: Option<String>,
    /// The version deleted.
    pub version_id: Option<String>,
    /// The version the key reads as now; empty if the key has no current object.
    pub current_version_id: Option<String>,
}

/// Answer to `archive-object` and `restore-object`: the object's lifecycle state now.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ObjectLifecycleResponse {
    pub ern: Option<String>,
    pub bucket_ern: Option<String>,
    pub key: Option<String>,
    /// `"STANDARD"` or `"ARCHIVED"`.
    pub lifecycle_state: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub archived_at: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub restored_at: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub restored_until: Option<String>,
    pub archive_file: Option<String>,
}

/// An object whose file does not match its record, as `verify-objects` reports it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ObjectProblem {
    pub key: Option<String>,
    pub ern: Option<String>,
    /// What is wrong: `"missing"`, `"empty"`, `"short"`, `"long"`, `"mismatch"` (an encrypted
    /// file whose header records another length) or `"unreadable"`.
    pub problem: Option<String>,
    /// Size on the object's record.
    #[serde(deserialize_with = "lenient_u64")]
    pub recorded_size: u64,
    /// Size of the file on disk.
    #[serde(deserialize_with = "lenient_u64")]
    pub file_size: u64,
    /// Size the file should have, given the record (larger for an encrypted object).
    #[serde(deserialize_with = "lenient_u64")]
    pub expected_file_size: u64,
    pub internal_name: Option<String>,
    pub internal_dir: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub created: Option<String>,
    /// More on the problem, for `"mismatch"` and `"unreadable"`.
    pub detail: Option<String>,
}

/// Answer to `verify-objects`: one page of a bucket checked in key order. Pass `next_key` as the
/// next call's `after_key`; it is empty once the end of the bucket was reached.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VerifyObjectsResponse {
    pub bucket_ern: Option<String>,
    pub after_key: Option<String>,
    /// Objects looked at on this page.
    #[serde(deserialize_with = "lenient_u64")]
    pub scanned: u64,
    /// Objects whose file was checked.
    #[serde(deserialize_with = "lenient_u64")]
    pub checked: u64,
    /// Directories, incomplete and archived objects, which have no file to check.
    #[serde(deserialize_with = "lenient_u64")]
    pub skipped: u64,
    pub problems: Vec<ObjectProblem>,
    pub next_key: Option<String>,
}

/// Paging, sorting and filtering for `list-objects`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListObjectsRequest {
    pub bucket_ern: String,
    pub prefix: String,
    pub page_size: u64,
    pub page_index: u64,
    pub sort_column: String,
    pub sort_direction: SortDirection,
    pub include_directories: bool,
}

impl Default for ListObjectsRequest {
    fn default() -> Self {
        Self {
            bucket_ern: String::new(),
            prefix: String::new(),
            page_size: 10,
            page_index: 0,
            sort_column: "name".into(),
            sort_direction: SortDirection::Asc,
            include_directories: false,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListObjectsResponse {
    pub objects: Vec<EsmObject>,
    #[serde(deserialize_with = "lenient_u64")]
    pub total: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DeleteObjectsResponse {
    pub ern: Option<String>,
    /// Keys asked to be deleted.
    #[serde(deserialize_with = "lenient_u64")]
    pub asked: u64,
    /// Objects actually deleted (or taken on, when `is_async`).
    #[serde(deserialize_with = "lenient_u64")]
    pub objects: u64,
    #[serde(rename = "async")]
    pub is_async: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TouchObjectResponse {
    pub ern: Option<String>,
    pub bucket_name: Option<String>,
    pub prefix: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub objects: u64,
    #[serde(rename = "async")]
    pub is_async: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GetObjectCountResponse {
    pub ern: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub count: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GetObjectSizeResponse {
    pub ern: Option<String>,
    pub bucket_ern: Option<String>,
    pub key: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub size: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CountObjectsResponse {
    pub ern: Option<String>,
    pub prefix: Option<String>,
    pub include_directories: bool,
    #[serde(deserialize_with = "lenient_u64")]
    pub count: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ObjectAttributeResponse {
    pub ern: Option<String>,
    pub name: Option<String>,
    pub value: Option<Variant>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListObjectAttributesResponse {
    pub ern: Option<String>,
    pub attributes: Attributes,
    #[serde(deserialize_with = "lenient_u64")]
    pub total: u64,
}

// ---------------------------------------------------------------------------------------------
// Uploads and downloads
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CreateUploadResponse {
    pub upload_id: Option<String>,
    pub bucket_ern: Option<String>,
    pub key: Option<String>,
}

/// Answer to `put-object` and `complete-upload`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CompleteUploadResponse {
    pub ern: Option<String>,
    pub bucket_ern: Option<String>,
    pub key: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub size: u64,
    pub status: Option<String>,
    pub content_type: Option<String>,
    pub md5_sum: Option<String>,
    /// The version the upload became, in a bucket with versioning on; empty otherwise. For an
    /// unchanged upload, the version that already held these bytes.
    pub version_id: Option<String>,
    /// True when the bucket has versioning on and the bytes were the ones the key already held:
    /// nothing was stored, and the answer describes the object that was there.
    pub unchanged: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AbortUploadResponse {
    pub upload_id: Option<String>,
    pub bucket_ern: Option<String>,
    pub key: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub parts: u64,
    pub object_removed: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CreateDownloadResponse {
    pub download_id: Option<String>,
    pub bucket_ern: Option<String>,
    pub key: Option<String>,
    pub ern: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub size: u64,
    pub content_type: Option<String>,
}

/// Part size, concurrency, attributes and version for [`Esm::upload_file`](super::Esm::upload_file)
/// and friends. Defaults: 5 MiB parts, 4 in flight, no attributes, the current version.
#[derive(Debug, Clone)]
pub struct TransferOptions {
    /// Bytes per part. A file smaller than this goes up whole in one `put-object`; an object
    /// smaller than this comes down whole in one `get-object`.
    pub part_size: usize,
    /// Parts in flight at once (at least 1).
    pub concurrency: usize,
    /// Sent as `x-euclid-attributes` with the upload.
    pub attributes: Attributes,
    /// Sent as `x-euclid-system-attributes` with the upload.
    pub system_attributes: Attributes,
    /// For [`Esm::download_file`](super::Esm::download_file): a non-current version to download
    /// instead of the current one. Ignored by uploads and by
    /// [`Esm::download_bucket`](super::Esm::download_bucket), which always reads current versions.
    pub version_id: Option<String>,
}

impl Default for TransferOptions {
    fn default() -> Self {
        Self {
            part_size: 5 * 1024 * 1024,
            concurrency: 4,
            attributes: Attributes::new(),
            system_attributes: Attributes::new(),
            version_id: None,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Subscriptions and events
// ---------------------------------------------------------------------------------------------

/// Body of `subscribe`: deliver a bucket's events to a target (e.g. an EQS queue).
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscribeRequest {
    /// The bucket ERN.
    pub source_ern: String,
    /// Delivery type, e.g. `"EQS"`.
    #[serde(rename = "type")]
    pub kind: String,
    pub target_ern: String,
    /// Event types to deliver; empty means all.
    pub event_types: Vec<String>,
    /// Only keys under this prefix; empty means all.
    pub prefix: String,
    /// Also deliver directory events.
    pub directories: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SubscribeResponse {
    pub ern: Option<String>,
    pub source_ern: Option<String>,
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub target_ern: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Subscription {
    pub ern: Option<String>,
    pub source_ern: Option<String>,
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub target_ern: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub created: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub modified: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListSubscriptionsResponse {
    pub subscriptions: Vec<Subscription>,
    #[serde(deserialize_with = "lenient_u64")]
    pub total: u64,
}

/// A bucket event as delivered to a subscription target, e.g. the body of an EQS message.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct BucketEvent {
    pub event_type: Option<String>,
    pub bucket_ern: Option<String>,
    pub key: Option<String>,
    pub ern: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub size: u64,
    pub content_type: Option<String>,
    pub md5_sum: Option<String>,
}

impl BucketEvent {
    /// Parses a delivered message body.
    pub fn parse(message_body: &str) -> crate::Result<Self> {
        Ok(serde_json::from_str(message_body)?)
    }
}
