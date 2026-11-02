//! Request and response types of the ESM (Euclid Storage Manager) module.
//!
//! Field names are the wire names in camelCase. Response types default every field, so a field
//! the server leaves out reads as `None`/zero/empty instead of failing the whole response.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::eam::SortDirection;
use crate::serde_util::{lenient_string, lenient_u64};

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
    pub attributes: Attributes,
    #[serde(deserialize_with = "lenient_string")]
    pub created: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub modified: Option<String>,
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

/// Part size, concurrency and attributes for [`Esm::upload_file`](super::Esm::upload_file) and
/// friends. Defaults: 5 MiB parts, 4 in flight, no attributes.
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
}

impl Default for TransferOptions {
    fn default() -> Self {
        Self {
            part_size: 5 * 1024 * 1024,
            concurrency: 4,
            attributes: Attributes::new(),
            system_attributes: Attributes::new(),
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
