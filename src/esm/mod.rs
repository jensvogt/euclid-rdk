//! ESM - Euclid Storage Manager (object storage).
//!
//! JSON operations (buckets, listings, tags, attributes, subscriptions) are SigV4-signed with the
//! session's access key when it has one. Object bytes - `put-object`, `get-object`, the parts of
//! a multipart upload or download - always travel with the bearer token, as in euclid-cli and
//! euclid-jdk: those bodies are opaque bytes the CLI never signs.

pub mod model;
mod transfer;

use std::time::Duration;

pub use model::*;
use serde_json::{json, Value};

use crate::service::ServiceClient;
use crate::{Error, Result};

/// Timeout for a request carrying object bytes, where the default 10 s is too short for a
/// multi-megabyte part on a slow link.
pub const DEFAULT_TRANSFER_TIMEOUT: Duration = Duration::from_secs(120);

/// ESM operations, obtained from [`Session::esm`](crate::Session::esm).
///
/// Requests are SigV4-signed with the session's access key when it has one, otherwise
/// authenticated with the bearer token. Cloning is cheap.
#[derive(Debug, Clone)]
pub struct Esm {
    client: ServiceClient,
    transfer_timeout: Duration,
}

impl Esm {
    pub(crate) fn new(client: ServiceClient) -> Self {
        Self {
            client,
            transfer_timeout: DEFAULT_TRANSFER_TIMEOUT,
        }
    }

    /// Timeout for each request that carries object bytes (default
    /// [`DEFAULT_TRANSFER_TIMEOUT`]). JSON operations keep the client's default.
    pub fn with_transfer_timeout(mut self, timeout: Duration) -> Self {
        self.transfer_timeout = timeout;
        self
    }

    // -----------------------------------------------------------------------------------------
    // Buckets
    // -----------------------------------------------------------------------------------------

    /// Creates a bucket. `priority` (e.g. `"HIGH"`) is left to the server's default when `None`.
    pub async fn create_bucket(&self, name: &str, priority: Option<&str>) -> Result<CreateBucketResponse> {
        let mut body = json!({ "name": name });
        if let Some(p) = priority.filter(|p| !p.is_empty()) {
            body["priority"] = json!(p);
        }
        self.client.call("create-bucket", &body).await
    }

    /// Deletes a bucket and everything in it. With `run_async`, the server takes the deletion on
    /// as a background job and answers at once with its id.
    pub async fn delete_bucket(&self, ern: &str, run_async: bool) -> Result<DeleteBucketResponse> {
        let value = self
            .client
            .call_value("delete-bucket", &json!({ "ern": ern, "async": run_async }))
            .await?;
        // An inline delete answers 200 with no body at all.
        if value.is_null() {
            return Ok(DeleteBucketResponse::default());
        }
        Ok(serde_json::from_value(value)?)
    }

    pub async fn list_buckets(&self, request: &ListBucketsRequest) -> Result<ListBucketsResponse> {
        self.client.call("list-buckets", request).await
    }

    /// The ERN of the bucket called `name`.
    pub async fn get_bucket_ern(&self, name: &str) -> Result<String> {
        self.client
            .call_field::<Option<String>>("get-bucket-ern", &json!({ "name": name }), "ern")
            .await
            .map(Option::unwrap_or_default)
    }

    /// Whether a bucket called `name` exists: `false` on 404, any other failure is an error.
    pub async fn exists_bucket(&self, name: &str) -> Result<bool> {
        match self.get_bucket_ern(name).await {
            Ok(_) => Ok(true),
            Err(Error::Service { status: 404, .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Reads one bucket by name, or by ERN if `name_or_ern` starts with `ern:`.
    pub async fn get_bucket(&self, name_or_ern: &str) -> Result<Bucket> {
        let body = if name_or_ern.starts_with("ern:") {
            json!({ "ern": name_or_ern, "name": null })
        } else {
            json!({ "ern": null, "name": name_or_ern })
        };
        self.client.call_field("get-bucket", &body, "bucket").await
    }

    pub async fn get_bucket_size(&self, ern: &str) -> Result<GetBucketSizeResponse> {
        self.client.call("get-bucket-size", &json!({ "ern": ern })).await
    }

    pub async fn rename_bucket(&self, ern: &str, new_name: &str) -> Result<RenameBucketResponse> {
        self.client
            .call("rename-bucket", &json!({ "ern": ern, "newName": new_name }))
            .await
    }

    /// Marks a bucket internal (hidden from ordinary listings) or not.
    pub async fn set_bucket_internal(&self, ern: &str, internal: bool) -> Result<SetBucketInternalResponse> {
        self.client
            .call("set-bucket-internal", &json!({ "ern": ern, "internal": internal }))
            .await
    }

    /// Takes a bucket out of service: its events are held rather than delivered until
    /// [`start_bucket`](Self::start_bucket).
    pub async fn stop_bucket(&self, ern: &str) -> Result<BucketStoppedResponse> {
        self.client.call("stop-bucket", &json!({ "ern": ern })).await
    }

    /// Puts a stopped bucket back into service, releasing what was held.
    pub async fn start_bucket(&self, ern: &str) -> Result<BucketStoppedResponse> {
        self.client.call("start-bucket", &json!({ "ern": ern })).await
    }

    pub async fn set_bucket_priority(&self, ern: &str, priority: &str) -> Result<SetBucketPriorityResponse> {
        self.client
            .call("set-bucket-priority", &json!({ "ern": ern, "priority": priority }))
            .await
    }

    /// Encrypts objects written to the bucket from now on, with the EKM key `key_id`, or with a
    /// key the server creates when `None`. Objects already there stay as they are.
    pub async fn enable_encryption(&self, bucket_ern: &str, key_id: Option<&str>) -> Result<EnableEncryptionResponse> {
        let body = json!({ "bucketErn": bucket_ern, "keyId": key_id.unwrap_or_default() });
        self.client.call("enable-encryption", &body).await
    }

    pub async fn disable_encryption(&self, bucket_ern: &str) -> Result<DisableEncryptionResponse> {
        self.client
            .call("disable-encryption", &json!({ "bucketErn": bucket_ern }))
            .await
    }

    /// Deletes every object in the bucket under `prefix` (empty for all), keeping the bucket.
    pub async fn purge_bucket(&self, ern: &str, prefix: &str, run_async: bool) -> Result<PurgeBucketResponse> {
        let root = self
            .client
            .call_value(
                "purge-bucket",
                &json!({ "ern": ern, "prefix": prefix, "async": run_async }),
            )
            .await?;
        // "count" when the purge ran inline, "objects" when it was taken on.
        let count = root
            .get("count")
            .and_then(Value::as_u64)
            .or_else(|| root.get("objects").and_then(Value::as_u64))
            .unwrap_or(0);
        Ok(PurgeBucketResponse {
            ern: root.get("ern").and_then(Value::as_str).map(str::to_owned),
            count,
            job_id: root.get("jobId").and_then(Value::as_str).map(str::to_owned),
            is_async: root.get("async").and_then(Value::as_bool).unwrap_or(false),
        })
    }

    pub async fn add_bucket_tag(&self, bucket_ern: &str, key: &str, value: &str) -> Result<()> {
        let body = json!({ "ern": bucket_ern, "key": key, "value": value });
        self.client.call_unit("add-bucket-tag", &body).await
    }

    pub async fn set_bucket_tag(&self, bucket_ern: &str, key: &str, value: &str) -> Result<()> {
        let body = json!({ "ern": bucket_ern, "key": key, "value": value });
        self.client.call_unit("set-bucket-tag", &body).await
    }

    pub async fn delete_bucket_tag(&self, bucket_ern: &str, key: &str) -> Result<()> {
        self.client
            .call_unit("delete-bucket-tag", &json!({ "ern": bucket_ern, "key": key }))
            .await
    }

    // -----------------------------------------------------------------------------------------
    // Objects
    // -----------------------------------------------------------------------------------------

    pub async fn list_objects(&self, request: &ListObjectsRequest) -> Result<ListObjectsResponse> {
        self.client.call("list-objects", request).await
    }

    /// Every object under `prefix`, paging through `list-objects` 1000 at a time in key order.
    pub async fn list_all_objects(&self, bucket_ern: &str, prefix: &str) -> Result<Vec<EsmObject>> {
        const PAGE: u64 = 1000;
        let mut objects = Vec::new();
        for page_index in 0.. {
            let listed = self
                .list_objects(&ListObjectsRequest {
                    bucket_ern: bucket_ern.into(),
                    prefix: prefix.into(),
                    page_size: PAGE,
                    page_index,
                    sort_column: "key".into(),
                    ..Default::default()
                })
                .await?;
            let n = listed.objects.len() as u64;
            objects.extend(listed.objects);
            if n < PAGE {
                break;
            }
        }
        Ok(objects)
    }

    /// Deletes one object by its ERN.
    pub async fn delete_object(&self, ern: &str) -> Result<()> {
        self.client.call_unit("delete-object", &json!({ "ern": ern })).await
    }

    /// Deletes the objects with these keys from a bucket.
    pub async fn delete_objects<I, S>(
        &self,
        bucket_ern: &str,
        keys: I,
        run_async: bool,
    ) -> Result<DeleteObjectsResponse>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let keys: Vec<String> = keys.into_iter().map(Into::into).collect();
        let body = json!({ "ern": bucket_ern, "keys": keys, "async": run_async });
        self.client.call("delete-objects", &body).await
    }

    /// Re-announces the objects under `prefix` (empty for all) to the bucket's subscribers, as
    /// though they had just been written.
    pub async fn touch_object(&self, bucket_ern: &str, prefix: &str, run_async: bool) -> Result<TouchObjectResponse> {
        let body = json!({ "ern": bucket_ern, "prefix": prefix, "async": run_async });
        self.client.call("touch-object", &body).await
    }

    pub async fn copy_object(
        &self,
        source_bucket_ern: &str,
        source_key: &str,
        target_bucket_ern: &str,
        target_key: &str,
    ) -> Result<EsmObject> {
        self.transfer_object(
            "copy-object",
            source_bucket_ern,
            source_key,
            target_bucket_ern,
            target_key,
        )
        .await
    }

    /// Copies an object and removes the source.
    pub async fn move_object(
        &self,
        source_bucket_ern: &str,
        source_key: &str,
        target_bucket_ern: &str,
        target_key: &str,
    ) -> Result<EsmObject> {
        self.transfer_object(
            "move-object",
            source_bucket_ern,
            source_key,
            target_bucket_ern,
            target_key,
        )
        .await
    }

    async fn transfer_object(
        &self,
        action: &str,
        source_bucket_ern: &str,
        source_key: &str,
        target_bucket_ern: &str,
        target_key: &str,
    ) -> Result<EsmObject> {
        let body = json!({
            "sourceBucketErn": source_bucket_ern,
            "sourceKey": source_key,
            "targetBucketErn": target_bucket_ern,
            "targetKey": target_key,
        });
        self.client.call(action, &body).await
    }

    /// Renames an object within its bucket.
    pub async fn rename_object(&self, bucket_ern: &str, key: &str, new_key: &str) -> Result<EsmObject> {
        let body = json!({ "bucketErn": bucket_ern, "key": key, "newKey": new_key });
        self.client.call("rename-object", &body).await
    }

    pub async fn get_object_count(&self, bucket_ern: &str) -> Result<GetObjectCountResponse> {
        self.client
            .call("get-object-count", &json!({ "ern": bucket_ern, "prefix": "" }))
            .await
    }

    /// Counts the objects under `prefix` (empty for all), optionally counting directories too.
    pub async fn count_objects(
        &self,
        bucket_ern: &str,
        prefix: &str,
        include_directories: bool,
    ) -> Result<CountObjectsResponse> {
        let body = json!({ "ern": bucket_ern, "prefix": prefix, "includeDirectories": include_directories });
        self.client.call("count-objects", &body).await
    }

    pub async fn get_object_size(&self, bucket_ern: &str, key: &str) -> Result<GetObjectSizeResponse> {
        self.client
            .call("get-object-size", &json!({ "bucketErn": bucket_ern, "key": key }))
            .await
    }

    pub async fn get_object_size_by_ern(&self, object_ern: &str) -> Result<GetObjectSizeResponse> {
        self.client.call("get-object-size", &json!({ "ern": object_ern })).await
    }

    // -----------------------------------------------------------------------------------------
    // Object attributes
    // -----------------------------------------------------------------------------------------

    /// Adds an attribute to an object; fails if it already has one by that name.
    pub async fn add_object_attribute(
        &self,
        ern: &str,
        name: &str,
        value: &Variant,
    ) -> Result<ObjectAttributeResponse> {
        self.object_attribute("add-object-attribute", ern, name, value).await
    }

    /// Sets an attribute on an object, replacing any value it had.
    pub async fn set_object_attribute(
        &self,
        ern: &str,
        name: &str,
        value: &Variant,
    ) -> Result<ObjectAttributeResponse> {
        self.object_attribute("set-object-attribute", ern, name, value).await
    }

    async fn object_attribute(
        &self,
        action: &str,
        ern: &str,
        name: &str,
        value: &Variant,
    ) -> Result<ObjectAttributeResponse> {
        let body = json!({ "ern": ern, "name": name, "value": value });
        self.client.call(action, &body).await
    }

    pub async fn list_object_attributes(&self, ern: &str) -> Result<ListObjectAttributesResponse> {
        self.client.call("list-object-attributes", &json!({ "ern": ern })).await
    }

    pub async fn delete_object_attribute(&self, ern: &str, name: &str) -> Result<()> {
        self.client
            .call_unit("delete-object-attribute", &json!({ "ern": ern, "name": name }))
            .await
    }

    // -----------------------------------------------------------------------------------------
    // Subscriptions
    // -----------------------------------------------------------------------------------------

    /// Delivers the bucket's events to a target, e.g. an EQS queue. Parse what arrives with
    /// [`BucketEvent::parse`].
    pub async fn subscribe(&self, request: &SubscribeRequest) -> Result<SubscribeResponse> {
        self.client.call("subscribe", request).await
    }

    pub async fn unsubscribe(&self, subscription_ern: &str) -> Result<()> {
        self.client
            .call_unit("unsubscribe", &json!({ "ern": subscription_ern }))
            .await
    }

    pub async fn list_subscriptions(&self, bucket_ern: &str) -> Result<ListSubscriptionsResponse> {
        self.client
            .call("list-subscriptions", &json!({ "bucketErn": bucket_ern }))
            .await
    }
}
