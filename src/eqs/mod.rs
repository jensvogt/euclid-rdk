//! EQS - Euclid Queue Service.

pub mod model;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::json;

pub use model::*;

use crate::service::{CallOptions, ServiceClient};
use crate::{Error, Result};

/// Extra time a long poll's request gets beyond the wait it asked for: the server answers at the
/// end of the window, so a timeout of exactly that window would race the answer.
const LONG_POLL_RESPONSE_MARGIN: Duration = Duration::from_secs(10);
/// Pause between long-poll rounds that came back empty before the wait was up.
const SLOTS_BUSY_BACKOFF: Duration = Duration::from_millis(500);
/// A long poll this close to its deadline is considered to have waited the whole time.
const HONOURED_WAIT_TOLERANCE: Duration = Duration::from_millis(250);
/// How long a short poll believes a message count of zero before receiving anyway.
const DEFAULT_ZERO_COUNT_TRUST: Duration = Duration::from_secs(10);

/// EQS operations, obtained from [`Session::eqs`](crate::Session::eqs).
///
/// Requests are SigV4-signed with the session's access key when it has one, otherwise
/// authenticated with the bearer token. Cloning is cheap; clones share the short-poll state.
#[derive(Debug, Clone)]
pub struct Eqs {
    client: ServiceClient,
    zero_count_trust: Duration,
    /// Since when each queue (by ERN) has read as empty for short polls.
    zero_count_since: Arc<Mutex<HashMap<String, Instant>>>,
}

impl Eqs {
    pub(crate) fn new(client: ServiceClient) -> Self {
        Self {
            client,
            zero_count_trust: DEFAULT_ZERO_COUNT_TRUST,
            zero_count_since: Arc::default(),
        }
    }

    /// An equivalent client whose requests carry `x-euclid-internal: true` - the system talking
    /// to itself, kept out of the autoscaler's load signal.
    pub fn as_internal(&self) -> Self {
        Self {
            client: self.client.clone().internal(),
            ..self.clone()
        }
    }

    /// How long a short poll ([`receive_messages`](Self::receive_messages) with `wait_time` 0)
    /// trusts a message count of zero before asking the queue itself. Defaults to 10 seconds.
    pub fn zero_count_trust(mut self, trust: Duration) -> Self {
        self.zero_count_trust = trust;
        self
    }

    // -----------------------------------------------------------------------------------------
    // Queues
    // -----------------------------------------------------------------------------------------

    pub async fn list_queues(&self, request: &ListQueuesRequest) -> Result<ListQueuesResponse> {
        self.client.call("list-queues", request).await
    }

    /// Creates a queue with default settings (30 s visibility, 3 retries, 1 MiB, no DLQ, `MEDIUM`).
    pub async fn create_queue(&self, name: &str) -> Result<QueueErn> {
        self.create_queue_with(&CreateQueueRequest {
            name: name.into(),
            ..Default::default()
        })
        .await
    }

    pub async fn create_queue_with(&self, request: &CreateQueueRequest) -> Result<QueueErn> {
        self.client.call("create-queue", request).await
    }

    pub async fn delete_queue(&self, ern: &str) -> Result<()> {
        self.client.call_unit("delete-queue", &json!({ "ern": ern })).await
    }

    /// Reads one queue by name, or by ERN if `name_or_ern` starts with `ern:`.
    pub async fn get_queue(&self, name_or_ern: &str) -> Result<Queue> {
        let body = if name_or_ern.starts_with("ern:") {
            json!({ "ern": name_or_ern, "name": null })
        } else {
            json!({ "ern": null, "name": name_or_ern })
        };
        self.client.call_field("get-queue", &body, "queue").await
    }

    pub async fn get_queue_ern(&self, name: &str) -> Result<QueueErn> {
        self.client.call("get-queue-ern", &json!({ "name": name })).await
    }

    /// Whether a queue of that name exists: `false` on a 404, any other failure is an error.
    pub async fn exists_queue(&self, name: &str) -> Result<bool> {
        match self.get_queue_ern(name).await {
            Ok(_) => Ok(true),
            Err(e) if e.status() == Some(404) && matches!(e, Error::Service { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub async fn get_queue_metadata(&self, ern: &str) -> Result<QueueMetadata> {
        self.client.call("get-queue-metadata", &json!({ "ern": ern })).await
    }

    /// Removes every message from the queue.
    pub async fn purge_queue(&self, ern: &str) -> Result<()> {
        self.client.call_unit("purge-queue", &json!({ "ern": ern })).await
    }

    /// Purges every queue of the session's own account and region.
    pub async fn purge_all_queues(&self) -> Result<()> {
        let id = self.client.identity();
        let (region, account_id) = (id.region.clone(), id.account_id.clone());
        self.purge_all_queues_in(region.as_deref(), account_id.as_deref(), "")
            .await
    }

    /// Purges every queue of an account and region, optionally only in one namespace (empty for all).
    pub async fn purge_all_queues_in(
        &self,
        region: Option<&str>,
        account_id: Option<&str>,
        namespace: &str,
    ) -> Result<()> {
        let body = json!({ "region": region, "accountId": account_id, "nameSpace": namespace });
        self.client.call_unit("purge-all-queues", &body).await
    }

    /// Takes a queue out of service.
    pub async fn stop_queue(&self, ern: &str) -> Result<QueueStatus> {
        self.client.call("stop-queue", &json!({ "ern": ern })).await
    }

    /// Puts a stopped queue back into service.
    pub async fn start_queue(&self, ern: &str) -> Result<QueueStatus> {
        self.client.call("start-queue", &json!({ "ern": ern })).await
    }

    /// Changes the queue's default visibility timeout, in seconds (0..=43200).
    pub async fn set_queue_visibility(&self, ern: &str, visibility: u64) -> Result<SetQueueVisibilityResponse> {
        let body = json!({ "ern": ern, "visibility": visibility });
        self.client.call("set-queue-visibility", &body).await
    }

    /// Changes the queue's delivery delay, in seconds.
    pub async fn set_queue_delay(&self, ern: &str, delay: u64) -> Result<SetQueueDelayResponse> {
        self.client
            .call("set-queue-delay", &json!({ "ern": ern, "delay": delay }))
            .await
    }

    /// Changes the largest message the queue accepts; 0 means the default.
    pub async fn set_queue_max_message_length(
        &self,
        ern: &str,
        max_message_length: u64,
    ) -> Result<SetQueueMaxMessageLengthResponse> {
        let body = json!({ "ern": ern, "maxMessageLength": max_message_length });
        let mut value = self.client.call_value("set-queue-max-message-length", &body).await?;
        // A server that predates the effective figure resolves it the way the server would.
        if value.get("effectiveMaxMessageLength").is_none() {
            let configured = value.get("maxMessageLength").and_then(|v| v.as_u64()).unwrap_or(0);
            let effective = if configured > 0 {
                configured
            } else {
                DEFAULT_MAX_MESSAGE_LENGTH
            };
            if let Some(object) = value.as_object_mut() {
                object.insert("effectiveMaxMessageLength".into(), effective.into());
            }
        }
        Ok(serde_json::from_value(value)?)
    }

    /// Drains a dead letter queue back onto the queues its messages came from.
    pub async fn redrive_dlq(&self, ern: &str) -> Result<RedriveDlqResponse> {
        self.redrive_dlq_to(ern, "").await
    }

    /// Drains a dead letter queue onto `target_ern` (empty: back to where each message came from).
    pub async fn redrive_dlq_to(&self, ern: &str, target_ern: &str) -> Result<RedriveDlqResponse> {
        self.client
            .call("redrive-dlq", &json!({ "ern": ern, "targetErn": target_ern }))
            .await
    }

    pub async fn add_queue_tag(&self, ern: &str, key: &str, value: &str) -> Result<()> {
        let body = json!({ "ern": ern, "key": key, "value": value });
        self.client.call_unit("add-queue-tag", &body).await
    }

    pub async fn set_queue_tag(&self, ern: &str, key: &str, value: &str) -> Result<()> {
        let body = json!({ "ern": ern, "key": key, "value": value });
        self.client.call_unit("set-queue-tag", &body).await
    }

    pub async fn delete_queue_tag(&self, ern: &str, key: &str) -> Result<()> {
        self.client
            .call_unit("delete-queue-tag", &json!({ "ern": ern, "key": key }))
            .await
    }

    // -----------------------------------------------------------------------------------------
    // Sending
    // -----------------------------------------------------------------------------------------

    /// Sends a message without attributes, at `MEDIUM` priority.
    pub async fn send_message(&self, ern: &str, body: &str) -> Result<SendMessageResponse> {
        self.send_message_with(&SendMessageRequest {
            ern: ern.into(),
            body: body.into(),
            ..Default::default()
        })
        .await
    }

    pub async fn send_message_with(&self, request: &SendMessageRequest) -> Result<SendMessageResponse> {
        self.client.call("send-message", request).await
    }

    /// Sends several messages to one queue in one request. Messages the server refuses are
    /// reported in `failed` rather than failing the whole call.
    pub async fn send_message_batch(&self, request: &SendMessageBatchRequest) -> Result<SendMessageBatchResponse> {
        self.client.call("send-message-batch", request).await
    }

    // -----------------------------------------------------------------------------------------
    // Receiving
    // -----------------------------------------------------------------------------------------

    /// Receives up to `max_messages`, waiting up to `wait_time` seconds for any to arrive.
    ///
    /// With `wait_time` 0 (a short poll) the queue's message count is asked first and an empty
    /// queue answered without receiving. The count trails the messages and can be wrong, so a
    /// zero is believed only for [`zero_count_trust`](Self::zero_count_trust); past that one real
    /// receive asks the messages themselves.
    ///
    /// With a `wait_time`, the request is held server-side; if it comes back empty before the
    /// wait is up (all receive slots busy), it is repeated until messages arrive or time runs out.
    pub async fn receive_messages(
        &self,
        ern: &str,
        max_messages: u64,
        wait_time: u64,
    ) -> Result<ReceiveMessagesResponse> {
        if wait_time == 0 {
            let available = self.get_message_count(ern).await?.available;
            let now = Instant::now();
            if available == 0 {
                let mut since = self.zero_count_since.lock().unwrap_or_else(|e| e.into_inner());
                match since.get(ern) {
                    None => {
                        since.insert(ern.to_owned(), now);
                        return Ok(ReceiveMessagesResponse::default());
                    }
                    Some(first) if now.duration_since(*first) < self.zero_count_trust => {
                        return Ok(ReceiveMessagesResponse::default());
                    }
                    Some(_) => {}
                }
            }
            self.zero_count_since
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(ern);
            return self.do_receive_messages(ern, max_messages, 0).await;
        }

        let deadline = Instant::now() + Duration::from_secs(wait_time);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let response = self
                .do_receive_messages(ern, max_messages, remaining.as_secs().max(1))
                .await?;
            if !response.messages.is_empty() {
                return Ok(response);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining <= HONOURED_WAIT_TOLERANCE {
                return Ok(response);
            }
            tokio::time::sleep(remaining.min(SLOTS_BUSY_BACKOFF)).await;
        }
    }

    /// Receives batches of `batch_size` until the queue answers empty, and returns them all.
    pub async fn receive_all_messages(&self, ern: &str, batch_size: u64) -> Result<ReceiveMessagesResponse> {
        let mut messages = Vec::new();
        loop {
            let batch = self.receive_messages(ern, batch_size, 0).await?.messages;
            if batch.is_empty() {
                break;
            }
            messages.extend(batch);
        }
        Ok(ReceiveMessagesResponse { messages })
    }

    async fn do_receive_messages(
        &self,
        ern: &str,
        max_messages: u64,
        wait_time: u64,
    ) -> Result<ReceiveMessagesResponse> {
        let body = json!({ "ern": ern, "maxCount": max_messages, "waitTime": wait_time });
        let options = CallOptions {
            timeout: Some(Duration::from_secs(wait_time) + LONG_POLL_RESPONSE_MARGIN),
            ..Default::default()
        };
        let value = self.client.call_value_with("receive-messages", &body, &options).await?;
        Ok(serde_json::from_value(value)?)
    }

    /// Deletes a received message by the receipt handle the receive returned. Fails once the
    /// message's visibility timeout has expired.
    pub async fn delete_message(&self, receipt_handle: &str) -> Result<()> {
        let body = json!({ "receiptHandle": receipt_handle, "messageId": "" });
        self.client.call_unit("delete-message", &body).await
    }

    /// Deletes a message by its ID, received or not.
    pub async fn delete_message_by_id(&self, message_id: &str) -> Result<()> {
        let body = json!({ "receiptHandle": "", "messageId": message_id });
        self.client.call_unit("delete-message", &body).await
    }

    // -----------------------------------------------------------------------------------------
    // Inspecting messages
    // -----------------------------------------------------------------------------------------

    pub async fn get_message_count(&self, ern: &str) -> Result<MessageCount> {
        self.client.call("get-message-count", &json!({ "ern": ern })).await
    }

    /// Reads a queue's messages without consuming them.
    pub async fn list_messages(&self, request: &ListMessagesRequest) -> Result<ListMessagesResponse> {
        self.client.call("list-messages", request).await
    }

    pub async fn get_message(&self, message_id: &str) -> Result<Message> {
        self.client
            .call_field("get-message", &json!({ "messageId": message_id }), "message")
            .await
    }

    pub async fn get_message_metadata(&self, message_id: &str) -> Result<MessageMetadata> {
        self.client
            .call("get-message-metadata", &json!({ "messageId": message_id }))
            .await
    }

    /// Changes how long a received message stays invisible, in seconds from now.
    pub async fn set_message_visibility(&self, message_id: &str, visibility: u64) -> Result<()> {
        let body = json!({ "messageId": message_id, "visibility": visibility });
        self.client.call_unit("set-message-visibility", &body).await
    }

    pub async fn get_message_attribute(&self, message_id: &str, name: &str) -> Result<MessageAttribute> {
        let body = json!({ "messageId": message_id, "name": name });
        self.client.call("get-message-attribute", &body).await
    }

    pub async fn set_message_attribute(
        &self,
        message_id: &str,
        key: &str,
        value: &Variant,
    ) -> Result<MessageAttribute> {
        let body = json!({ "messageId": message_id, "key": key, "value": value });
        self.client.call("set-message-attribute", &body).await
    }

    /// Replaces a message's body in place.
    pub async fn update_message_body(&self, message_id: &str, body: &str) -> Result<UpdateMessageBodyResponse> {
        let request = json!({ "messageId": message_id, "body": body });
        self.client.call("update-message-body", &request).await
    }
}
