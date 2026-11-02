//! Request and response types of the EQS (Euclid Queue Service) module.
//!
//! Field names are the wire names in camelCase. Response types default every field, so a field
//! the server leaves out reads as `None`/zero instead of failing the whole response.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub use crate::eam::{Metadata, SortDirection};
use crate::serde_util::{lenient_string, lenient_u64};

fn default_visibility() -> u64 {
    30
}
fn default_max_message_length() -> u64 {
    DEFAULT_MAX_MESSAGE_LENGTH
}
fn default_max_receive_count() -> u64 {
    3
}
fn medium() -> String {
    "MEDIUM".into()
}

/// The largest message a queue accepts unless configured otherwise: 1 MiB.
pub const DEFAULT_MAX_MESSAGE_LENGTH: u64 = 1024 * 1024;

// ---------------------------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------------------------

pub use crate::variant::Variant;

// ---------------------------------------------------------------------------------------------
// Queues
// ---------------------------------------------------------------------------------------------

/// A queue, as listings and `get-queue` describe it.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Queue {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub ern: Option<String>,
    #[serde(default)]
    pub tags: HashMap<String, serde_json::Value>,
    #[serde(default, deserialize_with = "lenient_u64")]
    pub size: u64,
    #[serde(default, deserialize_with = "lenient_u64")]
    pub delay: u64,
    #[serde(default, deserialize_with = "lenient_u64")]
    pub available: u64,
    #[serde(default, deserialize_with = "lenient_u64")]
    pub delayed: u64,
    #[serde(default, deserialize_with = "lenient_u64")]
    pub invisible: u64,
    #[serde(default = "default_visibility", deserialize_with = "lenient_u64")]
    pub visibility: u64,
    #[serde(default = "default_max_message_length", deserialize_with = "lenient_u64")]
    pub max_message_length: u64,
    #[serde(default = "default_max_receive_count", deserialize_with = "lenient_u64")]
    pub max_receive_count: u64,
    #[serde(default)]
    pub dead_letter_queue_arn: Option<String>,
    #[serde(default)]
    pub priority: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub internal: bool,
    #[serde(default, deserialize_with = "lenient_string")]
    pub created: Option<String>,
    #[serde(default, deserialize_with = "lenient_string")]
    pub modified: Option<String>,
}

impl Default for Queue {
    fn default() -> Self {
        serde_json::from_value(serde_json::json!({})).expect("every Queue field has a default")
    }
}

impl Queue {
    /// A tag's value as text.
    pub fn tag(&self, key: &str) -> Option<String> {
        self.tags.get(key).map(|v| match v {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        })
    }
}

/// Paging, sorting and filtering for `list-queues`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListQueuesRequest {
    pub prefix: String,
    pub page_size: u64,
    pub page_index: u64,
    pub sort_column: String,
    pub sort_direction: SortDirection,
    /// Also list the queues euclid keeps for itself.
    pub include_internal: bool,
}

impl Default for ListQueuesRequest {
    fn default() -> Self {
        Self {
            prefix: String::new(),
            page_size: 10,
            page_index: 0,
            sort_column: "name".into(),
            sort_direction: SortDirection::Asc,
            include_internal: false,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListQueuesResponse {
    pub metadata: Option<Metadata>,
    pub queues: Vec<Queue>,
    #[serde(deserialize_with = "lenient_u64")]
    pub total: u64,
}

/// Body of `create-queue`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateQueueRequest {
    pub name: String,
    /// Default visibility timeout in seconds.
    pub visibility: u64,
    /// Receives after which a message moves to the dead letter queue.
    pub max_retries: u64,
    pub max_message_length: u64,
    /// Name of the dead letter queue; empty for none.
    pub dlq_name: String,
    /// Delivery delay in seconds.
    pub delay: u64,
    /// `LOW`, `MEDIUM` or `HIGH`.
    pub priority: String,
    pub internal: bool,
}

impl Default for CreateQueueRequest {
    fn default() -> Self {
        Self {
            name: String::new(),
            visibility: 30,
            max_retries: 3,
            max_message_length: DEFAULT_MAX_MESSAGE_LENGTH,
            dlq_name: String::new(),
            delay: 0,
            priority: medium(),
            internal: false,
        }
    }
}

/// A queue's name and ERN, as `create-queue` and `get-queue-ern` answer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct QueueErn {
    pub name: Option<String>,
    pub ern: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct QueueMetadata {
    pub region: Option<String>,
    pub account_id: Option<String>,
    pub owner: Option<String>,
    pub name_space: Option<String>,
    pub name: Option<String>,
    pub ern: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub size: u64,
    #[serde(deserialize_with = "lenient_u64")]
    pub messages: u64,
}

/// Answer to `stop-queue`/`start-queue`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct QueueStatus {
    pub ern: Option<String>,
    pub status: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub available: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SetQueueVisibilityResponse {
    pub ern: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub visibility: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SetQueueDelayResponse {
    pub ern: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub delay: u64,
}

/// `max_message_length` is what the queue is configured with (0 = default);
/// `effective_max_message_length` is what it enforces.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SetQueueMaxMessageLengthResponse {
    pub ern: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub max_message_length: u64,
    #[serde(deserialize_with = "lenient_u64")]
    pub effective_max_message_length: u64,
}

/// Message counts of a queue.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct MessageCount {
    pub ern: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub available: u64,
    #[serde(deserialize_with = "lenient_u64")]
    pub delayed: u64,
    #[serde(deserialize_with = "lenient_u64")]
    pub invisible: u64,
    #[serde(deserialize_with = "lenient_u64")]
    pub total: u64,
}

/// Where a redrive put messages, and how many.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RedriveTarget {
    pub queue_ern: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub messages: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RedriveDlqResponse {
    pub ern: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub messages: u64,
    #[serde(deserialize_with = "lenient_u64")]
    pub remaining: u64,
    pub targets: Vec<RedriveTarget>,
    pub note: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Message {
    pub ern: Option<String>,
    pub queue_ern: Option<String>,
    pub message_id: Option<String>,
    pub status: Option<String>,
    pub priority: Option<String>,
    pub body: Option<String>,
    /// What [`Eqs::delete_message`](super::Eqs::delete_message) takes after a receive.
    pub receipt_handle: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub size: u64,
    #[serde(deserialize_with = "lenient_u64")]
    pub received_count: u64,
    pub content_type: Option<String>,
    pub attributes: HashMap<String, Variant>,
    pub system_attributes: HashMap<String, Variant>,
    #[serde(deserialize_with = "lenient_string")]
    pub last_received: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub created: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub modified: Option<String>,
}

/// Body of `send-message`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendMessageRequest {
    pub ern: String,
    pub body: String,
    pub attributes: HashMap<String, Variant>,
    /// `LOW`, `MEDIUM` or `HIGH`.
    pub priority: String,
}

impl Default for SendMessageRequest {
    fn default() -> Self {
        Self {
            ern: String::new(),
            body: String::new(),
            attributes: HashMap::new(),
            priority: medium(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SendMessageResponse {
    pub message_id: Option<String>,
}

/// Body of `send-message-batch`: several messages to one queue in one request.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendMessageBatchRequest {
    pub ern: String,
    pub messages: Vec<BatchEntry>,
}

impl SendMessageBatchRequest {
    pub fn new(ern: impl Into<String>) -> Self {
        Self {
            ern: ern.into(),
            messages: Vec::new(),
        }
    }

    /// Adds a plain message.
    pub fn message(mut self, body: impl Into<String>) -> Self {
        self.messages.push(BatchEntry {
            body: body.into(),
            ..Default::default()
        });
        self
    }

    /// Adds a message with attributes and a priority.
    pub fn message_with(
        mut self,
        body: impl Into<String>,
        attributes: HashMap<String, Variant>,
        priority: impl Into<String>,
    ) -> Self {
        self.messages.push(BatchEntry {
            body: body.into(),
            attributes,
            priority: priority.into(),
            ..Default::default()
        });
        self
    }
}

/// One message of a batch. An empty priority leaves it to the server.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchEntry {
    pub body: String,
    pub attributes: HashMap<String, Variant>,
    pub system_attributes: HashMap<String, Variant>,
    pub priority: String,
}

/// A message of a batch the server refused, by its index in the request.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct BatchFailure {
    #[serde(deserialize_with = "lenient_u64")]
    pub index: u64,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SendMessageBatchResponse {
    pub ern: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub asked: u64,
    #[serde(deserialize_with = "lenient_u64")]
    pub sent: u64,
    pub message_ids: Vec<String>,
    pub failed: Vec<BatchFailure>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ReceiveMessagesResponse {
    pub messages: Vec<Message>,
}

/// Paging and sorting for `list-messages`, which reads a queue without consuming it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListMessagesRequest {
    pub queue_ern: String,
    pub page_size: u64,
    pub page_index: u64,
    pub sort_column: String,
    pub sort_direction: SortDirection,
}

impl Default for ListMessagesRequest {
    fn default() -> Self {
        Self {
            queue_ern: String::new(),
            page_size: 10,
            page_index: 0,
            sort_column: "created".into(),
            sort_direction: SortDirection::Asc,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListMessagesResponse {
    pub messages: Vec<Message>,
    #[serde(deserialize_with = "lenient_u64")]
    pub total: u64,
}

/// One attribute of a message, as `get-message-attribute`/`set-message-attribute` answer.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct MessageAttribute {
    pub message_id: Option<String>,
    pub name: Option<String>,
    pub value: Option<Variant>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct MessageMetadata {
    pub message_id: Option<String>,
    pub queue_ern: Option<String>,
    pub receipt_handle: Option<String>,
    pub status: Option<String>,
    pub priority: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub size: u64,
    #[serde(deserialize_with = "lenient_u64")]
    pub received_count: u64,
    #[serde(deserialize_with = "lenient_u64")]
    pub visibility_timeout: u64,
    pub content_type: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub created: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub modified: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UpdateMessageBodyResponse {
    pub message_id: Option<String>,
    pub queue_ern: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub size: u64,
    #[serde(deserialize_with = "lenient_u64")]
    pub previous_size: u64,
    pub content_type: Option<String>,
}
