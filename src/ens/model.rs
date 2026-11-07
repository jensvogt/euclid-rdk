//! Request and response types of the ENS (Euclid Notification Service) module.
//!
//! Field names are the wire names in camelCase. Response types default every field, so a field
//! the server leaves out reads as `None`/zero instead of failing the whole response.

use std::collections::HashMap;

use serde::{Deserialize, Deserializer, Serialize};

pub use crate::eam::{Metadata, SortDirection};
use crate::serde_util::{lenient_string, lenient_u64};
pub use crate::variant::Variant;

/// The largest message a topic accepts unless configured otherwise: 1 MiB.
pub const DEFAULT_MAX_MESSAGE_LENGTH: u64 = 1024 * 1024;

/// Retention period that keeps every message published to a topic.
pub const RETENTION_FOREVER: i64 = -1;

fn default_max_message_length() -> u64 {
    DEFAULT_MAX_MESSAGE_LENGTH
}

/// Reads a signed integer that may arrive as a number or a numeric string; anything else is 0.
/// Retention periods are signed: [`RETENTION_FOREVER`] is -1.
fn lenient_i64<'de, D: Deserializer<'de>>(d: D) -> Result<i64, D::Error> {
    Ok(match Option::<serde_json::Value>::deserialize(d)? {
        Some(serde_json::Value::Number(n)) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)).unwrap_or(0),
        Some(serde_json::Value::String(s)) => s.trim().parse().unwrap_or(0),
        _ => 0,
    })
}

// ---------------------------------------------------------------------------------------------
// Topics
// ---------------------------------------------------------------------------------------------

/// A topic, as listings and `get-topic` describe it.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Topic {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub ern: Option<String>,
    #[serde(default)]
    pub tags: HashMap<String, serde_json::Value>,
    /// Bytes stored on the topic (message bodies only).
    #[serde(default, deserialize_with = "lenient_u64")]
    pub size: u64,
    #[serde(default, deserialize_with = "lenient_u64")]
    pub messages: u64,
    #[serde(default = "default_max_message_length", deserialize_with = "lenient_u64")]
    pub max_message_length: u64,
    /// How many messages have ever been published to the topic - a lifetime total that, unlike
    /// `messages`, does not fall on a purge or when retention removes what the topic held.
    #[serde(default, deserialize_with = "lenient_u64")]
    pub send: u64,
    /// How many messages have ever been handed to the subscriptions again by `resend-messages`.
    #[serde(default, deserialize_with = "lenient_u64")]
    pub resend: u64,
    #[serde(default)]
    pub status: Option<String>,
    /// Seconds a published message is kept; 0 follows the installation default,
    /// [`RETENTION_FOREVER`] keeps everything.
    #[serde(default, deserialize_with = "lenient_i64")]
    pub retention_period: i64,
    /// Whether a message is deleted once it has been handed to every subscription, instead of
    /// being kept for the retention period. `false` from a server that predates the setting.
    #[serde(default)]
    pub delete_after_delivery: bool,
    #[serde(default, deserialize_with = "lenient_string")]
    pub created: Option<String>,
    #[serde(default, deserialize_with = "lenient_string")]
    pub modified: Option<String>,
}

impl Default for Topic {
    fn default() -> Self {
        serde_json::from_value(serde_json::json!({})).expect("every Topic field has a default")
    }
}

impl Topic {
    /// A tag's value as text.
    pub fn tag(&self, key: &str) -> Option<String> {
        self.tags.get(key).map(|v| match v {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        })
    }
}

/// Paging and sorting for `list-topics`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListTopicsRequest {
    pub prefix: String,
    pub page_size: u64,
    pub page_index: u64,
    pub sort_column: String,
    pub sort_direction: SortDirection,
}

impl Default for ListTopicsRequest {
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

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListTopicsResponse {
    pub topics: Vec<Topic>,
    #[serde(deserialize_with = "lenient_u64")]
    pub total: u64,
}

/// A topic's name and ERN, as `create-topic` and `get-topic-ern` answer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TopicErn {
    pub name: Option<String>,
    pub ern: Option<String>,
}

/// Answer to `get-topic-metadata`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TopicMetadata {
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
    pub status: Option<String>,
    #[serde(deserialize_with = "lenient_i64")]
    pub retention_period: i64,
    /// Whether a message is deleted once it has been handed to every subscription.
    pub delete_after_delivery: bool,
    /// Messages held while the topic is stopped.
    #[serde(deserialize_with = "lenient_u64")]
    pub held: u64,
}

/// Answer to `stop-topic` / `start-topic`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TopicStatus {
    pub ern: Option<String>,
    pub status: Option<String>,
    /// Held messages delivered by a start.
    #[serde(deserialize_with = "lenient_u64")]
    pub released: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SetTopicRetentionResponse {
    pub ern: Option<String>,
    #[serde(deserialize_with = "lenient_i64")]
    pub retention_period: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SetTopicMaxMessageLengthResponse {
    pub ern: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub max_message_length: u64,
}

/// Answer to `set-topic-delete-after-delivery`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SetTopicDeleteAfterDeliveryResponse {
    pub ern: Option<String>,
    pub delete_after_delivery: bool,
}

/// Answer to `purge-topic`. With `async` the purge is only accepted, and `messages` says how many
/// the topic held when it was; without it the topic is already empty and `messages` is 0.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PurgeTopicResponse {
    pub ern: Option<String>,
    #[serde(rename = "async")]
    pub is_async: bool,
    #[serde(deserialize_with = "lenient_u64")]
    pub messages: u64,
}

/// Answer to `resend-messages`. With `async`, `messages` is what was taken on and `resent`/`held`
/// are 0.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ResendMessagesResponse {
    pub ern: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub resent: u64,
    #[serde(deserialize_with = "lenient_u64")]
    pub held: u64,
    #[serde(deserialize_with = "lenient_u64")]
    pub messages: u64,
    #[serde(rename = "async")]
    pub is_async: bool,
}

// ---------------------------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------------------------

/// A message stored on a topic. Topics are never consumed from; what stays is a record of what
/// was published.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Message {
    pub ern: Option<String>,
    pub topic_ern: Option<String>,
    pub message_id: Option<String>,
    pub status: Option<String>,
    pub body: Option<String>,
    pub attributes: HashMap<String, Variant>,
    pub content_type: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub last_received: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub created: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub modified: Option<String>,
}

/// Body of `publish-message`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishMessageRequest {
    pub ern: String,
    pub body: String,
    pub attributes: HashMap<String, Variant>,
    /// Priority of the queue messages the publish fans out to: `LOW`, `MEDIUM` or `HIGH`. It means
    /// nothing on the topic itself, which is not consumed from.
    pub priority: String,
}

impl Default for PublishMessageRequest {
    fn default() -> Self {
        Self {
            ern: String::new(),
            body: String::new(),
            attributes: HashMap::new(),
            priority: "MEDIUM".into(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PublishMessageResponse {
    pub message_id: Option<String>,
}

/// Paging and sorting for `list-messages`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListMessagesRequest {
    pub topic_ern: String,
    pub page_size: u64,
    pub page_index: u64,
    pub sort_column: String,
    pub sort_direction: SortDirection,
}

impl Default for ListMessagesRequest {
    fn default() -> Self {
        Self {
            topic_ern: String::new(),
            page_size: 10,
            page_index: 0,
            sort_column: "created".into(),
            sort_direction: SortDirection::Asc,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListMessagesResponse {
    pub messages: Vec<Message>,
    #[serde(deserialize_with = "lenient_u64")]
    pub total: u64,
}

/// Answer to `get-message-count`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct MessageCount {
    pub ern: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub available: u64,
    #[serde(deserialize_with = "lenient_u64")]
    pub send: u64,
    #[serde(deserialize_with = "lenient_u64")]
    pub resend: u64,
}

/// Answer to `get-message-attribute` / `set-message-attribute`.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct MessageAttribute {
    pub message_id: Option<String>,
    pub key: Option<String>,
    pub value: Option<Variant>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UpdateMessageBodyResponse {
    pub message_id: Option<String>,
    pub topic_ern: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub size: u64,
    #[serde(deserialize_with = "lenient_u64")]
    pub previous_size: u64,
    pub content_type: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// Subscriptions
// ---------------------------------------------------------------------------------------------

/// What a topic delivers to. `kind` is the delivery protocol; `"SQS"` (an EQS queue) is the only
/// one so far.
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

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListSubscriptionsResponse {
    pub subscriptions: Vec<Subscription>,
    #[serde(deserialize_with = "lenient_u64")]
    pub total: u64,
}
