//! ENS - Euclid Notification Service (pub/sub topics).
//!
//! ENS fans a published message out to everything subscribed to the topic, at publish time.
//! Where a queue message is consumed and gone, a topic is never consumed from: what stays on it
//! is a record of what was sent, kept for the topic's retention period.

pub mod model;

pub use model::*;
use serde_json::json;

use crate::service::ServiceClient;
use crate::{Error, Result};

/// The delivery protocol [`Ens::subscribe`] uses: an EQS queue. The only one there is for now.
pub const PROTOCOL_SQS: &str = "SQS";

/// ENS operations, obtained from [`Session::ens`](crate::Session::ens).
///
/// Requests are SigV4-signed with the session's access key when it has one, otherwise
/// authenticated with the bearer token. Cloning is cheap.
#[derive(Debug, Clone)]
pub struct Ens {
    client: ServiceClient,
}

impl Ens {
    pub(crate) fn new(client: ServiceClient) -> Self {
        Self { client }
    }

    // -----------------------------------------------------------------------------------------
    // Topics
    // -----------------------------------------------------------------------------------------

    /// Creates a topic accepting messages up to 1 MiB.
    pub async fn create_topic(&self, name: &str) -> Result<TopicErn> {
        self.create_topic_with_max_length(name, DEFAULT_MAX_MESSAGE_LENGTH)
            .await
    }

    /// Creates a topic accepting messages up to `max_message_length` bytes.
    pub async fn create_topic_with_max_length(&self, name: &str, max_message_length: u64) -> Result<TopicErn> {
        let body = json!({ "name": name, "maxMessageLength": max_message_length });
        self.client.call("create-topic", &body).await
    }

    pub async fn list_topics(&self, request: &ListTopicsRequest) -> Result<ListTopicsResponse> {
        self.client.call("list-topics", request).await
    }

    /// Reads one topic by name, or by ERN if `name_or_ern` starts with `ern:`.
    pub async fn get_topic(&self, name_or_ern: &str) -> Result<Topic> {
        let body = if name_or_ern.starts_with("ern:") {
            json!({ "ern": name_or_ern, "name": null })
        } else {
            json!({ "ern": null, "name": name_or_ern })
        };
        self.client.call_field("get-topic", &body, "topic").await
    }

    pub async fn get_topic_ern(&self, name: &str) -> Result<TopicErn> {
        self.client.call("get-topic-ern", &json!({ "name": name })).await
    }

    /// Whether a topic of that name exists: `false` on a 404, any other failure is an error.
    pub async fn exists_topic(&self, name: &str) -> Result<bool> {
        match self.get_topic_ern(name).await {
            Ok(_) => Ok(true),
            Err(Error::Service { status: 404, .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub async fn get_topic_metadata(&self, ern: &str) -> Result<TopicMetadata> {
        self.client.call("get-topic-metadata", &json!({ "ern": ern })).await
    }

    pub async fn delete_topic(&self, ern: &str) -> Result<()> {
        self.client.call_unit("delete-topic", &json!({ "ern": ern })).await
    }

    /// Deletes every message stored on the topic, keeping the topic.
    pub async fn purge_topic(&self, ern: &str) -> Result<()> {
        self.client.call_unit("purge-topic", &json!({ "ern": ern })).await
    }

    /// Purges a topic, optionally asynchronously. With `run_async` the server answers 202 as soon
    /// as it has accepted the purge, with how many messages the topic held then, and empties it in
    /// the background - for a topic too large to empty within the gateway's timeout. Nothing is
    /// resumed: a purge interrupted halfway has removed part of the topic, and asking again removes
    /// the rest.
    pub async fn purge_topic_with(&self, ern: &str, run_async: bool) -> Result<PurgeTopicResponse> {
        let body = json!({ "ern": ern, "async": run_async });
        self.client.call("purge-topic", &body).await
    }

    /// Purges every topic of the session's own account and region.
    pub async fn purge_all_topics(&self) -> Result<()> {
        let id = self.client.identity();
        let (region, account_id) = (id.region.clone(), id.account_id.clone());
        self.purge_all_topics_in(region.as_deref(), account_id.as_deref(), "")
            .await
    }

    /// Purges every topic of an account and region, optionally only in one namespace (empty for
    /// all).
    pub async fn purge_all_topics_in(
        &self,
        region: Option<&str>,
        account_id: Option<&str>,
        namespace: &str,
    ) -> Result<()> {
        let body = json!({ "region": region, "accountId": account_id, "nameSpace": namespace });
        self.client.call_unit("purge-all-topics", &body).await
    }

    /// Stops a topic delivering: what is published is still accepted and stored, but held
    /// instead of fanned out, until [`start_topic`](Self::start_topic).
    pub async fn stop_topic(&self, ern: &str) -> Result<TopicStatus> {
        self.client.call("stop-topic", &json!({ "ern": ern })).await
    }

    /// Starts a stopped topic, delivering what it held (oldest first) before answering;
    /// `released` says how many went out.
    pub async fn start_topic(&self, ern: &str) -> Result<TopicStatus> {
        self.client.call("start-topic", &json!({ "ern": ern })).await
    }

    /// Sets how long messages published from now on are kept, in seconds. 0 follows the
    /// installation default; [`RETENTION_FOREVER`] keeps everything; below that is refused (400).
    pub async fn set_topic_retention(&self, ern: &str, retention_period: i64) -> Result<SetTopicRetentionResponse> {
        let body = json!({ "ern": ern, "retentionPeriod": retention_period });
        self.client.call("set-topic-retention", &body).await
    }

    /// Changes the largest message the topic accepts from now on. Unlike queues, 0 is refused;
    /// use [`stop_topic`](Self::stop_topic) to take nothing for now.
    pub async fn set_topic_max_message_length(
        &self,
        ern: &str,
        max_message_length: u64,
    ) -> Result<SetTopicMaxMessageLengthResponse> {
        let body = json!({ "ern": ern, "maxMessageLength": max_message_length });
        self.client.call("set-topic-max-message-length", &body).await
    }

    /// Sets whether the topic deletes each message once it has been handed to every subscription
    /// (`true`), or keeps it for the retention period as every topic does by default (`false`).
    ///
    /// It applies to what is published from now on: messages already on the topic stay until
    /// their retention runs out (use [`purge_topic`](Self::purge_topic) to remove them). A message
    /// on a topic with no subscription is kept either way, and what a topic deletes is gone for
    /// [`resend_messages`](Self::resend_messages) too.
    pub async fn set_topic_delete_after_delivery(
        &self,
        ern: &str,
        delete_after_delivery: bool,
    ) -> Result<SetTopicDeleteAfterDeliveryResponse> {
        let body = json!({ "ern": ern, "deleteAfterDelivery": delete_after_delivery });
        self.client.call("set-topic-delete-after-delivery", &body).await
    }

    pub async fn add_topic_tag(&self, ern: &str, key: &str, value: &str) -> Result<()> {
        let body = json!({ "ern": ern, "key": key, "value": value });
        self.client.call_unit("add-topic-tag", &body).await
    }

    pub async fn set_topic_tag(&self, ern: &str, key: &str, value: &str) -> Result<()> {
        let body = json!({ "ern": ern, "key": key, "value": value });
        self.client.call_unit("set-topic-tag", &body).await
    }

    pub async fn delete_topic_tag(&self, ern: &str, key: &str) -> Result<()> {
        self.client
            .call_unit("delete-topic-tag", &json!({ "ern": ern, "key": key }))
            .await
    }

    // -----------------------------------------------------------------------------------------
    // Messages
    // -----------------------------------------------------------------------------------------

    /// Publishes `body` with no attributes at `MEDIUM` priority.
    pub async fn publish_message(&self, ern: &str, body: &str) -> Result<PublishMessageResponse> {
        self.publish_message_with(&PublishMessageRequest {
            ern: ern.into(),
            body: body.into(),
            ..Default::default()
        })
        .await
    }

    /// Publishes with attributes and a priority for the fanned-out queue messages. A body larger
    /// than the topic accepts is refused with 400; attributes do not count towards that.
    pub async fn publish_message_with(&self, request: &PublishMessageRequest) -> Result<PublishMessageResponse> {
        self.client.call("publish-message", request).await
    }

    /// Reads what a topic has stored, without consuming anything.
    pub async fn list_messages(&self, request: &ListMessagesRequest) -> Result<ListMessagesResponse> {
        self.client.call("list-messages", request).await
    }

    pub async fn get_message(&self, message_id: &str) -> Result<Message> {
        self.client
            .call_field("get-message", &json!({ "messageId": message_id }), "message")
            .await
    }

    pub async fn get_message_count(&self, ern: &str) -> Result<MessageCount> {
        self.client.call("get-message-count", &json!({ "ern": ern })).await
    }

    pub async fn get_message_attribute(&self, message_id: &str, key: &str) -> Result<MessageAttribute> {
        let body = json!({ "messageId": message_id, "key": key });
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

    pub async fn update_message_body(&self, message_id: &str, body: &str) -> Result<UpdateMessageBodyResponse> {
        let request = json!({ "messageId": message_id, "body": body });
        self.client.call("update-message-body", &request).await
    }

    /// Hands what the topic still holds to its subscribers again - a replay, so subscribers must
    /// be idempotent.
    pub async fn resend_messages(&self, ern: &str) -> Result<ResendMessagesResponse> {
        self.resend_messages_with(ern, "", false).await
    }

    /// Resends one message (`message_id`), or all of them when it is empty. With `run_async` the
    /// server answers 202 once it has counted what it will hand over; `async` cannot be combined
    /// with a `message_id`.
    pub async fn resend_messages_with(
        &self,
        ern: &str,
        message_id: &str,
        run_async: bool,
    ) -> Result<ResendMessagesResponse> {
        let body = json!({ "ern": ern, "messageId": message_id, "async": run_async });
        self.client.call("resend-messages", &body).await
    }

    // -----------------------------------------------------------------------------------------
    // Subscriptions
    // -----------------------------------------------------------------------------------------

    /// Subscribes an EQS queue (`target_ern`) to the topic, with the [`PROTOCOL_SQS`] protocol.
    pub async fn subscribe(&self, topic_ern: &str, target_ern: &str) -> Result<Subscription> {
        self.subscribe_with_protocol(topic_ern, PROTOCOL_SQS, target_ern).await
    }

    /// Subscribes `target_ern` to the topic with an explicit delivery protocol.
    pub async fn subscribe_with_protocol(
        &self,
        topic_ern: &str,
        protocol: &str,
        target_ern: &str,
    ) -> Result<Subscription> {
        let body = json!({ "sourceErn": topic_ern, "type": protocol, "targetErn": target_ern });
        self.client.call("subscribe", &body).await
    }

    pub async fn unsubscribe(&self, subscription_ern: &str) -> Result<()> {
        self.client
            .call_unit("unsubscribe", &json!({ "ern": subscription_ern }))
            .await
    }

    pub async fn list_subscriptions(&self, topic_ern: &str) -> Result<ListSubscriptionsResponse> {
        self.client
            .call("list-subscriptions", &json!({ "topicErn": topic_ern }))
            .await
    }
}
