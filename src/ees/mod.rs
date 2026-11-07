//! EES - Euclid Event Service: durable subscriptions to events from ESM and the other modules.
//!
//! A subscriber is a name, not a connection. Subscribing it to event types makes EES keep every
//! matching event for it (in [`DeliveryMode::Durable`]) until it is received and acknowledged;
//! several processes sharing the name compete for the events, each one going to exactly one of
//! them.

pub mod model;

use std::time::Duration;

pub use model::*;
use serde_json::json;

use crate::service::{CallOptions, ServiceClient};
use crate::Result;

/// Extra time a long poll's request gets beyond the wait it asked for: the server answers at the
/// end of the window, so a timeout of exactly that window would race the answer.
const LONG_POLL_RESPONSE_MARGIN: Duration = Duration::from_secs(10);

/// EES operations, obtained from [`Session::ees`](crate::Session::ees).
///
/// Requests are SigV4-signed with the session's access key when it has one, otherwise
/// authenticated with the bearer token. Cloning is cheap.
#[derive(Debug, Clone)]
pub struct Ees {
    client: ServiceClient,
}

impl Ees {
    pub(crate) fn new(client: ServiceClient) -> Self {
        Self { client }
    }

    // -----------------------------------------------------------------------------------------
    // Subscriptions
    // -----------------------------------------------------------------------------------------

    /// Subscribes `name` to every event of `event_types`, durably.
    pub async fn subscribe_events(&self, name: &str, event_types: &[&str]) -> Result<SubscribeEventsResponse> {
        self.subscribe_events_with(&SubscribeEventsRequest {
            name: name.into(),
            event_types: event_types.iter().map(|t| (*t).to_owned()).collect(),
            ..Default::default()
        })
        .await
    }

    /// Subscribes with a payload filter and a delivery mode. Answers with all of the subscriber's
    /// subscriptions.
    pub async fn subscribe_events_with(&self, request: &SubscribeEventsRequest) -> Result<SubscribeEventsResponse> {
        self.client.call("subscribe-events", request).await
    }

    /// Removes every subscription of `name`.
    pub async fn unsubscribe_events(&self, name: &str) -> Result<UnsubscribeEventsResponse> {
        self.unsubscribe_event_type(name, "").await
    }

    /// Removes the subscription of `name` to one event type; an empty `event_type` removes all.
    pub async fn unsubscribe_event_type(&self, name: &str, event_type: &str) -> Result<UnsubscribeEventsResponse> {
        let body = json!({ "name": name, "eventType": event_type });
        self.client.call("unsubscribe-events", &body).await
    }

    /// The subscriptions of `name`, and how many events are waiting for it.
    pub async fn list_subscriptions(&self, name: &str) -> Result<ListSubscriptionsResponse> {
        self.client.call("list-subscriptions", &json!({ "name": name })).await
    }

    // -----------------------------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------------------------

    /// Claims up to 10 events for `name` without waiting, for [`DEFAULT_VISIBILITY_TIMEOUT`]
    /// seconds.
    pub async fn receive_events(&self, name: &str) -> Result<ReceiveEventsResponse> {
        self.receive_events_with(&ReceiveEventsRequest {
            name: name.into(),
            ..Default::default()
        })
        .await
    }

    /// Claims events, waiting up to `wait_time` seconds (at most [`MAX_WAIT_TIME`]) for any to
    /// arrive. A claimed event is invisible to other receivers for `visibility_timeout` seconds;
    /// acknowledge it with [`ack_events`](Self::ack_events) before then or it is handed out again.
    pub async fn receive_events_with(&self, request: &ReceiveEventsRequest) -> Result<ReceiveEventsResponse> {
        let options = CallOptions {
            timeout: Some(Duration::from_secs(request.wait_time.min(MAX_WAIT_TIME)) + LONG_POLL_RESPONSE_MARGIN),
            ..Default::default()
        };
        let value = self.client.call_value_with("receive-events", request, &options).await?;
        Ok(serde_json::from_value(value)?)
    }

    /// Acknowledges one handled event.
    pub async fn ack_event(&self, name: &str, event_id: &str) -> Result<AckEventsResponse> {
        self.ack_events(name, &[event_id]).await
    }

    /// Acknowledges handled events, removing them for good. Events no longer there are not an
    /// error; `acknowledged` counts the ones that were.
    pub async fn ack_events(&self, name: &str, event_ids: &[&str]) -> Result<AckEventsResponse> {
        let body = json!({ "name": name, "eventIds": event_ids });
        self.client.call("ack-events", &body).await
    }
}
