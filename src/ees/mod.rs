//! EES - Euclid Event Service: durable subscriptions to events from ESM and the other modules.
//!
//! A subscriber registers a durable *name* and pulls. Nothing has to be created beforehand:
//! [`Ees::receive_events`] claims waiting events and [`Ees::ack_events`] deletes them, and an
//! event that is claimed but never acknowledged becomes claimable again when its visibility
//! timeout runs out - so a consumer that crashes mid-work loses nothing.
//!
//! The name decides fan-out. Two *instances* of one application share a name, so whichever claims
//! an event first processes it; two *different* applications use different names and each receive
//! their own copy.
//!
//! The ESM object events - [`ESM_OBJECT_CREATED`], [`ESM_OBJECT_UPDATED`], [`ESM_OBJECT_DELETED`]
//! - carry the flat payload [`EsmObjectEvent`] describes ([`Event::esm_object`]).
//!
//! With the `ws` feature, `EventStream` and `EventListener` replace the poll loop with events
//! pushed over a WebSocket.

#[cfg(feature = "ws")]
mod listener;
pub mod model;
#[cfg(feature = "ws")]
mod stream;

use std::time::Duration;

#[cfg(feature = "ws")]
pub use listener::{EventListener, EventListenerBuilder};
pub use model::*;
use serde_json::{json, Map, Value};
#[cfg(feature = "ws")]
pub use stream::{EventStream, EventStreamListener, ListenerId, StreamFrame};

use crate::service::{CallOptions, ServiceClient};
use crate::Result;

/// Timeout of a `receive-events` request: the server waits at most 20 s, so 30 s leaves room for
/// the answer, as the JDK's long-poll client does.
const LONG_POLL_TIMEOUT: Duration = Duration::from_secs(30);

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

    /// Subscribes `name` to every event of `event_types`, durably and without a filter.
    pub async fn subscribe_events(&self, name: &str, event_types: &[&str]) -> Result<SubscribeEventsResponse> {
        self.subscribe_events_with(&SubscribeEventsRequest {
            name: name.into(),
            event_types: event_types.iter().map(|t| (*t).to_owned()).collect(),
            ..Default::default()
        })
        .await
    }

    /// Subscribes with a filter and/or delivery mode. Subscribing again with the same name and
    /// event type replaces its filter and mode rather than adding a second subscription.
    pub async fn subscribe_events_with(&self, request: &SubscribeEventsRequest) -> Result<SubscribeEventsResponse> {
        self.client.call("subscribe-events", request).await
    }

    /// Removes every subscription of `name`.
    pub async fn unsubscribe_events(&self, name: &str) -> Result<UnsubscribeEventsResponse> {
        self.unsubscribe_event_type(name, "").await
    }

    /// Removes the subscription of `name` to one event type; an empty type removes them all.
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

    /// Claims up to 10 waiting events without waiting, hidden from other claims for 300 s.
    pub async fn receive_events(&self, name: &str) -> Result<ReceiveEventsResponse> {
        self.receive_events_with(name, 10, 0, 300).await
    }

    /// Claims up to `max_events` events, waiting up to `wait_time` seconds (the server caps it at
    /// 20) for one to arrive. A claimed event is hidden from other claims for
    /// `visibility_timeout` seconds; acknowledge it within that or it is delivered again.
    pub async fn receive_events_with(
        &self,
        name: &str,
        max_events: u64,
        wait_time: u64,
        visibility_timeout: u64,
    ) -> Result<ReceiveEventsResponse> {
        let body = json!({
            "name": name,
            "maxEvents": max_events,
            "waitTime": wait_time,
            "visibilityTimeout": visibility_timeout,
        });
        let options = CallOptions {
            timeout: Some(LONG_POLL_TIMEOUT.max(Duration::from_secs(wait_time) + Duration::from_secs(10))),
            ..Default::default()
        };
        let value = self.client.call_value_with("receive-events", &body, &options).await?;
        Ok(serde_json::from_value(value)?)
    }

    /// Acknowledges (deletes) one claimed event.
    pub async fn ack_event(&self, name: &str, event_id: &str) -> Result<AckEventsResponse> {
        self.ack_events(name, &[event_id]).await
    }

    /// Acknowledges (deletes) claimed events.
    pub async fn ack_events<S: AsRef<str>>(&self, name: &str, event_ids: &[S]) -> Result<AckEventsResponse> {
        let ids: Vec<&str> = event_ids.iter().map(AsRef::as_ref).collect();
        self.client
            .call("ack-events", &json!({ "name": name, "eventIds": ids }))
            .await
    }

    // -----------------------------------------------------------------------------------------
    // WebSocket stream
    // -----------------------------------------------------------------------------------------

    /// A WebSocket event stream on the same server and identity as this client, signing its
    /// handshake as `ees`. Nothing connects until the first subscribe, attach or wait.
    #[cfg(feature = "ws")]
    pub fn event_stream(&self) -> EventStream {
        EventStream::new(&self.client, "ees")
    }
}

/// A filter of exact-match string pairs, e.g. `filter([("bucketName", "inbox")])`, for
/// [`SubscribeEventsRequest::filter`].
pub fn filter<K: Into<String>, V: Into<String>>(pairs: impl IntoIterator<Item = (K, V)>) -> Map<String, Value> {
    pairs
        .into_iter()
        .map(|(k, v)| (k.into(), Value::String(v.into())))
        .collect()
}
