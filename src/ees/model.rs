//! Request and response types of the EES (Euclid Event Service) module.
//!
//! Field names are the wire names in camelCase. Response types default every field, so a field
//! the server leaves out reads as `None`/zero/empty instead of failing the whole response.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::serde_util::{lenient_string, lenient_u64};

/// `esm.object.created`: an object was first written.
pub const ESM_OBJECT_CREATED: &str = "esm.object.created";
/// `esm.object.updated`: an existing object was replaced or otherwise changed.
pub const ESM_OBJECT_UPDATED: &str = "esm.object.updated";
/// `esm.object.deleted`: an object was deleted, including the source of a move.
pub const ESM_OBJECT_DELETED: &str = "esm.object.deleted";

// ---------------------------------------------------------------------------------------------
// Delivery mode
// ---------------------------------------------------------------------------------------------

/// How a subscriber's events reach it: kept until acknowledged, or only seen while connected.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum DeliveryMode {
    /// Every matching event is stored for the subscriber until it is acknowledged, so nothing is
    /// lost while the subscriber is away. A connected client is told that something is waiting
    /// rather than sent the event: instances sharing a name decide who processes it by claiming.
    #[default]
    Durable,
    /// Nothing is stored. The event is pushed to the WebSocket sessions attached to the name and
    /// is then gone - what a view wants, and what costs no database write per event.
    Live,
}

impl DeliveryMode {
    /// The wire value: `"durable"` or `"live"`.
    pub fn wire_value(self) -> &'static str {
        match self {
            DeliveryMode::Durable => "durable",
            DeliveryMode::Live => "live",
        }
    }

    /// Reads a wire value, defaulting to [`Durable`](Self::Durable) for anything unrecognised -
    /// losing events because a mode was misspelled would be the worse failure.
    pub fn from_wire_value(value: &str) -> Self {
        if value.eq_ignore_ascii_case("live") {
            DeliveryMode::Live
        } else {
            DeliveryMode::Durable
        }
    }
}

impl Serialize for DeliveryMode {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.wire_value())
    }
}

impl<'de> Deserialize<'de> for DeliveryMode {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = Option::<Value>::deserialize(d)?;
        Ok(DeliveryMode::from_wire_value(
            value.as_ref().and_then(Value::as_str).unwrap_or_default(),
        ))
    }
}

// ---------------------------------------------------------------------------------------------
// Subscriptions
// ---------------------------------------------------------------------------------------------

/// Body of `subscribe-events`.
///
/// The filter is evaluated where the event is published, so a subscriber only accumulates what
/// it asked for; an empty filter means every event of these types. Subscribing again with the
/// same name and type replaces the filter and mode.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscribeEventsRequest {
    /// The subscriber name. Instances of one application share it (each event is handled once);
    /// different applications use different names (each gets its own copy).
    pub name: String,
    /// Event types, e.g. [`ESM_OBJECT_CREATED`].
    pub event_types: Vec<String>,
    /// Exact-match key/value pairs the payload must satisfy, e.g. `{"bucketErn": "..."}`.
    pub filter: Map<String, Value>,
    /// `None` sends `null`, which the server reads as durable.
    pub mode: Option<DeliveryMode>,
}

impl Default for SubscribeEventsRequest {
    fn default() -> Self {
        Self {
            name: String::new(),
            event_types: Vec::new(),
            filter: Map::new(),
            mode: Some(DeliveryMode::Durable),
        }
    }
}

/// One subscription: a subscriber name, one event type and its filter.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EventSubscription {
    pub subscriber: Option<String>,
    pub event_type: Option<String>,
    #[serde(deserialize_with = "object_or_empty")]
    pub filter: Map<String, Value>,
    pub account_id: Option<String>,
    pub mode: DeliveryMode,
    #[serde(deserialize_with = "lenient_string")]
    pub created: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub last_seen: Option<String>,
}

/// Answer to `subscribe-events`: every subscription the name now has.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SubscribeEventsResponse {
    pub subscriptions: Vec<EventSubscription>,
}

/// Answer to `unsubscribe-events`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UnsubscribeEventsResponse {
    pub subscriber: Option<String>,
    /// How many subscriptions were removed.
    #[serde(deserialize_with = "lenient_u64")]
    pub removed: u64,
}

/// Answer to `list-subscriptions`.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListSubscriptionsResponse {
    pub subscriptions: Vec<EventSubscription>,
    /// Events stored for the name and not yet acknowledged.
    #[serde(deserialize_with = "lenient_u64")]
    pub waiting: u64,
}

// ---------------------------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------------------------

/// One event, as `receive-events` claims it (or as a live WebSocket subscription pushes it, in
/// which case only `event_type` and `payload` are set).
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Event {
    /// What [`Ees::ack_events`](crate::Ees::ack_events) takes.
    pub event_id: Option<String>,
    pub event_type: Option<String>,
    pub source_module: Option<String>,
    #[serde(deserialize_with = "object_or_empty")]
    pub payload: Map<String, Value>,
    /// How often the event has been claimed.
    #[serde(deserialize_with = "lenient_u64")]
    pub attempts: u64,
    #[serde(deserialize_with = "lenient_string")]
    pub created: Option<String>,
}

impl Event {
    /// The payload of an `esm.object.*` event, typed. `None` for any other event type.
    pub fn esm_object(&self) -> Option<EsmObjectEvent> {
        let event_type = self.event_type.as_deref()?;
        if !event_type.starts_with("esm.object.") {
            return None;
        }
        serde_json::from_value(Value::Object(self.payload.clone())).ok()
    }
}

/// The flat payload all three ESM object events carry. Its values are strings, numbers and
/// booleans precisely so a filter can match them by equality: `{"bucketErn": ..}` for one bucket,
/// `{"prefix": "invoices/2026/"}` for one "directory", `{"directory": false}` to skip markers.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EsmObjectEvent {
    pub ern: Option<String>,
    pub bucket_ern: Option<String>,
    pub bucket_name: Option<String>,
    pub key: Option<String>,
    pub prefix: Option<String>,
    pub directory: bool,
    #[serde(deserialize_with = "lenient_u64")]
    pub size: u64,
    pub content_type: Option<String>,
    pub md5_sum: Option<String>,
    /// Who uploaded the object.
    pub owner: Option<String>,
    /// Who made this change - differs from `owner` for a move performed by an operator.
    pub user_id: Option<String>,
    pub account_id: Option<String>,
    pub region: Option<String>,
    pub namespace: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub event_time: Option<String>,
}

/// Answer to `receive-events`.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ReceiveEventsResponse {
    pub events: Vec<Event>,
    #[serde(deserialize_with = "lenient_u64")]
    pub total: u64,
}

/// Answer to `ack-events`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AckEventsResponse {
    pub subscriber: Option<String>,
    /// How many of the given events were deleted.
    #[serde(deserialize_with = "lenient_u64")]
    pub acknowledged: u64,
}

/// Reads a JSON object, treating anything else (absent, null, a scalar) as empty - as the JDK
/// reads payloads and filters, whose shape is decided by the event type.
fn object_or_empty<'de, D: Deserializer<'de>>(d: D) -> Result<Map<String, Value>, D::Error> {
    Ok(match Option::<Value>::deserialize(d)? {
        Some(Value::Object(map)) => map,
        _ => Map::new(),
    })
}
