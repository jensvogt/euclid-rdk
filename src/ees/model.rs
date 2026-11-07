//! Request and response types of the EES (Euclid Event Service) module.
//!
//! Field names are the wire names in camelCase. Response types default every field, so a field
//! the server leaves out reads as `None`/zero/empty instead of failing the whole response.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::serde_util::{lenient_string, lenient_u64};

/// How long a received event stays claimed unless the receive says otherwise: 300 seconds.
pub const DEFAULT_VISIBILITY_TIMEOUT: u64 = 300;

/// The longest a receive waits for an event; the server clamps any longer `wait_time` to this.
pub const MAX_WAIT_TIME: u64 = 20;

/// Reads a JSON object; anything else (absent, `null`, another type) is empty.
fn object<'de, D: Deserializer<'de>>(d: D) -> Result<Map<String, Value>, D::Error> {
    Ok(match Option::<Value>::deserialize(d)? {
        Some(Value::Object(map)) => map,
        _ => Map::new(),
    })
}

// ---------------------------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------------------------

/// How a subscription delivers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum DeliveryMode {
    /// Every matching event is stored for the subscriber and kept until it is acknowledged, so
    /// nothing is lost while the subscriber is away. Receivers sharing a subscriber name compete:
    /// the claim in `receive-events` gives each event to exactly one of them.
    #[default]
    Durable,
    /// Nothing is stored: the event is pushed to whatever websocket sessions are attached to the
    /// name and is then gone.
    Live,
}

impl DeliveryMode {
    /// The spelling on the wire: `durable` or `live`.
    pub fn wire_value(self) -> &'static str {
        match self {
            Self::Durable => "durable",
            Self::Live => "live",
        }
    }

    /// `live` (any case) is [`Live`](Self::Live); anything else is [`Durable`](Self::Durable).
    pub fn from_wire_value(value: &str) -> Self {
        if value.eq_ignore_ascii_case("live") {
            Self::Live
        } else {
            Self::Durable
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
        Ok(lenient_string(d)?
            .map(|v| Self::from_wire_value(&v))
            .unwrap_or_default())
    }
}

// ---------------------------------------------------------------------------------------------
// Subscriptions
// ---------------------------------------------------------------------------------------------

/// One event type a subscriber has subscribed to.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EventSubscription {
    /// The subscriber name the subscription belongs to.
    pub subscriber: Option<String>,
    pub event_type: Option<String>,
    /// Payload fields an event has to match; empty for every event of the type.
    #[serde(deserialize_with = "object")]
    pub filter: Map<String, Value>,
    pub account_id: Option<String>,
    pub mode: DeliveryMode,
    #[serde(deserialize_with = "lenient_string")]
    pub created: Option<String>,
    /// When the subscriber last received.
    #[serde(deserialize_with = "lenient_string")]
    pub last_seen: Option<String>,
}

/// Body of `subscribe-events`.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscribeEventsRequest {
    /// The subscriber name: what receives and acknowledgements name. Required.
    pub name: String,
    /// Event types to subscribe to, one subscription each. At least one is required.
    pub event_types: Vec<String>,
    /// Payload fields an event has to match; empty for every event of these types.
    pub filter: Map<String, Value>,
    pub mode: DeliveryMode,
}

/// Answer to `subscribe-events`: every subscription the subscriber now has.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SubscribeEventsResponse {
    pub subscriptions: Vec<EventSubscription>,
}

/// Answer to `unsubscribe-events`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UnsubscribeEventsResponse {
    pub subscriber: Option<String>,
    /// How many subscriptions went.
    #[serde(deserialize_with = "lenient_u64")]
    pub removed: u64,
}

/// Answer to `list-subscriptions`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListSubscriptionsResponse {
    pub subscriptions: Vec<EventSubscription>,
    /// Events stored for the subscriber and not yet acknowledged.
    #[serde(deserialize_with = "lenient_u64")]
    pub waiting: u64,
}

// ---------------------------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------------------------

/// One event a receive claimed. Acknowledge it with its `event_id` once it is handled, or it
/// becomes claimable again when the visibility timeout runs out.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Event {
    pub event_id: Option<String>,
    pub event_type: Option<String>,
    /// The module that raised it, e.g. `esm`.
    pub source_module: Option<String>,
    #[serde(deserialize_with = "object")]
    pub payload: Map<String, Value>,
    /// How many times it has been handed out, this time included.
    #[serde(deserialize_with = "lenient_u64")]
    pub attempts: u64,
    #[serde(deserialize_with = "lenient_string")]
    pub created: Option<String>,
}

/// Body of `receive-events`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiveEventsRequest {
    pub name: String,
    /// Most events to claim; the server takes at least 1.
    pub max_events: u64,
    /// Seconds to wait for an event before answering empty; clamped to [`MAX_WAIT_TIME`].
    pub wait_time: u64,
    /// Seconds a claim holds before the events become claimable again.
    pub visibility_timeout: u64,
}

impl Default for ReceiveEventsRequest {
    /// Up to 10 events, no wait, [`DEFAULT_VISIBILITY_TIMEOUT`] - as euclid-jdk's
    /// `receiveEvents(name)`.
    fn default() -> Self {
        Self {
            name: String::new(),
            max_events: 10,
            wait_time: 0,
            visibility_timeout: DEFAULT_VISIBILITY_TIMEOUT,
        }
    }
}

/// Answer to `receive-events`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ReceiveEventsResponse {
    pub events: Vec<Event>,
    /// Events in this answer.
    #[serde(deserialize_with = "lenient_u64")]
    pub total: u64,
}

/// Answer to `ack-events`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AckEventsResponse {
    pub subscriber: Option<String>,
    /// How many of the events were still there to acknowledge. An event already acknowledged, or
    /// whose retention ran out, is not an error - it just does not count.
    #[serde(deserialize_with = "lenient_u64")]
    pub acknowledged: u64,
}
