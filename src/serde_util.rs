//! Lenient deserialization helpers shared by the module models.

use serde::{Deserialize, Deserializer};

/// Reads a string field that may arrive as a string, a number or a bool - timestamps in
/// particular - the way Jackson's `asText()` does. Use with `#[serde(default, deserialize_with = ..)]`.
pub(crate) fn lenient_string<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Ok(match Option::<serde_json::Value>::deserialize(d)? {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) => Some(s),
        Some(other) => Some(other.to_string()),
    })
}

/// Reads an integer that may arrive as a number or a numeric string; anything else is 0.
pub(crate) fn lenient_u64<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    Ok(match Option::<serde_json::Value>::deserialize(d)? {
        Some(serde_json::Value::Number(n)) => n.as_u64().or_else(|| n.as_f64().map(|f| f as u64)).unwrap_or(0),
        Some(serde_json::Value::String(s)) => s.trim().parse().unwrap_or(0),
        _ => 0,
    })
}

pub(crate) fn default_true() -> bool {
    true
}
