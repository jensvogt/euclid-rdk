//! The typed value euclid uses for message and object attributes.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A typed value, `{"type": "string", "value": "..."}` on the wire - an EQS/ENS message
/// attribute or an ESM object attribute.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Variant {
    /// The value's type name, e.g. `"string"`, `"number"`, `"bool"`.
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub value: Value,
}

impl Variant {
    pub fn new(kind: impl Into<String>, value: impl Into<Value>) -> Self {
        Self {
            kind: kind.into(),
            value: value.into(),
        }
    }

    /// A `"string"` variant.
    pub fn string(value: impl Into<String>) -> Self {
        Self::new("string", value.into())
    }

    /// The value as text, the way euclid-jdk reads it: a string as itself, anything else as JSON.
    pub fn as_text(&self) -> Option<String> {
        match &self.value {
            Value::Null => None,
            Value::String(s) => Some(s.clone()),
            other => Some(other.to_string()),
        }
    }
}
