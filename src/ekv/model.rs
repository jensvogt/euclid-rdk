//! Request and response types of the EKV (Euclid Key-Value store) module.
//!
//! Items are plain JSON objects: attribute name to JSON value, with the table's partition key
//! (and sort key, if it has one) among them. The server's bookkeeping attributes `_created` and
//! `_modified` are split off into [`Item::created`]/[`Item::modified`].

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

pub use crate::eam::SortDirection;
use crate::serde_util::{lenient_string, lenient_u64};

const CREATED_ATTRIBUTE: &str = "_created";
const MODIFIED_ATTRIBUTE: &str = "_modified";

/// An item's attributes by name.
pub type Attributes = Map<String, Value>;

// ---------------------------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------------------------

/// Type of a table's partition or sort key.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    #[default]
    String,
    Number,
    Binary,
}

impl KeyType {
    /// The wire spelling: `string`, `number`, `binary`.
    pub fn wire_value(self) -> &'static str {
        match self {
            KeyType::String => "string",
            KeyType::Number => "number",
            KeyType::Binary => "binary",
        }
    }

    /// Parses a wire value case-insensitively; empty or unknown values give `None`.
    pub fn from_wire_value(value: &str) -> Option<Self> {
        [KeyType::String, KeyType::Number, KeyType::Binary]
            .into_iter()
            .find(|t| t.wire_value().eq_ignore_ascii_case(value))
    }
}

fn lenient_key_type<'de, D: Deserializer<'de>>(d: D) -> Result<Option<KeyType>, D::Error> {
    Ok(lenient_string(d)?.as_deref().and_then(KeyType::from_wire_value))
}

/// Condition on the sort key in a [`QueryRequest`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize)]
pub enum SortOperator {
    /// No condition: every item of the partition.
    #[default]
    #[serde(rename = "")]
    None,
    #[serde(rename = "eq")]
    Eq,
    #[serde(rename = "lt")]
    Lt,
    #[serde(rename = "le")]
    Le,
    #[serde(rename = "gt")]
    Gt,
    #[serde(rename = "ge")]
    Ge,
    /// Between `sort_value` and `sort_upper`, inclusive.
    #[serde(rename = "between")]
    Between,
    /// Sort key starts with `sort_value`.
    #[serde(rename = "begins-with")]
    BeginsWith,
}

// ---------------------------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------------------------

/// A table, as `create-table`, `get-table` and listings describe it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TableDescription {
    pub name: Option<String>,
    pub ern: Option<String>,
    pub partition_key: Option<String>,
    #[serde(deserialize_with = "lenient_key_type")]
    pub partition_key_type: Option<KeyType>,
    /// `None` for a table without a sort key (the server sends an empty string).
    #[serde(deserialize_with = "empty_to_none")]
    pub sort_key: Option<String>,
    #[serde(deserialize_with = "lenient_key_type")]
    pub sort_key_type: Option<KeyType>,
    #[serde(deserialize_with = "lenient_u64")]
    pub item_count: u64,
    #[serde(deserialize_with = "lenient_string")]
    pub created: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub modified: Option<String>,
}

impl TableDescription {
    pub fn has_sort_key(&self) -> bool {
        self.sort_key.as_deref().is_some_and(|k| !k.is_empty())
    }
}

fn empty_to_none<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Ok(lenient_string(d)?.filter(|s| !s.is_empty()))
}

/// Body of `create-table`. Both key types default to `string`; an empty `sort_key` means the table
/// has a partition key only.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTableRequest {
    pub name: String,
    pub partition_key: String,
    pub partition_key_type: KeyType,
    pub sort_key: String,
    pub sort_key_type: KeyType,
}

/// Paging and sorting for `list-tables`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListTablesRequest {
    pub prefix: String,
    pub page_size: u64,
    pub page_index: u64,
    pub sort_column: String,
    pub sort_direction: SortDirection,
}

impl Default for ListTablesRequest {
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListTablesResponse {
    pub tables: Vec<TableDescription>,
    #[serde(deserialize_with = "lenient_u64")]
    pub total: u64,
}

// ---------------------------------------------------------------------------------------------
// Items
// ---------------------------------------------------------------------------------------------

/// One item: its attributes, and when the server created and last modified it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Item {
    /// Every attribute except the bookkeeping `_created`/`_modified`.
    pub attributes: Attributes,
    pub created: Option<String>,
    pub modified: Option<String>,
}

impl Item {
    /// An attribute's value.
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.attributes.get(name)
    }

    /// An attribute's value as a string, if it is one.
    pub fn get_str(&self, name: &str) -> Option<&str> {
        self.get(name).and_then(Value::as_str)
    }

    /// Splits an item object into attributes and bookkeeping; `None` if `value` is no object.
    pub(crate) fn from_value(value: Value) -> Option<Self> {
        let Value::Object(mut attributes) = value else {
            return None;
        };
        let text = |v: Option<Value>| {
            v.and_then(|v| match v {
                Value::Null => None,
                Value::String(s) => Some(s),
                other => Some(other.to_string()),
            })
        };
        let created = text(attributes.remove(CREATED_ATTRIBUTE));
        let modified = text(attributes.remove(MODIFIED_ATTRIBUTE));
        Some(Self {
            attributes,
            created,
            modified,
        })
    }
}

impl<'de> Deserialize<'de> for Item {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Item::from_value(Value::deserialize(d)?).unwrap_or_default())
    }
}

/// Body of `query`: the items of one partition, optionally narrowed by a condition on the sort
/// key. A page size of 0 returns every match.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryRequest {
    pub table: String,
    pub partition_key: Value,
    pub sort_operator: SortOperator,
    /// Operand of the sort condition; the lower bound for [`SortOperator::Between`].
    pub sort_value: Value,
    /// Upper bound for [`SortOperator::Between`].
    pub sort_upper: Value,
    /// Ascending by sort key when `true`, descending otherwise.
    pub forward: bool,
    pub page_size: u64,
    pub page_index: u64,
}

impl Default for QueryRequest {
    fn default() -> Self {
        Self {
            table: String::new(),
            partition_key: Value::Null,
            sort_operator: SortOperator::None,
            sort_value: Value::Null,
            sort_upper: Value::Null,
            forward: true,
            page_size: 0,
            page_index: 0,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueryResponse {
    pub items: Vec<Item>,
    /// Items returned; the server's figure, or the number of items when it sends none.
    pub count: u64,
    /// Items matching the query across all pages - what tells a caller paging through a partition
    /// that there is a page after this one. Falls back to `count` from a server that sends none.
    pub total: u64,
}

/// Body of `scan`: a table's items regardless of their key, optionally narrowed by when they were
/// last written and by a condition on any one attribute. A page size of 0 returns every match.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanRequest {
    pub table: String,
    pub page_size: u64,
    pub page_index: u64,
    /// What to order by: `pk`, `sk` or `modified`. Anything else, the empty string included, is
    /// key order.
    pub sort_column: String,
    pub sort_direction: SortDirection,
    /// ISO-8601 lower bound on when an item was last written; empty for none.
    pub modified_from: String,
    /// ISO-8601 upper bound on when an item was last written; empty for none.
    pub modified_to: String,
    /// An attribute to compare (any attribute, not only a key), or empty for none.
    pub attribute_name: String,
    /// How to compare it, in the vocabulary a query uses for the sort key.
    /// [`SortOperator::None`] narrows nothing.
    pub attribute_operator: SortOperator,
    /// Operand of the attribute condition; the lower bound for [`SortOperator::Between`]. Typed as
    /// written, so a number compares as a number.
    pub attribute_value: Value,
    /// Upper bound for [`SortOperator::Between`].
    pub attribute_upper: Value,
}

impl Default for ScanRequest {
    fn default() -> Self {
        Self {
            table: String::new(),
            page_size: 0,
            page_index: 0,
            sort_column: String::new(),
            sort_direction: SortDirection::Asc,
            modified_from: String::new(),
            modified_to: String::new(),
            attribute_name: String::new(),
            attribute_operator: SortOperator::None,
            attribute_value: Value::Null,
            attribute_upper: Value::Null,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanResponse {
    pub items: Vec<Item>,
    /// Items on this page.
    pub count: u64,
    /// Items in the whole table.
    pub total: u64,
}

/// What `query` and `scan` answer, before `count` falls back to the number of items.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub(crate) struct RawItems {
    pub items: Vec<Item>,
    pub count: Option<u64>,
    pub total: Option<u64>,
}
