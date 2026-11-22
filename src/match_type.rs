//! The match type shared by every listing that filters by name.

use serde::{Deserialize, Serialize};

/// How a listing's `prefix` is matched against names or keys.
///
/// Every type but [`Regex`](MatchType::Regex) takes the text literally, so `"a.b"` does not also
/// find `"aXb"`. A regex is compiled by the server first; one that does not compile is refused
/// with HTTP 400 rather than read as "no filter". Leaving the match type unset is the same as
/// [`Prefix`](MatchType::Prefix).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MatchType {
    /// Starts with the text.
    #[default]
    Prefix,
    /// Ends with the text.
    EndsWith,
    /// Contains the text anywhere.
    Contains,
    /// Matches the text as a regular expression.
    Regex,
}

impl MatchType {
    /// The wire spelling: `prefix`, `endsWith`, `contains`, `regex`.
    pub fn wire_value(self) -> &'static str {
        match self {
            MatchType::Prefix => "prefix",
            MatchType::EndsWith => "endsWith",
            MatchType::Contains => "contains",
            MatchType::Regex => "regex",
        }
    }
}
