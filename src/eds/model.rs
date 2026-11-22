//! Request and response types of the EDS (Euclid Domain Name Service) module.
//!
//! Field names are the wire names in camelCase. Response types default every field, so a field
//! the server leaves out reads as `None`/zero instead of failing the whole response.

use serde::{Deserialize, Serialize};

use crate::serde_util::{lenient_string, lenient_u64};

/// A zone the name server answers for authoritatively.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct HostedZone {
    /// The zone's apex, e.g. `"corp.example"`.
    #[serde(deserialize_with = "lenient_string")]
    pub name: Option<String>,
    /// `ern:eds:<region>:<account>:<namespace>:zone:<name>`.
    #[serde(deserialize_with = "lenient_string")]
    pub ern: Option<String>,
    /// The namespace that owns the zone.
    #[serde(deserialize_with = "lenient_string")]
    pub namespace: Option<String>,
    /// The zone's default TTL in seconds, used by records put without one.
    #[serde(deserialize_with = "lenient_u64")]
    pub ttl: u64,
    #[serde(deserialize_with = "lenient_string")]
    pub description: Option<String>,
    /// How many record sets the zone holds (the generated SOA and NS are not counted).
    #[serde(deserialize_with = "lenient_u64")]
    pub record_count: u64,
    /// The SOA serial: bumped on every change to the zone.
    #[serde(deserialize_with = "lenient_u64")]
    pub serial: u64,
    #[serde(deserialize_with = "lenient_string")]
    pub created: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub modified: Option<String>,
}

/// Every record of one type at one name of a zone.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RecordSet {
    #[serde(deserialize_with = "lenient_string")]
    pub zone: Option<String>,
    /// The owner name, as it was put.
    #[serde(deserialize_with = "lenient_string")]
    pub name: Option<String>,
    /// The type mnemonic, e.g. `"A"`.
    #[serde(rename = "type", deserialize_with = "lenient_string")]
    pub record_type: Option<String>,
    /// The TTL in seconds; 0 means the zone's.
    #[serde(deserialize_with = "lenient_u64")]
    pub ttl: u64,
    /// The values, in zone-file presentation form.
    pub values: Vec<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub created: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub modified: Option<String>,
}

/// One resource record of an [`Answer`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AnswerRecord {
    #[serde(deserialize_with = "lenient_string")]
    pub name: Option<String>,
    #[serde(rename = "type", deserialize_with = "lenient_string")]
    pub record_type: Option<String>,
    #[serde(deserialize_with = "lenient_u64")]
    pub ttl: u64,
    /// The record's data in presentation form.
    #[serde(deserialize_with = "lenient_string")]
    pub value: Option<String>,
}

/// What the name server answers for a question - the same answer a DNS client gets.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Answer {
    /// The name asked for.
    #[serde(deserialize_with = "lenient_string")]
    pub name: Option<String>,
    /// The type asked for.
    #[serde(rename = "type", deserialize_with = "lenient_string")]
    pub record_type: Option<String>,
    /// `true` when the name lies in one of the server's zones.
    pub authoritative: bool,
    /// The zone that answered; `None` when none of the server's zones holds the name.
    #[serde(deserialize_with = "lenient_string")]
    pub zone: Option<String>,
    /// `NOERROR`, `NXDOMAIN` or `REFUSED` (a name in none of the zones).
    #[serde(deserialize_with = "lenient_string")]
    pub rcode: Option<String>,
    /// The answer section.
    pub answers: Vec<AnswerRecord>,
    /// The authority section, e.g. the SOA of an NXDOMAIN or NODATA answer.
    pub authority: Vec<AnswerRecord>,
}

/// Body of `create-zone`.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateZoneRequest {
    /// The zone's apex, e.g. `"corp.example"`. Unique across the whole installation.
    pub name: String,
    /// The zone's default TTL in seconds; 0 lets the server choose.
    pub ttl: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl CreateZoneRequest {
    /// A zone with the default TTL and no description.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }
}

/// Prefix filter and paging for `list-zones`. The default lists every zone, unpaged.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListZonesRequest {
    /// Only zones whose name starts with this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// Zones per page; 0 returns them all.
    pub page_size: u64,
    /// Zero-based page, applied when `page_size` is set.
    pub page_index: u64,
}

/// Answer to `list-zones`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct ListZonesResponse {
    pub zones: Vec<HostedZone>,
    /// How many zones match, across all pages.
    #[serde(deserialize_with = "lenient_u64")]
    pub total: u64,
}

/// Body of `put-record`: every record of one type at one name, replacing those there.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PutRecordRequest {
    /// The zone's apex.
    pub zone: String,
    /// The owner name: `"@"` for the apex, a label relative to the zone (`"www"`), or a fully
    /// qualified name inside it. Defaults to `"@"`.
    pub name: String,
    /// The type mnemonic: A, AAAA, CNAME, MX, NS, PTR, SRV or TXT.
    #[serde(rename = "type")]
    pub record_type: String,
    /// The TTL in seconds; 0 means the zone's.
    pub ttl: u64,
    /// The values, in zone-file presentation form, e.g. `"10 mail.corp.example"` for MX.
    pub values: Vec<String>,
}

impl Default for PutRecordRequest {
    fn default() -> Self {
        Self {
            zone: String::new(),
            name: "@".into(),
            record_type: String::new(),
            ttl: 0,
            values: Vec::new(),
        }
    }
}

impl PutRecordRequest {
    /// The records of `record_type` at `name` in `zone`, with the zone's TTL.
    pub fn new<I, S>(
        zone: impl Into<String>,
        name: impl Into<String>,
        record_type: impl Into<String>,
        values: I,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            zone: zone.into(),
            name: name.into(),
            record_type: record_type.into(),
            ttl: 0,
            values: values.into_iter().map(Into::into).collect(),
        }
    }
}

/// Filters and paging for `list-records`. Each filter is sent only when set.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListRecordsRequest {
    /// The zone's apex.
    pub zone: String,
    /// Only record sets at this owner name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Only record sets of this type.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub record_type: Option<String>,
    /// Record sets per page; 0 returns them all.
    pub page_size: u64,
    /// Zero-based page, applied when `page_size` is set.
    pub page_index: u64,
}

impl ListRecordsRequest {
    /// Every record set of `zone`, unpaged.
    pub fn new(zone: impl Into<String>) -> Self {
        Self {
            zone: zone.into(),
            ..Default::default()
        }
    }
}

/// Answer to `list-records`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct ListRecordsResponse {
    pub records: Vec<RecordSet>,
    /// How many record sets match, across all pages.
    #[serde(deserialize_with = "lenient_u64")]
    pub total: u64,
}
