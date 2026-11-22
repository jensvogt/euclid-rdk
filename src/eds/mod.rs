//! EDS - Euclid Domain Name Service.
//!
//! The zones the name server answers for authoritatively, the record sets in them, and what it
//! would answer for a question.
//!
//! EDS has two ports. This client manages zones and records through euclid's gateway, with the
//! session's credentials and grants; DNS queries themselves are served on UDP and TCP (port 1053
//! by default) to anybody who can reach it, which this client does not talk to -
//! [`Eds::get_answer`] shows the same answer without needing a DNS client.
//!
//! A zone's name is unique across the installation, not just the account, because a DNS question
//! names no account. Asking for another account's zone is answered with 404, the same as one that
//! does not exist. Each action needs the matching `eds:*` permission on the zone's ERN
//! (`ern:eds:<region>:<account>:<namespace>:zone:<name>`); a caller without it gets 403.

pub mod model;

pub use model::*;
use serde_json::json;

use crate::service::ServiceClient;
use crate::Result;

/// EDS operations, obtained from [`Session::eds`](crate::Session::eds).
///
/// Requests are SigV4-signed with the session's access key when it has one, otherwise
/// authenticated with the bearer token. Cloning is cheap.
#[derive(Debug, Clone)]
pub struct Eds {
    client: ServiceClient,
}

impl Eds {
    pub(crate) fn new(client: ServiceClient) -> Self {
        Self { client }
    }

    // ── Zones ────────────────────────────────────────────────────────────────

    /// Creates a zone, which the name server answers for from then on: with the records put into
    /// it, and with NXDOMAIN for every other name below it. The zone is owned by the session's
    /// account and namespace, and gets an SOA and NS record without being asked.
    ///
    /// Fails with 400 if the name is not a valid zone name, lies in the service domain or the TTL
    /// is out of range, 403 without `eds:create-zone`, or 409 if a zone of that name exists
    /// already - in any account.
    pub async fn create_zone(&self, request: &CreateZoneRequest) -> Result<HostedZone> {
        self.client.call("create-zone", request).await
    }

    /// Retrieves a zone: its TTL, its SOA serial and how many record sets it holds.
    ///
    /// Fails with 404 if no zone of that name belongs to the account.
    pub async fn get_zone(&self, name: &str) -> Result<HostedZone> {
        self.client.call("get-zone", &json!({ "name": name })).await
    }

    /// Lists a page of the zones of the session's account and namespace, optionally only those
    /// whose name starts with a prefix. A zone the caller's grants do not let it read is left off
    /// the page. `ListZonesRequest::default()` lists them all.
    pub async fn list_zones(&self, request: &ListZonesRequest) -> Result<ListZonesResponse> {
        self.client.call("list-zones", request).await
    }

    /// Deletes a zone and every record in it, returning how many record sets went with it. Names
    /// in it stop resolving at once; resolvers that cached them keep them for up to their TTL.
    ///
    /// Fails with 404 if no zone of that name belongs to the account.
    pub async fn delete_zone(&self, name: &str) -> Result<u64> {
        let deleted: Deleted = self.client.call("delete-zone", &json!({ "name": name })).await?;
        Ok(deleted.deleted_records)
    }

    // ── Records ──────────────────────────────────────────────────────────────

    /// Writes every record of one type at one name, replacing those there in one step - there is
    /// never a moment when half the old values and half the new ones are served.
    ///
    /// Fails with 400 if the name is not in the zone, the type is not storable, a value cannot be
    /// encoded, there are no values, or a CNAME has more than one value or is put at the apex; 404
    /// if the zone does not belong to the account; or 409 if a CNAME would sit beside other
    /// records.
    pub async fn put_record(&self, request: &PutRecordRequest) -> Result<RecordSet> {
        self.client.call("put-record", request).await
    }

    /// Removes every record of one type at one name. A `name` of `None` is the apex (`"@"`).
    ///
    /// Fails with 400 if the name is not in the zone or no type is given, or 404 if the zone does
    /// not belong to the account or holds no such records.
    pub async fn delete_record(&self, zone: &str, name: Option<&str>, record_type: &str) -> Result<()> {
        self.client
            .call_unit(
                "delete-record",
                &json!({ "zone": zone, "name": name.unwrap_or("@"), "type": record_type }),
            )
            .await
    }

    /// Lists a page of a zone's record sets, by name and type, with their values as they were put.
    /// The SOA and NS records the server makes for every zone are not stored, so they are not
    /// listed.
    ///
    /// Fails with 400 if the name is not in the zone or the type is unknown, or 404 if the zone
    /// does not belong to the account.
    pub async fn list_records(&self, request: &ListRecordsRequest) -> Result<ListRecordsResponse> {
        self.client.call("list-records", request).await
    }

    // ── Lookups ──────────────────────────────────────────────────────────────

    /// Shows what the name server answers for a name, from the zones it holds - the same answer a
    /// DNS client gets, without needing one. A `record_type` of `None` means `A`.
    ///
    /// A name in none of its zones comes back `REFUSED`; the DNS port forwards those instead, when
    /// forwarders are configured. Not checked against the caller's grants on any zone, since
    /// anybody who can reach the DNS port gets the same answer. Fails with 400 if the type is
    /// unknown.
    pub async fn get_answer(&self, name: &str, record_type: Option<&str>) -> Result<Answer> {
        let body = match record_type {
            Some(record_type) => json!({ "name": name, "type": record_type }),
            None => json!({ "name": name }),
        };
        let mut answer: Answer = self.client.call("get-answer", &body).await?;
        // A refused answer names the zone as "" rather than leaving it out.
        if answer.zone.as_deref() == Some("") {
            answer.zone = None;
        }
        Ok(answer)
    }
}

#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct Deleted {
    #[serde(deserialize_with = "crate::serde_util::lenient_u64")]
    deleted_records: u64,
}
