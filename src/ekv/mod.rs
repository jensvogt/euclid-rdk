//! EKV - Euclid Key-Value store.
//!
//! Tables hold items addressed by a partition key and, optionally, a sort key. An item is a JSON
//! object; keys and items can be passed as anything that serializes to one, e.g. `json!({..})`
//! or a `#[derive(Serialize)]` struct.

pub mod model;

use serde::Serialize;
use serde_json::{json, Value};

pub use model::*;

use crate::service::ServiceClient;
use crate::{Error, Result};

/// EKV operations, obtained from [`Session::ekv`](crate::Session::ekv).
///
/// Requests are SigV4-signed with the session's access key when it has one, otherwise
/// authenticated with the bearer token. Cloning is cheap.
#[derive(Debug, Clone)]
pub struct Ekv {
    client: ServiceClient,
}

impl Ekv {
    pub(crate) fn new(client: ServiceClient) -> Self {
        Self { client }
    }

    // -----------------------------------------------------------------------------------------
    // Tables
    // -----------------------------------------------------------------------------------------

    /// Creates a table keyed by `partition_key` and, if given, `sort_key` - both of type
    /// `string`. Use [`create_table_with`](Self::create_table_with) for other key types.
    pub async fn create_table(
        &self,
        name: &str,
        partition_key: &str,
        sort_key: Option<&str>,
    ) -> Result<TableDescription> {
        self.create_table_with(&CreateTableRequest {
            name: name.into(),
            partition_key: partition_key.into(),
            sort_key: sort_key.unwrap_or_default().into(),
            ..Default::default()
        })
        .await
    }

    pub async fn create_table_with(&self, request: &CreateTableRequest) -> Result<TableDescription> {
        self.client.call("create-table", request).await
    }

    pub async fn get_table(&self, name: &str) -> Result<TableDescription> {
        self.client.call("get-table", &json!({ "name": name })).await
    }

    /// Whether a table of that name exists: `false` on a 404, any other failure is an error.
    pub async fn exists_table(&self, name: &str) -> Result<bool> {
        match self.get_table(name).await {
            Ok(_) => Ok(true),
            Err(Error::Service { status: 404, .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub async fn list_tables(&self, request: &ListTablesRequest) -> Result<ListTablesResponse> {
        self.client.call("list-tables", request).await
    }

    /// Deletes a table and everything in it; returns how many items went with it.
    pub async fn delete_table(&self, name: &str) -> Result<u64> {
        let root = self.client.call_value("delete-table", &json!({ "name": name })).await?;
        Ok(root.get("deletedItems").and_then(Value::as_u64).unwrap_or(0))
    }

    // -----------------------------------------------------------------------------------------
    // Items
    // -----------------------------------------------------------------------------------------

    /// Writes an item, replacing any item with the same key. `item` must include the table's key
    /// attributes. Returns the item as stored.
    pub async fn put_item(&self, table: &str, item: &impl Serialize) -> Result<Item> {
        let root = self
            .client
            .call_value("put-item", &json!({ "table": table, "item": item }))
            .await?;
        Ok(Item::from_value(root).unwrap_or_default())
    }

    /// Reads the item with `key` (partition key, plus sort key if the table has one).
    pub async fn get_item(&self, table: &str, key: &impl Serialize) -> Result<Item> {
        let root = self
            .client
            .call_value("get-item", &json!({ "table": table, "key": key }))
            .await?;
        Ok(Item::from_value(root).unwrap_or_default())
    }

    /// Deletes the item with `key`; `false` if there was none.
    pub async fn delete_item(&self, table: &str, key: &impl Serialize) -> Result<bool> {
        let root = self
            .client
            .call_value("delete-item", &json!({ "table": table, "key": key }))
            .await?;
        Ok(root.get("deleted").and_then(Value::as_bool).unwrap_or(false))
    }

    // -----------------------------------------------------------------------------------------
    // Query and scan
    // -----------------------------------------------------------------------------------------

    /// Every item of one partition, in sort key order.
    pub async fn query(&self, table: &str, partition_key: impl Into<Value>) -> Result<QueryResponse> {
        self.query_with(&QueryRequest {
            table: table.into(),
            partition_key: partition_key.into(),
            ..Default::default()
        })
        .await
    }

    /// Items of one partition whose sort key satisfies `sort_operator sort_value`.
    pub async fn query_where(
        &self,
        table: &str,
        partition_key: impl Into<Value>,
        sort_operator: SortOperator,
        sort_value: impl Into<Value>,
    ) -> Result<QueryResponse> {
        self.query_with(&QueryRequest {
            table: table.into(),
            partition_key: partition_key.into(),
            sort_operator,
            sort_value: sort_value.into(),
            ..Default::default()
        })
        .await
    }

    pub async fn query_with(&self, request: &QueryRequest) -> Result<QueryResponse> {
        let raw: RawItems = self.client.call("query", request).await?;
        Ok(QueryResponse {
            count: raw.count.unwrap_or(raw.items.len() as u64),
            items: raw.items,
        })
    }

    /// Reads a table page by page, in no particular order. A page size of 0 returns every item.
    pub async fn scan(&self, table: &str, page_size: u64, page_index: u64) -> Result<ScanResponse> {
        let body = json!({ "table": table, "pageSize": page_size, "pageIndex": page_index });
        let raw: RawItems = self.client.call("scan", &body).await?;
        Ok(ScanResponse {
            count: raw.count.unwrap_or(raw.items.len() as u64),
            total: raw.total,
            items: raw.items,
        })
    }
}
