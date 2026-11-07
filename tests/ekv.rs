//! EKV against a mock server: authentication, request bodies, response parsing, error mapping.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use euclid_rdk::ekv::{
    CreateTableRequest, KeyType, ListTablesRequest, QueryRequest, ScanRequest, SortDirection, SortOperator,
};
use euclid_rdk::{Eam, Ekv, Error};
use serde::Serialize;
use serde_json::{json, Value};
use wiremock::matchers::{header, method};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

fn jwt() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{}}}"#, now + 3600));
    format!("{}.{payload}.sig", URL_SAFE_NO_PAD.encode(b"{}"))
}

async fn ekv(server: &MockServer, with_access_key: bool) -> Ekv {
    let mut login = json!({
        "token": jwt(),
        "metadata": { "region": "eu-central-1", "accountId": "000000000000", "user": "jvo" }
    });
    if with_access_key {
        login["accessKeyId"] = json!("AKIATEST");
        login["secretAccessKey"] = json!("secret");
    }
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(login))
        .mount(server)
        .await;
    Eam::for_server(server.uri())
        .credentials("jvo", "pw")
        .no_cache()
        .no_ca_cert()
        .login()
        .await
        .unwrap()
        .ekv()
}

type Seen = Arc<Mutex<Vec<(Value, String)>>>;

/// Mounts `action` answering `answer`; records each request's body and Authorization header.
async fn mount(server: &MockServer, action: &str, answer: Value) -> Seen {
    let seen: Seen = Arc::default();
    let record = seen.clone();
    Mock::given(method("POST"))
        .and(header("x-euclid-target", "ekv"))
        .and(header("x-euclid-action", action))
        .respond_with(move |req: &Request| {
            let auth = req
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            record
                .lock()
                .unwrap()
                .push((serde_json::from_slice(&req.body).unwrap(), auth));
            ResponseTemplate::new(200).set_body_json(answer.clone())
        })
        .mount(server)
        .await;
    seen
}

fn body(seen: &Seen) -> Value {
    seen.lock().unwrap().last().expect("a request").0.clone()
}

fn table_json() -> Value {
    json!({
        "name": "orders", "ern": "ern:ekv:eu-central-1:000000000000::table:orders",
        "partitionKey": "customer", "partitionKeyType": "STRING",
        "sortKey": "order", "sortKeyType": "number",
        "itemCount": 7, "created": "2026-11-02T12:00:00Z", "modified": "2026-11-02T12:00:01Z"
    })
}

#[tokio::test]
async fn requests_are_signed_with_an_access_key_and_bearer_without() {
    let mut auths = Vec::new();
    for with_access_key in [true, false] {
        let server = MockServer::start().await;
        let seen = mount(&server, "list-tables", json!({ "tables": [], "total": 0 })).await;
        ekv(&server, with_access_key)
            .await
            .list_tables(&ListTablesRequest::default())
            .await
            .unwrap();
        auths.push(seen.lock().unwrap()[0].1.clone());
    }
    assert!(
        auths[0].starts_with("AWS4-HMAC-SHA256 Credential=AKIATEST/"),
        "{}",
        auths[0]
    );
    assert!(auths[0].contains("/eu-central-1/ekv/aws4_request"), "{}", auths[0]);
    assert!(auths[1].starts_with("Bearer "), "{}", auths[1]);
}

#[tokio::test]
async fn create_table_sends_jdk_defaults_and_parses_description() {
    let server = MockServer::start().await;
    let ekv = ekv(&server, true).await;
    let seen = mount(&server, "create-table", table_json()).await;

    let table = ekv.create_table("orders", "customer", None).await.unwrap();
    assert_eq!(
        body(&seen),
        json!({ "name": "orders", "partitionKey": "customer", "partitionKeyType": "string",
                "sortKey": "", "sortKeyType": "string" })
    );
    // Key types are read case-insensitively.
    assert_eq!(table.partition_key_type, Some(KeyType::String));
    assert_eq!(table.sort_key_type, Some(KeyType::Number));
    assert_eq!(table.item_count, 7);
    assert!(table.has_sort_key());

    ekv.create_table_with(&CreateTableRequest {
        name: "t".into(),
        partition_key: "id".into(),
        partition_key_type: KeyType::Number,
        sort_key: "ts".into(),
        sort_key_type: KeyType::Binary,
    })
    .await
    .unwrap();
    assert_eq!(body(&seen)["partitionKeyType"], "number");
    assert_eq!(body(&seen)["sortKeyType"], "binary");
}

#[tokio::test]
async fn empty_sort_key_and_unknown_key_type_read_as_none() {
    let server = MockServer::start().await;
    let ekv = ekv(&server, true).await;
    mount(
        &server,
        "get-table",
        json!({ "name": "t", "partitionKey": "id", "partitionKeyType": "weird", "sortKey": "", "sortKeyType": "" }),
    )
    .await;

    let table = ekv.get_table("t").await.unwrap();
    assert_eq!(table.sort_key, None);
    assert!(!table.has_sort_key());
    assert_eq!(table.partition_key_type, None);
    assert_eq!(table.sort_key_type, None);
}

#[tokio::test]
async fn list_and_delete_tables() {
    let server = MockServer::start().await;
    let ekv = ekv(&server, true).await;
    let list = mount(&server, "list-tables", json!({ "tables": [table_json()], "total": 1 })).await;
    let delete = mount(&server, "delete-table", json!({ "deletedItems": 42 })).await;

    let tables = ekv.list_tables(&ListTablesRequest::default()).await.unwrap();
    assert_eq!(
        body(&list),
        json!({ "prefix": "", "pageSize": 10, "pageIndex": 0, "sortColumn": "name", "sortDirection": "asc" })
    );
    assert_eq!(tables.total, 1);
    assert_eq!(tables.tables[0].name.as_deref(), Some("orders"));

    assert_eq!(ekv.delete_table("orders").await.unwrap(), 42);
    assert_eq!(body(&delete), json!({ "name": "orders" }));
}

#[tokio::test]
async fn exists_table_maps_404_to_false() {
    let server = MockServer::start().await;
    let ekv = ekv(&server, true).await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "get-table"))
        .respond_with(|req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            match body["name"].as_str() {
                Some("there") => ResponseTemplate::new(200).set_body_json(table_json()),
                Some("gone") => ResponseTemplate::new(404).set_body_string("No such table"),
                _ => ResponseTemplate::new(500).set_body_string("boom"),
            }
        })
        .mount(&server)
        .await;

    assert!(ekv.exists_table("there").await.unwrap());
    assert!(!ekv.exists_table("gone").await.unwrap());
    assert_eq!(ekv.exists_table("broken").await.unwrap_err().status(), Some(500));
}

#[derive(Serialize)]
struct Order<'a> {
    customer: &'a str,
    order: &'a str,
    amount: u32,
}

#[tokio::test]
async fn items_are_written_read_and_deleted() {
    let server = MockServer::start().await;
    let ekv = ekv(&server, true).await;
    let stored = json!({ "customer": "alice", "order": "o1", "amount": 10,
                         "_created": "2026-11-02T12:00:00Z", "_modified": 1762084800 });
    let put = mount(&server, "put-item", stored.clone()).await;
    let get = mount(&server, "get-item", stored).await;
    let delete = mount(&server, "delete-item", json!({ "deleted": true })).await;

    // Anything serializable is an item: here a struct.
    let item = ekv
        .put_item(
            "orders",
            &Order {
                customer: "alice",
                order: "o1",
                amount: 10,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        body(&put),
        json!({ "table": "orders", "item": { "customer": "alice", "order": "o1", "amount": 10 } })
    );
    // Bookkeeping attributes are split off, a numeric one read as text.
    assert_eq!(item.created.as_deref(), Some("2026-11-02T12:00:00Z"));
    assert_eq!(item.modified.as_deref(), Some("1762084800"));
    assert!(item.get("_created").is_none());
    assert_eq!(item.attributes.len(), 3);

    let key = json!({ "customer": "alice", "order": "o1" });
    let item = ekv.get_item("orders", &key).await.unwrap();
    assert_eq!(body(&get), json!({ "table": "orders", "key": key }));
    assert_eq!(item.get("amount"), Some(&json!(10)));
    assert_eq!(item.get_str("customer"), Some("alice"));

    assert!(ekv.delete_item("orders", &key).await.unwrap());
    assert_eq!(body(&delete), json!({ "table": "orders", "key": key }));
}

#[tokio::test]
async fn delete_item_without_flag_is_false() {
    let server = MockServer::start().await;
    let ekv = ekv(&server, true).await;
    mount(&server, "delete-item", json!({})).await;
    assert!(!ekv.delete_item("orders", &json!({ "customer": "x" })).await.unwrap());
}

#[tokio::test]
async fn query_sends_conditions_with_jdk_defaults() {
    let server = MockServer::start().await;
    let ekv = ekv(&server, true).await;
    let seen = mount(
        &server,
        "query",
        json!({ "items": [{ "customer": "alice", "order": "o1" }, { "customer": "alice", "order": "o2" }] }),
    )
    .await;

    // Partition only: no operator, nulls for the unused operands, forward, everything.
    let all = ekv.query("orders", "alice").await.unwrap();
    assert_eq!(
        body(&seen),
        json!({ "table": "orders", "partitionKey": "alice", "sortOperator": "", "sortValue": null,
                "sortUpper": null, "forward": true, "pageSize": 0, "pageIndex": 0 })
    );
    // No count in the answer: it is the number of items.
    assert_eq!(all.count, 2);

    ekv.query_where("orders", 7, SortOperator::BeginsWith, "o")
        .await
        .unwrap();
    assert_eq!(body(&seen)["partitionKey"], 7);
    assert_eq!(body(&seen)["sortOperator"], "begins-with");
    assert_eq!(body(&seen)["sortValue"], "o");

    ekv.query_with(&QueryRequest {
        table: "orders".into(),
        partition_key: json!("alice"),
        sort_operator: SortOperator::Between,
        sort_value: json!(1),
        sort_upper: json!(5),
        forward: false,
        page_size: 2,
        page_index: 1,
    })
    .await
    .unwrap();
    assert_eq!(
        body(&seen),
        json!({ "table": "orders", "partitionKey": "alice", "sortOperator": "between", "sortValue": 1,
                "sortUpper": 5, "forward": false, "pageSize": 2, "pageIndex": 1 })
    );
}

#[tokio::test]
async fn sort_operators_use_wire_spellings() {
    let spellings: Vec<Value> = [
        SortOperator::None,
        SortOperator::Eq,
        SortOperator::Lt,
        SortOperator::Le,
        SortOperator::Gt,
        SortOperator::Ge,
        SortOperator::Between,
        SortOperator::BeginsWith,
    ]
    .iter()
    .map(|o| serde_json::to_value(o).unwrap())
    .collect();
    assert_eq!(
        spellings,
        [
            json!(""),
            json!("eq"),
            json!("lt"),
            json!("le"),
            json!("gt"),
            json!("ge"),
            json!("between"),
            json!("begins-with")
        ]
    );
}

#[tokio::test]
async fn scan_pages_and_reports_totals() {
    let server = MockServer::start().await;
    let ekv = ekv(&server, true).await;
    let seen = mount(
        &server,
        "scan",
        json!({ "items": [{ "id": 1 }, { "id": 2 }], "count": 2, "total": 9 }),
    )
    .await;

    let page = ekv.scan("orders", 2, 3).await.unwrap();
    assert_eq!(body(&seen), json!({ "table": "orders", "pageSize": 2, "pageIndex": 3 }));
    assert_eq!(page.count, 2);
    assert_eq!(page.total, 9);
    assert_eq!(page.items[1].get("id"), Some(&json!(2)));
}

#[tokio::test]
async fn service_errors_carry_action_and_status() {
    let server = MockServer::start().await;
    let ekv = ekv(&server, true).await;
    Mock::given(method("POST"))
        .and(header("x-euclid-action", "get-item"))
        .respond_with(ResponseTemplate::new(404).set_body_string(r#"{"error":"No such item"}"#))
        .mount(&server)
        .await;

    let err = ekv
        .get_item("orders", &json!({ "customer": "nobody" }))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Service { status: 404, .. }));
    assert_eq!(
        err.to_string(),
        r#"ekv get-item failed with status 404: {"error":"No such item"}"#
    );
}

#[tokio::test]
async fn query_reports_the_total_matched() {
    let server = MockServer::start().await;
    let server2 = MockServer::start().await;
    let current = ekv(&server, true).await;
    let older = ekv(&server2, true).await;
    mount(
        &server,
        "query",
        json!({ "items": [{ "customer": "alice", "order": "o1" }], "count": 1, "total": 14 }),
    )
    .await;
    mount(
        &server2,
        "query",
        json!({ "items": [{ "customer": "alice", "order": "o1" }, { "customer": "alice", "order": "o2" }] }),
    )
    .await;

    let page = current.query("orders", "alice").await.unwrap();
    assert_eq!((page.count, page.total), (1, 14));

    // A server that predates the total: it is what came back.
    let page = older.query("orders", "alice").await.unwrap();
    assert_eq!((page.count, page.total), (2, 2));
}

#[tokio::test]
async fn scan_with_sends_ordering_and_filters() {
    let server = MockServer::start().await;
    let ekv = ekv(&server, true).await;
    let seen = mount(
        &server,
        "scan",
        json!({ "items": [{ "id": 1 }], "count": 1, "total": 9 }),
    )
    .await;

    let page = ekv
        .scan_with(&ScanRequest {
            table: "orders".into(),
            page_size: 5,
            sort_column: "modified".into(),
            sort_direction: SortDirection::Desc,
            modified_from: "2026-11-01T00:00:00Z".into(),
            attribute_name: "amount".into(),
            attribute_operator: SortOperator::Between,
            attribute_value: json!(10),
            attribute_upper: json!(20),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        body(&seen),
        json!({ "table": "orders", "pageSize": 5, "pageIndex": 0, "sortColumn": "modified",
                "sortDirection": "desc", "modifiedFrom": "2026-11-01T00:00:00Z", "modifiedTo": "",
                "attributeName": "amount", "attributeOperator": "between", "attributeValue": 10,
                "attributeUpper": 20 })
    );
    assert_eq!((page.count, page.total), (1, 9));

    ekv.scan_with(&ScanRequest {
        table: "orders".into(),
        ..Default::default()
    })
    .await
    .unwrap();
    assert_eq!(body(&seen)["attributeOperator"], "");
    assert_eq!(body(&seen)["attributeValue"], Value::Null);
    assert_eq!(body(&seen)["sortDirection"], "asc");
}
