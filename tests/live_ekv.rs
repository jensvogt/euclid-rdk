//! EKV round trip against a real euclid server. Ignored by default; run with
//!
//! ```sh
//! EUCLID_LIVE_URL=https://localhost:5566 cargo test --test live_ekv -- --ignored --nocapture
//! ```
//!
//! Uses the cached session in `~/.euclid/credentials`, or `EUCLID_USER`/`EUCLID_PASSWORD` when
//! set; `EUCLID_LIVE_NAMESPACE` activates a namespace. Creates its own uniquely named table and
//! deletes it again, also when a check fails.

use std::future::Future;
use std::time::{SystemTime, UNIX_EPOCH};

use euclid_rdk::ekv::{KeyType, QueryRequest, SortOperator};
use euclid_rdk::{Eam, Session};
use serde_json::json;

async fn session() -> Option<Session> {
    let Ok(url) = std::env::var("EUCLID_LIVE_URL") else {
        eprintln!("EUCLID_LIVE_URL not set - skipping");
        return None;
    };
    let mut eam = Eam::for_server(url);
    if let (Ok(user), Ok(password)) = (std::env::var("EUCLID_USER"), std::env::var("EUCLID_PASSWORD")) {
        eam = eam.credentials(user, password);
    }
    if let Ok(namespace) = std::env::var("EUCLID_LIVE_NAMESPACE") {
        eam = eam.namespace(namespace);
    }
    Some(eam.login().await.expect("login"))
}

fn unique_name(kind: &str) -> String {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("rdk-live-{kind}-{}-{}", std::process::id(), nanos % 1_000_000_000)
}

/// Runs `body`, then `cleanup` whatever happened, then re-raises a failure of `body`.
async fn with_cleanup<B, C>(body: B, cleanup: C)
where
    B: Future<Output = ()> + Send + 'static,
    C: Future<Output = ()>,
{
    let outcome = tokio::spawn(body).await;
    cleanup.await;
    if let Err(e) = outcome {
        std::panic::resume_unwind(e.into_panic());
    }
}

#[tokio::test]
#[ignore = "needs a live euclid server (EUCLID_LIVE_URL)"]
async fn ekv_round_trip() {
    let Some(session) = session().await else { return };
    let ekv = session.ekv();
    let name = unique_name("table");
    let created = ekv
        .create_table(&name, "customer", Some("order"))
        .await
        .expect("create table");
    println!("created table {name}: {created:?}");

    let test_ekv = ekv.clone();
    let test_name = name.clone();
    let body = async move {
        let (ekv, table) = (test_ekv, test_name);
        assert_eq!(created.partition_key.as_deref(), Some("customer"));
        assert_eq!(created.sort_key.as_deref(), Some("order"));
        assert!(created.has_sort_key());

        let described = ekv.get_table(&table).await.expect("get table");
        assert_eq!(described.name.as_deref(), Some(table.as_str()));
        assert_eq!(described.partition_key_type, Some(KeyType::String));
        assert_eq!(described.sort_key_type, Some(KeyType::String));
        assert!(ekv.exists_table(&table).await.expect("exists"));
        assert!(!ekv
            .exists_table(&format!("{table}-missing"))
            .await
            .expect("exists missing"));

        // Two partitions: alice with five orders, bob with one.
        for i in 1..=5 {
            let stored = ekv
                .put_item(
                    &table,
                    &json!({ "customer": "alice", "order": format!("2026-11-0{i}"), "amount": i * 10 }),
                )
                .await
                .expect("put item");
            assert_eq!(stored.get("amount"), Some(&json!(i * 10)));
            assert!(stored.created.is_some(), "no _created on {stored:?}");
        }
        ekv.put_item(
            &table,
            &json!({ "customer": "bob", "order": "2026-11-01", "amount": 99 }),
        )
        .await
        .expect("put item");

        let item = ekv
            .get_item(&table, &json!({ "customer": "alice", "order": "2026-11-03" }))
            .await
            .expect("get item");
        assert_eq!(item.get("amount"), Some(&json!(30)));
        assert_eq!(item.get_str("customer"), Some("alice"));
        assert!(item.created.is_some(), "no _created on {item:?}");

        let missing = ekv
            .get_item(&table, &json!({ "customer": "alice", "order": "1999-01-01" }))
            .await;
        assert_eq!(missing.expect_err("missing item").status(), Some(404));

        // Whole partition, then a sort-key condition, then descending with a page size.
        let all = ekv.query(&table, "alice").await.expect("query");
        assert_eq!(all.count, 5);
        let orders: Vec<_> = all.items.iter().filter_map(|i| i.get_str("order")).collect();
        assert_eq!(
            orders,
            ["2026-11-01", "2026-11-02", "2026-11-03", "2026-11-04", "2026-11-05"]
        );

        let later = ekv
            .query_where(&table, "alice", SortOperator::Ge, "2026-11-04")
            .await
            .expect("query ge");
        assert_eq!(later.items.len(), 2);

        let between = ekv
            .query_with(&QueryRequest {
                table: table.clone(),
                partition_key: json!("alice"),
                sort_operator: SortOperator::Between,
                sort_value: json!("2026-11-02"),
                sort_upper: json!("2026-11-04"),
                forward: false,
                page_size: 2,
                ..Default::default()
            })
            .await
            .expect("query between");
        let orders: Vec<_> = between.items.iter().filter_map(|i| i.get_str("order")).collect();
        assert_eq!(orders, ["2026-11-04", "2026-11-03"]);

        let prefix = ekv
            .query_where(&table, "alice", SortOperator::BeginsWith, "2026-11-0")
            .await
            .expect("query begins-with");
        assert_eq!(prefix.items.len(), 5);

        // Scan in pages of 4: 6 items over two pages.
        let first = ekv.scan(&table, 4, 0).await.expect("scan page 0");
        let second = ekv.scan(&table, 4, 1).await.expect("scan page 1");
        println!("scan pages: {} + {} of {}", first.count, second.count, first.total);
        assert_eq!(first.items.len(), 4);
        assert_eq!(second.items.len(), 2);
        assert_eq!(first.total, 6);

        assert!(ekv
            .delete_item(&table, &json!({ "customer": "bob", "order": "2026-11-01" }))
            .await
            .expect("delete item"));
        assert!(!ekv
            .delete_item(&table, &json!({ "customer": "bob", "order": "2026-11-01" }))
            .await
            .expect("delete item again"));
        assert_eq!(ekv.scan(&table, 0, 0).await.expect("scan all").items.len(), 5);
    };

    with_cleanup(body, async {
        match ekv.delete_table(&name).await {
            Ok(deleted) => println!("deleted table {name} ({deleted} items)"),
            Err(e) => eprintln!("CLEANUP FAILED - delete table {name} by hand: {e}"),
        }
    })
    .await;
}
