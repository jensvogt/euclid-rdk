//! Lists EKV tables, using the cached session. Read-only.
//!
//! ```sh
//! EUCLID_URL=https://localhost:5566 cargo run --example ekv [-- <table>]
//! ```
//!
//! With a table name, also describes that table and shows its first items.

use euclid_rdk::ekv::ListTablesRequest;
use euclid_rdk::Euclid;

#[tokio::main]
async fn main() -> euclid_rdk::Result<()> {
    let url = std::env::var("EUCLID_URL").unwrap_or_else(|_| "https://localhost:5566".into());
    let ekv = Euclid::for_server(url).ekv().await?;

    let tables = ekv
        .list_tables(&ListTablesRequest {
            page_size: 50,
            ..Default::default()
        })
        .await?;
    println!("tables ({} total):", tables.total);
    for table in &tables.tables {
        println!(
            "  {:<40} key={}{} items={}",
            table.name.as_deref().unwrap_or("-"),
            table.partition_key.as_deref().unwrap_or("-"),
            table.sort_key.as_deref().map(|s| format!("/{s}")).unwrap_or_default(),
            table.item_count
        );
    }

    if let Some(name) = std::env::args().nth(1) {
        println!("\n{:#?}", ekv.get_table(&name).await?);
        let page = ekv.scan(&name, 10, 0).await?;
        println!("first {} of {} items:", page.count, page.total);
        for item in page.items {
            println!("  {}", serde_json::Value::Object(item.attributes));
        }
    }
    Ok(())
}
