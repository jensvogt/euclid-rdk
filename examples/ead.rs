//! Lists the newest entries of the account's audit trail, using the cached session. Read-only.
//!
//! ```sh
//! EUCLID_URL=https://localhost:5566 cargo run --example ead [-- <module>]
//! ```

use euclid_rdk::ead::ListEventsRequest;
use euclid_rdk::Euclid;

#[tokio::main]
async fn main() -> euclid_rdk::Result<()> {
    let url = std::env::var("EUCLID_URL").unwrap_or_else(|_| "https://localhost:5566".into());
    let ead = Euclid::for_server(url).ead().await?;

    let listing = ead
        .list_events(&ListEventsRequest {
            module: std::env::args().nth(1),
            page_size: 20,
            ..Default::default()
        })
        .await?;
    let more = if listing.total_exact { "" } else { "at least " };
    println!("audit events ({more}{} total):", listing.total);
    for event in listing.events {
        println!(
            "  {:<25} {:<12} {:<6} {:<28} {}",
            event.created.unwrap_or_default(),
            event.user_id.unwrap_or_default(),
            event.module.unwrap_or_default(),
            event.command.unwrap_or_default(),
            event.status
        );
    }
    Ok(())
}
