//! Shows a subscriber's subscriptions and how many events wait for it, using the cached session.
//! Read-only: nothing is claimed or acknowledged.
//!
//! ```sh
//! EUCLID_URL=https://localhost:5566 cargo run --example ees -- <subscriber-name>
//! ```

use euclid_rdk::Euclid;

#[tokio::main]
async fn main() -> euclid_rdk::Result<()> {
    let url = std::env::var("EUCLID_URL").unwrap_or_else(|_| "https://localhost:5566".into());
    let Some(name) = std::env::args().nth(1) else {
        eprintln!("usage: ees <subscriber-name>");
        std::process::exit(2);
    };

    let ees = Euclid::for_server(url).ees().await?;
    let listed = ees.list_subscriptions(&name).await?;
    println!(
        "{name}: {} subscription(s), {} event(s) waiting",
        listed.subscriptions.len(),
        listed.waiting
    );
    for s in &listed.subscriptions {
        println!(
            "  {:<24} {:<8} filter={} last seen {}",
            s.event_type.as_deref().unwrap_or("-"),
            s.mode.wire_value(),
            serde_json::Value::Object(s.filter.clone()),
            s.last_seen.as_deref().unwrap_or("-")
        );
    }
    Ok(())
}
