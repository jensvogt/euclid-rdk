//! Lists topics and their subscriptions, using the cached session. Read-only.
//!
//! ```sh
//! EUCLID_URL=https://localhost:5566 cargo run --example ens
//! ```

use euclid_rdk::ens::ListTopicsRequest;
use euclid_rdk::Euclid;

#[tokio::main]
async fn main() -> euclid_rdk::Result<()> {
    let url = std::env::var("EUCLID_URL").unwrap_or_else(|_| "https://localhost:5566".into());
    let ens = Euclid::for_server(url).ens().await?;

    let topics = ens
        .list_topics(&ListTopicsRequest {
            page_size: 50,
            ..Default::default()
        })
        .await?;
    println!("topics ({} total):", topics.total);
    for topic in &topics.topics {
        let name = topic.name.as_deref().unwrap_or("-");
        let status = topic.status.as_deref().unwrap_or("-");
        println!("  {name:<40} messages={:<8} {status}", topic.messages);
        if let Some(ern) = &topic.ern {
            for subscription in ens.list_subscriptions(ern).await?.subscriptions {
                println!(
                    "    -> {} ({})",
                    subscription.target_ern.as_deref().unwrap_or("-"),
                    subscription.kind.as_deref().unwrap_or("-")
                );
            }
        }
    }
    Ok(())
}
