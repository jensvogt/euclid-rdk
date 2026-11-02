//! Lists queues and their message counts, using the cached session. Read-only.
//!
//! ```sh
//! EUCLID_URL=https://localhost:5566 cargo run --example eqs [-- <queue-name>]
//! ```
//!
//! With a queue name or ERN, also shows that queue and peeks at its first messages without consuming them.

use euclid_rdk::eqs::{ListMessagesRequest, ListQueuesRequest};
use euclid_rdk::Euclid;

#[tokio::main]
async fn main() -> euclid_rdk::Result<()> {
    let url = std::env::var("EUCLID_URL").unwrap_or_else(|_| "https://localhost:5566".into());
    let eqs = Euclid::for_server(url).eqs().await?;

    let queues = eqs.list_queues(&ListQueuesRequest::default()).await?;
    println!("queues ({} total):", queues.total);
    for queue in &queues.queues {
        println!(
            "  {:<40} available={:<6} invisible={:<6} delayed={:<6} {}",
            queue.name.as_deref().unwrap_or("-"),
            queue.available,
            queue.invisible,
            queue.delayed,
            queue.status.as_deref().unwrap_or("")
        );
    }

    if let Some(name_or_ern) = std::env::args().nth(1) {
        // A name resolves within the session's namespace; an ERN names the queue outright.
        let ern = if name_or_ern.starts_with("ern:") {
            name_or_ern
        } else {
            eqs.get_queue_ern(&name_or_ern).await?.ern.unwrap_or_default()
        };
        let queue = eqs.get_queue(&ern).await?;
        println!("{queue:#?}");
        println!("{:?}", eqs.get_message_count(&ern).await?);
        println!("{:?}", eqs.get_queue_metadata(&ern).await?);
        let peek = eqs
            .list_messages(&ListMessagesRequest {
                queue_ern: ern,
                page_size: 3,
                ..Default::default()
            })
            .await?;
        println!("messages ({} total):", peek.total);
        for message in peek.messages {
            println!("  {} {:?}", message.message_id.unwrap_or_default(), message.status);
        }
    }
    Ok(())
}
