//! Lists secrets (names, versions, tags - never values), using the cached session. Read-only.
//!
//! ```sh
//! EUCLID_URL=https://localhost:5566 cargo run --example ess
//! ```

use euclid_rdk::ess::ListSecretsRequest;
use euclid_rdk::Euclid;

#[tokio::main]
async fn main() -> euclid_rdk::Result<()> {
    let url = std::env::var("EUCLID_URL").unwrap_or_else(|_| "https://localhost:5566".into());
    let ess = Euclid::for_server(url).ess().await?;

    let listing = ess
        .list_secrets(&ListSecretsRequest {
            page_size: 50,
            ..Default::default()
        })
        .await?;
    println!("secrets ({} total):", listing.total);
    for secret in listing.secrets {
        println!(
            "  {:<40} version={:<4} tags={:?}",
            secret.name.unwrap_or_default(),
            secret.version,
            secret.tags
        );
    }
    Ok(())
}
