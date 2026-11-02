//! Lists encryption keys and certificates, using the cached session. Read-only; prints no key
//! material or PEM.
//!
//! ```sh
//! EUCLID_URL=https://localhost:5566 cargo run --example ekm
//! ```

use euclid_rdk::ekm::{ListCertificatesRequest, ListKeysRequest};
use euclid_rdk::Euclid;

#[tokio::main]
async fn main() -> euclid_rdk::Result<()> {
    let url = std::env::var("EUCLID_URL").unwrap_or_else(|_| "https://localhost:5566".into());
    let ekm = Euclid::for_server(url).ekm().await?;

    let keys = ekm
        .list_keys(&ListKeysRequest {
            page_size: 50,
            ..Default::default()
        })
        .await?;
    println!("keys ({} total):", keys.total);
    for key in &keys.keys {
        println!(
            "  {:<40} {}/{:<4} {:<17} {}",
            key.name.as_deref().unwrap_or("-"),
            key.algorithm.as_deref().unwrap_or("-"),
            key.length,
            key.status.as_deref().unwrap_or("-"),
            key.description.as_deref().unwrap_or("")
        );
    }

    let certificates = ekm
        .list_certificates(&ListCertificatesRequest {
            page_size: 50,
            ..Default::default()
        })
        .await?;
    println!("certificates ({} total):", certificates.total);
    for c in &certificates.certificates {
        println!(
            "  {:<30} subject={} not_after={} generated={}",
            c.name.as_deref().unwrap_or("-"),
            c.subject.as_deref().unwrap_or("-"),
            c.not_after.as_deref().unwrap_or("-"),
            c.generated
        );
    }
    Ok(())
}
