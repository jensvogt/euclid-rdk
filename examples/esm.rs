//! Lists buckets and a few objects of the first one, using the cached session (read-only).
//!
//! ```sh
//! EUCLID_URL=https://localhost:5566 cargo run --example esm
//! ```

use euclid_rdk::esm::{ListBucketsRequest, ListObjectsRequest};
use euclid_rdk::Euclid;

#[tokio::main]
async fn main() -> euclid_rdk::Result<()> {
    let url = std::env::var("EUCLID_URL").unwrap_or_else(|_| "https://localhost:5566".into());
    let esm = Euclid::for_server(url).esm().await?;

    let buckets = esm
        .list_buckets(&ListBucketsRequest {
            page_size: 5,
            ..Default::default()
        })
        .await?;
    println!("buckets ({} total):", buckets.total);
    for bucket in &buckets.buckets {
        println!(
            "  {:<30} objects={:<10} size={}",
            bucket.name.as_deref().unwrap_or("-"),
            bucket.objects,
            bucket.size
        );
    }

    // The smallest non-empty bucket: listing a bucket of millions of objects can take longer
    // than the default request timeout.
    let smallest = buckets
        .buckets
        .iter()
        .filter(|b| b.objects > 0)
        .min_by_key(|b| b.objects)
        .and_then(|b| b.ern.clone());
    if let Some(ern) = smallest {
        let bucket = esm.get_bucket(&ern).await?;
        let size = esm.get_bucket_size(&ern).await?;
        let count = esm.get_object_count(&ern).await?;
        println!(
            "\n{}: get-bucket objects={} get-bucket-size={} get-object-count={}",
            bucket.name.as_deref().unwrap_or("-"),
            bucket.objects,
            size.size,
            count.count
        );
        let objects = esm
            .list_objects(&ListObjectsRequest {
                bucket_ern: ern.clone(),
                page_size: 3,
                ..Default::default()
            })
            .await?;
        if let Some(key) = objects.objects.first().and_then(|o| o.key.clone()) {
            let bytes = esm.get_object(&ern, &key, 5 * 1024 * 1024).await?;
            println!("  get-object {key}: {} bytes", bytes.len());
        }
        for object in objects.objects {
            println!(
                "  {} ({} bytes, {})",
                object.key.unwrap_or_default(),
                object.size,
                object.content_type.unwrap_or_default()
            );
        }
        let subscriptions = esm.list_subscriptions(&ern).await?;
        println!("  subscriptions: {}", subscriptions.total);
    }
    Ok(())
}
