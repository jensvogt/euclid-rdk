//! Lists the hosted zones of the session's namespace and, for each, its record sets; then shows
//! what the name server answers for a name. Uses the cached session. Read-only.
//!
//! ```sh
//! EUCLID_URL=https://localhost:5566 cargo run --example eds [-- <name> [<type>]]
//! ```

use euclid_rdk::eds::{ListRecordsRequest, ListZonesRequest};
use euclid_rdk::Euclid;

#[tokio::main]
async fn main() -> euclid_rdk::Result<()> {
    let url = std::env::var("EUCLID_URL").unwrap_or_else(|_| "https://localhost:5566".into());
    let eds = Euclid::for_server(url).eds().await?;

    let zones = eds.list_zones(&ListZonesRequest::default()).await?;
    println!("zones ({} total):", zones.total);
    for zone in zones.zones {
        let name = zone.name.unwrap_or_default();
        println!(
            "  {name} (ttl {}, serial {}, {} record sets)",
            zone.ttl, zone.serial, zone.record_count
        );
        for set in eds.list_records(&ListRecordsRequest::new(&name)).await?.records {
            println!(
                "    {:<30} {:<6} {:>6} {}",
                set.name.unwrap_or_default(),
                set.record_type.unwrap_or_default(),
                set.ttl,
                set.values.join(", ")
            );
        }
    }

    if let Some(name) = std::env::args().nth(1) {
        let record_type = std::env::args().nth(2);
        let answer = eds.get_answer(&name, record_type.as_deref()).await?;
        println!(
            "\n{name}: {} (authoritative: {}, zone: {})",
            answer.rcode.unwrap_or_default(),
            answer.authoritative,
            answer.zone.unwrap_or_else(|| "-".into())
        );
        for record in answer.answers.iter().chain(&answer.authority) {
            println!(
                "  {:<30} {:<6} {:>6} {}",
                record.name.as_deref().unwrap_or_default(),
                record.record_type.as_deref().unwrap_or_default(),
                record.ttl,
                record.value.as_deref().unwrap_or_default()
            );
        }
    }
    Ok(())
}
