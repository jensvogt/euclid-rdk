//! Lists the API gateway's listeners and routes, using the cached session. Read-only; needs an
//! administrator session.
//!
//! ```sh
//! EUCLID_URL=https://localhost:5566 cargo run --example eag [-- <path-prefix>]
//! ```

use euclid_rdk::Euclid;

#[tokio::main]
async fn main() -> euclid_rdk::Result<()> {
    let url = std::env::var("EUCLID_URL").unwrap_or_else(|_| "https://localhost:5566".into());
    let prefix = std::env::args().nth(1).unwrap_or_default();
    let eag = Euclid::for_server(url).eag().await?;

    let listeners = eag.list_listeners().await?;
    println!("listeners ({} total, serving={}):", listeners.total, listeners.serving);
    for l in &listeners.listeners {
        let ns = l.namespace.as_deref().filter(|n| !n.is_empty()).unwrap_or("(unscoped)");
        print!("  {ns:<20} {:>5} {:?}", l.port, l.protocol);
        if let Some(cert) = &l.certificate {
            print!(
                "  cert {} until {} generated={} expired={}",
                cert.subject.as_deref().unwrap_or("-"),
                cert.not_after.as_deref().unwrap_or("-"),
                cert.generated,
                cert.expired
            );
        }
        println!();
    }

    let routes = eag.list_routes(&prefix).await?;
    println!("routes ({}):", routes.len());
    for r in &routes {
        let to = if r.is_module_route() {
            format!(
                "{} {}",
                r.module_target.as_deref().unwrap_or("-"),
                r.module_action.as_deref().unwrap_or("-")
            )
        } else {
            format!("app {}", r.application_id.as_deref().unwrap_or("-"))
        };
        println!(
            "  {:<24} {:<32} -> {to}  {:?} active={}",
            r.route_id.as_deref().unwrap_or("-"),
            r.path.as_deref().unwrap_or("-"),
            r.authentication,
            r.active
        );
    }
    if let Some(id) = routes.first().and_then(|r| r.route_id.as_deref()) {
        println!("get-route {id}: {:?}", eag.get_route(id).await?);
    }
    Ok(())
}
