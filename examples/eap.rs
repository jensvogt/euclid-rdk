//! Lists applications, nodes, platforms and egress sites, using the cached session. Read-only;
//! requires an administrator session.
//!
//! ```sh
//! EUCLID_URL=https://localhost:5566 cargo run --example eap [-- <application-id>]
//! ```
//!
//! With an application id, also shows that application (environment variable names only).

use euclid_rdk::Euclid;

#[tokio::main]
async fn main() -> euclid_rdk::Result<()> {
    let url = std::env::var("EUCLID_URL").unwrap_or_else(|_| "https://localhost:5566".into());
    let eap = Euclid::for_server(url).eap().await?;

    let applications = eap.list_applications().await?;
    println!("applications ({}):", applications.len());
    for app in &applications {
        println!(
            "  {:<32} {:<8} {:<8} desired={:<8} state={:<8} instances={} [{}..{}]",
            app.application_id.as_deref().unwrap_or("-"),
            app.application_type.wire_value(),
            app.runtime.as_deref().unwrap_or("-"),
            app.desired_state.as_deref().unwrap_or("-"),
            app.state.as_deref().unwrap_or("-"),
            app.instances,
            app.min_instances,
            app.max_instances,
        );
    }

    let nodes = eap.list_nodes().await?;
    println!("nodes ({} total):", nodes.total);
    for node in &nodes.nodes {
        println!(
            "  {:<24} {:<20} cpus={:<3} live={} drained={} {}",
            node.name.as_deref().unwrap_or("-"),
            node.address.as_deref().unwrap_or("-"),
            node.cpu_count,
            node.live,
            node.drained,
            node.version.as_deref().unwrap_or("-"),
        );
    }

    let platforms = eap.list_platforms().await?;
    println!("platforms ({}):", platforms.len());
    for platform in &platforms {
        println!(
            "  {:<24} namespace={:<16} owns={}",
            platform.name.as_deref().unwrap_or("-"),
            platform.namespace.as_deref().unwrap_or("-"),
            platform.owns.len()
        );
    }

    let egress = eap.list_egress_sites(None).await?;
    println!(
        "egress sites ({}), defaults: {:?}",
        egress.sites.len(),
        egress.default_limits
    );
    for site in &egress.sites {
        println!(
            "  {:<24} {:<32} limits={:?} in_flight={} blocked_until={}",
            site.application_id.as_deref().unwrap_or("-"),
            site.site.as_deref().unwrap_or("-"),
            site.limits,
            site.in_flight,
            site.blocked_until.as_deref().unwrap_or("-"),
        );
    }

    if let Some(id) = std::env::args().nth(1) {
        let app = eap.get_application(&id).await?;
        let env: Vec<&String> = app.environment.keys().collect();
        println!(
            "\n{id}: artifact={:?} version={:?} user={:?} resources={} env={env:?}",
            app.artifact_key,
            app.version,
            app.user_id,
            app.resources.len()
        );
        if let Some(node) = nodes.nodes.first().and_then(|n| n.name.clone()) {
            let detail = eap.get_node(&node).await?;
            println!(
                "node {node} runs {} application(s)",
                detail.applications.map_or(0, |a| a.len())
            );
        }
    }
    Ok(())
}
