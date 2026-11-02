//! Lists transfer servers, using the cached session. Read-only; needs an administrator.
//!
//! ```sh
//! EUCLID_URL=https://localhost:5566 cargo run --example ets [-- <server-id>]
//! ```
//!
//! With a server ID, also shows that server's full definition.

use euclid_rdk::Euclid;

#[tokio::main]
async fn main() -> euclid_rdk::Result<()> {
    let url = std::env::var("EUCLID_URL").unwrap_or_else(|_| "https://localhost:5566".into());
    let ets = Euclid::for_server(url).ets().await?;

    let servers = ets.list_servers().await?;
    println!("transfer servers ({}):", servers.len());
    for s in &servers {
        println!(
            "  {:<24} {:<5} {}:{:<6} bucket={:<24} desired={:<8} state={}",
            s.server_id.as_deref().unwrap_or("-"),
            s.protocol.as_deref().unwrap_or("-"),
            s.address.as_deref().unwrap_or("-"),
            s.port,
            s.bucket_name.as_deref().unwrap_or("-"),
            s.desired_state.as_deref().unwrap_or("-"),
            s.state.as_deref().unwrap_or("-"),
        );
    }

    if let Some(id) = std::env::args().nth(1) {
        println!("\n{:#?}", ets.get_server(&id).await?);
    }
    Ok(())
}
