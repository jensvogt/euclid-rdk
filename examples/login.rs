//! Logs in to an Euclid server and prints who you are.
//!
//! ```sh
//! EUCLID_URL=https://localhost:5566 EUCLID_USER=jens EUCLID_PASSWORD=secret \
//!     cargo run --example login
//! ```
//!
//! Optional: `EUCLID_NAMESPACE` to activate a namespace, `EUCLID_CA_CERT` for a CA certificate
//! other than the default (`/usr/local/euclid/etc/euclid_cert.crt`, then `/etc/euclid/euclid_cert.crt`). Without `EUCLID_USER`/`EUCLID_PASSWORD`, the cached
//! session in `~/.euclid/credentials` is used if it is still valid.

use euclid_rdk::eam::ListUsersRequest;
use euclid_rdk::Euclid;

#[tokio::main]
async fn main() -> euclid_rdk::Result<()> {
    let url = std::env::var("EUCLID_URL").unwrap_or_else(|_| "https://localhost:5566".into());

    let mut eam = Euclid::for_server(&url).access();
    if let Ok(user) = std::env::var("EUCLID_USER") {
        eam = eam.username(user);
    }
    if let Ok(password) = std::env::var("EUCLID_PASSWORD") {
        eam = eam.password(password);
    }
    if let Ok(namespace) = std::env::var("EUCLID_NAMESPACE") {
        eam = eam.namespace(namespace);
    }
    if let Ok(ca_cert) = std::env::var("EUCLID_CA_CERT") {
        eam = eam.ca_cert_path(ca_cert);
    }

    let session = eam.login().await?;
    println!("server     : {}", session.base_url());
    println!("user       : {}", session.user_id().unwrap_or("-"));
    println!("account    : {}", session.account_id().unwrap_or("-"));
    println!("region     : {}", session.region().unwrap_or("-"));
    println!("namespace  : {}", session.namespace().unwrap_or("-"));
    println!("admin      : {}", session.is_admin());

    if session.is_admin() {
        let users = session.list_users(&ListUsersRequest::default()).await?;
        println!("users ({} total):", users.total);
        for user in users.users {
            println!("  {}", user.user_id.unwrap_or_default());
        }
    }
    Ok(())
}
