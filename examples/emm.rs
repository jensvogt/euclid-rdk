//! Lists the managed modules and the backups, using the cached session. Read-only;
//! administrator-only server-side.
//!
//! ```sh
//! EUCLID_URL=https://localhost:5566 cargo run --example emm
//! ```

use euclid_rdk::Euclid;

#[tokio::main]
async fn main() -> euclid_rdk::Result<()> {
    let url = std::env::var("EUCLID_URL").unwrap_or_else(|_| "https://localhost:5566".into());
    let emm = Euclid::for_server(url).emm().await?;

    let modules = emm.list_modules().await?;
    println!("modules ({} total):", modules.total);
    for module in modules.modules {
        let running = module
            .instances
            .iter()
            .filter(|i| i.state.as_deref() == Some("RUNNING"))
            .count();
        println!(
            "  {:<20} core={:<5} stopped={:<5} instances={}/{} (min {} max {}) log={}",
            module.name.unwrap_or_default(),
            module.core,
            module.desired_stopped,
            running,
            module.instances.len(),
            module.min_instances,
            module.max_instances,
            module
                .log_level
                .filter(|l| !l.is_empty())
                .unwrap_or_else(|| "default".into())
        );
    }

    let backups = emm.list_backups().await?;
    println!(
        "backups in {} (schedule {:?}, keep {}):",
        backups.directory.unwrap_or_default(),
        backups.schedule.unwrap_or_default(),
        backups.keep
    );
    for backup in backups.backups {
        println!(
            "  {:<40} {:>12} bytes complete={}",
            backup.path.unwrap_or_default(),
            backup.size,
            backup.complete
        );
    }
    Ok(())
}
