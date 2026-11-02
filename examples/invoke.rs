//! Calls any euclid action with a JSON body and prints the answer, using the cached session.
//!
//! ```sh
//! EUCLID_URL=https://localhost:5566 cargo run --example invoke -- eqs list-queues '{}'
//! ```

use euclid_rdk::Euclid;

#[tokio::main]
async fn main() -> euclid_rdk::Result<()> {
    let url = std::env::var("EUCLID_URL").unwrap_or_else(|_| "https://localhost:5566".into());
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (target, action) = match args.as_slice() {
        [target, action, ..] => (target.as_str(), action.as_str()),
        _ => {
            eprintln!("usage: invoke <target> <action> [json-body]");
            std::process::exit(2);
        }
    };
    let body: serde_json::Value = serde_json::from_str(args.get(2).map(String::as_str).unwrap_or("{}"))?;

    let session = Euclid::for_server(url).session().await?;
    let answer = session.invoke(target, action, &body).await?;
    println!("{}", serde_json::to_string_pretty(&answer)?);
    Ok(())
}
