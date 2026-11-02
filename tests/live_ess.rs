//! ESS round trip against a real euclid server. Ignored by default; run with
//!
//! ```sh
//! EUCLID_LIVE_URL=https://localhost:5566 cargo test --test live_ess -- --ignored --nocapture
//! ```
//!
//! Uses the cached session in `~/.euclid/credentials`, or `EUCLID_USER`/`EUCLID_PASSWORD` when
//! set; `EUCLID_LIVE_NAMESPACE` activates a namespace. Creates its own uniquely named secret and
//! deletes it again, also when a check fails. Secret values are never printed.

use std::future::Future;
use std::time::{SystemTime, UNIX_EPOCH};

use euclid_rdk::ess::{ListSecretsRequest, UpdateSecretRequest};
use euclid_rdk::{Eam, Session};

async fn session() -> Option<Session> {
    let Ok(url) = std::env::var("EUCLID_LIVE_URL") else {
        eprintln!("EUCLID_LIVE_URL not set - skipping");
        return None;
    };
    let mut eam = Eam::for_server(url);
    if let (Ok(user), Ok(password)) = (std::env::var("EUCLID_USER"), std::env::var("EUCLID_PASSWORD")) {
        eam = eam.credentials(user, password);
    }
    if let Ok(namespace) = std::env::var("EUCLID_LIVE_NAMESPACE") {
        eam = eam.namespace(namespace);
    }
    Some(eam.login().await.expect("login"))
}

fn unique_name(kind: &str) -> String {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("rdk-live-{kind}-{}-{}", std::process::id(), nanos % 1_000_000_000)
}

/// Runs `body`, then `cleanup` whatever happened, then re-raises a failure of `body`.
async fn with_cleanup<B, C>(body: B, cleanup: C)
where
    B: Future<Output = ()> + Send + 'static,
    C: Future<Output = ()>,
{
    let outcome = tokio::spawn(body).await;
    cleanup.await;
    if let Err(e) = outcome {
        std::panic::resume_unwind(e.into_panic());
    }
}

#[tokio::test]
#[ignore = "needs a live euclid server (EUCLID_LIVE_URL)"]
async fn ess_round_trip() {
    let Some(session) = session().await else { return };
    let ess = session.ess();
    let name = unique_name("secret");
    // Throwaway values, generated per run; still never printed.
    let first = format!("v1-{}", unique_name("value"));
    let second = format!("v2-{}", unique_name("value"));

    let created = ess.create_secret(&name, &first).await.expect("create secret");
    println!("created secret {name} (version {})", created.version);

    let test_ess = ess.clone();
    let test_name = name.clone();
    let body = async move {
        let (ess, name) = (test_ess, test_name);
        assert_eq!(created.name.as_deref(), Some(name.as_str()));

        // Creating it again is refused rather than replacing it.
        let again = ess.create_secret(&name, "other").await;
        assert_eq!(
            again.err().and_then(|e| e.status()),
            Some(409),
            "second create must be refused"
        );

        let got = ess.get_secret(&name).await.expect("get secret");
        assert!(got.value.as_deref() == Some(first.as_str()), "value read back differs");
        let version = got.secret.as_ref().map(|s| s.version).unwrap_or_default();

        let rotated = ess.rotate_secret(&name, &second).await.expect("rotate");
        assert!(
            rotated.version > version,
            "rotation bumps the version: {} -> {}",
            version,
            rotated.version
        );
        let got = ess.get_secret(&name).await.expect("get rotated secret");
        assert!(
            got.value.as_deref() == Some(second.as_str()),
            "rotated value read back differs"
        );

        let described = ess
            .update_secret(&UpdateSecretRequest {
                name: name.clone(),
                description: Some("euclid-rdk live test".into()),
                ..Default::default()
            })
            .await
            .expect("update description");
        assert_eq!(described.description.as_deref(), Some("euclid-rdk live test"));
        assert_eq!(
            described.version, rotated.version,
            "a description change is not a rotation"
        );

        let tagged = ess.add_secret_tag(&name, "owner", "rdk").await.expect("add tag");
        assert_eq!(tagged.tags.get("owner").map(String::as_str), Some("rdk"));
        let untagged = ess.delete_secret_tag(&name, "owner").await.expect("delete tag");
        assert!(!untagged.tags.contains_key("owner"));

        let listing = ess
            .list_secrets(&ListSecretsRequest {
                prefix: name.clone(),
                ..Default::default()
            })
            .await
            .expect("list secrets");
        assert!(listing.secrets.iter().any(|s| s.name.as_deref() == Some(name.as_str())));
        assert!(ess.exists_secret(&name).await.expect("exists"));
        let debug = format!("{got:?}");
        assert!(!debug.contains(&second), "Debug output leaks the value");
    };

    with_cleanup(body, async {
        match ess.delete_secret(&name).await {
            Ok(_) => println!("deleted secret {name}"),
            Err(e) => eprintln!("CLEANUP FAILED - delete secret {name} by hand: {e}"),
        }
        match ess.exists_secret(&name).await {
            Ok(false) => {}
            other => eprintln!("secret {name} still listed after delete: {other:?}"),
        }
    })
    .await;
}
