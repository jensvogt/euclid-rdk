//! EKM round trips against a real euclid server. Ignored by default; run with
//!
//! ```sh
//! EUCLID_LIVE_URL=https://localhost:5566 cargo test --test live_ekm -- --ignored --nocapture
//! ```
//!
//! Uses the cached session in `~/.euclid/credentials`, or `EUCLID_USER`/`EUCLID_PASSWORD` when
//! set; `EUCLID_LIVE_NAMESPACE` activates a namespace. Creates its own key and certificate and
//! removes them again, also when a check fails. Key material and data are never printed.
//!
//! The server names keys itself, so the scratch key is recognised by its ERN and its
//! `rdk-live-*` description. Deleting a key only schedules it: it stays `PENDING_DELETION` for the
//! pending window, which this test keeps at the server's minimum of 1 day: each run leaves one
//! revoked scratch key in `PENDING_DELETION` for a day.

use std::future::Future;
use std::time::{SystemTime, UNIX_EPOCH};

use euclid_rdk::ekm::{CreateKeyRequest, ListCertificatesRequest, ListKeysRequest};
use euclid_rdk::{Eam, Ekm, Session};

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

/// Schedules the key (by id, i.e. name) for deletion with the shortest pending window the server
/// accepts (1 day).
async fn delete_key(ekm: &Ekm, key_id: &str) {
    for window in [1, 7] {
        match ekm.delete_key_after(key_id, window).await {
            Ok(deleted) => {
                println!(
                    "deleted key {key_id} (pending window {window} days, status {:?}, deletion date {:?})",
                    deleted.status, deleted.deletion_date
                );
                return;
            }
            Err(e) => println!("delete-key with a {window}-day window refused: {e}"),
        }
    }
    eprintln!("CLEANUP FAILED - delete key {key_id} by hand");
}

#[tokio::test]
#[ignore = "needs a live euclid server (EUCLID_LIVE_URL)"]
async fn ekm_key_round_trip() {
    let Some(session) = session().await else { return };
    let ekm = session.ekm();
    let description = unique_name("key");
    let created = ekm
        .create_key_with(&CreateKeyRequest {
            length: 256,
            description: description.clone(),
            ..Default::default()
        })
        .await
        .expect("create key");
    let ern = created.ern.clone().expect("key ern");
    let key_id = created.name.clone().expect("key name (its id)");
    println!(
        "created key {ern} ({:?} {:?}/{})",
        created.name, created.algorithm, created.length
    );

    let test_ekm = ekm.clone();
    let test_ern = ern.clone();
    let body = async move {
        let (ekm, ern) = (test_ekm, test_ern);
        assert_eq!(created.description.as_deref(), Some(description.as_str()));
        assert_eq!(created.length, 256);

        let key = ekm.get_key(&ern).await.expect("get key by ern");
        assert_eq!(key.ern.as_deref(), Some(ern.as_str()));
        let name = key.name.clone().expect("key name");
        let by_name = ekm.get_key(&name).await.expect("get key by name");
        assert_eq!(by_name.ern.as_deref(), Some(ern.as_str()));
        assert!(ekm.exists_key(&ern).await.expect("exists"));
        assert!(!ekm.exists_key(&unique_name("missing")).await.expect("exists missing"));

        let listed = ekm
            .list_keys(&ListKeysRequest {
                page_size: 0,
                ..Default::default()
            })
            .await
            .expect("list keys");
        assert!(listed.keys.iter().any(|k| k.ern.as_deref() == Some(ern.as_str())));

        let described = ekm
            .set_key_description(&ern, &format!("{description} (changed)"))
            .await
            .expect("set description");
        assert!(described.description.unwrap_or_default().ends_with("(changed)"));

        ekm.add_key_tag(&ern, "purpose", "rdk-live").await.expect("add tag");
        let tagged = ekm.get_key(&ern).await.expect("get tagged key");
        assert_eq!(tagged.tags.get("purpose").map(String::as_str), Some("rdk-live"));
        ekm.delete_key_tag(&ern, "purpose").await.expect("delete tag");
        assert!(!ekm.get_key(&ern).await.expect("get key").tags.contains_key("purpose"));

        // Encrypt and decrypt round trip; neither side is printed.
        let plaintext = format!("plain-{}", unique_name("data")).into_bytes();
        let ciphertext = ekm.encrypt(&name, &plaintext).await.expect("encrypt");
        assert!(!ciphertext.is_empty());
        assert_ne!(ciphertext.expose(), plaintext.as_slice());
        let decrypted = ekm.decrypt(&name, ciphertext.expose()).await.expect("decrypt");
        assert!(decrypted.expose() == plaintext.as_slice(), "decrypted data differs");
        // encrypt takes the key's id, not its ERN.
        let by_ern = ekm.encrypt(&ern, b"x").await;
        assert_eq!(by_ern.err().and_then(|e| e.status()), Some(404));

        // A revoked key no longer encrypts.
        let revoked = ekm.revoke_key(&ern).await.expect("revoke");
        println!("revoked: status {:?}", revoked.status);
        let refused = ekm.encrypt(&name, b"x").await;
        assert!(refused.is_err(), "a revoked key must not encrypt");
        println!(
            "encrypt after revoke refused with {:?}",
            refused.err().and_then(|e| e.status())
        );
    };

    with_cleanup(body, async { delete_key(&ekm, &key_id).await }).await;

    let after = ekm.get_key(&ern).await;
    match after {
        Ok(key) => println!(
            "after delete: status {:?}, deletion date {:?}",
            key.status, key.deletion_date
        ),
        Err(e) => println!("after delete: {e}"),
    }
}

#[tokio::test]
#[ignore = "needs a live euclid server (EUCLID_LIVE_URL)"]
async fn ekm_certificate_round_trip() {
    let Some(session) = session().await else { return };
    let ekm = session.ekm();
    let name = unique_name("cert");
    let created = ekm
        .create_certificate_with(&euclid_rdk::ekm::CreateCertificateRequest {
            name: name.clone(),
            description: "rdk live test".into(),
            common_name: "rdk-live.example".into(),
            subject_alt_names: vec!["rdk-live.example".into()],
            valid_days: 1,
            ..Default::default()
        })
        .await
        .expect("create certificate");
    println!("created certificate {name}");

    let test_ekm = ekm.clone();
    let test_name = name.clone();
    let body = async move {
        let (ekm, name) = (test_ekm, test_name);
        assert_eq!(created.name.as_deref(), Some(name.as_str()));
        assert!(created.generated);
        assert!(created
            .certificate
            .as_deref()
            .unwrap_or_default()
            .contains("BEGIN CERTIFICATE"));
        assert!(created.subject.unwrap_or_default().contains("rdk-live.example"));

        let fetched = ekm.get_certificate(&name).await.expect("get certificate");
        assert_eq!(fetched.ern, created.ern);
        assert_eq!(fetched.fingerprint, created.fingerprint);

        let listed = ekm
            .list_certificates(&ListCertificatesRequest {
                prefix: name.clone(),
                ..Default::default()
            })
            .await
            .expect("list certificates");
        assert!(listed
            .certificates
            .iter()
            .any(|c| c.name.as_deref() == Some(name.as_str())));
    };

    with_cleanup(body, async {
        match ekm.delete_certificate(&name).await {
            Ok(_) => println!("deleted certificate {name}"),
            Err(e) => eprintln!("CLEANUP FAILED - delete certificate {name} by hand: {e}"),
        }
    })
    .await;
    assert_eq!(
        ekm.get_certificate(&name).await.err().and_then(|e| e.status()),
        Some(404),
        "certificate should be gone"
    );
}
