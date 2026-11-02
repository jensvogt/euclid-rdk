# euclid-rdk

[![CI](https://github.com/jensvogt/euclid-rdk/actions/workflows/ci.yml/badge.svg)](https://github.com/jensvogt/euclid-rdk/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/euclid-rdk.svg)](https://crates.io/crates/euclid-rdk)
[![docs.rs](https://docs.rs/euclid-rdk/badge.svg)](https://docs.rs/euclid-rdk)

Rust client library for the [Euclid](https://github.com/jensvogt/euclid) APIs - the Rust
counterpart of [euclid-jdk](https://github.com/jensvogt/euclid-jdk).

Async, built on `reqwest`; use it from any Tokio runtime. Requires Rust 1.88+.

Status: **EAM** (access management), **EQS** (queues) and **ESM** (object storage) are implemented.
ENS and the other modules follow.

## Installation

```toml
[dependencies]
euclid-rdk = "0.1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Usage

Log in once and reuse the cached session:

```rust
use euclid_rdk::Euclid;

#[tokio::main]
async fn main() -> euclid_rdk::Result<()> {
    let session = Euclid::for_server("https://euclid.example.com")
        .access()
        .credentials("jens", "secret")
        .login()
        .await?;

    println!("{:?} in account {:?}", session.user_id(), session.account_id());
    Ok(())
}
```

The token returned by `login()` is cached in `~/.euclid/credentials` - the same file euclid-cli and
euclid-jdk use, so a login from any of them is picked up by the others - and reused while still
valid. Later processes can skip straight to:

```rust
let session = Euclid::for_server("https://euclid.example.com").session().await?;
```

### Login options

```rust
Euclid::for_server(url)
    .access()
    .email("jens@example.com")          // instead of a username
    .password("secret")
    .namespace("prod")                  // activate a namespace after login
    .ca_cert_path("/path/to/ca.crt")    // extra CA cert, alongside the system roots
    .credentials_file("/tmp/creds")     // cache elsewhere ...
    .no_cache()                         // ... or not at all
    .login()
    .await?;
```

If `/usr/local/euclid/etc/euclid_cert.crt` (euclid-cli's default) or `/etc/euclid/euclid_cert.crt`
exists, it is trusted automatically;
`no_ca_cert()` opts out.

### EAM operations

```rust
use euclid_rdk::eam::*;

let users = session.list_users(&ListUsersRequest { prefix: "j".into(), ..Default::default() }).await?;
let user = session.get_user("bob").await?;
session.change_password("old", "new").await?;

let grant = session.grant_role(&GrantRoleRequest {
    role: "operator".into(),
    principal: "ern:euclid:eam:eu-central-1:863459426936:user/bob".into(),
    namespaces: vec!["prod".into()],
    ..Default::default()                // resources default to "*"
}).await?;
session.revoke_role(grant.grant_id.as_deref().unwrap()).await?;

let check = session.check_permission(&CheckPermissionRequest {
    user_id: "bob".into(), target: "ens".into(), action: "publish-message".into(),
    namespace: "prod".into(), ..Default::default()
}).await?;
```

Also available: `register`, `delete_user`, `reset_password`, `change_namespace`, `logout`,
access keys (`create_access_key`, `list_access_keys`, `delete_access_key`), user groups, accounts,
namespaces, roles (`create_role`, `update_role`, `get_role`, `list_roles`, `delete_role`),
`list_grants` and `list_permissions`.

Anything not wrapped yet can be called directly:

```rust
let raw: serde_json::Value = session.invoke("eam", "some-action", &serde_json::json!({})).await?;
```

### Authentication

EAM calls carry the bearer token. EQS and ESM calls are SigV4-signed with the access key the login
returned (falling back to the bearer token without one), exactly as euclid-cli and euclid-jdk sign
them; a signed request answered `401 ... expired` is re-signed and sent once more. Object bytes
(ESM uploads/downloads) always travel with the bearer token.

### EQS queues

```rust
let eqs = session.eqs();                      // or Euclid::for_server(url).eqs().await?

let ern = eqs.create_queue("orders").await?.ern.unwrap();
eqs.send_message(&ern, r#"{"orderId":"4711"}"#).await?;

let response = eqs.receive_messages(&ern, 10, 20).await?;   // up to 10, wait up to 20 s
for message in response.messages {
    println!("{:?}", message.body);
    eqs.delete_message(message.receipt_handle.as_deref().unwrap()).await?;
}
```

Attributes and priority go through `send_message_with(&SendMessageRequest { .. })` using
`Variant::string(..)`/`Variant::new(type, value)`; `send_message_batch` sends many at once and
reports refused entries in `failed`. A short poll (`wait_time` 0) checks the message count first
and trusts a zero only for 10 s (`zero_count_trust`). Also: `list_queues`, `get_queue`,
`get_queue_ern`, `exists_queue`, `get_message_count`, `list_messages` (peek without consuming),
`purge_queue`, `stop_queue`/`start_queue`, `set_queue_visibility`/`delay`/`max_message_length`,
`redrive_dlq`, tags, message attributes and `update_message_body`. Queue names resolve within the
session's namespace; an ERN always works.

### ESM object storage

```rust
use euclid_rdk::esm::*;

let esm = session.esm();
let bucket = esm.create_bucket("reports", None).await?.ern.unwrap();

esm.put_object(&bucket, "hello.txt", b"hello".to_vec()).await?;
let bytes = esm.get_object(&bucket, "hello.txt", 5 * 1024 * 1024).await?;

// Large files go up and come down in parallel parts (5 MiB, 4 at a time by default);
// files smaller than one part use a single request.
esm.upload_file(&bucket, "big.iso", "/tmp/big.iso", &TransferOptions::default()).await?;
esm.download_file(&bucket, "big.iso", "/tmp/copy.iso", &TransferOptions::default()).await?;

let objects = esm.list_objects(&ListObjectsRequest { bucket_ern: bucket.clone(), ..Default::default() }).await?;
```

Also available: bucket tags, priority, stop/start, encryption, rename/purge,
`copy_object`/`move_object`/`rename_object`, object attributes (`Variant`), subscriptions
(`BucketEvent::parse` for delivered events), `upload_directory`/`download_bucket`, and the raw
multipart calls (`create_upload`, `upload_part`, `complete_upload`, `abort_upload`, ...). Failed
parts are retried on 5xx/connection errors; a part that fails for good aborts the upload. Byte
transfers use a 120 s timeout (`with_transfer_timeout`), JSON calls 10 s.

### Errors

Every call returns `euclid_rdk::Result<T>`. `Error::Authentication` is a rejected login,
`Error::Service { service, action, status, body }` any other non-2xx answer; `err.status()` gives
the HTTP status either way.

## Examples

```sh
EUCLID_URL=https://localhost:5566 EUCLID_USER=jens EUCLID_PASSWORD=secret cargo run --example login
EUCLID_URL=https://localhost:5566 cargo run --example eqs [-- <queue>]   # read-only
EUCLID_URL=https://localhost:5566 cargo run --example esm                # read-only
EUCLID_URL=https://localhost:5566 cargo run --example invoke -- eqs list-queues '{"pageSize":3}'
```

All but `login` use the cached session.

## Live tests

`tests/live.rs` runs EQS and ESM round trips against a real server: it creates a uniquely named
queue and bucket, sends/receives/deletes messages, uploads and downloads a 12 MiB multipart file,
and deletes both again, also when a check fails. Ignored by default:

```sh
EUCLID_LIVE_URL=https://localhost:5566 cargo test --test live -- --ignored --nocapture
```

## TLS

The default `native-tls` feature uses OpenSSL and accepts a self-signed development certificate as
the CA. The `rustls-tls` feature is available (`default-features = false, features = ["rustls-tls"]`),
but rustls rejects a self-signed leaf used as its own trust anchor.

## Releasing

Releases are cut by [release-please](https://github.com/googleapis/release-please) from
[Conventional Commits](https://www.conventionalcommits.org/) on `master`: a `feat:`/`fix:` commit
opens or updates a release PR that bumps the version in `Cargo.toml` and `CHANGELOG.md`. Merging
it tags the release, and the `publish` job uploads the crate to crates.io (needs the
`CARGO_REGISTRY_TOKEN` repository secret).
