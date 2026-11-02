# euclid-rdk

[![CI](https://github.com/jensvogt/euclid-rdk/actions/workflows/ci.yml/badge.svg)](https://github.com/jensvogt/euclid-rdk/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/euclid-rdk.svg)](https://crates.io/crates/euclid-rdk)
[![docs.rs](https://docs.rs/euclid-rdk/badge.svg)](https://docs.rs/euclid-rdk)

Rust client library for the [Euclid](https://github.com/jensvogt/euclid) APIs - the Rust
counterpart of [euclid-jdk](https://github.com/jensvogt/euclid-jdk).

Async, built on `reqwest`; use it from any Tokio runtime. Requires Rust 1.88+.

Status: **EAM** (access management), **EQS** (queues), **ENS** (pub/sub topics), **ESM** (object
storage), **EKV** (key-value tables), **ESS** (secrets), **ETS** (transfer servers) and **EAG** (API
gateway) are implemented. EAP, EES, EKM and EMO follow.

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

EAM calls carry the bearer token. All other module calls are SigV4-signed with the access key the login
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

### ENS topics

```rust
let ens = session.ens();                      // or Euclid::for_server(url).ens().await?

let topic = ens.create_topic("orders").await?.ern.unwrap();
ens.subscribe(&topic, &queue_ern).await?;     // fan out to an EQS queue ("SQS" protocol)

let mut attributes = HashMap::new();
attributes.insert("kind".to_owned(), Variant::string("order"));
ens.publish_message_with(&PublishMessageRequest {
    ern: topic.clone(), body: r#"{"orderId":"4711"}"#.into(), attributes, priority: "HIGH".into(),
}).await?;
```

A topic is never consumed from: it fans each message out to its subscriptions at publish time and
keeps a record for its retention period (`set_topic_retention`, `RETENTION_FOREVER`). The priority
belongs to the fanned-out queue messages. `stop_topic` holds delivery without losing what arrives,
and `start_topic` releases the backlog. Also: `list_messages`/`get_message`/`get_message_count`
(read without consuming), message attributes, `update_message_body`, `resend_messages` (a replay,
so subscribers must be idempotent), tags, `set_topic_max_message_length`, `purge_topic`, and
`list_subscriptions`/`unsubscribe`.

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

### EKV key-value tables

```rust
use euclid_rdk::ekv::*;
use serde_json::json;

let ekv = session.ekv();                      // or Euclid::for_server(url).ekv().await?
ekv.create_table("orders", "customer", Some("order")).await?;

ekv.put_item("orders", &json!({ "customer": "alice", "order": "2026-11-01", "amount": 10 })).await?;
let item = ekv.get_item("orders", &json!({ "customer": "alice", "order": "2026-11-01" })).await?;
println!("{:?} (created {:?})", item.get("amount"), item.created);

let recent = ekv.query_where("orders", "alice", SortOperator::Ge, "2026-11-01").await?;
let page = ekv.scan("orders", 100, 0).await?;           // page size 0 = everything
```

Items and keys are plain JSON objects, so a `json!` value or any `Serialize` struct works. The
server's `_created`/`_modified` attributes come back as `Item::created`/`Item::modified`. Key types
default to `string`; `create_table_with(&CreateTableRequest { .. })` sets `KeyType::Number` or
`KeyType::Binary`. `query_with(&QueryRequest { .. })` adds `SortOperator::Between` (with
`sort_upper`), descending order (`forward: false`) and paging. Also: `list_tables`, `get_table`,
`exists_table`, `delete_item` and `delete_table`. A missing item is a 404 `Error::Service`.

### ESS secrets

```rust
let ess = session.ess();                      // or Euclid::for_server(url).ess().await?

ess.create_secret("db-password", "s3cr3t").await?;      // 409 if the name is taken
let secret = ess.get_secret("db-password").await?;      // the only call that decrypts
let value = secret.value.unwrap_or_default();

ess.rotate_secret("db-password", "n3w").await?;         // bumps `version`
ess.update_secret(&UpdateSecretRequest {
    name: "db-password".into(), description: Some("prod database".into()), ..Default::default()
}).await?;
```

Secrets are encrypted under the namespace's EKM key unless `create_secret_with` names another
(`key_ern`). In `update_secret` only the fields that are `Some` change; `Some("")` clears a
description, `None` leaves it alone. Listings never carry values, and `Debug` output of anything
holding a value prints `<redacted>`. Also: `list_secrets`, `exists_secret`, `delete_secret` and
`add_secret_tag`/`delete_secret_tag`.

### ETS transfer servers

```rust
use euclid_rdk::ets::*;

let ets = session.ets();                      // administrator-only: others get 403
let server = ets.create_server(&CreateServerRequest {
    server_id: "inbound".into(),
    port: Some(2222),
    bucket: Some("uploads".into()),
    home_directory: Some("{user}".into()),    // every client gets its own key prefix
    user_groups: Some(vec!["partners".into()]),
    ..Default::default()                      // SFTP on 0.0.0.0
}).await?;
ets.start_server("inbound").await?;           // records intent; `state` follows shortly
```

A transfer server is an FTP or SFTP listener in front of an ESM bucket: clients log in with their
EAM credentials and every upload becomes an object. It is created stopped; `start_server` and
`stop_server` set `desired_state`, and the server's reconciler brings `state` in line.
`update_server` sends only the fields that are set. Also: `list_servers`, `get_server`,
`delete_server`. An unknown bucket is a 404, a port already in use a 409.

### EAG API gateway

```rust
use euclid_rdk::eag::*;

let eag = session.eag();                      // administrator-only: others get 403
eag.create_route("produkte", "/api/produkte", "my-app").await?;
eag.create_module_route("login", "/api/login", "eam", "login").await?;   // one origin, no CORS
eag.set_route_active("produkte", false).await?;                          // stop exposing it, keep it

let listeners = eag.list_listeners().await?;
```

The API gateway publishes plain HTTP paths to the outside world and forwards them to an
application or to one euclid module action. `update_route(&RouteRequest { .. })` changes only the
fields given, and the same struct with `create_route_with` sets methods, namespace,
`RouteAuthentication` and `active`. `list_routes(prefix)` covers the session's namespace;
`list_listeners` reports what is configured and, through `serving`, whether anything is bound.
Also: `get_route`, `delete_route`.

### Errors

Every call returns `euclid_rdk::Result<T>`. `Error::Authentication` is a rejected login,
`Error::Service { service, action, status, body }` any other non-2xx answer; `err.status()` gives
the HTTP status either way.

## Examples

```sh
EUCLID_URL=https://localhost:5566 EUCLID_USER=jens EUCLID_PASSWORD=secret cargo run --example login
EUCLID_URL=https://localhost:5566 cargo run --example eqs [-- <queue>]   # read-only
EUCLID_URL=https://localhost:5566 cargo run --example ens                # read-only
EUCLID_URL=https://localhost:5566 cargo run --example esm                # read-only
EUCLID_URL=https://localhost:5566 cargo run --example ekv [-- <table>]   # read-only
EUCLID_URL=https://localhost:5566 cargo run --example ess                # read-only, never prints values
EUCLID_URL=https://localhost:5566 cargo run --example ets [-- <id>]      # read-only
EUCLID_URL=https://localhost:5566 cargo run --example eag                # read-only
EUCLID_URL=https://localhost:5566 cargo run --example invoke -- eqs list-queues '{"pageSize":3}'
```

All but `login` use the cached session.

## Live tests

`tests/live*.rs` run round trips against a real server: EQS send/receive/delete, ESM objects and
a 12 MiB multipart transfer, ENS publish fanned out to a subscribed queue, EKV put/get/query/scan,
and an ESS secret lifecycle. Each creates uniquely named `rdk-live-*` resources and deletes them again, also when a check
fails. Ignored by default:

```sh
EUCLID_LIVE_URL=https://localhost:5566 cargo test --test live --test live_ens --test live_ekv --test live_ess -- --ignored --nocapture
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
