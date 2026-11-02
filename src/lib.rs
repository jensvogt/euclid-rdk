//! Rust client library for the [Euclid](https://github.com/jensvogt/euclid) APIs.
//!
//! The Rust counterpart of `euclid-jdk`. Log in once and reuse the cached session:
//!
//! ```no_run
//! # async fn run() -> euclid_rdk::Result<()> {
//! use euclid_rdk::Euclid;
//!
//! let session = Euclid::for_server("https://euclid.example.com")
//!     .access()
//!     .credentials("jens", "secret")
//!     .login()
//!     .await?;
//!
//! println!("logged in as {:?} in account {:?}", session.user_id(), session.account_id());
//! # Ok(())
//! # }
//! ```
//!
//! The token returned by `login()` is cached in `~/.euclid/credentials` - the same file euclid-cli
//! and euclid-jdk read and write - and reused automatically while it is still valid, so a later
//! process can skip straight to [`Euclid::session`].

pub mod auth;
pub mod credentials;
pub mod eam;
pub mod eqs;
mod error;
pub mod esm;
mod http;
mod serde_util;
mod service;
mod variant;

pub use eam::{Eam, Session};
pub use eqs::Eqs;
pub use error::{Error, Result};
pub use esm::Esm;
pub use variant::Variant;

/// Main entry point for talking to an Euclid server, e.g.
/// `Euclid::for_server(url).access().credentials(..).login().await`.
#[derive(Debug, Clone)]
pub struct Euclid {
    base_url: String,
}

impl Euclid {
    /// Targets an Euclid server, e.g. `https://euclid.example.com`.
    pub fn for_server(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
        }
    }

    /// Starts an EAM login flow against this server.
    pub fn access(&self) -> Eam {
        Eam::for_server(&self.base_url)
    }

    /// Resolves a session from the cached credentials for this server.
    ///
    /// Requires a prior `access().credentials(..).login()` - from this crate, euclid-jdk or
    /// euclid-cli - to have left a still-valid token in `~/.euclid/credentials`; otherwise this
    /// fails asking for explicit credentials.
    pub async fn session(&self) -> Result<Session> {
        self.access().login().await
    }

    /// EQS operations using the cached session for this server (see [`Euclid::session`]).
    pub async fn eqs(&self) -> Result<Eqs> {
        Ok(self.session().await?.eqs())
    }

    /// ESM operations using the cached session for this server (see [`Euclid::session`]).
    pub async fn esm(&self) -> Result<Esm> {
        Ok(self.session().await?.esm())
    }
}
