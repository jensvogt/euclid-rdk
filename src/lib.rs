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
pub mod eag;
pub mod eam;
pub mod eap;
pub mod ees;
pub mod ekm;
pub mod ekv;
pub mod emo;
pub mod ens;
pub mod eqs;
mod error;
pub mod esm;
pub mod ess;
pub mod ets;
mod http;
mod serde_util;
mod service;
mod variant;

pub use eag::Eag;
pub use eam::{Eam, Session};
pub use eap::Eap;
pub use ees::Ees;
pub use ekm::Ekm;
pub use ekv::Ekv;
pub use emo::Emo;
pub use ens::Ens;
pub use eqs::Eqs;
pub use error::{Error, Result};
pub use esm::Esm;
pub use ess::Ess;
pub use ets::Ets;
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

    /// ENS operations using the cached session for this server (see [`Euclid::session`]).
    pub async fn ens(&self) -> Result<Ens> {
        Ok(self.session().await?.ens())
    }

    /// EKV operations using the cached session for this server (see [`Euclid::session`]).
    pub async fn ekv(&self) -> Result<Ekv> {
        Ok(self.session().await?.ekv())
    }

    /// ESM operations using the cached session for this server (see [`Euclid::session`]).
    pub async fn esm(&self) -> Result<Esm> {
        Ok(self.session().await?.esm())
    }

    /// ESS operations using the cached session for this server (see [`Euclid::session`]).
    pub async fn ess(&self) -> Result<Ess> {
        Ok(self.session().await?.ess())
    }

    /// ETS operations using the cached session for this server (see [`Euclid::session`]).
    pub async fn ets(&self) -> Result<Ets> {
        Ok(self.session().await?.ets())
    }

    /// EAG operations using the cached session for this server (see [`Euclid::session`]).
    pub async fn eag(&self) -> Result<Eag> {
        Ok(self.session().await?.eag())
    }

    /// EKM operations using the cached session for this server (see [`Euclid::session`]).
    pub async fn ekm(&self) -> Result<Ekm> {
        Ok(self.session().await?.ekm())
    }

    /// EAP operations using the cached session for this server (see [`Euclid::session`]).
    pub async fn eap(&self) -> Result<Eap> {
        Ok(self.session().await?.eap())
    }

    /// EMO operations using the cached session for this server (see [`Euclid::session`]).
    pub async fn emo(&self) -> Result<Emo> {
        Ok(self.session().await?.emo())
    }

    /// EES operations using the cached session for this server (see [`Euclid::session`]).
    pub async fn ees(&self) -> Result<Ees> {
        Ok(self.session().await?.ees())
    }
}
