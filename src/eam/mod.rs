//! EAM - Euclid Access Management: logging in, and managing users, groups, accounts, namespaces,
//! access keys, roles and grants.

pub mod model;
mod session;

use std::path::{Path, PathBuf};

pub use model::*;
pub use session::Session;

use crate::credentials::{self, CachedCredentials};
use crate::http::HttpClient;
use crate::{Error, Result};

/// Where euclid deployments put the server's CA certificate, in the order they are tried: first
/// euclid-cli's default for the platform, then euclid-jdk's `/etc/euclid` location. The first one
/// that exists is used; on a machine without a deployment none does, and the system trust store
/// alone applies.
#[cfg(windows)]
pub const DEFAULT_CA_CERT_PATHS: &[&str] = &["C:\\Program Files\\euclid\\etc\\euclid_cert.crt"];
#[cfg(not(windows))]
pub const DEFAULT_CA_CERT_PATHS: &[&str] = &["/usr/local/euclid/etc/euclid_cert.crt", "/etc/euclid/euclid_cert.crt"];

fn default_ca_cert() -> Option<PathBuf> {
    DEFAULT_CA_CERT_PATHS.iter().map(PathBuf::from).find(|p| p.is_file())
}

/// Fluent builder for authenticating against an Euclid server.
///
/// ```no_run
/// # async fn run() -> euclid_rdk::Result<()> {
/// let session = euclid_rdk::Eam::for_server("https://euclid.example.com")
///     .credentials("jens", "secret")
///     .namespace("prod")
///     .login()
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Eam {
    base_url: String,
    login_path: String,
    username: Option<String>,
    email: Option<String>,
    password: Option<String>,
    ca_cert_path: Option<PathBuf>,
    account: Option<String>,
    namespace: Option<String>,
    cache: CachePolicy,
}

#[derive(Debug, Clone)]
enum CachePolicy {
    /// `$HOME/.euclid/credentials`, shared with euclid-cli and euclid-jdk.
    Default,
    File(PathBuf),
    Disabled,
}

impl std::fmt::Debug for Eam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Eam")
            .field("base_url", &self.base_url)
            .field("login_path", &self.login_path)
            .field("username", &self.username)
            .field("email", &self.email)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("ca_cert_path", &self.ca_cert_path)
            .field("account", &self.account)
            .field("namespace", &self.namespace)
            .field("cache", &self.cache)
            .finish()
    }
}

impl Eam {
    /// Starts a login against `base_url`; a trailing slash is ignored.
    pub fn for_server(base_url: impl Into<String>) -> Self {
        let base_url = base_url.into();
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            login_path: "/".into(),
            username: None,
            email: None,
            password: None,
            ca_cert_path: default_ca_cert(),
            account: None,
            namespace: None,
            cache: CachePolicy::Default,
        }
    }

    /// Path the login request is posted to, relative to the base URL. Defaults to `/`.
    pub fn login_path(mut self, login_path: impl Into<String>) -> Self {
        let path = login_path.into();
        self.login_path = if path.starts_with('/') {
            path
        } else {
            format!("/{path}")
        };
        self
    }

    /// Additional PEM CA certificate to trust, alongside the system trust store. Defaults to
    /// the first of [`DEFAULT_CA_CERT_PATHS`] that exists.
    pub fn ca_cert_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.ca_cert_path = Some(path.into());
        self
    }

    /// Trust the system roots only, even if one of [`DEFAULT_CA_CERT_PATHS`] exists.
    pub fn no_ca_cert(mut self) -> Self {
        self.ca_cert_path = None;
        self
    }

    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Sets username and password together.
    pub fn credentials(self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.username(username).password(password)
    }

    /// Logs in by email address instead of username. A username set alongside wins: the server
    /// resolves by user ID first and falls back to the email only when no user ID was given.
    pub fn email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    /// Account to work in instead of the user's home account, by account id or by name - mirroring
    /// `euclid-cli eam login --account`. Checked against
    /// [`Session::list_my_accounts`] right after login (see [`Session::switch_account`]) and
    /// applied before [`namespace`](Self::namespace), which is then looked for in this account.
    /// Applies whether login reuses a cached session or performs a fresh one.
    pub fn account(mut self, account: impl Into<String>) -> Self {
        self.account = Some(account.into()).filter(|a: &String| !a.is_empty());
        self
    }

    /// Namespace to make active once login succeeds - applied with a follow-up `change-namespace`,
    /// mirroring `euclid-cli eam login --namespace`. Applies whether login reuses a cached session
    /// or performs a fresh one.
    pub fn namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    /// Caches the session in `path` instead of `$HOME/.euclid/credentials`.
    pub fn credentials_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.cache = CachePolicy::File(path.into());
        self
    }

    /// Neither reads nor writes a credentials cache: every `login()` goes to the server.
    pub fn no_cache(mut self) -> Self {
        self.cache = CachePolicy::Disabled;
        self
    }

    fn cache_path(&self) -> Option<PathBuf> {
        match &self.cache {
            CachePolicy::Default => credentials::default_path(),
            CachePolicy::File(path) => Some(path.clone()),
            CachePolicy::Disabled => None,
        }
    }

    /// Authenticates and returns a session.
    ///
    /// If the credentials cache holds a still-valid token for this server, that session is
    /// reused without contacting the server (other than to switch account or namespace, if one was
    /// asked for and differs). Otherwise the configured credentials are sent and the resulting session is
    /// cached.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] if nothing is cached and no username/email or password was set,
    /// [`Error::Authentication`] if the server rejects the login, [`Error::InvalidArgument`] if an
    /// [`account`](Self::account) was asked for that is not one of the user's - the login itself
    /// still stands and is cached, in the home account, as `euclid-cli` does.
    pub async fn login(&self) -> Result<Session> {
        let cache_path = self.cache_path();
        let http = HttpClient::new(self.ca_cert_path.as_deref())?;

        if let Some(mut cached) = cache_path.as_deref().and_then(|p| self.cached_session(p, &http)) {
            if let Some(account) = &self.account {
                if cached.account_id() != Some(account.as_str()) {
                    cached.switch_account(account).await?;
                }
            }
            if let Some(ns) = &self.namespace {
                if cached.namespace() != Some(ns.as_str()) {
                    cached.change_namespace(ns).await?;
                }
            }
            return Ok(cached);
        }

        let username = self.username.clone().filter(|u| !u.is_empty());
        let email = self.email.clone().filter(|e| !e.is_empty());
        if username.is_none() && email.is_none() {
            return Err(Error::invalid("username or email must be set before calling login()"));
        }
        let Some(password) = self.password.clone() else {
            return Err(Error::invalid("password must be set before calling login()"));
        };

        // Only one identifier is sent: the server takes the user ID when present, so sending both
        // would silently ignore the email.
        let request = LoginRequest {
            email: if username.is_some() {
                String::new()
            } else {
                email.unwrap_or_default()
            },
            user_id: username.unwrap_or_default(),
            password,
        };
        let url = format!("{}{}", self.base_url, self.login_path);
        let headers = [("content-type".to_owned(), "application/json".to_owned())];
        let response = http
            .post(&url, serde_json::to_vec(&request)?, "eam", "login", &headers, None)
            .await?;
        if !response.is_success() {
            return Err(Error::Authentication {
                status: response.status,
                body: response.text(),
            });
        }

        let login: LoginResponse = serde_json::from_slice(&response.body)?;
        let metadata = login.metadata.unwrap_or_default();
        let mut session = Session::new(
            http,
            self.base_url.clone(),
            cache_path.clone(),
            CachedCredentials {
                token: login.token,
                user_id: metadata.user,
                account_id: metadata.account_id,
                region: metadata.region,
                access_key_id: login.access_key_id,
                secret_access_key: login.secret_access_key,
                is_admin: login.is_admin,
                base_url: Some(self.base_url.clone()),
                namespace: None,
            },
        );
        // The account before the namespace: a namespace belongs to an account, and the one
        // change-namespace checks it against is whichever the request carries.
        if let Some(account) = &self.account {
            if let Err(err) = session.switch_account(account).await {
                // The credentials were right, so the session is kept - in the home account - and
                // the next attempt need not send the password again for a typo in an account name.
                if let Some(path) = &cache_path {
                    credentials::store(path, &session.to_cached())?;
                }
                return Err(err);
            }
        }
        if let Some(ns) = &self.namespace {
            session.change_namespace(ns).await?;
        }
        if let Some(path) = &cache_path {
            credentials::store(path, &session.to_cached())?;
        }
        Ok(session)
    }

    fn cached_session(&self, path: &Path, http: &HttpClient) -> Option<Session> {
        let mut cached = credentials::load(path)?;
        let token = cached.token.as_deref()?;
        if cached.base_url.as_deref() != Some(self.base_url.as_str()) || !credentials::is_token_valid(token) {
            return None;
        }
        cached.namespace = cached.namespace.filter(|n| !n.is_empty());
        Some(Session::new(
            http.clone(),
            self.base_url.clone(),
            Some(path.to_path_buf()),
            cached,
        ))
    }
}
