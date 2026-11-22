//! EAM - Euclid Access Management: logging in, and managing users, groups, accounts, namespaces,
//! access keys, roles and grants.

mod callback;
pub mod model;
mod session;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

pub use model::*;
pub use session::Session;

use crate::credentials::{self, CachedCredentials};
use crate::http::{HttpClient, Response};
use crate::{Error, Result};
use callback::{Callback, LoopbackListener};

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

/// How long a federated login waits for the browser to come back unless told otherwise: the same
/// three minutes euclid-cli waits - long enough to type a password and a second factor, short
/// enough that a login nobody is attending to does not hold a port open indefinitely.
pub const DEFAULT_CALLBACK_TIMEOUT: Duration = Duration::from_secs(180);

type BrowserHook = Arc<dyn Fn(&str) + Send + Sync>;

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
///
/// An installation that federates its logins to an identity provider is signed into through a
/// browser instead, exactly as `euclid-cli eam login --oidc` / `--saml` do - no password is asked
/// for or sent, because the provider decides who is signing in:
///
/// ```no_run
/// # async fn run() -> euclid_rdk::Result<()> {
/// let session = euclid_rdk::Eam::for_server("https://euclid.example.com")
///     .login_with_oidc() // or login_with_saml()
///     .await?;
/// # Ok(())
/// # }
/// ```
///
/// Every way in ends the same way: the session is cached in `$HOME/.euclid/credentials`, shared
/// with euclid-cli and euclid-jdk, and reused by the next login while its token is valid. A
/// federated session is not a different kind of session - the server issues the same token, access
/// key and admin flag whichever proof it was given.
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
    browser: Option<BrowserHook>,
    callback_timeout: Duration,
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
            .field("browser", &self.browser.as_ref().map(|_| "<custom>"))
            .field("callback_timeout", &self.callback_timeout)
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
            browser: None,
            callback_timeout: DEFAULT_CALLBACK_TIMEOUT,
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

    /// Sets how a federated login ([`login_with_oidc`](Self::login_with_oidc),
    /// [`login_with_saml`](Self::login_with_saml)) shows the person the URL they have to
    /// authenticate at. Called once per login, before the wait for the callback begins.
    ///
    /// The default prints the URL to standard error and opens the system browser (`xdg-open`,
    /// `open` or `rundll32`), so somebody on a machine without one - over ssh, in a container - can
    /// copy the URL to one that has. An application with a user interface of its own will rather
    /// show the link there; a test drives the flow by fetching the URL itself.
    ///
    /// The hook must not block on the callback: the listener only answers once the hook has
    /// returned. Fetch the URL from a spawned task or thread instead.
    pub fn browser(mut self, browser: impl Fn(&str) + Send + Sync + 'static) -> Self {
        self.browser = Some(Arc::new(browser));
        self
    }

    /// Sets how long a federated login waits for the browser to come back before giving up.
    /// [`DEFAULT_CALLBACK_TIMEOUT`] (three minutes) unless set.
    pub fn callback_timeout(mut self, timeout: Duration) -> Self {
        self.callback_timeout = timeout;
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
        let http = self.http()?;

        if let Some(cached) = self.reuse_cached(cache_path.as_deref(), &http).await? {
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
        let response = self.post_login_path(&http, "login", &request).await?;
        if !response.is_success() {
            return Err(authentication_error(&response));
        }
        let login: LoginResponse = serde_json::from_slice(&response.body)?;
        self.establish(http, cache_path, login).await
    }

    /// Signs in through the installation's OpenID Connect provider, in a browser, the way
    /// `euclid-cli eam login --oidc` does - and caches the session exactly as
    /// [`login`](Self::login) does.
    ///
    /// The flow: a listener is bound on a loopback port first, because the redirect URI has to
    /// name the port it ended up on; the server is asked (`oidc-authorize`) where to send the
    /// person, with that listener as the redirect URI; the URL goes to the
    /// [`browser`](Self::browser); and once the provider redirects back with a code, the code and
    /// its state are redeemed (`oidc-login`) for an ordinary euclid session. No password is asked
    /// for or sent - the provider says who is signing in - so a username or password set on this
    /// builder is ignored. [`account`](Self::account) and [`namespace`](Self::namespace) apply as
    /// they do to a password login.
    ///
    /// A still-valid cached session is reused instead, as [`login`](Self::login) reuses one: the
    /// point of caching is not having to go through the browser again within the hour.
    ///
    /// The state that comes back is checked against the one that went out before anything is
    /// redeemed. The server would refuse a state it did not seal anyway, but a mismatch caught here
    /// says plainly that the callback belongs to a different login attempt.
    ///
    /// # Errors
    ///
    /// [`Error::Service`] if the server cannot start the flow - OIDC is not enabled (404),
    /// misconfigured (500), or the provider is unreachable (502); [`Error::Authentication`] if the
    /// provider refused the login, the callback does not belong to this attempt, or the server
    /// would not redeem the code (401) or give this identity an account (403); [`Error::Io`] of
    /// kind [`TimedOut`](std::io::ErrorKind::TimedOut) if the browser did not come back within the
    /// [`callback_timeout`](Self::callback_timeout), or of another kind if no loopback port could
    /// be bound.
    pub async fn login_with_oidc(&self) -> Result<Session> {
        let cache_path = self.cache_path();
        let http = self.http()?;
        if let Some(cached) = self.reuse_cached(cache_path.as_deref(), &http).await? {
            return Ok(cached);
        }

        let listener = LoopbackListener::bind().await?;
        let authorization = self
            .oidc_authorize_with(
                &http,
                &OidcAuthorizeRequest {
                    redirect_uri: listener.callback_url(),
                    ..Default::default()
                },
            )
            .await?;
        let Some(url) = authorization.authorization_url.filter(|u| !u.is_empty()) else {
            return Err(Error::service(
                "eam",
                "oidc-authorize",
                200,
                "the server did not say where to authenticate",
            ));
        };

        let callback = self.await_callback(&listener, &url).await?;
        if callback.state != authorization.state {
            return Err(Error::Authentication {
                status: 401,
                body: "the callback does not belong to this login attempt".into(),
            });
        }
        drop(listener);

        let request = OidcLoginRequest {
            code: callback.code.unwrap_or_default(),
            state: callback.state.unwrap_or_default(),
        };
        self.redeem(http, cache_path, "oidc-login", &request).await
    }

    /// Signs in through the installation's SAML 2.0 identity provider, in a browser, the way
    /// `euclid-cli eam login --saml` does - and caches the session exactly as
    /// [`login`](Self::login) does.
    ///
    /// Unlike OIDC, nothing about this client is ever registered with the provider: the provider
    /// posts its signed assertion to the server's own assertion consumer service, the server
    /// verifies it and issues the session, and only then hands that session to the loopback
    /// listener named as `returnTo` - in a self-submitting form post, so the token never appears in
    /// a URL. The listener therefore receives a finished session rather than something to redeem.
    ///
    /// A still-valid cached session is reused instead, as [`login`](Self::login) reuses one.
    ///
    /// # Errors
    ///
    /// [`Error::Service`] if the server cannot start the flow - SAML is not enabled (404), or
    /// misconfigured (500); [`Error::Authentication`] if the provider refused the login, or the
    /// browser came back without a session; [`Error::Io`] as for
    /// [`login_with_oidc`](Self::login_with_oidc).
    pub async fn login_with_saml(&self) -> Result<Session> {
        let cache_path = self.cache_path();
        let http = self.http()?;
        if let Some(cached) = self.reuse_cached(cache_path.as_deref(), &http).await? {
            return Ok(cached);
        }

        let listener = LoopbackListener::bind().await?;
        let authentication = self
            .saml_authorize_with(
                &http,
                &SamlAuthorizeRequest {
                    return_to: listener.callback_url(),
                },
            )
            .await?;
        let Some(url) = authentication.authentication_url.filter(|u| !u.is_empty()) else {
            return Err(Error::service(
                "eam",
                "saml-authorize",
                200,
                "the server did not say where to authenticate",
            ));
        };

        let callback = self.await_callback(&listener, &url).await?;
        drop(listener);
        let Some(session) = callback.session.filter(|s| !s.is_empty()) else {
            return Err(refused("the callback carried no session"));
        };
        let login: LoginResponse =
            serde_json::from_str(&session).map_err(|_| refused("the session euclid sent back is not valid JSON"))?;
        if login.token.as_deref().unwrap_or_default().is_empty() {
            return Err(refused("the session euclid sent back did not contain a token"));
        }
        self.establish(http, cache_path, login).await
    }

    /// Turns a SAML response obtained some other way into a session, by handing it to the
    /// server's assertion consumer service (`saml-acs`) - the last step of
    /// `euclid-cli eam login --onelogin`, which fetches the assertion from OneLogin's API rather
    /// than through a browser.
    ///
    /// Verified exactly as one a browser posts: the provider's signature is what is trusted, not
    /// how the assertion arrived. An assertion with no RelayState answers no login request euclid
    /// made, so the server refuses it unless it allows IdP-initiated logins
    /// (`saml.allow-idp-initiated`); and each assertion is accepted once only.
    ///
    /// Never answered from the cache, unlike [`login`](Self::login): the caller has spent an
    /// assertion on this, and quietly returning some other session would discard it.
    ///
    /// # Errors
    ///
    /// [`Error::Authentication`] if the assertion is refused - unsigned, expired, unsolicited, or
    /// replayed (401) - or the identity may not have an account here (403).
    pub async fn login_with_saml_assertion(&self, request: &SamlAcsRequest) -> Result<Session> {
        self.redeem(self.http()?, self.cache_path(), "saml-acs", request).await
    }

    /// Starts an OpenID Connect login without driving it: answers with where to send the person and
    /// the state the attempt travels under (`oidc-authorize`).
    ///
    /// The building block for a caller that runs the browser leg itself - a web application that
    /// registers its own callback, say - and finishes with [`oidc_login`](Self::oidc_login).
    /// [`login_with_oidc`](Self::login_with_oidc) is this and the rest of the flow put together for
    /// a program on the signing-in person's own machine.
    ///
    /// # Errors
    ///
    /// [`Error::Service`] if OIDC is not enabled (404), misconfigured (500), the `return_to` is not
    /// a permitted destination (400), or the provider is unreachable (502).
    pub async fn oidc_authorize(&self, request: &OidcAuthorizeRequest) -> Result<OidcAuthorizeResponse> {
        self.oidc_authorize_with(&self.http()?, request).await
    }

    /// Finishes an OpenID Connect login: redeems the code the provider sent back for a euclid
    /// session (`oidc-login`), and caches it as [`login`](Self::login) does - applying
    /// [`account`](Self::account) and [`namespace`](Self::namespace) on the way.
    ///
    /// Never answered from the cache: a code is good for one redemption, and the caller has
    /// presumably just been through a browser to get it.
    ///
    /// # Errors
    ///
    /// [`Error::Authentication`] if the code or state is refused (401), or the identity may not
    /// have an account here (403).
    pub async fn oidc_login(&self, request: &OidcLoginRequest) -> Result<Session> {
        self.redeem(self.http()?, self.cache_path(), "oidc-login", request)
            .await
    }

    /// Starts a SAML login without driving it: answers with where to send the person and the
    /// RelayState the attempt travels under (`saml-authorize`, also reachable as `saml-login`).
    ///
    /// The building block for a caller that runs the browser leg itself;
    /// [`login_with_saml`](Self::login_with_saml) is the whole flow for a program on the
    /// signing-in person's own machine. Where the session ends up is decided by
    /// [`SamlAuthorizeRequest::return_to`].
    ///
    /// # Errors
    ///
    /// [`Error::Service`] if SAML is not enabled (404), misconfigured (500), or the `return_to` is
    /// not a permitted destination (400).
    pub async fn saml_authorize(&self, request: &SamlAuthorizeRequest) -> Result<SamlAuthorizeResponse> {
        self.saml_authorize_with(&self.http()?, request).await
    }

    // -----------------------------------------------------------------------------------------
    // Plumbing
    // -----------------------------------------------------------------------------------------

    fn http(&self) -> Result<HttpClient> {
        HttpClient::new(self.ca_cert_path.as_deref())
    }

    /// POSTs `body` to the login path as `eam`/`action`. Unauthenticated: every action sent here
    /// is a way in.
    async fn post_login_path(&self, http: &HttpClient, action: &str, body: &impl serde::Serialize) -> Result<Response> {
        let url = format!("{}{}", self.base_url, self.login_path);
        let headers = [("content-type".to_owned(), "application/json".to_owned())];
        http.post(&url, serde_json::to_vec(body)?, "eam", action, &headers, None)
            .await
    }

    async fn oidc_authorize_with(
        &self,
        http: &HttpClient,
        request: &OidcAuthorizeRequest,
    ) -> Result<OidcAuthorizeResponse> {
        let response = self.post_login_path(http, "oidc-authorize", request).await?;
        if !response.is_success() {
            return Err(Error::service(
                "eam",
                "oidc-authorize",
                response.status,
                response.text(),
            ));
        }
        Ok(serde_json::from_slice(&response.body)?)
    }

    async fn saml_authorize_with(
        &self,
        http: &HttpClient,
        request: &SamlAuthorizeRequest,
    ) -> Result<SamlAuthorizeResponse> {
        let response = self.post_login_path(http, "saml-authorize", request).await?;
        if !response.is_success() {
            return Err(Error::service(
                "eam",
                "saml-authorize",
                response.status,
                response.text(),
            ));
        }
        Ok(serde_json::from_slice(&response.body)?)
    }

    /// Sends a proof to `action`, which answers with a login response, and establishes the
    /// session it describes.
    async fn redeem(
        &self,
        http: HttpClient,
        cache_path: Option<PathBuf>,
        action: &str,
        request: &impl serde::Serialize,
    ) -> Result<Session> {
        let response = self.post_login_path(&http, action, request).await?;
        if !response.is_success() {
            return Err(authentication_error(&response));
        }
        let login: LoginResponse = serde_json::from_slice(&response.body)?;
        self.establish(http, cache_path, login).await
    }

    /// Hands the URL to the browser and waits for it to come back, turning the two ways that can
    /// go wrong - no answer, or the provider's refusal - into errors.
    async fn await_callback(&self, listener: &LoopbackListener, url: &str) -> Result<Callback> {
        match &self.browser {
            Some(browser) => browser(url),
            None => open_in_browser(url),
        }
        let Some(callback) = listener.wait(self.callback_timeout).await? else {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "no callback from the identity provider within {:?}",
                    self.callback_timeout
                ),
            )));
        };
        if let Some(error) = &callback.error {
            return Err(refused(format!("the identity provider refused the login: {error}")));
        }
        Ok(callback)
    }

    /// A still-valid cached session for this server, moved to the [`account`](Self::account) and
    /// [`namespace`](Self::namespace) asked for, or `None` if there is none to reuse.
    ///
    /// A cached session may have been established - by this caller, by euclid-cli or by
    /// euclid-jdk, since all share the same credentials file - before an account or namespace was
    /// ever asked for, or scoped to different ones. Switching it here is what makes those settings
    /// apply whether a login ends up reusing a cached session or doing a fresh one.
    async fn reuse_cached(&self, cache_path: Option<&Path>, http: &HttpClient) -> Result<Option<Session>> {
        let Some(mut cached) = cache_path.and_then(|p| self.cached_session(p, http)) else {
            return Ok(None);
        };
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
        Ok(Some(cached))
    }

    /// What every way in does with the login response it got: build the session, move it to the
    /// account and namespace asked for, and cache it. Shared deliberately - a federated login is
    /// not a different kind of session, and a difference between the paths here would be one
    /// nobody meant to introduce.
    async fn establish(&self, http: HttpClient, cache_path: Option<PathBuf>, login: LoginResponse) -> Result<Session> {
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
                // The login itself succeeded, so the session is kept - in the home account - and
                // the next attempt need not send the password again (or go through the browser
                // again) for a typo in an account name.
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

fn authentication_error(response: &Response) -> Error {
    Error::Authentication {
        status: response.status,
        body: response.text(),
    }
}

/// A login refused on this side of the wire, reported the way the server reports one.
fn refused(message: impl Into<String>) -> Error {
    Error::Authentication {
        status: 401,
        body: message.into(),
    }
}

/// The default [`Eam::browser`]: prints the URL, then opens it the way the platform offers - best
/// effort, and said out loud either way, so a person on a machine with no browser can copy the URL
/// somewhere that has one.
fn open_in_browser(url: &str) {
    use std::process::{Command, Stdio};

    eprintln!(
        "Opening your browser to sign in. If it does not open, go to:\n\n  {url}\n\nWaiting for the callback ..."
    );
    // No shell in between, so nothing in the URL is ever interpreted as anything but an argument.
    let mut command = if cfg!(target_os = "macos") {
        Command::new("open")
    } else if cfg!(windows) {
        let mut command = Command::new("rundll32");
        command.arg("url.dll,FileProtocolHandler");
        command
    } else {
        Command::new("xdg-open")
    };
    command
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // The URL is printed above; that is the fallback if this fails.
    if let Ok(mut child) = command.spawn() {
        // Reaped on a thread of its own, so the opener does not linger as a zombie.
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }
}
