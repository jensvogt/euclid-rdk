//! Request and response types of the EAM (Euclid Access Management) module.
//!
//! Field names are the wire names in camelCase. Response types default every field, so a field
//! the server leaves out reads as `None`/empty instead of failing the whole response - the same
//! leniency euclid-jdk's `textOrNull` gives.

use serde::{Deserialize, Serialize};

use crate::serde_util::{default_true, lenient_string};

// ---------------------------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------------------------

/// The caller's identity, as responses carry it in a nested `"metadata"` object.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Metadata {
    pub region: Option<String>,
    pub account_id: Option<String>,
    pub user: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------------------------

/// Body of `eam login`. Only one of `user_id` and `email` should be non-empty: the server takes the
/// user ID when present and falls back to the email only otherwise.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LoginRequest {
    pub user_id: String,
    pub password: String,
    pub email: String,
}

/// Answer to `eam login`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LoginResponse {
    pub metadata: Option<Metadata>,
    pub token: Option<String>,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub created_at: Option<String>,
    pub is_admin: bool,
}

// ---------------------------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct User {
    pub user_id: Option<String>,
    pub ern: Option<String>,
    /// Always empty in what the server answers: the stored value is a password hash, and the
    /// server never sends it back. Kept so the type mirrors the server's DTO field for field.
    pub password: Option<String>,
    pub email: Option<String>,
    pub account_id: Option<String>,
    pub region: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub created: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub modified: Option<String>,
}

/// Paging and sorting for `list-users`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListUsersRequest {
    pub prefix: String,
    /// How `prefix` is matched; `None` matches it as a prefix, as every listing did before the
    /// choice existed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_type: Option<MatchType>,
    pub page_size: u64,
    pub page_index: u64,
    pub sort_column: String,
    pub sort_direction: SortDirection,
}

impl Default for ListUsersRequest {
    fn default() -> Self {
        Self {
            prefix: String::new(),
            match_type: None,
            page_size: 10,
            page_index: 0,
            sort_column: "userId".into(),
            sort_direction: SortDirection::Asc,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListUsersResponse {
    pub users: Vec<User>,
    pub total: u64,
}

/// Body of `eam register`.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    pub user_id: String,
    pub password: String,
    pub email: String,
    pub account_id: String,
    pub region: String,
    pub is_admin: bool,
}

/// Answer to `eam register`: the user as the server stored them - their ERN in particular, which
/// is built server-side from the account and user ID rather than sent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RegisterResponse {
    pub metadata: Option<Metadata>,
    pub user: User,
}

/// Body of `eam change-userid`. Both ids are always named: there is no "me" default.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ChangeUserIdRequest {
    pub user_id: String,
    pub new_user_id: String,
}

/// Body of `eam change-email`. The user is always named: there is no "me" default.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ChangeEmailRequest {
    pub user_id: String,
    pub email: String,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ChangePasswordRequest {
    pub user_id: String,
    pub old_password: String,
    pub new_password: String,
}

// ---------------------------------------------------------------------------------------------
// Access keys
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessKey {
    #[serde(default)]
    pub access_key_id: Option<String>,
    #[serde(default = "default_true")]
    pub active: bool,
    #[serde(default, deserialize_with = "lenient_string")]
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CreateAccessKeyResponse {
    pub metadata: Option<Metadata>,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub created_at: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// User groups
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UserGroup {
    pub name: Option<String>,
    pub ern: Option<String>,
    pub account_id: Option<String>,
    pub region: Option<String>,
    pub description: Option<String>,
    pub user_ids: Vec<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub created: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub modified: Option<String>,
}

/// Paging and sorting for `list-user-groups`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListUserGroupsRequest {
    pub prefix: String,
    /// How `prefix` is matched; `None` matches it as a prefix, as every listing did before the
    /// choice existed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_type: Option<MatchType>,
    pub page_size: u64,
    pub page_index: u64,
    pub sort_column: String,
    pub sort_direction: SortDirection,
}

impl Default for ListUserGroupsRequest {
    fn default() -> Self {
        Self {
            prefix: String::new(),
            match_type: None,
            page_size: 10,
            page_index: 0,
            sort_column: "name".into(),
            sort_direction: SortDirection::Asc,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListUserGroupsResponse {
    pub user_groups: Vec<UserGroup>,
    pub total: u64,
}

// ---------------------------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Account {
    pub account_id: Option<String>,
    pub name: Option<String>,
    pub ern: Option<String>,
    pub description: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub created: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub modified: Option<String>,
}

/// Paging and sorting for `list-accounts`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListAccountsRequest {
    pub prefix: String,
    /// How `prefix` is matched; `None` matches it as a prefix, as every listing did before the
    /// choice existed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_type: Option<MatchType>,
    pub page_size: u64,
    pub page_index: u64,
    pub sort_column: String,
    pub sort_direction: SortDirection,
}

impl Default for ListAccountsRequest {
    fn default() -> Self {
        Self {
            prefix: String::new(),
            match_type: None,
            page_size: 10,
            page_index: 0,
            sort_column: "accountId".into(),
            sort_direction: SortDirection::Asc,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListAccountsResponse {
    pub accounts: Vec<Account>,
    pub total: u64,
}

/// Answer to `list-my-accounts`: the accounts the caller may work in.
///
/// Not [`ListAccountsResponse`] with a filter - that is every account of the installation, for
/// administrators. This one is about the caller: the home account, always, plus every account a
/// grant held by them or one of their groups names (an administrator gets every account). An
/// account named by a grant but missing from the installation is listed under its id, with the id
/// as its name and no ERN, description or dates.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListMyAccountsResponse {
    /// Ordered by account id.
    pub accounts: Vec<Account>,
    pub total: u64,
    /// The account the caller was registered in - always among `accounts`, and the one to select
    /// when nothing else was asked for.
    pub home_account_id: Option<String>,
}

impl ListMyAccountsResponse {
    /// The id of the account `wanted` names - by account id, or else by name - among these.
    /// An id wins outright over a name, since nothing stops an account being named like another
    /// account's id; this is how `euclid-cli eam login --account` resolves it.
    pub fn resolve(&self, wanted: &str) -> Option<&str> {
        let ids = self.accounts.iter().filter_map(|a| a.account_id.as_deref());
        if let Some(id) = ids.clone().find(|id| *id == wanted) {
            return Some(id);
        }
        self.accounts
            .iter()
            .find(|a| !wanted.is_empty() && a.name.as_deref() == Some(wanted))
            .and_then(|a| a.account_id.as_deref())
    }
}

// ---------------------------------------------------------------------------------------------
// Namespaces
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Namespace {
    pub account_id: Option<String>,
    pub name: Option<String>,
    pub ern: Option<String>,
    pub description: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub created: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub modified: Option<String>,
}

/// Paging and sorting for `list-namespaces`. `account_id` names the account whose namespaces to
/// list.
///
/// A `page_size` of zero returns every namespace the caller may see. The page is taken over what
/// the caller may see rather than over the account, so a page is never short because of
/// namespaces filtered out of it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListNamespacesRequest {
    pub account_id: String,
    pub prefix: String,
    /// How `prefix` is matched; `None` matches it as a prefix, as every listing did before the
    /// choice existed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_type: Option<MatchType>,
    pub page_size: u64,
    pub page_index: u64,
    pub sort_column: String,
    pub sort_direction: SortDirection,
}

impl Default for ListNamespacesRequest {
    fn default() -> Self {
        Self {
            account_id: String::new(),
            prefix: String::new(),
            match_type: None,
            page_size: 10,
            page_index: 0,
            sort_column: "name".into(),
            sort_direction: SortDirection::Asc,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListNamespacesResponse {
    pub namespaces: Vec<Namespace>,
    pub total: u64,
}

// ---------------------------------------------------------------------------------------------
// Roles, grants and permissions
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Role {
    pub name: Option<String>,
    pub ern: Option<String>,
    pub account_id: Option<String>,
    pub region: Option<String>,
    pub description: Option<String>,
    pub permissions: Vec<String>,
    pub builtin: bool,
    #[serde(deserialize_with = "lenient_string")]
    pub created: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub modified: Option<String>,
}

/// Body of `create-role` and `update-role`. Permissions are `<module>:<action>`, as
/// [`Session::list_permissions`](crate::Session::list_permissions) names them.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleRequest {
    pub name: String,
    pub description: String,
    pub permissions: Vec<String>,
}

/// Paging, sorting and filtering for `list-roles`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListRolesRequest {
    pub prefix: String,
    /// How `prefix` is matched; `None` matches it as a prefix, as every listing did before the
    /// choice existed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_type: Option<MatchType>,
    pub page_size: u64,
    pub page_index: u64,
    pub sort_column: String,
    pub sort_direction: SortDirection,
    pub include_builtin: bool,
}

impl Default for ListRolesRequest {
    fn default() -> Self {
        Self {
            prefix: String::new(),
            match_type: None,
            page_size: 10,
            page_index: 0,
            sort_column: "name".into(),
            sort_direction: SortDirection::Asc,
            include_builtin: true,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListRolesResponse {
    pub roles: Vec<Role>,
    pub total: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Grant {
    pub grant_id: Option<String>,
    pub role: Option<String>,
    pub principal: Option<String>,
    pub account_id: Option<String>,
    pub namespaces: Vec<String>,
    pub resources: Vec<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub granted: Option<String>,
    pub granted_by: Option<String>,
}

/// Body of `grant-role`. Namespaces and resources both default to `*`, so a grant that names
/// neither applies account-wide rather than nowhere.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantRoleRequest {
    pub role: String,
    pub principal: String,
    pub account_id: String,
    pub namespaces: Vec<String>,
    pub resources: Vec<String>,
}

impl Default for GrantRoleRequest {
    fn default() -> Self {
        Self {
            role: String::new(),
            principal: String::new(),
            account_id: String::new(),
            namespaces: vec!["*".into()],
            resources: vec!["*".into()],
        }
    }
}

/// Filtering, paging and sorting for `list-grants`. Empty filters match everything; a page size of
/// 0 returns all grants.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListGrantsRequest {
    pub principal: String,
    pub role: String,
    pub account_id: String,
    pub page_size: u64,
    pub page_index: u64,
    pub sort_column: String,
    pub sort_direction: SortDirection,
}

impl Default for ListGrantsRequest {
    fn default() -> Self {
        Self {
            principal: String::new(),
            role: String::new(),
            account_id: String::new(),
            page_size: 0,
            page_index: 0,
            sort_column: "principal".into(),
            sort_direction: SortDirection::Asc,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListGrantsResponse {
    pub grants: Vec<Grant>,
    pub total: u64,
}

/// Body of `check-permission`.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckPermissionRequest {
    pub user_id: String,
    pub target: String,
    pub action: String,
    pub namespace: String,
    pub resource_ern: String,
}

/// What `list-permissions` answers: every permission a role can hold, and the modules they come
/// from.
///
/// Generated server-side from the modules' own dispatch tables, so it is exactly what can be
/// granted. The modules that are not bindable at all contribute nothing to `permissions` and are
/// named separately, so a caller can say why they are missing rather than wondering.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListPermissionsResponse {
    /// Every permission, sorted, as `<module>:<action>`.
    pub permissions: Vec<String>,
    /// The modules that have permissions, sorted - what a `<module>:*` permission may name.
    pub modules: Vec<String>,
    /// The modules whose actions can never be granted to anybody - today `emd` and `emm`. Only an
    /// installation administrator reaches them.
    pub unbindable_modules: Vec<String>,
}

/// Whether a request would be allowed, and which role decided it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PermissionCheckResponse {
    pub allowed: bool,
    pub reason: Option<String>,
    pub role: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// Federated login (OIDC, SAML)
// ---------------------------------------------------------------------------------------------

/// Body of `oidc-authorize`: asks EAM to start an OpenID Connect login and say where to send the
/// browser.
///
/// Nothing in here identifies anybody: the identity provider decides who is signing in, which is
/// the point of federating the login. What this says is only where the two legs of the flow should
/// end up. Both fields default to empty - the server's configured callback, and no browser
/// hand-off.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OidcAuthorizeRequest {
    /// Where the provider should send the browser back to with the authorization code, or empty
    /// for the one the server has configured (`oidc.redirect-uri`). A native client names its own
    /// loopback listener here - see [`Eam::login_with_oidc`](super::Eam::login_with_oidc) - and the
    /// provider must accept it, usually as a wildcard loopback URI. Whatever is used is sealed into
    /// the state and presented again when the code is redeemed, since the provider requires the
    /// two to match.
    pub redirect_uri: String,
    /// Where the server should send the browser once the login has succeeded, for a flow that ends
    /// in a browser rather than in a caller collecting the response; empty means the caller redeems
    /// the code itself with `oidc-login`. Only destinations the server permits
    /// (`oidc.return-to-prefixes`) are accepted, because the token travels in that redirect's
    /// fragment.
    pub return_to: String,
}

/// Answer to `oidc-authorize`: where to send the person to authenticate, and the state that
/// belongs to that particular attempt.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct OidcAuthorizeResponse {
    /// The provider's authorization endpoint with every parameter already on it. Open it in a
    /// browser; nothing else needs to be added.
    pub authorization_url: Option<String>,
    /// The opaque state this attempt travels under, also present in `authorization_url`. Returned
    /// separately so a caller can check that the callback it receives belongs to the authorization
    /// it started. It carries the flow's nonce and PKCE verifier, sealed by the server - there is
    /// nothing in it to read, and it is the flow's only memory, so the `oidc-login` that redeems
    /// the code has to present it unchanged.
    pub state: Option<String>,
}

/// Body of `oidc-login`: hands EAM what came back from the OpenID Connect provider, to be turned
/// into a euclid session.
///
/// Answered with the same [`LoginResponse`] a password login produces, because from there on a
/// federated session is not a different kind of session.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OidcLoginRequest {
    /// The authorization code from the provider's callback.
    pub code: String,
    /// The state from the provider's callback, exactly as it arrived. Not merely checked against
    /// the one that was issued: it *is* the flow's memory - the nonce and the PKCE verifier are
    /// sealed inside it - so a callback without it cannot be completed by any server instance, and
    /// one that has been altered is refused.
    pub state: String,
}

/// Body of `saml-authorize`: asks EAM to start a SAML 2.0 login and say where to send the browser.
///
/// Unlike [`OidcAuthorizeRequest`] there is no redirect URI: the identity provider posts its
/// assertion to the server's own assertion consumer service, which is registered with the provider
/// once, and only afterwards does the server hand the finished session on. So nothing about the
/// caller ever has to be registered with the provider.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SamlAuthorizeRequest {
    /// Where the server should deliver the session once the assertion has been accepted, or empty
    /// to have the assertion consumer answer with the login response itself. A loopback address
    /// (`http://127.0.0.1:<port>/...`) is a native client waiting on its own port and gets the
    /// session in a self-submitting form post, so the token never sits in a URL; anywhere else is
    /// a front end and gets it in the redirect's fragment. Only destinations the server permits
    /// (`saml.return-to-prefixes`) are accepted.
    pub return_to: String,
}

/// Answer to `saml-authorize`: where to send the person to authenticate with the SAML identity
/// provider.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SamlAuthorizeResponse {
    /// The provider's single sign-on URL, with the deflated, encoded AuthnRequest and the
    /// RelayState already on it. Open it in a browser; nothing else needs to be added.
    pub authentication_url: Option<String>,
    /// The opaque RelayState this attempt travels under, also present in `authentication_url`.
    /// Returned separately so a caller can tell whether what comes back belongs to the login it
    /// started. It carries the request ID the assertion has to answer, sealed - there is nothing in
    /// it to read.
    pub relay_state: Option<String>,
}

/// Body of `saml-acs`: a signed SAML response, handed to EAM's assertion consumer service as JSON.
///
/// The browser binding delivers the same two values as an HTML form post, straight from the
/// identity provider; this is the shape for a program that obtained the assertion some other way -
/// from the provider's API, as `euclid-cli eam login --onelogin` does - and wants it turned into a
/// session. Either way it is verified identically: the provider's signature is what is trusted,
/// not how the assertion arrived.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SamlAcsRequest {
    /// The base64-encoded SAML response, as the provider issued it.
    pub saml_response: String,
    /// The RelayState that came with it, or empty for an assertion that answers no login request
    /// euclid made. Such an unsolicited assertion is refused unless the server allows IdP-initiated
    /// logins (`saml.allow-idp-initiated`).
    pub relay_state: String,
}

// ---------------------------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------------------------

/// How a listing's `prefix` is matched against the names it lists.
///
/// Every type but [`Regex`](Self::Regex) takes the text literally, so a search for `a.b` does not
/// also find `aXb`; a pattern the server cannot use is refused with HTTP 400. Leaving the match
/// type unset (`None`) means [`Prefix`](Self::Prefix), which is what every listing did before the
/// choice existed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MatchType {
    /// Names starting with the text.
    #[default]
    Prefix,
    /// Names ending with the text.
    EndsWith,
    /// Names containing the text anywhere.
    Contains,
    /// Names matching the text as a regular expression.
    Regex,
}

/// Sort order of a listing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortDirection {
    #[default]
    Asc,
    Desc,
}
