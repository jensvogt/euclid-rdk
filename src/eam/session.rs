use std::path::PathBuf;

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};

use super::model::*;
use crate::credentials::{self, CachedCredentials};
use crate::ead::Ead;
use crate::eag::Eag;
use crate::eap::Eap;
use crate::ees::Ees;
use crate::ekm::Ekm;
use crate::ekv::Ekv;
use crate::emm::Emm;
use crate::emo::Emo;
use crate::ens::Ens;
use crate::eqs::Eqs;
use crate::esm::Esm;
use crate::ess::Ess;
use crate::ets::Ets;
use crate::http::HttpClient;
use crate::service::{Identity, ServiceClient};
use crate::{Error, Result};

/// An authenticated connection to an Euclid server, as returned by [`Eam::login`](super::Eam::login).
///
/// EAM requests carry the bearer token and the caller's identity (`x-euclid-region`,
/// `x-euclid-account-id`, `x-euclid-user-id`) and, once one is chosen, `x-euclid-namespace` -
/// which restricts every namespace-scoped call made through this session to that namespace.
///
/// Cloning is cheap; clones share the underlying connection pool.
#[derive(Clone)]
pub struct Session {
    http: HttpClient,
    base_url: String,
    credentials_path: Option<PathBuf>,
    creds: CachedCredentials,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("base_url", &self.base_url)
            .field("user_id", &self.creds.user_id)
            .field("account_id", &self.creds.account_id)
            .field("region", &self.creds.region)
            .field("namespace", &self.creds.namespace)
            .field("is_admin", &self.creds.is_admin)
            .field("access_key_id", &self.creds.access_key_id)
            .finish_non_exhaustive()
    }
}

impl Session {
    pub(crate) fn new(
        http: HttpClient,
        base_url: String,
        credentials_path: Option<PathBuf>,
        creds: CachedCredentials,
    ) -> Self {
        Self {
            http,
            base_url,
            credentials_path,
            creds,
        }
    }

    pub(crate) fn to_cached(&self) -> CachedCredentials {
        CachedCredentials {
            base_url: Some(self.base_url.clone()),
            ..self.creds.clone()
        }
    }

    // -----------------------------------------------------------------------------------------
    // Identity
    // -----------------------------------------------------------------------------------------

    /// The bearer token this session presents.
    pub fn token(&self) -> &str {
        self.creds.token.as_deref().unwrap_or_default()
    }
    pub fn user_id(&self) -> Option<&str> {
        self.creds.user_id.as_deref()
    }
    pub fn account_id(&self) -> Option<&str> {
        self.creds.account_id.as_deref()
    }
    pub fn region(&self) -> Option<&str> {
        self.creds.region.as_deref()
    }
    /// Public half of the caller's SigV4 access key, if the login returned one.
    pub fn access_key_id(&self) -> Option<&str> {
        self.creds.access_key_id.as_deref()
    }
    /// Secret half of the caller's SigV4 access key, if the login returned one.
    pub fn secret_access_key(&self) -> Option<&str> {
        self.creds.secret_access_key.as_deref()
    }
    pub fn is_admin(&self) -> bool {
        self.creds.is_admin
    }
    /// The active namespace, if one was chosen.
    pub fn namespace(&self) -> Option<&str> {
        self.creds.namespace.as_deref()
    }
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    // -----------------------------------------------------------------------------------------
    // Plumbing
    // -----------------------------------------------------------------------------------------

    pub(crate) fn identity(&self) -> Identity {
        Identity {
            token: self.token().to_owned(),
            user_id: self.creds.user_id.clone(),
            account_id: self.creds.account_id.clone(),
            region: self.creds.region.clone(),
            namespace: self.creds.namespace.clone(),
            access_key_id: self.creds.access_key_id.clone(),
            secret_access_key: self.creds.secret_access_key.clone(),
        }
    }

    /// A client for `target` on behalf of this session. EAM always uses the bearer token; the
    /// service modules are SigV4-signed when the session holds an access key.
    pub(crate) fn service(&self, target: &str) -> ServiceClient {
        let client = ServiceClient::new(self.http.clone(), self.base_url.clone(), self.identity(), target);
        if target == "eam" {
            client.bearer_only()
        } else {
            client
        }
    }

    /// Sends `body` as `target`/`action` and returns the raw JSON answer.
    ///
    /// The escape hatch for operations this crate does not wrap yet. Authenticated the way the
    /// typed clients are: EAM with the bearer token, every other module SigV4-signed when the
    /// session holds an access key.
    pub async fn invoke(&self, target: &str, action: &str, body: &impl Serialize) -> Result<Value> {
        self.service(target).call_value(action, body).await
    }

    async fn eam<R: DeserializeOwned>(&self, action: &str, body: &impl Serialize) -> Result<R> {
        self.service("eam").call(action, body).await
    }

    /// Calls `action` and reads the object nested under `field` in the answer.
    async fn eam_field<R: DeserializeOwned>(&self, action: &str, body: &impl Serialize, field: &str) -> Result<R> {
        self.service("eam").call_field(action, body, field).await
    }

    async fn eam_unit(&self, action: &str, body: &impl Serialize) -> Result<()> {
        self.service("eam").call_unit(action, body).await
    }

    // -----------------------------------------------------------------------------------------
    // Module clients
    // -----------------------------------------------------------------------------------------

    /// EQS (queue) operations for this session.
    pub fn eqs(&self) -> Eqs {
        Eqs::new(self.service("eqs"))
    }

    /// ENS (pub/sub topic) operations for this session.
    pub fn ens(&self) -> Ens {
        Ens::new(self.service("ens"))
    }

    /// EAP (application platform) operations for this session. Every EAP action is
    /// administrator-only server-side: a non-admin session gets 403 from all of them.
    pub fn eap(&self) -> Eap {
        Eap::new(self.service("eap"))
    }

    /// EES (event) operations for this session: subscribe a durable name to an event type with a
    /// filter, then claim and acknowledge events - how an application watches ESM and the others.
    pub fn ees(&self) -> Ees {
        Ees::new(self.service("ees"))
    }

    /// EMO (monitoring) operations for this session, for pushing metrics a process has measured
    /// about itself. Meant for ordinary principals - an application reporting its own load.
    pub fn emo(&self) -> Emo {
        Emo::new(self.service("emo"))
    }

    /// EKM (key management) operations for this session: encryption keys and certificates.
    pub fn ekm(&self) -> Ekm {
        Ekm::new(self.service("ekm"))
    }

    /// EKV (key-value store) operations for this session.
    pub fn ekv(&self) -> Ekv {
        Ekv::new(self.service("ekv"))
    }

    /// ESS (secrets) operations for this session.
    pub fn ess(&self) -> Ess {
        Ess::new(self.service("ess"))
    }

    /// ETS (transfer server) operations for this session. Every ETS action is administrator-only
    /// server-side: a non-admin session gets 403 from all of them.
    pub fn ets(&self) -> Ets {
        Ets::new(self.service("ets"))
    }

    /// EAG (API gateway) operations for this session: the routes the gateway publishes and the
    /// listeners it publishes them on. Administrator-only server-side, like ETS.
    pub fn eag(&self) -> Eag {
        Eag::new(self.service("eag"))
    }

    /// EAD (audit) operations for this session: the account's audit trail.
    pub fn ead(&self) -> Ead {
        Ead::new(self.service("ead"))
    }

    /// EMM (module manager) operations for this session: module pools, backups, export and
    /// import. Administrator-only server-side: a non-admin session gets 403 from every action.
    pub fn emm(&self) -> Emm {
        Emm::new(self.service("emm"))
    }

    /// ESM (object storage) operations for this session.
    pub fn esm(&self) -> Esm {
        Esm::new(self.service("esm"))
    }

    // -----------------------------------------------------------------------------------------
    // Session
    // -----------------------------------------------------------------------------------------

    /// Makes `namespace` the active namespace of this session, after the server has validated it.
    /// Every namespace-scoped call afterward is restricted to it. The credentials cache is updated
    /// so later processes pick the change up.
    pub async fn change_namespace(&mut self, namespace: &str) -> Result<()> {
        self.eam_unit("change-namespace", &json!({ "namespace": namespace }))
            .await?;
        self.creds.namespace = Some(namespace.to_owned()).filter(|n| !n.is_empty());
        if let Some(path) = &self.credentials_path {
            credentials::update_namespace(path, &self.base_url, self.namespace());
        }
        Ok(())
    }

    /// Makes `account` - an account id, or an account's name - the account this session works in:
    /// every later request carries it in `x-euclid-account-id`. It has to be one
    /// [`list_my_accounts`](Self::list_my_accounts) names (the home account, or one a grant held by
    /// the user or one of their groups covers); an id wins where a name would match another
    /// account.
    ///
    /// Switching to a different account clears the active namespace, since a namespace belongs to
    /// an account - choose one in the new account with [`change_namespace`](Self::change_namespace).
    /// Module clients obtained before the switch keep the old account. The credentials cache is
    /// updated.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] naming the user's accounts if `account` is not one of them; the
    /// session is left as it was.
    pub async fn switch_account(&mut self, account: &str) -> Result<()> {
        let mine = self.list_my_accounts().await?;
        let account_id = resolve_account(&mine, account)?;
        if self.creds.account_id.as_deref() != Some(account_id.as_str()) {
            self.creds.account_id = Some(account_id);
            self.creds.namespace = None;
        }
        self.sync_cache();
        Ok(())
    }

    /// Renews this session before its token runs out: the server hands back a fresh token (and the
    /// same access key), and this session adopts it. The account and namespace in use are kept.
    /// An expired token cannot be renewed - log in again instead. Module clients obtained before
    /// the refresh keep presenting the old token. The credentials cache is updated.
    pub async fn refresh_session(&mut self) -> Result<()> {
        let login: LoginResponse = self.eam("refresh-session", &json!({})).await?;
        let Some(token) = login.token.filter(|t| !t.is_empty()) else {
            return Err(Error::service(
                "eam",
                "refresh-session",
                200,
                "the answer carried no token",
            ));
        };
        self.creds.token = Some(token);
        if login.access_key_id.is_some() {
            self.creds.access_key_id = login.access_key_id;
            self.creds.secret_access_key = login.secret_access_key;
        }
        self.creds.is_admin = login.is_admin;
        if let Some(metadata) = login.metadata {
            if metadata.user.is_some() {
                self.creds.user_id = metadata.user;
            }
            if metadata.region.is_some() {
                self.creds.region = metadata.region;
            }
            // metadata.accountId is the home account; an account switched to stays in use.
            if self.creds.account_id.is_none() {
                self.creds.account_id = metadata.account_id;
            }
        }
        self.sync_cache();
        Ok(())
    }

    /// Rewrites the credentials cache from this session, if what is cached is for this server.
    /// Best-effort, like the namespace update: a cache that cannot be written means the next
    /// process logs in again, not that the call failed.
    fn sync_cache(&self) {
        let Some(path) = &self.credentials_path else { return };
        if credentials::load(path).and_then(|c| c.base_url).as_deref() == Some(self.base_url.as_str()) {
            let _ = credentials::store(path, &self.to_cached());
        }
    }

    /// Forgets the cached credentials for this server, so the next `login()` has to authenticate
    /// again. The token itself stays valid on the server until it expires.
    pub fn logout(self) -> Result<()> {
        if let Some(path) = &self.credentials_path {
            if credentials::load(path).and_then(|c| c.base_url).as_deref() == Some(self.base_url.as_str()) {
                std::fs::remove_file(path)?;
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------------------------
    // Users
    // -----------------------------------------------------------------------------------------

    pub async fn list_users(&self, request: &ListUsersRequest) -> Result<ListUsersResponse> {
        self.eam("list-users", request).await
    }

    pub async fn get_user(&self, user_id: &str) -> Result<User> {
        self.eam_field("get-user", &json!({ "userId": user_id }), "user").await
    }

    /// Creates a user. Requires administrator privileges.
    pub async fn register(&self, request: &RegisterRequest) -> Result<()> {
        self.eam_unit("register", request).await
    }

    pub async fn delete_user(&self, user_id: &str) -> Result<()> {
        self.eam_unit("delete-user", &json!({ "userId": user_id })).await
    }

    /// Changes the caller's own password, which needs the current one.
    pub async fn change_password(&self, old_password: &str, new_password: &str) -> Result<()> {
        // No userId: the server reads an absent one as "mine", which is all this means.
        let request = ChangePasswordRequest {
            old_password: old_password.into(),
            new_password: new_password.into(),
            ..Default::default()
        };
        self.eam_unit("change-password", &request).await
    }

    /// Sets another user's password without knowing the old one. Requires administrator
    /// privileges; use [`change_password`](Self::change_password) for your own.
    pub async fn reset_password(&self, user_id: &str, new_password: &str) -> Result<()> {
        if Some(user_id) == self.user_id() {
            return Err(Error::invalid(
                "reset_password() is for another user's password; use change_password(old, new) for your own",
            ));
        }
        let request = ChangePasswordRequest {
            user_id: user_id.into(),
            new_password: new_password.into(),
            ..Default::default()
        };
        self.eam_unit("change-password", &request).await
    }

    /// Gives a user a different user ID. Requires administrator privileges.
    ///
    /// Both ids are named outright, even to rename yourself. The user's ERN, grants and group
    /// memberships move with the name; access keys stay valid. Sessions already open - this one
    /// included, if it renamed itself - keep working until their token expires and cannot be
    /// refreshed afterwards, so log in again under the new id.
    ///
    /// Returns the renamed user, so the new ERN can be read rather than built. The server refuses
    /// with 400 (missing or identical ids), 403, 404 (no such user) or 409 (the new id is taken,
    /// or an application runs as this user - point it elsewhere with `update_application` first).
    pub async fn change_userid(&self, user_id: &str, new_user_id: &str) -> Result<User> {
        let request = ChangeUserIdRequest {
            user_id: user_id.into(),
            new_user_id: new_user_id.into(),
        };
        self.eam_field("change-userid", &request, "user").await
    }

    /// Gives a user a different email address. Requires administrator privileges.
    ///
    /// The user is always named, since an address is a way in (login accepts it in place of the
    /// user id). Nothing else about the user changes, and open sessions keep working. An address
    /// cannot be cleared this way.
    ///
    /// Returns the user as stored. The server refuses with 400 (missing value, not an address, or
    /// the address the user already has), 403, 404 or 409 (another user holds the address).
    pub async fn change_email(&self, user_id: &str, email: &str) -> Result<User> {
        let request = ChangeEmailRequest {
            user_id: user_id.into(),
            email: email.into(),
        };
        self.eam_field("change-email", &request, "user").await
    }

    // -----------------------------------------------------------------------------------------
    // Access keys
    // -----------------------------------------------------------------------------------------

    /// Creates a SigV4 access key for the caller. The secret is returned only here.
    pub async fn create_access_key(&self) -> Result<CreateAccessKeyResponse> {
        self.eam("create-access-key", &json!({})).await
    }

    pub async fn list_access_keys(&self) -> Result<Vec<AccessKey>> {
        self.eam_field::<Option<Vec<AccessKey>>>("list-access-keys", &json!({}), "accessKeys")
            .await
            .map(Option::unwrap_or_default)
    }

    pub async fn delete_access_key(&self, access_key_id: &str) -> Result<()> {
        self.eam_unit("delete-access-key", &json!({ "accessKeyId": access_key_id }))
            .await
    }

    // -----------------------------------------------------------------------------------------
    // User groups
    // -----------------------------------------------------------------------------------------

    pub async fn create_user_group(&self, name: &str, description: &str) -> Result<UserGroup> {
        self.eam_field(
            "create-user-group",
            &json!({ "name": name, "description": description }),
            "userGroup",
        )
        .await
    }

    pub async fn list_user_groups(&self, request: &ListUserGroupsRequest) -> Result<ListUserGroupsResponse> {
        self.eam("list-user-groups", request).await
    }

    /// Reads one group by name, or by ERN if `name_or_ern` starts with `ern:`.
    pub async fn get_user_group(&self, name_or_ern: &str) -> Result<UserGroup> {
        let body = if name_or_ern.starts_with("ern:") {
            json!({ "ern": name_or_ern, "name": null })
        } else {
            json!({ "ern": null, "name": name_or_ern })
        };
        self.eam_field("get-user-group", &body, "userGroup").await
    }

    /// Adds a user (ERN) to a user group (ERN).
    pub async fn add_user_to_user_group(&self, user_group: &str, user: &str) -> Result<()> {
        self.eam_unit("user-group-add-user", &json!({ "userGroup": user_group, "user": user }))
            .await
    }

    /// Removes a user (ERN) from a user group (ERN).
    pub async fn remove_user_from_user_group(&self, user_group: &str, user: &str) -> Result<()> {
        self.eam_unit(
            "user-group-remove-user",
            &json!({ "userGroup": user_group, "user": user }),
        )
        .await
    }

    pub async fn delete_user_group(&self, name: &str) -> Result<()> {
        self.eam_unit("delete-user-group", &json!({ "name": name })).await
    }

    // -----------------------------------------------------------------------------------------
    // Accounts
    // -----------------------------------------------------------------------------------------

    /// Creates an account. Requires administrator privileges.
    pub async fn create_account(&self, account_id: &str, name: &str, description: &str) -> Result<Account> {
        let body = json!({ "accountId": account_id, "name": name, "description": description });
        self.eam_field("create-account", &body, "account").await
    }

    /// Reads one account by ID, or by ERN if `account_id_or_ern` starts with `ern:`.
    pub async fn get_account(&self, account_id_or_ern: &str) -> Result<Account> {
        let body = if account_id_or_ern.starts_with("ern:") {
            json!({ "accountId": null, "ern": account_id_or_ern })
        } else {
            json!({ "accountId": account_id_or_ern, "ern": null })
        };
        self.eam_field("get-account", &body, "account").await
    }

    pub async fn list_accounts(&self, request: &ListAccountsRequest) -> Result<ListAccountsResponse> {
        self.eam("list-accounts", request).await
    }

    /// The accounts this session's user may work in, and which of them is their home account.
    /// Unlike [`list_accounts`](Self::list_accounts) this is not administrator-only and not paged.
    /// [`switch_account`](Self::switch_account) picks one of them.
    pub async fn list_my_accounts(&self) -> Result<ListMyAccountsResponse> {
        self.eam("list-my-accounts", &json!({})).await
    }

    pub async fn delete_account(&self, account_id: &str) -> Result<()> {
        self.eam_unit("delete-account", &json!({ "accountId": account_id }))
            .await
    }

    // -----------------------------------------------------------------------------------------
    // Namespaces
    // -----------------------------------------------------------------------------------------

    /// Creates a namespace under an account. Requires administrator privileges on that account.
    pub async fn create_namespace(&self, account_id: &str, name: &str, description: &str) -> Result<Namespace> {
        let body = json!({ "accountId": account_id, "name": name, "description": description });
        self.eam_field("create-namespace", &body, "namespace").await
    }

    pub async fn list_namespaces(&self, request: &ListNamespacesRequest) -> Result<ListNamespacesResponse> {
        self.eam("list-namespaces", request).await
    }

    /// Deletes a namespace. It must have no remaining grants.
    pub async fn delete_namespace(&self, account_id: &str, name: &str) -> Result<()> {
        self.eam_unit("delete-namespace", &json!({ "accountId": account_id, "name": name }))
            .await
    }

    // -----------------------------------------------------------------------------------------
    // Roles, grants and permissions
    // -----------------------------------------------------------------------------------------

    /// Grants a role to a principal. Keep the returned `grant_id`: it is what
    /// [`revoke_role`](Self::revoke_role) takes.
    pub async fn grant_role(&self, request: &GrantRoleRequest) -> Result<Grant> {
        self.eam_field("grant-role", request, "grant").await
    }

    pub async fn revoke_role(&self, grant_id: &str) -> Result<()> {
        self.eam_unit("revoke-role", &json!({ "grantId": grant_id })).await
    }

    pub async fn list_grants(&self, request: &ListGrantsRequest) -> Result<ListGrantsResponse> {
        self.eam("list-grants", request).await
    }

    /// Answers whether `request.user_id` may perform `target`/`action`, counting group membership
    /// the way a real request does, and which role decided it.
    pub async fn check_permission(&self, request: &CheckPermissionRequest) -> Result<PermissionCheckResponse> {
        self.eam("check-permission", request).await
    }

    /// Everything that can be granted, as `<module>:<action>`.
    pub async fn list_permissions(&self) -> Result<Vec<String>> {
        self.eam_field::<Option<Vec<String>>>("list-permissions", &json!({}), "permissions")
            .await
            .map(Option::unwrap_or_default)
    }

    pub async fn create_role(&self, request: &RoleRequest) -> Result<Role> {
        self.eam_field("create-role", request, "role").await
    }

    pub async fn update_role(&self, request: &RoleRequest) -> Result<Role> {
        self.eam_field("update-role", request, "role").await
    }

    pub async fn get_role(&self, name: &str) -> Result<Role> {
        self.eam_field("get-role", &json!({ "name": name }), "role").await
    }

    pub async fn list_roles(&self, request: &ListRolesRequest) -> Result<ListRolesResponse> {
        self.eam("list-roles", request).await
    }

    pub async fn delete_role(&self, name: &str) -> Result<()> {
        self.eam_unit("delete-role", &json!({ "name": name })).await
    }
}

/// The account id `wanted` names among `mine`, or an error listing the user's accounts the way
/// `euclid-cli eam login --account` does.
pub(crate) fn resolve_account(mine: &ListMyAccountsResponse, wanted: &str) -> Result<String> {
    if let Some(id) = mine.resolve(wanted) {
        return Ok(id.to_owned());
    }
    let known: Vec<String> = mine
        .accounts
        .iter()
        .filter_map(|a| {
            let id = a.account_id.as_deref()?;
            Some(match a.name.as_deref().filter(|n| !n.is_empty() && *n != id) {
                Some(name) => format!("{id} ({name})"),
                None => id.to_owned(),
            })
        })
        .collect();
    let mut message = format!("'{wanted}' is not an account you may work in");
    if !known.is_empty() {
        message.push_str("; yours are: ");
        message.push_str(&known.join(", "));
    }
    Err(Error::invalid(message))
}
