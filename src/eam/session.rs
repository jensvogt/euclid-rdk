use std::path::PathBuf;

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};

use super::model::*;
use crate::credentials::{self, CachedCredentials};
use crate::eag::Eag;
use crate::ekm::Ekm;
use crate::ekv::Ekv;
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
