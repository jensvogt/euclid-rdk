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
    pub page_size: u64,
    pub page_index: u64,
    pub sort_column: String,
    pub sort_direction: SortDirection,
}

impl Default for ListUsersRequest {
    fn default() -> Self {
        Self {
            prefix: String::new(),
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
    pub page_size: u64,
    pub page_index: u64,
    pub sort_column: String,
    pub sort_direction: SortDirection,
}

impl Default for ListUserGroupsRequest {
    fn default() -> Self {
        Self {
            prefix: String::new(),
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
    pub page_size: u64,
    pub page_index: u64,
    pub sort_column: String,
    pub sort_direction: SortDirection,
}

impl Default for ListAccountsRequest {
    fn default() -> Self {
        Self {
            prefix: String::new(),
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
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListNamespacesRequest {
    pub account_id: String,
    pub prefix: String,
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

/// Whether a request would be allowed, and which role decided it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PermissionCheckResponse {
    pub allowed: bool,
    pub reason: Option<String>,
    pub role: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------------------------

/// Sort order of a listing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortDirection {
    #[default]
    Asc,
    Desc,
}
