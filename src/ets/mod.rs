//! ETS - Euclid Transfer Service (transfer servers).
//!
//! A transfer server is an FTP or SFTP listener fronting an ESM bucket: clients authenticate with
//! their EAM credentials and whatever they upload becomes an object in that bucket. Every action
//! here changes - or reveals - which network listeners exist and who may reach which bucket
//! through them, so all of them are administrator-only: a non-admin session gets HTTP 403.
//!
//! Starting and stopping only record intent: they set the server's `desired_state`, and
//! euclid-mgr's reconciler launches or tears down the process, so `state` can lag behind.

pub mod model;

pub use model::*;
use serde_json::json;

use crate::service::ServiceClient;
use crate::{Error, Result};

/// ETS operations, obtained from [`Session::ets`](crate::Session::ets).
///
/// Requests are SigV4-signed with the session's access key when it has one, otherwise
/// authenticated with the bearer token. Cloning is cheap.
#[derive(Debug, Clone)]
pub struct Ets {
    client: ServiceClient,
}

impl Ets {
    pub(crate) fn new(client: ServiceClient) -> Self {
        Self { client }
    }

    /// Defines a new transfer server. It is created stopped - call
    /// [`start_server`](Self::start_server) to run it.
    ///
    /// The bucket is resolved now, so a name matching nothing is a 404 here rather than a server
    /// that runs but stores nothing; a port another transfer server holds is refused with 409.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] without sending anything if the request names neither users
    /// nor user groups - nobody could log in to such a listener.
    pub async fn create_server(&self, request: &CreateServerRequest) -> Result<TransferServer> {
        let none = |v: &Option<Vec<String>>| v.as_ref().is_none_or(Vec::is_empty);
        if none(&request.user_ids) && none(&request.user_groups) {
            return Err(Error::invalid(
                "at least one of user_ids or user_groups is required, otherwise nobody can log in",
            ));
        }
        self.client.call("create-server", request).await
    }

    /// Changes an existing server. Only the fields set on the request are sent and touched.
    pub async fn update_server(&self, request: &UpdateServerRequest) -> Result<TransferServer> {
        self.client.call("update-server", request).await
    }

    /// Lists every transfer server.
    pub async fn list_servers(&self) -> Result<Vec<TransferServer>> {
        self.list_servers_with_prefix("").await
    }

    /// Lists the transfer servers whose ID starts with `prefix` (empty for all).
    pub async fn list_servers_with_prefix(&self, prefix: &str) -> Result<Vec<TransferServer>> {
        let response: ListServersResponse = self.client.call("list-servers", &json!({ "prefix": prefix })).await?;
        Ok(response.servers)
    }

    pub async fn get_server(&self, server_id: &str) -> Result<TransferServer> {
        self.client.call("get-server", &json!({ "serverId": server_id })).await
    }

    /// Deletes a server's definition, which also stops it: the reconciler tears down whatever is
    /// no longer defined on its next tick.
    pub async fn delete_server(&self, server_id: &str) -> Result<()> {
        self.client
            .call_unit("delete-server", &json!({ "serverId": server_id }))
            .await
    }

    /// Records that the server should run. The returned `state` may still read `"STOPPED"` while
    /// `desired_state` is already `"RUNNING"`.
    pub async fn start_server(&self, server_id: &str) -> Result<TransferServer> {
        self.client
            .call("start-server", &json!({ "serverId": server_id }))
            .await
    }

    /// Records that the server should be stopped, keeping its definition.
    pub async fn stop_server(&self, server_id: &str) -> Result<TransferServer> {
        self.client.call("stop-server", &json!({ "serverId": server_id })).await
    }
}
