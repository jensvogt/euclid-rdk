//! EAG - Euclid API Gateway (routes and listeners). Every action is administrator-only.
//!
//! The API gateway is a second listener, separate from the one this client talks to: it publishes
//! plain HTTP paths to the outside world and forwards them to applications or to single euclid
//! module actions. These operations manage what it publishes; every one of them decides what is
//! exposed and on what terms, so a non-admin session gets 403 from all of them.

pub mod model;

pub use model::*;
use serde_json::{json, Value};

use crate::service::ServiceClient;
use crate::Result;

/// EAG operations, obtained from [`Session::eag`](crate::Session::eag).
///
/// Requests are SigV4-signed with the session's access key when it has one, otherwise
/// authenticated with the bearer token. Cloning is cheap.
#[derive(Debug, Clone)]
pub struct Eag {
    client: ServiceClient,
}

impl Eag {
    pub(crate) fn new(client: ServiceClient) -> Self {
        Self { client }
    }

    // -----------------------------------------------------------------------------------------
    // Routes
    // -----------------------------------------------------------------------------------------

    /// Publishes `path` and forwards it to the application `application_id`.
    pub async fn create_route(&self, route_id: &str, path: &str, application_id: &str) -> Result<Route> {
        self.create_route_with(&RouteRequest {
            route_id: Some(route_id.into()),
            path: Some(path.into()),
            application_id: Some(application_id.into()),
            ..Default::default()
        })
        .await
    }

    /// Publishes `path` as an upload endpoint: a request body sent there is stored as an object in
    /// the ESM bucket `bucket_ern`. An upload route has to require authentication -
    /// [`RouteAuthentication::Euclid`] or [`RouteAuthentication::Basic`]; `None` is refused with
    /// 400. Use [`create_route_with`](Self::create_route_with) for a key prefix, size limit or
    /// content types.
    pub async fn create_upload_route(
        &self,
        route_id: &str,
        path: &str,
        bucket_ern: &str,
        authentication: RouteAuthentication,
    ) -> Result<Route> {
        self.create_route_with(&RouteRequest {
            route_id: Some(route_id.into()),
            path: Some(path.into()),
            kind: Some(RouteType::Upload),
            bucket: Some(bucket_ern.into()),
            authentication: Some(authentication),
            ..Default::default()
        })
        .await
    }

    /// Publishes `path` and forwards it to one action of a euclid module - e.g. EAM `login` for a
    /// browser front end, so it needs only one origin instead of two plus CORS.
    pub async fn create_module_route(
        &self,
        route_id: &str,
        path: &str,
        module_target: &str,
        module_action: &str,
    ) -> Result<Route> {
        self.create_route_with(&RouteRequest {
            route_id: Some(route_id.into()),
            path: Some(path.into()),
            module_target: Some(module_target.into()),
            module_action: Some(module_action.into()),
            ..Default::default()
        })
        .await
    }

    /// Creates a route with every option; `None` fields take the server's defaults.
    pub async fn create_route_with(&self, request: &CreateRouteRequest) -> Result<Route> {
        self.client.call("create-route", request).await
    }

    /// Changes a route; `None` fields stay as they are.
    pub async fn update_route(&self, request: &UpdateRouteRequest) -> Result<Route> {
        self.client.call("update-route", request).await
    }

    /// Takes a route out of service, or puts it back, changing nothing else - the way to stop
    /// exposing something in a hurry, since it comes back exactly as it was.
    pub async fn set_route_active(&self, route_id: &str, active: bool) -> Result<Route> {
        self.update_route(&RouteRequest {
            route_id: Some(route_id.into()),
            active: Some(active),
            ..Default::default()
        })
        .await
    }

    /// Lists the routes of this session's account and namespace whose path starts with
    /// `path_prefix` (empty for all).
    pub async fn list_routes(&self, path_prefix: &str) -> Result<Vec<Route>> {
        self.client
            .call_field::<Option<Vec<Route>>>("list-routes", &json!({ "prefix": path_prefix }), "routes")
            .await
            .map(Option::unwrap_or_default)
    }

    pub async fn get_route(&self, route_id: &str) -> Result<Route> {
        self.client.call("get-route", &json!({ "routeId": route_id })).await
    }

    /// Deletes a route, which stops the gateway serving its path. To take it out of service
    /// temporarily use [`set_route_active`](Self::set_route_active) instead.
    pub async fn delete_route(&self, route_id: &str) -> Result<()> {
        self.client
            .call_unit("delete-route", &json!({ "routeId": route_id }))
            .await
    }

    // -----------------------------------------------------------------------------------------
    // Listeners
    // -----------------------------------------------------------------------------------------

    /// What the gateway was configured to serve, and whether it is serving it. For an HTTPS
    /// listener the certificate comes with it, including whether euclid minted it itself.
    pub async fn list_listeners(&self) -> Result<ListListenersResponse> {
        let root = self.client.call_value("list-listeners", &json!({})).await?;
        let listeners: Vec<Listener> = match root.get("listeners") {
            Some(v @ Value::Array(_)) => serde_json::from_value(v.clone())?,
            _ => Vec::new(),
        };
        Ok(ListListenersResponse {
            total: root
                .get("total")
                .and_then(Value::as_u64)
                .unwrap_or(listeners.len() as u64),
            serving: root.get("serving").and_then(Value::as_bool).unwrap_or(false),
            listeners,
        })
    }
}
