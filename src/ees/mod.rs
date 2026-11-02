//! EES - Euclid Event Service: durable subscriptions to events from ESM and the other modules.

pub mod model;

use crate::service::ServiceClient;

/// EES operations, obtained from [`Session::ees`](crate::Session::ees).
///
/// Requests are SigV4-signed with the session's access key when it has one, otherwise
/// authenticated with the bearer token. Cloning is cheap.
#[derive(Debug, Clone)]
pub struct Ees {
    #[allow(dead_code)]
    client: ServiceClient,
}

impl Ees {
    pub(crate) fn new(client: ServiceClient) -> Self {
        Self { client }
    }
}
