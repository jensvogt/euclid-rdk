//! EMO - Euclid Monitoring (pushing metrics a process measured about itself).

pub mod model;

use crate::service::ServiceClient;

/// EMO operations, obtained from [`Session::emo`](crate::Session::emo).
///
/// Requests are SigV4-signed with the session's access key when it has one, otherwise
/// authenticated with the bearer token. Cloning is cheap.
#[derive(Debug, Clone)]
pub struct Emo {
    #[allow(dead_code)]
    client: ServiceClient,
}

impl Emo {
    pub(crate) fn new(client: ServiceClient) -> Self {
        Self { client }
    }
}
