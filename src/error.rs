use std::fmt;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Everything a call into euclid can fail with.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The server rejected the login itself (wrong password, unknown user, ...).
    #[error("Login failed with status {status}: {body}")]
    Authentication { status: u16, body: String },

    /// The server answered a request with a non-2xx status.
    #[error("{service} {action} failed with status {status}: {body}")]
    Service {
        service: String,
        action: String,
        status: u16,
        body: String,
    },

    /// The call could not be made as asked - missing credentials, a bad argument.
    #[error("{0}")]
    InvalidArgument(String),

    /// The request never got an answer: connection refused, TLS failure, timeout.
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// A body could not be encoded, or a response could not be decoded.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Reading or writing a local file (credentials, CA certificate) failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    pub(crate) fn service(service: &str, action: &str, status: u16, body: impl Into<String>) -> Self {
        Error::Service {
            service: service.to_owned(),
            action: action.to_owned(),
            status,
            body: body.into(),
        }
    }

    pub(crate) fn invalid(message: impl fmt::Display) -> Self {
        Error::InvalidArgument(message.to_string())
    }

    /// The HTTP status the server answered with, if it answered at all.
    pub fn status(&self) -> Option<u16> {
        match self {
            Error::Authentication { status, .. } | Error::Service { status, .. } => Some(*status),
            Error::Http(e) => e.status().map(|s| s.as_u16()),
            _ => None,
        }
    }
}
