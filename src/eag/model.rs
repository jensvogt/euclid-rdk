//! Request and response types of the EAG (Euclid API Gateway) module.
//!
//! Field names are the wire names in camelCase. Response types default every field, so a field
//! the server leaves out reads as `None`/empty instead of failing the whole response. Request
//! fields left `None` are omitted from the body, as euclid-jdk does.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::serde_util::{lenient_string, lenient_u64};

// ---------------------------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------------------------

/// What a route requires of a caller before the API gateway forwards a request.
///
/// A property of the route rather than of the gateway, so one application can serve a public read
/// and an operation only a euclid principal may perform behind the same listener.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum RouteAuthentication {
    /// Anyone may call it.
    None,
    /// A euclid principal must authenticate.
    Euclid,
    /// HTTP basic authentication.
    Basic,
    /// Anything this client does not know, or none given.
    #[default]
    Unknown,
}

impl RouteAuthentication {
    /// The spelling on the wire: `NONE`, `EUCLID`, `BASIC`, `UNKNOWN`.
    pub fn wire_value(self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::Euclid => "EUCLID",
            Self::Basic => "BASIC",
            Self::Unknown => "UNKNOWN",
        }
    }

    /// Reads a wire value case-insensitively; anything unrecognized is [`Unknown`](Self::Unknown).
    pub fn from_wire_value(value: &str) -> Self {
        [Self::None, Self::Euclid, Self::Basic]
            .into_iter()
            .find(|a| a.wire_value().eq_ignore_ascii_case(value))
            .unwrap_or(Self::Unknown)
    }
}

impl Serialize for RouteAuthentication {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.wire_value())
    }
}

impl<'de> Deserialize<'de> for RouteAuthentication {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(lenient_string(d)?
            .map(|v| Self::from_wire_value(&v))
            .unwrap_or_default())
    }
}

/// What the API gateway does with a request a route matches.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum RouteType {
    /// Forwards it to an application or to one action of a euclid module. What the server
    /// assumes when a create names no type.
    Proxy,
    /// Is the endpoint itself: stores the request body as an object in an ESM bucket (see
    /// [`UploadSpec`]).
    Upload,
    /// Anything this client does not know, or none given.
    #[default]
    Unknown,
}

impl RouteType {
    /// The spelling on the wire: `PROXY`, `UPLOAD`, `UNKNOWN`.
    pub fn wire_value(self) -> &'static str {
        match self {
            Self::Proxy => "PROXY",
            Self::Upload => "UPLOAD",
            Self::Unknown => "UNKNOWN",
        }
    }

    /// Reads a wire value case-insensitively; anything unrecognized is [`Unknown`](Self::Unknown).
    pub fn from_wire_value(value: &str) -> Self {
        [Self::Proxy, Self::Upload]
            .into_iter()
            .find(|t| t.wire_value().eq_ignore_ascii_case(value))
            .unwrap_or(Self::Unknown)
    }
}

impl Serialize for RouteType {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.wire_value())
    }
}

impl<'de> Deserialize<'de> for RouteType {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(lenient_string(d)?
            .map(|v| Self::from_wire_value(&v))
            .unwrap_or_default())
    }
}

/// What a listener speaks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Protocol {
    #[default]
    Http,
    Https,
}

impl Protocol {
    /// The spelling on the wire: `http` or `https`.
    pub fn wire_value(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    /// `https` (any case) is [`Https`](Self::Https); anything else is [`Http`](Self::Http).
    pub fn from_wire_value(value: &str) -> Self {
        if value.eq_ignore_ascii_case("https") {
            Self::Https
        } else {
            Self::Http
        }
    }
}

impl<'de> Deserialize<'de> for Protocol {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(lenient_string(d)?
            .map(|v| Self::from_wire_value(&v))
            .unwrap_or_default())
    }
}

// ---------------------------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------------------------

fn default_true() -> bool {
    true
}

/// A path the API gateway publishes, and what it forwards to: an application, or one action of a
/// euclid module.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Route {
    #[serde(default)]
    pub route_id: Option<String>,
    #[serde(default)]
    pub ern: Option<String>,
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    /// Whether the route forwards ([`RouteType::Proxy`]) or stores uploads
    /// ([`RouteType::Upload`]); [`RouteType::Unknown`] from a server that predates route types.
    #[serde(default, rename = "type")]
    pub kind: RouteType,
    /// Where an upload route stores what it receives; all empty on a proxy route.
    #[serde(default)]
    pub upload: UploadSpec,
    #[serde(default)]
    pub application_id: Option<String>,
    #[serde(default)]
    pub module_target: Option<String>,
    #[serde(default)]
    pub module_action: Option<String>,
    /// HTTP methods served; empty for all.
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub authentication: RouteAuthentication,
    /// Seconds the gateway gives the backend before giving up on a request; 0 for the gateway's
    /// default.
    #[serde(default, deserialize_with = "lenient_u64")]
    pub timeout: u64,
    /// Whether the route is in service; `true` when the server leaves it out.
    #[serde(default = "default_true")]
    pub active: bool,
    #[serde(default, deserialize_with = "lenient_string")]
    pub created: Option<String>,
    #[serde(default, deserialize_with = "lenient_string")]
    pub modified: Option<String>,
}

impl Default for Route {
    fn default() -> Self {
        serde_json::from_value(serde_json::json!({})).expect("every Route field has a default")
    }
}

impl Route {
    /// Whether the route reaches a euclid module action rather than an application.
    pub fn is_module_route(&self) -> bool {
        self.module_target.as_deref().is_some_and(|t| !t.is_empty())
    }
}

/// Where an upload route puts what it receives, and what it accepts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UploadSpec {
    /// ERN of the ESM bucket objects are written to.
    pub bucket: Option<String>,
    /// Prefix every key is confined to, or empty for the whole bucket.
    pub key_prefix: Option<String>,
    /// Largest body accepted, in bytes; 0 is no limit beyond the listener's.
    #[serde(deserialize_with = "lenient_u64")]
    pub max_bytes: u64,
    /// Bytes per part streamed to ESM, and the size under which a body is stored with a single
    /// put instead of a multipart upload.
    #[serde(deserialize_with = "lenient_u64")]
    pub part_size: u64,
    /// Content types accepted; empty for any.
    pub content_types: Vec<String>,
}

/// Body of `create-route` and `update-route`. Fields left `None` are not sent: on create the
/// server applies its defaults, on update they stay as they are. `route_id` names the route.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// [`RouteType::Proxy`] (the server's default on create) or [`RouteType::Upload`].
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<RouteType>,
    /// Forward to this application...
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    /// ...or to this euclid module (`eam`, ...) ...
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_target: Option<String>,
    /// ...and this action of it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<RouteAuthentication>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    /// Seconds the gateway gives the backend, 0..=3600; 0 for the gateway's default. Anything else
    /// is refused with 400.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    /// Upload routes only: ERN of the ESM bucket to store into (404 if there is none). Required
    /// for, and only accepted on, a [`RouteType::Upload`] route.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    /// Upload routes only: prefix every key is confined to; empty for the whole bucket.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_prefix: Option<String>,
    /// Upload routes only: largest body accepted, in bytes; 0 is no limit beyond the listener's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
    /// Upload routes only: bytes per multipart part; the server defaults to 5 MiB.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub part_size: Option<u64>,
    /// Upload routes only: content types accepted; empty for any. Replaces the list on update.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_types: Option<Vec<String>>,
}

/// Body of `create-route`.
pub type CreateRouteRequest = RouteRequest;
/// Body of `update-route`.
pub type UpdateRouteRequest = RouteRequest;

// ---------------------------------------------------------------------------------------------
// Listeners
// ---------------------------------------------------------------------------------------------

/// One port the API gateway was configured to serve, and what it serves there.
///
/// This is what was *configured*: a listener whose port was taken, or whose certificate could not
/// be loaded, is still listed. [`ListListenersResponse::serving`] says whether anything is bound.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Listener {
    /// The namespace this listener serves; empty for the single unscoped listener.
    pub namespace: Option<String>,
    pub port: u32,
    pub protocol: Protocol,
    /// Whether the gateway's ports are bound at all - the same on every entry.
    pub serving: bool,
    /// The certificate an HTTPS listener serves: the one it named, or its namespace's
    /// conventional one. Empty for plain HTTP.
    pub certificate_name: Option<String>,
    /// What the configuration wrote, to tell "names its certificate" from "takes the default".
    pub configured_certificate: Option<String>,
    /// The certificate itself; `None` for plain HTTP or when it was not found.
    pub certificate: Option<ListenerCertificate>,
}

impl Listener {
    /// Whether the configuration names this listener's certificate explicitly.
    pub fn names_certificate(&self) -> bool {
        self.configured_certificate.as_deref().is_some_and(|c| !c.is_empty())
    }
}

/// The public facts of the certificate an HTTPS listener serves. No key material is ever sent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListenerCertificate {
    pub ern: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub serial_number: Option<String>,
    pub fingerprint: Option<String>,
    pub subject_alt_names: Vec<String>,
    /// Whether euclid minted it itself (self-signed): callers reject it until they are given it.
    pub generated: bool,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub expired: bool,
}

/// The wire shape of a listener: the certificate's fields are flattened into it.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct WireListener {
    namespace: Option<String>,
    port: Option<serde_json::Value>,
    protocol: Protocol,
    serving: bool,
    certificate: Option<String>,
    certificate_configured: Option<String>,
    certificate_found: bool,
    certificate_ern: Option<String>,
    certificate_subject: Option<String>,
    certificate_issuer: Option<String>,
    certificate_serial_number: Option<String>,
    certificate_fingerprint: Option<String>,
    certificate_subject_alt_names: Vec<String>,
    certificate_generated: bool,
    #[serde(deserialize_with = "lenient_string")]
    certificate_not_before: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    certificate_not_after: Option<String>,
    certificate_expired: bool,
}

impl<'de> Deserialize<'de> for Listener {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let w = WireListener::deserialize(d)?;
        let port = match &w.port {
            Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(0) as u32,
            Some(serde_json::Value::String(s)) => s.trim().parse().unwrap_or(0),
            _ => 0,
        };
        let certificate = w.certificate_found.then_some(ListenerCertificate {
            ern: w.certificate_ern,
            subject: w.certificate_subject,
            issuer: w.certificate_issuer,
            serial_number: w.certificate_serial_number,
            fingerprint: w.certificate_fingerprint,
            subject_alt_names: w.certificate_subject_alt_names,
            generated: w.certificate_generated,
            not_before: w.certificate_not_before,
            not_after: w.certificate_not_after,
            expired: w.certificate_expired,
        });
        Ok(Listener {
            namespace: w.namespace,
            port,
            protocol: w.protocol,
            serving: w.serving,
            certificate_name: w.certificate,
            configured_certificate: w.certificate_configured,
            certificate,
        })
    }
}

/// Answer to `list-listeners`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListListenersResponse {
    pub listeners: Vec<Listener>,
    /// The server's total; the number of listeners when it sends none.
    pub total: u64,
    /// Whether the gateway's ports are bound at all.
    pub serving: bool,
}
