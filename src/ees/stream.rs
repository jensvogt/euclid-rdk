//! The gateway's WebSocket event stream (feature `ws`).
//!
//! One persistent connection that authenticates once at handshake time - SigV4-signed as a `GET`
//! with an empty body, or with the bearer token, like every HTTP call - and then carries
//! subscribe/unsubscribe control frames out and event frames in. Port of euclid-jdk's
//! `EuclidEventStream`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Map, Value};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::Message;

use super::model::DeliveryMode;
use crate::auth::sigv4;
use crate::service::{Identity, ServiceClient};
use crate::{Error, Result};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const ACK_TIMEOUT: Duration = Duration::from_secs(3);
/// Comfortably inside the gateway's idle timeout (300 s by default); the gateway does not ping.
const PING_INTERVAL: Duration = Duration::from_secs(60);
const RECONNECT_DELAY: Duration = Duration::from_secs(1);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(30);
const ACTION: &str = "event-stream";
const FRAME_CHANNEL_CAPACITY: usize = 1024;

/// Called as frames arrive on an [`EventStream`].
///
/// The methods are the things the gateway can say to a connected client:
/// - [`on_event`](Self::on_event): here is an event. Only a live subscription receives these.
/// - [`on_notify`](Self::on_notify): something is waiting for a durable subscription - claim it
///   with `receive-events`, since instances sharing a name decide by claiming who processes it.
/// - [`on_lag`](Self::on_lag): the connection fell behind and pushed events were dropped. For a
///   durable subscription the events are still stored, so it means "go and claim".
/// - [`on_reconnected`](Self::on_reconnected): the connection was re-established and its
///   subscriptions registered again. Nothing was pushed meanwhile, so it means the same as a lag.
///
/// Every method is called on the connection's reading task and must not block; anything that
/// talks to the server belongs on a task of the listener's own, as [`EventListener`] does.
///
/// [`EventListener`]: super::EventListener
pub trait EventStreamListener: Send + Sync {
    /// A live event arrived.
    fn on_event(&self, _topic: &str, _body: &Value) {}

    /// A durable subscription has events waiting.
    fn on_notify(&self, _topic: &str) {}

    /// The gateway dropped `dropped` pushed events because this connection fell behind.
    fn on_lag(&self, _dropped: u64) {}

    /// The connection was lost and re-established, with its subscriptions registered again.
    /// Defaults to [`on_lag(0)`](Self::on_lag).
    fn on_reconnected(&self) {
        self.on_lag(0);
    }
}

/// Identifies a listener added with [`EventStream::add_listener`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ListenerId(u64);

/// A frame as [`EventStream::frames`] reports it - the channel form of [`EventStreamListener`].
#[derive(Debug, Clone, PartialEq)]
pub enum StreamFrame {
    /// A live event: its type and payload.
    Event { topic: String, body: Value },
    /// A durable subscription has events of this type waiting.
    Notify { topic: String },
    /// The gateway dropped this many pushed events.
    Lag { dropped: u64 },
    /// The connection was re-established and its subscriptions restored.
    Reconnected,
}

/// One persistent WebSocket connection to the gateway's event stream.
///
/// Connecting is lazy: the first [`subscribe`](Self::subscribe), [`attach`](Self::attach) or
/// [`await_event`](Self::await_event) performs the handshake, and a failure (WebSocket support
/// disabled on the server, network error) is returned so the caller can fall back to polling.
///
/// A connection that drops is re-established in the background with a backoff (1 s doubling up
/// to 30 s), and the subscriptions it carried are registered again - delivery is per connection
/// on the gateway, so without the replay a reconnected client would receive nothing. Listeners
/// are then told via [`EventStreamListener::on_reconnected`]. A keepalive ping goes out every
/// 60 s so an idle connection is not closed by the gateway's idle timeout.
///
/// Cloning is cheap; clones share the connection. The connection is closed by
/// [`close`](Self::close) or when the last clone is dropped.
#[derive(Clone)]
pub struct EventStream {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for EventStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventStream")
            .field("base_url", &self.inner.base_url)
            .field("target", &self.inner.target)
            .field("connected", &self.is_connected())
            .field("subscriber_name", &self.subscriber_name())
            .finish_non_exhaustive()
    }
}

struct Inner {
    base_url: String,
    identity: Identity,
    target: String,
    ca_cert_path: Option<PathBuf>,
    connection: Mutex<Option<Connection>>,
    connect_lock: tokio::sync::Mutex<()>,
    pending_acks: Mutex<HashMap<String, oneshot::Sender<Option<String>>>>,
    /// Every delivery registration made, in order, so a replacement connection gets the same.
    registrations: Mutex<Vec<Registration>>,
    /// Unnamed topic/filter subscriptions, to make a repeated `subscribe` a no-op.
    active: Mutex<HashSet<Subscription>>,
    listeners: Mutex<Vec<(ListenerId, Arc<dyn EventStreamListener>)>>,
    waiters: Mutex<Vec<Waiter>>,
    frames: broadcast::Sender<StreamFrame>,
    subscriber_name: Mutex<Option<String>>,
    maintenance: Mutex<Vec<JoinHandle<()>>>,
    closed: AtomicBool,
    reconnecting: AtomicBool,
    next_id: AtomicU64,
    generation: AtomicU64,
}

struct Connection {
    generation: u64,
    sender: mpsc::UnboundedSender<Message>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Subscription {
    topic: String,
    filter: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Registration {
    topic: Option<String>,
    filter: BTreeMap<String, String>,
    name: Option<String>,
    mode: Option<DeliveryMode>,
}

struct Waiter {
    id: u64,
    topic: String,
    filter: BTreeMap<String, String>,
    done: Option<oneshot::Sender<()>>,
}

impl EventStream {
    /// A stream on the server and identity `client` uses, signing its handshake as `target`
    /// (e.g. `"ees"`, `"eqs"`) - purely for the signature; the gateway does not route by it.
    pub(crate) fn new(client: &ServiceClient, target: &str) -> Self {
        let (frames, _) = broadcast::channel(FRAME_CHANNEL_CAPACITY);
        Self {
            inner: Arc::new(Inner {
                base_url: client.base_url().to_owned(),
                identity: client.identity().clone(),
                target: target.to_owned(),
                ca_cert_path: client.ca_cert_path().map(Into::into),
                connection: Mutex::new(None),
                connect_lock: tokio::sync::Mutex::new(()),
                pending_acks: Mutex::default(),
                registrations: Mutex::default(),
                active: Mutex::default(),
                listeners: Mutex::default(),
                waiters: Mutex::default(),
                frames,
                subscriber_name: Mutex::new(None),
                maintenance: Mutex::default(),
                closed: AtomicBool::new(false),
                reconnecting: AtomicBool::new(false),
                next_id: AtomicU64::new(1),
                generation: AtomicU64::new(0),
            }),
        }
    }

    /// Whether a connection is currently open.
    pub fn is_connected(&self) -> bool {
        lock(&self.inner.connection).is_some()
    }

    /// Subscribes this connection to events of `topic` matching `filter` (exact-match pairs on
    /// the event body; empty matches every event of the topic). The gateway creates a live
    /// subscription of its own for it, removed when the connection ends. A no-op without a round
    /// trip if already subscribed to exactly this topic and filter.
    pub async fn subscribe(&self, topic: &str, filter: &[(&str, &str)]) -> Result<()> {
        let subscription = Subscription {
            topic: topic.to_owned(),
            filter: to_filter(filter),
        };
        if !lock(&self.inner.active).insert(subscription.clone()) {
            return Ok(());
        }
        let result = self
            .inner
            .send_control_frame("subscribe", Some(topic), &subscription.filter, None, None)
            .await;
        if result.is_err() {
            lock(&self.inner.active).remove(&subscription);
        }
        result
    }

    /// Undoes [`subscribe`](Self::subscribe). A no-op if not subscribed to exactly this topic
    /// and filter.
    pub async fn unsubscribe(&self, topic: &str, filter: &[(&str, &str)]) -> Result<()> {
        let subscription = Subscription {
            topic: topic.to_owned(),
            filter: to_filter(filter),
        };
        if !lock(&self.inner.active).remove(&subscription) {
            return Ok(());
        }
        self.inner
            .send_control_frame("unsubscribe", Some(topic), &subscription.filter, None, None)
            .await
    }

    /// Registers the EES subscription `name` for `topic`/`filter` and attaches this connection
    /// to it. It is the same subscription `subscribe-events` takes over HTTP and outlives the
    /// connection; `None` leaves the mode to the server, which defaults to durable. Subscribing
    /// again with the same name and topic replaces its filter and mode.
    pub async fn subscribe_named(
        &self,
        name: &str,
        topic: &str,
        filter: &[(&str, &str)],
        mode: Option<DeliveryMode>,
    ) -> Result<()> {
        self.inner
            .send_control_frame("subscribe", Some(topic), &to_filter(filter), Some(name), mode)
            .await
    }

    /// Attaches this connection to an existing subscription without redefining it - how a client
    /// listens to a subscription set up elsewhere, and the only form that cannot overwrite its
    /// filter.
    pub async fn attach(&self, name: &str) -> Result<()> {
        self.inner
            .send_control_frame("subscribe", None, &BTreeMap::new(), Some(name), None)
            .await
    }

    /// Stops receiving `name`'s events on this connection, leaving the subscription itself alone,
    /// so a durable subscriber keeps collecting while nothing listens.
    pub async fn detach(&self, name: &str) -> Result<()> {
        self.inner
            .send_control_frame("unsubscribe", None, &BTreeMap::new(), Some(name), None)
            .await
    }

    /// The subscriber name this connection's events arrive under - after an unnamed
    /// [`subscribe`](Self::subscribe), the name the gateway chose. `None` before any subscribe.
    pub fn subscriber_name(&self) -> Option<String> {
        lock(&self.inner.subscriber_name).clone()
    }

    /// Registers a listener for the frames arriving on this connection.
    pub fn add_listener(&self, listener: Arc<dyn EventStreamListener>) -> ListenerId {
        let id = ListenerId(self.inner.next_id.fetch_add(1, Ordering::Relaxed));
        lock(&self.inner.listeners).push((id, listener));
        id
    }

    /// Removes a listener added with [`add_listener`](Self::add_listener).
    pub fn remove_listener(&self, id: ListenerId) {
        lock(&self.inner.listeners).retain(|(existing, _)| *existing != id);
    }

    /// Every frame from now on, as a channel. A receiver that falls more than 1024 frames behind
    /// gets [`RecvError::Lagged`](tokio::sync::broadcast::error::RecvError::Lagged).
    pub fn frames(&self) -> broadcast::Receiver<StreamFrame> {
        self.inner.frames.subscribe()
    }

    /// Subscribes to `topic`/`filter` (if not already) and waits up to `timeout` for the next
    /// matching live event. `Ok(false)` on timeout.
    pub async fn await_event(&self, topic: &str, filter: &[(&str, &str)], timeout: Duration) -> Result<bool> {
        // Registered before subscribing: an event sent the instant the subscription is
        // acknowledged could otherwise be dispatched before anything waited for it.
        let (done, rx) = oneshot::channel();
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        lock(&self.inner.waiters).push(Waiter {
            id,
            topic: topic.to_owned(),
            filter: to_filter(filter),
            done: Some(done),
        });
        let result = match self.subscribe(topic, filter).await {
            Ok(()) => Ok(tokio::time::timeout(timeout, rx).await.is_ok_and(|r| r.is_ok())),
            Err(e) => Err(e),
        };
        lock(&self.inner.waiters).retain(|w| w.id != id);
        result
    }

    /// Closes the connection, if open, and stops reconnecting. Safe to call when never connected.
    pub fn close(&self) {
        self.inner.close();
    }
}

impl Inner {
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        for handle in lock(&self.maintenance).drain(..) {
            handle.abort();
        }
        if let Some(connection) = lock(&self.connection).take() {
            let _ = connection.sender.send(Message::Close(Some(CloseFrame {
                code: CloseCode::Normal,
                reason: "".into(),
            })));
        }
    }

    async fn send_control_frame(
        self: &Arc<Self>,
        kind: &str,
        topic: Option<&str>,
        filter: &BTreeMap<String, String>,
        name: Option<&str>,
        mode: Option<DeliveryMode>,
    ) -> Result<()> {
        self.connect().await?;
        self.send_on_current_connection(kind, topic, filter, name, mode).await?;

        // Remembered only once acknowledged, so a replay never re-sends something the gateway
        // rejected, and dropped on unsubscribe so a reconnect does not resurrect it.
        let registration = Registration {
            topic: topic.map(str::to_owned),
            filter: filter.clone(),
            name: name.map(str::to_owned),
            mode,
        };
        let mut registrations = lock(&self.registrations);
        if kind == "subscribe" {
            if !registrations.contains(&registration) {
                registrations.push(registration);
            }
        } else {
            registrations.retain(|r| r != &registration);
        }
        Ok(())
    }

    async fn send_on_current_connection(
        &self,
        kind: &str,
        topic: Option<&str>,
        filter: &BTreeMap<String, String>,
        name: Option<&str>,
        mode: Option<DeliveryMode>,
    ) -> Result<()> {
        let sender = lock(&self.connection)
            .as_ref()
            .map(|c| c.sender.clone())
            .ok_or_else(|| io_error("event stream is not connected"))?;

        let id = self.frame_id();
        let (ack, acked) = oneshot::channel();
        lock(&self.pending_acks).insert(id.clone(), ack);

        let frame = build_control_frame(kind, &id, topic, filter, name, mode);
        let outcome = if sender.send(Message::Text(frame.into())).is_err() {
            None
        } else {
            match tokio::time::timeout(ACK_TIMEOUT, acked).await {
                Ok(Ok(acknowledged)) => Some(acknowledged),
                _ => None,
            }
        };
        lock(&self.pending_acks).remove(&id);

        match outcome {
            Some(acknowledged) => {
                // The ack is where an unnamed subscription learns the name the gateway gave it,
                // and where a named one is confirmed.
                if let Some(acknowledged) = acknowledged.filter(|n| !n.is_empty()) {
                    *lock(&self.subscriber_name) = (kind != "unsubscribe").then_some(acknowledged);
                }
                Ok(())
            }
            None => Err(io_error(format!(
                "failed to {kind} to {}",
                match topic {
                    Some(topic) => format!("topic {topic}"),
                    None => format!("subscriber {}", name.unwrap_or_default()),
                }
            ))),
        }
    }

    fn frame_id(&self) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("{nanos:x}-{}", self.next_id.fetch_add(1, Ordering::Relaxed))
    }

    async fn connect(self: &Arc<Self>) -> Result<()> {
        if lock(&self.connection).is_some() {
            return Ok(());
        }
        let _guard = self.connect_lock.lock().await;
        if lock(&self.connection).is_some() {
            return Ok(());
        }
        if self.closed.load(Ordering::SeqCst) {
            return Err(io_error("event stream is closed"));
        }

        let url = websocket_url(&self.base_url);
        let mut request = url
            .as_str()
            .into_client_request()
            .map_err(|e| io_error(format!("invalid event stream URL {url}: {e}")))?;
        for (name, value) in self.handshake_headers() {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|e| Error::invalid(format!("invalid header name {name:?}: {e}")))?;
            let value =
                HeaderValue::from_str(&value).map_err(|e| Error::invalid(format!("invalid header value: {e}")))?;
            request.headers_mut().insert(name, value);
        }

        let connecting = open_socket(request, self.ca_cert_path.as_deref());
        let (socket, _) = match tokio::time::timeout(CONNECT_TIMEOUT, connecting).await {
            Ok(Ok(connected)) => connected,
            Ok(Err(e)) => return Err(e.into_error(&url)),
            Err(_) => return Err(io_error(format!("timed out connecting event stream to {url}"))),
        };

        let (mut sink, mut source) = socket.split();
        let (sender, mut outbox) = mpsc::unbounded_channel::<Message>();
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;

        tokio::spawn(async move {
            while let Some(message) = outbox.recv().await {
                let closing = matches!(message, Message::Close(_));
                if sink.send(message).await.is_err() || closing {
                    break;
                }
            }
            let _ = sink.close().await;
        });

        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            while let Some(message) = source.next().await {
                let Some(inner) = weak.upgrade() else { return };
                match message {
                    Ok(Message::Text(text)) => inner.handle_frame(text.as_str()),
                    Ok(Message::Close(_)) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            if let Some(inner) = weak.upgrade() {
                inner.connection_lost(generation);
            }
        });

        *lock(&self.connection) = Some(Connection { generation, sender });
        self.start_maintenance();
        Ok(())
    }

    /// Starts the keepalive once, on the first successful connection.
    fn start_maintenance(self: &Arc<Self>) {
        let mut maintenance = lock(&self.maintenance);
        if !maintenance.is_empty() {
            return;
        }
        let weak = Arc::downgrade(self);
        maintenance.push(tokio::spawn(async move {
            loop {
                tokio::time::sleep(PING_INTERVAL).await;
                let Some(inner) = weak.upgrade() else { return };
                if inner.closed.load(Ordering::SeqCst) {
                    return;
                }
                let current = lock(&inner.connection)
                    .as_ref()
                    .map(|c| (c.generation, c.sender.clone()));
                if let Some((generation, sender)) = current {
                    if sender.send(Message::Ping(Vec::new().into())).is_err() {
                        inner.connection_lost(generation);
                    }
                }
            }
        }));
    }

    /// Called when connection `generation` went away. Reconnects on a task of its own, after
    /// [`RECONNECT_DELAY`], with a backoff, until it succeeds or the stream is closed.
    fn connection_lost(self: &Arc<Self>, generation: u64) {
        {
            let mut connection = lock(&self.connection);
            if connection.as_ref().is_some_and(|c| c.generation == generation) {
                *connection = None;
            }
        }
        if self.closed.load(Ordering::SeqCst) || self.reconnecting.swap(true, Ordering::SeqCst) {
            return;
        }
        let weak: Weak<Inner> = Arc::downgrade(self);
        let handle = tokio::spawn(async move {
            let mut delay = RECONNECT_DELAY;
            tokio::time::sleep(RECONNECT_DELAY).await;
            loop {
                let Some(inner) = weak.upgrade() else { return };
                if inner.closed.load(Ordering::SeqCst) {
                    inner.reconnecting.store(false, Ordering::SeqCst);
                    return;
                }
                match inner.reconnect_once().await {
                    Ok(()) => {
                        inner.reconnecting.store(false, Ordering::SeqCst);
                        for listener in inner.listeners_snapshot() {
                            listener.on_reconnected();
                        }
                        let _ = inner.frames.send(StreamFrame::Reconnected);
                        return;
                    }
                    Err(_) => {
                        // A half-established connection is given up, so the next attempt starts
                        // afresh rather than replaying onto it.
                        lock(&inner.connection).take();
                    }
                }
                drop(inner);
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(MAX_RECONNECT_DELAY);
            }
        });
        let mut maintenance = lock(&self.maintenance);
        maintenance.retain(|h| !h.is_finished());
        maintenance.push(handle);
    }

    async fn reconnect_once(self: &Arc<Self>) -> Result<()> {
        self.connect().await?;
        let replay = lock(&self.registrations).clone();
        for r in replay {
            self.send_on_current_connection("subscribe", r.topic.as_deref(), &r.filter, r.name.as_deref(), r.mode)
                .await?;
        }
        Ok(())
    }

    fn listeners_snapshot(&self) -> Vec<Arc<dyn EventStreamListener>> {
        lock(&self.listeners).iter().map(|(_, l)| Arc::clone(l)).collect()
    }

    /// Routing headers plus authentication. The handshake is a `GET` with no body, so it is signed
    /// as one - distinct from the `POST` signing of the action calls.
    fn handshake_headers(&self) -> Vec<(String, String)> {
        let id = &self.identity;
        let mut headers: Vec<(String, String)> = Vec::new();
        if let Some(v) = &id.region {
            headers.push(("x-euclid-region".into(), v.clone()));
        }
        if let Some(v) = &id.account_id {
            headers.push(("x-euclid-account-id".into(), v.clone()));
        }
        if let Some(v) = &id.user_id {
            headers.push(("x-euclid-user-id".into(), v.clone()));
        }
        // The gateway reads the namespace from the handshake and scopes the connection's
        // subscriptions with it.
        if let Some(v) = id.namespace.as_deref().filter(|n| !n.is_empty()) {
            headers.push(("x-euclid-namespace".into(), v.to_owned()));
        }

        let key = match (id.access_key_id.as_deref(), id.secret_access_key.as_deref()) {
            (Some(k), Some(s)) if !k.is_empty() && !s.is_empty() => Some((k, s)),
            _ => None,
        };
        match key {
            Some((key_id, secret)) => {
                let host = authority(&self.base_url);
                let mut signable: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
                signable.push(("host", &host));
                signable.push(("x-euclid-target", &self.target));
                signable.push(("x-euclid-action", ACTION));
                let signature = sigv4::sign(
                    "GET",
                    "/",
                    &signable,
                    b"",
                    key_id,
                    secret,
                    id.region.as_deref().unwrap_or_default(),
                    &self.target,
                    &sigv4::amz_date_now(),
                );
                headers.push(("x-amz-date".into(), signature.amz_date));
                headers.push(("x-amz-content-sha256".into(), signature.content_sha256));
                headers.push(("authorization".into(), signature.authorization));
            }
            None => headers.push(("authorization".into(), format!("Bearer {}", id.token))),
        }
        headers.push(("x-euclid-target".into(), self.target.clone()));
        headers.push(("x-euclid-action".into(), ACTION.into()));
        headers
    }

    fn handle_frame(&self, frame: &str) {
        let Ok(root) = serde_json::from_str::<Value>(frame) else {
            return;
        };
        let Some(kind) = text(&root, "type") else { return };

        match kind.as_str() {
            "subscribed" | "unsubscribed" => {
                let Some(id) = text(&root, "id") else { return };
                if let Some(ack) = lock(&self.pending_acks).remove(&id) {
                    let _ = ack.send(text(&root, "name"));
                }
            }
            "lag" => {
                let dropped = root.get("dropped").and_then(as_u64).unwrap_or(0);
                for listener in self.listeners_snapshot() {
                    listener.on_lag(dropped);
                }
                let _ = self.frames.send(StreamFrame::Lag { dropped });
            }
            "event" => {
                let (Some(topic), Some(body)) = (text(&root, "topic"), root.get("body")) else {
                    return;
                };
                // A durable subscription is told that something is waiting, not what it is.
                if text(body, "delivery").as_deref() == Some("notify") {
                    for listener in self.listeners_snapshot() {
                        listener.on_notify(&topic);
                    }
                    let _ = self.frames.send(StreamFrame::Notify { topic });
                    return;
                }
                for listener in self.listeners_snapshot() {
                    listener.on_event(&topic, body);
                }
                for waiter in lock(&self.waiters).iter_mut() {
                    if waiter.topic == topic && matches_filter(body, &waiter.filter) {
                        if let Some(done) = waiter.done.take() {
                            let _ = done.send(());
                        }
                    }
                }
                let _ = self.frames.send(StreamFrame::Event {
                    topic,
                    body: body.clone(),
                });
            }
            _ => {}
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.close();
    }
}

fn build_control_frame(
    kind: &str,
    id: &str,
    topic: Option<&str>,
    filter: &BTreeMap<String, String>,
    name: Option<&str>,
    mode: Option<DeliveryMode>,
) -> String {
    let mut frame = Map::new();
    frame.insert("type".into(), json!(kind));
    frame.insert("id".into(), json!(id));
    // Omitted rather than sent empty when attaching: a frame naming a subscription and no topic
    // says "send me what this one gets", while one carrying a topic redefines it.
    if let Some(topic) = topic {
        frame.insert("topic".into(), json!(topic));
        frame.insert("filter".into(), json!(filter));
    }
    if let Some(name) = name.filter(|n| !n.is_empty()) {
        frame.insert("name".into(), json!(name));
    }
    if let Some(mode) = mode {
        frame.insert("mode".into(), json!(mode.wire_value()));
    }
    Value::Object(frame).to_string()
}

fn websocket_url(base_url: &str) -> String {
    let url = if let Some(rest) = base_url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base_url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        base_url.to_owned()
    };
    format!("{url}/")
}

/// `host[:port]` as written in the base URL - what the WebSocket client puts in the Host header.
fn authority(base_url: &str) -> String {
    let rest = base_url.split_once("://").map_or(base_url, |(_, rest)| rest);
    let authority = rest.split('/').next().unwrap_or_default();
    authority.rsplit('@').next().unwrap_or_default().to_owned()
}

fn matches_filter(body: &Value, filter: &BTreeMap<String, String>) -> bool {
    filter.iter().all(|(key, expected)| match body.get(key) {
        None => false,
        Some(Value::String(s)) => s == expected,
        Some(other) => &other.to_string() == expected,
    })
}

fn to_filter(filter: &[(&str, &str)]) -> BTreeMap<String, String> {
    filter.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect()
}

fn text(node: &Value, field: &str) -> Option<String> {
    match node.get(field)? {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}

fn as_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_f64().map(|f| f as u64))
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
}

fn io_error(message: impl Into<String>) -> Error {
    Error::Io(std::io::Error::other(message.into()))
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

type Socket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
type Handshake = (Socket, tokio_tungstenite::tungstenite::handshake::client::Response);

/// Why a connection attempt failed: the TLS setup, or the handshake itself.
enum OpenError {
    Setup(Error),
    Handshake(tokio_tungstenite::tungstenite::Error),
}

impl OpenError {
    fn into_error(self, url: &str) -> Error {
        match self {
            OpenError::Setup(e) => e,
            OpenError::Handshake(e) => io_error(format!("failed to connect event stream to {url}: {e}")),
        }
    }
}

/// Opens the connection, for `wss://` with the system/webpki roots plus the session's extra CA
/// certificate - the same trust the HTTP client has.
#[cfg(any(feature = "native-tls", feature = "rustls-tls"))]
async fn open_socket(
    request: tokio_tungstenite::tungstenite::handshake::client::Request,
    ca_cert_path: Option<&std::path::Path>,
) -> std::result::Result<Handshake, OpenError> {
    let connector = tls_connector(ca_cert_path).map_err(OpenError::Setup)?;
    tokio_tungstenite::connect_async_tls_with_config(request, None, false, Some(connector))
        .await
        .map_err(OpenError::Handshake)
}

/// Without a TLS feature only `ws://` works.
#[cfg(not(any(feature = "native-tls", feature = "rustls-tls")))]
async fn open_socket(
    request: tokio_tungstenite::tungstenite::handshake::client::Request,
    _ca_cert_path: Option<&std::path::Path>,
) -> std::result::Result<Handshake, OpenError> {
    tokio_tungstenite::connect_async_with_config(request, None, false)
        .await
        .map_err(OpenError::Handshake)
}

#[cfg(feature = "native-tls")]
fn tls_connector(ca_cert_path: Option<&std::path::Path>) -> Result<tokio_tungstenite::Connector> {
    let mut builder = native_tls::TlsConnector::builder();
    if let Some(path) = ca_cert_path {
        let pem = std::fs::read(path)?;
        for block in pem_blocks(&pem) {
            let cert = native_tls::Certificate::from_pem(block.as_bytes())
                .map_err(|e| io_error(format!("invalid CA certificate {}: {e}", path.display())))?;
            builder.add_root_certificate(cert);
        }
    }
    let connector = builder
        .build()
        .map_err(|e| io_error(format!("TLS setup failed: {e}")))?;
    Ok(tokio_tungstenite::Connector::NativeTls(connector))
}

#[cfg(all(feature = "rustls-tls", not(feature = "native-tls")))]
fn tls_connector(ca_cert_path: Option<&std::path::Path>) -> Result<tokio_tungstenite::Connector> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::CertificateDer;

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = ca_cert_path {
        let pem = std::fs::read(path)?;
        for cert in CertificateDer::pem_slice_iter(&pem) {
            let cert = cert.map_err(|e| io_error(format!("invalid CA certificate {}: {e}", path.display())))?;
            roots
                .add(cert)
                .map_err(|e| io_error(format!("invalid CA certificate {}: {e}", path.display())))?;
        }
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| io_error(format!("TLS setup failed: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(tokio_tungstenite::Connector::Rustls(Arc::new(config)))
}

#[cfg(feature = "native-tls")]
fn pem_blocks(pem: &[u8]) -> Vec<String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let text = String::from_utf8_lossy(pem);
    let mut blocks = Vec::new();
    let mut rest = text.as_ref();
    while let Some(start) = rest.find(BEGIN) {
        let Some(end) = rest[start..].find(END) else { break };
        let end = start + end + END.len();
        blocks.push(rest[start..end].to_owned());
        rest = &rest[end..];
    }
    blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_frames_match_the_jdk() {
        let filter: BTreeMap<String, String> = [("queueErn".to_owned(), "q".to_owned())].into();
        let frame: Value =
            serde_json::from_str(&build_control_frame("subscribe", "1", Some("t"), &filter, None, None)).unwrap();
        assert_eq!(
            frame,
            json!({"type": "subscribe", "id": "1", "topic": "t", "filter": {"queueErn": "q"}})
        );

        let attach: Value = serde_json::from_str(&build_control_frame(
            "subscribe",
            "2",
            None,
            &BTreeMap::new(),
            Some("n"),
            Some(DeliveryMode::Live),
        ))
        .unwrap();
        assert_eq!(
            attach,
            json!({"type": "subscribe", "id": "2", "name": "n", "mode": "live"})
        );
    }

    #[test]
    fn urls_and_authority() {
        assert_eq!(websocket_url("https://h:5566"), "wss://h:5566/");
        assert_eq!(websocket_url("http://h"), "ws://h/");
        assert_eq!(authority("https://h:5566"), "h:5566");
        assert_eq!(authority("https://u@h/x"), "h");
    }

    #[test]
    fn filter_matches_as_text() {
        let body = json!({"a": "x", "n": 12, "b": true});
        let f = |pairs: &[(&str, &str)]| to_filter(pairs);
        assert!(matches_filter(&body, &f(&[("a", "x"), ("n", "12"), ("b", "true")])));
        assert!(!matches_filter(&body, &f(&[("a", "y")])));
        assert!(!matches_filter(&body, &f(&[("missing", "x")])));
    }
}
