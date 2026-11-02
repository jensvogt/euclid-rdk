//! A handler called for every event a subscriber receives, without a poll loop (feature `ws`).
//! Port of euclid-jdk's `EuclidEventListener`.

use std::fmt::Display;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::future::BoxFuture;
use futures_util::FutureExt;
use serde_json::{Map, Value};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::model::{DeliveryMode, Event, SubscribeEventsRequest};
use super::stream::{EventStream, EventStreamListener, ListenerId};
use super::Ees;
use crate::{Error, Result};

/// How many events one claim asks for. The listener keeps claiming until a claim comes back empty.
const CLAIM_BATCH: u64 = 32;
/// How long [`EventListener::close`] lets running handlers finish before aborting them.
const CLOSE_GRACE: Duration = Duration::from_secs(5);

type Handler = Arc<dyn Fn(Event) -> BoxFuture<'static, std::result::Result<(), String>> + Send + Sync>;

enum Job {
    Drain,
    Dispatch(Event),
}

/// Calls a handler for every event a subscriber receives.
///
/// The durable half of the event stream put together: the subscription is registered through
/// [`Ees`], the stream is attached to its name, and when the gateway says something is waiting
/// the events are claimed, handed to the handler, and acknowledged. Nothing is acknowledged before
/// the handler returns `Ok`, so an application that dies mid-event gets it again rather than
/// losing it. A [`DeliveryMode::Live`] listener is the same shape without the store: pushed events
/// go straight to the handler, with nothing to acknowledge or catch up on.
///
/// Claiming runs on tasks of the listener's own, never on the stream's reading task, so a slow
/// handler delays this subscriber and nothing else. [`concurrency`](EventListenerBuilder::concurrency)
/// runs several such tasks; that is safe because the claim decides who handles an event.
///
/// ```no_run
/// # async fn run(session: euclid_rdk::Session) -> euclid_rdk::Result<()> {
/// use euclid_rdk::ees::{self, EventListener};
///
/// let ees = session.ees();
/// let listener = EventListener::builder()
///     .ees(ees.clone())
///     .stream(ees.event_stream())
///     .name("invoice-import")
///     .event_types(["esm.object.created"])
///     .filter(ees::filter([("bucketName", "inbox")]))
///     .handler(|event| async move {
///         println!("new object {:?}", event.esm_object().and_then(|o| o.key));
///         Ok::<_, std::convert::Infallible>(())
///     })
///     .build()?;
/// listener.start().await?;
/// // ... events arrive on the handler until the listener is closed
/// listener.close().await;
/// # Ok(())
/// # }
/// ```
pub struct EventListener {
    shared: Arc<Shared>,
    stream: EventStream,
    concurrency: usize,
    started: AtomicBool,
    hook: Mutex<Option<ListenerId>>,
    jobs: Mutex<Option<mpsc::UnboundedSender<Job>>>,
    workers: Mutex<Vec<JoinHandle<()>>>,
}

impl std::fmt::Debug for EventListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventListener")
            .field("name", &self.shared.name)
            .field("event_types", &self.shared.event_types)
            .field("mode", &self.shared.mode)
            .field("concurrency", &self.concurrency)
            .field("started", &self.started.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

struct Shared {
    ees: Ees,
    name: String,
    event_types: Vec<String>,
    filter: Map<String, Value>,
    mode: DeliveryMode,
    visibility_timeout: u64,
    handler: Handler,
}

/// Builds an [`EventListener`]; `ees`, `stream`, `name` and `handler` are required.
pub struct EventListenerBuilder {
    ees: Option<Ees>,
    stream: Option<EventStream>,
    name: String,
    event_types: Vec<String>,
    filter: Map<String, Value>,
    mode: DeliveryMode,
    concurrency: usize,
    visibility_timeout: u64,
    handler: Option<Handler>,
}

impl std::fmt::Debug for EventListenerBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventListenerBuilder")
            .field("name", &self.name)
            .field("event_types", &self.event_types)
            .field("mode", &self.mode)
            .field("concurrency", &self.concurrency)
            .finish_non_exhaustive()
    }
}

impl EventListener {
    pub fn builder() -> EventListenerBuilder {
        EventListenerBuilder {
            ees: None,
            stream: None,
            name: String::new(),
            event_types: Vec::new(),
            filter: Map::new(),
            mode: DeliveryMode::Durable,
            concurrency: 1,
            visibility_timeout: 300,
            handler: None,
        }
    }

    /// Registers the subscription, attaches the stream to it, and starts delivering. A durable
    /// listener first drains whatever is already waiting, so events that arrived while the
    /// application was down are handled at startup. Calling it again does nothing.
    pub async fn start(&self) -> Result<()> {
        if self.started.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let shared = &self.shared;
        shared
            .ees
            .subscribe_events_with(&SubscribeEventsRequest {
                name: shared.name.clone(),
                event_types: shared.event_types.clone(),
                filter: shared.filter.clone(),
                mode: Some(shared.mode),
            })
            .await?;

        let (sender, receiver) = mpsc::unbounded_channel();
        let receiver = Arc::new(tokio::sync::Mutex::new(receiver));
        {
            let mut workers = self.workers.lock().unwrap_or_else(|e| e.into_inner());
            for _ in 0..self.concurrency {
                let (shared, receiver) = (Arc::clone(&self.shared), Arc::clone(&receiver));
                workers.push(tokio::spawn(async move {
                    loop {
                        let job = receiver.lock().await.recv().await;
                        match job {
                            Some(Job::Drain) => shared.drain().await,
                            Some(Job::Dispatch(event)) => {
                                shared.dispatch(event).await;
                            }
                            None => return,
                        }
                    }
                }));
            }
        }

        let hook = Arc::new(Hook {
            jobs: sender.clone(),
            mode: shared.mode,
        });
        *self.hook.lock().unwrap_or_else(|e| e.into_inner()) = Some(self.stream.add_listener(hook));
        if shared.mode == DeliveryMode::Durable {
            for _ in 0..self.concurrency {
                let _ = sender.send(Job::Drain);
            }
        }
        *self.jobs.lock().unwrap_or_else(|e| e.into_inner()) = Some(sender);
        self.stream.attach(&shared.name).await
    }

    /// Detaches the stream and stops delivering, giving running handlers up to 5 s to finish.
    /// The subscription itself is left alone, so a durable one keeps collecting events for the
    /// next start - use [`Ees::unsubscribe_events`] to give that up.
    pub async fn close(&self) {
        if let Some(id) = self.hook.lock().unwrap_or_else(|e| e.into_inner()).take() {
            self.stream.remove_listener(id);
        }
        self.jobs.lock().unwrap_or_else(|e| e.into_inner()).take();
        let workers: Vec<_> = self
            .workers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
            .collect();
        for mut worker in workers {
            if tokio::time::timeout(CLOSE_GRACE, &mut worker).await.is_err() {
                worker.abort();
            }
        }
        if self.started.load(Ordering::SeqCst) {
            // The gateway drops the attachment when the connection closes anyway.
            let _ = self.stream.detach(&self.shared.name).await;
        }
    }
}

impl Drop for EventListener {
    fn drop(&mut self) {
        if let Some(id) = self.hook.lock().unwrap_or_else(|e| e.into_inner()).take() {
            self.stream.remove_listener(id);
        }
        for worker in self.workers.lock().unwrap_or_else(|e| e.into_inner()).drain(..) {
            worker.abort();
        }
    }
}

impl Shared {
    /// Claims and handles everything waiting, in batches, until a claim comes back empty. A failed
    /// claim is left for the next notification: the events are still stored.
    async fn drain(&self) {
        loop {
            let Ok(claimed) = self
                .ees
                .receive_events_with(&self.name, CLAIM_BATCH, 0, self.visibility_timeout)
                .await
            else {
                return;
            };
            if claimed.events.is_empty() {
                return;
            }
            let mut handled = Vec::with_capacity(claimed.events.len());
            for event in claimed.events {
                let id = event.event_id.clone();
                if self.dispatch(event).await {
                    handled.extend(id);
                }
            }
            // Only what the handler got through is acknowledged; the rest comes back when its
            // visibility timeout runs out.
            if !handled.is_empty() && self.ees.ack_events(&self.name, &handled).await.is_err() {
                return;
            }
        }
    }

    /// Runs the handler; `false` if it returned an error or panicked.
    async fn dispatch(&self, event: Event) -> bool {
        matches!(AssertUnwindSafe((self.handler)(event)).catch_unwind().await, Ok(Ok(())))
    }
}

/// What the stream calls; turns frames into jobs for the listener's own tasks.
struct Hook {
    jobs: mpsc::UnboundedSender<Job>,
    mode: DeliveryMode,
}

impl EventStreamListener for Hook {
    fn on_event(&self, topic: &str, body: &Value) {
        if self.mode != DeliveryMode::Live {
            return;
        }
        // For a live subscription this frame is the event, and the only copy there will be.
        let event = Event {
            event_type: Some(topic.to_owned()),
            payload: body.as_object().cloned().unwrap_or_default(),
            ..Default::default()
        };
        let _ = self.jobs.send(Job::Dispatch(event));
    }

    fn on_notify(&self, _topic: &str) {
        let _ = self.jobs.send(Job::Drain);
    }

    fn on_lag(&self, _dropped: u64) {
        // The events the gateway could not push are still stored: go and get them.
        if self.mode == DeliveryMode::Durable {
            let _ = self.jobs.send(Job::Drain);
        }
    }
}

impl EventListenerBuilder {
    /// The client used to register the subscription and claim its events.
    pub fn ees(mut self, ees: Ees) -> Self {
        self.ees = Some(ees);
        self
    }

    /// The connection to attach to; one stream can carry several listeners.
    pub fn stream(mut self, stream: EventStream) -> Self {
        self.stream = Some(stream);
        self
    }

    /// The subscriber name. Instances of one application share it, so each event is handled by
    /// exactly one of them.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// The event types to receive, e.g. `["esm.object.created"]`.
    pub fn event_types<I, S>(mut self, event_types: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.event_types = event_types.into_iter().map(Into::into).collect();
        self
    }

    /// The payload filter, evaluated where the event is published (see [`super::filter`]).
    pub fn filter(mut self, filter: Map<String, Value>) -> Self {
        self.filter = filter;
        self
    }

    /// The delivery mode. Defaults to [`DeliveryMode::Durable`].
    pub fn mode(mut self, mode: DeliveryMode) -> Self {
        self.mode = mode;
        self
    }

    /// How many tasks independently claim and dispatch at once (at least one). Raise it when
    /// publishing outruns what one task drains.
    pub fn concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency.max(1);
        self
    }

    /// How long, in seconds, a claimed event stays hidden from other claims while the handler
    /// works on it. Defaults to 300 (the server's default); an event whose handler fails comes
    /// back after it.
    pub fn visibility_timeout(mut self, seconds: u64) -> Self {
        self.visibility_timeout = seconds;
        self
    }

    /// The async handler called for each event. Returning `Err` (or panicking) leaves the event
    /// unacknowledged, so it is delivered again.
    pub fn handler<F, Fut, E>(mut self, handler: F) -> Self
    where
        F: Fn(Event) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = std::result::Result<(), E>> + Send + 'static,
        E: Display,
    {
        let handler = Arc::new(handler);
        self.handler = Some(Arc::new(move |event| {
            let handler = Arc::clone(&handler);
            async move { handler(event).await.map_err(|e| e.to_string()) }.boxed()
        }));
        self
    }

    /// Builds the listener, not yet started.
    pub fn build(self) -> Result<EventListener> {
        let (Some(ees), Some(stream), Some(handler)) = (self.ees, self.stream, self.handler) else {
            return Err(Error::invalid("ees, stream, name and handler are required"));
        };
        if self.name.is_empty() {
            return Err(Error::invalid("ees, stream, name and handler are required"));
        }
        Ok(EventListener {
            shared: Arc::new(Shared {
                ees,
                name: self.name,
                event_types: self.event_types,
                filter: self.filter,
                mode: self.mode,
                visibility_timeout: self.visibility_timeout,
                handler,
            }),
            stream,
            concurrency: self.concurrency,
            started: AtomicBool::new(false),
            hook: Mutex::new(None),
            jobs: Mutex::new(None),
            workers: Mutex::new(Vec::new()),
        })
    }
}
