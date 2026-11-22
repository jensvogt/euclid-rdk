//! Catches the one request a browser brings back at the end of a federated login, on a port this
//! process owns for the length of that login - the equivalent of euclid-cli's `CallbackListener`
//! and euclid-jdk's `LoopbackCallbackListener`.
//!
//! A loopback listener rather than a URL on the euclid gateway because a program logging somebody
//! in from their own machine is a public client: it has no secret to identify itself with, so what
//! the provider hands back has to come back to the machine that asked for it, and `127.0.0.1` is
//! the one address nothing else can reach. The port is whatever the kernel hands out - providers
//! expect a native client to register a wildcard loopback URI for exactly this reason.
//!
//! Two things can arrive, and both are taken: an OpenID Connect provider redirects back with
//! `code` and `state` in the query, and euclid's SAML assertion consumer posts the finished
//! session as a form field named `session` - base64url-encoded JSON, in a body rather than a URL so
//! the token never sits in a browser history entry. Either may instead carry the provider's
//! `error`. Anything else - a browser asking for a favicon, most often - is answered with a 404 and
//! does not end the wait, so one stray request cannot consume the login.

use std::collections::HashMap;
use std::future::poll_fn;
use std::io;
use std::net::Ipv4Addr;
use std::task::Poll;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The page the browser is left on once the callback has been taken. Says where to go next,
/// because the person reading it is about to wonder why a terminal or an application asked them to
/// sign in.
const CALLBACK_PAGE: &str =
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>euclid</title></head>\
<body style=\"font-family:sans-serif;padding:3rem\"><h1>Signed in</h1>\
<p>You can close this tab and go back to the application.</p></body></html>";

/// The most a request line and headers may take; a callback is a few hundred bytes.
const MAX_HEAD: usize = 16 * 1024;

/// The most a form body may take; a SAML hand-off carries one login response.
const MAX_BODY: usize = 1024 * 1024;

/// What the browser brought back.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Callback {
    /// The OIDC authorization code.
    pub code: Option<String>,
    /// The OIDC state, exactly as it arrived.
    pub state: Option<String>,
    /// The SAML hand-off's decoded login response JSON.
    pub session: Option<String>,
    /// The provider's refusal (with its description, when it gave one), or a reason the hand-off
    /// could not be read.
    pub error: Option<String>,
}

/// A listener bound to `127.0.0.1` on a kernel-chosen port. Requests are only served while
/// [`wait`](Self::wait) runs; a browser arriving earlier waits in the kernel's accept queue.
#[derive(Debug)]
pub(crate) struct LoopbackListener {
    listener: TcpListener,
    port: u16,
}

impl LoopbackListener {
    /// Binds the listener. Bound before anything is asked of the server, because the redirect URI
    /// has to name the port the listener ended up on.
    pub async fn bind() -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        Ok(Self { listener, port })
    }

    /// The URL to hand out as the place to come back to: `http://127.0.0.1:<port>/callback`.
    pub fn callback_url(&self) -> String {
        format!("http://127.0.0.1:{}/callback", self.port)
    }

    /// Serves requests until one carries a callback, or `timeout` passes (`Ok(None)`).
    ///
    /// Connections are served concurrently, so a browser that opens a speculative connection and
    /// sends nothing on it cannot hold up the one that carries the callback.
    pub async fn wait(&self, timeout: Duration) -> io::Result<Option<Callback>> {
        match tokio::time::timeout(timeout, self.serve()).await {
            Ok(result) => result.map(Some),
            Err(_) => Ok(None),
        }
    }

    async fn serve(&self) -> io::Result<Callback> {
        enum Event {
            Accepted(io::Result<(TcpStream, std::net::SocketAddr)>),
            Handled(Option<Callback>),
        }

        let mut connections = FuturesUnordered::new();
        loop {
            let event = poll_fn(|cx| {
                if let Poll::Ready(Some(handled)) = connections.poll_next_unpin(cx) {
                    return Poll::Ready(Event::Handled(handled));
                }
                self.listener.poll_accept(cx).map(Event::Accepted)
            })
            .await;
            match event {
                Event::Handled(Some(callback)) => return Ok(callback),
                Event::Handled(None) => {}
                Event::Accepted(Ok((stream, _))) => connections.push(handle(stream)),
                Event::Accepted(Err(e)) => return Err(e),
            }
        }
    }
}

/// Answers one connection from the browser: the callback, if it carried one.
async fn handle(mut stream: TcpStream) -> Option<Callback> {
    let (method, target, body) = read_request(&mut stream).await?;

    let query = target.split_once('?').map(|(_, q)| q).unwrap_or_default();
    let mut parameters = parse_form(query);
    // The SAML hand-off is a form post from the page euclid answered the assertion with.
    if method.eq_ignore_ascii_case("POST") {
        parameters.extend(parse_form(&String::from_utf8_lossy(&body)));
    }

    let has_code = parameters.contains_key("code");
    let has_session = parameters.contains_key("session");
    let has_error = parameters.contains_key("error");
    if !has_code && !has_session && !has_error {
        let _ = stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        let _ = stream.shutdown().await;
        return None;
    }

    let mut session = None;
    let mut error = None;
    if let Some(encoded) = parameters.get("session") {
        match URL_SAFE_NO_PAD.decode(encoded.trim_end_matches('=')) {
            Ok(bytes) => session = Some(String::from_utf8_lossy(&bytes).into_owned()),
            Err(e) => error = Some(format!("the session euclid sent back could not be read: {e}")),
        }
    }
    if let Some(refusal) = parameters.get("error") {
        error = Some(match parameters.get("error_description") {
            Some(description) => format!("{refusal} ({description})"),
            None => refusal.clone(),
        });
    }

    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        CALLBACK_PAGE.len()
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(CALLBACK_PAGE.as_bytes()).await;
    let _ = stream.shutdown().await;

    Some(Callback {
        code: parameters.remove("code"),
        state: parameters.remove("state"),
        session,
        error,
    })
}

/// Reads one HTTP/1.1 request: its method, its target and its body. `None` for anything that is
/// not a readable request - a connection closed early, or one that sends far more than a callback
/// would.
async fn read_request(stream: &mut TcpStream) -> Option<(String, String, Vec<u8>)> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(position) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break position;
        }
        if buffer.len() > MAX_HEAD {
            return None;
        }
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    };

    let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next()?.split_whitespace();
    let method = request_line.next()?.to_owned();
    let target = request_line.next()?.to_owned();
    let content_length = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    if content_length > MAX_BODY {
        return None;
    }

    let mut body = buffer.split_off(head_end + 4);
    while body.len() < content_length {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);
    Some((method, target, body))
}

/// Parses a query string or form body - the two are the same encoding. The first occurrence of a
/// name wins.
fn parse_form(encoded: &str) -> HashMap<String, String> {
    let mut parameters = HashMap::new();
    for pair in encoded.split('&').filter(|p| !p.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        parameters
            .entry(percent_decode(name))
            .or_insert_with(|| percent_decode(value));
    }
    parameters
}

/// Decodes `application/x-www-form-urlencoded` text: `+` is a space, `%XX` a byte. A `%` not
/// followed by two hex digits is kept as it is.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' => match (bytes.get(i + 1).and_then(hex), bytes.get(i + 2).and_then(hex)) {
                (Some(high), Some(low)) => {
                    out.push(high << 4 | low);
                    i += 2;
                }
                _ => out.push(b'%'),
            },
            other => out.push(other),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(byte: &u8) -> Option<u8> {
    (*byte as char).to_digit(16).map(|d| d as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_decoding_handles_plus_percent_and_repeats() {
        let parsed = parse_form("error=access_denied&error_description=not+for%20you&error=second&flag");
        assert_eq!(parsed["error"], "access_denied");
        assert_eq!(parsed["error_description"], "not for you");
        assert_eq!(parsed["flag"], "");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz%41"), "%zzA");
    }
}
