//! Sync HTTP/1.1 client implementing [`libsignal_service::transport::HttpClient`].
//!
//! Uses [`crate::tls::tls_connect_with_config`] for TLS plus a
//! hand-rolled HTTP/1.1 request/response framing for the body. Avoids
//! pulling `ureq` (which bundles its own rustls and would conflict
//! with our `=0.22.2` pin) and `reqwest` (Tokio-coupled).
//!
//! # Sync-to-async bridge
//!
//! `HttpClient::execute` is async, but the underlying request runs on
//! a one-shot worker thread to keep the `smol-rs::LocalExecutor`
//! unblocked. The async future awaits a `oneshot`-shaped
//! [`async_channel`] that the worker posts to on completion.
//!
//! Cost is one OS thread + one channel per request. Acceptable for the
//! traffic shape libsignal-service-rs produces: prekey fetches,
//! attribute updates, profile lookups — single-digit requests per
//! user-visible action.
//!
//! # Connection lifecycle
//!
//! Each request opens a fresh TCP+TLS connection and sets
//! `Connection: close`. There is no connection pool. What survives
//! across requests is the shared [`Arc<ClientConfig>`] (built once by
//! [`SyncHttpClient::new`]), which keeps the rustls in-memory
//! session-ticket cache alive — so back-to-back requests to the same
//! Signal host resume the TLS session via PSK and skip the ECDHE
//! work.
//!
//! # Scope
//!
//! Only what Signal endpoints actually need: HTTP/1.1, no
//! `Transfer-Encoding: chunked`, no redirects (Signal-Server replies
//! 4xx/5xx for any redirect path the client should follow), no
//! cookies. Fixed-length response bodies parsed by reading to EOF
//! after the server closes.

use std::io::{Read, Write};
use std::sync::Arc;

use async_trait::async_trait;
use libsignal_service::transport::{
    BasicAuth, HeaderMap, HttpClient, HttpError, HttpRequest, HttpResponse, WebSocketChannels,
};
use rustls::{ClientConfig, RootCertStore};

use crate::tls::{build_tls_config, tls_connect_with_config};

/// Sync HTTP/1.1 client over a pinned-roots TLS configuration.
///
/// One-shot connection per request (`Connection: close`); no
/// connection pool. The shared `Arc<ClientConfig>` is reused across
/// every HTTP and WS connect from this client instance, which keeps
/// the rustls in-memory session-ticket cache alive and enables TLS
/// 1.3 PSK resumption on back-to-back reconnects.
///
/// `Clone` is NOT derived intentionally: callers that need to share
/// the client across threads should put it in an `Arc<>` themselves,
/// and the libsignal-service-rs convention is to install it as a
/// `thread_local!` on the worker thread (see
/// `xous-signal-worker::worker_main`).
pub struct SyncHttpClient {
    /// Shared rustls config built once via [`build_tls_config`] with
    /// the caller-supplied root store. Holds the session-ticket cache
    /// across all requests issued through this client.
    config: Arc<ClientConfig>,
    /// `User-Agent` header value sent on every request. Set by the
    /// worker to a fixed `xas/<version>` string at startup; not
    /// exposed for runtime mutation.
    user_agent: String,
    /// Default per-request timeout. Used for both the underlying TCP
    /// `set_read_timeout` and `set_write_timeout` if the
    /// per-`HttpRequest` value is `None`.
    timeout: std::time::Duration,
}

impl SyncHttpClient {
    /// Build a client. `roots` is the trust anchor set used for every
    /// connection from this client — must match the endpoint
    /// universe. Production xas wires this with
    /// [`crate::signal_production_roots`].
    ///
    /// `user_agent` is sent verbatim in the `User-Agent` header. It is
    /// metadata-class information visible to Signal-Server and any
    /// on-path observer; chosen by the calling worker (`xas/<version>`
    /// in production).
    pub fn new(roots: RootCertStore, user_agent: String) -> Self {
        // Both `execute` (HTTP/1.1) and `connect_websocket` (which upgrades
        // an HTTP/1.1 request) want ALPN "http/1.1", so a single shared
        // config covers all transport in this client.
        let config = build_tls_config(roots, &[b"http/1.1"]);
        Self { config, user_agent, timeout: std::time::Duration::from_secs(65) }
    }
}

/// The `?Send` bound matches `libsignal-service-rs`'s trait
/// definition. Tasks created by the upstream code may hold `!Send`
/// state (notably PDDB-backed store handles); the local executor in
/// the worker thread is what makes the `?Send` form workable.
#[async_trait(?Send)]
impl HttpClient for SyncHttpClient {
    /// Execute a single HTTP/1.1 request and return the response.
    ///
    /// Each call spawns a one-shot OS thread named
    /// `xous-net-bridge-http` that performs the synchronous TCP +
    /// TLS + write + read cycle and posts the result back through an
    /// `async_channel::bounded(1)` oneshot. The async future blocks on
    /// `rx.recv().await`.
    ///
    /// # rv32 / 16 MiB constraint
    ///
    /// Thread-per-request. The Signal worker runs single-digit HTTP
    /// requests per user action (link, profile fetch, prekey bundle
    /// fetch, credential refresh), so the spawn cost stays bounded by
    /// the worker's command rate. A flurry of inbound messages from N
    /// first-touch contacts produces N profile fetches and therefore
    /// N spawns; if that workload ever dominates, a fixed-size worker
    /// pool with a bounded queue would convert the unbounded behaviour
    /// into a documentable back-pressure point. A related cap on
    /// response body size and a heapless budgeting pass are possible
    /// follow-ups.
    ///
    /// # Timeouts
    ///
    /// `req.timeout` takes precedence; falls back to the client-level
    /// default (65 s) configured in [`SyncHttpClient::new`] if unset.
    ///
    /// # Errors
    ///
    /// - `HttpError::Network` for thread spawn failure, channel error, TLS connect failure, read/write IO
    ///   error.
    /// - `HttpError::Encode` if a header value is non-ASCII (Signal endpoints don't ship UTF-8 headers; this
    ///   is defensive).
    /// - `HttpError::InvalidUrl` for missing host.
    /// - `HttpError::Decode` for malformed response framing.
    ///
    /// # Logging
    ///
    /// Two `perf/net` lines per call: `http_req entry` (method, URL,
    /// request body length) and `http_req exit` (status, timings,
    /// response body length). The URL and method are metadata-class.
    /// Request and response bodies are NEVER logged; libsignal
    /// envelope bodies routed through this client carry Signal-Protocol
    /// ciphertext, but the path also carries plaintext registration
    /// metadata (ACI, prekey IDs, attribute payloads) so logging
    /// bodies would be a finding.
    async fn execute(&self, req: HttpRequest) -> Result<HttpResponse, HttpError> {
        let (tx, rx) = async_channel::bounded(1);
        let config = Arc::clone(&self.config);
        let user_agent = self.user_agent.clone();
        let timeout = req.timeout.unwrap_or(self.timeout);

        // Spawn a one-shot worker thread to run the sync HTTP exchange.
        // The async future blocks on `rx.recv().await` until the worker
        // completes.
        std::thread::Builder::new()
            .name("xous-net-bridge-http".into())
            .spawn(move || {
                let result = sync_execute(req, config, &user_agent, timeout);
                let _ = tx.send_blocking(result);
            })
            .map_err(|e| HttpError::Network(format!("thread spawn: {e}")))?;

        rx.recv().await.map_err(|_| HttpError::Network("HTTP worker thread died".to_string()))?
    }

    /// Open a WSS connection to `url` and return a
    /// [`WebSocketChannels`] pair the caller can use for
    /// bidirectional frame traffic.
    ///
    /// Delegates to [`crate::ws_pump`]; see that module for the
    /// thread-pool and frame-channel details. The `Arc<ClientConfig>`
    /// is cloned (cheap, refcount-only) so the resulting WS
    /// connection reuses the same trust roots and TLS session-ticket
    /// cache as the HTTP path.
    async fn connect_websocket(
        &self,
        url: url::Url,
        headers: HeaderMap,
        auth: Option<BasicAuth>,
    ) -> Result<WebSocketChannels, HttpError> {
        crate::ws_pump::connect_websocket(Arc::clone(&self.config), url, headers, auth).await
    }
}

/// Run a single HTTP/1.1 request/response cycle synchronously.
///
/// Called on the one-shot worker thread spawned by
/// [`HttpClient::execute`]. Builds the request bytes, drives TCP +
/// TLS + write + read-to-EOF, and parses the response via
/// [`parse_http_response`].
///
/// `_timeout` is applied to both `set_read_timeout` and
/// `set_write_timeout` on the underlying TCP socket. Both calls may
/// fail (Xous returns an error if the socket is in a state that does
/// not accept timeouts); those failures are logged and tolerated.
fn sync_execute(
    req: HttpRequest,
    config: Arc<ClientConfig>,
    user_agent: &str,
    _timeout: std::time::Duration,
) -> Result<HttpResponse, HttpError> {
    let _perf_start = std::time::Instant::now();
    let host =
        req.url.host_str().ok_or_else(|| HttpError::InvalidUrl("missing host".to_string()))?.to_string();
    let port = req.url.port_or_known_default().unwrap_or(443);
    let path = match req.url.query() {
        Some(q) => format!("{}?{}", req.url.path(), q),
        None => req.url.path().to_string(),
    };
    let _perf_method = req.method.as_str().to_string();
    let _perf_url = format!("{}", req.url);
    let _perf_body_len = req.body.as_deref().map(|b| b.len()).unwrap_or(0);
    tracing::info!(
        "perf/net: http_req entry method={} url={} body_len={}",
        _perf_method,
        _perf_url,
        _perf_body_len
    );

    let _perf_pre_tls = std::time::Instant::now();
    let mut stream = tls_connect_with_config(&host, port, config)
        .map_err(|e| HttpError::Network(format!("tls connect: {e}")))?;
    let _perf_tls_ms = _perf_pre_tls.elapsed().as_millis();
    // Per-request read timeout so a hung server can't block the
    // worker thread forever. `rustls::StreamOwned` exposes `.sock` as
    // the inner Read+Write TCP stream.
    if let Err(e) = stream.sock.set_read_timeout(Some(_timeout)) {
        tracing::debug!("could not set read timeout: {e}");
    }
    // Bound the writer's TCP retransmit budget; without this, a
    // server-initiated Close mid-write blocks ~89 s on hardware.
    // Defense-in-depth alongside the kernel-side socket-reaper fix.
    if let Err(e) = stream.sock.set_write_timeout(Some(_timeout)) {
        tracing::debug!("could not set write timeout: {e}");
    }

    // Construct the request bytes.
    let mut request = Vec::with_capacity(256);
    write!(request, "{} {} HTTP/1.1\r\n", req.method.as_str(), path)
        .map_err(|e| HttpError::Encode(e.to_string()))?;
    write!(request, "Host: {}\r\n", host).map_err(|e| HttpError::Encode(e.to_string()))?;
    write!(request, "User-Agent: {}\r\n", user_agent).map_err(|e| HttpError::Encode(e.to_string()))?;
    write!(request, "Connection: close\r\n").map_err(|e| HttpError::Encode(e.to_string()))?;
    write!(request, "Accept: */*\r\n").map_err(|e| HttpError::Encode(e.to_string()))?;

    if let Some(BasicAuth { username, password }) = req.auth {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let creds = format!("{username}:{password}");
        let encoded = STANDARD.encode(creds.as_bytes());
        write!(request, "Authorization: Basic {encoded}\r\n")
            .map_err(|e| HttpError::Encode(e.to_string()))?;
    }

    for (name, value) in &req.headers {
        let v = value.to_str().map_err(|_| HttpError::Encode("header value not ASCII".to_string()))?;
        write!(request, "{}: {}\r\n", name.as_str(), v).map_err(|e| HttpError::Encode(e.to_string()))?;
    }

    let body = req.body.as_deref().unwrap_or(&[]);
    write!(request, "Content-Length: {}\r\n", body.len()).map_err(|e| HttpError::Encode(e.to_string()))?;
    request.extend_from_slice(b"\r\n");
    request.extend_from_slice(body);

    let _perf_pre_write = std::time::Instant::now();
    stream.write_all(&request).map_err(|e| HttpError::Network(format!("write: {e}")))?;
    stream.flush().map_err(|e| HttpError::Network(format!("flush: {e}")))?;
    let _perf_write_ms = _perf_pre_write.elapsed().as_millis();

    // Read until EOF (since we sent Connection: close).
    let _perf_pre_read = std::time::Instant::now();
    let mut raw = Vec::with_capacity(4096);
    stream.read_to_end(&mut raw).map_err(|e| HttpError::Network(format!("read: {e}")))?;
    let _perf_read_ms = _perf_pre_read.elapsed().as_millis();

    let resp = parse_http_response(&raw);
    let (_perf_status, _perf_resp_body_len) = match &resp {
        Ok(r) => (r.status.as_u16(), r.body.len()),
        Err(_) => (0u16, 0usize),
    };
    tracing::info!(
        "perf/net: http_req exit method={} url={} req_body_len={} status={} resp_body_len={} tls_ms={} write_ms={} read_ms={} total_ms={}",
        _perf_method,
        _perf_url,
        _perf_body_len,
        _perf_status,
        _perf_resp_body_len,
        _perf_tls_ms,
        _perf_write_ms,
        _perf_read_ms,
        _perf_start.elapsed().as_millis()
    );
    resp
}

/// Parse a raw HTTP/1.1 response into [`HttpResponse`].
///
/// Handles `Content-Length`-bounded bodies and `Connection: close`-
/// terminated bodies (read-to-EOF). Does NOT handle
/// `Transfer-Encoding: chunked` — Signal-Server's chat endpoints are
/// fixed-length per request, so this is sufficient. A chunked response
/// would surface as either a [`HttpError::Decode`] (if the header
/// terminator isn't found) or a body with the literal hex-length
/// markers inline (if the upstream caller doesn't validate); both are
/// acceptable failure modes for an endpoint that should never produce
/// chunked output.
///
/// # Errors
///
/// - `HttpError::Decode` for missing header terminator, non-UTF-8 header bytes, missing status line / code,
///   or a status code that doesn't fit in `u16`.
fn parse_http_response(raw: &[u8]) -> Result<HttpResponse, HttpError> {
    let header_end =
        find_header_end(raw).ok_or_else(|| HttpError::Decode("no header terminator".to_string()))?;
    let header_block = &raw[..header_end];
    let body = raw[header_end + 4..].to_vec();

    let header_text =
        std::str::from_utf8(header_block).map_err(|_| HttpError::Decode("non-UTF-8 header".to_string()))?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().ok_or_else(|| HttpError::Decode("missing status line".to_string()))?;
    let mut status_parts = status_line.splitn(3, ' ');
    let _http_version = status_parts.next();
    let status_code = status_parts
        .next()
        .ok_or_else(|| HttpError::Decode("missing status code".to_string()))?
        .parse::<u16>()
        .map_err(|e| HttpError::Decode(e.to_string()))?;
    let status = http::StatusCode::from_u16(status_code).map_err(|e| HttpError::Decode(e.to_string()))?;

    let mut headers = HeaderMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(":") {
            if let (Ok(n), Ok(v)) =
                (http::HeaderName::try_from(name.trim()), http::HeaderValue::try_from(value.trim()))
            {
                headers.insert(n, v);
            }
        }
    }

    Ok(HttpResponse { status, headers, body })
}

/// Locate the offset of the `\r\n\r\n` terminator separating the
/// HTTP/1.1 header block from the body. Returns the offset of the
/// first byte of the terminator, or `None` if no terminator is
/// present.
fn find_header_end(raw: &[u8]) -> Option<usize> { raw.windows(4).position(|w| w == b"\r\n\r\n") }
