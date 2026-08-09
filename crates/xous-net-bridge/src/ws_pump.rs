//! Production WSS bridge: sync tungstenite, async-channel-facing.
//!
//! The async-side caller (`libsignal-service-rs`'s
//! `SignalWebSocketProcess::run`) receives a [`WebSocketChannels`]
//! pair — one [`async_channel::Sender`] for outbound frames, one
//! [`async_channel::Receiver`] for inbound frames. Internally, a pool
//! of OS threads owns a sync [`tungstenite::WebSocket`] and bridges
//! frames in both directions.
//!
//! # Thread layout
//!
//! Three threads per WSS:
//!
//! - **setup thread** (`xous-net-bridge-ws-setup`): owns the TLS + tungstenite handshake. On success, wraps
//!   the resulting `WebSocket<RustlsStream>` in `Arc<Mutex<_>>` and spawns the reader and writer. Holds no
//!   state after that — its only role post-spawn is to `join` the children and close the inbound channel.
//! - **reader thread** (`xous-net-bridge-ws-reader`): acquires the mutex, calls `WebSocket::read()`, releases
//!   the mutex, forwards each frame into the incoming channel. The TCP read timeout (5 s, set in
//!   [`crate::tls::tls_connect_with_config`]) gives the writer a window to acquire the mutex on idle WSes.
//! - **writer thread** (`xous-net-bridge-ws-writer`): acquires the mutex, calls `WebSocket::send()`, releases
//!   the mutex.
//!
//! Single-threaded designs deadlock on `WebSocket::read()`: that call
//! blocks the calling thread until a frame arrives, so a single
//! thread cannot service outgoing frames while waiting. The
//! `Mutex<WebSocket>` + short-read-timeout pattern is the smallest
//! abstraction over sync tungstenite that supports bidirectional
//! traffic.
//!
//! # Why no async WSS library
//!
//! No async WSS+rustls stack works on Xous today. `tokio-tungstenite`
//! requires Tokio's IO drivers; `async-tungstenite`'s smol backend
//! still depends on `polling`, which itself needs epoll-class
//! primitives the Xous net service does not currently expose. Sync
//! tungstenite plus thread-per-direction is the pragmatic alternative
//! for the v0.x line.
//!
//! # rv32 / 16 MiB constraint
//!
//! Three OS threads per WSS is not cheap — each Xous thread reserves
//! stack pages eagerly. The Signal worker holds at most one identified
//! WS plus one unidentified WS plus a small number of HTTPS requests
//! in flight, so peak thread count stays well under double digits.
//! Combined with the worker thread itself (single
//! `xous_signal_worker::run_signal_worker` thread holding the
//! `LocalExecutor`), peak concurrent threads in the worker process at
//! a typical xas session run ≈ 7 (1 worker + 3 × 2 WSS pumps).
//!
//! # Logging surface
//!
//! Both worker loops emit `tracing` lines on every frame:
//!
//! - `ws reader: recv frame frame_count=... kind=... payload_len=...`
//! - `ws writer: send ok|send failed ...`
//! - `perf/net: ws recv|send kind=... payload_len=... read_ms|send_ms=...`
//!
//! `payload_len` is the encrypted-on-the-wire length (not plaintext).
//! `kind` is the WS frame type (`Binary`, `Text`, `Ping`, `Pong`,
//! `Close`). No frame contents, no auth headers, no negotiated PSK
//! material is ever logged. Safe to ship to UART.
//!
//! # Trust boundary
//!
//! Outbound frames arrive on `out_rx` already serialized by
//! libsignal-service-rs into `WebSocketMessage` protobuf — they are
//! the *plaintext-on-application-side, ciphertext-on-the-wire* bytes.
//! Signal Protocol encryption (Double Ratchet) and sealed-sender
//! framing happen one layer up, before bytes reach this module.
//!
//! Inbound frames flow the other way: TLS-decrypted on the wire side
//! (by rustls), forwarded verbatim into `in_tx`. Authentication of
//! Signal messages and per-envelope decryption happen in
//! `libsignal-service-rs` and `signalapp/libsignal` further up.

use std::sync::{Arc, Mutex};

use libsignal_service::transport::{BasicAuth, HeaderMap, HttpError, WebSocketChannels, WsFrame};
use rustls::ClientConfig;
use tungstenite::client::IntoClientRequest;
use tungstenite::protocol::{CloseFrame, Message, WebSocket};

use crate::tls::{RustlsStream, tls_connect_with_config};

/// Bounded capacity of the frame channels between the async caller and
/// the sync reader/writer threads.
///
/// 16 frames is a balance between memory cost on rv32 (each frame is a
/// `WsFrame` enum holding a `Vec<u8>` of WS payload bytes) and the
/// observed `SignalWebSocketProcess::run` traffic patterns
/// (back-to-back send bursts during link, infrequent idle reads
/// otherwise).
const FRAME_CHANNEL_CAPACITY: usize = 16;

/// Establish a WSS connection and return a [`WebSocketChannels`] pair
/// the async caller can use for bidirectional frame traffic.
///
/// Used by [`crate::http::SyncHttpClient::connect_websocket`] as the
/// implementation of [`libsignal_service::transport::HttpClient::connect_websocket`].
/// The returned channel pair is what
/// `libsignal-service-rs::SignalWebSocketProcess::run` polls — the
/// async-side caller never touches the underlying `Mutex<WebSocket>`
/// or the reader/writer threads. The Signal worker
/// (`xous_signal_worker::manager_task`) does not own this socket
/// directly; it interacts with libsignal-service-rs, which interacts
/// with the channel pair returned here.
///
/// # Pipeline
///
/// 1. Spawn the setup thread, which drives the TLS handshake via [`crate::tls::tls_connect_with_config`] and
///    then the tungstenite HTTP/1.1 upgrade with `headers` and (optional) `auth`.
/// 2. On handshake success, the setup thread wraps the `WebSocket` in `Arc<Mutex<_>>`, spawns the reader and
///    writer threads, and signals success on `handshake_done_rx`.
/// 3. This `async fn` resumes, returns the [`WebSocketChannels`] pair to the caller, and returns.
/// 4. The reader and writer threads run until the WS closes, the socket errors, the mutex is poisoned, or
///    `in_tx` / `out_rx` closes. On exit, the setup thread joins both and drops `in_tx`, which the async
///    executor sees as channel-closed.
///
/// # Errors
///
/// - `HttpError::Network` if the setup thread fails to spawn or dies before the handshake completes.
/// - Any error from [`handshake`] (TLS connect, tungstenite upgrade) propagates through the
///   `handshake_done_rx` channel and is returned here.
///
/// # Auth
///
/// `auth` is encoded as an HTTP `Authorization: Basic <b64(user:pass)>`
/// header and merged with `headers`. Same algorithm tungstenite would
/// use natively; we do it here so the credentials live with the
/// per-connection headers rather than the URL.
///
/// `password` is the post-link Signal-server credential, not a
/// long-lived account secret. It is transmitted over TLS and is the
/// same value `libsignal-service-rs` would have sent via reqwest;
/// stripping it from logs is the caller's responsibility (none of the
/// tracing lines in this module emit headers).
pub(crate) async fn connect_websocket(
    config: Arc<ClientConfig>,
    url: url::Url,
    headers: HeaderMap,
    auth: Option<BasicAuth>,
) -> Result<WebSocketChannels, HttpError> {
    let (handshake_done_tx, handshake_done_rx) = async_channel::bounded(1);
    let (out_tx, out_rx) = async_channel::bounded::<WsFrame>(FRAME_CHANNEL_CAPACITY);
    let (in_tx, in_rx) = async_channel::bounded::<Result<WsFrame, HttpError>>(FRAME_CHANNEL_CAPACITY);

    // Reader/writer worker threads (spawned only after a successful
    // handshake; the handshake itself runs on a dedicated setup thread).
    std::thread::Builder::new()
        .name("xous-net-bridge-ws-setup".into())
        .spawn(move || {
            let ws = match handshake(config, url, headers, auth) {
                Ok(ws) => ws,
                Err(e) => {
                    let _ = handshake_done_tx.send_blocking(Err(e));
                    return;
                }
            };
            // Wrap the WS in an Arc<Mutex<>> so reader and writer threads
            // can share it. tungstenite's WebSocket<S> isn't Sync, but we
            // serialize all access through the Mutex.
            let ws = Arc::new(Mutex::new(ws));
            let _ = handshake_done_tx.send_blocking(Ok(()));

            // Reader thread: pull frames off the WS, push to in_tx.
            let reader_ws = Arc::clone(&ws);
            let reader_tx = in_tx.clone();
            let reader = std::thread::Builder::new()
                .name("xous-net-bridge-ws-reader".into())
                .spawn(move || reader_loop(reader_ws, reader_tx))
                .expect("ws reader thread spawn");

            // Writer thread: pull frames off out_rx, push to the WS.
            let writer_ws = Arc::clone(&ws);
            let writer = std::thread::Builder::new()
                .name("xous-net-bridge-ws-writer".into())
                .spawn(move || writer_loop(writer_ws, out_rx))
                .expect("ws writer thread spawn");

            // Wait for both to finish; once either ends (channel closed,
            // remote close, etc.), drop everything.
            let _ = reader.join();
            let _ = writer.join();
            // Drop in_tx so the executor sees the channel close.
            drop(in_tx);
        })
        .map_err(|e| HttpError::Network(format!("ws setup thread spawn: {e}")))?;

    // Wait for the handshake to complete before returning.
    handshake_done_rx.recv().await.map_err(|_| HttpError::Network("ws setup thread died".to_string()))??;

    Ok(WebSocketChannels { outgoing: out_tx, incoming: in_rx })
}

/// Drive the TLS handshake then the tungstenite WSS upgrade.
///
/// Runs on the setup thread, off the async executor. Returns the
/// handshake-complete [`WebSocket`]; the caller then wraps it in
/// `Arc<Mutex<_>>` and hands it to the reader/writer pair.
///
/// `headers` are passed through verbatim; `auth` is encoded as `Basic`
/// and inserted as an `Authorization` header (see
/// [`connect_websocket`] for the security note on this).
///
/// # Errors
///
/// - `HttpError::InvalidUrl` if `url` lacks a host.
/// - `HttpError::Network` for any TLS or tungstenite handshake failure. The display of the inner error is
///   included; rustls and tungstenite error strings contain peer hostname, error category, and (on cert
///   verification) certificate subject — no secret material — so the message is safe to log.
fn handshake(
    config: Arc<ClientConfig>,
    url: url::Url,
    headers: HeaderMap,
    auth: Option<BasicAuth>,
) -> Result<WebSocket<RustlsStream>, HttpError> {
    let host = url.host_str().ok_or_else(|| HttpError::InvalidUrl("missing host".to_string()))?.to_string();
    let port = url.port_or_known_default().unwrap_or(443);

    let stream = tls_connect_with_config(&host, port, config)
        .map_err(|e| HttpError::Network(format!("tls connect: {e}")))?;

    // Build a tungstenite ClientRequest; merge in headers/auth.
    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|e| HttpError::Network(format!("ws client_request: {e}")))?;
    let req_headers = request.headers_mut();
    for (name, value) in &headers {
        req_headers.insert(name, value.clone());
    }
    if let Some(BasicAuth { username, password }) = auth {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let encoded = STANDARD.encode(format!("{username}:{password}").as_bytes());
        if let Ok(v) = http::HeaderValue::try_from(format!("Basic {encoded}")) {
            req_headers.insert(http::header::AUTHORIZATION, v);
        }
    }

    let (ws, _resp) =
        tungstenite::client(request, stream).map_err(|e| HttpError::Network(format!("ws handshake: {e}")))?;
    Ok(ws)
}

/// Reader thread body. Owns half of the shared mutex; pulls frames
/// off the WS and forwards them on `tx`.
///
/// Terminates on any of:
///
/// - `Message::Close` from the peer (forwards a `WsFrame::Close` to the caller before exiting).
/// - `tungstenite::Error::ConnectionClosed` / `AlreadyClosed`.
/// - Mutex poisoning (another thread panicked while holding it).
/// - `tx.send_blocking` returning `Err` (the async caller dropped its receiver mid-frame).
/// - `tx.is_closed()` observed at an idle read-timeout tick (the async caller dropped its receiver while no
///   frame was in flight): the teardown checkpoint that stops an abandoned *idle* WS from leaking this thread
///   + the socket. See the WouldBlock/TimedOut arm below.
/// - Any tungstenite read error other than the WouldBlock / TimedOut pair; those two are otherwise absorbed
///   as keepalive yield points (they are the writer's window to acquire the mutex on an idle socket).
///
/// Note this covers the reader/inbound half. The writer thread exits
/// when its `out_rx` closes; a caller that drops `incoming` while
/// holding `outgoing` open is not a shape libsignal-service-rs
/// produces (it drops the `WebSocketChannels` pair together), and the
/// symmetric writer-side shutdown belongs to the deferred ws_pump
/// lifecycle work (issue #39: shared shutdown flag / WsStats).
///
/// Each frame is logged on the `ws reader:` and `perf/net:` channels;
/// see the module-level docs for what's in those lines.
fn reader_loop(
    ws: Arc<Mutex<WebSocket<RustlsStream>>>,
    tx: async_channel::Sender<Result<WsFrame, HttpError>>,
) {
    // Count every frame the reader gets off the wire. Combined with
    // the writer-side counter this lets a trace correlate keepalive
    // responses to outbound keepalive requests.
    let mut frame_count: u64 = 0;
    loop {
        // Pull one message from the WS. read() blocks on the underlying
        // TCP, which has a short SO_RCVTIMEO set in `tls_connect`.
        // When no inbound frame arrives within the timeout, read()
        // returns `WouldBlock`/`TimedOut`; we drop the mutex, briefly
        // letting the writer thread acquire it (so periodic
        // libsignal-service-rs keepalives can actually go out), then
        // re-loop.
        let _perf_read_start = std::time::Instant::now();
        let msg = {
            let mut guard = match ws.lock() {
                Ok(g) => g,
                Err(_) => {
                    tracing::warn!(frame_count, "ws reader: mutex poisoned, exiting");
                    break;
                }
            };
            guard.read()
        };
        let _perf_read_ms = _perf_read_start.elapsed().as_millis();

        let (kind, payload_len, frame) = match msg {
            Ok(Message::Binary(b)) => {
                let len = b.len();
                ("Binary", len, Ok(WsFrame::Binary(b)))
            }
            Ok(Message::Text(s)) => {
                let len = s.len();
                ("Text", len, Ok(WsFrame::Text(s)))
            }
            Ok(Message::Ping(b)) => {
                let len = b.len();
                ("Ping", len, Ok(WsFrame::Ping(b)))
            }
            Ok(Message::Pong(b)) => {
                let len = b.len();
                ("Pong", len, Ok(WsFrame::Pong(b)))
            }
            Ok(Message::Close(frame)) => {
                let (code, reason) = match frame {
                    Some(CloseFrame { code, reason }) => (code.into(), reason.into_owned()),
                    None => (1005, String::new()),
                };
                frame_count += 1;
                tracing::info!(frame_count, kind = "Close", code, "ws reader: recv frame, exiting",);
                let _ = tx.send_blocking(Ok(WsFrame::Close { code, reason }));
                break;
            }
            Ok(Message::Frame(_)) => continue, // raw control frame; ignore
            Err(tungstenite::Error::ConnectionClosed) => {
                tracing::info!(frame_count, "ws reader: ConnectionClosed, exiting");
                break;
            }
            Err(tungstenite::Error::AlreadyClosed) => {
                tracing::info!(frame_count, "ws reader: AlreadyClosed, exiting");
                break;
            }
            // Read timed out with nothing to read. Yield and re-loop —
            // see the keepalive comment above.
            Err(tungstenite::Error::Io(e))
                if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) =>
            {
                // The idle timeout doubles as the teardown checkpoint:
                // if the async caller dropped its receiver, no frame
                // could ever be delivered again — exit instead of
                // pumping an abandoned socket forever. Without this
                // check the reader only notices the dropped receiver
                // when a frame actually arrives, which on a quiet WS
                // is never: 3 threads + a socket + the WS mutex linger
                // per abandoned connection on a 16 MiB device.
                if tx.is_closed() {
                    tracing::info!(frame_count, "ws reader: receiver dropped, exiting");
                    break;
                }
                // Brief sleep to avoid pegging the CPU between timeouts;
                // also gives the writer thread a clear window to acquire
                // the mutex.
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
            Err(e) => {
                let s = format!("{e}");
                tracing::warn!(frame_count, error = %s, "ws reader: read err, forwarding");
                ("Err", 0, Err(HttpError::Network(format!("ws read: {s}"))))
            }
        };

        // Successful (or err-as-frame) reception: bump and log.
        frame_count += 1;
        tracing::info!(frame_count, kind, payload_len, "ws reader: recv frame");
        tracing::info!(
            "perf/net: ws recv kind={} payload_len={} read_ms={}",
            kind,
            payload_len,
            _perf_read_ms
        );

        if tx.send_blocking(frame).is_err() {
            // Receiver dropped; close the connection.
            tracing::warn!(frame_count, "ws reader: tx send_blocking failed (receiver gone), exiting");
            break;
        }
    }
    tracing::info!(frame_count, "ws reader: loop exited");
}

/// Writer thread body. Owns the other half of the shared mutex; pulls
/// frames off `rx` and sends them on the WS.
///
/// Terminates on any of:
///
/// - `rx` closing (the async caller dropped its sender — typically because `SignalWebSocketProcess::run`
///   exited).
/// - Mutex poisoning.
/// - A `WebSocket::send` error. The error is logged with `write_timed_out` separated out so traces can
///   distinguish the OS-level write-timeout firing on the inner TCP socket (the defense-in-depth bound set by
///   [`crate::tls::tls_connect_with_config`]) from a protocol-level tungstenite error.
///
/// Each enqueued and each emitted frame is logged on the
/// `ws writer:` and `perf/net:` channels.
fn writer_loop(ws: Arc<Mutex<WebSocket<RustlsStream>>>, rx: async_channel::Receiver<WsFrame>) {
    // Count outgoing frames. Combined with the reader counter, this
    // tells a trace whether queued keepalives are actually leaving the
    // host or merely being enqueued.
    let mut frame_count: u64 = 0;
    while let Ok(frame) = rx.recv_blocking() {
        frame_count += 1;
        let (kind, payload_len) = match &frame {
            WsFrame::Binary(b) => ("Binary", b.len()),
            WsFrame::Text(s) => ("Text", s.len()),
            WsFrame::Ping(b) => ("Ping", b.len()),
            WsFrame::Pong(b) => ("Pong", b.len()),
            WsFrame::Close { .. } => ("Close", 0),
        };
        tracing::info!(frame_count, kind, payload_len, "ws writer: dequeued frame");

        let msg = match frame {
            WsFrame::Binary(b) => Message::Binary(b),
            WsFrame::Text(s) => Message::Text(s),
            WsFrame::Ping(b) => Message::Ping(b),
            WsFrame::Pong(b) => Message::Pong(b),
            WsFrame::Close { code, reason } => Message::Close(Some(CloseFrame {
                code: tungstenite::protocol::frame::coding::CloseCode::from(code),
                reason: reason.into(),
            })),
        };

        let _perf_send_start = std::time::Instant::now();
        let send_result = {
            let mut guard = match ws.lock() {
                Ok(g) => g,
                Err(_) => {
                    tracing::warn!(frame_count, "ws writer: mutex poisoned, exiting");
                    break;
                }
            };
            guard.send(msg)
        };
        let _perf_send_ms = _perf_send_start.elapsed().as_millis();

        match send_result {
            Ok(()) => {
                tracing::info!(frame_count, kind, payload_len, "ws writer: send ok");
                tracing::info!(
                    "perf/net: ws send kind={} payload_len={} send_ms={}",
                    kind,
                    payload_len,
                    _perf_send_ms
                );
            }
            Err(e) => {
                // Distinguish OS-level write-timeout (the
                // `set_write_timeout` set in `tls_connect_with_config`
                // firing on the inner TCP socket) from a protocol-level
                // tungstenite error. Hardware traces can then grep for
                // write-timeout firings separately from other failures.
                let write_timed_out = matches!(&e,
                    tungstenite::Error::Io(io_err)
                        if io_err.kind() == std::io::ErrorKind::TimedOut
                            || io_err.kind() == std::io::ErrorKind::WouldBlock);
                tracing::warn!(frame_count, kind, ?e, write_timed_out, "ws writer: send failed, exiting");
                tracing::info!(
                    "perf/net: ws send_err kind={} payload_len={} send_ms={} write_timed_out={} err={:?}",
                    kind,
                    payload_len,
                    _perf_send_ms,
                    write_timed_out,
                    e
                );
                break;
            }
        }
    }
    tracing::info!(frame_count, "ws writer: loop exited");
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use rustls::pki_types::PrivatePkcs8KeyDer;
    use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};

    use super::*;

    /// Regression test for the abandoned-pump leak: when the async
    /// caller drops both halves of the [`WebSocketChannels`] pair while
    /// the WS is idle (the server sends nothing and never closes — the
    /// quiet-Signal-edge shape), the reader thread must notice at its
    /// next read-timeout tick and tear the connection down, instead of
    /// pumping timeout cycles forever. Pre-fix, the reader only
    /// noticed the dropped receiver when a frame actually arrived — on
    /// an idle WS, never — leaving 3 threads + a socket + the WS mutex
    /// alive per abandoned connection on a 16 MiB device.
    ///
    /// Observable used by the test: the server's blocking `ws.read()`
    /// errors out when the client's socket actually closes, which
    /// happens only after the reader loop exits and the last
    /// `Arc<Mutex<WebSocket>>` drops. Deadline is 20 s (expected:
    /// one 5 s read-timeout cycle + epsilon; generous for slow CI).
    #[test]
    fn abandoned_pump_tears_down_on_idle_ws() {
        // --- self-signed identity for an in-process WSS server ---
        let key_pair = rcgen::KeyPair::generate().expect("keypair");
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("params")
            .self_signed(&key_pair)
            .expect("self-sign");
        let cert_der = cert.der().clone();
        let key_der = PrivatePkcs8KeyDer::from(key_pair.serialize_der());

        let server_config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der.clone()], key_der.into())
                .expect("server config"),
        );

        let mut roots = RootCertStore::empty();
        roots.add(cert_der).expect("trust test cert");
        let client_config =
            Arc::new(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth());

        // Bind the same name the client dials ("localhost") so both
        // endpoints agree on its address family: the client connects
        // via url host "localhost" through
        // tls_connect_with_config's TcpStream::connect((host, port)),
        // and the cert SAN is "localhost", so binding a bare
        // 127.0.0.1 could leave the client dialing [::1]:port (a
        // different, unbound family) on IPv6-first resolvers.
        let listener = TcpListener::bind("localhost:0").expect("bind localhost");
        let port = listener.local_addr().expect("addr").port();

        // --- idle server: accept one WSS, then block reading until the
        // client goes away; report how the read ended + elapsed time ---
        let (server_done_tx, server_done_rx) = mpsc::channel();
        let srv_cfg = Arc::clone(&server_config);
        thread::spawn(move || {
            let (tcp, _) = listener.accept().expect("accept");
            let conn = ServerConnection::new(srv_cfg).expect("server conn");
            let stream = StreamOwned::new(conn, tcp);
            let mut ws = tungstenite::accept(stream).expect("ws accept");
            // An idle Signal edge sends nothing; just block on read
            // until the client side actually disappears (the read
            // errors when the client's socket closes, which happens
            // only after the reader loop exits and the last
            // Arc<Mutex<WebSocket>> drops). The server socket has no
            // read timeout set, so WouldBlock/TimedOut never occur
            // here — any Err means the peer went away.
            loop {
                match ws.read() {
                    Ok(_) => continue, // tolerate stray frames
                    Err(_) => break,
                }
            }
            let _ = server_done_tx.send(());
        });

        // --- client: connect, then abandon the pump ---
        let url = url::Url::parse(&format!("wss://localhost:{port}/")).expect("url");
        let channels =
            futures_lite::future::block_on(connect_websocket(client_config, url, HeaderMap::new(), None))
                .expect("connect_websocket");
        drop(channels); // caller walks away: both halves dropped

        // The server observes its socket close only after the reader
        // loop exits and drops the last Arc<Mutex<WebSocket>>. Pre-fix
        // that never happens on an idle WS, so recv_timeout elapses;
        // the deadline (20 s) is generous over the expected single
        // ~5 s read-timeout cycle. `Disconnected` (server thread died
        // before signalling — e.g. a harness accept/handshake failure)
        // is distinguished from `Timeout` (the actual leak) so a
        // broken harness doesn't masquerade as the production bug.
        match server_done_rx.recv_timeout(Duration::from_secs(20)) {
            Ok(()) => {} // teardown observed — pass
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!("abandoned pump never tore down: reader thread is leaked")
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("test server thread exited without signalling (harness failure, not the leak)")
            }
        }
    }
}
