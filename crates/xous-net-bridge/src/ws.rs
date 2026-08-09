//! Single-shot sync WSS connection helper.
//!
//! Wraps `tungstenite::client` over the TLS stream produced by
//! [`crate::tls::tls_connect`]. tungstenite handles only the HTTP/1.1
//! Upgrade handshake; the underlying TLS is wired in via our own
//! [`crate::tls::tls_connect`] so the rustls version stays pinned at
//! `=0.22.2` (see the workspace `Cargo.toml`).
//!
//! Production traffic goes through [`crate::ws_pump`] instead — this
//! module is for examples (`examples/signal_ws_keepalive.rs`) and
//! smoke tests where the caller does not need the reader/writer
//! thread pair.

use std::io;

use rustls::RootCertStore;
use tungstenite::client::IntoClientRequest;
use tungstenite::handshake::client::Response;
use tungstenite::protocol::WebSocket;

use crate::tls::{RustlsStream, tls_connect};

/// Open a WSS connection to `wss://host:port/path` and return the
/// established [`WebSocket`] plus the server's HTTP-upgrade
/// [`Response`].
///
/// `roots` is the *complete* trust anchor set — system roots are not
/// consulted. For Signal endpoints, pass [`crate::signal_production_roots`];
/// for general public endpoints, [`crate::webpki_roots`]. Passing the
/// wrong store silently downgrades the security posture; see
/// [`crate::tls::build_tls_config`] for the full caveat.
///
/// # ALPN
///
/// Always offers `http/1.1`. Signal's chat WS endpoint expects this;
/// no current Signal-Server endpoint negotiates anything else over a
/// WSS upgrade.
///
/// # Errors
///
/// - Invalid URL components or [`IntoClientRequest`] failures surface as [`io::Error::other`].
/// - TLS connect / handshake failures bubble through from [`tls_connect`] unchanged.
/// - Tungstenite client errors (HTTP status != 101, malformed upgrade response, etc.) are wrapped as
///   [`io::Error::other`] with the tungstenite display string.
pub fn ws_connect(
    host: &str,
    port: u16,
    path: &str,
    roots: RootCertStore,
) -> io::Result<(WebSocket<RustlsStream>, Response)> {
    let url = format!("wss://{host}:{port}{path}");
    let request = url.into_client_request().map_err(io::Error::other)?;

    // ALPN "http/1.1" matches what reqwest/tungstenite would normally send
    // and what Signal's chat WS endpoint expects.
    let stream = tls_connect(host, port, roots, &[b"http/1.1"])?;

    let (ws, resp) = tungstenite::client(request, stream).map_err(|e| io::Error::other(e.to_string()))?;
    Ok((ws, resp))
}
