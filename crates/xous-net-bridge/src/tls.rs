//! Sync TLS connection establishment for HTTPS and WSS.
//!
//! Both Signal transport layers (HTTPS in [`crate::http`], WSS in
//! [`crate::ws`] / [`crate::ws_pump`]) sit on rustls 0.22 over a sync
//! `Read + Write` stream. On hosted Linux that's
//! `std::net::TcpStream`; on Xous the same type is exposed by
//! `services/net` (see `xous-core/services/net/src/std_tcpstream.rs`).
//! The API is identical, so [`tls_connect`] works unchanged on both
//! targets.
//!
//! # Trust roots
//!
//! Two pinned root stores are exposed: [`signal_production_roots`] and
//! [`signal_staging_roots`]. Both are vendored copies of the bundles
//! that `whisperfish/libsignal-service-rs` carries
//! (`certs/production-root-ca.pem`, `certs/staging-root-ca.pem`).
//! System roots are never consulted on the hot path — a compromise of
//! any public CA cannot man-in-the-middle a Signal connection through
//! [`build_tls_config`]-derived configs.
//!
//! [`webpki_roots()`] is provided for the few non-Signal endpoints
//! (e.g. CDN smoke tests in `examples/`); production Signal traffic
//! must go through the pinned roots.
//!
//! # Resumption + observability
//!
//! [`build_tls_config`] installs a [`CountingResumptionStore`] wrapping
//! rustls's `ClientSessionMemoryCache`, so [`tls_connect_with_config`]
//! can emit `was_resumed=true|false` per connection without relying on
//! ambiguous post-handshake heuristics. The cache is sized for a
//! handful of distinct Signal hostnames; it lives in process memory
//! only and is dropped on process exit (TLS tickets are never written
//! to disk).
//!
//! # rv32 / 16 MiB constraint
//!
//! Software ECDHE + cert verification on rv32 is roughly an order of
//! magnitude slower than the symmetric work of a TLS 1.3 PSK
//! resumption; every saved full handshake meaningfully improves send
//! latency. That cost ratio is why the `was_resumed` diagnostic exists
//! at all — it lets hardware traces correlate `handshake_ms` against
//! PSK availability.
//!
//! Single-hart, single-threaded async: there is at most one
//! handshake in flight per host at any given moment. The
//! `CountingResumptionStore`'s "snapshot before / snapshot after"
//! race documented on the struct is theoretical for this reason.
//!
//! # Constant-time caveat
//!
//! Cryptographic primitives in this module are provided by rustls 0.22
//! over the `ring` crypto provider. `ring` claims constant-time
//! arithmetic on supported platforms; rv32imac is not among them. On
//! Precursor we have:
//!
//! - No hardware AES instructions (rustls falls back to ChaCha20 or a software AES).
//! - No constant-time multiplier in the rv32imac base ISA.
//! - No published audit of rustls/ring on rv32-xous.
//!
//! Accordingly, this module makes NO constant-time claim against
//! local-attacker side-channel measurement. An attacker with
//! cycle-accurate timing access to the device should be assumed able
//! to learn at least the cipher-suite negotiated and the rough cost
//! of the handshake. None of the secret material here (resumption
//! tickets, derived keys, ephemeral private keys) is held in this
//! module's own types; rustls owns those buffers, and they are
//! dropped (without explicit zeroization on the rv32imac target —
//! ring does its own zeroization but the surrounding tokio-free Rust
//! stack does not zero secondary copies) when the `ClientConnection`
//! is dropped.

use std::fmt;
use std::io;
use std::net::TcpStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use rustls::client::{
    ClientSessionMemoryCache, ClientSessionStore, Resumption, Tls12ClientSessionValue,
    Tls13ClientSessionValue,
};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, NamedGroup, RootCertStore, StreamOwned};

/// A handshake-completed sync TLS stream over TCP.
///
/// Returned by [`tls_connect`] / [`tls_connect_with_config`]. The stream
/// is `Read + Write` (via rustls's [`StreamOwned`]), is plaintext on
/// the application side, ciphertext on the wire side, and carries the
/// full [`ClientConnection`] state (resumption ticket, cipher suite,
/// half-close state). Drop terminates the connection abruptly; callers
/// that need a clean TCP close should issue an explicit close-notify
/// via the inner `ClientConnection` first.
pub type RustlsStream = StreamOwned<ClientConnection, TcpStream>;

/// Counting wrapper around [`ClientSessionMemoryCache`], installed by
/// [`build_tls_config`].
///
/// Forwards every [`ClientSessionStore`] method to the inner cache
/// verbatim. On top of that it increments a monotonic counter every
/// time `take_tls13_ticket` returns `Some` — i.e., a cached TLS 1.3
/// session ticket was consumed to offer PSK resumption on an outgoing
/// handshake.
///
/// [`tls_connect_with_config`] snapshots the counter immediately
/// before driving the handshake, then again after, and logs
/// `was_resumed=true` if the post snapshot is greater. A single global
/// counter is shared across all hosts; concurrent handshakes against
/// the same `Arc<ClientConfig>` can in principle mis-attribute
/// resumption, but xas only ever holds one config and the WS pump /
/// HTTP poller connect to distinct hosts in sequence, so the race is
/// theoretical.
///
/// # Why a direct hook rather than a heuristic
///
/// Per RFC 8446 §4.2.11, a TLS 1.3 server MAY still send a Certificate
/// message on a resumed connection depending on its
/// `psk_key_exchange_modes`. The observation "peer certificates > 0"
/// therefore does not disprove resumption — only the conjunction of
/// "peer certs > 0 AND handshake_ms is full-handshake-shaped" does,
/// and `handshake_ms` already captures that. A direct hook into the
/// resumption store removes the interpretation matrix entirely.
///
/// # Why `AtomicUsize`, not `AtomicU64`
///
/// `rv32imac` (Precursor) lacks 64-bit atomics. A 32-bit counter wraps
/// after ~4 billion handshakes; the device will never issue that many
/// in its service life.
///
/// # Security note
///
/// This store holds opaque session-ticket bytes from rustls. The
/// tickets are encrypted under server-side keys and reveal nothing
/// about identity or content on inspection, but they ARE bearer tokens
/// for the resumed PSK secret — an attacker with read access to
/// process memory and an outbound connection to the same Signal
/// endpoint could re-offer one. The store is process-memory-only and
/// dropped on exit; tickets are never written to PDDB.
pub struct CountingResumptionStore {
    inner: ClientSessionMemoryCache,
    /// Total `take_tls13_ticket(...) -> Some(...)` calls observed across
    /// every host. Snapshotted by [`tls_connect_with_config`] for the
    /// `was_resumed` diagnostic. See the struct docs for the
    /// `AtomicUsize`-vs-`AtomicU64` choice.
    take_some_count: AtomicUsize,
}

impl CountingResumptionStore {
    fn new(size: usize) -> Self {
        Self { inner: ClientSessionMemoryCache::new(size), take_some_count: AtomicUsize::new(0) }
    }

    /// Monotonic count of `take_tls13_ticket(...) -> Some(...)` calls
    /// observed across the lifetime of this store.
    ///
    /// Intended for tests and the diagnostic snapshot in
    /// [`tls_connect_with_config`]; not part of any production
    /// decision-making.
    pub fn take_some_count(&self) -> usize { self.take_some_count.load(Ordering::Acquire) }
}

impl fmt::Debug for CountingResumptionStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CountingResumptionStore")
            .field("take_some_count", &self.take_some_count.load(Ordering::Relaxed))
            .field("inner", &self.inner)
            .finish()
    }
}

/// Every method except `take_tls13_ticket` is a verbatim forward to the
/// inner [`ClientSessionMemoryCache`]. `take_tls13_ticket` additionally
/// bumps [`CountingResumptionStore::take_some_count`] on a hit, which
/// is the entire purpose of the wrapper.
impl ClientSessionStore for CountingResumptionStore {
    fn set_kx_hint(&self, server_name: ServerName<'static>, group: NamedGroup) {
        self.inner.set_kx_hint(server_name, group)
    }

    fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<NamedGroup> { self.inner.kx_hint(server_name) }

    fn set_tls12_session(&self, server_name: ServerName<'static>, value: Tls12ClientSessionValue) {
        self.inner.set_tls12_session(server_name, value)
    }

    fn tls12_session(&self, server_name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        self.inner.tls12_session(server_name)
    }

    fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
        self.inner.remove_tls12_session(server_name)
    }

    fn insert_tls13_ticket(&self, server_name: ServerName<'static>, value: Tls13ClientSessionValue) {
        self.inner.insert_tls13_ticket(server_name, value)
    }

    fn take_tls13_ticket(&self, server_name: &ServerName<'static>) -> Option<Tls13ClientSessionValue> {
        let v = self.inner.take_tls13_ticket(server_name);
        if v.is_some() {
            self.take_some_count.fetch_add(1, Ordering::AcqRel);
        }
        v
    }
}

/// Process-wide handle to the counting store installed by
/// [`build_tls_config`].
///
/// `OnceLock` so the first build wins; subsequent calls to
/// `build_tls_config` keep using it. xas only ever builds one
/// `ClientConfig`, so the global is shared across every Signal endpoint
/// the process touches in its lifetime. Read by
/// [`tls_connect_with_config`]'s before/after handshake snapshot.
///
/// Tests that bypass [`build_tls_config`] (e.g. `tests/tls_resumption.rs`
/// which wires its own `Resumption::store`) leave this unset; the
/// handshake log in that case reports `was_resumed=unknown` rather than
/// `true`/`false`.
static ACTIVE_COUNTER: OnceLock<Arc<CountingResumptionStore>> = OnceLock::new();

/// Returns the global counter installed by [`build_tls_config`], or
/// `None` if no config has been built yet.
///
/// Test-only entry point. Production code never reads this directly —
/// [`tls_connect_with_config`] snapshots internally.
#[doc(hidden)]
pub fn active_counter_for_tests() -> Option<Arc<CountingResumptionStore>> { ACTIVE_COUNTER.get().cloned() }

/// Build a [`ClientConfig`] suitable for sharing across many
/// [`tls_connect_with_config`] calls.
///
/// The returned [`Arc`] is the unit of TLS 1.3 PSK session-ticket
/// reuse: as long as the same `Arc<ClientConfig>` is passed to
/// subsequent connects against the same host, the in-memory cache of
/// up to 8 tickets survives reconnects, allowing PSK resumption
/// instead of a full ECDHE handshake every time.
///
/// # Trust roots
///
/// `roots` is the *complete* set of trust anchors for any connection
/// using the returned config — system roots are NOT consulted. For
/// Signal endpoints, callers must pass [`signal_production_roots`] (or
/// [`signal_staging_roots`]). Passing [`webpki_roots()`] silently
/// downgrades to the public Mozilla bundle and allows a misissued
/// certificate from any public CA to MITM the connection. Mirrors what
/// `libsignal-service-rs/src/push_service/mod.rs` does for its own
/// reqwest-based path.
///
/// # ALPN
///
/// `alpn` is sent as the offered protocol list. Empty disables ALPN.
/// HTTPS callers pass `&[b"http/1.1"]`; WSS upgrades use the same
/// protocol (the upgrade happens after the HTTP/1.1 handshake).
///
/// # Cipher suite
///
/// Defaults to rustls 0.22's stock suite list (TLS 1.3 preferred).
/// Signal-Server negotiates TLS 1.3 in production; a TLS 1.2
/// negotiation indicates either a MITM or a misconfigured staging
/// endpoint and the resulting `proto=...` line in the post-handshake
/// log should be treated as a finding.
///
/// # Resumption cache size
///
/// rustls's default cache holds 256 tickets; we shrink to 8 because
/// xas only ever talks to a handful of Signal endpoints plus an
/// occasional CDN, and a smaller cache reduces ticket-eviction
/// pressure if Signal's load balancer happens to issue tickets pinned
/// to different backends.
///
/// # Idempotence
///
/// `ACTIVE_COUNTER` is `OnceLock`-backed, so the first call wins.
/// Subsequent calls return new `ClientConfig`s that all point at the
/// same [`CountingResumptionStore`], which is what enables the
/// `was_resumed` diagnostic to observe activity across the whole
/// process.
pub fn build_tls_config(roots: RootCertStore, alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let mut config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    if !alpn.is_empty() {
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    }
    // On-the-wire behaviour is identical to a plain
    // `Resumption::in_memory_sessions(8)`; the wrapper only adds a
    // fetch_add on the take-some path so `tls_connect_with_config` can
    // emit `was_resumed=true|false` directly rather than inferring it.
    let counter = ACTIVE_COUNTER.get_or_init(|| Arc::new(CountingResumptionStore::new(8))).clone();
    config.resumption = Resumption::store(counter);
    Arc::new(config)
}

/// Public Mozilla NSS-bundle root CAs, taken from the `webpki-roots`
/// crate.
///
/// Suitable for general HTTPS to public endpoints (CDN smoke tests
/// in `examples/`, etc.). **NOT suitable for Signal endpoints** — those
/// pin their own CA via [`signal_production_roots`]. A connection
/// established with this root store and pointed at chat.signal.org
/// would accept a certificate from any public CA, defeating the
/// project's MITM-resistance assumptions.
pub fn webpki_roots() -> RootCertStore { RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() } }

/// Signal's production root CA, pinned.
///
/// Mirrors `libsignal-service-rs/src/push_service/mod.rs` (the
/// reqwest-based upstream path): disable system roots, trust only this
/// CA. The PEM is bundled at `certs/signal-production.pem` and is a
/// vendored copy of
/// `whisperfish/libsignal-service-rs/certs/production-root-ca.pem`.
///
/// # Security
///
/// This is the single most consequential trust-boundary input in the
/// worker process: it is the *only* set of trust anchors every Signal
/// HTTP and WSS connection is validated against. Construction is
/// build-time (the PEM bytes are baked into the binary by
/// `include_bytes!`); a parse failure is therefore a release-artifact
/// bug, not a runtime input-validation failure. Constructed once by
/// `xous_signal_worker::worker_main` at thread start and handed to
/// [`crate::SyncHttpClient::new`]; never replaced at runtime.
///
/// Substituting [`webpki_roots`] here would silently downgrade the
/// MITM-resistance posture to "any public CA can issue a valid cert
/// for chat.signal.org" — see [`webpki_roots`] for the deliberate
/// staging-only intent.
///
/// # Panics
///
/// Panics if the bundled PEM fails to parse. That is a build-time
/// invariant — the bytes are baked in by `include_bytes!` and verified
/// by the test suite — so a panic here means a bad release artifact.
pub fn signal_production_roots() -> RootCertStore {
    parse_pem_roots(include_bytes!("../certs/signal-production.pem"))
        .expect("Signal production root CA bundled at build time should parse")
}

/// Signal's staging root CA, pinned. Same shape as
/// [`signal_production_roots`] but targets the staging environment.
///
/// # Panics
///
/// Panics if the bundled PEM fails to parse; see
/// [`signal_production_roots`] for rationale.
pub fn signal_staging_roots() -> RootCertStore {
    parse_pem_roots(include_bytes!("../certs/signal-staging.pem"))
        .expect("Signal staging root CA bundled at build time should parse")
}

/// Parse a PEM byte slice into a [`RootCertStore`].
///
/// Each `-----BEGIN CERTIFICATE-----` block is added as a trust anchor.
/// Returns the first underlying IO or rustls parse error if any
/// certificate fails to decode.
fn parse_pem_roots(pem: &[u8]) -> io::Result<RootCertStore> {
    let mut reader = std::io::BufReader::new(pem);
    let mut store = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut reader) {
        let cert = cert?;
        store.add(cert).map_err(io::Error::other)?;
    }
    Ok(store)
}

/// Open a sync TLS connection to `host:port` using a pre-built shared
/// [`ClientConfig`].
///
/// Hot-path callers that reconnect to the same host should build the
/// config once via [`build_tls_config`] and reuse the resulting
/// `Arc<ClientConfig>` so the in-memory session-ticket cache survives
/// across reconnects — that is what enables TLS 1.3 PSK resumption.
///
/// The TLS handshake is driven to completion before this function
/// returns, so the returned [`RustlsStream`] is immediately usable for
/// application-layer I/O. Any handshake failure (cert verification,
/// suite mismatch, peer close, network error) surfaces here rather
/// than on a later `read`/`write`.
///
/// # Socket timeouts
///
/// The underlying [`TcpStream`] is configured with:
///
/// - `set_read_timeout(5s)` — the WebSocket pump in [`crate::ws_pump`] holds a mutex across the blocking
///   `WebSocket::read()` in its reader thread; without a short timeout the writer thread could never inject
///   keepalives.
/// - `set_write_timeout(30s)` — bounds the writer's TCP retransmit budget so a server-initiated `Close`
///   mid-write does not block the thread for ~89 s on hardware. Acts as defense-in-depth alongside the
///   `services/net` socket-reaper fix that addresses the root cause kernel-side.
///
/// # Logging
///
/// Emits two `tracing::info!` lines per call on the `perf/net` channel:
///
/// - `tls_connect exit ... server_name_ms=... client_conn_ms=... tcp_ms=... setup_total_ms=...`
/// - `tls_handshake ... handshake_ms=... was_resumed=true|false|unknown proto=... cipher=...`
///
/// Neither line contains any keying material, certificate fingerprint,
/// or session-ticket content — only timing, the peer hostname (already
/// known to anyone seeing the connection on the wire), the negotiated
/// TLS version, and the cipher suite name. Safe to ship to UART.
///
/// On handshake failure, the log line is `tls_handshake_error ... err=<display>`
/// — rustls's error display contains no secret material, but does
/// surface the certificate's subject CN on a verification failure, which
/// is metadata-class information.
///
/// # Errors
///
/// Returns `io::Error` for invalid hostnames, TCP connect failures, or
/// any error returned by rustls's `complete_io` (cert verification,
/// protocol downgrade rejection, peer reset).
///
/// # Security
///
/// The TLS configuration in `config` is authoritative for what
/// certificates this connection will accept. Callers are responsible
/// for ensuring `config` was built with the appropriate pinned roots
/// for the endpoint (see [`build_tls_config`]). Mismatching them is
/// the most likely way to silently degrade the security posture of
/// this transport.
pub fn tls_connect_with_config(host: &str, port: u16, config: Arc<ClientConfig>) -> io::Result<RustlsStream> {
    let t_start = std::time::Instant::now();
    tracing::info!("perf/net: tls_connect entry host={} port={}", host, port);
    let server_name =
        ServerName::try_from(host.to_string()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let _perf_sn_ms = t_start.elapsed().as_millis() as u64;
    let conn = ClientConnection::new(config, server_name).map_err(io::Error::other)?;
    let _perf_conn_ms = t_start.elapsed().as_millis() as u64;

    let sock = TcpStream::connect((host, port))?;
    let setup_ms = t_start.elapsed().as_millis() as u64;
    tracing::info!(host, port, setup_ms, "tls_connect: setup-phase complete");
    // Split from the post-handshake `tls_handshake` line below so external
    // log-grep tools that match on this exact format stay decoupled from
    // the additive resumption diagnostic.
    tracing::info!(
        "perf/net: tls_connect exit host={} port={} server_name_ms={} client_conn_ms={} tcp_ms={} setup_total_ms={}",
        host,
        port,
        _perf_sn_ms,
        _perf_conn_ms - _perf_sn_ms,
        setup_ms - _perf_conn_ms,
        setup_ms
    );

    // Short TCP read timeout. WebSocket users (`ws_pump::reader_loop`)
    // hold a mutex across the blocking `WebSocket::read()`; without a
    // timeout, the reader would block forever waiting for an inbound
    // frame and the writer thread could never acquire the mutex to
    // send keepalives. Signal's provisioning WS times out clients at
    // ~60 s of idle, so missing keepalives means the link drops before
    // the user finishes scanning. The timeout makes `read()` return
    // `Err(WouldBlock|TimedOut)` periodically; the reader catches that
    // and re-loops, briefly releasing the mutex.
    sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    // Bound the writer's TCP retransmit budget; without this, a
    // server-initiated Close mid-write blocks ~89 s on hardware.
    // Defense-in-depth alongside the kernel-side socket-reaper fix in
    // xous-core's services/net.
    sock.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;

    let mut stream = StreamOwned::new(conn, sock);

    // Snapshot the active counting-store's take-some counter immediately
    // before driving the handshake. If `complete_io` consumes a TLS 1.3
    // session ticket from the cache, `CountingResumptionStore::take_tls13_ticket`
    // increments this counter; comparing the post-handshake snapshot to
    // this one yields an unambiguous `was_resumed` per connection (subject
    // to the cross-host concurrency caveat documented on the struct).
    //
    // `ACTIVE_COUNTER` is `None` only when the caller wired a custom
    // `Resumption::store` directly (e.g. the integration test in
    // `tests/tls_resumption.rs`); in that case `was_resumed` reports
    // `unknown` and the test's own counting store is the source of truth.
    let counter_before = ACTIVE_COUNTER.get().map(|c| c.take_some_count());

    // Drive the handshake to completion. On TLS 1.3 PSK resumption rustls
    // performs ~1 RTT of symmetric crypto + HKDF; on a full handshake it
    // does ECDHE + cert verification, which on rv32 with software crypto
    // is roughly an order of magnitude more wall-time. `handshake_ms` by
    // itself is sufficient to distinguish the two; `was_resumed` below
    // removes any ambiguity at the cost of one extra Acquire load.
    let hs_start = std::time::Instant::now();
    if let Err(e) = stream.conn.complete_io(&mut stream.sock) {
        tracing::info!(
            "perf/net: tls_handshake_error host={} port={} setup_total_ms={} handshake_ms={} err={}",
            host,
            port,
            setup_ms,
            hs_start.elapsed().as_millis() as u64,
            e
        );
        return Err(e);
    }
    let handshake_ms = hs_start.elapsed().as_millis() as u64;

    let proto = stream.conn.protocol_version().map(|v| format!("{:?}", v)).unwrap_or_else(|| "?".to_string());
    let cipher = stream
        .conn
        .negotiated_cipher_suite()
        .map(|s| format!("{:?}", s.suite()))
        .unwrap_or_else(|| "?".to_string());

    let was_resumed = match (counter_before, ACTIVE_COUNTER.get()) {
        (Some(before), Some(c)) => {
            if c.take_some_count() > before {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        // No active counter installed: caller bypassed `build_tls_config`
        // (test-only path). Don't claim either way.
        _ => "unknown".to_string(),
    };
    tracing::info!(
        "perf/net: tls_handshake host={} port={} handshake_ms={} was_resumed={} proto={} cipher={}",
        host,
        port,
        handshake_ms,
        was_resumed,
        proto,
        cipher
    );

    Ok(stream)
}

/// Convenience wrapper for one-shot callers (examples, tests).
///
/// Builds a fresh [`ClientConfig`] per call. Because the in-memory
/// session-ticket cache lives inside the config — and the global
/// counter installed by [`build_tls_config`] is `OnceLock`-backed, so
/// the second call still observes the original counter — this is
/// effectively non-resuming when used repeatedly.
///
/// **Hot-path callers** (everything inside [`crate::http::SyncHttpClient`]
/// and [`crate::ws_pump`]) must go through [`build_tls_config`] +
/// [`tls_connect_with_config`] explicitly; constructing the
/// `Arc<ClientConfig>` once and reusing it is what allows TLS 1.3
/// resumption across reconnects.
pub fn tls_connect(host: &str, port: u16, roots: RootCertStore, alpn: &[&[u8]]) -> io::Result<RustlsStream> {
    tls_connect_with_config(host, port, build_tls_config(roots, alpn))
}

#[cfg(test)]
mod counting_store_tests {
    use rustls::pki_types::ServerName;

    use super::*;

    /// `take_some_count` increments only when `take_tls13_ticket` returns
    /// `Some` — not on `take_tls13_ticket` calls that miss, and not on
    /// `insert_tls13_ticket`. This is the load-bearing property
    /// `tls_connect_with_config` relies on for `was_resumed`.
    #[test]
    fn take_some_count_increments_only_on_hit() {
        let store = CountingResumptionStore::new(8);
        let name: ServerName<'static> = ServerName::try_from("example.com").unwrap();

        // Empty cache: take returns None, counter unchanged.
        assert!(store.take_tls13_ticket(&name).is_none());
        assert_eq!(store.take_some_count(), 0);

        // Inserting a value doesn't bump the take-some counter — only
        // `take_tls13_ticket(...) -> Some` does. We can't construct a real
        // Tls13ClientSessionValue here (the constructor is rustls-internal),
        // so this branch is exercised indirectly by the integration test
        // in `tests/tls_resumption.rs` which drives a real handshake pair.
        // The assertion below covers the negative case: take on an empty
        // store never touches the counter regardless of how many times we
        // call it.
        for _ in 0..16 {
            let _ = store.take_tls13_ticket(&name);
        }
        assert_eq!(store.take_some_count(), 0);
    }

    /// `build_tls_config` is idempotent w.r.t. the active counter: calling
    /// it more than once returns configs that share the same counting
    /// store. (Production xas calls it once; defensive assertion in case a
    /// future refactor adds a second caller.)
    #[test]
    fn build_tls_config_reuses_the_active_counter() {
        let roots = webpki_roots();
        let _c1 = build_tls_config(roots.clone(), &[]);
        let _c2 = build_tls_config(roots, &[]);
        // Both calls populated the OnceLock — once. Second call sees the
        // already-installed counter and reuses it.
        let counter = active_counter_for_tests().expect("counter installed");
        // Counter is fresh; no handshakes were driven, so take-some=0.
        assert_eq!(counter.take_some_count(), 0);
    }
}
