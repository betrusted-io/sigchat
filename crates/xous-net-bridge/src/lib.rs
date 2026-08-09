//! Sync TLS + HTTPS + WebSocket transport for the Signal client.
//!
//! Implements the [`HttpClient`] trait that
//! `libsignal-service-rs` requires for HTTP/1.1 and WSS, on a sync
//! TCP/TLS stack. The async surface upstream code interacts with is
//! bridged to a small pool of sync worker threads via `async-channel`.
//!
//! # Layout
//!
//! - [`tls`] — sync rustls 0.22 handshake driver over `std::net::TcpStream`, pinned trust roots for Signal
//!   production and staging, and the [`tls::CountingResumptionStore`] that observability hangs off.
//! - [`http`] — [`http::SyncHttpClient`]: one-shot HTTP/1.1 client ([`HttpClient`] impl) and dispatcher for
//!   [`ws_pump`]'s WSS upgrade.
//! - [`ws`] — minimal `tungstenite::client` wrapper for examples/smoke-tests; not on the hot path.
//! - [`ws_pump`] — production WSS bridge: a pair of worker threads share an `Arc<Mutex<WebSocket>>` and
//!   exchange frames with the async executor via [`WebSocketChannels`].
//!
//! # Crate boundaries
//!
//! Upstream of this crate: `libsignal-service-rs` (via the
//! [`HttpClient`] trait — implemented by [`http::SyncHttpClient`] and
//! installed as a `thread_local!` by
//! `xous-signal-worker::worker_main`). Below this crate:
//! `std::net::TcpStream` (which Xous's `services/net` provides at the
//! kernel level), rustls 0.22, tungstenite 0.21.
//!
//! No `presage` or `xous-pddb-ipc` deps. Storage and Signal-Protocol
//! state live elsewhere; this crate is plaintext-network only.
//!
//! # Threading model
//!
//! The Signal worker runs on a single Xous thread with a
//! `smol-rs::LocalExecutor`. The transport itself is sync, so each
//! HTTP request spawns a one-shot OS thread (in
//! [`http::SyncHttpClient`]) and the WS pump spawns three OS threads
//! ([`ws_pump`]: setup, reader, writer). All cross-thread traffic
//! flows through `async-channel`, never via shared `Mutex`-protected
//! application state. Mutex usage is confined to the [`ws_pump`]
//! reader/writer pair serializing access to a single tungstenite
//! `WebSocket`.
//!
//! # Trust boundary
//!
//! Bytes on either side of this crate are TLS-encrypted on the wire
//! and plaintext (post-TLS / pre-Signal-Protocol) on the
//! application-facing side. This crate never inspects the Signal
//! Protocol payload — it sees raw byte buffers exchanged with rustls.
//! Signal-Protocol cryptography (Double Ratchet, X3DH, PQXDH, sealed
//! sender) happens further up the stack, in `signalapp/libsignal`
//! consumed via `libsignal-service-rs`.
//!
//! Trust roots are pinned: [`signal_production_roots`] and
//! [`signal_staging_roots`] are the only roots production Signal
//! traffic ever uses. System CAs are not consulted on the hot path —
//! a compromise of any public CA cannot man-in-the-middle a Signal
//! connection established through this crate.
//!
//! # Threat model
//!
//! Network is fully attacker-controlled. The TCP byte stream below
//! rustls is treated as adversarially crafted, in the rustls style
//! ("everything arriving from the wire is treated as adversarially
//! crafted"); cert verification, alert handling, and downgrade
//! resistance are delegated to rustls 0.22 with the default
//! cipher-suite list.
//!
//! What is NOT supported by this transport, by construction:
//!
//! - TLS 1.2 fallback against Signal endpoints — the production stack negotiates TLS 1.3; a TLS 1.2
//!   negotiation visible in the post-handshake `proto=` log line means either a MITM or a misconfigured
//!   staging endpoint, and should be treated as a finding.
//! - System CA bundle — never consulted; even with system roots compromised, a misissued cert from any public
//!   CA cannot MITM a Signal connection through this crate.
//! - HTTP redirects — Signal-Server replies 4xx/5xx for any path the client should follow; redirects are
//!   dropped on the floor.
//! - HTTP `Transfer-Encoding: chunked` — Signal endpoints never use it; see [`http`] for the failure modes if
//!   they did.
//! - Connection pooling — every HTTP request opens a fresh TCP and sends `Connection: close`. What survives
//!   across requests is the `Arc<ClientConfig>` and its in-memory session-ticket cache, which is what enables
//!   TLS 1.3 PSK resumption.
//!
//! Caller responsibilities:
//!
//! - Pass [`signal_production_roots`] (or [`signal_staging_roots`]) to [`http::SyncHttpClient::new`] for any
//!   Signal-bound traffic. Passing [`webpki_roots()`] silently downgrades to the public Mozilla bundle and
//!   defeats the MITM-resistance assumption.
//! - Treat any frame surfaced on `WebSocketChannels::incoming` as untrusted bytes until libsignal-service-rs
//!   has decrypted and authenticated the envelope.
//!
//! # Platform constraints
//!
//! Target: `riscv32imac-unknown-xous` (Precursor PVT2) and
//! `x86_64-unknown-linux-gnu` (hosted). 16 MiB SRAM, single hart,
//! no hardware AES, no constant-time multiplier. The rv32imac base
//! ISA has 32-bit `LR/SC` and `AMO*.W` atomics but no 64-bit
//! atomics; the counter in [`tls::CountingResumptionStore`] is
//! deliberately `AtomicUsize` (32-bit on rv32) rather than
//! `AtomicU64` for this reason. See [`tls`] for the wrap-around
//! reasoning.
//!
//! Constant-time guarantees: this crate does not implement any
//! cryptographic primitives itself; it composes rustls + ring on a
//! sync `std::net::TcpStream`. The constant-time properties of the
//! underlying primitives on rv32imac (no AES-NI, no constant-time
//! multiplier, no compiler-output verification) are best-effort, NOT
//! audited. An attacker with cycle-accurate side-channel measurement
//! capability against the device should be assumed able to observe
//! timing leakage. This is the residual side-channel risk
//! Precursor's open-hardware design minimizes but cannot eliminate.
//!
//! # Logging discipline
//!
//! All `tracing::info!` / `tracing::warn!` lines emitted by this
//! crate are designed for UART. None of them include: TLS keying
//! material, session-ticket contents, certificate fingerprints
//! beyond the negotiated subject CN that rustls's `Display` impl
//! surfaces on verification failure, plaintext request or response
//! bodies, frame payloads, or HTTP `Authorization` header values.
//! What is logged: peer hostname (already visible on the wire),
//! timings, frame counts, frame kinds, payload byte lengths, status
//! codes, and protocol/cipher-suite names. See per-item `# Logging`
//! sections for the exact line shapes.
//!
//! [`HttpClient`]: libsignal_service::transport::HttpClient
//! [`WebSocketChannels`]: libsignal_service::transport::WebSocketChannels

pub mod http;
pub mod tls;
pub mod ws;
pub mod ws_pump;

pub use http::SyncHttpClient;
pub use tls::{
    RustlsStream, build_tls_config, signal_production_roots, signal_staging_roots, tls_connect,
    tls_connect_with_config, webpki_roots,
};
pub use ws::ws_connect;
