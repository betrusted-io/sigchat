//! Baseline measurement for issue #1 (send latency): TLS handshake cost
//! with vs without the shared-Arc<ClientConfig> change ("Stage 0" in the
//! issue's history).
//!
//! This is **not** a "send pipeline" measurement — it isolates the TLS
//! handshake cost, which is the variable Stage 0 directly reduces. Pipeline-
//! level measurement requires hardware or a real Signal account.
//!
//! Two scenarios per target:
//!
//! 1. **shared**: `tls_connect_with_config` reusing one `Arc<ClientConfig>` across all iterations. The Stage
//!    0 path. The first handshake is full; every subsequent handshake should be a TLS 1.3 PSK resumption
//!    (5-15 ms on x86_64 vs. 50-200 ms full).
//! 2. **per-call**: legacy `tls_connect` constructing a fresh ClientConfig every iteration. The pre-Stage-0
//!    path. Every handshake is a full handshake; resumption is silently disabled.
//!
//! Two targets:
//!
//! - `localhost`: in-process rustls server with self-signed cert. Removes network and load-balancer variance.
//!   Lower-bound numbers.
//! - `chat.signal.org:443`: real Signal endpoint. Includes network RTT and any load-balancer ticket-rejection
//!   noise. Note: measurement showed chat.signal.org never issues session tickets, so resumption cannot
//!   engage against production (see issue #1). Skipped automatically if `XAS_BENCH_NET=1` is not set in the
//!   environment, because production runs of `cargo test` shouldn't hit the live Signal infrastructure.
//!
//! Run with:
//!
//! ```sh
//! cargo test --release -p xous-net-bridge --test handshake_bench -- --nocapture
//! XAS_BENCH_NET=1 cargo test --release -p xous-net-bridge --test handshake_bench -- --nocapture
//! ```

use std::fmt;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rustls::client::{ClientSessionStore, Resumption, Tls12ClientSessionValue, Tls13ClientSessionValue};
use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
use rustls::server::ServerConnection;
use rustls::{ClientConfig, NamedGroup, RootCertStore, ServerConfig};
use xous_net_bridge::{RustlsStream, signal_production_roots, tls_connect, tls_connect_with_config};

const ITERS: usize = 20;

/// In-memory ClientSessionStore that counts inserts/takes. Lets the bench
/// distinguish "resumption is working but provides no measurable savings"
/// from "resumption never engaged." Without this, identical timings could
/// mean either case.
struct CountingStore {
    tls13: Mutex<Vec<(ServerName<'static>, Tls13ClientSessionValue)>>,
    inserts: AtomicUsize,
    takes_some: AtomicUsize,
    takes_none: AtomicUsize,
}

impl fmt::Debug for CountingStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "inserts={} takes(some)={} takes(none)={}",
            self.inserts.load(Ordering::SeqCst),
            self.takes_some.load(Ordering::SeqCst),
            self.takes_none.load(Ordering::SeqCst),
        )
    }
}

impl CountingStore {
    fn new() -> Self {
        Self {
            tls13: Mutex::new(Vec::new()),
            inserts: AtomicUsize::new(0),
            takes_some: AtomicUsize::new(0),
            takes_none: AtomicUsize::new(0),
        }
    }
}

impl ClientSessionStore for CountingStore {
    fn set_kx_hint(&self, _: ServerName<'static>, _: NamedGroup) {}

    fn kx_hint(&self, _: &ServerName<'_>) -> Option<NamedGroup> { None }

    fn set_tls12_session(&self, _: ServerName<'static>, _: Tls12ClientSessionValue) {}

    fn tls12_session(&self, _: &ServerName<'_>) -> Option<Tls12ClientSessionValue> { None }

    fn remove_tls12_session(&self, _: &ServerName<'static>) {}

    fn insert_tls13_ticket(&self, server_name: ServerName<'static>, value: Tls13ClientSessionValue) {
        self.inserts.fetch_add(1, Ordering::SeqCst);
        self.tls13.lock().unwrap().push((server_name, value));
    }

    fn take_tls13_ticket(&self, server_name: &ServerName<'static>) -> Option<Tls13ClientSessionValue> {
        let mut tls13 = self.tls13.lock().unwrap();
        let pos = tls13.iter().position(|(n, _)| n == server_name);
        match pos {
            Some(p) => {
                self.takes_some.fetch_add(1, Ordering::SeqCst);
                Some(tls13.remove(p).1)
            }
            None => {
                self.takes_none.fetch_add(1, Ordering::SeqCst);
                None
            }
        }
    }
}

fn build_counting_config(roots: RootCertStore, alpn: &[&[u8]]) -> (Arc<ClientConfig>, Arc<CountingStore>) {
    let store = Arc::new(CountingStore::new());
    let mut config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    if !alpn.is_empty() {
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    }
    config.resumption = Resumption::store(Arc::clone(&store) as Arc<dyn ClientSessionStore>);
    (Arc::new(config), store)
}

fn percentile(samples_sorted: &[u128], pct: f64) -> u128 {
    if samples_sorted.is_empty() {
        return 0;
    }
    let idx = ((samples_sorted.len() as f64 - 1.0) * pct).round() as usize;
    samples_sorted[idx.min(samples_sorted.len() - 1)]
}

struct Stats {
    label: &'static str,
    target: String,
    samples_us: Vec<u128>,
}

impl Stats {
    fn new(label: &'static str, target: String) -> Self {
        Self { label, target, samples_us: Vec::with_capacity(ITERS) }
    }

    fn record(&mut self, d: Duration) { self.samples_us.push(d.as_micros()); }

    fn finalize(mut self) -> Self {
        self.samples_us.sort_unstable();
        self
    }

    fn median_ms(&self) -> f64 { percentile(&self.samples_us, 0.5) as f64 / 1000.0 }

    fn p99_ms(&self) -> f64 { percentile(&self.samples_us, 0.99) as f64 / 1000.0 }

    fn first_ms(&self) -> f64 {
        // After sort the original order is lost; first-iteration cost is
        // typically the max, since it's the only full handshake when
        // resumption works. Approximate via max.
        self.samples_us.last().copied().unwrap_or(0) as f64 / 1000.0
    }
}

impl fmt::Display for Stats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<14} target={:<28} n={}  median={:6.2} ms  p99={:6.2} ms  worst={:6.2} ms",
            self.label,
            self.target,
            self.samples_us.len(),
            self.median_ms(),
            self.p99_ms(),
            self.first_ms(),
        )
    }
}

fn drive_handshake_then_close(stream: &mut RustlsStream) -> std::io::Result<()> {
    // For chat.signal.org: write a minimal HTTP/1.1 GET so the handshake
    // completes and the server replies. Read until EOF so any post-handshake
    // NewSessionTicket frames are processed by the client (otherwise the
    // ticket arrives but our caller drops the stream before rustls reads it,
    // and the cache stays empty).
    stream.write_all(b"GET / HTTP/1.1\r\nHost: chat.signal.org\r\nConnection: close\r\n\r\n")?;
    stream.flush()?;
    let mut sink = [0u8; 4096];
    loop {
        match stream.read(&mut sink) {
            Ok(0) => break,
            Ok(_) => continue,
            Err(_) => break,
        }
    }
    Ok(())
}

fn drive_local_handshake(stream: &mut RustlsStream) -> std::io::Result<()> {
    stream.flush()?;
    // Read the greeting AND drain to EOF so post-handshake tickets land.
    let mut sink = [0u8; 64];
    let n = stream.read(&mut sink)?;
    assert!(n > 0, "expected greeting from local server");
    loop {
        match stream.read(&mut sink) {
            Ok(0) => break,
            Ok(_) => continue,
            Err(_) => break,
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------
// Local rustls server (mirrors tls_resumption.rs's setup, abbreviated)
// -----------------------------------------------------------------------

fn mint_self_signed()
-> (rustls::pki_types::CertificateDer<'static>, PrivatePkcs8KeyDer<'static>, RootCertStore) {
    let key_pair = rcgen::KeyPair::generate().expect("keypair");
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .expect("cert params")
        .self_signed(&key_pair)
        .expect("self-signed");
    let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = PrivatePkcs8KeyDer::from(key_pair.serialize_der());

    let mut roots = RootCertStore::empty();
    roots.add(cert_der.clone()).expect("add root");
    (cert_der, key_der, roots)
}

fn build_test_server_config(
    cert_der: rustls::pki_types::CertificateDer<'static>,
    key_der: PrivatePkcs8KeyDer<'static>,
) -> Arc<ServerConfig> {
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], rustls::pki_types::PrivateKeyDer::Pkcs8(key_der))
        .expect("server config");
    Arc::new(config)
}

fn pick_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("port");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Server thread: accepts up to `n` connections, completes handshake on
/// each, sends "hi\n", closes. Stops when `stop` is set or `n` exhausted.
fn run_local_server(
    port: u16,
    n: usize,
    server_config: Arc<ServerConfig>,
    stop: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind");
        listener.set_nonblocking(false).expect("blocking accept");
        for _ in 0..n {
            if stop.load(Ordering::SeqCst) {
                break;
            }
            let (mut sock, _peer) = match listener.accept() {
                Ok(p) => p,
                Err(_) => continue,
            };
            sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
            let mut srv = ServerConnection::new(Arc::clone(&server_config)).expect("server conn");
            if srv.complete_io(&mut sock).is_err() {
                continue;
            }
            let _ = srv.writer().write_all(b"hi\n");
            let _ = srv.complete_io(&mut sock);
        }
    })
}

// -----------------------------------------------------------------------
// Bench drivers
// -----------------------------------------------------------------------

fn bench_local_shared(roots: RootCertStore, port: u16) -> (Stats, Arc<CountingStore>) {
    let mut stats = Stats::new("shared", "127.0.0.1 (local rustls)".into());
    let (config, store) = build_counting_config(roots, &[]);
    for _ in 0..ITERS {
        let t0 = Instant::now();
        let mut s = tls_connect_with_config("localhost", port, Arc::clone(&config)).expect("connect");
        drive_local_handshake(&mut s).expect("handshake");
        let elapsed = t0.elapsed();
        drop(s);
        stats.record(elapsed);
    }
    (stats.finalize(), store)
}

fn bench_local_per_call(roots: RootCertStore, port: u16) -> Stats {
    let mut stats = Stats::new("per-call", "127.0.0.1 (local rustls)".into());
    for _ in 0..ITERS {
        let roots_per_call = roots.clone();
        let t0 = Instant::now();
        let mut s = tls_connect("localhost", port, roots_per_call, &[]).expect("connect");
        drive_local_handshake(&mut s).expect("handshake");
        let elapsed = t0.elapsed();
        drop(s);
        stats.record(elapsed);
    }
    stats.finalize()
}

fn bench_remote_shared(host: &str, port: u16, roots: RootCertStore) -> (Stats, Arc<CountingStore>) {
    let mut stats = Stats::new("shared", format!("{host}:{port}"));
    let (config, store) = build_counting_config(roots, &[b"http/1.1"]);
    for _ in 0..ITERS {
        let t0 = Instant::now();
        let mut s = tls_connect_with_config(host, port, Arc::clone(&config)).expect("connect");
        drive_handshake_then_close(&mut s).expect("handshake");
        let elapsed = t0.elapsed();
        drop(s);
        stats.record(elapsed);
        // Light pacing so we don't get rate-limited.
        thread::sleep(Duration::from_millis(50));
    }
    (stats.finalize(), store)
}

fn bench_remote_per_call<F: Fn() -> RootCertStore>(host: &str, port: u16, mk_roots: F) -> Stats {
    let mut stats = Stats::new("per-call", format!("{host}:{port}"));
    for _ in 0..ITERS {
        let roots = mk_roots();
        let t0 = Instant::now();
        let mut s = tls_connect(host, port, roots, &[b"http/1.1"]).expect("connect");
        drive_handshake_then_close(&mut s).expect("handshake");
        let elapsed = t0.elapsed();
        drop(s);
        stats.record(elapsed);
        thread::sleep(Duration::from_millis(50));
    }
    stats.finalize()
}

// -----------------------------------------------------------------------
// Tests (each prints; no asserts beyond non-emptiness)
// -----------------------------------------------------------------------

#[test]
fn local_handshake_shared_vs_per_call() {
    let (cert_der, key_der, roots) = mint_self_signed();
    let server_config = build_test_server_config(cert_der, key_der);

    let port = pick_port();
    let stop = Arc::new(AtomicBool::new(false));
    // 2*ITERS connections (shared run + per-call run).
    let server = run_local_server(port, 2 * ITERS, Arc::clone(&server_config), Arc::clone(&stop));
    thread::sleep(Duration::from_millis(50));

    let (shared, shared_store) = bench_local_shared(roots.clone(), port);
    let per_call = bench_local_per_call(roots, port);

    stop.store(true, Ordering::SeqCst);
    let _ = server.join();

    eprintln!("\n--- local rustls handshake bench ---");
    eprintln!("{shared}");
    eprintln!("  cache: {:?}", shared_store);
    eprintln!("{per_call}");
    eprintln!("  cache: (per-call config; no shared cache to observe)");

    assert!(!shared.samples_us.is_empty());
    assert!(!per_call.samples_us.is_empty());
}

#[test]
fn remote_handshake_shared_vs_per_call_signal() {
    if std::env::var_os("XAS_BENCH_NET").is_none() {
        eprintln!(
            "skipping remote handshake bench (set XAS_BENCH_NET=1 to enable; \
             touches chat.signal.org:443)"
        );
        return;
    }
    let host = "chat.signal.org";
    let port = 443u16;
    let (shared, shared_store) = bench_remote_shared(host, port, signal_production_roots());
    let per_call = bench_remote_per_call(host, port, signal_production_roots);

    eprintln!("\n--- {host}:{port} handshake bench ---");
    eprintln!("{shared}");
    eprintln!("  cache: {:?}", shared_store);
    eprintln!("{per_call}");
    eprintln!("  cache: (per-call config; no shared cache to observe)");
}

#[test]
fn remote_handshake_shared_vs_per_call_control() {
    // Control target: a public TLS endpoint known to issue session tickets
    // (cloudflare.com). If Stage 0 works against this and not against
    // chat.signal.org, the limiting factor is Signal-server-side ticket
    // policy, not our code. Gated on XAS_BENCH_NET=1 like the Signal test.
    if std::env::var_os("XAS_BENCH_NET").is_none() {
        eprintln!(
            "skipping control handshake bench (set XAS_BENCH_NET=1 to enable; \
             touches cloudflare.com:443)"
        );
        return;
    }
    let host = "cloudflare.com";
    let port = 443u16;
    let (shared, shared_store) = bench_remote_shared(host, port, xous_net_bridge::webpki_roots());
    let per_call = bench_remote_per_call(host, port, xous_net_bridge::webpki_roots);

    eprintln!("\n--- {host}:{port} handshake bench (control) ---");
    eprintln!("{shared}");
    eprintln!("  cache: {:?}", shared_store);
    eprintln!("{per_call}");
    eprintln!("  cache: (per-call config; no shared cache to observe)");
}
