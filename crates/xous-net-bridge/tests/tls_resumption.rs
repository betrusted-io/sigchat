//! Integration test for TLS session resumption via shared
//! `Arc<ClientConfig>` ("Stage 0" of issue #1).
//!
//! The test stands up a rustls 1.3 server in a worker thread, mints a fresh
//! self-signed certificate via `rcgen`, drives two HTTPS-style handshakes
//! through `tls_connect_with_config` using the SAME `Arc<ClientConfig>`, and
//! asserts that the second handshake performs a session-ticket lookup
//! (`take`). The actual fix being guarded against here is "someone reverts
//! `SyncHttpClient` / `tls_connect` to construct a fresh `ClientConfig` per
//! call" — in that world, every `ClientConfig` carries its own empty cache,
//! `take` is never called against a populated cache, and resumption never
//! happens.
//!
//! We deliberately do NOT exercise `SyncHttpClient` itself here — its
//! `execute()` runs an HTTP/1.1 request which the test server would also
//! have to implement. The load-bearing claim is at the `tls_connect_with_config`
//! layer; if that's correct, `SyncHttpClient` inherits it because the same
//! `Arc<ClientConfig>` flows through both `execute()` and `connect_websocket()`.

use std::fmt;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rustls::client::{ClientSessionStore, Resumption, Tls12ClientSessionValue, Tls13ClientSessionValue};
use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
use rustls::server::ServerConnection;
use rustls::{ClientConfig, NamedGroup, RootCertStore, ServerConfig};
use xous_net_bridge::{RustlsStream, tls_connect_with_config};

/// Counts the three load-bearing operations on the rustls client session
/// cache. After two handshakes against the same Arc<ClientConfig>:
///
/// * a working shared cache produces `inserts >= 1` (server issues a ticket on the first handshake; client
///   stores it) and `takes >= 1` (client looks up the stored ticket on the second handshake);
/// * a broken per-call ClientConfig produces `inserts >= 1` from the first handshake but `takes == 0` because
///   the second handshake's ClientConfig never sees the first one's cache.
struct CountingStore {
    tls13: Mutex<Vec<(ServerName<'static>, Tls13ClientSessionValue)>>,
    inserts_tls13: AtomicUsize,
    takes_tls13: AtomicUsize,
}

impl fmt::Debug for CountingStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CountingStore")
            .field("inserts_tls13", &self.inserts_tls13.load(Ordering::SeqCst))
            .field("takes_tls13", &self.takes_tls13.load(Ordering::SeqCst))
            .finish()
    }
}

impl CountingStore {
    fn new() -> Self {
        Self {
            tls13: Mutex::new(Vec::new()),
            inserts_tls13: AtomicUsize::new(0),
            takes_tls13: AtomicUsize::new(0),
        }
    }
}

impl ClientSessionStore for CountingStore {
    fn set_kx_hint(&self, _server_name: ServerName<'static>, _group: NamedGroup) {}

    fn kx_hint(&self, _server_name: &ServerName<'_>) -> Option<NamedGroup> { None }

    fn set_tls12_session(&self, _server_name: ServerName<'static>, _value: Tls12ClientSessionValue) {}

    fn tls12_session(&self, _server_name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> { None }

    fn remove_tls12_session(&self, _server_name: &ServerName<'static>) {}

    fn insert_tls13_ticket(&self, server_name: ServerName<'static>, value: Tls13ClientSessionValue) {
        self.inserts_tls13.fetch_add(1, Ordering::SeqCst);
        self.tls13.lock().unwrap().push((server_name, value));
    }

    fn take_tls13_ticket(&self, server_name: &ServerName<'static>) -> Option<Tls13ClientSessionValue> {
        let mut tls13 = self.tls13.lock().unwrap();
        let pos = tls13.iter().position(|(n, _)| n == server_name)?;
        let v = tls13.remove(pos).1;
        self.takes_tls13.fetch_add(1, Ordering::SeqCst);
        Some(v)
    }
}

fn mint_self_signed() -> (
    rcgen::Certificate,
    rustls::pki_types::CertificateDer<'static>,
    PrivatePkcs8KeyDer<'static>,
    RootCertStore,
) {
    let key_pair = rcgen::KeyPair::generate().expect("keypair");
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .expect("cert params")
        .self_signed(&key_pair)
        .expect("self-signed");
    let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = PrivatePkcs8KeyDer::from(key_pair.serialize_der());

    let mut roots = RootCertStore::empty();
    roots.add(cert_der.clone()).expect("add self-signed cert as root");
    (cert, cert_der, key_der, roots)
}

fn build_test_client_config(roots: RootCertStore, counting: Arc<CountingStore>) -> Arc<ClientConfig> {
    let mut config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    // No ALPN — the test server doesn't speak HTTP, just raw TLS.
    config.resumption = Resumption::store(counting);
    Arc::new(config)
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

/// Run a tiny rustls echo server on `localhost:port`. Accepts exactly
/// `n_handshakes` connections, completes the handshake on each, sends one
/// "hi" line, and closes. Stays alive until the last connection is served.
fn run_server(port: u16, n_handshakes: usize, server_config: Arc<ServerConfig>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind");
        for _ in 0..n_handshakes {
            let (mut sock, _peer) = listener.accept().expect("accept");
            sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
            let mut srv = ServerConnection::new(Arc::clone(&server_config)).expect("server conn");
            // Drive handshake to completion via complete_io.
            srv.complete_io(&mut sock).expect("server complete_io");
            srv.writer().write_all(b"hi\n").expect("server write");
            srv.complete_io(&mut sock).expect("server complete_io flush");
            let mut close_buf = [0u8; 64];
            let _ = sock.read(&mut close_buf);
        }
    })
}

fn drive_client_handshake(stream: &mut RustlsStream) {
    // Force the lazy TLS handshake by writing zero bytes via a flush, then
    // reading the server's "hi\n" greeting which finalizes the handshake on
    // both sides.
    stream.flush().expect("client flush");
    let mut buf = [0u8; 8];
    let n = stream.read(&mut buf).expect("client read");
    assert!(n > 0, "expected greeting");
}

fn pick_port() -> u16 {
    // Bind to :0, read the assigned port, drop the listener so the test
    // server can immediately rebind.
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("port pick");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

#[test]
fn shared_arc_clientconfig_enables_session_resumption() {
    // rustls 0.22 uses ring as the implicit crypto provider via the
    // default ClientConfig::builder(); no install_default() needed.

    let (_cert, cert_der, key_der, roots) = mint_self_signed();
    let server_config = build_test_server_config(cert_der, key_der);

    let counting = Arc::new(CountingStore::new());
    let client_config = build_test_client_config(roots, Arc::clone(&counting));

    let port = pick_port();
    let server = run_server(port, 2, server_config);

    // Give the server a moment to bind. (TcpListener::bind in the spawned
    // thread can race with the client's connect; a tiny sleep avoids
    // flake without adding bespoke synchronization.)
    thread::sleep(Duration::from_millis(50));

    // First handshake: full handshake. The server should issue a session
    // ticket which our CountingStore records via insert_tls13_ticket.
    let mut stream1 =
        tls_connect_with_config("localhost", port, Arc::clone(&client_config)).expect("first connect");
    drive_client_handshake(&mut stream1);
    drop(stream1);

    // Second handshake: with the same Arc<ClientConfig>, the cache is
    // populated, so take_tls13_ticket should produce the ticket from the
    // first handshake and the client offers PSK resumption.
    let mut stream2 =
        tls_connect_with_config("localhost", port, Arc::clone(&client_config)).expect("second connect");
    drive_client_handshake(&mut stream2);
    drop(stream2);

    server.join().expect("server thread");

    let inserts = counting.inserts_tls13.load(Ordering::SeqCst);
    let takes = counting.takes_tls13.load(Ordering::SeqCst);
    assert!(inserts >= 1, "expected first handshake to populate cache (inserts={inserts}, takes={takes})",);
    assert!(
        takes >= 1,
        "expected second handshake to consume a ticket from cache (inserts={inserts}, takes={takes}). \
         If this fails, Stage 0's shared-Arc invariant is broken — the second handshake's ClientConfig \
         is not the one that received the first handshake's ticket.",
    );
}
