//! Xous Signal app (`xas`) binary entry point.
//!
//! Sits at the top of the crate stack. From bottom to top:
//!
//! - `xous-net-bridge` — sync TLS + WSS + HTTPS transport, owns the `Arc<ClientConfig>` for TLS-1.3 ticket
//!   resumption.
//! - `presage-store-pddb` — `presage::Store` impl backed by Xous's PDDB (real) or an in-memory mock (hosted).
//! - `xous-signal-worker` — owns the `presage::Manager` on a dedicated worker thread driven by
//!   `smol-rs::LocalExecutor`, exposes a [`Cmd`] / [`Event`] async-channel surface.
//! - This crate — UI (`gam_app::App`, on hardware and hosted-Xous emulation) wired to the worker via the two
//!   channels.
//!
//! The startup sequence is:
//!
//! 1. Wire up the rv32 TRNG-backed `getrandom` shim if compiling for Xous; on hosted the OS RNG is used.
//! 2. Construct a [`PddbStore`] (mock backend on hosted; real PDDB behind the `pddb-backend` feature).
//! 3. Spawn [`run_signal_worker`].
//! 4. Hand the cmd/event channels to the UI and run.
//! 5. The UI sends [`Cmd::Shutdown`] on quit; the worker drains and emits `Event::ShuttingDown`.
//!
//! See `docs/ARCHITECTURE.md` for the full data-flow walkthrough;
//! `gam_app.rs`'s module docs describe the screens.

mod dialogue;
mod gam_app;
mod log_filter;
mod store;

use async_channel::bounded;
use presage_store_pddb::PddbStore;
use xous_signal_worker::{Cmd, Event, run_signal_worker};

/// `__getrandom_v03_custom` implementation backed by xous-core's
/// TRNG service.
///
/// Looks up the TRNG SID via `xous-api-names`, then calls
/// `Trng::fill_buf`. `fill_buf` takes `&mut [u32]` so this shim
/// casts from `*mut u8` to a `[u32; 1020]` scratch buffer, copies
/// the filled bytes back to `dest`, and handles a possible odd
/// tail (`len % 4 != 0`) with one final 1-word read.
///
/// The signature mirrors `getrandom::backends::custom`. A
/// thread-local `Trng` cell preserves the IPC connection across
/// calls so each `getrandom` entry reuses the same SID handshake.
///
/// # Trust boundary
///
/// This routes every `getrandom` call from libsignal, rustls, and
/// the rest of the dependency tree to the xous-core TRNG service.
/// Everything cryptographic on the device depends on this returning
/// real entropy.
///
/// # Errors
///
/// Returns `getrandom::Error::UNSUPPORTED` if the TRNG IPC call
/// fails. The thread-local `OnceCell` initialization may panic via
/// the inner `expect` if `xous-names` or the TRNG service are
/// unreachable at first use — that is a fatal misconfiguration of
/// the Xous image, not a recoverable runtime condition.
///
/// # Safety
///
/// Implements an `unsafe extern "Rust"` symbol that the
/// `getrandom` crate's custom backend mechanism resolves at link
/// time. Caller (the `getrandom` crate) guarantees `dest` is valid
/// for `len` bytes; this function only writes into `dest[..len]`.
#[cfg(target_os = "xous")]
#[unsafe(no_mangle)]
unsafe extern "Rust" fn __getrandom_v03_custom(dest: *mut u8, len: usize) -> Result<(), getrandom::Error> {
    use std::cell::OnceCell;
    thread_local! {
        static TRNG: OnceCell<trng::Trng> = const { OnceCell::new() };
    }

    if len == 0 {
        return Ok(());
    }

    TRNG.with(|cell| -> Result<(), getrandom::Error> {
        let trng = cell.get_or_init(|| {
            let xns = xous_names::XousNames::new().expect("connect to xous-names");
            trng::Trng::new(&xns).expect("connect to TRNG service")
        });

        // Fill the aligned u32 prefix in chunks of <=1020 words (the
        // max `fill_buf` accepts per call, per `services/trng/src/
        // lib.rs:64`).
        let words = len / 4;
        let mut filled_bytes = 0usize;
        let mut remaining_words = words;
        while remaining_words > 0 {
            let chunk = remaining_words.min(1020);
            let mut buf = [0u32; 1020];
            trng.fill_buf(&mut buf[..chunk]).map_err(|_| getrandom::Error::UNSUPPORTED)?;
            unsafe {
                core::ptr::copy_nonoverlapping(buf.as_ptr() as *const u8, dest.add(filled_bytes), chunk * 4);
            }
            filled_bytes += chunk * 4;
            remaining_words -= chunk;
        }

        // Tail bytes (len not a multiple of 4): pull one extra word
        // and copy the leading bytes.
        let tail = len - filled_bytes;
        if tail > 0 {
            let mut scratch = [0u32; 1];
            trng.fill_buf(&mut scratch).map_err(|_| getrandom::Error::UNSUPPORTED)?;
            unsafe {
                core::ptr::copy_nonoverlapping(scratch.as_ptr() as *const u8, dest.add(filled_bytes), tail);
            }
        }

        Ok(())
    })
}

/// Capacity of the [`Cmd`] and [`Event`] async channels between
/// the UI and the worker.
///
/// Sized for the UI's typical command pattern: a small handful of
/// commands in flight at any time (link, send, sync, account
/// info). The worker drains commands eagerly so back-pressure on
/// the UI side is unlikely on real workloads.
///
/// Capacity tradeoff: the `event_tx` cap bounds how many
/// back-pressured `Event::Message` emissions
/// `xous_signal_worker::manager_task` can buffer before its
/// `event_tx.send(...).await` blocks the worker's receive stream.
/// Too small → an idle or slow UI stalls inbound receive; too large
/// → unbounded memory on a poorly-behaved peer with high message
/// flux. 16 is the negotiated middle: enough for a bursty receive
/// from a chat the user just opened, small enough to keep the
/// post-Drop bare-`String` body exposure window bounded (SecretBox
/// wrapping of message bodies is tracked in issue #37, item 3).
const CHAN_CAP: usize = 16;

/// Construct the [`PddbStore`] the worker will use.
///
/// Selects backend based on feature flags:
///
/// - default (hosted / smoke / probe-flow / probe-pddb): in-memory mock backend.
/// - `pddb-real` on rv32-xous: real `PddbStore::with_pddb_backend`. On connect failure (PDDB service not yet
///   up), logs a warning and falls back to mock so the binary still boots.
///
/// # Trust boundary
///
/// The returned [`PddbStore`] is the only persistence boundary for
/// Signal-Protocol state. The mock backend is plaintext and is for
/// hosted / probe builds only — production images must be built
/// with `pddb-real` enabled.
#[cfg(feature = "pddb-real")]
fn build_store() -> PddbStore {
    match PddbStore::with_pddb_backend() {
        Ok(s) => {
            log::info!("xas: store=PDDB (real)");
            s
        }
        Err(e) => {
            log::warn!("xas: PDDB connect failed ({}); falling back to mock", e);
            PddbStore::with_mock_backend()
        }
    }
}

/// Mock-backend variant of [`build_store`] for builds without the
/// `pddb-real` feature.
///
/// # Security
///
/// The mock backend keeps every store byte in plaintext RAM —
/// suitable only for hosted-mode iteration and the Renode-driven
/// probe binaries. Never select this variant for a binary intended
/// to hold real registration data.
#[cfg(not(feature = "pddb-real"))]
fn build_store() -> PddbStore {
    log::info!("xas: store=mock");
    PddbStore::with_mock_backend()
}

fn main() -> std::io::Result<()> {
    init_logger();
    log::info!("xas: starting");

    let store = build_store();

    let (cmd_tx, cmd_rx) = bounded::<Cmd>(CHAN_CAP);
    let (event_tx, event_rx) = bounded::<Event>(CHAN_CAP);

    let worker = run_signal_worker(store, cmd_rx, event_tx);
    log::info!("xas: worker started");

    #[cfg(feature = "probe-flow")]
    probe_network();

    #[cfg(all(feature = "probe-pddb", target_os = "xous"))]
    probe_pddb();

    #[cfg(all(feature = "probe-send-batch", target_os = "xous"))]
    probe_send_batch();

    #[cfg(feature = "probe-echo")]
    probe_echo();

    // NOTE: load-bearing — there is no `probe-pddb-real` or
    // `probe-bulk-ab` auto-fire probe here. Calling
    // `presage_store_pddb::PddbBackend::connect()` immediately after
    // `run_signal_worker()` races xous-names server registration
    // during boot and triggers a `ServerNotFound` cascade in
    // unrelated services (llio, trng, modals, susres), which can
    // crash the boot via a watchdog reboot loop. xous-names itself
    // documents this race (`api/xous-api-names/src/lib.rs`).
    //
    // Bulk-write A/B benchmarking lives in shellchat as `pddb
    // bulk_probe [N]`, exercised by the user after PIN entry and
    // PDDB mount.

    // PDDB put-truncate smoke test (refs #14). Runtime-gated; exits
    // 0 PASS / 1 FAIL so a shell wrapper can assert the regression.
    #[cfg(feature = "pddb-real")]
    if std::env::var("XAS_PDDB_TRUNCATE_TEST").is_ok() {
        let backend = match presage_store_pddb::PddbBackend::connect() {
            Ok(b) => b,
            Err(e) => {
                log::error!("XAS_PDDB_TRUNCATE_TEST: connect: {}", e);
                std::process::exit(1);
            }
        };
        if !backend.is_mounted() {
            match backend.try_mount() {
                Ok(true) => {}
                Ok(false) => {
                    log::error!("XAS_PDDB_TRUNCATE_TEST: try_mount declined");
                    std::process::exit(1);
                }
                Err(e) => {
                    log::error!("XAS_PDDB_TRUNCATE_TEST: try_mount: {}", e);
                    std::process::exit(1);
                }
            }
        }
        let result = presage_store_pddb::smoke_put_truncates(&backend);
        log::info!("XAS_PDDB_TRUNCATE_TEST: {:?}", result);
        match result {
            presage_store_pddb::SmokeResult::Pass => std::process::exit(0),
            _ => std::process::exit(1),
        }
    }

    // Run as a GAM-rendered Xous app (hosted Xous emulation or rv32
    // hardware). Requires a reachable Xous environment; a bare
    // `cargo run` outside Xous errors out here.
    gam_app::run(cmd_tx, event_rx).map_err(std::io::Error::other)?;

    // Worker has been told to shut down; join it. If the join hangs
    // it's a worker-side bug — surface as a nonzero exit, not a
    // silent hang.
    let _ = worker.join();
    log::info!("xas: exiting");
    Ok(())
}

/// Install a `log` implementation for hosted builds.
///
/// Uses `env_logger` with a default `info` filter. Errors from
/// `try_init` are ignored (it returns `Err` if the logger has
/// already been installed, e.g. by a test harness).
#[cfg(not(target_os = "xous"))]
fn init_logger() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).try_init();
}

/// TCP-connect probe verifying Renode's WF200 wifi emulation
/// carries outbound traffic.
///
/// Three connect targets, each logged with elapsed time and
/// result:
///
/// 1. `8.8.8.8:53` — Google DNS over TCP. No DNS lookup needed; answers "is there any route to the internet".
/// 2. `1.1.1.1:443` — Cloudflare HTTPS. Same shape as (1) but a different provider, in case route filtering
///    is in play.
/// 3. `chat.signal.org:443` — the real Signal endpoint. Requires DNS, so this also exercises the Xous `dns`
///    service.
///
/// Each probe has a 10-second timeout. Output goes to the same
/// `INFO:xas:` stream the Robot smoke tests assert on.
#[cfg(feature = "probe-flow")]
fn probe_network() {
    use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
    use std::time::{Duration, Instant};

    log::info!("probe: starting network reachability probe");

    let timeout = Duration::from_secs(10);

    // (label, hostport, requires_dns)
    let probes: &[(&str, &str, bool)] = &[
        ("google-dns", "8.8.8.8:53", false),
        ("cloudflare-https", "1.1.1.1:443", false),
        ("signal-prod", "chat.signal.org:443", true),
    ];

    for (label, target, _needs_dns) in probes {
        let start = Instant::now();
        let addrs: Result<Vec<SocketAddr>, _> = target.to_socket_addrs().map(|i| i.collect());
        match addrs {
            Err(e) => {
                log::warn!("probe: {} resolve FAIL after {:?}: {}", label, start.elapsed(), e);
                continue;
            }
            Ok(addrs) if addrs.is_empty() => {
                log::warn!("probe: {} resolve EMPTY after {:?}", label, start.elapsed());
                continue;
            }
            Ok(addrs) => {
                let addr = addrs[0];
                match TcpStream::connect_timeout(&addr, timeout) {
                    Ok(_stream) => {
                        log::info!("probe: {} CONNECT OK to {} after {:?}", label, addr, start.elapsed());
                    }
                    Err(e) => {
                        log::warn!(
                            "probe: {} CONNECT FAIL to {} after {:?}: {}",
                            label,
                            addr,
                            start.elapsed(),
                            e
                        );
                    }
                }
            }
        }
    }

    log::info!("probe: network probe done");
}

/// In-image TCP echo probe — the first renode assertion where the
/// network stack must actually WORK, not merely fail cleanly.
///
/// Spawns a `std::net::TcpListener` echo server on `127.0.0.1:7777`
/// in one thread, then drives four client cases against it, one
/// connection each:
///
/// 1. `msg-1`..`msg-3` — three short patterned messages, sequential write-then-read (payloads are far below
///    the net service's per-socket 1530-byte (`NET_MTU`) rx/tx buffers, so no interleaving is needed).
/// 2. `bulk-8k` — one 8192-byte position-derived pattern, STREAMED: a writer thread pushes while the probe
///    thread reads the echo concurrently, sharing the socket via `impl Read/Write for &TcpStream`. 8 KiB
///    exceeds the sum of all four in-path smoltcp socket buffers (4 x 1530 B), so a blind `write_all` before
///    the first read would deadlock on echo back-pressure; concurrent one-socket rx/tx from two threads is
///    also exactly the shape `xous-net-bridge::ws_pump` uses in production.
///
/// The client side is `std::net::TcpStream` directly, not
/// `xous-net-bridge`: every bridge entry point is TLS-fused (no
/// plain-TCP path until the issue #39 open/pump split), and the
/// point of this stage is the on-target `std::net` → services/net →
/// smoltcp path, which is byte-identical for the bridge once it
/// opens its socket.
///
/// Sentinel grammar (asserted by `xas-echo.robot`):
/// `XAS-ECHO: <name> PASS|FAIL ...` per case, then
/// `XAS-ECHO DONE: pass=N fail=M`.
///
/// Kernel-image requirement: net service built with
/// `net/renode-minimal` (xous-core branch `xas-integration-net`).
/// smoltcp only gains its `127.0.0.1/8` interface address when an
/// IPv4 config is applied (`WlanIpConfigUpdate` path), which never
/// happens on the closed renode switch — the feature seeds a static
/// config at boot through the same handler.
#[cfg(feature = "probe-echo")]
fn probe_echo() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Instant;

    const ECHO_ADDR: &str = "127.0.0.1:7777";

    log::info!("probe-echo: starting in-image TCP echo probe on {}", ECHO_ADDR);

    // Deterministic case payloads. The bulk pattern is derived from the
    // byte position so truncation, reordering, and offset errors all
    // show up as a first-differing-offset, with no RNG dependency.
    let bulk: Vec<u8> = (0..8192usize).map(|i| (i.wrapping_mul(31).wrapping_add(7) & 0xff) as u8).collect();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("msg-1", b"xas-echo-1: the quick brown fox jumps over the lazy dog".to_vec()),
        ("msg-2", b"xas-echo-2: 0123456789 abcdefghijklmnopqrstuvwxyz".to_vec()),
        ("msg-3", b"xas-echo-3: ZYXWVUTSRQPONMLKJIHGFEDCBA 9876543210".to_vec()),
        ("bulk-8k", bulk),
    ];
    let case_count = cases.len();

    let listener = match TcpListener::bind(ECHO_ADDR) {
        Ok(l) => l,
        Err(e) => {
            for (name, _) in &cases {
                log::warn!("XAS-ECHO: {} FAIL (listener bind: {})", name, e);
            }
            log::info!("XAS-ECHO DONE: pass=0 fail={}", case_count);
            return;
        }
    };

    // Echo server: accept connections until the process exits, echoing
    // each until EOF. The accept loop is deliberately unbounded — the
    // warm-up below consumes a nondeterministic number of connections —
    // so this thread parks in accept() forever once the probe is done.
    // One leaked parked thread in a probe-only build, never joined.
    std::thread::spawn(move || {
        loop {
            let (mut sock, peer) = match listener.accept() {
                Ok(a) => a,
                Err(e) => {
                    log::warn!("probe-echo: server accept failed: {}", e);
                    return;
                }
            };
            log::info!("probe-echo: server accepted conn from {}", peer);
            // NO read timeout on the server socket, and that is load-bearing:
            // the net service's rx pump checks a blocked read's expiry
            // BEFORE its CloseWait/Closed remote-hangup branch, so a read
            // that carries a timeout is never woken early by the peer's
            // FIN — it sleeps until the timer fires and only then reports
            // EOF. With a timeout here, every client close would stall
            // this single-threaded loop on the dead connection for the
            // full ECHO_IO_TIMEOUT, serializing the next case behind it
            // and starving that case past its own client-side read budget
            // (observed on target: warm-up passes, then every real case
            // times out). A timeout-less read IS woken promptly on
            // CloseWait and returns Ok(0). A wedged connection is still
            // bounded: every case's CLIENT socket carries
            // ECHO_IO_TIMEOUT, so the case FAILs its sentinel and the
            // robot aborts instead of hanging.
            let _ = sock.set_write_timeout(Some(ECHO_IO_TIMEOUT));
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf) {
                    // Client closed: this connection is done.
                    Ok(0) => {
                        log::info!("probe-echo: server conn from {} closed (EOF)", peer);
                        break;
                    }
                    Ok(n) => {
                        if let Err(e) = sock.write_all(&buf[..n]) {
                            log::warn!("probe-echo: server echo write failed: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        log::warn!("probe-echo: server read failed: {}", e);
                        break;
                    }
                }
            }
        }
    });

    // Warm-up: the probe fires right after worker spawn, which can race
    // the net service's renode-minimal static-IPv4 seed (until the seed
    // lands, smoltcp has no 127.0.0.1/8 address and loopback connects
    // fail fast with no route/address). Retry a throwaway connect until
    // the stack carries one, then run the real cases.
    let warmup_start = Instant::now();
    let mut stack_ready = false;
    while warmup_start.elapsed() < ECHO_WARMUP_BUDGET {
        match run_echo_case(ECHO_ADDR, b"xas-echo-warmup") {
            Ok(()) => {
                stack_ready = true;
                log::info!("probe-echo: stack ready after {:?}", warmup_start.elapsed());
                break;
            }
            Err(e) => {
                log::debug!("probe-echo: warm-up not ready ({}); retrying", e);
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
    }
    if !stack_ready {
        log::warn!("probe-echo: stack not ready after {:?}", warmup_start.elapsed());
    }

    let mut pass = 0usize;
    let mut fail = 0usize;
    for (name, payload) in &cases {
        let start = Instant::now();
        match run_echo_case(ECHO_ADDR, payload) {
            Ok(()) => {
                pass += 1;
                log::info!(
                    "XAS-ECHO: {} PASS ({} bytes round-trip in {:?})",
                    name,
                    payload.len(),
                    start.elapsed()
                );
            }
            Err(e) => {
                fail += 1;
                log::warn!("XAS-ECHO: {} FAIL ({})", name, e);
            }
        }
    }

    log::info!("XAS-ECHO DONE: pass={} fail={}", pass, fail);
}

/// How long [`probe_echo`] retries its warm-up connect before giving
/// up on the network stack coming ready. Boot-order slack only; on a
/// healthy renode-minimal image the first or second attempt lands.
#[cfg(feature = "probe-echo")]
const ECHO_WARMUP_BUDGET: std::time::Duration = std::time::Duration::from_secs(90);

/// Per-call I/O bound for [`probe_echo`]'s CLIENT sockets (and the
/// server's echo writes): generous next to loopback latency, small
/// next to the robot's virtual-time budget, so a wedged case FAILs
/// its sentinel instead of eating the wall-clock cap. Deliberately
/// NOT applied to the server's reads — see the comment at the accept
/// loop: a timeout'd read is never woken early by a remote close, so
/// it would stall the loop for the full bound after every case.
#[cfg(feature = "probe-echo")]
const ECHO_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// One [`probe_echo`] client case: connect to `addr`, stream
/// `payload` from a writer thread while this thread reads the echo,
/// and verify the round-trip byte-exact.
///
/// The socket is shared between the two threads as `&TcpStream`
/// through an `Arc` (std implements `Read`/`Write` on the
/// reference), avoiding `try_clone()` — same sharing model
/// `xous-net-bridge` uses. Dropping both `Arc`s closes the socket,
/// which is the echo server's end-of-case signal.
#[cfg(feature = "probe-echo")]
fn run_echo_case(addr: &str, payload: &[u8]) -> Result<(), String> {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::sync::Arc;

    let addr: SocketAddr = addr.parse().map_err(|e| format!("addr parse: {}", e))?;
    let stream = TcpStream::connect_timeout(&addr, ECHO_IO_TIMEOUT).map_err(|e| format!("connect: {}", e))?;
    stream.set_read_timeout(Some(ECHO_IO_TIMEOUT)).map_err(|e| format!("set_read_timeout: {}", e))?;
    stream.set_write_timeout(Some(ECHO_IO_TIMEOUT)).map_err(|e| format!("set_write_timeout: {}", e))?;

    let stream = Arc::new(stream);
    let writer_stream = Arc::clone(&stream);
    let to_send = payload.to_vec();
    let writer = std::thread::spawn(move || -> Result<(), String> {
        (&*writer_stream).write_all(&to_send).map_err(|e| format!("write: {}", e))
    });

    let mut echoed = vec![0u8; payload.len()];
    let read_res = (&*stream).read_exact(&mut echoed).map_err(|e| format!("read: {}", e));
    let write_res = writer.join().map_err(|_| "writer thread panicked".to_string())?;
    write_res?;
    read_res?;

    if echoed != payload {
        let first_bad = echoed.iter().zip(payload.iter()).position(|(a, b)| a != b);
        return Err(format!(
            "payload mismatch ({} bytes, first differing offset {:?})",
            payload.len(),
            first_bad
        ));
    }
    Ok(())
}

/// Poll xous-core's PDDB Mount Poller via raw `xous` IPC and log
/// the result.
///
/// Mirrors `services/pddb/src/lib.rs`'s `PddbMountPoller::new` +
/// `is_mounted_nonblocking`, but depends only on `xous`,
/// `xous-api-names`, and `xous_ipc` (the same crate set the TRNG
/// shim already pulls in). The Mount Poller's `Poll` opcode (0) is
/// the simplest IPC roundtrip xas can do against PDDB: no payload,
/// returns a `Scalar1(0|1)` mount state.
///
/// Outcomes:
/// - `OK true` / `OK false` — IPC plumbing works; the value indicates whether the image auto-mounts or
///   expects password-driven mount.
/// - `connection refused` / no response — protocol drift (rkyv version, Buffer layout, or SID name mismatch).
#[cfg(all(feature = "probe-pddb", target_os = "xous"))]
fn probe_pddb() {
    use std::time::Instant;

    use xous::{Message, send_message};

    log::info!("probe-pddb: starting PDDB mount-poller probe");
    let start = Instant::now();

    let xns = match xous_names::XousNames::new() {
        Ok(x) => x,
        Err(e) => {
            log::warn!("probe-pddb: XousNames::new FAIL: {:?}", e);
            return;
        }
    };

    // SID name copied from `services/pddb/src/api.rs:19`. If this
    // doesn't match the running PDDB server's registered SID,
    // request_connection_blocking will block forever — which is
    // why this probe runs after the smoke boot lines, on a path
    // the Robot test can time out on.
    let conn = match xns.request_connection_blocking("_PDDB Mount Poller_") {
        Ok(c) => c,
        Err(e) => {
            log::warn!("probe-pddb: request_connection FAIL after {:?}: {:?}", start.elapsed(), e);
            return;
        }
    };
    log::info!("probe-pddb: connected to PDDB Mount Poller in {:?}", start.elapsed());

    // PollOp::Poll = 0, per `services/pddb/src/api.rs` PollOp enum.
    // Args are all unused (server reads only the opcode).
    let poll_start = Instant::now();
    let resp = send_message(conn, Message::new_blocking_scalar(0, 0, 0, 0, 0));
    match resp {
        Ok(xous::Result::Scalar1(v)) => {
            log::info!("probe-pddb: Poll OK is_mounted={} after {:?}", v != 0, poll_start.elapsed());
        }
        Ok(other) => {
            log::warn!("probe-pddb: Poll unexpected response {:?} after {:?}", other, poll_start.elapsed());
        }
        Err(e) => {
            log::warn!("probe-pddb: Poll FAIL after {:?}: {:?}", poll_start.elapsed(), e);
        }
    }

    log::info!("probe-pddb: probe done in {:?}", start.elapsed());
}

/// Exercise [`presage_store_pddb::BufferingBackend`] +
/// [`presage_store_pddb::KvBackend`] semantics against a fresh
/// [`presage_store_pddb::MockBackend`] and log UART lines for the
/// `xas-send-batch.robot` Renode test.
///
/// Uses [`presage_store_pddb::MockBackend`] rather than the real
/// PDDB because the real backend cannot mount inside Renode
/// (`Opcode::TryMount` requires rootkeys + password modal that
/// Renode does not inject). The wrapper's batching semantics are
/// the same regardless of inner backend; this probe adds rv32
/// build + boot + run coverage on top of the host-side
/// `cargo test -p presage-store-pddb` suite.
///
/// Synthetic send-shaped sequence:
///
/// 1. Wrap a fresh `MockBackend` in a `BufferingBackend`.
/// 2. `begin_batch` and confirm `is_batching` flips.
/// 3. Three writes simulating a cold send (recipient identity, sender certificate, outbound message body).
/// 4. Intra-batch read-through (writes visible inside the batch).
/// 5. Commit; confirm the replay count.
/// 6. Post-commit reads (writes durable in the inner backend).
/// 7. Abort path: open a second batch, write, drop without committing, verify the writes are gone.
#[cfg(all(feature = "probe-send-batch", target_os = "xous"))]
fn probe_send_batch() {
    use std::sync::Arc;
    use std::time::Instant;

    use presage_store_pddb::{BufferingBackend, KvBackend, MockBackend};

    log::info!("probe-send-batch: starting");
    let start = Instant::now();

    let backend = BufferingBackend::new(Arc::new(MockBackend::new()));
    log::info!("probe-send-batch: backend constructed");

    // --- 1. Begin a batch.
    let guard = match backend.begin_batch() {
        Ok(g) => g,
        Err(e) => {
            log::warn!("probe-send-batch: FAIL: begin_batch error: {}", e);
            return;
        }
    };
    if !backend.is_batching() {
        log::warn!("probe-send-batch: FAIL: is_batching false after begin");
        return;
    }
    log::info!("probe-send-batch: batch begin OK in {:?}", start.elapsed());

    // --- 2. Three writes simulating a cold-send protocol-store
    //        update.
    let phase = Instant::now();
    backend.put("signal.protocol.aci.identity", "peer.1", b"identity-bytes").unwrap();
    backend.put("signal.state", "sender_certificate", b"sender-cert-bytes").unwrap();
    backend.put("signal.contents.thread.peer", "00000000000186A0", b"hello world").unwrap();
    let buffered = guard.buffered_len();
    log::info!("probe-send-batch: 3 writes buffered in {:?} (count={})", phase.elapsed(), buffered);
    if buffered != 3 {
        log::warn!("probe-send-batch: FAIL: expected 3 buffered, got {}", buffered);
        return;
    }

    // --- 3. Intra-batch read-through.
    let read = backend.get("signal.protocol.aci.identity", "peer.1").unwrap();
    if read.as_deref() != Some(b"identity-bytes".as_slice()) {
        log::warn!("probe-send-batch: FAIL: intra-batch read mismatch");
        return;
    }
    log::info!("probe-send-batch: intra-batch read-through OK");

    // --- 4. Commit.
    let phase = Instant::now();
    let n = match guard.commit() {
        Ok(n) => n,
        Err(e) => {
            log::warn!("probe-send-batch: FAIL: commit error: {}", e);
            return;
        }
    };
    if backend.is_batching() {
        log::warn!("probe-send-batch: FAIL: still batching after commit");
        return;
    }
    log::info!("probe-send-batch: commit OK in {:?} (replayed {})", phase.elapsed(), n);

    // --- 5. Post-commit reads.
    let r1 = backend.get("signal.protocol.aci.identity", "peer.1").unwrap();
    let r2 = backend.get("signal.state", "sender_certificate").unwrap();
    let r3 = backend.get("signal.contents.thread.peer", "00000000000186A0").unwrap();
    if r1.as_deref() != Some(b"identity-bytes".as_slice())
        || r2.as_deref() != Some(b"sender-cert-bytes".as_slice())
        || r3.as_deref() != Some(b"hello world".as_slice())
    {
        log::warn!("probe-send-batch: FAIL: post-commit read mismatch");
        return;
    }
    log::info!("probe-send-batch: post-commit reads match");

    // --- 6. Abort path: open a second batch, write, drop without
    //        commit, verify nothing landed.
    {
        let _abort_guard = backend.begin_batch().unwrap();
        backend.put("signal.state", "sender_certificate", b"transient-cert").unwrap();
        // _abort_guard drops at end of block without commit -> abort.
    }
    let after_abort = backend.get("signal.state", "sender_certificate").unwrap();
    if after_abort.as_deref() != Some(b"sender-cert-bytes".as_slice()) {
        log::warn!("probe-send-batch: FAIL: abort didn't restore inner ({:?})", after_abort);
        return;
    }
    log::info!("probe-send-batch: abort path OK");

    log::info!("probe-send-batch: probe done in {:?}", start.elapsed());
}

/// Install a `log` implementation for rv32-xous builds.
///
/// `xous_api_log::init_wait()` blocks until it can connect to the
/// `xous-log-server` SID, then registers itself as the `log::Log`
/// impl. The server (running as a separate process in the baseline
/// Xous image) forwards records to the UART, which is what the
/// Renode Robot tests assert on.
///
/// If `init_wait` returns `Err` (log server did not come up in
/// time, fatal Xous-image misconfiguration), this function does
/// not panic — subsequent `log::*!` calls become no-ops, matching
/// the surface of a binary that never installed a logger.
#[cfg(target_os = "xous")]
fn init_logger() {
    if crate::log_filter::init().is_err() {
        let _ = xous_api_log::init_wait();
    }
}
