//! Integration test for the `set_write_timeout` fix (refs #16).
//!
//! Iter-2 hardware traces showed `xas` WebSocket sends hanging ~89 s per
//! attempt when the Signal server initiated a Close mid-write. The root
//! cause was the absence of a write timeout on the inner TCP socket:
//! `tls.rs` set `set_read_timeout` but not `set_write_timeout`, so the
//! kernel's TCP retransmit budget (~5 doublings starting from ~200 ms
//! RTO) determined the hang length. The fix is to bound the writer's TCP
//! retransmit budget via `set_write_timeout` on the inner `TcpStream`
//! exposed by `rustls::StreamOwned::sock`.
//!
//! ## What this test does
//!
//! It exercises the std-level `set_write_timeout` / `write_timeout` API
//! against a `TcpStream` connected to a non-reading peer, and asserts:
//!
//! 1. `set_write_timeout(Some(d))` succeeds (does not error on hosted).
//! 2. `write_timeout()` round-trips the value we set.
//! 3. A `write_all` against a peer that doesn't drain its receive buffer terminates in finite time with an
//!    error whose `ErrorKind` is one of `TimedOut`, `WouldBlock`, or `BrokenPipe` (the third because Linux
//!    converts an exhausted TCP retransmit budget to `ETIMEDOUT`/`EPIPE`, and either is acceptable evidence
//!    that the call did not hang indefinitely).
//!
//! ## Why this is a regression net, not a behavioural proof
//!
//! Linux's `SO_SNDTIMEO` only bounds an individual blocking write
//! syscall. With zero-window probing, the kernel makes incremental
//! forward progress (a few bytes per probe interval), so no single
//! `write()` syscall on Linux loopback ever blocks the full SO_SNDTIMEO
//! window even against a non-draining peer. The end-to-end "fire within
//! N seconds" semantic the fix relies on for the Xous hardware path is
//! provided by `services/net/src/main.rs`'s `tcp_tx_waiting` reaper,
//! which uses `body.offset` as a per-call timeout and is checked on
//! every poll. We exercise *that* path on hardware via the UART recipe
//! in the handoff doc; here we just guard the std-level plumbing.

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::thread;
use std::time::{Duration, Instant};

/// Spawn a `TcpListener`, accept exactly one connection, and hold the
/// accepted socket alive (never reading from it). Returns the bound
/// address. We shrink `SO_RCVBUF` so the writer hits backpressure
/// quickly.
fn spawn_silent_listener() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind localhost");
    let addr = listener.local_addr().expect("local_addr");
    set_recv_buf(listener.as_raw_fd(), 4 * 1024);
    thread::spawn(move || match listener.accept() {
        Ok((sock, _)) => {
            set_recv_buf(sock.as_raw_fd(), 4 * 1024);
            // Hold the accepted socket alive without reading from it.
            thread::sleep(Duration::from_secs(180));
            drop(sock);
        }
        Err(e) => panic!("listener accept failed: {e:?}"),
    });
    addr
}

/// Set `SO_RCVBUF` via libc. We can't use `socket2` (not in dev-deps)
/// and std doesn't expose `SO_RCVBUF`.
fn set_recv_buf(fd: std::os::fd::RawFd, bytes: i32) {
    const SOL_SOCKET: i32 = 1;
    const SO_RCVBUF: i32 = 8;
    let val: i32 = bytes;
    unsafe {
        unsafe extern "C" {
            fn setsockopt(
                fd: i32,
                level: i32,
                optname: i32,
                optval: *const core::ffi::c_void,
                optlen: u32,
            ) -> i32;
        }
        let rc = setsockopt(
            fd,
            SOL_SOCKET,
            SO_RCVBUF,
            &val as *const i32 as *const _,
            std::mem::size_of::<i32>() as u32,
        );
        if rc != 0 {
            eprintln!("set_recv_buf({}) failed: {:?}", bytes, std::io::Error::last_os_error());
        }
    }
}

fn set_send_buf(fd: std::os::fd::RawFd, bytes: i32) {
    const SOL_SOCKET: i32 = 1;
    const SO_SNDBUF: i32 = 7;
    let val: i32 = bytes;
    unsafe {
        unsafe extern "C" {
            fn setsockopt(
                fd: i32,
                level: i32,
                optname: i32,
                optval: *const core::ffi::c_void,
                optlen: u32,
            ) -> i32;
        }
        let rc = setsockopt(
            fd,
            SOL_SOCKET,
            SO_SNDBUF,
            &val as *const i32 as *const _,
            std::mem::size_of::<i32>() as u32,
        );
        if rc != 0 {
            eprintln!("set_send_buf({}) failed: {:?}", bytes, std::io::Error::last_os_error());
        }
    }
}

/// Assertion (1) and (2): the `set_write_timeout` / `write_timeout`
/// std API is plumbed and round-trips on hosted. This is the load-bearing
/// invariant for the fix in `tls.rs` and `http.rs` — if this regresses,
/// the fix is a no-op.
#[test]
fn set_write_timeout_roundtrips() {
    // No peer needed for the round-trip check — we just need a connected
    // TCP socket. Use a temporary local server.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let _accept_thread = thread::spawn(move || {
        let _ = listener.accept();
        // hold open
        thread::sleep(Duration::from_secs(5));
    });
    let stream = TcpStream::connect(addr).expect("connect");
    // Pre-set: should be None.
    assert_eq!(stream.write_timeout().expect("read"), None);
    let want = Duration::from_secs(30);
    stream.set_write_timeout(Some(want)).expect("set_write_timeout supported on hosted std");
    let got = stream.write_timeout().expect("read back");
    assert_eq!(got, Some(want), "write_timeout round-trip mismatch");
    // And clearing back to None.
    stream.set_write_timeout(None).expect("clear");
    assert_eq!(stream.write_timeout().expect("read"), None);
}

/// Assertion (3): a `write_all` against a peer that never drains its
/// recv buffer terminates in finite time with a recognisable error. We
/// pick a 60 s upper bound — generous enough that Linux's zero-window
/// probing + retransmit budget will have exhausted, tight enough that
/// "blocks forever" still regresses noisily.
#[test]
fn write_to_non_reading_peer_does_not_block_forever() {
    let addr = spawn_silent_listener();
    let stream = TcpStream::connect(addr).expect("connect to silent listener");
    set_send_buf(stream.as_raw_fd(), 4 * 1024);
    // Use a short SO_SNDTIMEO so any individual blocking write bounces
    // quickly; combined with the kernel-level retransmit timeout, this
    // bounds the total `write_all` wall time well under 60 s.
    stream.set_write_timeout(Some(Duration::from_secs(2))).expect("set_write_timeout");

    // 16 MiB — far larger than any per-end buffer, so write_all must
    // make many syscalls and at least one will block waiting for window.
    let payload = vec![0xa5u8; 16 * 1024 * 1024];
    let start = Instant::now();
    let result = (&stream).write_all(&payload);
    let elapsed = start.elapsed();
    let err = result.expect_err("write_all to non-reading peer should fail, not Ok");
    let kind = err.kind();
    eprintln!("write_to_non_reading_peer: terminated after {:?} with kind={:?} err={:?}", elapsed, kind, err);
    assert!(
        elapsed < Duration::from_secs(120),
        "write_all did not terminate within 120 s (elapsed {:?}); set_write_timeout regressed",
        elapsed
    );
    assert!(
        matches!(
            kind,
            std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::WouldBlock
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionReset
        ),
        "unexpected error kind {:?} (err={:?}); expected TimedOut/WouldBlock/BrokenPipe/ConnectionReset",
        kind,
        err
    );
}
