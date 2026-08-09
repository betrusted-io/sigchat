//! Real PDDB-backed [`KvBackend`].
//!
//! Wraps `xous_pddb_ipc::PddbClient` (the hand-rolled IPC client;
//! bypasses `services/pddb`'s gen1 dep cascade) and forwards
//! [`KvBackend`] operations to PDDB's wire protocol.
//!
//! # Trust boundary
//!
//! This is the only [`KvBackend`] impl whose `get` returns bytes
//! that have been authenticated by PDDB's per-page AES-256-GCM-SIV
//! before crossing IPC. Successful return from `get` is the trust
//! witness — the bytes are PDDB-decrypted plaintext for the
//! requested `(dict, key)`.
//!
//! `put` returns `Ok(())` after the PDDB server has run a basis
//! sync, so the write is durable across power-loss when `put`
//! returns successfully.
//!
//! # Security
//!
//! Bytes crossing this trait do **not** carry an additional MAC at
//! this layer. The single trust boundary is PDDB's encryption. A
//! caller who passes attacker-controlled bytes to `put` will have
//! those bytes authenticated by PDDB and returned verbatim by a
//! later `get` — i.e. attacker control of writes results in
//! attacker control of reads. The store-trait impls
//! (`SessionStore`, `IdentityKeyStore`, etc.) are responsible for
//! distinguishing "PDDB returned exactly the bytes I wrote" from
//! "the value was signed by the source I expected" — typically by
//! routing through libsignal's own `Record::deserialize` step,
//! which validates protobuf framing and key encodings.
//!
//! The `tracing::info!` perf events emitted by every method carry
//! the `(dict, key)` pair and value/result lengths only — never
//! value bytes. `dict` and `key` are non-secret in the cryptographic
//! sense, but for the protocol stores (`signal.protocol.aci.session`,
//! `signal.protocol.aci.identity`, etc.) the `key` is derived from
//! the peer's `ProtocolAddress.name()`, i.e. the peer's ACI UUID —
//! same privacy class as the other per-message identifiers
//! logged per receive. Key names therefore go through
//! [`crate::redact::log_id`]: last-4 by default, full under the
//! `verbose-pii` feature. Dict names are logged in full — they are
//! fixed schema names or thread-hash digests, not identifiers.
//!
//! # rv32 / 16 MiB constraint
//!
//! Each `get`/`put`/`delete` is one PDDB IPC. The expensive
//! component is the server-side basis sync — PDDB's
//! `Opcode::WriteKey` handler runs `basis_cache.sync(...)` after
//! every key_update. [`put_batch`](Self::put_batch) collapses N
//! writes into one trailing sync via the `WriteKeyBatch` opcode;
//! [`crate::BufferingBackend`] exists primarily to drive that path.
//!
//! Behavior:
//!
//! - `get` opens with `create_dict=false, create_key=false` and reads the whole key into a `Vec<u8>`. Returns
//!   `Ok(None)` on `NotFound`, the bytes on `Ok`, error otherwise.
//! - `put` opens with `create_dict=true, create_key=true` and writes the value. No client-side
//!   `flush_writes`: the PDDB server's `Opcode::WriteKey` handler already calls `basis_cache.sync(...)` on
//!   every write (see body for the line-cite), so `WriteKeyFlush` is redundant. Releases the handle on Drop.
//! - `delete` and `delete_dict` are direct opcodes; `NotFound` on delete is mapped to `Ok(())` (idempotent).
//! - `list_keys` calls `KeyCountInDict` + `ListKeyV2` chain, returns `Ok(Vec::new())` if the dict is empty,
//!   `NotFound` -> empty Vec for upstream-compatible behavior.
//!
//! Design notes:
//!
//! - A single `Mutex<PddbClient>` shared via `Arc` across [`crate::PddbStore`] clones (matching the
//!   `PddbStore::clone()` shallow-share contract). The `Mutex` serializes IPC requests; PDDB's server is
//!   itself single-threaded so concurrent requests would queue anyway.
//! - On `is_mounted() == false`, every operation returns `Error::backend("PDDB not mounted")`. The store
//!   layer is expected to surface this as a presage `StoreError` and the caller (worker thread) decides
//!   whether to retry / wait.

#![cfg(feature = "pddb-backend")]

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use xous_pddb_ipc::{ErrorKind as IpcErrorKind, KeyHandle, OpenOptions, PddbClient};

use crate::{Error, KvBackend};

/// Real PDDB-backed [`KvBackend`]. Constructed via
/// [`crate::PddbStore::with_pddb_backend`].
///
/// Holds an `Arc<Mutex<PddbClient>>` so clones share the same IPC
/// connection. The mutex serializes IPCs from this client; the
/// server itself is single-threaded so concurrent IPCs from
/// different connections also queue server-side.
#[derive(Debug)]
pub struct PddbBackend {
    client: Arc<Mutex<PddbClient>>,
}

impl PddbBackend {
    /// Connect to the running PDDB server.
    ///
    /// Does *not* block on PDDB being mounted — that's intentional.
    /// A caller that needs a mounted store should poll
    /// [`is_mounted`](Self::is_mounted) before issuing reads/writes;
    /// otherwise the per-op `NotMounted` error tells them when the
    /// cache is cold.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the server's SID isn't registered (i.e.
    /// PDDB isn't running) or the connection request itself fails.
    pub fn connect() -> Result<Self, Error> {
        PddbClient::new()
            .map(|c| PddbBackend { client: Arc::new(Mutex::new(c)) })
            .map_err(|e| Error::backend(format!("PDDB connect: {}", e)))
    }

    /// Forward to `PddbClient::is_mounted` so callers can pre-check.
    ///
    /// Returns `false` if the IPC mutex is poisoned — same
    /// fail-closed posture as the rest of this impl. The poison case
    /// is masked behind the `false` return: a poisoned mutex signals
    /// that a prior IPC panicked, but the caller cannot distinguish
    /// "PDDB not mounted yet" from "client state suspect" through this
    /// API. The worker (`xous_signal_worker::worker_main`) treats the
    /// two cases identically (poll, retry) so the conservative
    /// fail-closed posture is correct, even if non-obvious. The
    /// underlying [`xous_pddb_ipc::PddbClient::is_mounted`] is itself
    /// non-blocking (single scalar IPC), so polling is cheap.
    /// Currently unused inside this crate; xous-app-signal's
    /// `probe-pddb-real` feature is the expected consumer.
    /// `dead_code` allowed because the method is part of the public
    /// surface, not a private helper.
    #[allow(dead_code)]
    pub fn is_mounted(&self) -> bool {
        match self.client.lock() {
            Ok(g) => g.is_mounted(),
            Err(_) => false,
        }
    }

    /// Trigger an interactive mount. Blocks until the user enters
    /// the password and the mount completes, or the server returns
    /// non-OK.
    ///
    /// **Blocking on user input.** This call sits in the worker
    /// thread waiting for keyboard interaction with the PDDB unlock
    /// modal. Do not call from any latency-sensitive path.
    ///
    /// Use this from test paths that need a guaranteed-mounted PDDB
    /// before issuing put/get.
    #[allow(dead_code)]
    pub fn try_mount(&self) -> Result<bool, Error> {
        let guard = self.lock()?;
        guard.try_mount().map_err(|e| map_ipc_err(e, "try_mount"))
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, PddbClient>, Error> {
        self.client.lock().map_err(|_| Error::backend("PDDB client mutex poisoned"))
    }
}

impl KvBackend for PddbBackend {
    fn get(&self, dict: &str, key: &str) -> Result<Option<Vec<u8>>, Error> {
        let _perf_start = std::time::Instant::now();
        let guard = self.lock()?;
        let mut handle = match guard.open(dict, key, OpenOptions::default()) {
            Ok(h) => h,
            Err(e) if e.kind == IpcErrorKind::NotFound => {
                tracing::info!(
                    "perf/store: PddbBackend::get NotFound dict={:?} key={:?} ms={}",
                    dict,
                    crate::redact::log_id(key),
                    _perf_start.elapsed().as_millis()
                );
                return Ok(None);
            }
            Err(e) => return Err(map_ipc_err(e, "open for read")),
        };
        let mut bytes = Vec::new();
        read_all(&mut handle, &mut bytes).map_err(|e| Error::backend(format!("read: {}", e)))?;
        tracing::info!(
            "perf/store: PddbBackend::get Ok dict={:?} key={:?} len={} ms={}",
            dict,
            crate::redact::log_id(key),
            bytes.len(),
            _perf_start.elapsed().as_millis()
        );
        Ok(Some(bytes))
    }

    fn put(&self, dict: &str, key: &str, value: &[u8]) -> Result<(), Error> {
        let _perf_start = std::time::Instant::now();
        let _perf_val_len = value.len();
        let guard = self.lock()?;
        // Refs #14: xous-core PDDB's `WriteKey` opcode passes
        // `truncate=false` to `key_update`, so overwriting an
        // existing larger key leaves the trailing bytes intact and
        // `get` returns them concatenated to the new value. Delete
        // first to force a fresh allocation. NotFound on a
        // never-written key is normal — ignore.
        match guard.delete_key(dict, key) {
            Ok(()) => {}
            Err(e) if e.kind == IpcErrorKind::NotFound => {}
            Err(e) => return Err(map_ipc_err(e, "put: pre-delete")),
        }
        let mut handle =
            guard.open(dict, key, OpenOptions::create_all()).map_err(|e| map_ipc_err(e, "open for write"))?;
        // No explicit `handle.flush()` here. The PDDB server's
        // `Opcode::WriteKey` handler at xous-core/services/pddb/src/
        // main.rs:2293-2294 already calls `basis_cache.sync(...)`
        // after every key_update, so data is durable on WriteKey
        // return. A client-side `handle.flush()` would issue
        // `Opcode::WriteKeyFlush` (main.rs:2313-2329) which also
        // calls `basis_cache.sync(...)` — redundant multi-basis sync
        // per put. Dropping it saves 1 IPC + 1 basis sync per write.
        handle.write_all(value).map_err(|e| Error::backend(format!("write: {}", e)))?;
        tracing::info!(
            "perf/store: PddbBackend::put dict={:?} key={:?} len={} ms={}",
            dict,
            crate::redact::log_id(key),
            _perf_val_len,
            _perf_start.elapsed().as_millis()
        );
        Ok(())
    }

    fn put_batch(&self, entries: &[(&str, &str, &[u8])]) -> Result<(), Error> {
        if entries.is_empty() {
            return Ok(());
        }
        let _perf_start = std::time::Instant::now();
        let _perf_n = entries.len();
        let _perf_total: usize = entries.iter().map(|(d, k, v)| d.len() + k.len() + v.len()).sum();
        let guard = self.lock()?;
        // Single IPC, single trailing basis sync server-side. The
        // upstream `Opcode::WriteKeyBatch` handler applies each entry
        // with `truncate=true` so the `delete_key` prelude we'd
        // otherwise need for #14 is unnecessary on the batch path.
        let result = guard.write_batch(entries).map_err(|e| map_ipc_err(e, "write_batch"));
        tracing::info!(
            "perf/store: PddbBackend::put_batch n_entries={} total_bytes={} ok={} ms={}",
            _perf_n,
            _perf_total,
            result.is_ok(),
            _perf_start.elapsed().as_millis()
        );
        result
    }

    fn delete(&self, dict: &str, key: &str) -> Result<(), Error> {
        let _perf_start = std::time::Instant::now();
        let guard = self.lock()?;
        let result = match guard.delete_key(dict, key) {
            Ok(()) => Ok(()),
            Err(e) if e.kind == IpcErrorKind::NotFound => Ok(()),
            Err(e) => Err(map_ipc_err(e, "delete_key")),
        };
        tracing::info!(
            "perf/store: PddbBackend::delete dict={:?} key={:?} ms={}",
            dict,
            crate::redact::log_id(key),
            _perf_start.elapsed().as_millis()
        );
        result
    }

    fn delete_dict(&self, dict: &str) -> Result<(), Error> {
        let _perf_start = std::time::Instant::now();
        let guard = self.lock()?;
        let result = guard.delete_dict(dict).map_err(|e| map_ipc_err(e, "delete_dict"));
        tracing::info!(
            "perf/store: PddbBackend::delete_dict dict={:?} ms={}",
            dict,
            _perf_start.elapsed().as_millis()
        );
        result
    }

    fn list_keys(&self, dict: &str) -> Result<Vec<String>, Error> {
        let _perf_start = std::time::Instant::now();
        let guard = self.lock()?;
        let result = match guard.list_keys(dict) {
            Ok(v) => Ok(v),
            Err(e) if e.kind == IpcErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(map_ipc_err(e, "list_keys")),
        };
        let _perf_n = result.as_ref().map(|v| v.len()).unwrap_or(0);
        tracing::info!(
            "perf/store: PddbBackend::list_keys dict={:?} n={} ms={}",
            dict,
            _perf_n,
            _perf_start.elapsed().as_millis()
        );
        result
    }
}

/// Drain `handle` into `out`.
///
/// Mirrors `std::io::Read::read_to_end` but bounds the per-syscall
/// read at the 4 KiB chunk size that matches PDDB's per-buffer
/// ceiling. Loops until `read` returns zero, copying chunks into
/// `out`.
fn read_all(handle: &mut KeyHandle<'_>, out: &mut Vec<u8>) -> std::io::Result<()> {
    let mut chunk = [0u8; 4096];
    loop {
        let n = handle.read(&mut chunk)?;
        if n == 0 {
            return Ok(());
        }
        out.extend_from_slice(&chunk[..n]);
    }
}

/// Map an IPC error to a [`crate::Error::Backend`] with a stable
/// context string. The kind-to-string mapping is what callers see in
/// the error message; matching against `e.kind` upstream lets us
/// keep the wire-level kind enumeration internal.
fn map_ipc_err(e: xous_pddb_ipc::Error, ctx: &str) -> Error {
    match e.kind {
        IpcErrorKind::NotMounted => Error::backend(format!("{}: PDDB not mounted", ctx)),
        IpcErrorKind::AccessDenied => Error::backend(format!("{}: access denied", ctx)),
        IpcErrorKind::NoFreeSpace => Error::backend(format!("{}: out of space", ctx)),
        IpcErrorKind::InvalidInput => Error::backend(format!("{}: invalid input ({})", ctx, e.msg)),
        IpcErrorKind::NotFound => Error::backend(format!("{}: not found", ctx)),
        IpcErrorKind::Internal | IpcErrorKind::Ipc => Error::backend(format!("{}: {}", ctx, e.msg)),
    }
}
