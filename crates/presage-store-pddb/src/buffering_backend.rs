//! [`BufferingBackend`] — a [`KvBackend`] wrapper that defers
//! writes to an in-memory buffer during a "batch" scope, then
//! replays them to the inner backend on commit.
//!
//! Motivation: each `PddbBackend::put` on the real PDDB triggers an
//! expensive multi-basis sync inside the server's `Opcode::WriteKey`
//! handler (xous-core/services/pddb/src/main.rs:2293-2294).
//! Coalescing the writes that fire during a single Signal
//! `send_message` into one logical batch lets the application layer
//! choose where to pay that cost — typically once at the end of
//! send, rather than per Store-trait write.
//!
//! This wrapper sits between [`crate::PddbStore`] and the underlying
//! backend. It is **transparent** when no batch is active: every
//! call passes through to the inner backend with no extra work. It
//! is only interesting inside a batch scope opened via
//! [`BufferingBackend::begin_batch`].
//!
//! # Trust boundary
//!
//! [`BufferingBackend`] sits inside the PDDB trust boundary on the
//! write path: buffered bytes live in process memory until commit,
//! never on disk. Read-through against the buffer returns bytes the
//! same caller just wrote, so it adds no new trust hop.
//!
//! # Security
//!
//! The in-memory buffer is `Mutex<HashMap<(String, String),
//! BufferEntry>>` of secret-bearing values during a session-send
//! batch (the buffered values include session records, identity
//! state, etc.). The `Vec<u8>` payloads do not zero on drop. A
//! [`BatchGuard::commit`] on a successful path replays them to the
//! inner backend and clears the buffer; a `Drop`-abort clears the
//! buffer without replay. In both cases the `HashMap`'s capacity
//! storage is reused (so old `Vec<u8>` allocations are freed but
//! their backing memory may sit on the allocator's freelist until
//! reused).
//!
//! Crash semantics: if the process crashes between buffer-write and
//! commit, all buffered values are lost. This matches the existing
//! `session_cache` pattern (protocol/session_store.rs) — the
//! application is responsible for ordering durability boundaries.
//!
//! # Logging
//!
//! `begin_batch`, `commit_internal`, and `abort_internal` emit
//! `tracing::info!` perf events that carry buffer cardinality, put
//! and delete counts, and elapsed milliseconds. Value bytes are
//! never logged. A per-entry `put_batch` failure surfaces the inner
//! error message via `tracing::warn!`; that message is the backend's
//! own `Error::Backend(...)` string and does not carry value bytes.
//!
//! # rv32 / 16 MiB constraint
//!
//! Buffer memory is unbounded in this implementation. In practice
//! the worst-case batch (one `Signal::send_message` for a 100-member
//! group) touches at most ~110 entries × ~1 KB each = ~110 KB.
//!
//!
//! Batch semantics:
//!
//! - During a batch, `put(dict, key, value)` records the value in an in-memory `HashMap` keyed on `(dict,
//!   key)`. **No inner-backend write fires.**
//! - During a batch, `delete(dict, key)` records a tombstone in the same map.
//! - During a batch, `get(dict, key)` consults the buffer first (read-through): a buffered put returns the
//!   buffered bytes; a buffered tombstone returns `Ok(None)`; otherwise falls through to the inner backend.
//! - `list_keys(dict)` overlays the buffer on top of inner keys: inner ∪ buffered-puts ∖ buffered-deletes.
//!   Costs an inner `list_keys` call plus a buffer scan.
//! - `delete_dict(dict)` clears the buffer entries for `dict` and forwards to the inner backend. (Rare during
//!   send; included for completeness.)
//! - `commit_internal` (via [`BatchGuard::commit`]) drains the buffer, replays puts through `inner.put_batch`
//!   (one IPC for PddbBackend), replays deletes individually, clears the flag, and returns the number of
//!   replayed operations.
//! - `BatchGuard::Drop` without an explicit `commit()` is an abort: the buffer is cleared, the flag is reset,
//!   no replay fires.
//!
//! Concurrency: only one batch can be in flight at a time per
//! BufferingBackend instance. `begin_batch` returns
//! `Err(Error::backend("batch already in flight"))` if a batch is
//! active. Reads during a batch from another caller see the
//! pre-batch state (the buffer is per-batch).
//!
//! See the feasibility report at
//! `research/2026-05-12-pddb-send-batching-feasibility.md` for the
//! quantitative case for this layer.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::{Error, KvBackend};

/// One entry in the per-batch buffer.
///
/// A `Put` records the bytes to be written at commit time. A
/// `Delete` records that the key should be removed at commit time
/// (including a `delete` that supersedes an earlier `Put` of the
/// same key within the same batch).
#[derive(Debug, Clone)]
enum BufferEntry {
    Put(Vec<u8>),
    Delete,
}

/// Read-through, write-defer [`KvBackend`] wrapper.
///
/// See this file's module documentation for batch semantics, the
/// trust boundary, and the crash-loss bound. The wrapped backend is
/// held behind `Arc<dyn KvBackend>` so this layer is composable with
/// either [`crate::MockBackend`] (tests) or `PddbBackend` (production).
///
/// # Logging
///
/// Every batch open / commit / abort emits a `tracing::info!`
/// `perf/store: ...` event with cardinality and elapsed time. No
/// value bytes are emitted.
pub struct BufferingBackend {
    inner: Arc<dyn KvBackend>,
    batching: AtomicBool,
    buffer: Mutex<HashMap<(String, String), BufferEntry>>,
}

impl std::fmt::Debug for BufferingBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let buffered = self.buffer.lock().map(|b| b.len()).unwrap_or(0);
        f.debug_struct("BufferingBackend")
            .field("batching", &self.batching.load(Ordering::Acquire))
            .field("buffered_entries", &buffered)
            .finish_non_exhaustive()
    }
}

impl BufferingBackend {
    /// Wrap an inner [`KvBackend`]. The wrapper starts in pass-through
    /// mode (no batch in flight); writes pass straight through to
    /// the inner backend until [`begin_batch`](Self::begin_batch) is
    /// called.
    pub fn new(inner: Arc<dyn KvBackend>) -> Self {
        Self { inner, batching: AtomicBool::new(false), buffer: Mutex::new(HashMap::new()) }
    }

    /// Return `true` while a batch is in flight. Acquire-ordered
    /// load on the `batching` flag.
    pub fn is_batching(&self) -> bool { self.batching.load(Ordering::Acquire) }

    /// Number of buffered entries (puts + deletes). Test/diagnostic.
    /// Returns 0 if the buffer mutex is poisoned.
    pub fn buffered_len(&self) -> usize { self.buffer.lock().map(|b| b.len()).unwrap_or(0) }

    /// Open a batch scope.
    ///
    /// The returned [`BatchGuard`] aborts on `Drop` (no replay). Call
    /// [`BatchGuard::commit`] to replay the buffered operations to
    /// the inner backend.
    ///
    /// # Errors
    ///
    /// Returns `Err(Error::backend("batch already in flight on this
    /// backend"))` if a batch is already in flight. The flag is set
    /// via a `compare_exchange` so the check-and-set is atomic.
    pub fn begin_batch(&self) -> Result<BatchGuard<'_>, Error> {
        // Compare-and-swap: only succeed if no batch is active.
        match self.batching.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                tracing::info!("perf/store: BufferingBackend::begin_batch opened");
                Ok(BatchGuard { backend: self, committed: false })
            }
            Err(_) => Err(Error::backend("batch already in flight on this backend")),
        }
    }

    /// Internal: drain the buffer and replay to the inner backend.
    /// Called by [`BatchGuard::commit`].
    ///
    /// Puts and deletes are grouped: puts go through
    /// `inner.put_batch` in a single call (one server-side sync for
    /// `PddbBackend`); deletes are issued individually. Within the
    /// puts batch the order of replay is unspecified — the buffered
    /// set is a [`HashMap`].
    ///
    /// # Errors
    ///
    /// The buffer is drained via `mem::take` before any inner write
    /// fires, so the failure modes split into:
    ///
    /// - `put_batch` fails on the buffered puts (e.g. PDDB's `MAX_PDDB_WRITE_BATCH_LEN` ceiling exceeded).
    ///   The code falls back to per-entry `inner.put` for each buffered put. The original batch error is
    ///   logged but not surfaced; only a per-entry put failure becomes the returned error.
    /// - One of the deletes fails. The first delete error becomes the returned error; subsequent deletes are
    ///   still attempted.
    ///
    /// Either way, the batch flag is cleared on exit so a new batch
    /// can be opened. On partial-failure return the inner backend
    /// contains whatever succeeded — there is no rollback.
    fn commit_internal(&self) -> Result<usize, Error> {
        let _perf_start = std::time::Instant::now();
        // Take ownership of the buffer contents so other operations
        // (which check the flag) see an empty buffer immediately.
        let entries = {
            let mut guard = self.buffer.lock().map_err(|_| Error::backend("buffer mutex poisoned"))?;
            std::mem::take(&mut *guard)
        };
        let total_count = entries.len();

        // Split puts vs deletes. Hold onto the owned `(String, String,
        // Vec<u8>)` triples so the `&str` / `&[u8]` views into
        // `put_views` stay valid for the put_batch call.
        let mut puts: Vec<(String, String, Vec<u8>)> = Vec::new();
        let mut deletes: Vec<(String, String)> = Vec::new();
        for ((dict, key), entry) in entries {
            match entry {
                BufferEntry::Put(bytes) => puts.push((dict, key, bytes)),
                BufferEntry::Delete => deletes.push((dict, key)),
            }
        }

        let _perf_puts = puts.len();
        let _perf_deletes = deletes.len();
        let mut first_err: Option<Error> = None;
        let mut put_batch_fell_back = false;

        // Puts via the bulk path. Backends without a native bulk
        // opcode fall back to the default put-loop (see KvBackend
        // trait); PddbBackend issues one IPC + one server-side sync.
        //
        // If `put_batch` fails — the PDDB batch IPC caps the packed
        // payload at `MAX_PDDB_WRITE_BATCH_LEN` (3800 bytes), so a
        // single large buffered entry can push the whole batch over
        // the limit — fall back to per-entry `inner.put`. We've
        // already drained `self.buffer` via `mem::take` above, so
        // *some* path must replay these entries or the data is lost.
        // Per-entry put is slower (each call may chunk into multiple
        // `Opcode::WriteKey` IPCs and pays its own basis sync) but
        // it's correct and individual puts have no aggregate size
        // limit. The original batch error is logged but not
        // surfaced; if any per-entry put also fails, that error
        // becomes `first_err`.
        if !puts.is_empty() {
            let put_views: Vec<(&str, &str, &[u8])> =
                puts.iter().map(|(d, k, v)| (d.as_str(), k.as_str(), v.as_slice())).collect();
            if let Err(batch_err) = self.inner.put_batch(&put_views) {
                put_batch_fell_back = true;
                tracing::warn!(
                    "perf/store: BufferingBackend::commit put_batch failed ({}), \
                     falling back to per-entry inner.put for {} entries",
                    batch_err,
                    puts.len()
                );
                for (dict, key, value) in &puts {
                    if let Err(e) = self.inner.put(dict, key, value) {
                        if first_err.is_none() {
                            first_err = Some(e);
                        }
                    }
                }
            }
        }

        // Deletes individually. Could add a delete_batch analog if a
        // workload ever needs it; the send hot path doesn't issue
        // deletes during a batch, so this is fine.
        for (dict, key) in deletes {
            if let Err(e) = self.inner.delete(&dict, &key) {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }

        // Clear the flag last so any racing read sees inner with the
        // replayed state, not an empty buffer.
        self.batching.store(false, Ordering::Release);
        tracing::info!(
            "perf/store: BufferingBackend::commit n_entries={} (puts={}, deletes={}) put_batch_fell_back={} ms={}",
            total_count,
            _perf_puts,
            _perf_deletes,
            put_batch_fell_back,
            _perf_start.elapsed().as_millis()
        );
        match first_err {
            None => Ok(total_count),
            Some(e) => Err(e),
        }
    }

    /// Internal: abort the batch — discard the buffer, clear the
    /// flag. Called by `BatchGuard::Drop` when not committed.
    ///
    /// Clears the `HashMap` in place; the `Vec<u8>` payloads are
    /// dropped as part of the clear. They do not zero on drop; see
    /// the module-level Security note.
    fn abort_internal(&self) {
        let _perf_buffered_count = self.buffer.lock().map(|g| g.len()).unwrap_or(0);
        if let Ok(mut guard) = self.buffer.lock() {
            guard.clear();
        }
        self.batching.store(false, Ordering::Release);
        tracing::info!("perf/store: BufferingBackend::abort discarded={} (no replay)", _perf_buffered_count);
    }
}

impl KvBackend for BufferingBackend {
    fn get(&self, dict: &str, key: &str) -> Result<Option<Vec<u8>>, Error> {
        if self.is_batching() {
            // Consult the buffer first. If we have an entry, return
            // it without touching the inner backend.
            if let Ok(buf) = self.buffer.lock() {
                if let Some(entry) = buf.get(&(dict.to_string(), key.to_string())) {
                    return Ok(match entry {
                        BufferEntry::Put(bytes) => Some(bytes.clone()),
                        BufferEntry::Delete => None,
                    });
                }
            }
        }
        self.inner.get(dict, key)
    }

    fn put(&self, dict: &str, key: &str, value: &[u8]) -> Result<(), Error> {
        if self.is_batching() {
            let mut buf = self.buffer.lock().map_err(|_| Error::backend("buffer mutex poisoned"))?;
            buf.insert((dict.to_string(), key.to_string()), BufferEntry::Put(value.to_vec()));
            Ok(())
        } else {
            self.inner.put(dict, key, value)
        }
    }

    fn delete(&self, dict: &str, key: &str) -> Result<(), Error> {
        if self.is_batching() {
            let mut buf = self.buffer.lock().map_err(|_| Error::backend("buffer mutex poisoned"))?;
            buf.insert((dict.to_string(), key.to_string()), BufferEntry::Delete);
            Ok(())
        } else {
            self.inner.delete(dict, key)
        }
    }

    fn delete_dict(&self, dict: &str) -> Result<(), Error> {
        if self.is_batching() {
            // Pop any buffered entries for this dict, then forward.
            // The forward write is itself durable; subsequent reads
            // during the same batch see the post-delete-dict state.
            if let Ok(mut buf) = self.buffer.lock() {
                buf.retain(|(d, _), _| d != dict);
            }
        }
        self.inner.delete_dict(dict)
    }

    fn list_keys(&self, dict: &str) -> Result<Vec<String>, Error> {
        let inner_keys = self.inner.list_keys(dict)?;
        if !self.is_batching() {
            return Ok(inner_keys);
        }
        // Build the buffer-overlay view: inner ∪ buffered-puts ∖
        // buffered-deletes, scoped to this dict.
        let buf = self.buffer.lock().map_err(|_| Error::backend("buffer mutex poisoned"))?;
        let mut keys: std::collections::BTreeSet<String> = inner_keys.into_iter().collect();
        for ((d, k), entry) in buf.iter() {
            if d != dict {
                continue;
            }
            match entry {
                BufferEntry::Put(_) => {
                    keys.insert(k.clone());
                }
                BufferEntry::Delete => {
                    keys.remove(k);
                }
            }
        }
        Ok(keys.into_iter().collect())
    }
}

/// RAII guard for a batch scope.
///
/// [`commit`](Self::commit) replays the buffer to the inner backend
/// and consumes the guard. Dropping the guard without `commit()`
/// aborts the batch (buffer cleared, no replay) — i.e. abort is the
/// default, commit is opt-in. The abort-by-default RAII convention
/// matches what [`xous_pddb_ipc`] uses around its bulk-write surface,
/// even though the two operate at different layers: this `BatchGuard`
/// owns the in-memory write-coalescing buffer; on commit it calls
/// `KvBackend::put_batch`, which for `PddbBackend` issues exactly one
/// [`xous_pddb_ipc::PddbClient::write_batch`] IPC carrying every
/// buffered put. The IPC-layer batch is a single sub-second
/// server-side operation; this layer's batch can span an entire
/// Signal `send_message` call.
pub struct BatchGuard<'a> {
    backend: &'a BufferingBackend,
    committed: bool,
}

impl<'a> BatchGuard<'a> {
    /// Replay all buffered operations to the inner backend, then
    /// close the batch.
    ///
    /// Returns the number of operations replayed.
    ///
    /// # Errors
    ///
    /// If any individual replay fails the remaining entries are
    /// still attempted; the first failure is returned. The batch
    /// flag is cleared regardless so the backend stays usable. See
    /// [`BufferingBackend`]'s `commit_internal` for the full failure
    /// taxonomy (batch-overflow fallback to per-entry put, partial
    /// delete failures, etc.).
    pub fn commit(mut self) -> Result<usize, Error> {
        self.committed = true;
        self.backend.commit_internal()
    }

    /// Number of buffered entries pending commit. Test/diagnostic.
    pub fn buffered_len(&self) -> usize { self.backend.buffered_len() }
}

impl<'a> Drop for BatchGuard<'a> {
    fn drop(&mut self) {
        if !self.committed {
            self.backend.abort_internal();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockBackend;

    fn make() -> Arc<BufferingBackend> { Arc::new(BufferingBackend::new(Arc::new(MockBackend::new()))) }

    #[test]
    fn passthrough_when_not_batching() {
        let b = make();
        b.put("d", "k", b"v").unwrap();
        assert_eq!(b.get("d", "k").unwrap().as_deref(), Some(b"v".as_slice()));
        b.delete("d", "k").unwrap();
        assert_eq!(b.get("d", "k").unwrap(), None);
    }

    #[test]
    fn batched_put_invisible_to_inner_pre_commit() {
        let b = make();
        // Seed inner with a baseline value via direct (no batch) put.
        b.put("d", "k", b"baseline").unwrap();

        let guard = b.begin_batch().unwrap();
        // Inside the batch: put a new value.
        b.put("d", "k", b"batched").unwrap();
        // Read-through sees the buffered value.
        assert_eq!(b.get("d", "k").unwrap().as_deref(), Some(b"batched".as_slice()));
        // The inner backend itself still has the baseline.
        // (We can't easily test inner directly through the Arc<dyn>,
        // but we can verify by aborting and re-reading.)
        drop(guard); // abort
        assert!(!b.is_batching());
        assert_eq!(b.get("d", "k").unwrap().as_deref(), Some(b"baseline".as_slice()));
    }

    #[test]
    fn commit_replays_puts() {
        let b = make();
        let guard = b.begin_batch().unwrap();
        b.put("d", "k1", b"v1").unwrap();
        b.put("d", "k2", b"v2").unwrap();
        b.put("d", "k3", b"v3").unwrap();
        assert_eq!(guard.buffered_len(), 3);
        let n = guard.commit().unwrap();
        assert_eq!(n, 3);
        assert!(!b.is_batching());
        assert_eq!(b.get("d", "k1").unwrap().as_deref(), Some(b"v1".as_slice()));
        assert_eq!(b.get("d", "k2").unwrap().as_deref(), Some(b"v2".as_slice()));
        assert_eq!(b.get("d", "k3").unwrap().as_deref(), Some(b"v3".as_slice()));
    }

    #[test]
    fn commit_replays_deletes() {
        let b = make();
        b.put("d", "k", b"baseline").unwrap();
        let guard = b.begin_batch().unwrap();
        b.delete("d", "k").unwrap();
        assert_eq!(b.get("d", "k").unwrap(), None); // read-through sees delete
        guard.commit().unwrap();
        assert_eq!(b.get("d", "k").unwrap(), None); // inner committed
    }

    #[test]
    fn delete_then_put_in_same_batch() {
        let b = make();
        b.put("d", "k", b"baseline").unwrap();
        let guard = b.begin_batch().unwrap();
        b.delete("d", "k").unwrap();
        b.put("d", "k", b"replaced").unwrap();
        assert_eq!(b.get("d", "k").unwrap().as_deref(), Some(b"replaced".as_slice()));
        guard.commit().unwrap();
        assert_eq!(b.get("d", "k").unwrap().as_deref(), Some(b"replaced".as_slice()));
    }

    #[test]
    fn abort_loses_buffered_writes() {
        let b = make();
        b.put("d", "k", b"baseline").unwrap();
        {
            let _guard = b.begin_batch().unwrap();
            b.put("d", "k", b"discarded").unwrap();
            b.put("d", "fresh", b"never_committed").unwrap();
        } // _guard dropped here without commit -> abort
        assert!(!b.is_batching());
        assert_eq!(b.get("d", "k").unwrap().as_deref(), Some(b"baseline".as_slice()));
        assert_eq!(b.get("d", "fresh").unwrap(), None);
    }

    #[test]
    fn two_batches_in_flight_refused() {
        let b = make();
        let _guard1 = b.begin_batch().unwrap();
        let r = b.begin_batch();
        assert!(r.is_err());
    }

    #[test]
    fn list_keys_overlay_during_batch() {
        let b = make();
        b.put("d", "a", b"1").unwrap();
        b.put("d", "b", b"2").unwrap();
        let guard = b.begin_batch().unwrap();
        b.delete("d", "a").unwrap();
        b.put("d", "c", b"3").unwrap();
        let mut listed = b.list_keys("d").unwrap();
        listed.sort();
        assert_eq!(listed, vec!["b".to_string(), "c".to_string()]);
        drop(guard); // abort
        let mut listed = b.list_keys("d").unwrap();
        listed.sort();
        assert_eq!(listed, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn coalesce_same_key_overwrites() {
        let b = make();
        let guard = b.begin_batch().unwrap();
        b.put("d", "k", b"v1").unwrap();
        b.put("d", "k", b"v2").unwrap();
        b.put("d", "k", b"v3").unwrap();
        // Three puts collapse to one buffered entry.
        assert_eq!(guard.buffered_len(), 1);
        let n = guard.commit().unwrap();
        assert_eq!(n, 1); // only the latest replayed
        assert_eq!(b.get("d", "k").unwrap().as_deref(), Some(b"v3".as_slice()));
    }

    /// Counting wrapper that tracks individual `put` vs batched
    /// `put_batch` calls. Lets us assert that `commit` exercises the
    /// bulk path, not the per-key loop. When `fail_batch` is set,
    /// `put_batch` returns an error without persisting anything, so a
    /// test can drive the `commit_internal` fallback path.
    #[derive(Debug)]
    struct CountingBackend {
        inner: Arc<MockBackend>,
        puts: std::sync::atomic::AtomicUsize,
        batches: std::sync::atomic::AtomicUsize,
        batch_total_entries: std::sync::atomic::AtomicUsize,
        fail_batch: std::sync::atomic::AtomicBool,
    }

    impl CountingBackend {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                inner: Arc::new(MockBackend::new()),
                puts: Default::default(),
                batches: Default::default(),
                batch_total_entries: Default::default(),
                fail_batch: Default::default(),
            })
        }

        fn puts(&self) -> usize { self.puts.load(std::sync::atomic::Ordering::Acquire) }

        fn batches(&self) -> usize { self.batches.load(std::sync::atomic::Ordering::Acquire) }

        fn batch_total(&self) -> usize { self.batch_total_entries.load(std::sync::atomic::Ordering::Acquire) }

        fn set_fail_batch(&self, fail: bool) {
            self.fail_batch.store(fail, std::sync::atomic::Ordering::Release);
        }
    }

    impl KvBackend for CountingBackend {
        fn get(&self, dict: &str, key: &str) -> Result<Option<Vec<u8>>, Error> { self.inner.get(dict, key) }

        fn put(&self, dict: &str, key: &str, value: &[u8]) -> Result<(), Error> {
            self.puts.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            self.inner.put(dict, key, value)
        }

        fn put_batch(&self, entries: &[(&str, &str, &[u8])]) -> Result<(), Error> {
            self.batches.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            self.batch_total_entries.fetch_add(entries.len(), std::sync::atomic::Ordering::AcqRel);
            if self.fail_batch.load(std::sync::atomic::Ordering::Acquire) {
                // Mimic the PDDB IPC "batch exceeds MAX_PDDB_WRITE_BATCH_LEN; split"
                // path: return without writing anything so the
                // BufferingBackend has to recover via per-entry put.
                return Err(Error::backend("simulated batch-size overflow"));
            }
            // Don't fall through to default impl (which calls put);
            // exercise the bulk path semantics by writing through
            // the inner mock directly.
            for (d, k, v) in entries {
                self.inner.put(d, k, v)?;
            }
            Ok(())
        }

        fn delete(&self, dict: &str, key: &str) -> Result<(), Error> { self.inner.delete(dict, key) }

        fn delete_dict(&self, dict: &str) -> Result<(), Error> { self.inner.delete_dict(dict) }

        fn list_keys(&self, dict: &str) -> Result<Vec<String>, Error> { self.inner.list_keys(dict) }
    }

    /// On commit, multiple buffered puts should be flushed via a
    /// single `put_batch` call — not N individual `put` calls. This is
    /// the load-bearing assertion: it's the difference between phase 1
    /// (per-write savings) and Option B (per-batch savings).
    #[test]
    fn commit_uses_put_batch_not_per_put_loop() {
        let counting = CountingBackend::new();
        let bb = BufferingBackend::new(counting.clone());

        let guard = bb.begin_batch().unwrap();
        bb.put("d", "k1", b"v1").unwrap();
        bb.put("d", "k2", b"v2").unwrap();
        bb.put("d", "k3", b"v3").unwrap();
        let n = guard.commit().unwrap();
        assert_eq!(n, 3);

        // Exactly one batched call, three entries inside it.
        assert_eq!(counting.batches(), 1);
        assert_eq!(counting.batch_total(), 3);
        // Zero individual put() calls during commit.
        assert_eq!(counting.puts(), 0);
    }

    /// Pre-batch put (direct, no scope) passes through to `put`, not
    /// `put_batch`. Validates the "transparent when not batching"
    /// property at the abstraction boundary.
    #[test]
    fn unbatched_put_uses_put_not_put_batch() {
        let counting = CountingBackend::new();
        let bb = BufferingBackend::new(counting.clone());

        bb.put("d", "k", b"v").unwrap();

        assert_eq!(counting.batches(), 0);
        assert_eq!(counting.puts(), 1);
    }

    /// When `put_batch` fails (e.g. the PDDB
    /// `MAX_PDDB_WRITE_BATCH_LEN` cap is exceeded), the buffer has
    /// already been drained — `commit_internal` must replay the
    /// drained entries via per-entry `put` so the data lands on disk
    /// instead of being lost. The commit then reports success.
    #[test]
    fn commit_falls_back_to_per_put_when_put_batch_fails() {
        let counting = CountingBackend::new();
        counting.set_fail_batch(true);
        let bb = BufferingBackend::new(counting.clone());

        let guard = bb.begin_batch().unwrap();
        bb.put("d", "k1", b"v1").unwrap();
        bb.put("d", "k2", b"v2").unwrap();
        bb.put("d", "k3", b"v3").unwrap();
        let n = guard.commit().expect("commit must succeed via fallback");
        assert_eq!(n, 3, "commit returns total entry count even on fallback");

        // put_batch was called once and failed.
        assert_eq!(counting.batches(), 1);
        // Three fallback per-entry puts followed.
        assert_eq!(counting.puts(), 3);
        // Inner data is durable.
        assert_eq!(counting.inner.get("d", "k1").unwrap().as_deref(), Some(b"v1".as_slice()));
        assert_eq!(counting.inner.get("d", "k2").unwrap().as_deref(), Some(b"v2".as_slice()));
        assert_eq!(counting.inner.get("d", "k3").unwrap().as_deref(), Some(b"v3".as_slice()));
    }
}
