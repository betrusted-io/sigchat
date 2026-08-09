//! PDDB-backed implementation of `presage`'s storage traits.
//!
//! Implements every storage trait `presage::Manager` needs (state,
//! protocol, contents) on top of Xous's PDDB encrypted key-value
//! store. This is the only path by which Signal Protocol state
//! (identity keys, session records, prekey bundles, registration
//! data) is persisted on the device; loss of the PDDB password is
//! loss of the linked Signal session.
//!
//! # Layout
//!
//! Trait impls sit on top of an internal [`KvBackend`] abstraction:
//!
//! - [`KvBackend`] exposes `get` / `put` / `delete` / `delete_dict` / `list_keys` keyed on `(dict_name,
//!   key_name)` — the same shape PDDB itself exposes. `PddbBackend` (under the `pddb-backend` feature)
//!   forwards into the `xous-pddb-ipc` client; [`MockBackend`] is an in-memory `HashMap` for hosted-mode
//!   tests.
//! - [`BufferingBackend`] wraps any inner backend and adds send-time write coalescing: writes inside a
//!   [`BatchGuard`] scope stay in RAM until [`BatchGuard::commit`].
//! - [`PddbStore`] owns an `Arc<dyn KvBackend>`, an in-memory session cache (dirty-set + flush instead of
//!   write-through), and a `trust_new_identities` policy flag. `Clone + Send + Sync + 'static` (the bound
//!   `presage::store::Store` demands).
//!
//! # Trait coverage
//!
//! - `StateStore` (10 methods): registration data, master key, identity-key pairs, sender certificate.
//! - The 6 libsignal protocol storage traits + the `ProtocolStore` blanket impl. ACI/PNI splits are
//!   runtime-dispatched via [`IdentityType`]; sessions are buffered in `PddbStore` and flushed in bulk by
//!   [`PddbStore::flush_sessions`].
//! - 3 libsignal-service-rs extension traits (`PreKeysStore`, `KyberPreKeyStoreExt`, `SessionStoreExt`).
//! - Full `ContentsStore`: messages-by-thread, contacts, groups, profile keys, profile and group avatars,
//!   sticker packs.
//!
//! # Crate boundaries
//!
//! Upstream: `xous-signal-worker::run_signal_worker` takes a
//! [`PddbStore`] and hands it to `presage::Manager`. Below:
//! `xous-pddb-ipc` (only under the `pddb-backend` feature) and the
//! presage trait surface from the rev-pinned forks (docs/FORKS.md). No transport
//! deps — this crate never touches the network.
//!
//! # Trust boundary
//!
//! Every byte this crate writes to PDDB is Signal-Protocol
//! cryptographic material (or framing around it). PDDB itself
//! encrypts the bytes at rest under the user's PDDB password, so
//! this crate sees plaintext keys on the way to encrypted storage.
//! The bytes are NOT re-encrypted here — that would be a useless
//! second layer with the same key derivation problem.
//!
//! The `session_cache` and `session_dirty` fields keep recently-used
//! [`SessionRecord`] bytes in RAM for the duration of the worker
//! process; they are dropped on process exit and never written
//! elsewhere. Same applies to the [`BufferingBackend`]'s in-RAM
//! buffer during a batch.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex};

use presage::libsignal_service::protocol::SessionRecord;
use presage::model::identity::OnNewIdentity;

mod backend_mock;
mod backend_pddb;
mod buffering_backend;
mod content;
mod error;
mod protocol;
#[cfg(feature = "pddb-backend")]
mod put_truncate_smoke;
mod redact;
mod state;
mod store;

pub use backend_mock::MockBackend;
#[cfg(feature = "pddb-backend")]
pub use backend_pddb::PddbBackend;
pub use buffering_backend::{BatchGuard, BufferingBackend};
pub use error::Error;
pub use protocol::{IdentityType, PddbProtocolStore};
#[cfg(feature = "pddb-backend")]
pub use put_truncate_smoke::{SmokeResult, smoke_put_truncates};
pub use redact::{log_id, redact_id};

/// Internal KV abstraction used by all `PddbStore` trait impls.
///
/// The `(dict, key)` shape mirrors PDDB's API: dicts hold related
/// keys and can be dropped wholesale (`delete_dict`), which is what
/// `clear_registration` / `clear_profiles` / etc. exploit.
///
/// Implementations must be cheap to share across threads —
/// `PddbStore` holds the backend behind an `Arc` and clones the
/// `Arc` on `PddbStore::clone()`, so all callers see the same
/// underlying state.
///
/// # Trust boundary
///
/// `KvBackend` is the abstraction layer over the durability
/// substrate. The two impls in this crate are:
///
/// - `PddbBackend` (feature `pddb-backend`) — forwards to the running PDDB server. Bytes are authenticated by
///   PDDB's per-page AES-256-GCM-SIV before `KvBackend::get` returns them. This is the only trust boundary
///   for persisted secrets.
/// - [`MockBackend`] — plaintext `HashMap`, hosted-mode tests only. **Never built into production xas.**
///   Carries no crypto. Lives here because the trait impls are what unit tests cover, and a real PDDB
///   connection isn't available in hosted mode.
///
/// Bytes flowing across this trait are opaque to the backend — the
/// store-trait impls (`StateStore`, `ContentsStore`, the protocol
/// stores) are responsible for framing and decoding. A `KvBackend`
/// is not allowed to inspect or transform the values.
///
/// # Security
///
/// A `put(dict, key, value)` write is durable when it returns
/// `Ok(())`. The `PddbBackend` impl achieves this via PDDB's
/// `Opcode::WriteKey` handler, which calls `basis_cache.sync(...)`
/// before reply — see `services/pddb/src/main.rs:2293-2294`.
///
/// `KvBackend` impls must be `Send + Sync`: the store and its clones
/// share one backend behind an `Arc`. Implementors are responsible
/// for serializing concurrent IPCs — `PddbBackend` does so via an
/// internal `Mutex<PddbClient>`.
pub trait KvBackend: Send + Sync + fmt::Debug {
    /// Read `key` from `dict`. Returns `Ok(None)` if the key is
    /// absent; returns `Err` on backend failure (PDDB IPC failure,
    /// mutex poisoning, etc.).
    fn get(&self, dict: &str, key: &str) -> Result<Option<Vec<u8>>, Error>;

    /// Write `value` to `dict[key]`, replacing any prior value.
    /// Returns `Ok(())` after the value is durable.
    ///
    /// The `PddbBackend` impl issues a `delete_key` before the write
    /// to force a fresh allocation; see refs #14 for the truncation
    /// bug this works around.
    fn put(&self, dict: &str, key: &str, value: &[u8]) -> Result<(), Error>;

    /// Bulk write: apply N `(dict, key, value)` writes with **one**
    /// sync at the end (if the backend supports it natively). The
    /// default impl loops over `put` for backends without a native
    /// bulk path (MockBackend, future test fixtures, etc.).
    ///
    /// `PddbBackend` overrides this to invoke the PDDB
    /// `Opcode::WriteKeyBatch` opcode, which collapses the N
    /// per-`WriteKey` server-side basis syncs into one — the actual
    /// order-of-magnitude saving over per-key put loops.
    ///
    /// # Errors
    ///
    /// Not atomic across entries: if entry N fails, entries 0..N
    /// have already been applied. For `PddbBackend` the trailing
    /// sync still runs server-side, so partial state is durable.
    /// Callers (notably [`BufferingBackend`]'s commit path) must be
    /// prepared to recover by replaying entries individually if
    /// `put_batch` returns `Err` after a partial apply.
    fn put_batch(&self, entries: &[(&str, &str, &[u8])]) -> Result<(), Error> {
        for (dict, key, value) in entries {
            self.put(dict, key, value)?;
        }
        Ok(())
    }

    /// Remove `key` from `dict`. Idempotent: deleting a missing key
    /// must succeed.
    fn delete(&self, dict: &str, key: &str) -> Result<(), Error>;

    /// Remove `dict` and every key inside it. Used by `clear_*`
    /// methods on the store trait impls to wipe a whole table.
    fn delete_dict(&self, dict: &str) -> Result<(), Error>;

    /// List every key currently present in `dict`. Returns an empty
    /// `Vec` for a non-existent or empty dict. Key ordering is the
    /// backend's lexicographic sort; content-store callers exploit
    /// this for timestamp-ordered iteration.
    fn list_keys(&self, dict: &str) -> Result<Vec<String>, Error>;
}

/// PDDB-backed store implementing presage's full `Store` trait.
///
/// `Clone` is shallow — clones share the same backend, the same
/// session cache, and the same trust policy via `Arc`.
/// `presage::store::Store` requires `Clone + Send + Sync + 'static`;
/// every clone of a `PddbStore` therefore observes the same on-disk
/// state and the same in-flight session cache, which is the
/// behaviour Manager assumes when it stashes a store handle behind
/// shared state. A consequence: every live clone (held by `Manager`,
/// stashed in the worker dispatcher, captured in spawned tasks)
/// extends the lifetime of the cached `SessionRecord` bytes, which
/// libsignal-protocol does not zeroize on Drop today.
/// `xous_signal_worker::manager_task` drops
/// the Manager when its op channel closes; the cache is gone only
/// once the last clone has been dropped.
///
/// # Security
///
/// `PddbStore` is the single audit point that mediates every read
/// and write of Signal account state, libsignal key material,
/// per-thread message bodies, and registration credentials.
/// Sensitivity inherits from the underlying types — see the
/// `state`, `content`, and `protocol` private module docs for the
/// per-type tier breakdown.
///
/// `Debug` is hand-rolled because [`SessionRecord`] (held inside the
/// session cache) doesn't implement `Debug`. We surface only the
/// cache cardinality, not its contents — matches the privacy
/// expectations for a long-lived store. Derive-`Debug` here would be
/// catastrophic; a `tracing::debug!(?store)` on a logging path would
/// flush every cached session's bytes to UART. (See anti-pattern A.11
/// in `/home/tunnell/research-doc-patterns.md`.)
///
/// # Logging
///
/// None of `PddbStore`'s methods log secret-bearing values. The
/// `buffering_backend` and `backend_pddb` layers do emit
/// `tracing::info!` perf events — those carry dict/key strings (the
/// `dict` and `key` are non-secret), value *lengths* (the size of
/// e.g. a serialized session record), and elapsed milliseconds, but
/// never value bytes.
#[derive(Clone)]
pub struct PddbStore {
    pub(crate) backend: Arc<dyn KvBackend>,

    /// When the store was constructed with buffering enabled (via
    /// `new_buffering` / `with_pddb_backend`), this is a direct
    /// handle to the wrapper. Callers go through `begin_send_batch`
    /// to start a batch scope. `None` for plain backends (most
    /// tests, hosted mode); writes pass through unchanged in that
    /// case.
    pub(crate) buffering: Option<Arc<BufferingBackend>>,

    /// In-memory dirty-set cache. `store_session` writes here only;
    /// `flush_sessions` persists to the backend. Wrapped in `Mutex`
    /// so it stays `Send + Sync` even though the underlying
    /// `SessionRecord` is.
    ///
    /// **Holds Double Ratchet state for every active session.** See
    /// the [`protocol::session_store`] module doc for the
    /// per-record sensitivity analysis and the zeroization gap
    /// (libsignal's `SessionRecord` does not derive `Zeroize`).
    pub(crate) session_cache: Arc<Mutex<HashMap<protocol::session_store::SessionKey, SessionRecord>>>,

    /// Companion to `session_cache`: keys present here have unsaved
    /// changes since the last flush. Split from the cache itself so
    /// flushing only persists genuinely-dirty entries (and so
    /// read-through `load_session` can populate the cache without
    /// marking the entry dirty).
    pub(crate) session_dirty: Arc<Mutex<HashSet<protocol::session_store::SessionKey>>>,

    /// What to do when `IdentityKeyStore::is_trusted_identity` finds
    /// a known address with a different identity key. `Trust`
    /// accepts the change (TOFU-with-rotation); `Reject` refuses it.
    /// Per-store, settable at construction time.
    pub(crate) trust_new_identities: OnNewIdentity,
}

impl PddbStore {
    /// Build a store from any `KvBackend` with the default trust
    /// policy (`OnNewIdentity::Trust` — TOFU-with-rotation, what
    /// presage-store-sled / sqlite use unless overridden).
    ///
    /// The returned store is **not** wrapped in a
    /// [`BufferingBackend`]; writes pass through to the inner backend
    /// immediately. For send-time write coalescing, use
    /// [`new_buffering`](PddbStore::new_buffering) instead.
    pub fn new(backend: Arc<dyn KvBackend>) -> Self { Self::with_options(backend, OnNewIdentity::Trust) }

    /// Build a store with an explicit trust policy.
    ///
    /// `trust_new_identities` is consulted only on the
    /// known-and-different branch of
    /// [`IdentityKeyStore::is_trusted_identity`](presage::libsignal_service::protocol::IdentityKeyStore::is_trusted_identity);
    /// see the `protocol::identity_key_store` module for the full
    /// TOFU policy.
    pub fn with_options(backend: Arc<dyn KvBackend>, trust_new_identities: OnNewIdentity) -> Self {
        Self {
            backend,
            buffering: None,
            session_cache: Arc::new(Mutex::new(HashMap::new())),
            session_dirty: Arc::new(Mutex::new(HashSet::new())),
            trust_new_identities,
        }
    }

    /// Build a store with a [`BufferingBackend`] wrapping the inner
    /// backend. [`begin_send_batch`](PddbStore::begin_send_batch)
    /// becomes meaningful.
    ///
    /// This is what `with_pddb_backend` uses by default — production
    /// xas wants buffering enabled for send-time write coalescing.
    /// Tests that want to exercise the same code path can also use
    /// this constructor over any inner backend (typically
    /// [`MockBackend`]).
    pub fn new_buffering(inner: Arc<dyn KvBackend>) -> Self {
        Self::new_buffering_with_options(inner, OnNewIdentity::Trust)
    }

    /// Same as [`new_buffering`](PddbStore::new_buffering) but with
    /// an explicit trust policy.
    pub fn new_buffering_with_options(
        inner: Arc<dyn KvBackend>,
        trust_new_identities: OnNewIdentity,
    ) -> Self {
        let buffering = Arc::new(BufferingBackend::new(inner));
        let backend: Arc<dyn KvBackend> = buffering.clone();
        Self {
            backend,
            buffering: Some(buffering),
            session_cache: Arc::new(Mutex::new(HashMap::new())),
            session_dirty: Arc::new(Mutex::new(HashSet::new())),
            trust_new_identities,
        }
    }

    /// Convenience for hosted-mode tests — wraps a fresh
    /// [`MockBackend`]. **Test-only**; the mock has no encryption and
    /// must never reach a production build.
    pub fn with_mock_backend() -> Self { Self::new(Arc::new(MockBackend::new())) }

    /// Connect to xous-core's running PDDB server and wrap the
    /// resulting `xous_pddb_ipc::PddbClient` as a real
    /// [`KvBackend`]. `pddb-backend` feature only.
    ///
    /// Wraps the real `PddbBackend` in a [`BufferingBackend`] so the
    /// store supports send-time write coalescing via
    /// [`begin_send_batch`](PddbStore::begin_send_batch).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the PDDB server isn't reachable. Does NOT
    /// block on the basis being mounted — the caller (typically the
    /// xas worker thread) is responsible for waiting on
    /// `is_mounted()` before issuing operations that need the store,
    /// or for tolerating per-op `NotMounted` errors during the boot
    /// window.
    #[cfg(feature = "pddb-backend")]
    pub fn with_pddb_backend() -> Result<Self, Error> {
        let backend = backend_pddb::PddbBackend::connect()?;
        Ok(Self::new_buffering(Arc::new(backend)))
    }

    /// Open a send-time batch scope. Writes issued through this
    /// store between `begin_send_batch` and the returned guard's
    /// `commit()` (or abort-on-Drop) are buffered in memory and
    /// only flushed to the inner backend on commit.
    ///
    /// See [`BufferingBackend`] and [`BatchGuard`] for the
    /// read-through / write-defer semantics.
    ///
    /// `xous_signal_worker::handle_send` is the only production
    /// caller. It treats `Ok(None)` as pass-through (no inner
    /// buffering, hosted-mode test path) and `Err` as a logic bug
    /// to surface (the `Err` arm fires only on a same-thread nested
    /// batch; the worker's single-threaded executor means there is
    /// no other batch-open path that can race).
    ///
    /// # Errors
    ///
    /// - `Ok(None)` if the store was constructed without buffering (e.g.
    ///   `PddbStore::new(Arc::new(MockBackend::new()))`). Caller code can treat `None` as a no-op: writes
    ///   simply pass through unchanged. This makes the call site safe to add unconditionally.
    /// - `Err` if a batch is already in flight on this store. Only one batch can be open at a time per
    ///   `BufferingBackend` instance.
    pub fn begin_send_batch(&self) -> Result<Option<BatchGuard<'_>>, Error> {
        match self.buffering.as_deref() {
            Some(b) => b.begin_batch().map(Some),
            None => Ok(None),
        }
    }

    /// Return `true` if this store wraps a [`BufferingBackend`] and
    /// has an open batch.
    pub fn is_send_batching(&self) -> bool {
        self.buffering.as_deref().map(|b| b.is_batching()).unwrap_or(false)
    }

    /// Return `true` if the store still holds account state — any
    /// key in `signal.state` or in any protocol dict (both ACI and
    /// PNI). An empty or never-written store returns `false`.
    ///
    /// This is the pre-link stale-store probe: the xas worker calls
    /// it before starting `Manager::link_secondary_device`, because
    /// linking on top of leftover protocol dicts re-inherits stale
    /// sessions and orphaned kyber records. The probe is read-only —
    /// wiping stays with the user-driven `Store::clear` path (the
    /// implicit link-time wipe was reverted after it hung a device).
    ///
    /// Contents dicts (contacts, groups, profiles) are deliberately
    /// not probed: they are not protocol-hazardous, and any store
    /// that has them also has `signal.state` or protocol keys unless
    /// a wipe already removed those first.
    ///
    /// # Errors
    ///
    /// Infallible by design: a backend error on any probe is logged
    /// and treated as "no keys" (fail-open), so a flaky or
    /// not-yet-mounted PDDB cannot lock the user out of linking —
    /// the link itself will surface the real error.
    pub fn has_account_state(&self) -> bool {
        let mut dicts = vec![state::DICT.to_string()];
        for identity in [IdentityType::Aci, IdentityType::Pni] {
            dicts.push(protocol::dict_session(identity));
            dicts.push(protocol::dict_identity(identity));
            dicts.push(protocol::dict_prekey_bundle(identity));
            dicts.push(protocol::dict_signed_prekey(identity));
            dicts.push(protocol::dict_kyber_prekey(identity));
            dicts.push(protocol::dict_kyber_meta(identity));
            dicts.push(protocol::dict_sender_key(identity));
        }
        for dict in dicts {
            match self.backend.list_keys(&dict) {
                Ok(keys) if !keys.is_empty() => return true,
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!("has_account_state: list_keys({}) failed ({}); treating as empty", dict, e)
                }
            }
        }
        false
    }

    /// Number of entries currently in the session cache (any state —
    /// dirty or not). Test-/debug-only convenience; returns 0 if
    /// the cache mutex is poisoned.
    pub fn session_cache_len(&self) -> usize { self.session_cache.lock().map(|c| c.len()).unwrap_or(0) }

    /// Number of dirty session entries waiting to be flushed.
    /// Returns 0 if the dirty-set mutex is poisoned.
    pub fn session_dirty_len(&self) -> usize { self.session_dirty.lock().map(|d| d.len()).unwrap_or(0) }

    /// Persist every dirty session entry to the backend, then clear
    /// the dirty set. Cache entries themselves stay populated so
    /// subsequent `load_session` calls hit RAM. Call on
    /// `Received::QueueEmpty`, on a debounce timer, or whenever the
    /// dirty set crosses a high-water mark.
    ///
    /// Sessions sharing an address are bundled into one PDDB key
    /// (value: `device_id -> serialized SessionRecord`). One PDDB
    /// `put` per address per flush, regardless of how many devices
    /// rotated keys — saves 3 IPCs of fixed `open/flush/drop`
    /// overhead per device beyond the first.
    ///
    /// # Trust boundary
    ///
    /// On successful return, every dirty session record observed at
    /// entry has been written through to PDDB and is durable per
    /// PDDB's per-write `basis_cache.sync(...)`. A power-cut between
    /// `store_session` and the next `flush_sessions` loses the
    /// ratchet step but not the session itself; libsignal recovers
    /// by re-keying when sends fail.
    ///
    /// # Errors
    ///
    /// Returns the first backend error encountered. Partial
    /// durability is possible — sessions whose `put` succeeded
    /// before the failure are durable. The dirty set is cleared only
    /// on full success; on error the still-dirty entries remain
    /// queued for the next flush.
    ///
    /// Returns the number of session records written. Idempotent —
    /// calling twice in a row is cheap (second call sees an empty
    /// dirty set).
    pub fn flush_sessions(&self) -> Result<usize, Error> {
        use protocol::session_store::{
            SessionBundle, backend_get_session_bundle, backend_put_session_bundle,
        };

        let mut dirty =
            self.session_dirty.lock().map_err(|_| Error::backend("session dirty mutex poisoned"))?;
        if dirty.is_empty() {
            return Ok(0);
        }
        let cache = self.session_cache.lock().map_err(|_| Error::backend("session cache mutex poisoned"))?;

        // Group dirty entries by `(identity, address.name())`. The
        // grouping is the whole point — one PDDB put per group, not
        // per dirty entry.
        let mut groups: HashMap<(protocol::IdentityType, String), Vec<(u32, Vec<u8>)>> = HashMap::new();
        for key in dirty.iter() {
            let Some(record) = cache.get(key) else {
                continue;
            };
            let bytes = record.serialize().map_err(|e| Error::Encode(e.to_string()))?;
            groups.entry((key.0, key.1.clone())).or_default().push((key.2, bytes));
        }

        let mut written = 0_usize;
        for ((identity, name), entries) in groups {
            let dict = protocol::dict_session(identity);

            // Read-modify-write: existing PDDB bundle (if any) plus
            // the dirty changes. Devices not touched in this flush
            // pass their bytes through unchanged.
            let mut bundle: SessionBundle =
                backend_get_session_bundle(&*self.backend, &dict, &name)?.unwrap_or_default();
            for (device_id, ser) in entries {
                bundle.insert(device_id, ser);
                written += 1;
            }
            backend_put_session_bundle(&*self.backend, &dict, &name, &bundle)?;
        }
        dirty.clear();
        Ok(written)
    }
}

impl fmt::Debug for PddbStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PddbStore")
            .field("session_cache_len", &self.session_cache_len())
            .field("session_dirty_len", &self.session_dirty_len())
            .field("send_batching", &self.is_send_batching())
            .field("trust_new_identities", &self.trust_new_identities)
            .finish_non_exhaustive()
    }
}

// --- Helpers shared by every trait impl in this crate. ---
//
// Each is a trivial wrapper, but having one place to set the error
// mapping or serde format means future changes don't need to find
// every site.

/// Fetch a serde-JSON value from the backend, deserializing on hit.
/// Wraps the `backend.get(...)? + serde_json::from_slice(...)?`
/// pattern.
///
/// Returns `Ok(None)` if the key isn't present; returns
/// [`Error::Decode`] if the bytes are present but malformed.
pub(crate) fn backend_get_json<T: for<'de> serde::Deserialize<'de>>(
    backend: &dyn KvBackend,
    dict: &str,
    key: &str,
) -> Result<Option<T>, Error> {
    match backend.get(dict, key)? {
        Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        None => Ok(None),
    }
}

/// Serialize a value as JSON and write to the backend. Inverse of
/// [`backend_get_json`].
///
/// `serde_json::to_vec` failure is wrapped explicitly as
/// [`Error::Encode`]; the [`From<serde_json::Error>`] impl in
/// `error.rs` picks `Decode`, which would be wrong for the write
/// direction, so we route through `Error::encode` here.
pub(crate) fn backend_put_json<T: serde::Serialize + ?Sized>(
    backend: &dyn KvBackend,
    dict: &str,
    key: &str,
    value: &T,
) -> Result<(), Error> {
    let bytes = serde_json::to_vec(value).map_err(Error::encode)?;
    backend.put(dict, key, &bytes)?;
    Ok(())
}

/// List a dict's keys parsed as `u32` IDs (silently dropping
/// anything that doesn't parse). Used by the `*PreKeyStore::max_*_id`
/// and similar count/max queries.
///
/// The silent-drop behaviour is intentional: a stray non-numeric key
/// in a prekey dict would otherwise crash the max-id calculation.
/// In practice presage only ever writes numeric keys to these dicts.
pub(crate) fn list_keys_as_u32s(backend: &dyn KvBackend, dict: &str) -> Result<Vec<u32>, Error> {
    Ok(backend.list_keys(dict)?.into_iter().filter_map(|k| k.parse::<u32>().ok()).collect())
}

/// Like [`backend_get_json`] but errors on missing key.
///
/// Used by iterator closures over `list_keys` that have established
/// the key's presence and treat its disappearance as a backend
/// inconsistency rather than a normal absence. The closure is only
/// evaluated on the missing branch (avoids constructing the message
/// string on the hot path).
pub(crate) fn backend_get_json_required<T: for<'de> serde::Deserialize<'de>>(
    backend: &dyn KvBackend,
    dict: &str,
    key: &str,
    missing_msg: impl FnOnce() -> String,
) -> Result<T, Error> {
    match backend.get(dict, key)? {
        Some(bytes) => Ok(serde_json::from_slice(&bytes)?),
        None => Err(Error::Backend(missing_msg())),
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use futures_lite::future::block_on;
    use presage::libsignal_service::{
        Profile,
        prelude::{MasterKey, ProfileKey, Uuid},
        protocol::IdentityKeyPair,
    };
    use presage::manager::RegistrationData;
    use presage::store::{ContentsStore, StateStore};

    use super::*;

    /// Minimal fixture matching the real shape of the data the
    /// link/register flows produce. `RegistrationData` has private
    /// fields so we construct it via JSON round-trip — the on-disk
    /// format the StateStore actually serializes is the same JSON.
    /// `phone_number` and `profile_key` go in as their fully-typed
    /// serde representations (struct and byte array, respectively).
    fn fixture_registration() -> RegistrationData {
        let phone_number = serde_json::to_value(phonenumber::parse(None, "+15555550100").unwrap()).unwrap();
        // RegistrationData::profile_key serializes as base64 (not a
        // byte array) — see presage/src/serde.rs (whisperfish/presage)
        // serde_profile_key. We deserialize from a fixed base64 string
        // here so the test doesn't depend on a particular encoding
        // detail of `ProfileKey::generate`.
        let json_str = format!(
            "{{\"signal_servers\":\"Production\",\
              \"device_name\":\"xous-test\",\
              \"phone_number\":{phone_number},\
              \"uuid\":\"00000000-0000-4000-8000-000000000001\",\
              \"pni\":\"00000000-0000-4000-8000-000000000002\",\
              \"password\":\"test-password\",\
              \"device_id\":2,\
              \"registration_id\":1234,\
              \"pni_registration_id\":5678,\
              \"profile_key\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"}}"
        );
        serde_json::from_str(&json_str).expect("fixture deserializes")
    }

    fn fixture_profile() -> Profile {
        Profile {
            name: None,
            about: Some("hello from xous".to_string()),
            about_emoji: Some("\u{1F44B}".to_string()),
            avatar: None,
            unrestricted_unidentified_access: false,
        }
    }

    #[test]
    fn empty_store_reports_unregistered() {
        let store = PddbStore::with_mock_backend();
        block_on(async {
            assert!(!store.is_registered().await);
            assert!(store.load_registration_data().await.unwrap().is_none());
            assert!(store.sender_certificate().await.unwrap().is_none());
            assert!(store.fetch_master_key().await.unwrap().is_none());
        });
    }

    #[test]
    fn registration_data_round_trip() {
        let mut store = PddbStore::with_mock_backend();
        let reg = fixture_registration();
        block_on(async {
            store.save_registration_data(&reg).await.unwrap();
            assert!(store.is_registered().await);
            let loaded = store.load_registration_data().await.unwrap().unwrap();
            assert_eq!(serde_json::to_value(&loaded).unwrap(), serde_json::to_value(&reg).unwrap(),);
        });
    }

    #[test]
    fn identity_key_pair_round_trip() {
        let store = PddbStore::with_mock_backend();
        let mut rng = rand::rng();
        let aci_kp = IdentityKeyPair::generate(&mut rng);
        let pni_kp = IdentityKeyPair::generate(&mut rng);

        block_on(async {
            // `StateStore` only persists identity key pairs; the load
            // path lives on the protocol-store trait, not StateStore.
            // Assert via the raw backend instead — the bytes round-trip
            // through the dict.
            store.set_aci_identity_key_pair(aci_kp).await.unwrap();
            store.set_pni_identity_key_pair(pni_kp).await.unwrap();
            assert!(store.backend.get("signal.state", "aci_identity_key_pair").unwrap().is_some());
            assert!(store.backend.get("signal.state", "pni_identity_key_pair").unwrap().is_some());
        });
    }

    #[test]
    fn master_key_round_trip() {
        let store = PddbStore::with_mock_backend();
        let raw = [0xab_u8; 32];
        let mk = MasterKey::from_slice(&raw).unwrap();
        block_on(async {
            store.store_master_key(Some(&mk)).await.unwrap();
            let loaded = store.fetch_master_key().await.unwrap().unwrap();
            assert_eq!(loaded.inner, raw);

            // Storing None clears it.
            store.store_master_key(None).await.unwrap();
            assert!(store.fetch_master_key().await.unwrap().is_none());
        });
    }

    #[test]
    fn clear_registration_resets_state() {
        let mut store = PddbStore::with_mock_backend();
        let reg = fixture_registration();
        let mk = MasterKey::from_slice(&[0x77_u8; 32]).unwrap();
        block_on(async {
            store.save_registration_data(&reg).await.unwrap();
            store.store_master_key(Some(&mk)).await.unwrap();
            assert!(store.is_registered().await);

            store.clear_registration().await.unwrap();
            assert!(!store.is_registered().await);
            assert!(store.load_registration_data().await.unwrap().is_none());
            assert!(store.fetch_master_key().await.unwrap().is_none());
        });
    }

    /// Pre-link guard predicate: a never-written store must not
    /// trip it (a genuine first link must not be blocked).
    #[test]
    fn empty_store_has_no_account_state() {
        let store = PddbStore::with_mock_backend();
        assert!(!store.has_account_state());
    }

    /// Registration data alone trips the predicate, and a full
    /// `Store::clear` (the wipe the guard routes the user to)
    /// resets it.
    #[test]
    fn registration_counts_as_account_state_until_cleared() {
        let mut store = PddbStore::with_mock_backend();
        block_on(async {
            store.save_registration_data(&fixture_registration()).await.unwrap();
            assert!(store.has_account_state());

            store.clear().await.unwrap();
            assert!(!store.has_account_state());
        });
    }

    /// Leftover protocol keys trip the predicate even with no
    /// registration data — the post-fa1c37b hazard is exactly a
    /// store whose registration was cleared (presage clears it on
    /// link entry) but whose session/kyber dicts survived.
    #[test]
    fn protocol_keys_count_as_account_state() {
        let store = PddbStore::with_mock_backend();
        store.backend.put(&protocol::dict_kyber_prekey(IdentityType::Aci), "17", &[0u8; 4]).unwrap();
        assert!(store.has_account_state());
    }

    #[test]
    fn profile_round_trip() {
        let mut store = PddbStore::with_mock_backend();
        let uuid = Uuid::from_str("00000000-0000-4000-8000-000000000003").unwrap();
        let key = ProfileKey::generate([1u8; 32]);
        let profile = fixture_profile();
        block_on(async {
            assert!(store.profile(uuid, key).await.unwrap().is_none());
            store.save_profile(uuid, key, profile.clone()).await.unwrap();
            let loaded = store.profile(uuid, key).await.unwrap().unwrap();
            assert_eq!(serde_json::to_value(&loaded).unwrap(), serde_json::to_value(&profile).unwrap(),);
        });
    }

    /// A `PddbStore` clone shares its backend — both clones see the
    /// same writes. This is the property `Manager` relies on when it
    /// hands store clones to its sub-components.
    #[test]
    fn clones_share_backend() {
        let store_a = PddbStore::with_mock_backend();
        let mut store_b = store_a.clone();
        block_on(async {
            store_b.save_registration_data(&fixture_registration()).await.unwrap();
            assert!(store_a.is_registered().await);
        });
    }

    // ------------------------------------------------------------------
    // libsignal protocol storage traits
    // ------------------------------------------------------------------

    use presage::libsignal_service::pre_keys::{KyberPreKeyStoreExt, PreKeysStore};
    use presage::libsignal_service::prelude::SessionStoreExt;
    use presage::libsignal_service::protocol::ServiceId;
    use presage::libsignal_service::protocol::{
        Aci, GenericSignedPreKey, IdentityKeyStore, KeyPair, KyberPreKeyId, KyberPreKeyRecord,
        KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore, ProtocolAddress, SenderKeyRecord,
        SenderKeyStore, SessionRecord, SessionStore, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
        Timestamp, kem,
    };
    use presage::store::Store;

    fn registered_store() -> PddbStore {
        let mut store = PddbStore::with_mock_backend();
        block_on(async {
            store.save_registration_data(&fixture_registration()).await.unwrap();
        });
        store
    }

    fn fixture_address(uuid_str: &str, device: u32) -> ProtocolAddress {
        let aci_uuid = Uuid::from_str(uuid_str).unwrap();
        let aci = Aci::from_uuid_bytes(aci_uuid.into_bytes());
        ProtocolAddress::new(aci.service_id_string(), device.try_into().unwrap())
    }

    #[test]
    fn identity_key_store_round_trip() {
        let store = registered_store();
        let mut rng = rand::rng();
        let aci_kp = IdentityKeyPair::generate(&mut rng);

        block_on(async {
            store.set_aci_identity_key_pair(aci_kp).await.unwrap();
            let mut aci = store.aci_protocol_store();

            // get_identity_key_pair pulls from signal.state via the
            // protocol-store wrapper.
            let loaded = aci.get_identity_key_pair().await.unwrap();
            assert_eq!(loaded.serialize(), aci_kp.serialize());

            // get_local_registration_id pulls from RegistrationData.
            assert_eq!(aci.get_local_registration_id().await.unwrap(), 1234);

            // save_identity / get_identity round-trip.
            let addr = fixture_address("00000000-0000-4000-8000-000000000010", 1);
            let other_kp = IdentityKeyPair::generate(&mut rng);
            let other_id = *other_kp.identity_key();
            let change = aci.save_identity(&addr, &other_id).await.unwrap();
            assert!(matches!(change, presage::libsignal_service::protocol::IdentityChange::NewOrUnchanged));
            let loaded = aci.get_identity(&addr).await.unwrap().unwrap();
            assert_eq!(loaded, other_id);

            // Saving the same identity again is NewOrUnchanged.
            let change = aci.save_identity(&addr, &other_id).await.unwrap();
            assert!(matches!(change, presage::libsignal_service::protocol::IdentityChange::NewOrUnchanged));

            // Saving a different one is ReplacedExisting.
            let third_kp = IdentityKeyPair::generate(&mut rng);
            let third_id = *third_kp.identity_key();
            let change = aci.save_identity(&addr, &third_id).await.unwrap();
            assert!(matches!(change, presage::libsignal_service::protocol::IdentityChange::ReplacedExisting));
        });
    }

    #[test]
    fn pre_key_store_round_trip_packed() {
        let store = PddbStore::with_mock_backend();
        let mut rng = rand::rng();
        block_on(async {
            let mut aci = store.aci_protocol_store();
            for id_u32 in [1u32, 2, 3, 100] {
                let kp = KeyPair::generate(&mut rng);
                let record = PreKeyRecord::new(PreKeyId::from(id_u32), &kp);
                aci.save_pre_key(PreKeyId::from(id_u32), &record).await.unwrap();
            }
            // Round-trip
            for id_u32 in [1u32, 2, 3, 100] {
                let loaded = aci.get_pre_key(PreKeyId::from(id_u32)).await.unwrap();
                assert_eq!(u32::from(loaded.id().unwrap()), id_u32);
            }
            // Remove one
            aci.remove_pre_key(PreKeyId::from(2)).await.unwrap();
            assert!(aci.get_pre_key(PreKeyId::from(2)).await.is_err());
            // Other entries still present
            assert!(aci.get_pre_key(PreKeyId::from(3)).await.is_ok());
        });
    }

    #[test]
    fn signed_pre_key_round_trip() {
        let store = PddbStore::with_mock_backend();
        let mut rng = rand::rng();
        let identity_kp = IdentityKeyPair::generate(&mut rng);
        block_on(async {
            let mut aci = store.aci_protocol_store();
            let kp = KeyPair::generate(&mut rng);
            let sig =
                identity_kp.private_key().calculate_signature(&kp.public_key.serialize(), &mut rng).unwrap();
            let id = SignedPreKeyId::from(7);
            let record = SignedPreKeyRecord::new(id, Timestamp::from_epoch_millis(1), &kp, &sig);
            aci.save_signed_pre_key(id, &record).await.unwrap();
            let loaded = aci.get_signed_pre_key(id).await.unwrap();
            assert_eq!(loaded.signature().unwrap(), sig.to_vec());
        });
    }

    #[test]
    fn kyber_pre_key_one_time_round_trip_and_use() {
        let store = PddbStore::with_mock_backend();
        let mut rng = rand::rng();
        let identity_kp = IdentityKeyPair::generate(&mut rng);
        block_on(async {
            let mut aci = store.aci_protocol_store();
            let id = KyberPreKeyId::from(11);
            let record =
                KyberPreKeyRecord::generate(kem::KeyType::Kyber1024, id, identity_kp.private_key()).unwrap();
            aci.save_kyber_pre_key(id, &record).await.unwrap();
            assert!(aci.get_kyber_pre_key(id).await.is_ok());

            let ec_id = SignedPreKeyId::from(13);
            let base = KeyPair::generate(&mut rng).public_key;
            // One-time: mark_used deletes outright.
            aci.mark_kyber_pre_key_used(id, ec_id, &base).await.unwrap();
            assert!(aci.get_kyber_pre_key(id).await.is_err());
        });
    }

    #[test]
    fn kyber_pre_key_last_resort_dedup() {
        let store = PddbStore::with_mock_backend();
        let mut rng = rand::rng();
        let identity_kp = IdentityKeyPair::generate(&mut rng);
        block_on(async {
            let mut aci = store.aci_protocol_store();
            let id = KyberPreKeyId::from(31);
            let record =
                KyberPreKeyRecord::generate(kem::KeyType::Kyber1024, id, identity_kp.private_key()).unwrap();
            aci.store_last_resort_kyber_pre_key(id, &record).await.unwrap();

            let ec_id = SignedPreKeyId::from(13);
            let base = KeyPair::generate(&mut rng).public_key;

            // First use: succeeds.
            aci.mark_kyber_pre_key_used(id, ec_id, &base).await.unwrap();
            // Last-resort: still available after first mark.
            assert!(aci.get_kyber_pre_key(id).await.is_ok());
            // Second use with same base: rejected.
            assert!(aci.mark_kyber_pre_key_used(id, ec_id, &base).await.is_err());

            // load_last_resort_kyber_pre_keys returns it.
            let lasts = aci.load_last_resort_kyber_pre_keys().await.unwrap();
            assert_eq!(lasts.len(), 1);
        });
    }

    #[test]
    fn session_cache_then_flush_then_load() {
        let store = PddbStore::with_mock_backend();
        block_on(async {
            let mut aci = store.aci_protocol_store();
            let addr = fixture_address("00000000-0000-4000-8000-000000000020", 2);
            let session = SessionRecord::new_fresh();
            aci.store_session(&addr, &session).await.unwrap();

            // store_session writes to cache only; dirty set has it.
            assert_eq!(store.session_cache_len(), 1);
            assert_eq!(store.session_dirty_len(), 1);

            // load_session reads from cache.
            let loaded = aci.load_session(&addr).await.unwrap().unwrap();
            assert_eq!(loaded.serialize().unwrap(), session.serialize().unwrap());

            // Flush persists; dirty set drains.
            let written = store.flush_sessions().unwrap();
            assert_eq!(written, 1);
            assert_eq!(store.session_dirty_len(), 0);

            // Cache stays warm; PDDB has the bytes too. Drop cache and reload to verify.
            store.session_cache.lock().unwrap().clear();
            let loaded = aci.load_session(&addr).await.unwrap().unwrap();
            assert_eq!(loaded.serialize().unwrap(), session.serialize().unwrap());

            // Idempotent: a second flush is cheap.
            let written = store.flush_sessions().unwrap();
            assert_eq!(written, 0);
        });
    }

    #[test]
    fn sender_key_round_trip() {
        let store = PddbStore::with_mock_backend();
        let mut rng = rand::rng();
        let identity_kp = IdentityKeyPair::generate(&mut rng);
        block_on(async {
            let mut aci = store.aci_protocol_store();
            let addr = fixture_address("00000000-0000-4000-8000-000000000030", 3);
            let dist_id = Uuid::from_str("11111111-2222-3333-4444-555555555555").unwrap();

            // Build a SenderKeyRecord via the SenderKeyStore's own
            // create_sender_key_distribution_message helper. We don't
            // exercise the message API here — just round-trip the
            // record bytes.
            use presage::libsignal_service::protocol::create_sender_key_distribution_message;
            let _ = identity_kp; // unused in this construction
            let _ = create_sender_key_distribution_message(&addr, dist_id, &mut aci, &mut rng).await.unwrap();

            // Subsequent load returns Some.
            let loaded = aci.load_sender_key(&addr, dist_id).await.unwrap();
            assert!(loaded.is_some());

            // Storing a record-shaped clone round-trips.
            let bytes = loaded.unwrap().serialize().unwrap();
            let cloned = SenderKeyRecord::deserialize(&bytes).unwrap();
            aci.store_sender_key(&addr, dist_id, &cloned).await.unwrap();
            assert!(aci.load_sender_key(&addr, dist_id).await.unwrap().is_some());
        });
    }

    // ------------------------------------------------------------------
    // libsignal-service-rs extension traits
    // ------------------------------------------------------------------

    #[test]
    fn next_pre_key_id_increments() {
        let store = PddbStore::with_mock_backend();
        let mut rng = rand::rng();
        block_on(async {
            let mut aci = store.aci_protocol_store();
            // Empty store: starts at 1.
            assert_eq!(aci.next_pre_key_id().await.unwrap(), 1);
            assert_eq!(aci.next_signed_pre_key_id().await.unwrap(), 1);
            assert_eq!(aci.next_pq_pre_key_id().await.unwrap(), 1);

            // Save id=5; next becomes 6.
            let kp = KeyPair::generate(&mut rng);
            aci.save_pre_key(PreKeyId::from(5), &PreKeyRecord::new(PreKeyId::from(5), &kp)).await.unwrap();
            assert_eq!(aci.next_pre_key_id().await.unwrap(), 6);
        });
    }

    #[test]
    fn session_store_ext_delete_paths() {
        let store = PddbStore::with_mock_backend();
        block_on(async {
            let mut aci = store.aci_protocol_store();
            let aci_const = store.aci_protocol_store();
            // Two devices for the same UUID.
            let aci_uuid = "00000000-0000-4000-8000-000000000040";
            let addr1 = fixture_address(aci_uuid, 1);
            let addr2 = fixture_address(aci_uuid, 2);
            aci.store_session(&addr1, &SessionRecord::new_fresh()).await.unwrap();
            aci.store_session(&addr2, &SessionRecord::new_fresh()).await.unwrap();
            store.flush_sessions().unwrap();

            // get_sub_device_sessions: should return [2] (excluding device 1 = main).
            let aci_id = ServiceId::Aci(presage::libsignal_service::protocol::Aci::from_uuid_bytes(
                Uuid::from_str(aci_uuid).unwrap().into_bytes(),
            ));
            let subs = aci_const.get_sub_device_sessions(&aci_id).await.unwrap();
            assert_eq!(subs.len(), 1);
            assert_eq!(u32::from(subs[0]), 2);

            // delete_session(addr1): removes that one only.
            aci_const.delete_session(&addr1).await.unwrap();
            assert!(aci_const.load_session(&addr1).await.unwrap().is_none());
            assert!(aci_const.load_session(&addr2).await.unwrap().is_some());

            // delete_all_sessions(uuid): removes the rest.
            let n = aci_const.delete_all_sessions(&aci_id).await.unwrap();
            assert_eq!(n, 1);
            assert!(aci_const.load_session(&addr2).await.unwrap().is_none());
        });
    }

    // ------------------------------------------------------------------
    // ContentsStore (the rest of it)
    // ------------------------------------------------------------------

    #[test]
    fn contact_round_trip() {
        let mut store = PddbStore::with_mock_backend();
        let uuid = Uuid::from_str("00000000-0000-4000-8000-000000000050").unwrap();
        block_on(async {
            let contact = presage::model::contacts::Contact {
                uuid,
                phone_number: None,
                name: "Test User".to_string(),
                verified: Default::default(),
                profile_key: vec![],
                expire_timer: 0,
                expire_timer_version: 2,
                inbox_position: 0,
                avatar: None,
            };
            store.save_contact(&contact).await.unwrap();

            let aci =
                ServiceId::Aci(presage::libsignal_service::protocol::Aci::from_uuid_bytes(uuid.into_bytes()));
            let loaded = store.contact_by_id(&aci).await.unwrap().unwrap();
            assert_eq!(loaded.name, "Test User");

            let all: Vec<_> = store.contacts().await.unwrap().collect();
            assert_eq!(all.len(), 1);
            store.clear_contacts().await.unwrap();
            assert!(store.contact_by_id(&aci).await.unwrap().is_none());
        });
    }

    #[test]
    fn group_round_trip() {
        let store = PddbStore::with_mock_backend();
        let mut store_mut = store.clone();
        let master_key = [42u8; 32];
        block_on(async {
            let group = presage::model::groups::Group {
                title: "Test Group".to_string(),
                avatar: String::new(),
                disappearing_messages_timer: None,
                access_control: None,
                revision: 1,
                members: vec![],
                pending_members: vec![],
                requesting_members: vec![],
                invite_link_password: vec![],
                description: None,
            };
            store.save_group(master_key, group).await.unwrap();

            let loaded = store.group(master_key).await.unwrap().unwrap();
            assert_eq!(loaded.title, "Test Group");

            let all: Vec<_> = store.groups().await.unwrap().collect();
            assert_eq!(all.len(), 1);

            store_mut.clear_groups().await.unwrap();
            assert!(store.group(master_key).await.unwrap().is_none());
        });
    }

    #[test]
    fn profile_key_round_trip() {
        let mut store = PddbStore::with_mock_backend();
        let uuid = Uuid::from_str("00000000-0000-4000-8000-000000000060").unwrap();
        let pk = ProfileKey::generate([2u8; 32]);
        block_on(async {
            // First save: returns true (new).
            assert!(store.upsert_profile_key(&uuid, pk).await.unwrap());
            // Second save (same key): returns false.
            assert!(!store.upsert_profile_key(&uuid, pk).await.unwrap());

            let aci =
                ServiceId::Aci(presage::libsignal_service::protocol::Aci::from_uuid_bytes(uuid.into_bytes()));
            let loaded = store.profile_key(&aci).await.unwrap().unwrap();
            assert_eq!(loaded.get_bytes(), pk.get_bytes());
        });
    }

    #[test]
    fn sticker_pack_round_trip() {
        let mut store = PddbStore::with_mock_backend();
        let pack = presage::store::StickerPack {
            id: vec![1, 2, 3, 4],
            key: vec![5, 6, 7, 8],
            manifest: presage::store::StickerPackManifest {
                title: "Test".to_string(),
                author: "T".to_string(),
                cover: None,
                stickers: vec![],
            },
        };
        block_on(async {
            store.add_sticker_pack(&pack).await.unwrap();
            let loaded = store.sticker_pack(&[1, 2, 3, 4]).await.unwrap().unwrap();
            assert_eq!(loaded.manifest.title, "Test");

            let all: Vec<_> = store.sticker_packs().await.unwrap().collect();
            assert_eq!(all.len(), 1);

            assert!(store.remove_sticker_pack(&[1, 2, 3, 4]).await.unwrap());
            assert!(!store.remove_sticker_pack(&[1, 2, 3, 4]).await.unwrap());
        });
    }

    #[test]
    fn message_round_trip_and_range() {
        use presage::libsignal_service::content::{Content, ContentBody, Metadata};
        use presage::libsignal_service::proto;
        use presage::libsignal_service::protocol::DeviceId;
        use presage::store::Thread;

        let mut store = PddbStore::with_mock_backend();
        let aci_uuid = Uuid::from_str("00000000-0000-4000-8000-000000000080").unwrap();
        let aci = Aci::from_uuid_bytes(aci_uuid.into_bytes());
        let thread = Thread::Contact(ServiceId::Aci(aci));

        // Build a minimal Content. ContentBody::DataMessage with just a
        // body field — round-trips through prost.
        fn build_content(sender: ServiceId, ts: u64) -> Content {
            let body = ContentBody::DataMessage(proto::DataMessage {
                body: Some(format!("hello-{ts}")),
                ..Default::default()
            });
            Content {
                metadata: Metadata {
                    sender,
                    destination: sender,
                    sender_device: DeviceId::try_from(1u32).unwrap(),
                    server_guid: None,
                    timestamp: ts,
                    needs_receipt: false,
                    unidentified_sender: false,
                    was_plaintext: false,
                },
                body,
            }
        }

        block_on(async {
            for ts in [100u64, 200, 300] {
                store.save_message(&thread, build_content(ServiceId::Aci(aci), ts)).await.unwrap();
            }

            // Single-message lookup.
            let msg = store.message(&thread, 200).await.unwrap().unwrap();
            assert_eq!(msg.metadata.timestamp, 200);

            // Range query: 150..=250 → just 200.
            let msgs: Vec<_> = store.messages(&thread, 150u64..=250).await.unwrap().collect();
            assert_eq!(msgs.len(), 1);
            assert_eq!(msgs.into_iter().next().unwrap().unwrap().metadata.timestamp, 200);

            // Range unbounded: all three, sorted.
            let msgs: Vec<_> = store.messages(&thread, ..).await.unwrap().collect();
            assert_eq!(msgs.len(), 3);
            let timestamps: Vec<u64> = msgs.into_iter().map(|r| r.unwrap().metadata.timestamp).collect();
            assert_eq!(timestamps, vec![100, 200, 300]);

            // Delete one.
            assert!(store.delete_message(&thread, 200).await.unwrap());
            assert!(!store.delete_message(&thread, 200).await.unwrap()); // already gone
            assert!(store.message(&thread, 200).await.unwrap().is_none());

            // clear_thread wipes the rest.
            store.clear_thread(&thread).await.unwrap();
            assert!(store.message(&thread, 100).await.unwrap().is_none());
        });
    }

    #[test]
    fn store_clear_resets_everything() {
        let mut store = PddbStore::with_mock_backend();
        let uuid = Uuid::from_str("00000000-0000-4000-8000-000000000070").unwrap();
        let pk = ProfileKey::generate([3u8; 32]);
        block_on(async {
            // Populate StateStore + ContentsStore + ProtocolStore.
            store.save_registration_data(&fixture_registration()).await.unwrap();
            store.upsert_profile_key(&uuid, pk).await.unwrap();
            let mut aci = store.aci_protocol_store();
            let addr = fixture_address("00000000-0000-4000-8000-000000000071", 1);
            aci.store_session(&addr, &SessionRecord::new_fresh()).await.unwrap();
            store.flush_sessions().unwrap();

            assert!(store.is_registered().await);
            assert_eq!(store.session_cache_len(), 1);

            // clear() drops everything: state, contents, protocol dicts,
            // session cache.
            store.clear().await.unwrap();
            assert!(!store.is_registered().await);
            let aci2 = store.aci_protocol_store();
            assert!(aci2.load_session(&addr).await.unwrap().is_none());
            assert!(
                store
                    .profile_key(&ServiceId::Aci(presage::libsignal_service::protocol::Aci::from_uuid_bytes(
                        uuid.into_bytes()
                    )))
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(store.session_cache_len(), 0);
        });
    }

    // ------------------------------------------------------------------
    // BufferingBackend integration via PddbStore::new_buffering
    // ------------------------------------------------------------------

    /// A PddbStore built via `new_buffering` behaves identically to one
    /// built via `new` when no batch is open — writes pass through.
    #[test]
    fn buffering_store_passthrough_when_no_batch() {
        use presage::libsignal_service::protocol::IdentityKeyPair;
        let store = PddbStore::new_buffering(Arc::new(MockBackend::new()));
        let mut rng = rand::rng();
        let aci_kp = IdentityKeyPair::generate(&mut rng);
        block_on(async {
            store.set_aci_identity_key_pair(aci_kp).await.unwrap();
            assert!(store.backend.get("signal.state", "aci_identity_key_pair").unwrap().is_some());
        });
    }

    /// Inside a batch, Store-trait writes (which all go through
    /// `backend.put` eventually) get buffered. The inner backend
    /// remains unchanged until commit.
    #[test]
    fn buffering_store_writes_buffered_during_batch() {
        use presage::libsignal_service::protocol::IdentityKeyPair;
        let store = PddbStore::new_buffering(Arc::new(MockBackend::new()));
        let mut rng = rand::rng();
        let aci_kp = IdentityKeyPair::generate(&mut rng);

        block_on(async {
            // Seed inner with a sentinel via direct (no-batch) put.
            store.backend.put("signal.state", "sentinel", b"baseline").unwrap();

            let guard = store.begin_send_batch().unwrap().expect("buffering");
            assert!(store.is_send_batching());

            // A real Store-trait write inside the batch.
            store.set_aci_identity_key_pair(aci_kp).await.unwrap();
            assert!(guard.buffered_len() >= 1);

            // Inner is unchanged for the buffered key — we can verify
            // by aborting and reading through the (un-batched) path.
            // The sentinel stays put either way.
            drop(guard); // abort
            assert!(!store.is_send_batching());

            // The identity key was discarded by the abort.
            assert!(store.backend.get("signal.state", "aci_identity_key_pair").unwrap().is_none());
            // Sentinel still present.
            assert_eq!(
                store.backend.get("signal.state", "sentinel").unwrap().as_deref(),
                Some(b"baseline".as_slice())
            );
        });
    }

    /// Commit flushes the batch's buffered writes to the inner
    /// backend. Subsequent reads see them.
    #[test]
    fn buffering_store_commit_persists_writes() {
        use presage::libsignal_service::protocol::IdentityKeyPair;
        let store = PddbStore::new_buffering(Arc::new(MockBackend::new()));
        let mut rng = rand::rng();
        let aci_kp = IdentityKeyPair::generate(&mut rng);

        block_on(async {
            let guard = store.begin_send_batch().unwrap().expect("buffering");
            store.set_aci_identity_key_pair(aci_kp).await.unwrap();
            let n = guard.commit().unwrap();
            assert!(n >= 1);
            assert!(!store.is_send_batching());

            // Now visible in inner backend.
            assert!(store.backend.get("signal.state", "aci_identity_key_pair").unwrap().is_some());
        });
    }

    /// Reads through the same store during a batch see the buffered
    /// writes (read-through). The send-time path needs this so
    /// `is_trusted_identity` consults a freshly-buffered identity.
    #[test]
    fn buffering_store_read_through_during_batch() {
        use presage::libsignal_service::protocol::{
            Aci, IdentityKey, IdentityKeyPair, IdentityKeyStore, ProtocolAddress,
        };
        let mut store = PddbStore::new_buffering(Arc::new(MockBackend::new()));
        let mut rng = rand::rng();
        let local_kp = IdentityKeyPair::generate(&mut rng);
        let peer_kp = IdentityKeyPair::generate(&mut rng);

        block_on(async {
            store.set_aci_identity_key_pair(local_kp).await.unwrap();
            store.save_registration_data(&fixture_registration()).await.unwrap();

            let peer_addr = ProtocolAddress::new(
                Aci::from_uuid_bytes(
                    Uuid::from_str("00000000-0000-4000-8000-0000000000ab").unwrap().into_bytes(),
                )
                .service_id_string(),
                1u32.try_into().unwrap(),
            );

            // Inside a batch, save_identity buffers; then get_identity
            // (also via the protocol store) should see the buffered
            // value via read-through.
            let guard = store.begin_send_batch().unwrap().expect("buffering");
            let mut aci = store.aci_protocol_store();
            let peer_id: IdentityKey = *peer_kp.identity_key();
            aci.save_identity(&peer_addr, &peer_id).await.unwrap();
            let read_back = aci.get_identity(&peer_addr).await.unwrap();
            assert_eq!(read_back.as_ref(), Some(&peer_id));
            guard.commit().unwrap();

            // After commit, still readable.
            let aci2 = store.aci_protocol_store();
            let read_back = aci2.get_identity(&peer_addr).await.unwrap();
            assert_eq!(read_back.as_ref(), Some(&peer_id));
        });
    }

    /// A second `begin_send_batch` while one is already open returns
    /// Err so we don't accidentally interleave batches.
    #[test]
    fn buffering_store_rejects_nested_batches() {
        let store = PddbStore::new_buffering(Arc::new(MockBackend::new()));
        let _guard = store.begin_send_batch().unwrap().expect("buffering");
        assert!(store.begin_send_batch().is_err());
    }

    /// A store built via `with_mock_backend` (no buffering) returns
    /// `Ok(None)` from `begin_send_batch` — the call site is safe
    /// to add unconditionally.
    #[test]
    fn non_buffering_store_returns_none() {
        let store = PddbStore::with_mock_backend();
        assert!(matches!(store.begin_send_batch(), Ok(None)));
        assert!(!store.is_send_batching());
    }
}
