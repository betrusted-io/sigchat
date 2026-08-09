//! libsignal protocol storage traits implemented over `PddbStore`.
//!
//! Six required traits (`IdentityKeyStore`, `PreKeyStore`,
//! `SignedPreKeyStore`, `KyberPreKeyStore`, `SessionStore`,
//! `SenderKeyStore`) plus their `ProtocolStore` blanket, and the three
//! libsignal-service-rs extension traits (`PreKeysStore`,
//! `KyberPreKeyStoreExt`, `SessionStoreExt`) on the same struct.
//!
//! ACI vs PNI is a runtime split, not a type-level one: a single
//! [`PddbProtocolStore`] carries an [`IdentityType`] discriminator and
//! routes its dictionary names through it. Same shape
//! `presage-store-sqlite` uses (presage-store-sqlite/src/
//! protocol.rs:30-44 in whisperfish/presage).
//!
//! # Trust boundary
//!
//! Every byte read by this module came from PDDB. PDDB itself
//! authenticates each page with AES-256-GCM-SIV before returning it
//! (xous-core PDDB; see `services/pddb/src/backend/page.rs`). After
//! that, this module is the only thing standing between the disk
//! representation and a libsignal Double Ratchet step. We do **not**
//! add a second layer of MAC at the storage-trait boundary — PDDB's
//! per-page AEAD is the single trust boundary for persisted secrets.
//! Callers MUST NOT route bytes here from a non-PDDB source.
//!
//! # Security
//!
//! Persisted material, by sensitivity tier (high → public):
//!
//! - **`IdentityKeyPair`** (state dict, see `identity_key_store`): contains both the long-term Ed25519
//!   private key and its public half. **Compromise destroys the deniable-authentication property of every
//!   past and future session.** Stored as libsignal's binary `IdentityKeyPair::serialize()` (private bytes
//!   inline).
//! - **`SessionRecord`** (`session` dict): the Double Ratchet state for one `(uuid, device_id)`. Carries the
//!   current root key, chain keys, and the next-message ratchet keys. **Compromise reconstructs the
//!   last-ratchet plaintext window.** Stored as libsignal's protobuf `SessionRecord::serialize()`. See the
//!   write-coalescing note in `session_store.rs`.
//! - **`KyberPreKeyRecord`** (`kyber_prekey` dict): post-quantum secret material for one prekey. One-time
//!   keys are deleted on first use; last-resort keys persist and are dedup-protected against base-key reuse
//!   (`kyber_meta`).
//! - **`SignedPreKeyRecord`** (`signed_prekey` dict): the EC private key for a signed prekey plus the
//!   identity-key signature over its public half.
//! - **`PreKeyRecord`** (`prekey_bundle` packed key): one-time EC private keys. Consumed on first use by the
//!   receiver; the dirty set rewrites the whole bundle each time.
//! - **`SenderKeyRecord`** (`sender_key` dict): the symmetric sender key for a group distribution. Compromise
//!   lets the holder decrypt every message sent under that distribution id.
//! - **Identity public keys** (`identity` dict): peer identity keys (no private half). The decision to trust
//!   a (possibly rotated) key for an address is made by `is_trusted_identity` and governed by
//!   `PddbStore::trust_new_identities`.
//!
//! All persisted records are libsignal's own serialization — we do
//! **not** define new wire formats for key material. Bytes round-trip
//! through `record.serialize()` / `Record::deserialize(&[u8])`. The
//! `kyber_prekey` envelope is the one exception: a JSON `{record:
//! <bytes>, is_last_resort: bool}` wrapper around the libsignal bytes.
//!
//! Zeroization: this crate keeps libsignal's records owned through
//! the upstream `Drop` impls (presage-libsignal's
//! `KyberPreKeyRecord`/`PreKeyRecord`/`SignedPreKeyRecord` derive
//! `Zeroize` for their inner private-key bytes). The `Vec<u8>` /
//! `Vec<(u32, Vec<u8>)>` copies this module holds during
//! load/serialize do **not** zero on drop.
//!
//! # Logging
//!
//! Per-record bytes are never logged. Existing `tracing::warn!` calls
//! emit only the `ProtocolAddress` (UUID + device id), which is
//! non-secret-equivalent metadata. The `Debug` impl on
//! `PddbProtocolStore` is auto-derived but the inner `PddbStore::Debug`
//! is hand-rolled to print only cache cardinality (see `lib.rs`).
//!
//! # rv32 / 16 MiB constraint
//!
//! Storage is keyed by `(dict, key)` strings — every read or write
//! allocates two `String`s plus a value `Vec<u8>`. Per-record sizes
//! (libsignal binary serialization) are in the 70 B - 1500 B range; a
//! session-bundle for ~10 devices fits in a few KiB. The hot path
//! (session receive) buffers in the cache and flushes via
//! `flush_sessions`, capping PDDB IPCs at one `put` per address per
//! flush regardless of devices touched.
//!
//! # Encoding
//!
//! Dictionary layout:
//!
//! - `signal.protocol.{aci,pni}.session` — per `address.name()` (the UUID), key = `"{uuid}"`, value =
//!   `SessionBundle` (`device_id -> libsignal SessionRecord bytes`), bincode-versioned wrapper. **Hot.**
//!   Read/write through the in-memory dirty-set cache; [`crate::PddbStore::flush_sessions`] persists.
//! - `signal.protocol.{aci,pni}.identity` — per `ProtocolAddress`, key = `"{name}.{device_id}"`, value = peer
//!   identity *public* key bytes (`IdentityKey::serialize()`).
//! - `signal.protocol.{aci,pni}.prekey_bundle` — single packed key (`"all"`) holding `Vec<(u32, Vec<u8>)>` of
//!   all current one-time EC pre-keys. Packed because ~100 pre-keys × ~70 bytes is a fraction of one PDDB
//!   page; per-key would burn one page-AEAD per prekey.
//! - `signal.protocol.{aci,pni}.signed_prekey` — per id, value = libsignal `SignedPreKeyRecord::serialize()`
//!   bytes.
//! - `signal.protocol.{aci,pni}.kyber_prekey` — per id; the `is_last_resort` bit lives inside a JSON envelope
//!   alongside the libsignal record bytes (see [`kyber_pre_key_store`]).
//! - `signal.protocol.{aci,pni}.kyber_meta` — last-resort dedup table. Key = `"{kyber_id}.{ec_id}"`, value =
//!   `base_key.serialize()`. See `mark_kyber_pre_key_used` for the dedup semantics.
//! - `signal.protocol.{aci,pni}.sender_key` — per `(addr_name, device_id, distribution_uuid)`, value =
//!   libsignal `SenderKeyRecord::serialize()` bytes.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::PddbStore;

/// ACI vs PNI discriminator. The two protocol stores share their
/// schema — only the dict-name suffix changes.
///
/// The discriminator routes through a private `as_str` helper into
/// the dict-name helpers below. A typo or accidental crossover would
/// cross-pollinate ACI session state with PNI session state, so every
/// dict-name helper is in this file and gated through this enum.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum IdentityType {
    /// Account Identifier — Signal's primary user UUID.
    Aci,
    /// Phone-Number Identifier — separate identity for SMS-only
    /// reach, with its own keypair and session state.
    Pni,
}

impl IdentityType {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            IdentityType::Aci => "aci",
            IdentityType::Pni => "pni",
        }
    }
}

impl fmt::Display for IdentityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(self.as_str()) }
}

/// PDDB-backed implementation of every libsignal protocol storage
/// trait, parameterised at runtime by `IdentityType`.
///
/// `Clone` is shallow — two clones share the same [`PddbStore`]
/// (including its session cache) and the same identity discriminator,
/// which is exactly what `presage::Store::{aci,pni}_protocol_store`
/// expects.
///
/// # Security
///
/// Every method on this struct may read or write libsignal private
/// material (identity keypair, session root keys, pre-key private
/// bytes, sender-key chain bytes). Sensitivity inherits from the
/// underlying record types defined in libsignal-protocol; see the
/// protocol module-level docs for the per-record tier listing.
///
/// `Debug` is derived. The struct holds only the parent `PddbStore`
/// (whose own `Debug` is hand-rolled to redact secrets) and the
/// `IdentityType` discriminator, so derive is safe — but adding any
/// secret-bearing field here would require a hand-rolled `Debug` to
/// match the rustls/RustCrypto convention.
#[derive(Clone, Debug)]
pub struct PddbProtocolStore {
    pub(crate) store: PddbStore,
    pub(crate) identity: IdentityType,
}

impl PddbProtocolStore {
    pub(crate) fn new(store: PddbStore, identity: IdentityType) -> Self { Self { store, identity } }
}

// --- Dictionary name helpers ---

pub(crate) fn dict_session(identity: IdentityType) -> String {
    format!("signal.protocol.{}.session", identity.as_str())
}

pub(crate) fn dict_identity(identity: IdentityType) -> String {
    format!("signal.protocol.{}.identity", identity.as_str())
}

pub(crate) fn dict_prekey_bundle(identity: IdentityType) -> String {
    format!("signal.protocol.{}.prekey_bundle", identity.as_str())
}

pub(crate) fn dict_signed_prekey(identity: IdentityType) -> String {
    format!("signal.protocol.{}.signed_prekey", identity.as_str())
}

pub(crate) fn dict_kyber_prekey(identity: IdentityType) -> String {
    format!("signal.protocol.{}.kyber_prekey", identity.as_str())
}

pub(crate) fn dict_kyber_meta(identity: IdentityType) -> String {
    format!("signal.protocol.{}.kyber_meta", identity.as_str())
}

pub(crate) fn dict_sender_key(identity: IdentityType) -> String {
    format!("signal.protocol.{}.sender_key", identity.as_str())
}

/// Single packed key inside the `prekey_bundle` dict. We never split
/// out per-id keys — the whole vec rewrites on every save/remove.
pub(crate) const PREKEY_BUNDLE_KEY: &str = "all";

mod identity_key_store;
mod kyber_pre_key_store;
mod kyber_pre_key_store_ext;
mod pre_key_store;
mod pre_keys_store;
mod sender_key_store;
pub(crate) mod session_store;
mod session_store_ext;
mod signed_pre_key_store;

/// `ProtocolStore` blanket impl — composes the five required protocol
/// traits (per [`presage/src/store.rs:342-355`](https://github.com/whisperfish/presage/blob/main/presage/src/store.rs#L342-L355)).
impl presage::libsignal_service::protocol::ProtocolStore for PddbProtocolStore {}

/// Convert a [`crate::Error`] into the `SignalProtocolError` shape
/// libsignal expects from a protocol-store impl. Centralized here so
/// the eight impls don't each redefine it.
///
/// The mapping flattens every backend variant to
/// `SignalProtocolError::InvalidState("kv backend", e.to_string())`.
/// libsignal treats `InvalidState` as a fatal error for the
/// containing operation but does not unwind the session — the caller
/// (presage) surfaces it as a `StoreError` and decides whether to
/// abort the current message.
pub(crate) fn protocol_backend_err(
    e: crate::Error,
) -> presage::libsignal_service::protocol::SignalProtocolError {
    presage::libsignal_service::protocol::SignalProtocolError::InvalidState("kv backend", e.to_string())
}

/// Protocol-flavored [`crate::backend_get_json`]: takes a
/// `&'static str` decode context and returns `Result<Option<T>,
/// SignalProtocolError>`. Lets protocol-store impls share the
/// `backend.get + serde_json::from_slice` pattern while keeping their
/// per-callsite error context (e.g. "decode prekey bundle" vs "decode
/// kyber envelope") that the generic crate-level helper would replace
/// with the less informative "kv backend: ..." form.
pub(crate) fn backend_get_json_protocol<T: for<'de> serde::Deserialize<'de>>(
    backend: &dyn crate::KvBackend,
    dict: &str,
    key: &str,
    decode_context: &'static str,
) -> Result<Option<T>, presage::libsignal_service::protocol::SignalProtocolError> {
    use presage::libsignal_service::protocol::SignalProtocolError;
    match backend.get(dict, key).map_err(protocol_backend_err)? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| SignalProtocolError::InvalidState(decode_context, e.to_string())),
        None => Ok(None),
    }
}

/// Protocol-flavored `backend_put_json`: takes a `&'static str` encode
/// context. Inverse of `backend_get_json_protocol`.
pub(crate) fn backend_put_json_protocol<T: serde::Serialize + ?Sized>(
    backend: &dyn crate::KvBackend,
    dict: &str,
    key: &str,
    value: &T,
    encode_context: &'static str,
) -> Result<(), presage::libsignal_service::protocol::SignalProtocolError> {
    use presage::libsignal_service::protocol::SignalProtocolError;
    let bytes = serde_json::to_vec(value)
        .map_err(|e| SignalProtocolError::InvalidState(encode_context, e.to_string()))?;
    backend.put(dict, key, &bytes).map_err(protocol_backend_err)
}
