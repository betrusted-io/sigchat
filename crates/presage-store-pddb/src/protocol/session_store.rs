//! `SessionStore` impl with in-memory dirty-set cache.
//!
//! Every received message advances the ratchet, which means
//! `store_session` is on the receive hot path. PDDB writes cost at
//! least one 4 KiB page each (per-page AEAD); a write-through impl
//! burns a page per ratchet step. So we buffer.
//!
//! - `store_session` writes to an in-memory `HashMap<SessionKey, SessionRecord>` and marks the entry dirty.
//!   No PDDB write yet.
//! - `load_session` consults the cache first, then PDDB.
//! - [`crate::PddbStore::flush_sessions`] walks the dirty set and persists. The receive loop calls this on
//!   `Received::QueueEmpty`; tests call it explicitly to verify durability.
//!
//! # Trust boundary
//!
//! Persisted bytes -> [`SessionRecord`] is a trust crossing.
//! `SessionRecord::deserialize` validates libsignal's protobuf
//! framing and refuses malformed inputs; we forward that
//! `SignalProtocolError` upstream. Successful deserialization is the
//! trust witness — there is no second-layer MAC.
//!
//! # Security
//!
//! A [`SessionRecord`] carries Double Ratchet state for one
//! `(uuid, device_id)`:
//!
//! - **root key** for the current Diffie-Hellman ratchet;
//! - **chain keys** for the symmetric ratchets in each direction;
//! - the **ephemeral private keys** for the next-ratchet step;
//! - the *previous* root + chain keys retained for skipped-message decryption.
//!
//! Compromise of the bytes for an active session lets the holder
//! decrypt every plaintext that traverses that ratchet until the next
//! Diffie-Hellman ratchet step rotates the root key. The user has no
//! direct signal that this has happened — there is no safety-number
//! change for a session-state leak — so the only mitigation is to
//! keep the bytes inside the PDDB trust boundary.
//!
//! The in-memory `session_cache` on `PddbStore` is `Arc<Mutex<...>>`
//! of `HashMap<_, SessionRecord>`. libsignal's `SessionRecord` does
//! not implement `Drop`-time zeroization for its internal protobuf
//! buffers (see libsignal-protocol's `SessionRecord` source). The
//! `Vec<u8>` slices passed to `serialize` / `deserialize` likewise
//! leak.
//!
//! Bound on data loss: a power-cut between ratchet step and flush
//! leaves session state slightly behind the peer's view. libsignal
//! handles divergence by re-keying when sends fail (visible to the
//! user as a fresh safety-number prompt). Acceptable trade-off; the
//! alternative (write-through) is too slow for offline-message-burst
//! catch-up.
//!
//! # Logging
//!
//! `SessionRecord` does not derive `Debug` upstream and we add no
//! `tracing` emissions here that include its bytes. The
//! [`crate::PddbStore::Debug`] impl reports only cache cardinality.
//!
//! # rv32 / 16 MiB constraint
//!
//! One `SessionRecord` is ~250-1500 bytes serialized. The cache is
//! unbounded — it grows with the number of distinct
//! `(IdentityType, uuid, device_id)` triples the user has talked to.
//! For a Precursor user with hundreds of correspondents and a couple
//! devices each, the cache stays well under a MiB.
//! `flush_sessions` writes one PDDB key per address (bundled across
//! devices), so one IPC per flushed address regardless of device
//! count.

use std::collections::HashMap;

use async_trait::async_trait;
use presage::libsignal_service::protocol::{
    ProtocolAddress, SessionRecord, SessionStore, SignalProtocolError,
};

use super::{IdentityType, PddbProtocolStore, dict_session, protocol_backend_err};
use crate::{Error, KvBackend};

/// Cache key — `(identity, address.name(), device_id)`. The address
/// part is split from the device id so `flush_sessions` can group
/// by address and bundle every device's session into a single PDDB
/// key.
pub(crate) type SessionKey = (IdentityType, String, u32);

pub(crate) fn session_key(identity: IdentityType, address: &ProtocolAddress) -> SessionKey {
    (identity, address.name().to_string(), u32::from(address.device_id()))
}

/// On-disk shape for one PDDB session key: `device_id ->
/// SessionRecord::serialize() bytes`.
///
/// # Encoding
///
/// On-disk format is bincode prefixed by a one-byte version tag
/// (`SESSION_BUNDLE_VERSION_BINCODE_V1` = `0x01`). The encoder is
/// [`serialize_session_bundle`]; the decoder
/// [`deserialize_session_bundle`] falls back to legacy raw `serde_json`
/// if the first byte is not the version tag (preserves blobs written
/// by pre-versioning builds; the next write rewrites them as bincode).
///
/// # Security
///
/// Each value in the `HashMap` is a `Vec<u8>` of the libsignal binary
/// [`SessionRecord`] for one device — i.e. the full Double Ratchet
/// state for that `(uuid, device)`. Treatment is identical to a
/// [`SessionRecord`]: bytes must stay inside the PDDB trust boundary.
/// The `Vec<u8>` itself does not zero on drop.
pub(crate) type SessionBundle = HashMap<u32, Vec<u8>>;

/// Wire-format version byte for bincode-encoded `SessionBundle`
/// blobs. 0x01 was picked because it can't appear as the first byte
/// of a serde_json-encoded HashMap (JSON starts with `{` = 0x7B, or
/// — for an empty value — would be `{}`), so the deserializer can
/// route on the first byte without ambiguity. If we ever change the
/// encoding again, bump this and add the new branch to
/// `deserialize_session_bundle`.
const SESSION_BUNDLE_VERSION_BINCODE_V1: u8 = 0x01;

/// Encode a `SessionBundle` for the wire. Prefixes one version byte so
/// older blobs (raw `serde_json`) remain decodable in-place.
pub(crate) fn serialize_session_bundle(bundle: &SessionBundle) -> Result<Vec<u8>, Error> {
    let body = bincode::serialize(bundle).map_err(Error::encode)?;
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(SESSION_BUNDLE_VERSION_BINCODE_V1);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decode a `SessionBundle`. Reads the version byte; if it isn't
/// `SESSION_BUNDLE_VERSION_BINCODE_V1`, falls back to the legacy
/// `serde_json` decoder so blobs already on disk from a pre-bincode
/// build remain readable. The next time the caller writes the same
/// key it goes out as bincode, so the migration is one-way and
/// happens transparently.
pub(crate) fn deserialize_session_bundle(bytes: &[u8]) -> Result<SessionBundle, Error> {
    match bytes.first() {
        Some(&SESSION_BUNDLE_VERSION_BINCODE_V1) => {
            bincode::deserialize(&bytes[1..]).map_err(|e| Error::Decode(e.to_string()))
        }
        // Legacy: pre-versioning, raw serde_json. A real JSON map
        // starts with `{` (0x7B); a JSON array would be `[` (0x5B).
        // Neither collides with the version byte.
        _ => serde_json::from_slice(bytes).map_err(Error::from),
    }
}

/// `backend.get(...) + deserialize_session_bundle(...)` packaged for the
/// crate-internal SessionBundle callers. Mirrors
/// `backend_get_json_protocol` in shape but routes through the
/// bundle's bespoke codec.
pub(crate) fn backend_get_session_bundle(
    backend: &dyn KvBackend,
    dict: &str,
    key: &str,
) -> Result<Option<SessionBundle>, Error> {
    match backend.get(dict, key)? {
        Some(bytes) => Ok(Some(deserialize_session_bundle(&bytes)?)),
        None => Ok(None),
    }
}

/// `serialize_session_bundle(...) + backend.put(...)`. Inverse of
/// `backend_get_session_bundle`.
pub(crate) fn backend_put_session_bundle(
    backend: &dyn KvBackend,
    dict: &str,
    key: &str,
    bundle: &SessionBundle,
) -> Result<(), Error> {
    let bytes = serialize_session_bundle(bundle)?;
    backend.put(dict, key, &bytes)
}

/// `SignalProtocolError`-flavored wrapper for `backend_get_session_bundle`.
/// Carries the same `"decode session bundle"` context the previous
/// `backend_get_json_protocol::<SessionBundle>` call sites used.
pub(crate) fn backend_get_session_bundle_protocol(
    backend: &dyn KvBackend,
    dict: &str,
    key: &str,
) -> Result<Option<SessionBundle>, SignalProtocolError> {
    match backend.get(dict, key).map_err(protocol_backend_err)? {
        Some(bytes) => deserialize_session_bundle(&bytes)
            .map(Some)
            .map_err(|e| SignalProtocolError::InvalidState("decode session bundle", e.to_string())),
        None => Ok(None),
    }
}

/// `SignalProtocolError`-flavored wrapper for
/// `backend_put_session_bundle`.
pub(crate) fn backend_put_session_bundle_protocol(
    backend: &dyn KvBackend,
    dict: &str,
    key: &str,
    bundle: &SessionBundle,
) -> Result<(), SignalProtocolError> {
    let bytes = serialize_session_bundle(bundle)
        .map_err(|e| SignalProtocolError::InvalidState("encode session bundle", e.to_string()))?;
    backend.put(dict, key, &bytes).map_err(protocol_backend_err)
}

#[async_trait(?Send)]
impl SessionStore for PddbProtocolStore {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        let key = session_key(self.identity, address);

        // 1. Cache hit (most-recent ratchet state lives here until flush).
        {
            let cache = self
                .store
                .session_cache
                .lock()
                .map_err(|_| SignalProtocolError::InvalidState("session cache", "poisoned".into()))?;
            if let Some(rec) = cache.get(&key) {
                return Ok(Some(rec.clone()));
            }
        }

        // 2. Fall through to PDDB. One key per address; the value is a `SessionBundle` (device_id →
        //    serialized SessionRecord).
        let dict = dict_session(self.identity);
        let Some(bundle) = backend_get_session_bundle_protocol(&*self.store.backend, &dict, &key.1)? else {
            return Ok(None);
        };

        // Populate the cache with every device's record so a follow-up
        // `load_session` for a sibling device skips PDDB.
        {
            let mut cache = self
                .store
                .session_cache
                .lock()
                .map_err(|_| SignalProtocolError::InvalidState("session cache", "poisoned".into()))?;
            for (dev_id, ser) in &bundle {
                let cache_key = (self.identity, key.1.clone(), *dev_id);
                if !cache.contains_key(&cache_key) {
                    cache.insert(cache_key, SessionRecord::deserialize(ser)?);
                }
            }
        }

        match bundle.get(&key.2) {
            Some(ser) => SessionRecord::deserialize(ser).map(Some),
            None => Ok(None),
        }
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        let key = session_key(self.identity, address);
        let mut cache = self
            .store
            .session_cache
            .lock()
            .map_err(|_| SignalProtocolError::InvalidState("session cache", "poisoned".into()))?;
        cache.insert(key.clone(), record.clone());
        let mut dirty = self
            .store
            .session_dirty
            .lock()
            .map_err(|_| SignalProtocolError::InvalidState("session dirty", "poisoned".into()))?;
        dirty.insert(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_bundle() -> SessionBundle {
        let mut b: SessionBundle = HashMap::new();
        b.insert(1, vec![0x10, 0x20, 0x30, 0x40]);
        b.insert(2, vec![0xff; 256]);
        b.insert(7, b"hello".to_vec());
        b
    }

    #[test]
    fn bincode_roundtrip() {
        let b = sample_bundle();
        let bytes = serialize_session_bundle(&b).expect("serialize");
        assert_eq!(
            bytes.first(),
            Some(&SESSION_BUNDLE_VERSION_BINCODE_V1),
            "bincode-encoded blob must start with the version byte"
        );
        let decoded = deserialize_session_bundle(&bytes).expect("deserialize");
        assert_eq!(b, decoded);
    }

    #[test]
    fn legacy_json_decodes() {
        // A bundle produced by the pre-versioning build: raw
        // serde_json with `Vec<u8>` rendered as a decimal-int array.
        // The HashMap key here is stringified because that's how
        // serde_json round-trips `HashMap<u32, _>` (JSON object keys
        // must be strings).
        let legacy_json = br#"{"1":[16,32,48,64],"7":[104,101,108,108,111]}"#;
        let decoded = deserialize_session_bundle(legacy_json).expect("legacy decode");
        assert_eq!(decoded.get(&1), Some(&vec![16u8, 32, 48, 64]));
        assert_eq!(decoded.get(&7), Some(&b"hello".to_vec()));
    }

    #[test]
    fn empty_bundle_roundtrips() {
        let b: SessionBundle = HashMap::new();
        let bytes = serialize_session_bundle(&b).expect("serialize");
        let decoded = deserialize_session_bundle(&bytes).expect("deserialize");
        assert!(decoded.is_empty());
    }

    #[test]
    fn bincode_is_substantially_smaller_than_json() {
        // The whole point of the encoding swap: a `SessionBundle` of
        // 5 devices × ~250 bytes each (typical libsignal
        // SessionRecord size) must encode to well under MAX_PDDB_WRITE_
        // BATCH_LEN (3800) once bundled with its dict + key. JSON-
        // encoded the same bundle is 3-4× larger and would still
        // exceed the per-IPC chunk size, so the assertion guards the
        // load-bearing premise of the encoding change.
        let mut b: SessionBundle = HashMap::new();
        for dev in 1u32..=5 {
            b.insert(dev, vec![0xAB; 250]);
        }
        let bincode_bytes = serialize_session_bundle(&b).expect("serialize");
        let json_bytes = serde_json::to_vec(&b).expect("json serialize");
        assert!(
            bincode_bytes.len() * 2 < json_bytes.len(),
            "bincode should be at least 2× smaller than JSON for byte-array values: \
             bincode={}, json={}",
            bincode_bytes.len(),
            json_bytes.len()
        );
        // And the bincode form should fit comfortably in one batch IPC.
        assert!(
            bincode_bytes.len() < 2048,
            "5-device bundle ({} bytes) should fit well under a batch IPC",
            bincode_bytes.len()
        );
    }
}
