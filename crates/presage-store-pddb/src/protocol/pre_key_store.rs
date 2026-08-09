//! `PreKeyStore` impl, packed-key strategy.
//!
//! A single PDDB key (`signal.protocol.{aci,pni}.prekey_bundle["all"]`)
//! holds `Vec<(u32, Vec<u8>)>` — `(prekey_id, serialized_record)`
//! pairs covering every current one-time EC pre-key. Per-key storage
//! would burn one PDDB page per record (per-page AEAD); ~100
//! pre-keys × ~70 bytes packed easily fit in one page.
//!
//! Trade-off: every save/remove rewrites the whole vec. With ~100
//! entries × ~70 bytes that's ~7 KB per write — well under the
//! per-page rewrite cost of one-key-per-id. If the prekey count grows
//! materially we'll reconsider, but Signal's published
//! prekey-replenish count is 100 (`PRE_KEY_BATCH_SIZE`) and the
//! lower-bound is 10 (`PRE_KEY_MINIMUM`); so the upper bound is
//! well-behaved.
//!
//! # Security
//!
//! Each entry in the bundle is a serialized libsignal
//! [`PreKeyRecord`] — a one-time EC private key plus its id and
//! public half. Compromise of a prekey's private bytes lets an
//! attacker decrypt the X3DH-initiated session that consumed it, but
//! only until the first ratchet rotation. Prekeys are consumed by
//! the receiver on first use (`remove_pre_key` after session
//! establishment).
//!
//! The `Vec<u8>` envelopes in the bundle do not zero on drop. Per
//! call, we read the whole bundle, mutate, and write it back; each
//! step allocates a fresh `Vec<u8>` of the JSON-encoded bundle;
//!
//! # Encoding
//!
//! The bundle is stored as JSON of `Vec<(u32, Vec<u8>)>`. The inner
//! `Vec<u8>` is libsignal's binary `PreKeyRecord::serialize()`. JSON
//! is somewhat inefficient here because the inner `Vec<u8>` is
//! rendered as a decimal-int array (3-4× inflation vs raw bytes), but
//! ~100 × ~70 B keeps the encoded bundle well under one PDDB chunk.

use async_trait::async_trait;
use presage::libsignal_service::protocol::{PreKeyId, PreKeyRecord, PreKeyStore, SignalProtocolError};

use super::{
    PREKEY_BUNDLE_KEY, PddbProtocolStore, backend_get_json_protocol, backend_put_json_protocol,
    dict_prekey_bundle,
};

/// Load the packed bundle, or an empty vec if the key doesn't exist.
fn load_bundle(store: &PddbProtocolStore) -> Result<Vec<(u32, Vec<u8>)>, SignalProtocolError> {
    let dict = dict_prekey_bundle(store.identity);
    Ok(backend_get_json_protocol::<Vec<(u32, Vec<u8>)>>(
        &*store.store.backend,
        &dict,
        PREKEY_BUNDLE_KEY,
        "decode prekey bundle",
    )?
    .unwrap_or_default())
}

fn save_bundle(store: &PddbProtocolStore, bundle: &[(u32, Vec<u8>)]) -> Result<(), SignalProtocolError> {
    let dict = dict_prekey_bundle(store.identity);
    backend_put_json_protocol(&*store.store.backend, &dict, PREKEY_BUNDLE_KEY, bundle, "encode prekey bundle")
}

#[async_trait(?Send)]
impl PreKeyStore for PddbProtocolStore {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord, SignalProtocolError> {
        let bundle = load_bundle(self)?;
        let id: u32 = prekey_id.into();
        bundle
            .into_iter()
            .find(|(rid, _)| *rid == id)
            .ok_or(SignalProtocolError::InvalidPreKeyId)
            .and_then(|(_, bytes)| PreKeyRecord::deserialize(&bytes))
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let id: u32 = prekey_id.into();
        let bytes = record.serialize()?;
        let mut bundle = load_bundle(self)?;
        if let Some(existing) = bundle.iter_mut().find(|(rid, _)| *rid == id) {
            existing.1 = bytes;
        } else {
            bundle.push((id, bytes));
        }
        save_bundle(self, &bundle)
    }

    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<(), SignalProtocolError> {
        let id: u32 = prekey_id.into();
        let mut bundle = load_bundle(self)?;
        bundle.retain(|(rid, _)| *rid != id);
        save_bundle(self, &bundle)
    }
}

pub(super) fn max_pre_key_id(store: &PddbProtocolStore) -> Result<Option<u32>, SignalProtocolError> {
    Ok(load_bundle(store)?.iter().map(|(id, _)| *id).max())
}
