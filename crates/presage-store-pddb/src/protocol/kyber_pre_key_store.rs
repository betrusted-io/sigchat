//! `KyberPreKeyStore` impl. Three methods.
//!
//! Per-id binary records in `signal.protocol.{aci,pni}.kyber_prekey`.
//! Each record on disk is a JSON envelope `{record: <bytes>,
//! is_last_resort: bool}` so that `mark_kyber_pre_key_used` and the
//! `KyberPreKeyStoreExt` trait know whether to delete or retain —
//! same flag the sqlite store carries as a column
//! (presage-store-sqlite/src/protocol.rs:407-470 in whisperfish/presage).
//!
//! `mark_kyber_pre_key_used` consults a separate `kyber_meta` dict
//! for last-resort base-key dedup. Key = `"{kyber_id}.{ec_id}"`,
//! value = `base_key.serialize()` bytes. Inserting the same triple
//! twice is the "reused base key" error case (replay-protection
//! against a peer that tries to re-establish a session with the same
//! base key against the same last-resort prekey).
//!
//! # Security
//!
//! A [`KyberPreKeyRecord`] holds an ML-KEM-1024 secret key. These are
//! the post-quantum half of Signal's PQXDH X3DH variant. Compromise
//! of a prekey's private bytes lets the holder decrypt the PQXDH
//! ciphertext for one X3DH session.
//!
//! One-time keys are deleted on first use (`mark_kyber_pre_key_used`,
//! `is_last_resort == false` branch) — they should never persist
//! past a successful session establishment. Last-resort keys are
//! long-lived and rotate only when presage's replenish pass runs; the
//! dedup table (`kyber_meta`) prevents replay against a stale
//! last-resort key.
//!
//! The JSON envelope (`KyberStored`) is `serde_json`-encoded. The
//! inner `record: Vec<u8>` is libsignal's binary record bytes; the
//! `is_last_resort` bit is plaintext metadata.

use async_trait::async_trait;
use presage::libsignal_service::protocol::{
    CiphertextMessageType, GenericSignedPreKey, KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore,
    PublicKey, SignalProtocolError, SignedPreKeyId,
};
use serde::{Deserialize, Serialize};

use super::{
    PddbProtocolStore, backend_get_json_protocol, backend_put_json_protocol, dict_kyber_meta,
    dict_kyber_prekey, protocol_backend_err,
};
use crate::list_keys_as_u32s;

/// Wire envelope for a stored Kyber pre-key. JSON-encoded. The
/// `record` bytes are libsignal's binary
/// `KyberPreKeyRecord::serialize` output; we don't reframe.
///
/// # Security
///
/// `record` contains an ML-KEM-1024 secret key. The `Vec<u8>` does
/// not zero on drop; the JSON envelope must stay inside the PDDB
/// trust boundary. **MUST NOT be logged.** The `Debug` derive on
/// this type is never invoked because the struct is only constructed
/// at the storage boundary; if added, it would print the private
/// bytes as a decimal-int array.
#[derive(Serialize, Deserialize)]
pub(super) struct KyberStored {
    pub(super) record: Vec<u8>,
    pub(super) is_last_resort: bool,
}

pub(super) fn store_envelope(
    proto: &PddbProtocolStore,
    id: KyberPreKeyId,
    record: &KyberPreKeyRecord,
    is_last_resort: bool,
) -> Result<(), SignalProtocolError> {
    let dict = dict_kyber_prekey(proto.identity);
    let key = u32::from(id).to_string();
    let envelope = KyberStored { record: record.serialize()?, is_last_resort };
    backend_put_json_protocol(&*proto.store.backend, &dict, &key, &envelope, "encode kyber envelope")
}

pub(super) fn load_envelope(
    proto: &PddbProtocolStore,
    id: KyberPreKeyId,
) -> Result<Option<KyberStored>, SignalProtocolError> {
    let dict = dict_kyber_prekey(proto.identity);
    let key = u32::from(id).to_string();
    backend_get_json_protocol(&*proto.store.backend, &dict, &key, "decode kyber envelope")
}

#[async_trait(?Send)]
impl KyberPreKeyStore for PddbProtocolStore {
    async fn get_kyber_pre_key(
        &self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        let envelope =
            load_envelope(self, kyber_prekey_id)?.ok_or(SignalProtocolError::InvalidKyberPreKeyId)?;
        KyberPreKeyRecord::deserialize(&envelope.record)
    }

    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        store_envelope(self, kyber_prekey_id, record, /* is_last_resort */ false)
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        ec_prekey_id: SignedPreKeyId,
        base_key: &PublicKey,
    ) -> Result<(), SignalProtocolError> {
        let envelope =
            load_envelope(self, kyber_prekey_id)?.ok_or(SignalProtocolError::InvalidKyberPreKeyId)?;

        if envelope.is_last_resort {
            // Last-resort: dedup against (kyber_id, ec_id, base_key).
            // Reusing the same triple is a protocol violation —
            // `InvalidMessage(PreKey, "reused base key")` matches sqlite.
            let dict = dict_kyber_meta(self.identity);
            let key = format!("{}.{}", u32::from(kyber_prekey_id), u32::from(ec_prekey_id));
            let new_base_bytes = base_key.serialize();

            if let Some(prior) = self.store.backend.get(&dict, &key).map_err(protocol_backend_err)? {
                if prior == new_base_bytes.as_ref() {
                    return Err(SignalProtocolError::InvalidMessage(
                        CiphertextMessageType::PreKey,
                        "reused base key",
                    ));
                }
            }
            self.store.backend.put(&dict, &key, &new_base_bytes).map_err(protocol_backend_err)?;
        } else {
            // One-time: delete the prekey outright.
            let dict = dict_kyber_prekey(self.identity);
            let key = u32::from(kyber_prekey_id).to_string();
            self.store.backend.delete(&dict, &key).map_err(protocol_backend_err)?;
        }

        Ok(())
    }
}

pub(super) fn count_kyber_pre_keys(
    store: &PddbProtocolStore,
    last_resort_only: bool,
) -> Result<usize, SignalProtocolError> {
    let dict = dict_kyber_prekey(store.identity);
    let ids = list_keys_as_u32s(&*store.store.backend, &dict).map_err(protocol_backend_err)?;
    if !last_resort_only {
        return Ok(ids.len());
    }
    let mut count = 0_usize;
    for id in ids {
        if let Some(env) = load_envelope(store, KyberPreKeyId::from(id))? {
            if env.is_last_resort {
                count += 1;
            }
        }
    }
    Ok(count)
}

pub(super) fn max_kyber_pre_key_id(store: &PddbProtocolStore) -> Result<Option<u32>, SignalProtocolError> {
    let dict = dict_kyber_prekey(store.identity);
    let ids = list_keys_as_u32s(&*store.store.backend, &dict).map_err(protocol_backend_err)?;
    Ok(ids.into_iter().max())
}

pub(super) fn max_last_resort_kyber_pre_key_id(
    store: &PddbProtocolStore,
) -> Result<Option<u32>, SignalProtocolError> {
    let dict = dict_kyber_prekey(store.identity);
    let ids = list_keys_as_u32s(&*store.store.backend, &dict).map_err(protocol_backend_err)?;
    let mut best: Option<u32> = None;
    for id in ids {
        if let Some(env) = load_envelope(store, KyberPreKeyId::from(id))? {
            if env.is_last_resort {
                best = Some(best.map_or(id, |b| b.max(id)));
            }
        }
    }
    Ok(best)
}
