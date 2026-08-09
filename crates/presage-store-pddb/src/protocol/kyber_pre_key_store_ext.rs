//! `KyberPreKeyStoreExt` — last-resort prekey storage + stale-time
//! bookkeeping. Five methods.
//!
//! `mark_all_one_time_kyber_pre_keys_stale_if_necessary` and
//! `delete_all_stale_one_time_kyber_pre_keys` are stubbed to
//! `unimplemented!()` matching presage-store-sqlite's own approach
//! (presage-store-sqlite/src/protocol.rs:530-544 upstream — both
//! return `unimplemented!("should not be used yet")`). presage's
//! manager doesn't currently call them; the upstream comment is "this
//! seems unused on the trunk".

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use presage::libsignal_service::pre_keys::KyberPreKeyStoreExt;
use presage::libsignal_service::protocol::{
    GenericSignedPreKey, KyberPreKeyId, KyberPreKeyRecord, SignalProtocolError,
};

use super::{
    PddbProtocolStore, dict_kyber_prekey,
    kyber_pre_key_store::{KyberStored, load_envelope, store_envelope},
    protocol_backend_err,
};
use crate::list_keys_as_u32s;

#[async_trait(?Send)]
impl KyberPreKeyStoreExt for PddbProtocolStore {
    async fn store_last_resort_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        store_envelope(self, kyber_prekey_id, record, /* is_last_resort */ true)
    }

    async fn load_last_resort_kyber_pre_keys(&self) -> Result<Vec<KyberPreKeyRecord>, SignalProtocolError> {
        let dict = dict_kyber_prekey(self.identity);
        let ids = list_keys_as_u32s(&*self.store.backend, &dict).map_err(protocol_backend_err)?;
        let mut out = Vec::new();
        for id in ids {
            if let Some(KyberStored { record, is_last_resort: true }) =
                load_envelope(self, KyberPreKeyId::from(id))?
            {
                out.push(KyberPreKeyRecord::deserialize(&record)?);
            }
        }
        Ok(out)
    }

    async fn remove_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<(), SignalProtocolError> {
        let dict = dict_kyber_prekey(self.identity);
        let key = u32::from(kyber_prekey_id).to_string();
        self.store.backend.delete(&dict, &key).map_err(protocol_backend_err)
    }

    async fn mark_all_one_time_kyber_pre_keys_stale_if_necessary(
        &mut self,
        _stale_time: DateTime<Utc>,
    ) -> Result<(), SignalProtocolError> {
        unimplemented!("should not be used yet")
    }

    async fn delete_all_stale_one_time_kyber_pre_keys(
        &mut self,
        _threshold: DateTime<Utc>,
        _min_count: usize,
    ) -> Result<(), SignalProtocolError> {
        unimplemented!("should not be used yet")
    }
}
