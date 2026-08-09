//! `PreKeysStore` extension trait — 8 ID-counter / count methods. The
//! "next id" semantics match presage-store-sqlite (max + 1, or 1 for
//! an empty store) — see presage-store-sqlite/src/
//! protocol.rs:236-318 in whisperfish/presage.

use async_trait::async_trait;
use presage::libsignal_service::pre_keys::PreKeysStore;
use presage::libsignal_service::protocol::{KyberPreKeyId, SignalProtocolError, SignedPreKeyId};

use super::{
    PddbProtocolStore,
    kyber_pre_key_store::{count_kyber_pre_keys, max_kyber_pre_key_id, max_last_resort_kyber_pre_key_id},
    pre_key_store::max_pre_key_id,
    signed_pre_key_store::{count_signed_pre_keys, max_signed_pre_key_id},
};

#[async_trait(?Send)]
impl PreKeysStore for PddbProtocolStore {
    async fn next_pre_key_id(&self) -> Result<u32, SignalProtocolError> {
        Ok(max_pre_key_id(self)?.map(|id| id + 1).unwrap_or(1))
    }

    async fn next_signed_pre_key_id(&self) -> Result<u32, SignalProtocolError> {
        Ok(max_signed_pre_key_id(self)?.map(|id| id + 1).unwrap_or(1))
    }

    async fn next_pq_pre_key_id(&self) -> Result<u32, SignalProtocolError> {
        Ok(max_kyber_pre_key_id(self)?.map(|id| id + 1).unwrap_or(1))
    }

    async fn signed_pre_keys_count(&self) -> Result<usize, SignalProtocolError> {
        count_signed_pre_keys(self)
    }

    async fn kyber_pre_keys_count(&self, last_resort: bool) -> Result<usize, SignalProtocolError> {
        count_kyber_pre_keys(self, last_resort)
    }

    async fn signed_prekey_id(&self) -> Result<Option<SignedPreKeyId>, SignalProtocolError> {
        Ok(max_signed_pre_key_id(self)?.map(SignedPreKeyId::from))
    }

    async fn last_resort_kyber_prekey_id(&self) -> Result<Option<KyberPreKeyId>, SignalProtocolError> {
        Ok(max_last_resort_kyber_pre_key_id(self)?.map(KyberPreKeyId::from))
    }
}
