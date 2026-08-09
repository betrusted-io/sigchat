//! `SignedPreKeyStore` impl. Per-id, JSON-wrapper-free.
//!
//! Two methods, both per-id storage in
//! `signal.protocol.{aci,pni}.signed_prekey`. Records are stored as
//! their libsignal binary form (`record.serialize()?`) — same shape
//! presage-store-sqlite uses (presage-store-sqlite/
//! src/protocol.rs:341-360 in whisperfish/presage).
//!
//! # Security
//!
//! A signed prekey record holds an EC private key (the prekey
//! private half) plus the identity-key signature over its public
//! half. Compromise of the private bytes lets the holder forge a
//! prekey bundle and act as a valid receiver of X3DH-initiated
//! sessions for some window (until the signed prekey is rotated by
//! the next presage replenish pass).
//!
//! Stored as the libsignal binary form; PDDB's per-page AEAD is the
//! single trust boundary. Read returns a fresh `Vec<u8>` that does
//! not zero on drop.

use async_trait::async_trait;
use presage::libsignal_service::protocol::{
    GenericSignedPreKey, SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
};

use super::{PddbProtocolStore, dict_signed_prekey, protocol_backend_err};
use crate::list_keys_as_u32s;

#[async_trait(?Send)]
impl SignedPreKeyStore for PddbProtocolStore {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        let dict = dict_signed_prekey(self.identity);
        let key = u32::from(signed_prekey_id).to_string();
        let bytes = self
            .store
            .backend
            .get(&dict, &key)
            .map_err(protocol_backend_err)?
            .ok_or(SignalProtocolError::InvalidSignedPreKeyId)?;
        SignedPreKeyRecord::deserialize(&bytes)
    }

    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let dict = dict_signed_prekey(self.identity);
        let key = u32::from(signed_prekey_id).to_string();
        let bytes = record.serialize()?;
        self.store.backend.put(&dict, &key, &bytes).map_err(protocol_backend_err)
    }
}

pub(super) fn count_signed_pre_keys(store: &PddbProtocolStore) -> Result<usize, SignalProtocolError> {
    let dict = dict_signed_prekey(store.identity);
    store.store.backend.list_keys(&dict).map(|keys| keys.len()).map_err(protocol_backend_err)
}

pub(super) fn max_signed_pre_key_id(store: &PddbProtocolStore) -> Result<Option<u32>, SignalProtocolError> {
    let dict = dict_signed_prekey(store.identity);
    let ids = list_keys_as_u32s(&*store.store.backend, &dict).map_err(protocol_backend_err)?;
    Ok(ids.into_iter().max())
}
