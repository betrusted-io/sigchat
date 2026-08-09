//! `SenderKeyStore` impl. Two methods, per-(addr, device, dist_id)
//! keys in `signal.protocol.{aci,pni}.sender_key`.
//!
//! # Security
//!
//! A [`SenderKeyRecord`] holds the symmetric chain-key state for one
//! group-distribution sender. Compromise of the bytes lets the
//! holder decrypt **every** message sent under that
//! `distribution_id` (including past traffic), and forge messages
//! that the group members will accept as authentic from `sender`
//! until the next sender-key rotation.
//!
//! Records are stored as their libsignal binary
//! `SenderKeyRecord::serialize()` form. PDDB's per-page AEAD is the
//! single trust boundary. The `Vec<u8>` does not zero on drop.
//!
//! The composite key (`name`, `device_id`, `distribution_id`)
//! reveals the group-distribution mapping; non-secret-equivalent but
//! privacy-relevant.

use async_trait::async_trait;
use presage::libsignal_service::prelude::Uuid;
use presage::libsignal_service::protocol::{
    ProtocolAddress, SenderKeyRecord, SenderKeyStore, SignalProtocolError,
};

use super::{PddbProtocolStore, dict_sender_key, protocol_backend_err};

fn sender_key_key(address: &ProtocolAddress, distribution_id: Uuid) -> String {
    format!("{}.{}.{}", address.name(), u32::from(address.device_id()), distribution_id.simple())
}

#[async_trait(?Send)]
impl SenderKeyStore for PddbProtocolStore {
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let dict = dict_sender_key(self.identity);
        let key = sender_key_key(sender, distribution_id);
        let bytes = record.serialize()?;
        self.store.backend.put(&dict, &key, &bytes).map_err(protocol_backend_err)
    }

    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        let dict = dict_sender_key(self.identity);
        let key = sender_key_key(sender, distribution_id);
        match self.store.backend.get(&dict, &key).map_err(protocol_backend_err)? {
            Some(bytes) => SenderKeyRecord::deserialize(&bytes).map(Some),
            None => Ok(None),
        }
    }
}
