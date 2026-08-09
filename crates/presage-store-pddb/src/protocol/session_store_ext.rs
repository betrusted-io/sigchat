//! `SessionStoreExt` — bulk session deletion methods. Walks both the
//! in-memory cache and PDDB so deletions land in both stores.
//!
//! 4 user-facing methods (the 5th, `compute_safety_number`, has a
//! default impl in the trait). `delete_service_addr_device_session`
//! also has a default impl that we let through.
//!
//! On-disk schema: one PDDB key per address; value is a
//! [`SessionBundle`](crate::protocol::session_store::SessionBundle)
//! (`device_id -> serialized SessionRecord`). See `session_store.rs`
//! for the read/write helpers.
//!
//! # Security
//!
//! `delete_session` and `delete_all_sessions` are the
//! user-deletes-a-conversation path. After they return successfully,
//! the corresponding session bytes are gone from the cache and the
//! PDDB. Note however:
//!
//! - PDDB's underlying basis storage may still hold ciphertext in pages that have been freed but not yet
//!   overwritten. PDDB's free list reuses pages, but there is no zero-on-free guarantee.
//! - The `delete_session` "drop just this device_id" path reads, modifies, and writes the bundle back; the
//!   old bundle value remains in whatever PDDB page the previous write occupied until subsequent writes
//!   overwrite it.
//! - The transient `bundle` `HashMap<u32, Vec<u8>>` and the `serialize_session_bundle` output `Vec<u8>` do
//!   not zero on drop.
//!
//! Treat `delete_session` as "best-effort durable forget", not as a
//! cryptographic wipe.

use async_trait::async_trait;
use presage::libsignal_service::prelude::SessionStoreExt;
use presage::libsignal_service::protocol::{DeviceId, ProtocolAddress, ServiceId, SignalProtocolError};
use presage::libsignal_service::push_service::DEFAULT_DEVICE_ID;

use super::session_store::{
    backend_get_session_bundle_protocol, backend_put_session_bundle_protocol, session_key,
};
use super::{PddbProtocolStore, dict_session, protocol_backend_err};

#[async_trait(?Send)]
impl SessionStoreExt for PddbProtocolStore {
    async fn get_sub_device_sessions(&self, name: &ServiceId) -> Result<Vec<DeviceId>, SignalProtocolError> {
        let uuid = name.raw_uuid().to_string();
        let main: u32 = u32::from(*DEFAULT_DEVICE_ID);

        // Combine cache (entries not yet flushed) with PDDB
        // (already-persisted bundle). The same `(addr, device_id)`
        // can appear in both; dedup at the end.
        let mut device_ids: Vec<u32> = Vec::new();

        {
            let cache = self
                .store
                .session_cache
                .lock()
                .map_err(|_| SignalProtocolError::InvalidState("session cache", "poisoned".into()))?;
            for ((id_kind, addr, dev), _) in cache.iter() {
                if *id_kind == self.identity && addr == &uuid && *dev != main {
                    device_ids.push(*dev);
                }
            }
        }

        let dict = dict_session(self.identity);
        if let Some(bundle) = backend_get_session_bundle_protocol(&*self.store.backend, &dict, &uuid)? {
            for dev in bundle.keys() {
                if *dev != main {
                    device_ids.push(*dev);
                }
            }
        }

        device_ids.sort_unstable();
        device_ids.dedup();
        Ok(device_ids.into_iter().filter_map(|d| DeviceId::try_from(d).ok()).collect())
    }

    async fn delete_session(&self, address: &ProtocolAddress) -> Result<(), SignalProtocolError> {
        let key = session_key(self.identity, address);
        {
            let mut cache = self
                .store
                .session_cache
                .lock()
                .map_err(|_| SignalProtocolError::InvalidState("session cache", "poisoned".into()))?;
            cache.remove(&key);
        }
        {
            let mut dirty = self
                .store
                .session_dirty
                .lock()
                .map_err(|_| SignalProtocolError::InvalidState("session dirty", "poisoned".into()))?;
            dirty.remove(&key);
        }

        // Drop just this device_id from the PDDB bundle. If the
        // bundle becomes empty, delete the whole key so a future
        // `list_keys` doesn't return a stale empty entry.
        let dict = dict_session(self.identity);
        let Some(mut bundle) = backend_get_session_bundle_protocol(&*self.store.backend, &dict, &key.1)?
        else {
            return Ok(());
        };
        if bundle.remove(&key.2).is_none() {
            return Ok(());
        }
        if bundle.is_empty() {
            self.store.backend.delete(&dict, &key.1).map_err(protocol_backend_err)?;
        } else {
            backend_put_session_bundle_protocol(&*self.store.backend, &dict, &key.1, &bundle)?;
        }
        Ok(())
    }

    async fn delete_all_sessions(&self, address: &ServiceId) -> Result<usize, SignalProtocolError> {
        // Count UNIQUE (uuid, device_id) entries removed across cache
        // + PDDB. Cache and bundle can overlap on a not-yet-flushed
        // session; counting both would double-count.
        use std::collections::HashSet;

        let uuid = address.raw_uuid().to_string();
        let dict = dict_session(self.identity);
        let mut affected: HashSet<u32> = HashSet::new();

        {
            let mut cache = self
                .store
                .session_cache
                .lock()
                .map_err(|_| SignalProtocolError::InvalidState("session cache", "poisoned".into()))?;
            let mut dirty = self
                .store
                .session_dirty
                .lock()
                .map_err(|_| SignalProtocolError::InvalidState("session dirty", "poisoned".into()))?;
            cache.retain(|(id_kind, addr, dev), _| {
                let drop = *id_kind == self.identity && addr == &uuid;
                if drop {
                    affected.insert(*dev);
                    dirty.remove(&(*id_kind, addr.clone(), *dev));
                }
                !drop
            });
        }

        if let Some(bundle) = backend_get_session_bundle_protocol(&*self.store.backend, &dict, &uuid)? {
            for dev in bundle.keys() {
                affected.insert(*dev);
            }
            self.store.backend.delete(&dict, &uuid).map_err(protocol_backend_err)?;
        }

        Ok(affected.len())
    }
}
