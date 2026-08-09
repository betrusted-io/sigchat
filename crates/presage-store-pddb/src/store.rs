//! `presage::store::Store` blanket — combines [`presage::store::StateStore`],
//! [`presage::store::ContentsStore`], and the ACI/PNI protocol-store
//! accessors.
//!
//! `Store::clear` is the one method that crosses every persisted
//! dict. It is documented inline; the in-memory session cache is
//! cleared last so a flush after `clear` does not re-persist
//! sessions that the user just asked to wipe.
//!
//! # Security
//!
//! `clear` is the only API that wipes the user's account state.
//! After it returns successfully:
//!
//! - the StateStore dict (`signal.state`) is gone — registration data, identity keypairs, master key, sender
//!   cert all removed;
//! - every ContentsStore dict (`signal.contacts`, `signal.groups`, etc.) is gone;
//! - every ProtocolStore dict for both ACI and PNI is gone;
//! - the in-memory session cache and dirty set are empty.
//!
//! Limitations: PDDB's free-list reuses pages but does not
//! zero-on-free, so freed pages may still hold ciphertext on disk
//! until the next write reuses the page. Treat `clear` as durable
//! forget against a future cold reader of PDDB, not as a
//! cryptographic erase.

use presage::store::{ContentsStore, StateStore, Store};

use crate::{Error, IdentityType, PddbProtocolStore, PddbStore};

impl Store for PddbStore {
    type AciStore = PddbProtocolStore;
    type Error = Error;
    type PniStore = PddbProtocolStore;

    /// Clear *everything* — state, profiles, every protocol-store
    /// dict (both ACI and PNI), and the in-memory session cache.
    /// Per-impl `clear_*` methods are wired up here.
    ///
    /// See the module-level Security note for the durability bound
    /// (PDDB free-list does not zero pages on free).
    ///
    /// `xous_signal_worker::Cmd::Logout` is the production caller;
    /// the worker treats `Err` from this method as non-fatal (logs a
    /// warning, emits `Event::LoggedOut` anyway). Per-dict failure
    /// semantics are under `# Errors` below.
    ///
    /// # Errors
    ///
    /// Returns the first backend error encountered via `?`. Earlier
    /// `delete_dict` calls have already taken effect; there is no
    /// rollback. Order of dictionaries wiped:
    /// `signal.state` (via `clear_registration`), every contents
    /// dict (via `clear_contents`), then for each of
    /// `IdentityType::Aci` and `IdentityType::Pni` the seven
    /// protocol dicts in the order
    /// `session, identity, prekey_bundle, signed_prekey,
    /// kyber_prekey, kyber_meta, sender_key`. The in-memory session
    /// cache and dirty set are cleared only after every backend
    /// dict has been deleted successfully, so on partial failure
    /// they retain the pre-`clear` state and a subsequent
    /// `flush_sessions` could re-persist sessions whose
    /// protocol-dict was already wiped.
    async fn clear(&mut self) -> Result<(), <Self as StateStore>::StateStoreError> {
        // Wipe registration data + identity keypairs + sender cert +
        // master key.
        self.clear_registration().await?;
        // Wipe all messages, contacts, groups, profiles, sticker packs.
        self.clear_contents().await?;
        // Wipe both protocol-store dictionaries (sessions, identities,
        // pre-keys, signed pre-keys, kyber pre-keys, sender keys).
        for identity in [IdentityType::Aci, IdentityType::Pni] {
            self.backend.delete_dict(&crate::protocol::dict_session(identity))?;
            self.backend.delete_dict(&crate::protocol::dict_identity(identity))?;
            self.backend.delete_dict(&crate::protocol::dict_prekey_bundle(identity))?;
            self.backend.delete_dict(&crate::protocol::dict_signed_prekey(identity))?;
            self.backend.delete_dict(&crate::protocol::dict_kyber_prekey(identity))?;
            self.backend.delete_dict(&crate::protocol::dict_kyber_meta(identity))?;
            self.backend.delete_dict(&crate::protocol::dict_sender_key(identity))?;
        }

        // Drop in-memory session state — otherwise a flush after
        // `clear` would re-persist it.
        if let Ok(mut cache) = self.session_cache.lock() {
            cache.clear();
        }
        if let Ok(mut dirty) = self.session_dirty.lock() {
            dirty.clear();
        }

        Ok(())
    }

    fn aci_protocol_store(&self) -> Self::AciStore { PddbProtocolStore::new(self.clone(), IdentityType::Aci) }

    fn pni_protocol_store(&self) -> Self::PniStore { PddbProtocolStore::new(self.clone(), IdentityType::Pni) }
}
