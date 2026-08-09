//! `presage::store::StateStore` implementation for `PddbStore`.
//!
//! All state lives in a single PDDB dictionary, `signal.state`, with
//! one key per field. This matches presage-store-sqlite's `kv` table
//! layout. Per-field keys keep reads cheap and let
//! `clear_registration` walk the dict instead of editing a giant
//! blob.
//!
//! # Trust boundary
//!
//! Every byte read here came from PDDB and has been authenticated by
//! PDDB's per-page AEAD. The libsignal types reconstruct themselves
//! from those bytes; a deserialization failure is the only signal
//! that something is wrong, and surfaces as [`Error::Decode`] or
//! [`Error::Protocol`].
//!
//! # Security
//!
//! Persisted material, by sensitivity tier:
//!
//! - **`IdentityKeyPair`** (`aci_identity_key_pair`, `pni_identity_key_pair`): long-term private+public
//!   identity keys. See the protocol module's identity store for the full compromise analysis. Stored as
//!   libsignal binary `IdentityKeyPair::serialize()`.
//! - **`MasterKey`** (`master_key`): the 32-byte Signal storage service master key. Compromise gives the
//!   holder read+write access to the user's Signal storage-service-encrypted content (contacts, groups,
//!   profile metadata). Stored as the **raw 32 bytes** of `master_key.inner` — no framing, no MAC, no
//!   zeroization at this layer.
//! - **`RegistrationData`** (`registration`): contains the Signal account password, both ACI and PNI
//!   registration ids, the profile key, the linked device id, and the user's E.164 phone number. Compromise
//!   lets the holder authenticate to Signal's chat service as the user and rotate prekeys / sessions. Stored
//!   as `serde_json` of the upstream `RegistrationData` shape; the `password` field is a plain `String`, the
//!   `profile_key` serializes to base64 (see presage/src/serde.rs `serde_profile_key` in
//!   whisperfish/presage).
//! - **`SenderCertificate`** (`sender_certificate`): a signed certificate that authorizes sealed-sender
//!   envelopes for this account. Contains the user's public identity key and a server-issued signature. Not
//!   secret-equivalent (the cert is what gets sent on the wire) but loss-of-control means anyone who has the
//!   cert can send sealed-sender messages spoofed as the user until expiry.
//!
//! All read/write paths return / accept `Vec<u8>` that do not zero
//! on drop. The `MasterKey` and the `password` field inside
//! `RegistrationData` are the values most worth wrapping in
//! `secrecy::SecretBox`.
//!
//! Serialization choices:
//!
//! - `RegistrationData` — `serde_json` (debuggable from a `pddbcli` dump). Same choice presage-store-sqlite
//!   makes. The debuggability comes at the cost of plaintext-in-PDDB-page storage; the entire blob (including
//!   the account password) sits in one key.
//! - `IdentityKeyPair` — `.serialize()` to a libsignal-defined binary form,
//!   `IdentityKeyPair::try_from(&[u8])` to read. Matches presage-store-sqlite's pattern.
//! - `SenderCertificate` — `.serialized()? -> Vec<u8>` / `SenderCertificate::deserialize(&[u8])`.
//!   Protocol-defined wire format; do not reframe.
//! - `MasterKey` — store the 32 raw bytes from `master_key.inner`; `MasterKey::from_slice` to read.
//!
//! # Logging
//!
//! None of the StateStore methods emit `tracing` events that include
//! field values. The store-level callers (presage) may log
//! `RegistrationData`-derived facts (e.g. the user's UUID); the bytes
//! themselves never leave PDDB except into the caller's owned types.

use presage::libsignal_service::prelude::MasterKey;
use presage::libsignal_service::protocol::{IdentityKeyPair, SenderCertificate};
use presage::manager::RegistrationData;
use presage::store::StateStore;

use crate::{Error, PddbStore, backend_get_json, backend_put_json};

/// PDDB dictionary that holds all `StateStore` keys. `pub(crate)`
/// so [`crate::PddbStore::has_account_state`] can probe it.
pub(crate) const DICT: &str = "signal.state";

/// One key per `StateStore` field. The keys are short, opaque strings —
/// pddbcli readers will see them with their data when dumping the dict.
const KEY_REGISTRATION: &str = "registration";
const KEY_ACI_IDENTITY_KEY_PAIR: &str = "aci_identity_key_pair";
const KEY_PNI_IDENTITY_KEY_PAIR: &str = "pni_identity_key_pair";
const KEY_SENDER_CERTIFICATE: &str = "sender_certificate";
const KEY_MASTER_KEY: &str = "master_key";

impl StateStore for PddbStore {
    type StateStoreError = Error;

    async fn load_registration_data(&self) -> Result<Option<RegistrationData>, Error> {
        backend_get_json(&*self.backend, DICT, KEY_REGISTRATION)
    }

    async fn set_aci_identity_key_pair(&self, key_pair: IdentityKeyPair) -> Result<(), Error> {
        let bytes = key_pair.serialize();
        self.backend.put(DICT, KEY_ACI_IDENTITY_KEY_PAIR, &bytes)?;
        Ok(())
    }

    async fn set_pni_identity_key_pair(&self, key_pair: IdentityKeyPair) -> Result<(), Error> {
        let bytes = key_pair.serialize();
        self.backend.put(DICT, KEY_PNI_IDENTITY_KEY_PAIR, &bytes)?;
        Ok(())
    }

    async fn save_registration_data(&mut self, state: &RegistrationData) -> Result<(), Error> {
        backend_put_json(&*self.backend, DICT, KEY_REGISTRATION, state)
    }

    async fn sender_certificate(&self) -> Result<Option<SenderCertificate>, Error> {
        match self.backend.get(DICT, KEY_SENDER_CERTIFICATE)? {
            Some(bytes) => Ok(Some(SenderCertificate::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    async fn save_sender_certificate(&self, certificate: &SenderCertificate) -> Result<(), Error> {
        let bytes = certificate.serialized()?;
        self.backend.put(DICT, KEY_SENDER_CERTIFICATE, bytes)?;
        Ok(())
    }

    async fn is_registered(&self) -> bool {
        // Same pattern as presage-store-sqlite: presence of the
        // registration blob is the source of truth. Errors collapse to
        // "not registered" rather than panicking — this matches the
        // trait, which doesn't return Result here.
        self.load_registration_data().await.ok().flatten().is_some()
    }

    async fn clear_registration(&mut self) -> Result<(), Error> {
        // Drops every key in the state dict — registration, both
        // identity key pairs, sender certificate, master key. The
        // protocol stores live in their own dicts and aren't touched
        // here; presage's `Store::clear` chains both.
        self.backend.delete_dict(DICT)?;
        Ok(())
    }

    async fn fetch_master_key(&self) -> Result<Option<MasterKey>, Error> {
        match self.backend.get(DICT, KEY_MASTER_KEY)? {
            Some(bytes) => MasterKey::from_slice(&bytes)
                .map(Some)
                .map_err(|e| Error::Decode(format!("master key length: {e}"))),
            None => Ok(None),
        }
    }

    async fn store_master_key(&self, master_key: Option<&MasterKey>) -> Result<(), Error> {
        match master_key {
            Some(k) => self.backend.put(DICT, KEY_MASTER_KEY, &k.inner)?,
            None => self.backend.delete(DICT, KEY_MASTER_KEY)?,
        }
        Ok(())
    }
}
