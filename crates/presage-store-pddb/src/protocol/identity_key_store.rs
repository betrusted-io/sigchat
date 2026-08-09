//! `IdentityKeyStore` impl. Five methods.
//!
//! - `get_identity_key_pair`: pulled from the StateStore-side `signal.state["{aci|pni}_identity_key_pair"]`
//!   key written by `set_aci_identity_key_pair` / `set_pni_identity_key_pair`. The bytes are libsignal's
//!   binary `IdentityKeyPair::serialize()` format (private + public halves inline).
//! - `get_local_registration_id`: comes from the registration blob loaded by
//!   `StateStore::load_registration_data`. Same source the sqlite store uses.
//! - `save_identity` / `is_trusted_identity` / `get_identity`: per- `ProtocolAddress` keys in
//!   `signal.protocol.{aci,pni}.identity`. These hold **peer** identity public keys; no private material
//!   crosses this dict.
//!
//! # Trust boundary
//!
//! `get_identity_key_pair` reconstructs an [`IdentityKeyPair`] —
//! including its private half — from raw PDDB bytes. PDDB has already
//! authenticated those bytes (per-page AES-256-GCM-SIV); we trust
//! libsignal's `IdentityKeyPair::try_from(&[u8])` to reject anything
//! that isn't a valid keypair encoding. There is no second-layer MAC
//! here. A successful `try_from` is the trust witness.
//!
//! `save_identity` / `is_trusted_identity` make the TOFU decision
//! described inline. The two-state policy (`Trust` accepts rotation,
//! `Reject` denies it) is governed by the `trust_new_identities` flag
//! on the parent `PddbStore` — set once at construction time.
//!
//! # Security
//!
//! The local identity key bytes returned by `get_identity_key_pair`
//! are the single most sensitive value in this entire crate.
//! Compromise of these bytes:
//!
//! - destroys the deniable-authentication property of every past and future session for this identity (ACI or
//!   PNI);
//! - lets the holder impersonate the user to any Signal peer (until the user rekeys);
//! - lets the holder decrypt prekey-initiated sessions that haven't yet ratcheted forward.
//!
//! The `Vec<u8>` returned by `backend.get(...)` does **not** zero on
//! drop. libsignal's `IdentityKeyPair` itself zeroes its internal
//! private-key buffer on drop (see libsignal-protocol's
//! `PrivateKey`), but the transient `bytes` local here lives in a
//! plain `Vec<u8>`. Logging the `bytes` value, including via
//! `tracing::debug!(?bytes)` on this function's body, would leak the
//! key. **MUST NOT happen.**
//!
//! Peer identity public keys are not secret-equivalent on their own,
//! but the (address, identity-key) mapping is privacy-relevant: it
//! reveals which UUIDs the user has spoken to.
//!
//! # Logging
//!
//! `is_trusted_identity` warns on trust-on-first-use. The peer's
//! `ProtocolAddress` name is an ACI UUID, so it goes through
//! [`crate::redact::log_id`] — last four characters by default, full
//! under `verbose-pii`. presage-store-sqlite logs it whole; we do not,
//! because here the log is a UART anyone with a debug cable can read.
//! No identity bytes are logged.

use async_trait::async_trait;
use presage::libsignal_service::protocol::{
    Direction, IdentityChange, IdentityKey, IdentityKeyPair, IdentityKeyStore, ProtocolAddress,
    SignalProtocolError,
};
use presage::store::StateStore;
use tracing::warn;

use super::{PddbProtocolStore, dict_identity, protocol_backend_err};

/// Key inside `signal.state` holding the ACI/PNI identity keypair —
/// matches the constants in `state.rs` (kept in sync deliberately;
/// this trait sits across the StateStore/ProtocolStore boundary).
const STATE_DICT: &str = "signal.state";
fn state_key_identity_key_pair(identity: super::IdentityType) -> &'static str {
    match identity {
        super::IdentityType::Aci => "aci_identity_key_pair",
        super::IdentityType::Pni => "pni_identity_key_pair",
    }
}

fn identity_key(address: &ProtocolAddress) -> String {
    format!("{}.{}", address.name(), u32::from(address.device_id()))
}

#[async_trait(?Send)]
impl IdentityKeyStore for PddbProtocolStore {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        let key = state_key_identity_key_pair(self.identity);
        let bytes =
            self.store.backend.get(STATE_DICT, key).map_err(protocol_backend_err)?.ok_or_else(|| {
                SignalProtocolError::InvalidState("get_identity_key_pair", format!("no {key} stored"))
            })?;
        IdentityKeyPair::try_from(&bytes[..])
    }

    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        let data = self
            .store
            .load_registration_data()
            .await
            .map_err(|e| SignalProtocolError::InvalidState("get_local_registration_id", e.to_string()))?
            .ok_or_else(|| {
                SignalProtocolError::InvalidState("get_local_registration_id", "no registration data".into())
            })?;
        Ok(data.registration_id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<IdentityChange, SignalProtocolError> {
        let dict = dict_identity(self.identity);
        let key = identity_key(address);
        let new_bytes = identity.serialize();

        let prior = self.store.backend.get(&dict, &key).map_err(protocol_backend_err)?;
        let changed = matches!(prior, Some(ref old) if old.as_slice() != new_bytes.as_ref());

        self.store.backend.put(&dict, &key, &new_bytes).map_err(protocol_backend_err)?;

        Ok(IdentityChange::from_changed(changed))
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> Result<bool, SignalProtocolError> {
        match self.get_identity(address).await? {
            // TOFU policy matching presage-store-sqlite. Three cases:
            //  - known-and-equal: trusted unconditionally.
            //  - known-and-different: a rotation. The store-level `trust_new_identities` flag decides.
            //    `Trust` accepts silently (libsignal will surface the safety-number change to UI); `Reject`
            //    refuses and blocks the message until the user re-verifies.
            //  - unknown: trust-on-first-use. Always accepted, but a warning is logged so audit can see a
            //    fresh identity showed up.
            Some(stored) if &stored == identity => Ok(true),
            Some(_) => {
                Ok(matches!(self.store.trust_new_identities, presage::model::identity::OnNewIdentity::Trust))
            }
            None => {
                warn!(
                    peer = %crate::redact::log_id(address.name()),
                    device = ?address.device_id(),
                    "trusting new identity (TOFU)"
                );
                Ok(true)
            }
        }
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        let dict = dict_identity(self.identity);
        let key = identity_key(address);
        match self.store.backend.get(&dict, &key).map_err(protocol_backend_err)? {
            Some(bytes) => Ok(Some(IdentityKey::decode(&bytes)?)),
            None => Ok(None),
        }
    }
}
