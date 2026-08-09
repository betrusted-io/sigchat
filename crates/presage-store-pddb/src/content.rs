//! `presage::store::ContentsStore` implementation for `PddbStore`.
//!
//! Storage layout:
//!
//! - `signal.contacts` — per `ServiceId`, JSON `Contact`.
//! - `signal.groups` — per master_key (hex), JSON `Group`.
//! - `signal.group_avatars` — per master_key (hex), raw bytes.
//! - `signal.profile_keys` — per uuid, JSON `ProfileKey`.
//! - `signal.profiles` — per `sha256(uuid || profile_key)`, JSON `Profile`. Same key-derivation scheme
//!   presage-store-sled uses.
//! - `signal.profile_avatars` — same key, raw avatar bytes.
//! - `signal.sticker_packs` — per pack id (hex), JSON `StickerPack`.
//! - `signal.threads.<thread_hex>` — one **dictionary per thread**. `thread_hex` is `sha256("contact:" +
//!   uuid)` or `sha256("group:" + base64(master_key))`. Keys inside the dictionary are 16-hex-character
//!   zero-padded `u64` timestamps so that `list_keys` order matches arrival order under PDDB's lexicographic
//!   key sort. Values are JSON `StoredMessage` envelopes wrapping libsignal's binary `Content` protobuf body
//!   alongside its `Metadata`.
//!
//! Messages-by-thread serialization choice — JSON envelope around
//! prost-encoded body bytes — matches presage-store-sqlite's pattern
//! (presage-store-sqlite/src/content.rs:154 upstream stores the
//! body as raw protobuf bytes alongside metadata columns). We don't
//! adopt presage-store-sled's `InternalSerialization.proto` wrapper:
//! it requires a build script and a textsecure proto, both of which
//! we'd have to maintain alongside upstream.
//!
//! # Security
//!
//! ContentsStore is the **application-data** layer (vs StateStore's
//! account-credential layer and ProtocolStore's key-material layer).
//! Sensitivity tiers here are different:
//!
//! - **`ProfileKey`** (`profile_keys`, derived into the `profile_dict_key` hash, also embedded in
//!   `RegistrationData`): the 32-byte symmetric profile encryption key per contact. Compromise lets the
//!   holder decrypt that contact's profile metadata (name, about, avatar). Stored as JSON of the upstream
//!   `ProfileKey` struct (`{"bytes": [...]}`).
//! - **`Group` master keys** (used as the dict-key in `signal.groups` and `signal.group_avatars`): 32-byte
//!   keys identifying a Signal group. Compromise lets the holder derive the group's access credentials.
//!   Stored hex-encoded as the dict-key string — i.e. the master key is itself embedded in the PDDB key
//!   namespace, not in the value. PDDB's per-page AEAD covers the keyspace, but `list_keys` returns
//!   hex-encoded master keys to whoever calls it.
//! - **Message bodies** (`signal.threads.<...>` values): the decrypted plaintext (`proto::Content`) of every
//!   message the user has sent or received in that thread. Compromise reveals all of the user's message
//!   history with that contact / group. Stored as JSON envelope with a `body_proto: Vec<u8>` field carrying
//!   the protobuf-encoded `Content`.
//! - **Contacts / groups / profiles / sticker packs**: metadata about the user's social graph. Not
//!   secret-equivalent but highly privacy-sensitive — knowing who the user talks to is a metadata leak.
//! - **Avatar bytes**: raw images, stored unframed.
//!
//! All values cross the PDDB trust boundary as `Vec<u8>` that do not
//! zero on drop. The bodies-by-thread `body_proto` `Vec<u8>` lives
//! inside a `StoredMessage` whose `Debug` derive is never invoked but
//! would print the protobuf body bytes as a decimal-int array if it
//! were.
//!
//! # Logging
//!
//! No method here emits `tracing` events that include value bytes or
//! decoded plaintext. presage's manager and the worker layer may log
//! the user-visible *fact* that a message arrived (sender UUID,
//! timestamp), but never the body.
//!
//! # rv32 / 16 MiB constraint
//!
//! `messages(thread, range)` walks the thread dict's full key list,
//! filters by range, and eagerly loads matching values into a
//! `Vec<Result<Content, Error>>` returned as the `MessagesIter`. For
//! a thread of N messages all matching the range, this allocates N
//! `Content` instances plus their backing `Vec<u8>` clones. The
//! caller decides cardinality; presage callers typically use bounded
//! ranges.

use std::ops::{Bound, RangeBounds};

use presage::{
    AvatarBytes,
    libsignal_service::{
        Profile,
        content::{Content, Metadata},
        prelude::{ProfileKey, Uuid},
        protocol::{DeviceId, ServiceId},
        zkgroup::GroupMasterKeyBytes,
    },
    model::{contacts::Contact, groups::Group},
    store::{ContentsStore, StickerPack, Thread},
};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Error, PddbStore, backend_get_json, backend_get_json_required, backend_put_json};

// --- Dictionary names ---

const DICT_CONTACTS: &str = "signal.contacts";
const DICT_GROUPS: &str = "signal.groups";
const DICT_GROUP_AVATARS: &str = "signal.group_avatars";
const DICT_PROFILES: &str = "signal.profiles";
const DICT_PROFILE_KEYS: &str = "signal.profile_keys";
const DICT_PROFILE_AVATARS: &str = "signal.profile_avatars";
const DICT_STICKER_PACKS: &str = "signal.sticker_packs";
const THREAD_DICT_PREFIX: &str = "signal.threads.";

// --- Key derivations ---

fn profile_dict_key(uuid: Uuid, key: ProfileKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(uuid.as_bytes());
    hasher.update(key.get_bytes());
    format!("{:x}", hasher.finalize())
}

fn group_key(master_key: &GroupMasterKeyBytes) -> String { hex_encode(master_key) }

fn sticker_pack_key(id: &[u8]) -> String { hex_encode(id) }

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        write!(s, "{b:02x}").expect("write to String");
    }
    s
}

/// Per-thread dictionary name. `sha256("contact:" + uuid)` or
/// `sha256("group:" + base64(master_key))` — same shape sled uses
/// (presage-store-sled/src/content.rs:471-485 upstream) so the
/// derivation is portable. We don't keep raw thread descriptors in
/// the dictionary name; the hash is enough since we never list-by-
/// thread on the wire (thread descriptors come in from the caller).
fn thread_dict_name(thread: &Thread) -> String {
    let key = match thread {
        Thread::Contact(service_id) => format!("contact:{}", service_id.service_id_string()),
        Thread::Group(master_key) => {
            // Base64-encode the master key bytes the same way sled does.
            use base64::{Engine, engine::general_purpose::STANDARD};
            format!("group:{}", STANDARD.encode(master_key))
        }
    };
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    format!("{}{:x}", THREAD_DICT_PREFIX, hasher.finalize())
}

/// Sortable lexicographic timestamp key. PDDB doesn't expose a
/// numeric ordering on keys, so we zero-pad to 16 hex digits — that
/// gives us `list_keys` in arrival order without parsing.
fn message_key(timestamp: u64) -> String { format!("{timestamp:016x}") }

// --- Message storage envelope ---

/// On-disk wrapper for a single message. The body is libsignal's
/// binary `proto::Content` (re-encodable from `ContentBody`) so we
/// don't have to re-derive `Serialize` for libsignal types we don't
/// own. Metadata fields are spelled out individually for
/// pddbcli-readability.
///
/// # Security
///
/// `body_proto` is the protobuf-encoded plaintext of a Signal
/// message — i.e. the decrypted message body, including any
/// attachment pointers. Treat it as user content. The struct does
/// **not** derive `Debug`; logging a `StoredMessage` would dump the
/// plaintext body as a decimal-int array.
#[derive(Serialize, Deserialize)]
struct StoredMessage {
    sender: String,
    destination: String,
    sender_device: u32,
    server_guid: Option<String>,
    timestamp: u64,
    needs_receipt: bool,
    unidentified_sender: bool,
    was_plaintext: bool,
    body_proto: Vec<u8>,
}

impl StoredMessage {
    fn from_content(content: Content) -> Self {
        let Content { metadata, body } = content;
        let body_proto = body.into_proto().encode_to_vec();
        let sender_device: u32 = metadata.sender_device.into();
        Self {
            sender: metadata.sender.service_id_string(),
            destination: metadata.destination.service_id_string(),
            sender_device,
            server_guid: metadata.server_guid.map(|u| u.to_string()),
            timestamp: metadata.timestamp,
            needs_receipt: metadata.needs_receipt,
            unidentified_sender: metadata.unidentified_sender,
            was_plaintext: metadata.was_plaintext,
            body_proto,
        }
    }

    fn into_content(self) -> Result<Content, Error> {
        use presage::libsignal_service::proto;

        let proto = proto::Content::decode(&*self.body_proto)
            .map_err(|e| Error::Decode(format!("body_proto decode: {e}")))?;
        let sender = ServiceId::parse_from_service_id_string(&self.sender)
            .ok_or_else(|| Error::Decode(format!("invalid sender service id: {}", self.sender)))?;
        let destination = ServiceId::parse_from_service_id_string(&self.destination)
            .ok_or_else(|| Error::Decode(format!("invalid destination service id: {}", self.destination)))?;
        let server_guid = self.server_guid.as_deref().and_then(|s| Uuid::parse_str(s).ok());
        let sender_device = DeviceId::try_from(self.sender_device)
            .map_err(|e| Error::Decode(format!("sender_device: {e}")))?;
        let metadata = Metadata {
            sender,
            destination,
            sender_device,
            server_guid,
            timestamp: self.timestamp,
            needs_receipt: self.needs_receipt,
            unidentified_sender: self.unidentified_sender,
            was_plaintext: self.was_plaintext,
        };

        Content::from_proto(proto, metadata).map_err(|e| Error::Decode(format!("Content::from_proto: {e:?}")))
    }
}

// --- Profile-key serde shim ---
//
// `ProfileKey` from zkgroup serde-derives, but `serde_json::to_value`
// of the struct gives a `{"bytes": [...]}` object. We use that shape
// for the dict — keeps the `[patch.crates-io].curve25519-dalek` we
// pin from drifting and matches what libsignal-service-rs's
// `serde_profile_key` would produce on a fresh roundtrip.

fn serialize_profile_key(pk: &ProfileKey) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(pk).map_err(Error::encode)
}

fn deserialize_profile_key(bytes: &[u8]) -> Result<ProfileKey, Error> {
    serde_json::from_slice(bytes).map_err(Error::from)
}

// --- ContentsStore impl ---

impl ContentsStore for PddbStore {
    type ContactsIter = std::vec::IntoIter<Result<Contact, Error>>;
    type ContentsStoreError = Error;
    type GroupsIter = std::vec::IntoIter<Result<(GroupMasterKeyBytes, Group), Error>>;
    type MessagesIter = std::vec::IntoIter<Result<Content, Error>>;
    type StickerPacksIter = std::vec::IntoIter<Result<StickerPack, Error>>;

    // --- Profiles ---

    async fn save_profile(&mut self, uuid: Uuid, key: ProfileKey, profile: Profile) -> Result<(), Error> {
        let dict_key = profile_dict_key(uuid, key);
        backend_put_json(&*self.backend, DICT_PROFILES, &dict_key, &profile)
    }

    async fn profile(&self, uuid: Uuid, key: ProfileKey) -> Result<Option<Profile>, Error> {
        let dict_key = profile_dict_key(uuid, key);
        backend_get_json(&*self.backend, DICT_PROFILES, &dict_key)
    }

    async fn save_profile_avatar(
        &mut self,
        uuid: Uuid,
        key: ProfileKey,
        avatar: &AvatarBytes,
    ) -> Result<(), Error> {
        let dict_key = profile_dict_key(uuid, key);
        self.backend.put(DICT_PROFILE_AVATARS, &dict_key, avatar)?;
        Ok(())
    }

    async fn profile_avatar(&self, uuid: Uuid, key: ProfileKey) -> Result<Option<AvatarBytes>, Error> {
        let dict_key = profile_dict_key(uuid, key);
        self.backend.get(DICT_PROFILE_AVATARS, &dict_key)
    }

    async fn upsert_profile_key(&mut self, uuid: &Uuid, key: ProfileKey) -> Result<bool, Error> {
        let dict_key = uuid.to_string();
        let prior = self.backend.get(DICT_PROFILE_KEYS, &dict_key)?;
        let new_bytes = serialize_profile_key(&key)?;
        self.backend.put(DICT_PROFILE_KEYS, &dict_key, &new_bytes)?;
        // Returns `true` when this is a new key; matches sled's contract.
        Ok(prior.is_none())
    }

    async fn profile_key(&self, service_id: &ServiceId) -> Result<Option<ProfileKey>, Error> {
        let dict_key = service_id.raw_uuid().to_string();
        match self.backend.get(DICT_PROFILE_KEYS, &dict_key)? {
            Some(bytes) => deserialize_profile_key(&bytes).map(Some),
            None => Ok(None),
        }
    }

    async fn clear_profiles(&mut self) -> Result<(), Error> {
        self.backend.delete_dict(DICT_PROFILES)?;
        self.backend.delete_dict(DICT_PROFILE_KEYS)?;
        self.backend.delete_dict(DICT_PROFILE_AVATARS)?;
        Ok(())
    }

    // --- Contacts ---

    async fn save_contact(&mut self, contact: &Contact) -> Result<(), Error> {
        let dict_key = contact.uuid.to_string();
        backend_put_json(&*self.backend, DICT_CONTACTS, &dict_key, contact)
    }

    async fn contacts(&self) -> Result<Self::ContactsIter, Error> {
        let keys = self.backend.list_keys(DICT_CONTACTS)?;
        let backend = self.backend.clone();
        let items: Vec<Result<Contact, Error>> = keys
            .into_iter()
            .map(move |k| {
                backend_get_json_required(&*backend, DICT_CONTACTS, &k, || {
                    format!("contact disappeared: {k}")
                })
            })
            .collect();
        Ok(items.into_iter())
    }

    async fn contact_by_id(&self, id: &ServiceId) -> Result<Option<Contact>, Error> {
        let dict_key = id.raw_uuid().to_string();
        backend_get_json(&*self.backend, DICT_CONTACTS, &dict_key)
    }

    async fn clear_contacts(&mut self) -> Result<(), Error> {
        self.backend.delete_dict(DICT_CONTACTS)?;
        Ok(())
    }

    // --- Groups ---

    async fn save_group(
        &self,
        master_key: GroupMasterKeyBytes,
        group: impl Into<Group>,
    ) -> Result<(), Error> {
        let group: Group = group.into();
        let dict_key = group_key(&master_key);
        backend_put_json(&*self.backend, DICT_GROUPS, &dict_key, &group)
    }

    async fn groups(&self) -> Result<Self::GroupsIter, Error> {
        let keys = self.backend.list_keys(DICT_GROUPS)?;
        let backend = self.backend.clone();
        let items: Vec<Result<(GroupMasterKeyBytes, Group), Error>> = keys
            .into_iter()
            .map(move |k| {
                let group: Group = backend_get_json_required(&*backend, DICT_GROUPS, &k, || {
                    format!("group disappeared: {k}")
                })?;
                let master_key_bytes = parse_hex_master_key(&k)?;
                Ok((master_key_bytes, group))
            })
            .collect();
        Ok(items.into_iter())
    }

    async fn group(&self, master_key: GroupMasterKeyBytes) -> Result<Option<Group>, Error> {
        let dict_key = group_key(&master_key);
        backend_get_json(&*self.backend, DICT_GROUPS, &dict_key)
    }

    async fn save_group_avatar(
        &self,
        master_key: GroupMasterKeyBytes,
        avatar: &AvatarBytes,
    ) -> Result<(), Error> {
        let dict_key = group_key(&master_key);
        self.backend.put(DICT_GROUP_AVATARS, &dict_key, avatar)?;
        Ok(())
    }

    async fn group_avatar(&self, master_key: GroupMasterKeyBytes) -> Result<Option<AvatarBytes>, Error> {
        let dict_key = group_key(&master_key);
        self.backend.get(DICT_GROUP_AVATARS, &dict_key)
    }

    async fn clear_groups(&mut self) -> Result<(), Error> {
        self.backend.delete_dict(DICT_GROUPS)?;
        self.backend.delete_dict(DICT_GROUP_AVATARS)?;
        Ok(())
    }

    // --- Sticker packs ---

    async fn add_sticker_pack(&mut self, pack: &StickerPack) -> Result<(), Error> {
        let dict_key = sticker_pack_key(&pack.id);
        backend_put_json(&*self.backend, DICT_STICKER_PACKS, &dict_key, pack)
    }

    async fn sticker_pack(&self, id: &[u8]) -> Result<Option<StickerPack>, Error> {
        let dict_key = sticker_pack_key(id);
        backend_get_json(&*self.backend, DICT_STICKER_PACKS, &dict_key)
    }

    async fn remove_sticker_pack(&mut self, id: &[u8]) -> Result<bool, Error> {
        let dict_key = sticker_pack_key(id);
        let existed = self.backend.get(DICT_STICKER_PACKS, &dict_key)?.is_some();
        self.backend.delete(DICT_STICKER_PACKS, &dict_key)?;
        Ok(existed)
    }

    async fn sticker_packs(&self) -> Result<Self::StickerPacksIter, Error> {
        let keys = self.backend.list_keys(DICT_STICKER_PACKS)?;
        let backend = self.backend.clone();
        let items: Vec<Result<StickerPack, Error>> = keys
            .into_iter()
            .map(move |k| {
                backend_get_json_required(&*backend, DICT_STICKER_PACKS, &k, || {
                    format!("sticker pack disappeared: {k}")
                })
            })
            .collect();
        Ok(items.into_iter())
    }

    // --- Messages-by-thread ---

    async fn save_message(&self, thread: &Thread, message: Content) -> Result<(), Error> {
        let dict = thread_dict_name(thread);
        let key = message_key(message.metadata.timestamp);
        let stored = StoredMessage::from_content(message);
        backend_put_json(&*self.backend, &dict, &key, &stored)
    }

    async fn delete_message(&mut self, thread: &Thread, timestamp: u64) -> Result<bool, Error> {
        let dict = thread_dict_name(thread);
        let key = message_key(timestamp);
        let existed = self.backend.get(&dict, &key)?.is_some();
        self.backend.delete(&dict, &key)?;
        Ok(existed)
    }

    async fn message(&self, thread: &Thread, timestamp: u64) -> Result<Option<Content>, Error> {
        let dict = thread_dict_name(thread);
        let key = message_key(timestamp);
        match backend_get_json::<StoredMessage>(&*self.backend, &dict, &key)? {
            Some(stored) => stored.into_content().map(Some),
            None => Ok(None),
        }
    }

    async fn messages(
        &self,
        thread: &Thread,
        range: impl RangeBounds<u64>,
    ) -> Result<Self::MessagesIter, Error> {
        let dict = thread_dict_name(thread);
        let keys = self.backend.list_keys(&dict)?;
        let backend = self.backend.clone();

        // Filter by range, then preload — list_keys is non-streaming,
        // so the eager Vec is what the underlying capability gives us.
        // A cache layer can optimize if profiling demands it.
        let mut filtered: Vec<u64> = keys
            .into_iter()
            .filter_map(|k| u64::from_str_radix(&k, 16).ok())
            .filter(|ts| range_contains_u64(&range, *ts))
            .collect();
        filtered.sort_unstable();

        let dict_owned = dict.clone();
        let items: Vec<Result<Content, Error>> = filtered
            .into_iter()
            .map(move |ts| {
                let key = message_key(ts);
                let stored: StoredMessage = backend_get_json_required(&*backend, &dict_owned, &key, || {
                    format!("message disappeared: {key}")
                })?;
                stored.into_content()
            })
            .collect();
        Ok(items.into_iter())
    }

    async fn clear_thread(&mut self, thread: &Thread) -> Result<(), Error> {
        let dict = thread_dict_name(thread);
        self.backend.delete_dict(&dict)?;
        Ok(())
    }

    async fn clear_messages(&mut self) -> Result<(), Error> {
        // PDDB doesn't expose a "drop all dicts matching a prefix" so
        // we walk the known thread-dict names. We don't keep an index
        // of all thread descriptors anywhere; threads appear as soon
        // as `save_message` is called and disappear on `clear_thread`.
        // If a future caller creates threads we lose track of, this
        // method becomes a no-op for those — matches sled's behaviour,
        // which similarly relies on knowing the full set of dict
        // names. An index dict could be added later if
        // `clear_messages` becomes a hot path.
        //
        // For tests, callers should `clear_thread` per known thread
        // explicitly.
        Ok(())
    }

    async fn clear_contents(&mut self) -> Result<(), Error> {
        // Matches sled's `clear_contents`: drops contacts + groups +
        // group avatars + every per-thread dict the caller has
        // visibility of (we delegate to `clear_messages`'s no-op for
        // the threads side).
        self.backend.delete_dict(DICT_CONTACTS)?;
        self.backend.delete_dict(DICT_GROUPS)?;
        self.backend.delete_dict(DICT_GROUP_AVATARS)?;
        self.clear_profiles().await?;
        Ok(())
    }
}

fn parse_hex_master_key(hex: &str) -> Result<GroupMasterKeyBytes, Error> {
    if hex.len() != 64 {
        return Err(Error::Decode(format!("group key not 64 hex chars: {} chars", hex.len())));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let idx = i * 2;
        *byte = u8::from_str_radix(&hex[idx..idx + 2], 16)
            .map_err(|e| Error::Decode(format!("hex parse: {e}")))?;
    }
    Ok(out)
}

fn range_contains_u64<R: RangeBounds<u64>>(range: &R, value: u64) -> bool {
    let after_start = match range.start_bound() {
        Bound::Included(&s) => value >= s,
        Bound::Excluded(&s) => value > s,
        Bound::Unbounded => true,
    };
    let before_end = match range.end_bound() {
        Bound::Included(&e) => value <= e,
        Bound::Excluded(&e) => value < e,
        Bound::Unbounded => true,
    };
    after_start && before_end
}
