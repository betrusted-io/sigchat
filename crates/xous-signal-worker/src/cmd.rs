//! Channel vocabulary between the app's main thread and the
//! [`presage::Manager`] worker.
//!
//! [`Cmd`] flows main -> worker; [`Event`] flows worker -> main. The
//! same pair of `async-channel` channels serves both directions: the
//! sync UI side uses `send_blocking`/`recv_blocking`, the async
//! worker side uses `send`/`recv`. No `block_on` round-trips, no
//! locks across the boundary.
//!
//! # Trust boundary
//!
//! This module defines the *only* IPC surface between the worker and
//! the rest of xas. Everything in it is the audit checkpoint between
//! UI code that may run untrusted UTF-8 (user input, contact strings)
//! and the worker that holds the [`PddbStore`](presage_store_pddb::PddbStore)
//! and the Signal-Protocol session state. Variants are deliberately
//! string- and primitive-typed so the boundary remains
//! readable in code review; richer typed payloads must stay inside
//! the worker.
//!
//! # Sensitive data crossing this boundary
//!
//! - [`Cmd::SendMessage`] carries the outgoing plaintext `body` (still unencrypted at this point: libsignal
//!   does the X3DH/PQXDH + double-ratchet encryption *after* this command is consumed by the worker).
//! - [`Event::Message`] carries the *decrypted* plaintext `body` of an inbound message — the libsignal trust
//!   witness for "this text was authentically sent by `sender`."
//! - [`Event::LinkUrl`] carries the secondary-device provisioning URL. Anyone able to read this URL within
//!   its window can claim the link.
//! - [`Event::LinkComplete`] / [`AccountInfoData`] surface ACI, phone number, and device name — Signal
//!   account identifiers that link the device to its real-world account.

/// Commands sent from the app (main thread) to the Manager worker.
#[derive(Debug, Clone)]
pub enum Cmd {
    /// Channel-roundtrip ping. The worker replies with `Event::Pong`
    /// without touching the store. Useful as a startup liveness probe.
    Hello,

    /// Ask the worker for `Manager::registration_data().whoami()`.
    /// On a fresh install this fails fast inside `load_registered`
    /// because the mock store has no registration data, which is the
    /// expected path the test exercises. Once a linked store lands,
    /// this becomes the real "who am I to the Signal server" probe.
    GetWhoami,

    /// Link this device as a secondary to a phone-resident Signal
    /// account. The worker calls
    /// [`presage::Manager::link_secondary_device`], which streams a
    /// provisioning URL out (forwarded as [`Event::LinkUrl`]) and
    /// blocks until the phone confirms. On success the worker emits
    /// [`Event::LinkComplete`] and *retains the resulting `Manager`
    /// for subsequent receive/send calls*. On failure it emits
    /// [`Event::LinkError`] and the worker stays unregistered.
    ///
    /// Refused with [`Event::StaleStoreDetected`] (no link started)
    /// when the store still holds account state from a previous
    /// link — see that variant for the rationale.
    ///
    /// # Trust boundary
    ///
    /// Triggers the only path that writes identity and root keys to
    /// PDDB. After `LinkComplete`, the worker holds a registered
    /// Manager whose Signal-Protocol session state derives from
    /// material handshaked with the primary phone during this call.
    ///
    /// # Security
    ///
    /// `device_name` is sent to the primary device (the Signal
    /// server forwards it) and shown to the user there; treat as
    /// user-controlled UTF-8 that ends up in another party's UI.
    LinkDevice { device_name: String },

    /// Cancel an in-flight link. Best-effort — if the
    /// worker is already past the URL step, the cancel may be ignored
    /// and the link completes anyway.
    LinkCancel,

    /// Open the receive stream. Requires a linked Manager (from
    /// [`Cmd::LinkDevice`] or the worker's startup `load_registered`).
    /// The manager task that owns the Manager starts pumping
    /// `Manager::receive_messages`, translating each
    /// `Received::Content` into `Event::Message` and calling
    /// `store.flush_sessions()` on `Received::QueueEmpty`. Idempotent:
    /// a second StartReceive while the stream is open is dropped.
    StartReceive,

    /// Send a 1:1 text message to the named recipient. Routed through
    /// the manager task that owns the Manager.
    ///
    /// `recipient` is either a `service_id_string()` (e.g.
    /// `"00000000-0000-4000-8000-000000000001"` for an Aci) or a
    /// `+e164` phone number; the worker parses it into a
    /// libsignal `ServiceId` before calling
    /// [`presage::Manager::send_message`]. Phone-number recipients
    /// are resolved against the contacts store (which is empty until
    /// `Cmd::SyncContacts` has run successfully).
    ///
    /// `body` is the plaintext UTF-8 message body. `timestamp` is the
    /// client-generated unix-ms timestamp the UI used when it
    /// optimistically appended the outgoing message to its in-RAM
    /// history; the worker echoes this same value back in
    /// [`Event::SendComplete`] and [`Event::SendError`] so the UI can
    /// correlate event-to-pending-message in its optimistic-render
    /// path. The worker also uses this as the Signal-protocol
    /// timestamp on the wire.
    ///
    /// Requires a linked Manager. Sending before link gets a
    /// `SendError { reason: "not linked yet — ...", .. }`.
    ///
    /// # Trust boundary
    ///
    /// `body` is *plaintext* at this point. Encryption (X3DH/PQXDH +
    /// double-ratchet seal) happens inside `Manager::send_message`
    /// after the worker consumes this command.
    ///
    /// # Logging
    ///
    /// The worker emits `body_len` (length only, never the body
    /// itself) to its log pipeline. `recipient` is logged in full.
    SendMessage { recipient: String, body: String, timestamp: u64 },

    /// Read account-identity info from the loaded Manager and
    /// reply via `Event::AccountInfo`. UI uses this to populate
    /// the Profile screen on a cold start where the device was
    /// already linked from a prior session — `Event::LinkComplete`
    /// only fires on a fresh link or when load_registered succeeds
    /// during the worker's startup retry budget (which can expire
    /// before PDDB unlocks). Re-tries `load_registered` if the
    /// Manager isn't loaded yet.
    GetAccountInfo,

    /// User-triggered: contact-sync round-trip with the linked phone.
    /// Routed to the manager task, which calls
    /// `manager.request_contacts()` — a self-targeted
    /// `SyncMessage.Request{type=CONTACTS}`; the primary phone replies
    /// with the contacts blob; presage's `SynchronizeMessage` handler
    /// saves the entries to `ContentsStore` as the receive stream
    /// absorbs them. Replies with [`Event::SyncComplete`] /
    /// [`Event::SyncError`]. Works before or after
    /// [`Cmd::StartReceive`].
    ///
    /// Skipped on link by default (it adds 30-90s of WS roundtrips on
    /// rv32 and races the WS-rotation problem); F2 in the post-link UI
    /// is the user-triggered way to populate contacts on demand.
    SyncContacts,

    /// User-triggered: log out from the linked Signal account. Tears
    /// down the manager (drops the WS pump, ends the receive stream),
    /// wipes the PDDB-backed Store (registration data, identity
    /// keypairs, sender cert, master key, all protocol-store
    /// dictionaries, all messages-by-thread, all profiles + contacts),
    /// and emits [`Event::LoggedOut`]. The worker stays alive — the
    /// user can immediately send a fresh [`Cmd::LinkDevice`] to
    /// relink.
    ///
    /// # Security
    ///
    /// Best-effort key destruction. The store wipe routes through
    /// `Store::clear`, which deletes the PDDB dictionaries holding
    /// the identity keypair, prekeys, signed prekeys, root/chain
    /// keys, sender cert, and master key. Errors during the wipe are
    /// logged but non-fatal — `Event::LoggedOut` fires anyway. Stale
    /// material left by a failed wipe would still be encrypted at
    /// rest by the PDDB master secret, but a subsequent re-link
    /// could read it back; the warning log is the only signal an
    /// operator currently has.
    ///
    /// `presage_store_pddb`'s `Store::clear` is not atomic across
    /// dictionaries (see `presage-store-pddb/src/store.rs::clear`):
    /// a mid-clear error leaves
    /// `session_cache` and `session_dirty` partially populated, and
    /// downstream the PDDB free-list does **not** zero pages on
    /// dictionary delete. Acquiring the flash post-wipe
    /// can therefore recover ciphertext that the API surface
    /// presents as gone. A secure-erase opcode from the PDDB
    /// side would be the deeper fix.
    ///
    /// This does **not** remove the device from the primary phone's
    /// Linked Devices list — that requires `unlink_secondary`,
    /// which is a primary-only API. The user must remove the entry
    /// from the primary's UI to fully retire the link.
    Logout,

    /// User-triggered: lookup a Signal username (e.g., `alice.42`)
    /// to its ACI, so the UI can open a `Screen::Thread { uuid }`
    /// for it. Routed to the manager task; the result arrives as
    /// [`Event::UsernameResolveResult`]. Works before or after
    /// [`Cmd::StartReceive`].
    ResolveUsername(String),

    /// Tell the worker to drain its event channel and exit. The main
    /// thread sends this before joining the worker handle so we don't
    /// rely on dropping the cmd channel sender (which works but is
    /// implicit).
    Shutdown,
}

/// Identity fields read from `Manager::registration_data()`.
///
/// Mirrors the shape of [`Event::LinkComplete`] but lives in its own
/// struct since the same data is also surfaced via
/// [`Event::AccountInfo`].
///
/// # Security
///
/// Contains Signal account identifiers (ACI and registered phone
/// number) and the user-supplied device name. None of these are
/// secret in the cryptographic sense — they are public to the Signal
/// server and to anyone the account communicates with — but they
/// link the device to its real-world account. The `Debug` derive
/// stringifies all three fields, so any `tracing::debug!(?info)` or
/// panic backtrace involving this struct emits the account identity
/// to the log pipeline.
#[derive(Debug, Clone)]
pub struct AccountInfoData {
    /// Device label the user chose at link time (e.g. `"xas-phoenix"`).
    /// Round-trips through the primary phone's Linked Devices list.
    pub device_name: String,
    /// Account Identifier in UUID form (libsignal `Aci::to_string()`).
    pub aci: String,
    /// Registered phone number in e164 form (`+<country><digits>`).
    pub phone: String,
}

impl AccountInfoData {
    /// Read the identity fields out of a loaded `Manager`'s
    /// registration data. The single home for the
    /// `device_name`/`aci`/`phone` extraction that the link, load,
    /// and account-info paths all share.
    pub(crate) fn from_manager(
        manager: &presage::Manager<presage_store_pddb::PddbStore, presage::manager::Registered>,
    ) -> Self {
        let data = manager.registration_data();
        Self {
            device_name: data.device_name.clone().unwrap_or_default(),
            aci: data.service_ids.aci.to_string(),
            phone: data.phone_number.to_string(),
        }
    }
}

/// Events sent from the worker back to the app (main thread).
#[derive(Debug, Clone)]
pub enum Event {
    /// Reply to `Cmd::Hello`.
    Pong,

    /// Reply to `Cmd::GetWhoami`. We keep it as `Result<String, String>`
    /// rather than presage's `WhoAmIResponse` / `presage::Error<E>`:
    /// the IPC boundary forces stringification anyway (Xous IPC
    /// won't carry trait-object errors), and a stringly-typed
    /// outcome is what the UI ultimately needs.
    Whoami(Result<String, String>),

    /// The provisioning URL the user must scan or transcribe with
    /// their Signal phone. Emitted once per [`Cmd::LinkDevice`],
    /// promptly after the worker calls `link_secondary_device`. The
    /// URL is a `tsdevice://...` deep-link — render as text or as a
    /// QR depending on the surface.
    ///
    /// # Security
    ///
    /// The URL carries the provisioning-session identifier libsignal
    /// will accept to complete the link. Anyone who reads this string
    /// during its window (until the primary phone scans it or the
    /// libsignal call times out) can pair their own device against
    /// this xas instance's pending link request — meaning the
    /// attacker walks away with a Signal-Protocol session bound to
    /// our generated identity. The string MUST be treated as
    /// sensitive even though it expires:
    ///
    /// - Do not log the URL to any persistent surface (UART, PDDB diagnostic dump, screenshot uploader).
    /// - Render directly to the user's display only; do not stage it through any in-memory buffer that may be
    ///   later dumped.
    ///
    /// `handle_link_device` emits it only under the default-off
    /// `link-uri-uart` feature.
    LinkUrl(String),

    /// Linking succeeded. The worker has just transitioned to
    /// `Manager<S, Registered>` internally and persisted the
    /// registration data via `StateStore`. Fields are pulled from
    /// `RegistrationData` for display.
    ///
    /// # Trust boundary
    ///
    /// Emission of this variant is the witness that the worker now
    /// holds a `Manager<PddbStore, Registered>` whose Signal-Protocol
    /// identity is provisioned and persisted. No code path emits this
    /// variant without having received a successful link result from
    /// libsignal-service.
    ///
    /// # Security
    ///
    /// Carries the same identifiers as `AccountInfoData` (the inner
    /// type of [`Event::AccountInfo`]). See that struct's `# Security`
    /// block for the disclosure caveat.
    LinkComplete {
        /// Device label from `RegistrationData::device_name`. Empty
        /// string if upstream stored `None` (rare — link flow always
        /// supplies one).
        device_name: String,
        /// Account Identifier as a UUID string.
        aci: String,
        /// Registered phone number, e164 form.
        phone: String,
    },

    /// Linking failed before the user-visible UI could
    /// finish. Reasons include network error, timeout, and the phone
    /// rejecting the link request. String-typed because the IPC
    /// boundary forces stringification (same shape as `Whoami`).
    LinkError(String),

    /// The worker refused a [`Cmd::LinkDevice`] because the store
    /// still holds account state from a previous link
    /// (`PddbStore::has_account_state`). Linking over a stale store
    /// re-inherits stale sessions and orphaned kyber records; the
    /// implicit link-time wipe that used to prevent this (3680fe2)
    /// hung a device and was reverted (fa1c37b), so the worker never
    /// wipes on this path — it emits this event and the UI routes
    /// the user to the explicit Wipe settings flow instead. No link
    /// was started; a fresh `Cmd::LinkDevice` after a wipe proceeds
    /// normally.
    StaleStoreDetected,

    /// Reply to `Cmd::GetAccountInfo`. Carries the same fields as
    /// `LinkComplete` but fires on demand rather than tied to the
    /// link/load lifecycle. `Err(reason)` when the manager isn't
    /// loaded (e.g. PDDB still locked or the device was never
    /// linked).
    AccountInfo(Result<AccountInfoData, String>),

    /// Confirms the receive loop is established. Emitted
    /// after `Manager::receive_messages` has returned a stream and
    /// the worker is parked on its `next()`. UI uses this to
    /// transition the status indicator from "starting" to "listening".
    ReceiveStarted,

    /// A single decrypted incoming message. Fields are flattened
    /// from `presage::libsignal_service::content::Content` for the
    /// same IPC reason `LinkComplete` is — string-typed payloads
    /// cross the boundary cleanly. Only `DataMessage`-style text
    /// bodies are surfaced; control / sync / receipt messages from
    /// the receive stream are silently dropped at the worker (their
    /// effect on the store is already applied).
    ///
    /// # Trust boundary
    ///
    /// Emission of this variant means libsignal-protocol has
    /// authenticated the message: the double-ratchet MAC matched
    /// the receiving chain, and the sealed-sender envelope was
    /// signed by a sender certificate that chains to a server-
    /// trusted root. `sender` is therefore the libsignal-authenticated
    /// identity of the originator — not a network-controlled string.
    ///
    /// # Security
    ///
    /// `body` is decrypted plaintext from a remote party. Three
    /// cautions:
    ///
    /// 1. The string content is attacker-influenceable — it is whatever the sender chose to type. UI code
    ///    rendering it must treat as untrusted UTF-8 (display sanitization, no shell/format interpretation).
    /// 2. The string MUST NOT be logged or persisted outside the PDDB-backed `Store`. The worker itself logs
    ///    only the variant kind and `body_len`, never the body.
    /// 3. The string lives in RAM only — `Drop` of this struct deallocates without zeroizing. Defense in
    ///    depth would require a `Zeroizing<String>` wrapper here; out of scope for the channel surface.
    Message {
        /// `service_id_string()` of the sender — the thread key the
        /// UI groups conversations by. libsignal-authenticated; see
        /// the variant's `# Trust boundary`.
        sender: String,
        /// Display-friendly phone-number form of the sender, resolved
        /// from the contacts store at the time the message was
        /// processed. `None` when the contact isn't in the store
        /// (first-sight from a peer who isn't yet synced from the
        /// linked phone). UIs should fall back to `sender` (the UUID)
        /// when this is `None`.
        sender_phone: Option<String>,
        /// Display-friendly profile name of the sender, same lookup
        /// path as `sender_phone`. Empty profiles are surfaced as
        /// `None`.
        sender_name: Option<String>,
        /// Plaintext body. Empty string means an attachment-only or
        /// reaction-only DataMessage that we can't render in MVP.
        ///
        /// MUST NOT be logged or persisted outside the PDDB-backed
        /// `Store`.
        body: String,
        /// Server timestamp (UNIX millis), matches what `Content`
        /// carries.
        timestamp: u64,
        /// `Some(master_key)` when the DataMessage carried a
        /// `GroupContextV2` — this is a group message, NOT a 1:1
        /// message from `sender`. The bytes are the GV2 master key
        /// (normally 32) used only as a stable opaque thread
        /// discriminator; group name/member resolution stays with
        /// presage until real group support lands. `None` for plain
        /// 1:1 traffic, including sync-sent transcripts of 1:1
        /// sends.
        ///
        /// # Security
        ///
        /// The GV2 master key derives the group's zkgroup secrets;
        /// treat like `body` — never log, never persist outside the
        /// PDDB-backed store (presage already keeps it there).
        group_master_key: Option<Vec<u8>>,
    },

    /// Receive loop hit a fatal error and unwound. The
    /// worker's Manager is consumed at this point; the user must
    /// re-link to resume.
    ReceiveError(String),

    /// A `Cmd::SendMessage` succeeded. `timestamp` is the
    /// server-side timestamp the message was tagged with — useful
    /// to the UI for echoing the sent message into the conversation
    /// list as an outgoing entry.
    SendComplete { timestamp: u64 },

    /// A `Cmd::SendMessage` failed. Common reasons:
    /// invalid recipient UUID, network error, recipient session
    /// expired (in which case Signal expects a re-key on next
    /// attempt). `timestamp` is the same client-generated timestamp
    /// the UI used when it optimistically appended the outgoing
    /// message; it lets the UI find the right pending row to mark
    /// failed. `None` means the failure happened before a timestamp
    /// was assigned (e.g. recipient parse failed, manager task died
    /// before the call).
    SendError { reason: String, timestamp: Option<u64> },

    /// First-touch profile lookup completed for a sender we
    /// previously surfaced as `Event::Message { sender_name: None }`.
    /// The UI walks its in-RAM messages and replaces any rows whose
    /// `author_label` is the bare UUID with this `name`.
    ///
    /// Best-effort: emitted only after the receive stream is paused
    /// (between iterations of `manager_task`'s outer loop), so the
    /// UI may continue showing the UUID for some seconds after the
    /// first message arrives. On 404 (sender opted out of profile
    /// fetches) or other error, no event is emitted — the UI keeps
    /// the UUID indefinitely until the next user-triggered Sync.
    ContactResolved {
        /// ACI of the resolved sender, formatted as a UUID.
        aci_uuid: presage::libsignal_service::prelude::Uuid,
        /// Profile name (`given_name [+ ' ' + family_name]`) decoded
        /// from the cipher response. Empty profile names are filtered
        /// out at the worker — this `name` is always non-empty.
        name: String,
    },

    /// `Cmd::SyncContacts` finished. The worker has already emitted
    /// one `ContactResolved` per (uuid, name) it saw in the freshly-
    /// synced contacts table. UI uses this terminator to flip the
    /// "Syncing…" indicator off.
    SyncComplete,

    /// `Cmd::SyncContacts` failed. UI surfaces the reason via a
    /// modal/notification.
    SyncError(String),

    /// `Cmd::Logout` finished. Manager dropped, store wiped. UI
    /// resets account state, clears messages/dialogues, transitions
    /// to `Screen::Menu` with `MenuItem::Link`.
    LoggedOut,

    /// Server-forced auth expiry: Signal sent WS close code 4401
    /// ("Reauthentication required") and our credential-refresh
    /// path failed to recover (N consecutive 403s on the refreshed
    /// WS). Emitted by `manager_task` after the reauth retry budget
    /// is exhausted. UI mirrors the `LoggedOut` reset but surfaces
    /// the reason as a banner so the user understands they need to
    /// re-link rather than thinking the device is generally broken.
    /// See #13 for the underlying bug. The String is a short
    /// human-readable reason (typically the last 403 response body
    /// or a synthesized "reauthentication failed after N retries").
    SignalAuthExpired(String),

    /// Server-forced displacement: Signal sent WS close code 4409
    /// ("Connected elsewhere"). This fires when a different
    /// authenticated WS for the same (accountIdentifier, deviceId)
    /// pair connects to the server — Signal-Server's
    /// `ConflictingMessageConsumerException` displaces the older
    /// listener. Common scenario: another xas instance, or this
    /// same xas's previous WS that got displaced by a fresh
    /// reconnect while the server's slot hadn't cleared yet.
    /// Emitted by `manager_task` when the receive stream sees
    /// 4409 — treated as terminal rather than retried, because
    /// auto-reconnect would just self-displace again. UI mirrors
    /// the `LoggedOut` reset with a banner explaining that another
    /// device or app instance took over. User re-links to use this
    /// device. See #1 for the underlying bug. The String is a
    /// short human-readable reason for diagnostics (typically
    /// "Server reported 4409 'Connected elsewhere' — another
    /// device with this Signal account is active.").
    SignalConflictingDevice(String),

    /// `Cmd::ResolveUsername` finished. Result is `Some(aci)` if the
    /// username resolved (UI opens a Thread for that uuid),
    /// `None` if no such username exists, or
    /// `Err(reason)` for any other failure (network, etc.).
    UsernameResolveResult(Result<Option<presage::libsignal_service::prelude::Uuid>, String>),

    /// Confirms the worker is winding down. The main thread joins
    /// after receiving this — same way Manager state machines on
    /// other Whisperfish ports signal teardown.
    ShuttingDown,
}
