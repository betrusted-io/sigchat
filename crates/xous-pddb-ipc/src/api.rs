//! Wire types for the PDDB server.
//!
//! Each type here corresponds to a payload that crosses the IPC
//! boundary into the PDDB server process. The on-the-wire layout is
//! defined upstream at `xous-core/services/pddb/src/api.rs`; this
//! module is a verbatim subset (only what the KV-shaped call paths
//! need) and the rkyv derives must produce byte-identical archives.
//!
//! # Trust boundary
//!
//! Every struct in this module crosses the kernel-mediated IPC
//! boundary. The PDDB server is a separate process; the kernel
//! schedules the page-lend, copies the payload into the receiver's
//! address space, and returns the receiver's mutations on
//! `lend_mut`. We trust:
//!
//! - the kernel for in-process isolation (only the named PDDB server sees the lent page);
//! - the PDDB server to honor the wire schema (it does, because we are a wire-level subset of its own client
//!   crate).
//!
//! We do **not** trust:
//!
//! - field values returned by the server beyond what the variant discriminants in [`PddbRequestCode`] /
//!   [`PddbRetcode`] declare. `PddbBuf::len` is range-checked by [`crate::client::KeyHandle`] on every read.
//!
//! # Wire format
//!
//! Two transport flavors:
//!
//! 1. **rkyv 0.8 `Archive`** for the variable-shape requests ([`PddbKeyRequest`], [`PddbDictRequest`],
//!    [`PddbKeyList`], [`PddbWriteBatch`]). The kernel lends a freshly-serialized page; the server
//!    deserializes and re-serializes the same type in place. The workspace pins rkyv 0.8.16; xous-core pins
//!    0.8.8. rkyv promises wire compatibility inside the 0.8.x line.
//! 2. **C-repr 4096-byte page** for [`PddbBuf`]. The server reads it as a raw struct (no serialization). The
//!    buffer must be page-aligned; see [`PddbBuf::from_slice_mut`].
//!
//! # rv32 / 16 MiB constraint
//!
//! All four rkyv payloads fit in one 4 KiB page. The streaming
//! [`PddbBuf`] is exactly one 4 KiB page by `const`-assert at the
//! bottom of this module. Each IPC round-trip pays the kernel cost
//! of a `MutableLend` (TLB shootdown + zero on `MutableBorrow`
//! return); the per-byte transfer rate is capped at 4072 bytes per
//! round-trip on the streaming path.
//!
//! # Security
//!
//! Payload bytes are opaque PDDB record bytes. This crate performs
//! no cryptography; encryption-at-rest is the PDDB server's
//! responsibility. No constant-time guarantee is required nor
//! provided — the entries crossing this boundary include MAC'd
//! ciphertext (already-protected, side-channel-irrelevant) and
//! libsignal session bytes (which the caller has already chosen to
//! commit to durable storage and which transit a trusted IPC).

use bitfield::bitfield;
use num_derive::{FromPrimitive, ToPrimitive};

/// Name registered by the PDDB main server with `xous-names`.
///
/// The server registers this string on boot; clients resolve it via
/// `XousNames::request_connection_blocking` to obtain a CID.
/// Defined verbatim from upstream — must match byte-for-byte.
pub const SERVER_NAME_PDDB: &str = "_Plausibly Deniable Database_";

/// Name registered by the PDDB mount-state poller server.
///
/// A separate SID from the main server: replies are cheap scalars
/// and can race ahead of long-running key operations on
/// [`SERVER_NAME_PDDB`].
pub const SERVER_NAME_PDDB_POLLER: &str = "_PDDB Mount Poller_";

/// Maximum length (in bytes) of a basis name on the wire.
///
/// PDDB itself enforces the cap server-side; this constant exists so
/// callers can validate inputs before incurring an IPC.
pub const BASIS_NAME_LEN: usize = 64;

/// Maximum length (in bytes) of a dictionary name on the wire.
///
/// Derived from the upstream [`PddbDictRequest`] wire layout: 127
/// bytes total carve-out, minus four `u32` header fields.
pub const DICT_NAME_LEN: usize = 127 - 4 - 4 - 4 - 4; // 111

/// Maximum length (in bytes) of a key name on the wire.
///
/// Derived from the upstream [`PddbKeyRequest`] wire layout: 127
/// bytes total carve-out, minus three `u64` and two `u32` header
/// fields.
pub const KEY_NAME_LEN: usize = 127 - 8 - 8 - 8 - 4 - 4; // 95

/// Server-issued opaque handle for an open key.
///
/// The server mints one on [`Opcode::KeyRequest`] success and the
/// client echoes it back on every subsequent [`Opcode::ReadKey`] /
/// [`Opcode::WriteKey`] / [`Opcode::WriteKeyFlush`] /
/// [`Opcode::KeyDrop`]. The token has no meaning outside the
/// server's in-memory `token_dict` mapping; clients must treat the
/// three `u32` words as opaque.
pub type ApiToken = [u32; 3];

/// PDDB main-server opcodes.
///
/// Subset of the upstream `Opcode` enum carrying only the variants
/// this crate emits. Discriminants are sourced verbatim from
/// `services/pddb/src/api.rs` and **must not be reordered**: the
/// `#[repr(u32)]` discriminant is the literal `u32` written into
/// every IPC message, and adding a new variant in the wrong slot
/// would re-number existing variants and silently route messages to
/// the wrong server handler.
///
/// # Wire format
///
/// The numeric value is passed as the `id` field of
/// `xous::Message::new_lend_mut` / `new_blocking_scalar`. Each
/// variant pairs with a specific message kind:
///
/// - Scalar (no buffer): [`Opcode::TryMount`], [`Opcode::WriteKeyFlush`], [`Opcode::KeyDrop`]; the poller
///   server's [`PollOp::Poll`] uses opcode 0 on a different SID.
/// - `MutableLend` (rkyv'd page): [`Opcode::KeyRequest`], [`Opcode::DeleteKey`], [`Opcode::DeleteDict`],
///   [`Opcode::KeyCountInDict`], [`Opcode::ListKeyV2`], [`Opcode::WriteKeyBatch`].
/// - `MutableLend` (raw [`PddbBuf`] page): [`Opcode::ReadKey`], [`Opcode::WriteKey`].
#[derive(Debug, Clone, Copy, FromPrimitive, ToPrimitive)]
#[repr(u32)]
pub enum Opcode {
    /// Cheap blocking-scalar mount check. The main server returns
    /// `Scalar1(1)` if mounted, `Scalar1(0)` otherwise. Prefer
    /// [`PollOp::Poll`] on the poller SID for non-blocking checks.
    IsMounted = 0,
    /// Trigger an interactive mount. Server pops the GAM password
    /// modal and waits for the user; this can block for arbitrarily
    /// long. Returns `Scalar2(retcode, failcount)` or
    /// `Scalar1(retcode)` (handler details in upstream
    /// `main.rs::Opcode::TryMount`).
    TryMount = 1,
    /// Delete a single key. Wire payload: [`PddbKeyRequest`]
    /// (server fills `result`).
    DeleteKey = 8,
    /// Delete a dictionary and all its keys. Wire payload:
    /// [`PddbKeyRequest`] — *not* [`PddbDictRequest`]. The fields
    /// the server reads are the same (`dict`, `basis`); the
    /// upstream handler at `services/pddb/src/main.rs::DeleteDict`
    /// rkyv-deserializes a [`PddbKeyRequest`].
    DeleteDict = 9,
    /// Query attributes of an open key. Carried for wire-schema
    /// compatibility; not exercised by this crate.
    KeyAttributes = 10,
    /// Count + token-fetch for [`Opcode::ListKeyV2`]. Wire payload:
    /// [`PddbDictRequest`]; server fills `key_count` /
    /// `found_key_count` and stamps `token` server-side for the
    /// follow-up listing.
    KeyCountInDict = 11,
    /// Open (and optionally create) a `(dict, key)` pair. Wire
    /// payload: [`PddbKeyRequest`]; server fills `token` and
    /// `result`. The returned token is the handle for subsequent
    /// `ReadKey` / `WriteKey` / `KeyDrop`.
    KeyRequest = 15,
    /// Stream bytes out of an open key. Wire payload: raw
    /// page-aligned [`PddbBuf`] (no rkyv); server fills `data` and
    /// `retcode` in place.
    ReadKey = 16,
    /// Stream bytes into an open key. Wire payload: raw page-aligned
    /// [`PddbBuf`]; server reads `data[..len]` and writes `retcode`
    /// back in place. Upstream handler runs a full basis sync after
    /// every successful write (see `main.rs:2293-2294`), so this
    /// opcode pays one disk sync per IPC.
    WriteKey = 17,
    /// Force a basis sync. Blocking-scalar; server returns
    /// `Scalar1(retcode)` where 1 = `Ok`. Mostly redundant for our
    /// use because [`Opcode::WriteKey`] already syncs server-side;
    /// retained for the `std::io::Write::flush` shim.
    WriteKeyFlush = 18,
    /// Release a key token (the inverse of [`Opcode::KeyRequest`]).
    /// Blocking-scalar with the three token words. Best-effort:
    /// missing this opcode triggers server-side token aging, not a
    /// resource leak.
    KeyDrop = 20,
    /// Drain dictionary listing, multi-call. Wire payload:
    /// [`PddbKeyList`]; server packs `data` with `(u8 length, [u8]
    /// name)` records and sets `end = true` on the last page.
    ListKeyV2 = 45,
    /// Bulk write of `(dict, key, value)` triples in a single IPC,
    /// followed by ONE basis sync at the end.
    ///
    /// Trades per-entry granularity for amortized sync cost: N
    /// writes pay one trailing sync instead of N per-write syncs.
    /// Wire payload: [`PddbWriteBatch`] with `data` packed per the
    /// format documented on that type.
    ///
    /// Server side added in xous-core commit `8f3894f2d`, which
    /// lives on `tunnell/xous-core` branch
    /// `iter2-selective-dict-sync` — NOT on any deploy branch, so
    /// callers must probe for the opcode and keep a per-entry
    /// fallback. The opcode number must match that commit exactly —
    /// see `services/pddb/src/api.rs`.
    WriteKeyBatch = 57,
}

/// Mount-poller opcodes.
///
/// Registered against a separate SID ([`SERVER_NAME_PDDB_POLLER`])
/// from the main PDDB server: replies are fast scalars that don't
/// queue behind long-running key operations.
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum PollOp {
    /// Non-blocking mount-state probe. Replies `Scalar1(1)` if
    /// mounted, `Scalar1(0)` otherwise. Cheaper than
    /// [`Opcode::IsMounted`] on the main server.
    Poll = 0,
}

/// Per-request return code carried inside the rkyv'd request structs.
///
/// The server writes one of these into the response after handling.
/// Variants 0-3 (`Create`/`Open`/`Close`/`Delete`) are upstream
/// request-flavor markers used by other call paths; we do not emit
/// them and treat any of them in a reply as an internal error.
///
/// # Wire format
///
/// rkyv-archived as part of the parent struct. Discriminant numbers
/// are load-bearing and match upstream exactly.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone)]
pub enum PddbRequestCode {
    /// Request flavor: create. Sent by upstream call paths; not
    /// emitted by this crate.
    Create = 0,
    /// Request flavor: open. Sent by upstream call paths; not
    /// emitted by this crate.
    Open = 1,
    /// Request flavor: close. Sent by upstream call paths; not
    /// emitted by this crate.
    Close = 2,
    /// Request flavor: delete. Sent by upstream call paths; not
    /// emitted by this crate.
    Delete = 3,
    /// Success.
    NoErr = 4,
    /// PDDB has not been mounted. Caller should `try_mount` or wait.
    NotMounted = 5,
    /// Basis is full; no room for the requested data.
    NoFreeSpace = 6,
    /// The named dictionary or key does not exist.
    NotFound = 7,
    /// Server hit an unexpected state. Treat as fatal for the request.
    InternalError = 8,
    /// Caller does not have access to the named basis or key.
    AccessDenied = 9,
    /// Sentinel for uninitialized reply fields. A reply with this
    /// code indicates the server returned without writing a code —
    /// treat as `InternalError`.
    Uninit = 10,
    /// `KeyRequest` with `create_*` flags found an existing entry
    /// when only creation was requested.
    DuplicateEntry = 11,
    /// Bulk-read transport marker; unused on our call paths.
    BulkRead = 12,
}

/// Per-buffer return code on the streaming and bulk-write paths.
///
/// Discriminant `0 = Uninit` is the sentinel: callers initialize the
/// reply field to `Uninit` before lending the buffer so that a
/// server crash mid-handler is detectable. `1 = Ok` is the only
/// success value.
///
/// # Wire format
///
/// rkyv-archived for [`PddbKeyList`] / [`PddbWriteBatch`]; raw
/// `u8`-discriminant for the C-repr [`PddbBuf`].
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PddbRetcode {
    /// Sentinel — reply field was never written. Treat as internal
    /// error.
    Uninit = 0,
    /// Success.
    Ok = 1,
    /// The basis backing this key has been unmounted or the key was
    /// deleted between handle open and operation. Treat as
    /// `BrokenPipe`.
    BasisLost = 2,
    /// Caller lacks access to the basis.
    AccessDenied = 3,
    /// Server reached end-of-data before satisfying the requested
    /// length. On reads, mapped to `read = 0` (EOF); on writes,
    /// indicates an internal error.
    UnexpectedEof = 4,
    /// Server-side unexpected state.
    InternalError = 5,
    /// Basis is full.
    DiskFull = 6,
}

bitfield! {
    /// Per-key flag word inside a `PddbKeyAttrIpc` response.
    ///
    /// Defined for wire-schema completeness even though this crate
    /// does not currently round-trip `KeyAttributes` responses. The
    /// `bitfield!` macro generates getters and setters for the named
    /// bits; everything else in the `u32` is reserved.
    #[derive(Copy, Clone, PartialEq, Eq)]
    pub struct KeyFlags(u32);
    impl Debug;
    /// Bit 0: key entry is valid (initialized, not pending free).
    pub valid, set_valid: 0;
    /// Bit 1: key location is unresolved (server has not yet bound
    /// the key to a specific basis page).
    pub unresolved, set_unresolved: 1;
}

/// rkyv payload for [`Opcode::KeyRequest`], [`Opcode::DeleteKey`],
/// [`Opcode::DeleteDict`].
///
/// Caller fills the input fields, sets `result = PddbRequestCode::Uninit`,
/// lends the page; the server reads the inputs and overwrites
/// `token` and `result` on return.
///
/// # Wire format
///
/// rkyv 0.8 archived. Field order is load-bearing for archive
/// compatibility; see module-level `# Wire format` note. The fields
/// `cb_sid` and `alloc_hint` are passed through unchanged from the
/// upstream schema even though this crate never sets them to
/// non-`None`; preserving them keeps the rkyv `Archive` layout
/// identical so we round-trip cleanly.
///
/// # Security
///
/// `basis`, `dict`, `key` are caller-controlled bytes that cross
/// into the server's address space. The server independently
/// validates names against [`DICT_NAME_LEN`] / [`KEY_NAME_LEN`];
/// [`crate::client::PddbClient`] pre-validates to fail fast and
/// avoid an unnecessary IPC. None of these strings is secret-bearing
/// (they are stable identifiers, e.g. `"signal-sessions"`).
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct PddbKeyRequest {
    /// If `true`, the server constrains the operation to `basis`;
    /// if `false`, the server uses union-of-bases semantics.
    pub basis_specified: bool,
    /// Basis name (only consulted when `basis_specified` is true).
    pub basis: String,
    /// Dictionary name. Must be `<= DICT_NAME_LEN - 1` bytes.
    pub dict: String,
    /// Key name. Must be `<= KEY_NAME_LEN - 1` bytes. May be empty
    /// for [`Opcode::DeleteDict`].
    pub key: String,
    /// Server-issued handle. Caller sets to `None`; server writes
    /// `Some(token)` on [`Opcode::KeyRequest`] success.
    pub token: Option<ApiToken>,
    /// Auto-create the dictionary if missing (only meaningful for
    /// [`Opcode::KeyRequest`]).
    pub create_dict: bool,
    /// Auto-create the key if missing (only meaningful for
    /// [`Opcode::KeyRequest`]).
    pub create_key: bool,
    /// Initial allocation hint for `create_key` paths. Reduces
    /// re-allocations on append-heavy workloads.
    pub alloc_hint: Option<u64>,
    /// Optional callback SID for change notifications. Wire-only;
    /// this crate never sets it.
    pub cb_sid: Option<[u32; 4]>,
    /// Server-written result. Must be initialized to
    /// [`PddbRequestCode::Uninit`] by the caller.
    pub result: PddbRequestCode,
}

/// rkyv payload for [`Opcode::KeyCountInDict`] (and other
/// dict-shaped operations upstream).
///
/// Caller fills `dict`, `token`, sets `code = Uninit`; server reads
/// `dict`, writes `code`, `key_count`, `found_key_count`. The
/// `token` field disambiguates concurrent dictionary listings (a
/// stateful operation on the server side — see [`PddbKeyList`]).
///
/// # Wire format
///
/// rkyv 0.8 archived. Note the four-`u32` token here (versus the
/// three-`u32` [`ApiToken`] used for open key handles) — these are
/// distinct identifiers.
///
/// # Security
///
/// Same trust posture as [`PddbKeyRequest`]: name fields are
/// caller-controlled and validated server-side.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone)]
pub struct PddbDictRequest {
    /// Restrict to the named basis when `true`.
    pub basis_specified: bool,
    /// Basis name (consulted only when `basis_specified`).
    pub basis: String,
    /// Dictionary name.
    pub dict: String,
    /// Key name (used by per-key sub-operations; unused for
    /// `KeyCountInDict`).
    pub key: String,
    /// Index into a paged listing; unused on our call paths.
    pub index: u32,
    /// Listing token. The caller seeds this with a unique value so
    /// the server can disambiguate concurrent `ListKeyV2` drains;
    /// see [`crate::client::PddbClient::list_keys`].
    pub token: [u32; 4],
    /// Server-written result code.
    pub code: PddbRequestCode,
    /// Server-side cap on bulk-read payload size; unused here.
    pub bulk_limit: Option<usize>,
    /// Server-written: total keys in the dictionary.
    pub key_count: u32,
    /// Server-written: keys visible in the requested basis union.
    pub found_key_count: u32,
}

/// Capacity (in bytes) of the [`PddbKeyList::data`] packed-name buffer.
///
/// Chosen by upstream to leave room for the surrounding `token`,
/// `retcode`, `end` fields inside a single 4 KiB page.
pub const MAX_PDDBKLISTLEN: usize = 4064;

/// rkyv payload for [`Opcode::ListKeyV2`].
///
/// Multi-call protocol: the caller initializes `token` from a prior
/// [`Opcode::KeyCountInDict`] response, lends the buffer, drains
/// names from `data`, and repeats until the server sets `end = true`.
///
/// # Wire format
///
/// `data` carries a sequence of `(u8 length, [u8] name)` records,
/// terminated by a single 0-length record (a leading zero byte). The
/// server fills as many names as fit, sets `end` on the last page.
/// Parsing logic lives in [`crate::client::PddbClient::list_keys`];
/// it rejects records whose length would overrun the buffer.
///
/// # Security
///
/// Names returned by the server cross the trust boundary. The
/// parser bounds every `data[idx..idx+len]` slice against
/// [`MAX_PDDBKLISTLEN`] and validates UTF-8 before pushing to the
/// caller's `Vec<String>`; a malformed buffer surfaces as
/// `ErrorKind::Internal`, never as a panic.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct PddbKeyList {
    /// Listing token from the prior `KeyCountInDict` reply.
    pub token: [u32; 4],
    /// Packed `(len, name)` records, 0-terminated.
    pub data: [u8; MAX_PDDBKLISTLEN],
    /// Server-written result code.
    pub retcode: PddbRetcode,
    /// `true` when this is the final page of the listing.
    pub end: bool,
}

/// Capacity (in bytes) of the [`PddbWriteBatch::data`] packed-entry
/// buffer.
///
/// Caller-side packing logic in
/// [`crate::client::PddbClient::write_batch`] refuses any entry that
/// would push the cumulative packed size past this cap, with a
/// trailing-byte safety margin for the terminator. Exceeding the
/// cap on the wire would silently drop entries server-side.
///
/// # Consumer convention
///
/// `presage-store-pddb`'s `BufferingBackend::commit_internal` is the
/// primary caller of [`crate::client::PddbClient::write_batch`]. When
/// a buffered batch packs above this cap, the inner `write_batch`
/// returns `ErrorKind::InvalidInput` and the buffering layer falls
/// back to per-entry `put` (one `Opcode::WriteKey` IPC + one basis
/// sync per entry). Typical Signal session-send batches stay well
/// under the cap; multi-recipient group sends are the workload most
/// likely to trip it. Splitting an oversized buffered batch into
/// multiple `write_batch` calls of size <= cap would preserve the
/// one-sync-per-batch saving when N > 1.
pub const MAX_PDDB_WRITE_BATCH_LEN: usize = 3800;

/// rkyv payload for [`Opcode::WriteKeyBatch`].
///
/// Carries N `(dict, key, value)` triples in one IPC, packed into
/// `data`. Server applies each entry with `truncate = true` and
/// runs **one** trailing basis sync — N writes pay one sync instead
/// of N.
///
/// # Wire format
///
/// `data` is laid out as a sequence of entries followed by a
/// terminator. Each entry is:
///
/// ```text
///   u8 dict_len, dict bytes (UTF-8)
///   u8 key_len,  key bytes (UTF-8)
///   u16 value_len (little-endian), value bytes
/// ```
///
/// Terminator: a single byte of value 0 (a 0-length dict name).
/// Empty dict names are otherwise illegal in PDDB so the discriminant
/// is unambiguous.
///
/// Caller-side length caps (enforced before the IPC fires):
/// `dict.len() <= DICT_NAME_LEN - 1`, `key.len() <= KEY_NAME_LEN - 1`,
/// `value.len() <= u16::MAX`, and the cumulative packed size must fit
/// in [`MAX_PDDB_WRITE_BATCH_LEN`].
///
/// # Security
///
/// `data` may carry secret bytes (libsignal session bytes, message
/// ciphertext); the buffer is page-lent to the server and dropped
/// after the IPC returns. Drop of the surrounding `Buffer` releases
/// the page without explicit zeroization. This is unchanged from the
/// streaming-write path through [`PddbBuf`].
///
/// Not atomic across entries: if the server fails entry N, entries
/// 0..N have already been applied. The trailing sync still runs.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct PddbWriteBatch {
    /// Restrict to the named basis when `true`.
    pub basis_specified: bool,
    /// Basis name (consulted only when `basis_specified`).
    pub basis: String,
    /// Packed `(dict, key, value)` entries, 0-terminated.
    pub data: [u8; MAX_PDDB_WRITE_BATCH_LEN],
    /// Server-written result code.
    pub retcode: PddbRetcode,
}

/// Capacity (in bytes) of the [`PddbBuf::data`] payload region.
///
/// The 24-byte header (token + retcode + reserved + len + position)
/// plus this constant exactly fills a 4096-byte page; a const-eval
/// assertion at the bottom of this module enforces the equation.
pub const PDDB_BUF_DATA_LEN: usize = 4072;

/// Page-aligned streaming buffer for [`Opcode::ReadKey`] and
/// [`Opcode::WriteKey`].
///
/// `#[repr(C, align(4096))]` because the server reads this as a raw
/// page, not as an rkyv-serialized payload: `xous_ipc::Buffer::lend_mut`
/// page-lends the underlying allocation directly into the server's
/// address space. The C layout and 4 KiB alignment are part of the
/// wire contract — changing either silently corrupts every transfer.
///
/// # Wire format
///
/// One page laid out as:
///
/// ```text
///   offset  size  field
///   0       12    token: [u32; 3]   ApiToken
///   12      1     retcode           PddbRetcode (u8 discriminant)
///   13      1     reserved          padding
///   14      2     len: u16          payload length in `data`
///   16      8     position: u64     byte offset within the key
///   24      4072  data              payload bytes
/// ```
///
/// On read, the caller writes `token`, `position`, `len = max bytes
/// to read`, and `retcode = Uninit`; the server overwrites `len`
/// (actual bytes returned), `retcode`, and `data[..len]`. On write,
/// the caller additionally writes `data[..len]`; the server reads
/// it, writes `retcode`, and may reduce `len` to indicate partial
/// progress.
///
/// # Security
///
/// `data` may carry secret bytes — the entire key value on read,
/// caller-supplied bytes on write. The buffer is allocated by
/// `xous_ipc::Buffer::new(4096)` inside [`crate::client::KeyHandle`]
/// and reused across reads/writes; on Drop, the backing page is
/// returned to the kernel without explicit zeroization.
///
/// No constant-time guarantee is required: the bytes here are
/// either (a) already-MAC'd / already-encrypted ciphertext from
/// libsignal that has cleared its constant-time guards, or
/// (b) opaque KV record bytes whose timing is uninteresting.
#[repr(C, align(4096))]
pub struct PddbBuf {
    /// Open-key handle from a prior [`Opcode::KeyRequest`] reply.
    pub token: ApiToken,
    /// Server-written outcome.
    pub retcode: PddbRetcode,
    /// Padding — load-bearing for the 4096-byte total size.
    pub reserved: u8,
    /// On request: caller's requested length (`<= PDDB_BUF_DATA_LEN`).
    /// On reply: actual bytes transferred (`<= request len`).
    pub len: u16,
    /// Byte offset within the key. Server uses this to position the
    /// read/write inside an open key; caller advances it between
    /// IPCs to chain through a multi-page transfer.
    pub position: u64,
    /// Payload bytes. Caller writes on the way out (for `WriteKey`);
    /// server writes on the way back (for `ReadKey`).
    pub data: [u8; PDDB_BUF_DATA_LEN],
}

impl PddbBuf {
    /// Re-interpret a page-aligned byte slice as a `&mut PddbBuf`.
    ///
    /// The slice's *pointer* is the only thing consulted; its length
    /// is ignored. `xous_ipc::Buffer::as_mut` returns `[..self.used]`,
    /// which is 0 immediately after `Buffer::new(4096)` even though
    /// the underlying allocation is one full 4 KiB page. Mirrors
    /// upstream `services/pddb/src/api.rs::PddbBuf::from_slice_mut`.
    ///
    /// # Invariants
    ///
    /// The caller must guarantee that `s.as_mut_ptr()` points to a
    /// page-aligned allocation of at least
    /// `core::mem::size_of::<PddbBuf>() = 4096` bytes. The only safe
    /// source within this crate is `xous_ipc::Buffer::new(4096)` (or
    /// larger).
    pub fn from_slice_mut(s: &mut [u8]) -> &mut Self {
        // SAFETY: `xous_ipc::Buffer::new(4096)` always returns a
        // page-aligned allocation of at least 4096 bytes; `Buffer::as_mut`
        // exposes that page's backing memory. The cast preserves
        // provenance and produces a single `&mut PddbBuf` whose
        // lifetime is bounded by the input slice — no aliasing.
        // Upstream PDDB uses the same pointer-only cast on the same
        // input source.
        unsafe { &mut *(s.as_mut_ptr() as *mut Self) }
    }
}

/// Compile-time assertion: [`PddbBuf`] must be exactly one page.
///
/// Load-bearing: if a future field addition changes the size, the
/// raw-page IPC silently misaligns and the server reads garbage
/// (`retcode` and `len` end up in the payload area). The const eval
/// fires before any wire-incompatible build can complete.
const _ASSERT_PDDB_BUF_SIZE: () = {
    if core::mem::size_of::<PddbBuf>() != 4096 {
        panic!("PddbBuf must be exactly one 4096-byte page");
    }
};

// ---- Error type ------------------------------------------------------

/// Crate-wide error type.
///
/// Carries a coarse [`ErrorKind`] for programmatic dispatch and a
/// `String` `msg` for diagnostics. The string is intended for log
/// output, not for parsing; it interpolates upstream error variants
/// via `Debug` so a future PDDB-server version change appears in
/// logs without code changes here.
///
/// # Security
///
/// `msg` may carry context (dictionary name, opcode name) but
/// should not carry value bytes. Callers logging the `Display`
/// representation will not leak the key payload through this path
/// because [`crate::client::KeyHandle`] never plumbs value bytes
/// into `Error::new` — `msg` strings are static or contain only
/// opcode/kind metadata.
#[derive(Debug, Clone)]
pub struct Error {
    /// Coarse-grained category. Stable across error sources.
    pub kind: ErrorKind,
    /// Diagnostic message. Stable shape but not API-stable text.
    pub msg: String,
}

impl Error {
    /// Construct an error from a kind and a message. `msg` accepts
    /// anything implementing `Into<String>` so call sites can pass
    /// static `&str` or formatted `String` interchangeably.
    pub fn new(kind: ErrorKind, msg: impl Into<String>) -> Self { Self { kind, msg: msg.into() } }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.msg)
    }
}

impl std::error::Error for Error {}

/// Coarse-grained outcome categories.
///
/// Mirrors the subset of `std::io::ErrorKind` cases that map
/// usefully onto PDDB outcomes, plus PDDB-specific kinds
/// ([`ErrorKind::NotMounted`], [`ErrorKind::Ipc`]). Callers are
/// expected to switch on this enum, not on the `msg` string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// PDDB is not mounted — the database is locked or the user
    /// has not entered the password. Recovery: call
    /// [`crate::client::PddbClient::try_mount`] or wait and retry.
    NotMounted,
    /// The requested dictionary or key does not exist. On bulk
    /// listing paths, indicates the dict itself is absent (an
    /// empty dict returns `Ok(vec![])`).
    NotFound,
    /// Caller lacks access to the basis or key.
    AccessDenied,
    /// Client-side validation failed (name too long, batch
    /// payload too large, empty dict in a batch entry). No IPC
    /// was issued.
    InvalidInput,
    /// Basis is full.
    NoFreeSpace,
    /// Unexpected server state, malformed reply, or sentinel
    /// `Uninit` retcode. Treat as fatal for the request.
    Internal,
    /// Transport-level failure: name lookup, connection, or
    /// `Buffer` round-trip rejected by the kernel. Often
    /// terminal — connection may have been torn down.
    Ipc,
}
