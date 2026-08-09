//! High-level client over PDDB's IPC surface.
//!
//! Exposes a [`PddbClient`] that owns the long-lived connections to
//! the main PDDB server and its mount poller, plus the streaming
//! [`KeyHandle`] type returned by [`PddbClient::open`]. The
//! per-operation entry points mirror the upstream `services/pddb`
//! client shape so that, if the dependency cascade is ever resolved,
//! swapping in `pddb::Pddb` becomes a one-line change.
//!
//! # Trust boundary
//!
//! Every method on [`PddbClient`] crosses a kernel-mediated IPC
//! into a separate process. We trust the kernel to route only to
//! the named server SID and to copy / page-lend payloads safely.
//! We do not trust returned payload bytes beyond what the
//! variant discriminants in [`crate::api::PddbRequestCode`] /
//! [`crate::api::PddbRetcode`] declare; every parser in this module
//! bounds-checks lengths before indexing.
//!
//! # rv32 / 16 MiB constraint
//!
//! Each `MutableLend` round-trip requires a page-aligned 4 KiB
//! `xous_ipc::Buffer`. The streaming path on [`KeyHandle`] reuses
//! one such buffer across all reads and writes (allocated once at
//! `open` time). The bulk-write path allocates a fresh page per
//! [`PddbClient::write_batch`] call (4 KiB).
//!
//! Per-operation IPC costs:
//!
//! - `open`: 1 round-trip.
//! - `delete_key`, `delete_dict`: 1 round-trip each.
//! - `list_keys`: 1 + N round-trips (`KeyCountInDict` plus enough `ListKeyV2` calls to drain the dict's
//!   names, at ~4 KiB of packed names per page).
//! - `write_batch`: 1 round-trip for N entries totalling up to [`crate::api::MAX_PDDB_WRITE_BATCH_LEN`] =
//!   3800 packed bytes.
//! - `KeyHandle::read` / `KeyHandle::write`: 1 round-trip per up-to-4072-byte chunk.
//! - `KeyHandle::flush_writes`, `Drop` (via `KeyDrop`): 1 blocking-scalar round-trip.
//!
//! Each `WriteKey` round-trip pays a full multi-basis sync on the
//! server side (upstream `main.rs:2293-2294`); the bulk-write path
//! pays one sync per **batch**. The two costs differ by orders of
//! magnitude for N > 1; prefer [`PddbClient::write_batch`] on
//! latency-sensitive write hot paths.

use std::io::{self, Read, Write};

use num_traits::ToPrimitive;
use xous::{CID, Message, send_message};
use xous_ipc::Buffer;

use crate::api::{
    ApiToken, DICT_NAME_LEN, Error, ErrorKind, KEY_NAME_LEN, MAX_PDDB_WRITE_BATCH_LEN, MAX_PDDBKLISTLEN,
    Opcode, PDDB_BUF_DATA_LEN, PddbBuf, PddbDictRequest, PddbKeyList, PddbKeyRequest, PddbRequestCode,
    PddbRetcode, PddbWriteBatch, SERVER_NAME_PDDB, SERVER_NAME_PDDB_POLLER,
};

/// PDDB IPC client.
///
/// Owns two long-lived `CID`s — one to the main PDDB server (for
/// KV operations) and one to the mount poller (for cheap
/// mount-state checks). Both connections are released by `Drop`.
///
/// # Invariants
///
/// - `main_conn` is connected to the SID registered as [`crate::api::SERVER_NAME_PDDB`].
/// - `poller_conn` is connected to [`crate::api::SERVER_NAME_PDDB_POLLER`].
/// - Both are held for the lifetime of the value; this crate makes no attempt to reconnect after a transport
///   error.
///
/// # Security
///
/// The connections themselves are non-secret. Method-level docs
/// describe the per-operation trust handling.
#[derive(Debug)]
pub struct PddbClient {
    main_conn: CID,
    poller_conn: CID,
}

impl PddbClient {
    /// Look up the two PDDB SIDs by name and open long-lived
    /// connections to each.
    ///
    /// Uses `xous-api-names` to resolve [`crate::api::SERVER_NAME_PDDB`]
    /// and [`crate::api::SERVER_NAME_PDDB_POLLER`] to their CIDs.
    /// Both calls block until the named server is registered with
    /// xous-names, which means: if PDDB has not started this will
    /// block, not error.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Ipc`] if `XousNames::new` fails or
    /// either connection request returns a kernel error (e.g. the
    /// server has been unregistered).
    pub fn new() -> Result<Self, Error> {
        let xns = xous_names::XousNames::new()
            .map_err(|e| Error::new(ErrorKind::Ipc, format!("XousNames::new failed: {:?}", e)))?;
        let main_conn = xns
            .request_connection_blocking(SERVER_NAME_PDDB)
            .map_err(|e| Error::new(ErrorKind::Ipc, format!("connect to PDDB main server: {:?}", e)))?;
        let poller_conn = xns
            .request_connection_blocking(SERVER_NAME_PDDB_POLLER)
            .map_err(|e| Error::new(ErrorKind::Ipc, format!("connect to PDDB mount poller: {:?}", e)))?;
        Ok(Self { main_conn, poller_conn })
    }

    /// Non-blocking mount-state check via the poller server.
    ///
    /// Sends a single blocking-scalar opcode (`PollOp::Poll = 0`)
    /// over the poller connection. Returns `true` if mounted,
    /// `false` if not mounted or if the IPC itself failed — the
    /// distinction is not surfaced because callers treat
    /// not-mounted and unreachable identically (both are "do not
    /// try to read/write yet"). Mirrors
    /// `services/pddb/src/lib.rs::is_mounted_nonblocking`.
    ///
    /// `presage_store_pddb::PddbBackend::connect` deliberately does
    /// not block on mount; the readiness poll happens in the worker
    /// (`xous_signal_worker::worker_main`'s `load_registered` retry
    /// loop). This method's fast non-blocking contract is what makes
    /// that deferred-readiness pattern workable.
    ///
    /// # rv32 / 16 MiB constraint
    ///
    /// Single round-trip; no buffer allocation. Cheap enough to
    /// call from a UI redraw path.
    pub fn is_mounted(&self) -> bool {
        match send_message(self.poller_conn, Message::new_blocking_scalar(0, 0, 0, 0, 0)) {
            Ok(xous::Result::Scalar1(v)) => v != 0,
            _ => false,
        }
    }

    /// Trigger an interactive PDDB mount.
    ///
    /// Pops the GAM password modal, waits for the user to enter the
    /// password, then mounts. Blocks until either path completes:
    /// success returns `Ok(true)`; a server-side failure (wrong
    /// password, user abort, malformed basis) returns `Ok(false)`.
    ///
    /// Server returns `Scalar2(retcode, failcount)`, where
    /// `retcode == 0` is success. Older firmware may return
    /// `Scalar1(retcode)` — both shapes are handled.
    ///
    /// # Trust boundary
    ///
    /// The password input itself never crosses this process: the
    /// PDDB server reads it directly from GAM via its own IPC. We
    /// only signal "begin the interactive flow" and observe a
    /// boolean outcome.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Ipc`] if the server returns an
    /// unexpected message shape (neither `Scalar1` nor `Scalar2`).
    pub fn try_mount(&self) -> Result<bool, Error> {
        let resp = send_message(
            self.main_conn,
            Message::new_blocking_scalar(Opcode::TryMount.to_usize().unwrap(), 0, 0, 0, 0),
        )
        .map_err(|e| Error::new(ErrorKind::Ipc, format!("TryMount: {:?}", e)))?;
        match resp {
            xous::Result::Scalar2(retcode, _) => Ok(retcode == 0),
            xous::Result::Scalar1(retcode) => Ok(retcode == 0),
            other => Err(Error::new(ErrorKind::Ipc, format!("TryMount: {:?}", other))),
        }
    }

    /// Open (and optionally create) a `(dict, key)` pair.
    ///
    /// Returns a streaming [`KeyHandle`] whose `Read` / `Write`
    /// impls round-trip [`crate::api::PddbBuf`] pages. The handle
    /// holds an [`crate::api::ApiToken`] for the lifetime of the
    /// returned value; `Drop` issues an [`crate::api::Opcode::KeyDrop`].
    ///
    /// # rv32 / 16 MiB constraint
    ///
    /// Allocates one page-aligned 4 KiB `xous_ipc::Buffer` per
    /// returned handle; this buffer is reused across every `read`
    /// and `write` on the handle. Open itself is one IPC round-trip.
    ///
    /// # Errors
    ///
    /// - [`ErrorKind::InvalidInput`] if `dict.len() > DICT_NAME_LEN - 1` or `key.len() > KEY_NAME_LEN - 1`
    ///   (validated client-side; no IPC is issued).
    /// - [`ErrorKind::NotFound`] if either the dict or key doesn't exist and `opts.create_*` does not
    ///   authorize creation.
    /// - [`ErrorKind::AccessDenied`], [`ErrorKind::NotMounted`], [`ErrorKind::NoFreeSpace`] for the obvious
    ///   server-side conditions.
    /// - [`ErrorKind::Internal`] if the server returns success but does not stamp a token (should not happen
    ///   against the upstream PDDB).
    /// - [`ErrorKind::Ipc`] for transport failures.
    ///
    /// # Security
    ///
    /// `dict` and `key` are caller-controlled name strings that
    /// cross into the server's address space; they are stable
    /// identifiers (e.g. `"signal-sessions"`) and not secret-bearing.
    /// No value bytes are sent on this opcode — the handle is the
    /// vehicle for value bytes on subsequent `Read`/`Write`.
    pub fn open(&self, dict: &str, key: &str, opts: OpenOptions) -> Result<KeyHandle<'_>, Error> {
        if dict.len() > DICT_NAME_LEN - 1 {
            return Err(Error::new(ErrorKind::InvalidInput, "dictionary name too long"));
        }
        if key.len() > KEY_NAME_LEN - 1 {
            return Err(Error::new(ErrorKind::InvalidInput, "key name too long"));
        }

        let request = PddbKeyRequest {
            basis_specified: false,
            basis: String::new(),
            dict: dict.to_string(),
            key: key.to_string(),
            token: None,
            create_dict: opts.create_dict,
            create_key: opts.create_key,
            alloc_hint: opts.alloc_hint.map(|h| h as u64),
            cb_sid: None,
            result: PddbRequestCode::Uninit,
        };
        let mut buf =
            Buffer::into_buf(request).map_err(|_| Error::new(ErrorKind::Ipc, "Buffer::into_buf"))?;
        buf.lend_mut(self.main_conn, Opcode::KeyRequest.to_u32().unwrap())
            .map_err(|_| Error::new(ErrorKind::Ipc, "lend_mut KeyRequest"))?;
        let response: PddbKeyRequest = buf
            .to_original::<PddbKeyRequest, _>()
            .map_err(|_| Error::new(ErrorKind::Ipc, "to_original KeyRequest"))?;

        match response.result {
            PddbRequestCode::NoErr => {
                let token = response
                    .token
                    .ok_or_else(|| Error::new(ErrorKind::Internal, "server returned no token"))?;
                Ok(KeyHandle {
                    conn: self.main_conn,
                    token,
                    pos: 0,
                    buf: Buffer::new(core::mem::size_of::<PddbBuf>()),
                })
            }
            PddbRequestCode::AccessDenied => {
                Err(Error::new(ErrorKind::AccessDenied, "dict/key access denied"))
            }
            PddbRequestCode::NotMounted => Err(Error::new(ErrorKind::NotMounted, "PDDB not mounted")),
            PddbRequestCode::NoFreeSpace => Err(Error::new(ErrorKind::NoFreeSpace, "out of space")),
            PddbRequestCode::NotFound => Err(Error::new(ErrorKind::NotFound, "dict/key not found")),
            other => Err(Error::new(ErrorKind::Internal, format!("KeyRequest: {:?}", other))),
        }
    }

    /// Delete a single key from a dictionary.
    ///
    /// Wraps [`crate::api::Opcode::DeleteKey`]. Server-side handler
    /// rkyv-deserializes a [`crate::api::PddbKeyRequest`] (not
    /// `PddbDictRequest`); the choice of payload type is the
    /// load-bearing detail that makes the server accept the request.
    /// See upstream `services/pddb/src/main.rs::Opcode::DeleteKey`
    /// for the handler and `services/pddb/src/lib.rs::delete_key`
    /// for the equivalent client.
    ///
    /// # Errors
    ///
    /// - [`ErrorKind::NotFound`] if the dict or key is absent.
    /// - [`ErrorKind::NotMounted`] if PDDB is locked.
    /// - [`ErrorKind::Ipc`] for transport failures.
    /// - [`ErrorKind::Internal`] for any other server reply.
    pub fn delete_key(&self, dict: &str, key: &str) -> Result<(), Error> {
        let request = PddbKeyRequest {
            basis_specified: false,
            basis: String::new(),
            dict: dict.to_string(),
            key: key.to_string(),
            token: None,
            create_dict: false,
            create_key: false,
            alloc_hint: None,
            cb_sid: None,
            result: PddbRequestCode::Uninit,
        };
        let mut buf =
            Buffer::into_buf(request).map_err(|_| Error::new(ErrorKind::Ipc, "Buffer::into_buf"))?;
        buf.lend_mut(self.main_conn, Opcode::DeleteKey.to_u32().unwrap())
            .map_err(|_| Error::new(ErrorKind::Ipc, "lend_mut DeleteKey"))?;
        let response: PddbKeyRequest = buf
            .to_original::<PddbKeyRequest, _>()
            .map_err(|_| Error::new(ErrorKind::Ipc, "to_original DeleteKey"))?;
        match response.result {
            PddbRequestCode::NoErr => Ok(()),
            PddbRequestCode::NotFound => Err(Error::new(ErrorKind::NotFound, "key not found")),
            PddbRequestCode::NotMounted => Err(Error::new(ErrorKind::NotMounted, "PDDB not mounted")),
            other => Err(Error::new(ErrorKind::Internal, format!("DeleteKey: {:?}", other))),
        }
    }

    /// Delete a dictionary and every key it contains.
    ///
    /// Wraps [`crate::api::Opcode::DeleteDict`]. Server-side handler
    /// rkyv-deserializes a [`crate::api::PddbKeyRequest`] — same wire
    /// shape as `delete_key`. An earlier version of this code sent
    /// a [`crate::api::PddbDictRequest`] (a structurally similar but
    /// distinct rkyv type); the server silently deserialized garbage
    /// fields and returned nonsensical codes (e.g. `Create`).
    ///
    /// Deleting a non-existent dictionary is treated as success
    /// (`NotFound` is folded into `Ok(())`) — this matches the
    /// upstream `services/pddb/src/lib.rs::delete_dict` convention
    /// and keeps the operation idempotent.
    ///
    /// # Errors
    ///
    /// - [`ErrorKind::NotMounted`] if PDDB is locked.
    /// - [`ErrorKind::Ipc`] for transport failures.
    /// - [`ErrorKind::Internal`] for any other server reply.
    pub fn delete_dict(&self, dict: &str) -> Result<(), Error> {
        let request = PddbKeyRequest {
            basis_specified: false,
            basis: String::new(),
            dict: dict.to_string(),
            key: String::new(),
            token: None,
            create_dict: false,
            create_key: false,
            alloc_hint: None,
            cb_sid: None,
            result: PddbRequestCode::Uninit,
        };
        let mut buf =
            Buffer::into_buf(request).map_err(|_| Error::new(ErrorKind::Ipc, "Buffer::into_buf"))?;
        buf.lend_mut(self.main_conn, Opcode::DeleteDict.to_u32().unwrap())
            .map_err(|_| Error::new(ErrorKind::Ipc, "lend_mut DeleteDict"))?;
        let response: PddbKeyRequest = buf
            .to_original::<PddbKeyRequest, _>()
            .map_err(|_| Error::new(ErrorKind::Ipc, "to_original DeleteDict"))?;
        match response.result {
            PddbRequestCode::NoErr => Ok(()),
            PddbRequestCode::NotFound => Ok(()), // delete-non-existent is fine
            PddbRequestCode::NotMounted => Err(Error::new(ErrorKind::NotMounted, "PDDB not mounted")),
            other => Err(Error::new(ErrorKind::Internal, format!("DeleteDict: {:?}", other))),
        }
    }

    /// Drain a dictionary's key names into a `Vec`.
    ///
    /// Two-phase wire protocol:
    ///
    /// 1. [`crate::api::Opcode::KeyCountInDict`] establishes a fresh listing token server-side.
    /// 2. [`crate::api::Opcode::ListKeyV2`] is repeated until the server sets `end = true`; each page carries
    ///    up to [`crate::api::MAX_PDDBKLISTLEN`] = 4064 bytes of packed `(u8 length, [u8] name)` records.
    ///
    /// Returns an empty `Vec` for a present-but-empty dictionary;
    /// returns [`ErrorKind::NotFound`] if the dictionary itself does
    /// not exist (matches upstream `services/pddb/src/lib.rs::list_keys`).
    ///
    /// # rv32 / 16 MiB constraint
    ///
    /// Allocates one page-aligned 4 KiB `xous_ipc::Buffer` per
    /// `ListKeyV2` round-trip (the buffer is dropped between
    /// iterations). The returned `Vec<String>` and its inner
    /// `String`s are heap-allocated and grow unbounded with the
    /// dictionary's key count — callers paging large dicts on the
    /// hot path should be aware.
    ///
    /// # Errors
    ///
    /// - [`ErrorKind::InvalidInput`] if `dict.len() > DICT_NAME_LEN - 1`.
    /// - [`ErrorKind::NotFound`] if the dict is absent.
    /// - [`ErrorKind::NotMounted`] if PDDB is locked.
    /// - [`ErrorKind::AccessDenied`] if another listing holds the server-side lock against this dict.
    /// - [`ErrorKind::Internal`] if a `ListKeyV2` response is malformed (length-prefix overruns the buffer,
    ///   name not UTF-8).
    /// - [`ErrorKind::Ipc`] for transport failures.
    ///
    /// # Security
    ///
    /// The packed-name buffer is server-supplied and treated as
    /// untrusted: the parser bounds every `data[idx..idx+len]` slice
    /// against [`crate::api::MAX_PDDBKLISTLEN`] and validates UTF-8
    /// before pushing to the result. A malformed buffer surfaces
    /// as `ErrorKind::Internal`; the parser never panics.
    pub fn list_keys(&self, dict: &str) -> Result<Vec<String>, Error> {
        if dict.len() > DICT_NAME_LEN - 1 {
            return Err(Error::new(ErrorKind::InvalidInput, "dict name too long"));
        }

        // Phase 1: KeyCountInDict establishes a fresh listing
        // token. The token disambiguates concurrent listings —
        // PDDB's listing protocol is stateful server-side and the
        // server holds per-token cursors.
        let token = random_token_4();
        let request = PddbDictRequest {
            basis_specified: false,
            basis: String::new(),
            dict: dict.to_string(),
            key: String::new(),
            index: 0,
            token,
            code: PddbRequestCode::Uninit,
            bulk_limit: None,
            key_count: 0,
            found_key_count: 0,
        };
        let resp = self.dict_request_send(request, Opcode::KeyCountInDict)?;
        match resp.code {
            PddbRequestCode::NoErr => {}
            PddbRequestCode::NotFound => {
                return Err(Error::new(ErrorKind::NotFound, "dictionary not found"));
            }
            PddbRequestCode::NotMounted => {
                return Err(Error::new(ErrorKind::NotMounted, "PDDB not mounted"));
            }
            other => {
                return Err(Error::new(ErrorKind::Internal, format!("KeyCountInDict: {:?}", other)));
            }
        }

        // Phase 2: drain ListKeyV2 until `end` is set. Each
        // iteration pays one IPC round-trip and yields up to
        // ~4 KiB of packed names.
        let mut keys = Vec::new();
        loop {
            let req = PddbKeyList {
                token,
                end: false,
                retcode: PddbRetcode::Uninit,
                data: [0u8; MAX_PDDBKLISTLEN],
            };
            let mut buf =
                Buffer::into_buf(req).map_err(|_| Error::new(ErrorKind::Ipc, "Buffer::into_buf KeyList"))?;
            buf.lend_mut(self.main_conn, Opcode::ListKeyV2.to_u32().unwrap())
                .map_err(|_| Error::new(ErrorKind::Ipc, "lend_mut ListKeyV2"))?;
            let response: PddbKeyList = buf
                .to_original::<PddbKeyList, _>()
                .map_err(|_| Error::new(ErrorKind::Ipc, "to_original KeyList"))?;

            match response.retcode {
                PddbRetcode::Ok => {}
                PddbRetcode::AccessDenied => {
                    return Err(Error::new(ErrorKind::AccessDenied, "key list locked by another process"));
                }
                other => {
                    return Err(Error::new(ErrorKind::Internal, format!("ListKeyV2: {:?}", other)));
                }
            }

            // Packed list format: (u8 len, [u8] name) repeating,
            // with a 0-length record indicating end of buffer.
            // Every slice is bounded against MAX_PDDBKLISTLEN
            // before indexing; a malformed length-prefix surfaces
            // as Internal, not a panic.
            let mut idx = 0;
            while idx < MAX_PDDBKLISTLEN && response.data[idx] != 0 {
                let strlen = response.data[idx] as usize;
                idx += 1;
                if idx + strlen > MAX_PDDBKLISTLEN {
                    return Err(Error::new(ErrorKind::Internal, "key list overran buffer"));
                }
                let name = std::str::from_utf8(&response.data[idx..idx + strlen])
                    .map_err(|_| Error::new(ErrorKind::Internal, "key name not utf-8"))?;
                keys.push(name.to_string());
                idx += strlen;
            }

            if response.end {
                break;
            }
        }

        Ok(keys)
    }

    /// Bulk-write `(dict, key, value)` triples in a single IPC.
    ///
    /// Wraps [`crate::api::Opcode::WriteKeyBatch`]. The server
    /// applies each entry with `truncate = true` and runs **one**
    /// trailing basis sync — N writes pay one sync instead of N.
    /// For send-heavy hot paths this is the critical primitive: a
    /// single libsignal `send_message` step writes O(10) session
    /// records, which through individual [`KeyHandle::write`] would
    /// be O(10) full multi-basis syncs (upstream
    /// `main.rs:2293-2294`) and through this opcode is one. The
    /// server side is xous-core commit `8f3894f2d` on
    /// `tunnell/xous-core` branch `iter2-selective-dict-sync`; no
    /// deploy branch ships it, so the probe-plus-fallback below
    /// stays load-bearing.
    ///
    /// The upstream caller is
    /// `presage_store_pddb::PddbBackend::put_batch`, which forwards
    /// the buffered-batch contents from
    /// `presage_store_pddb::BufferingBackend::commit_internal`. The
    /// per-entry fallback semantics (per-entry `put` on a cap-overflow
    /// `InvalidInput`) live in `BufferingBackend`; see
    /// `MAX_PDDB_WRITE_BATCH_LEN` for the cap value.
    ///
    /// The `truncate = true` server semantics on this path mean the
    /// `delete_key` prelude that
    /// `presage_store_pddb::PddbBackend::put` uses to work around
    /// `Opcode::WriteKey`'s `truncate = false` (refs #14) is
    /// **unnecessary** on the batch path. Maintainers adding new
    /// single-entry write helpers should copy `put_batch`'s shape if
    /// possible.
    ///
    /// An empty `entries` slice short-circuits to `Ok(())` without
    /// an IPC.
    ///
    /// # Wire format
    ///
    /// The packed buffer layout is documented on
    /// [`crate::api::PddbWriteBatch`]. Per-entry caller-side caps
    /// (validated before any IPC fires):
    /// `dict.len() in [1, DICT_NAME_LEN - 1]`,
    /// `key.len() <= KEY_NAME_LEN - 1`, `value.len() <= u16::MAX`,
    /// and the packed total (plus 1 byte for the terminator) must
    /// fit in [`crate::api::MAX_PDDB_WRITE_BATCH_LEN`] = 3800.
    ///
    /// # rv32 / 16 MiB constraint
    ///
    /// Allocates one page-aligned 4 KiB `xous_ipc::Buffer` per
    /// call. A caller streaming O(N) entries past
    /// `MAX_PDDB_WRITE_BATCH_LEN` needs to split into multiple
    /// `write_batch` calls (each its own IPC + sync) — typical
    /// libsignal session batches fit comfortably under the cap.
    ///
    /// # Errors
    ///
    /// - [`ErrorKind::InvalidInput`] for empty dict names, dict / key names exceeding the wire caps, value
    ///   lengths exceeding `u16::MAX`, or a packed total over the cap.
    /// - [`ErrorKind::NotFound`] (basis lost), [`ErrorKind::AccessDenied`], [`ErrorKind::NoFreeSpace`] (disk
    ///   full), [`ErrorKind::Internal`] (unexpected EOF / server uninit sentinel) for server-reported
    ///   failures.
    /// - [`ErrorKind::Ipc`] for transport failures.
    ///
    /// # Security
    ///
    /// `value` bytes can be secret-bearing (libsignal session
    /// records, ciphertext envelopes). They cross the trust
    /// boundary into the PDDB server's address space inside the
    /// page-lent buffer; the buffer is allocated locally, copied
    /// into via `copy_from_slice`, and dropped when this method
    /// returns. No explicit zeroization runs on Drop today.
    ///
    /// Not atomic across entries. If entry N fails, entries `0..N`
    /// have already been applied; the trailing sync still runs, so
    /// partial state is durable. Callers cannot infer N from this
    /// method's `Err` return.
    pub fn write_batch(&self, entries: &[(&str, &str, &[u8])]) -> Result<(), Error> {
        if entries.is_empty() {
            return Ok(());
        }
        let mut request = PddbWriteBatch {
            basis_specified: false,
            basis: String::new(),
            data: [0u8; MAX_PDDB_WRITE_BATCH_LEN],
            retcode: PddbRetcode::Uninit,
        };
        let mut index = 0usize;
        for (dict, key, value) in entries {
            if dict.is_empty() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "empty dict name (collides with terminator)",
                ));
            }
            if dict.len() > DICT_NAME_LEN - 1 {
                return Err(Error::new(ErrorKind::InvalidInput, "dict name too long"));
            }
            if key.len() > KEY_NAME_LEN - 1 {
                return Err(Error::new(ErrorKind::InvalidInput, "key name too long"));
            }
            if value.len() > u16::MAX as usize {
                return Err(Error::new(ErrorKind::InvalidInput, "value too large for one entry"));
            }
            let needed = 1 + dict.len() + 1 + key.len() + 2 + value.len();
            if index + needed + 1 > MAX_PDDB_WRITE_BATCH_LEN {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "batch exceeds MAX_PDDB_WRITE_BATCH_LEN; split",
                ));
            }
            request.data[index] = dict.len() as u8;
            index += 1;
            request.data[index..index + dict.len()].copy_from_slice(dict.as_bytes());
            index += dict.len();
            request.data[index] = key.len() as u8;
            index += 1;
            request.data[index..index + key.len()].copy_from_slice(key.as_bytes());
            index += key.len();
            let vlen = (value.len() as u16).to_le_bytes();
            request.data[index] = vlen[0];
            request.data[index + 1] = vlen[1];
            index += 2;
            request.data[index..index + value.len()].copy_from_slice(value);
            index += value.len();
        }
        // Write the terminator (a 0-length dict). `data` was
        // zero-initialized so this is belt-and-suspenders, but it
        // documents intent and survives a future allocation source
        // that doesn't pre-zero.
        if index < MAX_PDDB_WRITE_BATCH_LEN {
            request.data[index] = 0;
        }

        let mut buf = Buffer::into_buf(request)
            .map_err(|_| Error::new(ErrorKind::Ipc, "Buffer::into_buf WriteKeyBatch"))?;
        buf.lend_mut(self.main_conn, Opcode::WriteKeyBatch.to_u32().unwrap())
            .map_err(|_| Error::new(ErrorKind::Ipc, "lend_mut WriteKeyBatch"))?;
        let response = buf
            .to_original::<PddbWriteBatch, _>()
            .map_err(|_| Error::new(ErrorKind::Ipc, "to_original WriteKeyBatch"))?;
        match response.retcode {
            PddbRetcode::Ok => Ok(()),
            PddbRetcode::BasisLost => Err(Error::new(ErrorKind::NotFound, "basis lost")),
            PddbRetcode::AccessDenied => Err(Error::new(ErrorKind::AccessDenied, "access denied")),
            PddbRetcode::DiskFull => Err(Error::new(ErrorKind::NoFreeSpace, "disk full")),
            PddbRetcode::UnexpectedEof => Err(Error::new(ErrorKind::Internal, "unexpected EOF")),
            PddbRetcode::InternalError => Err(Error::new(ErrorKind::Internal, "internal error")),
            PddbRetcode::Uninit => {
                Err(Error::new(ErrorKind::Internal, "server returned without setting retcode"))
            }
        }
    }

    /// Lend a [`PddbDictRequest`] to the main server and return the
    /// server-mutated reply. Helper for opcodes that share the
    /// `PddbDictRequest` wire shape — currently only
    /// [`crate::api::Opcode::KeyCountInDict`].
    fn dict_request_send(&self, request: PddbDictRequest, op: Opcode) -> Result<PddbDictRequest, Error> {
        let mut buf =
            Buffer::into_buf(request).map_err(|_| Error::new(ErrorKind::Ipc, "Buffer::into_buf"))?;
        buf.lend_mut(self.main_conn, op.to_u32().unwrap())
            .map_err(|_| Error::new(ErrorKind::Ipc, format!("lend_mut {:?}", op)))?;
        buf.to_original::<PddbDictRequest, _>()
            .map_err(|_| Error::new(ErrorKind::Ipc, "to_original DictRequest"))
    }
}

impl Drop for PddbClient {
    fn drop(&mut self) {
        // Release both kernel connections. Failure is non-fatal:
        // each connection was registered against this process and
        // the kernel reaps them via the process teardown path on
        // exit. We swallow errors here because the alternative —
        // panicking from Drop — would mask the actual shutdown cause.
        //
        // SAFETY: `xous::disconnect` is unsafe because it makes the
        // CID invalid for any concurrent users. Here, `&mut self`
        // gives exclusive access to both CIDs (no other handle can
        // call into them after Drop begins) and the function returns
        // immediately after — no later code in this Drop touches
        // either CID.
        unsafe {
            let _ = xous::disconnect(self.main_conn);
            let _ = xous::disconnect(self.poller_conn);
        }
    }
}

/// Open-time flags and hints for [`PddbClient::open`].
///
/// Mirrors the subset of upstream `services/pddb/src/lib.rs::get`
/// options that the KvBackend exercises (basis name and the
/// change-callback are intentionally omitted). `Default` constructs
/// a read-only open: both `create_*` flags off, no allocation hint.
#[derive(Default, Clone, Copy)]
pub struct OpenOptions {
    /// Auto-create the dictionary if it doesn't exist.
    pub create_dict: bool,
    /// Auto-create the key inside the dictionary if it doesn't exist.
    pub create_key: bool,
    /// Initial allocation hint (in bytes) passed through to the
    /// server. The server uses this to size the underlying key
    /// allocation, reducing reallocations on append-heavy callers.
    /// `None` defers entirely to the server's default.
    pub alloc_hint: Option<usize>,
}

impl OpenOptions {
    /// Construct options enabling both `create_dict` and
    /// `create_key`. Equivalent to `OpenOptions { create_dict: true,
    /// create_key: true, alloc_hint: None }`.
    pub fn create_all() -> Self { Self { create_dict: true, create_key: true, alloc_hint: None } }
}

/// Streaming handle to an open `(dict, key)` pair.
///
/// Returned by [`PddbClient::open`]. Implements `std::io::Read` and
/// `std::io::Write` so callers can pipe arbitrary-sized values
/// through the 4072-byte [`crate::api::PddbBuf::data`] area
/// (one round-trip per chunk).
///
/// # Invariants
///
/// - `token` is a server-issued [`crate::api::ApiToken`] valid until `Drop` issues an
///   [`crate::api::Opcode::KeyDrop`].
/// - `pos` advances by `len` after every successful `read` / `write`.
/// - `buf` is a page-aligned 4 KiB allocation reused across all reads and writes; its contents persist
///   between calls but are not visible to external callers.
///
/// # rv32 / 16 MiB constraint
///
/// One 4 KiB buffer allocated per handle, reused for every IPC.
/// Each `read` / `write` pays one IPC round-trip; large values
/// chunk at the 4072-byte ceiling. Each `write` pays a full
/// multi-basis sync server-side (upstream `main.rs:2293-2294`); see
/// [`PddbClient::write_batch`] for the amortized alternative on
/// hot paths.
///
/// # Security
///
/// `data` bytes flowing through `read` / `write` may carry secret
/// material (libsignal session bytes, message ciphertext). The
/// internal buffer is reused across calls and is not explicitly
/// zeroized between operations or on Drop; the previous payload
/// remains in the buffer's backing page until overwritten or until
/// the kernel reclaims the page.
///
/// `KeyHandle` operates on opaque PDDB record bytes; no
/// constant-time guarantee is required nor provided.
///
/// # Examples
///
/// Read an entire key into a `Vec`:
///
/// ```no_run
/// use std::io::Read;
///
/// use xous_pddb_ipc::{OpenOptions, PddbClient};
///
/// # fn try_main() -> Result<(), Box<dyn std::error::Error>> {
/// let client = PddbClient::new()?;
/// let mut handle = client.open("xas-sessions", "alice@1234", OpenOptions::default())?;
/// let mut bytes = Vec::new();
/// handle.read_to_end(&mut bytes)?;
/// # Ok(())
/// # }
/// ```
pub struct KeyHandle<'a> {
    conn: CID,
    token: ApiToken,
    pos: u64,
    buf: Buffer<'a>,
}

impl<'a> KeyHandle<'a> {
    /// Force a basis sync, blocking until the server flushes
    /// in-memory state to disk.
    ///
    /// Sends [`crate::api::Opcode::WriteKeyFlush`] as a blocking
    /// scalar carrying the three [`crate::api::ApiToken`] words.
    /// The server returns the [`crate::api::PddbRetcode`]
    /// discriminant (`Ok = 1`) as a `Scalar1`. Mirrors
    /// `services/pddb/src/lib.rs::Pddb::sync`.
    ///
    /// Largely redundant against the current upstream
    /// [`crate::api::Opcode::WriteKey`] handler, which already runs
    /// a full basis sync after every successful write (upstream
    /// `main.rs:2293-2294`). Retained for two reasons:
    ///
    /// 1. The `std::io::Write::flush` shim on this type maps onto it, so callers using standard patterns get
    ///    a working flush.
    /// 2. If a future upstream WriteKey handler drops the per-write sync, this method becomes the durability
    ///    boundary again.
    ///
    /// This call does **not** witness durability — `Ok(())` only
    /// guarantees the server reported `PddbRetcode::Ok`. A type-state
    /// commit-witness version is a possible future refinement.
    ///
    /// # Errors
    ///
    /// - [`ErrorKind::Internal`] for `BasisLost` (basis unmounted mid-flush), `InternalError`, the `Uninit`
    ///   sentinel, or an unrecognized retcode.
    /// - [`ErrorKind::NoFreeSpace`] for `DiskFull`.
    /// - [`ErrorKind::AccessDenied`] for `AccessDenied`.
    /// - [`ErrorKind::Ipc`] for kernel transport failures or an unexpected reply shape.
    pub fn flush_writes(&mut self) -> Result<(), Error> {
        let token = self.token;
        let resp = send_message(
            self.conn,
            Message::new_blocking_scalar(
                Opcode::WriteKeyFlush.to_usize().unwrap(),
                token[0] as usize,
                token[1] as usize,
                token[2] as usize,
                0,
            ),
        )
        .map_err(|e| Error::new(ErrorKind::Ipc, format!("WriteKeyFlush: {:?}", e)))?;
        let xous::Result::Scalar1(rcode) = resp else {
            return Err(Error::new(ErrorKind::Ipc, format!("WriteKeyFlush: unexpected {:?}", resp)));
        };
        match rcode {
            r if r == PddbRetcode::Ok as usize => Ok(()),
            r if r == PddbRetcode::BasisLost as usize => {
                Err(Error::new(ErrorKind::Internal, "WriteKeyFlush: BasisLost"))
            }
            r if r == PddbRetcode::DiskFull as usize => {
                Err(Error::new(ErrorKind::NoFreeSpace, "WriteKeyFlush: DiskFull"))
            }
            r if r == PddbRetcode::AccessDenied as usize => {
                Err(Error::new(ErrorKind::AccessDenied, "WriteKeyFlush: AccessDenied"))
            }
            r if r == PddbRetcode::InternalError as usize => {
                Err(Error::new(ErrorKind::Internal, "WriteKeyFlush: InternalError"))
            }
            other => {
                Err(Error::new(ErrorKind::Internal, format!("WriteKeyFlush: unknown retcode={}", other)))
            }
        }
    }
}

/// Stream-read of PDDB key bytes via [`crate::api::Opcode::ReadKey`].
///
/// Each call pays one IPC round-trip with a single 4 KiB
/// `MutableLend`. Returns 0 to signal EOF (the server's
/// `UnexpectedEof` retcode is the EOF marker — PDDB does not
/// distinguish "you asked for more than I had" from "stream is
/// over").
impl<'a> Read for KeyHandle<'a> {
    /// Read up to [`crate::api::PDDB_BUF_DATA_LEN`] = 4072 bytes
    /// from the open key into `buf`, advancing the handle's
    /// internal position.
    ///
    /// Larger callers chunk naturally because the server caps
    /// `len` at 4072 per IPC; one read = one IPC. The server's
    /// reported `len` is range-checked against the requested
    /// length and any over-report surfaces as a `BrokenPipe`
    /// (the parser never panics on attacker-controlled length).
    ///
    /// # Errors
    ///
    /// - `io::ErrorKind::Other` for IPC transport failures, malformed over-length replies, or unexpected
    ///   retcodes.
    /// - `io::ErrorKind::BrokenPipe` for `BasisLost` (basis unmounted mid-stream).
    /// - `io::ErrorKind::PermissionDenied` for `AccessDenied`.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // Prime the request fields. Note that `pbuf` is a view into
        // the same 4 KiB page that the kernel will lend to the
        // server; we drop the borrow before `lend_mut` and reacquire
        // it on return.
        let readlen = {
            let pbuf = PddbBuf::from_slice_mut(self.buf.as_mut());
            pbuf.token = self.token;
            let n = if buf.len() <= PDDB_BUF_DATA_LEN { buf.len() } else { PDDB_BUF_DATA_LEN };
            pbuf.len = n as u16;
            pbuf.retcode = PddbRetcode::Uninit;
            pbuf.position = self.pos;
            n
        };
        self.buf
            .lend_mut(self.conn, Opcode::ReadKey.to_u32().unwrap())
            .map_err(|_| io::Error::other("lend_mut ReadKey"))?;
        let pbuf = PddbBuf::from_slice_mut(self.buf.as_mut());
        match pbuf.retcode {
            PddbRetcode::Ok => {
                let got = pbuf.len as usize;
                // Trust boundary: server-reported len is bounded
                // against our requested ceiling. A larger value
                // would be a server bug; we refuse to index `pbuf.data`
                // past `readlen` either way.
                if got > readlen {
                    return Err(io::Error::other("server returned more data than requested"));
                }
                buf[..got].copy_from_slice(&pbuf.data[..got]);
                self.pos += got as u64;
                Ok(got)
            }
            // The server emits UnexpectedEof when the position has
            // reached the end of the key. std::io::Read::read returns
            // Ok(0) for EOF.
            PddbRetcode::UnexpectedEof => Ok(0),
            PddbRetcode::BasisLost => Err(io::Error::new(io::ErrorKind::BrokenPipe, "basis lost")),
            PddbRetcode::AccessDenied => {
                Err(io::Error::new(io::ErrorKind::PermissionDenied, "access denied"))
            }
            other => Err(io::Error::other(format!("ReadKey retcode {:?}", other))),
        }
    }
}

/// Stream-write of PDDB key bytes via [`crate::api::Opcode::WriteKey`].
///
/// Each call pays one IPC round-trip plus one full multi-basis sync
/// server-side (upstream `main.rs:2293-2294`). Use
/// [`PddbClient::write_batch`] when N > 1 entries are known up front.
///
/// # Truncate semantics
///
/// The upstream `Opcode::WriteKey` handler passes `truncate = false`
/// to its inner `key_update`, so a `WriteKey` against an existing key
/// that previously held more bytes leaves the trailing bytes intact
/// and subsequent reads return the new bytes concatenated with the
/// leftover tail. Callers that want overwrite semantics through this
/// surface must `delete_key` first
/// (`presage_store_pddb::PddbBackend::put` is the in-tree example;
/// refs #14 tracks the upstream fix). The
/// [`PddbClient::write_batch`] path is unaffected — the server-side
/// `Opcode::WriteKeyBatch` handler uses `truncate = true`.
impl<'a> Write for KeyHandle<'a> {
    /// Write up to [`crate::api::PDDB_BUF_DATA_LEN`] = 4072 bytes
    /// from `buf` to the open key, advancing the handle's internal
    /// position by the number of bytes the server reports
    /// accepting.
    ///
    /// Larger writes chunk naturally; a `write_all` over a 12 KiB
    /// value pays three IPCs and three full basis syncs.
    ///
    /// # Errors
    ///
    /// - `io::ErrorKind::Other` for IPC transport failures, malformed over-length acknowledgments, or
    ///   unexpected retcodes.
    /// - `io::ErrorKind::OutOfMemory` for `DiskFull`.
    /// - `io::ErrorKind::BrokenPipe` for `BasisLost`.
    /// - `io::ErrorKind::PermissionDenied` for `AccessDenied`.
    ///
    /// # Security
    ///
    /// `buf` may carry secret bytes. They are copied into the
    /// handle's reusable internal buffer via `copy_from_slice` and
    /// page-lent to the PDDB server; on return the buffer retains
    /// the bytes until overwritten or until the handle is dropped.
    /// The kernel does not zero the page on Drop.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let writelen = {
            let pbuf = PddbBuf::from_slice_mut(self.buf.as_mut());
            pbuf.token = self.token;
            let n = if buf.len() <= PDDB_BUF_DATA_LEN { buf.len() } else { PDDB_BUF_DATA_LEN };
            pbuf.data[..n].copy_from_slice(&buf[..n]);
            pbuf.len = n as u16;
            pbuf.retcode = PddbRetcode::Uninit;
            pbuf.position = self.pos;
            n
        };
        self.buf
            .lend_mut(self.conn, Opcode::WriteKey.to_u32().unwrap())
            .map_err(|_| io::Error::other("lend_mut WriteKey"))?;
        let pbuf = PddbBuf::from_slice_mut(self.buf.as_mut());
        match pbuf.retcode {
            PddbRetcode::Ok => {
                let wrote = pbuf.len as usize;
                // Server-reported wrote-count is bounded against
                // what we supplied. Any over-report is a server
                // bug; surface as Other rather than advance pos
                // into space.
                if wrote > writelen {
                    return Err(io::Error::other("server reported writing more than supplied"));
                }
                self.pos += wrote as u64;
                Ok(wrote)
            }
            PddbRetcode::DiskFull => Err(io::Error::new(io::ErrorKind::OutOfMemory, "disk full")),
            PddbRetcode::BasisLost => Err(io::Error::new(io::ErrorKind::BrokenPipe, "basis lost")),
            PddbRetcode::AccessDenied => {
                Err(io::Error::new(io::ErrorKind::PermissionDenied, "access denied"))
            }
            other => Err(io::Error::other(format!("WriteKey retcode {:?}", other))),
        }
    }

    /// Force a basis sync via [`KeyHandle::flush_writes`].
    ///
    /// PDDB's notion of "flush" is [`crate::api::Opcode::WriteKeyFlush`]
    /// (commit pending writes to disk), distinct from std::io's
    /// notion of "flush" (drain a write buffer). We map the std
    /// call to the PDDB opcode so callers using standard patterns
    /// (`std::io::copy`, `BufWriter`, etc.) get the durability
    /// guarantee they expect. Errors are stringified into
    /// `io::ErrorKind::Other`; use [`KeyHandle::flush_writes`]
    /// directly to access the typed [`ErrorKind`] discriminant.
    fn flush(&mut self) -> io::Result<()> {
        self.flush_writes().map_err(|e| io::Error::other(format!("WriteKeyFlush: {}", e)))
    }
}

impl<'a> Drop for KeyHandle<'a> {
    fn drop(&mut self) {
        // Best-effort token release via Opcode::KeyDrop. If this
        // call fails (e.g. process is tearing down and the server
        // SID is already gone) the server's own token aging path
        // reclaims the entry — no resource leak, just a slightly
        // longer-lived server-side handle.
        //
        // We intentionally do NOT zeroize `self.buf` here. The
        // backing 4 KiB page is owned by xous_ipc::Buffer and
        // released on its own Drop; the kernel does not zero
        // freed pages either. Secret bytes that flowed through
        // this handle may sit in the freed page until the
        // allocator hands it out again.
        let _ = send_message(
            self.conn,
            Message::new_blocking_scalar(
                Opcode::KeyDrop.to_usize().unwrap(),
                self.token[0] as usize,
                self.token[1] as usize,
                self.token[2] as usize,
                0,
            ),
        );
    }
}

/// Mint a 128-bit token suitable for distinguishing concurrent
/// [`crate::api::Opcode::ListKeyV2`] drains.
///
/// Returns four `u32` words from `xous::create_server_id`, which is
/// backed by the kernel's TRNG. Uses the kernel TRNG path rather
/// than a userspace PRNG because (a) xous-core's gen2 PDDB code
/// takes the same path, keeping behavior aligned, and (b) the
/// kernel call is already mediated and audited.
///
/// # Security
///
/// The token is not used for authentication — server-side it only
/// disambiguates per-listing cursors — but kernel TRNG-quality
/// random words also guarantee uniqueness within reasonable
/// concurrent-call counts, which is the property we need.
///
/// # Panics
///
/// Panics if `xous::create_server_id` returns `Err` — the kernel
/// TRNG path has no recoverable failure mode in the upstream
/// implementation and a failure here would indicate either a
/// kernel bug or the process being torn down; either way, listing
/// keys is impossible. Documented in `# Panics` rather than
/// returned because callers (`PddbClient::list_keys`) cannot
/// usefully recover and the panic surfaces with a clear backtrace
/// rather than `ErrorKind::Internal`.
fn random_token_4() -> [u32; 4] { xous::create_server_id().expect("create_server_id").to_array() }
