//! Hand-rolled PDDB IPC client for the xas Signal app.
//!
//! Replicates just enough of `xous-core/services/pddb`'s client
//! surface to back the `KvBackend` impl in `presage-store-pddb`
//! (`get` / `put` / `delete` / `delete_dict` / `list_keys`, plus
//! the bulk `WriteKeyBatch` opcode).
//!
//! # Why hand-rolled
//!
//! The `pddb` crate published by `xous-core` cascades into 10+
//! services on a path-dep build (`spinor`, `root-keys`, `llio`,
//! `tts-frontend`, `gam`, `modals`, `keystore-api`, …). For an app
//! that only needs the key-value surface, replicating the IPC
//! protocol locally is dramatically less audit surface than pulling
//! the whole stack.
//!
//! The wire structs in [`api`] are byte-compatible verbatim copies
//! from `xous-core/services/pddb/src/api.rs`. rkyv 0.8 wire
//! compatibility is what makes the verbatim approach work; if
//! xous-core moves to a newer rkyv, this crate has to track.
//!
//! # Trust boundary
//!
//! All bytes that traverse this crate are *opaque blobs from
//! presage's perspective*. The PDDB server side does the actual
//! encryption-at-rest. None of the cryptographic content the Signal
//! app stores (identity keys, session records, registration data)
//! is encrypted or decrypted in this crate; it is only marshalled
//! across the IPC boundary as length-prefixed byte slices.
//!
//! # Scope
//!
//! Deliberately limited to the operations the `KvBackend` exercises.
//! PDDB's basis-management, key-attribute, and bulk-read surfaces
//! are not exposed — adding them is straightforward by mirroring
//! `xous-core/services/pddb/src/lib.rs`.
//!
//! # Crate boundaries
//!
//! Upstream of this crate: `presage-store-pddb`'s `PddbBackend`
//! (only constructed under the `pddb-backend` feature). Below this
//! crate: `xous_api_names` (to look up the PDDB SID),
//! `xous::send_message` (the IPC primitive). No dependency on
//! presage, libsignal, or any of the Signal-protocol crates.
//!
//! This crate has no `BatchGuard`-style RAII type today; the bulk
//! IPC surface is the single [`client::PddbClient::write_batch`]
//! method, which is the atomic unit of "one IPC, one server-side
//! sync." If a future per-IPC scope grows here it should mirror the
//! abort-on-drop-by-default RAII convention `presage_store_pddb`
//! uses for its in-memory write-coalescing buffer (named there
//! `presage_store_pddb::BatchGuard` to avoid collision).

pub mod api;
pub mod client;

pub use api::{Error, ErrorKind};
pub use client::{KeyHandle, OpenOptions, PddbClient};
