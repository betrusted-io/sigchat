//! Error type for `presage-store-pddb`.
//!
//! Implements `presage::store::StoreError`. Variants cover the three
//! places a store call can fail: the underlying KV backend (PDDB or
//! the mock HashMap), serde encode/decode, and libsignal protocol
//! round-trips for the binary `IdentityKeyPair` /
//! `SenderCertificate` fields.
//!
//! # Security
//!
//! The error messages embedded in [`Error::Backend`],
//! [`Error::Encode`], and [`Error::Decode`] are stringified upstream
//! errors. The string content depends on what the backend / serde
//! layer chose to expose:
//!
//! - PDDB IPC errors carry an opaque kind plus a context string (see `backend_pddb::map_ipc_err`); they do
//!   not carry value bytes.
//! - `serde_json` errors carry position information and the expected/found field name. For dicts whose values
//!   are secret-bearing, this means a malformed value would surface a message like "invalid character at line
//!   1 column 17". The bytes themselves are not in the message — only positional metadata.
//! - `SignalProtocolError` strings come from libsignal-protocol; that crate is careful not to embed key bytes
//!   in error messages.
//!
//! Treat these strings as safe to log at trace/debug level. If you
//! introduce a new error path that *would* embed value bytes,
//! preserve only the position / length and forward those.

use presage::store::StoreError as PresageStoreError;

/// Errors raised by `PddbStore`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A `KvBackend` operation failed (PDDB I/O, mock-backend lock
    /// poisoning, etc.). The string is the backend's own error rendering.
    #[error("kv backend: {0}")]
    Backend(String),

    /// `serde_json` failed to serialize a value before storing it.
    #[error("encode: {0}")]
    Encode(String),

    /// `serde_json` failed to deserialize a stored value, or a libsignal
    /// `deserialize`/`from_slice` call rejected raw bytes from disk.
    #[error("decode: {0}")]
    Decode(String),

    /// A libsignal protocol error — surfaced from
    /// `IdentityKeyPair::deserialize`, `SenderCertificate::deserialize`,
    /// `SenderCertificate::serialized()`.
    #[error("protocol: {0}")]
    Protocol(#[from] presage::libsignal_service::protocol::SignalProtocolError),
}

impl PresageStoreError for Error {}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        // serde_json conflates encode and decode errors in one type.
        // Keep both variants on our side — the From impl picks `Decode`
        // because that's the more common direction when round-tripping
        // through the store; encode-side callsites use
        // `.map_err(Error::encode)` explicitly.
        Error::Decode(e.to_string())
    }
}

impl Error {
    /// Construct an [`Error::Encode`] from any `Display`-able error
    /// (typically `serde_json::Error` on the serialize path).
    pub(crate) fn encode<E: std::fmt::Display>(e: E) -> Self { Error::Encode(e.to_string()) }

    /// Construct an [`Error::Backend`] from any `Display`-able error
    /// (PDDB IPC failure, mutex poisoning, validation failures
    /// reported as backend errors).
    pub(crate) fn backend<E: std::fmt::Display>(e: E) -> Self { Error::Backend(e.to_string()) }
}
