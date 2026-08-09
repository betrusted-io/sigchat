# presage-store-pddb

Implements presage's storage traits on top of Xous's encrypted
PDDB. This is what lets a linked Signal session survive across
device reboots and PDDB lock cycles.

## What's here

- **`src/lib.rs`** — `KvBackend` trait + `PddbStore` struct
  (the public surface presage gets handed). Plus 720 LoC of
  integration tests covering round-trip, cache+flush,
  multi-identity, message ranges.
- **`src/backend_mock.rs`** — in-memory `KvBackend` impl for
  hosted unit tests. ~75 LoC.
- **`src/backend_pddb.rs`** — real PDDB-backed `KvBackend`
  impl. Uses `xous-pddb-ipc` to talk to the PDDB service.
  ~155 LoC.
- **`src/state.rs`** — `StateStore` impl (registration data,
  identity keypairs, sender cert, master key).
- **`src/content.rs`** — `ContentsStore` impl (~540 LoC across
  8 content types: profiles, contacts, groups, avatars, sticker
  packs, messages-by-thread).
- **`src/protocol/`** — six required + three optional libsignal
  protocol stores (IdentityKeyStore, PreKeyStore, etc.). The
  bulk of the crate.

## Why this crate exists separately

Two reasons:

1. **Trait-impl isolation.** presage defines ~11 distinct
   storage traits (some required, some extension); this crate
   implements every one of them. Keeping it separate means the
   Signal-protocol-bearing code (`xous-signal-worker`) doesn't
   reach into PDDB internals — it just hands a `PddbStore` to
   `presage::Manager` and lets the trait dispatch handle
   storage.
2. **Backend-swappable for tests.** The `KvBackend` abstraction
   lets the mock backend ship for free. Hosted unit tests use
   the in-memory mock; rv32 hardware uses the real PDDB. Same
   trait surface, no test-only branches in the protocol code.

## Who depends on this crate

- `xous-app-signal` — owns the `PddbStore` and hands clones to
  the worker.
- `xous-signal-worker` — uses it as the type parameter for
  `Manager<PddbStore, _>`.

## Size note

At ~3 kLoC this is the largest first-party crate. The size is
mostly justified by the 11-trait surface (many small impl
blocks) but there's some duplication — the dedup helpers in lib.rs and protocol/mod.rs were extracted from three duplication patterns (centralize `backend_err`
helpers, add `backend_get_json` / `backend_put_json` helpers,
consolidate `list_keys → parse u32 → max/filter` patterns).
~100-120 LoC achievable but not transformative.
