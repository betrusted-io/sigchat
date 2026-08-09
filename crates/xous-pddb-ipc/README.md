# xous-pddb-ipc

Hand-rolled PDDB IPC client. **rv32-xous-only.** Replicates the
wire protocol the `KvBackend` in `presage-store-pddb` needs,
without pulling in the full `xous-core/services/pddb` crate.

## Why this exists

`services/pddb` (the upstream Rust client to xous-core's PDDB
service) is feature-gated behind `gen1`, which when enabled
pulls in 10+ other Xous services as path-deps:
`services/{root-keys, ticktimer, llio, susres, …}`. Adding
`services/pddb` as a dep would force `cargo` to rebuild the
entire xous-core workspace on every `cargo build` of xas — a
multi-minute cycle on every iteration.

`xous-pddb-ipc` replicates only the wire surface our backend
needs (11 opcodes: IsMounted, ReadKey, WriteKey, DeleteKey,
DeleteDict, KeyAttributes, KeyCountInDict, KeyRequest,
WriteKeyFlush, KeyDrop, ListKeyV2 + Mount Poller's Poll). Each
opcode corresponds to one server-side handler the upstream
`services/pddb` exposes; the format-on-the-wire matches byte-
for-byte. This is verified by integration tests on hosted
xous-core that exercise the same operations through both clients.

## What's here

- **`src/api.rs`** — opcode + message-shape definitions. Mirror
  of `xous-core/services/pddb/src/api.rs`'s subset we use.
- **`src/client.rs`** — the `PddbClient` struct + IPC ergonomics
  (looking up the SID via `xous-api-names`, sending Borrow /
  MutableBorrow messages, parsing replies).
- **`src/lib.rs`** — re-exports the public surface.

## Who depends on this crate

- `presage-store-pddb` (via `backend_pddb.rs`).

## Maintenance note

If xous-core's PDDB service changes its wire protocol (rare —
PDDB is a stable service), this crate must be updated to match.
Watch `xous-core/services/pddb/src/api.rs` for opcode ordering
or struct-field changes. The stage report `docs/history/stage/REPORT-5.md`
describes how the dictionary layout was originally derived.
