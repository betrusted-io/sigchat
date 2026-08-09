# crates/

xas's first-party Rust crates. The patched upstream forks
(`presage`, `libsignal-service-rs`, `curve25519-dalek`) are
consumed as rev-pinned git dependencies — pin matrix in
[`../docs/FORKS.md`](../docs/FORKS.md). For the architectural
rationale behind this split, see
[`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md).

## Why a multi-crate workspace

xas is a single binary, but the code is split across multiple
crates for three concrete reasons:

1. **Build-time isolation of the Xous IPC bypass crate.** The
   upstream `services/pddb` crate pulls in 10+ Xous services as
   path-deps and forces a full xous-core workspace rebuild on
   every change. The hand-rolled IPC client (`xous-pddb-ipc`)
   replicates just the wire protocol we need, in its own crate,
   so iterating on it doesn't trigger the cascade.
2. **Trait-impl boundary for the storage layer.** presage defines
   storage traits; `presage-store-pddb` implements them against
   PDDB. Keeping it in its own crate makes the trait surface
   explicit and means the Signal-protocol-bearing code
   (`xous-signal-worker`) doesn't reach into PDDB internals.
3. **Worker-vs-app separation.** The `xous-signal-worker` crate
   owns the worker thread + LocalExecutor that runs presage; the
   `xous-app-signal` binary owns the GAM-rendered UI and talks
   to the worker over async channels (`Cmd`/`Event`). This
   split is what lets the same UI code run in both hosted Xous
   emulation and on rv32 hardware unchanged.

## Crates in this folder

| Crate | LoC* | Purpose |
|---|---|---|
| [`xous-app-signal`](xous-app-signal/) | ~2.4k | Binary entry point (binary name: `xas`). Spawns the signal worker, renders UI via GAM, dispatches keys → `Cmd`s and `Event`s → screen updates. |
| [`xous-signal-worker`](xous-signal-worker/) | ~1.3k | Owns the worker thread that runs `presage::Manager` on a `LocalExecutor`. Defines the `Cmd` / `Event` enums that flow over async channels between worker and UI. Where `catch_unwind` lives so panics in libsignal don't kill the worker. |
| [`presage-store-pddb`](presage-store-pddb/) | ~3.0k | Implements presage's `Store` + `IdentityKeyStore` + (a dozen) other storage traits over PDDB. Has a hosted-mode `backend_mock` for unit tests and a `backend_pddb` for real use. The biggest crate by line count, mostly because the trait surface is wide. |
| [`xous-net-bridge`](xous-net-bridge/) | ~0.6k | Sync TLS + WebSocket transport, bridged to async via channels (`ws_pump`). This is what libsignal-service-rs's HTTP/WS code calls into. The keepalive race documented in the upstream PR draft #2 lives in `ws_pump.rs`. |
| [`xous-pddb-ipc`](xous-pddb-ipc/) | ~0.8k | Hand-rolled PDDB IPC client (rv32-xous only). Replicates just the wire protocol `presage-store-pddb`'s `KvBackend` needs, instead of pulling in the full `services/pddb` crate (which would drag in 10+ other services as path deps and rebuild xous-core on every iteration). |

\* LoC = `wc -l src/**/*.rs` rounded; for orientation, not load-bearing.

## Map to the architecture doc

[`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) lays out the
runtime architecture (worker thread, async channel bridge,
GAM UI loop). The crates here map to its sections roughly as:

- **The big picture** and the **inbound/outbound walkthroughs**
  → `xous-signal-worker` (the worker thread + Cmd/Event surface
  the walkthroughs trace through)
- **Where state lives** → `presage-store-pddb` + `xous-pddb-ipc`
- **ws_pump in detail** → `xous-net-bridge`
- The GAM render path the walkthroughs end at →
  `xous-app-signal/src/gam_app.rs` (QR modal via the upstream
  `modals` client)

If a crate's purpose feels unclear after reading this table,
that's a signal worth recording in the project's roadmap.
