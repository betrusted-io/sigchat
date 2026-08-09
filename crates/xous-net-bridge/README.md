# xous-net-bridge

The sync↔async transport bridge. Implements
libsignal-service-rs's `HttpClient` and `WebSocketChannels`
traits on top of Xous's `std::net::TcpStream` + tungstenite +
rustls, bridging blocking I/O into the async executor that runs
inside `xous-signal-worker`. This is the "bridge" in the
codebase — the only crate where that noun is load-bearing.

## What's here

- **`src/tls.rs`** — rustls setup against Signal's pinned root
  store. Exports `signal_production_roots()` for both this
  crate's HTTP/WS code and (separately) the kernel's net
  stack tests.
- **`src/http.rs`** — `SyncHttpClient`: synchronous TLS+HTTP
  request runner that libsignal-service-rs's
  `presage::Manager` calls into.
- **`src/ws.rs` + `src/ws_pump.rs`** — the WebSocket pump.
  Three threads (setup / reader / writer) bridging a blocking
  `WebSocket<RustlsStream>` into an `async-channel`-fronted
  `WebSocketChannels` that libsignal-service-rs awaits on.

## Why this crate exists separately

The async↔sync impedance match is non-trivial and was the
single biggest source of bugs during hardware bring-up (read
timeouts, keepalive races, stream rotation). Isolating it lets
us:

- Test the transport in isolation with mocked streams.
- Swap implementations without touching the worker (e.g., a per-send-fresh-WS variant on the roadmap).
- Audit the audit-critical part of the stack (everything
  Signal-server-facing) without wading through unrelated UI or
  storage code.

## Who depends on this crate

- `xous-signal-worker` — directly imports `SyncHttpClient` and
  `signal_production_roots`.
- The rev-pinned libsignal-service-rs fork
  (see [`../../docs/FORKS.md`](../../docs/FORKS.md)) — patched to
  call into this crate's `WebSocketChannels` shape rather than
  its own reqwest-based transport.

## Where the upstream PR lives

The keepalive-tolerance change
([whisperfish/libsignal-service-rs#431](https://github.com/whisperfish/libsignal-service-rs/pull/431),
closed unmerged) is carried in `src/websocket/mod.rs` on the
libsignal-service-rs fork branch, not here — but the
*consequence* (tolerating up to 3 outstanding keepalives so a
healthy WS isn't closed by scheduling jitter) is what makes the
ws_pump usable on rv32.
