# xas: Architecture

This document explains how xas works to a Rust developer with
passing knowledge of cryptography (knows what [AEAD](https://en.wikipedia.org/wiki/Authenticated_encryption) is, has heard
of the [Double Ratchet](https://en.wikipedia.org/wiki/Double_Ratchet_Algorithm), can read async Rust). After reading it
once, you should be able to pick up any open chore and know
which file to open first.

If you want to *build* the project, read [BUILDING.md](../BUILDING.md)
instead. If you want to know *why* xas exists, read the
"Why a Signal client on Precursor" section of the [README](../README.md).
This document is about the code shape.

---

## 1. What xas is, in one paragraph

xas is a Signal messenger client that runs as an unprivileged
user-space app on **Xous**, the microkernel OS for the
**Precursor** open-hardware device. It links to a Signal account
as a secondary device (the same way Signal Desktop does), receives
and sends 1:1 text messages, and persists its session state in
PDDB (Xous's encrypted user store). The deliberate goal is
end-to-end auditability: every layer from the FPGA bitstream up
through the Signal protocol implementation is open code that the
user can inspect.

## 2. The big picture

Four boxes. Three boundaries you cross every time a message moves.

```
   ┌──────────────────────┐
   │   xas GAM main loop  │   single thread, runs in xas's
   │   (gam_app.rs)       │   xous process; owns the LCD
   └──────────┬───────────┘
              │  async-channel<Cmd>  (App → worker)
              │  async-channel<Event> (worker → App)
              ▼
   ┌──────────────────────┐
   │  signal-worker       │   our code: thin async bridge
   │  thread              │   (xous-signal-worker crate)
   │  (worker_main)       │
   └──────────┬───────────┘
              │  rust function calls into:
              ▼
   ┌──────────────────────┐
   │  presage::Manager    │   upstream crate; owns Signal
   │  + libsignal-service │   protocol state + Web/REST
   │  + libsignal         │   surfaces to chat.signal.org
   └──────────┬───────────┘
              │  TLS+WSS + HTTPS
              ▼
   ┌──────────────────────┐
   │  Signal servers      │   chat.signal.org and friends
   └──────────────────────┘
```

The right thing to internalize is which layer owns which problem:

| Layer | What it does | Whose code |
|---|---|---|
| GAM main loop | LCD render, key handling, app screens | ours |
| signal-worker | Cmd/Event IPC translation | ours (~1000 LOC) |
| presage Manager | Signal protocol state machine, store wiring | **upstream `whisperfish/presage`** (rev-pinned fork; [FORKS.md](FORKS.md)) |
| libsignal-service-rs | Signal HTTP + WSS + envelope/cipher framing | **upstream `whisperfish/libsignal-service-rs`** (rev-pinned fork; [FORKS.md](FORKS.md)) |
| signalapp/libsignal | Double Ratchet, X3DH/PQXDH, sealed sender, AES-GCM-SIV | **upstream `signalapp/libsignal`** (Cargo dep) |
| smoltcp + xous-net | TCP/IP stack inside the Xous kernel | upstream xous-core |
| FPGA + WF200 | Wi-Fi radio + RISC-V SoC | upstream betrusted-io hardware |

**The trust argument is the central design principle.** All
Signal-protocol cryptography happens in code we did not write —
the same crates that the Whisperfish project uses on Sailfish OS
and that have years of community use. xas adds:

1. A storage backend (`presage-store-pddb`) that implements
   presage's `Store` trait against Xous's PDDB instead of sled
   or SQLite.
2. A network backend (`xous-net-bridge`) that wires
   libsignal-service-rs's `HttpClient` and `WebSocketChannels`
   traits to Xous's `std::net::TcpStream` + tungstenite + rustls.
3. The signal worker (`xous-signal-worker`) that owns a
   long-lived thread running the presage Manager and exposes a
   `Cmd`/`Event` channel surface to the single-threaded GAM
   event loop.
4. The UI itself (`xous-app-signal`).

**We do not implement any cryptography ourselves.** We do not
parse Signal protobufs ourselves. We do not maintain our own
copy of the Signal protocol — we are a downstream consumer of
the upstream Rust implementations. If a vulnerability is found
in the Signal protocol, the fix lands in `signalapp/libsignal`
or `whisperfish/libsignal-service-rs` upstream and reaches xas
via a fork-pin bump ([FORKS.md](FORKS.md)) — not via patching by
us.

## 3. The Xous IPC primer (~200 words)

Xous is a microkernel: most things you'd think of as "the OS"
(the network stack, the GUI manager, persistent storage) are
unprivileged user-space services. They communicate via typed
synchronous IPC: each service registers a *server ID* (a
128-bit string), other processes call `xous::connect()` to get
a *connection ID*, and then send messages via
`xous::send_message()` (synchronous: the caller blocks until
the server replies). That's it — no shared memory by default,
no async runtime in the kernel.

xas is an unprivileged Xous app. Its `main()` (in
[`crates/xous-app-signal/src/main.rs`](../crates/xous-app-signal/src/main.rs))
spawns a worker thread (`run_signal_worker`, line ~145), then
enters the GAM (Graphics Abstraction Manager) event loop. The
GAM event loop is a `match` over IPC messages from the GUI
service — keypresses, focus changes, redraw requests. It MUST
NOT block on long operations or the LCD freezes.

But Signal operations are slow on rv32 (~tens of seconds for
prekey fetch + AES-GCM-SIV + WS round-trip). So we shove all of
that onto a worker thread and bridge it via two
**async-channel**s — `Cmd` flows from the main loop to the
worker, `Event` flows back. The worker owns a single
`presage::Manager` instance for its lifetime. The two
async-channel-s let us use `send_blocking`/`recv_blocking` from
the synchronous main loop and `send`/`recv` from the worker's
async context, without `block_on` gymnastics on the IPC side.

## 4. Inbound message walkthrough

An incoming Signal message becomes a row on the LCD by
traversing eight layers. Each step lists the file path so you
can jump straight to the code.

1. **TLS+WSS payload arrives at the device.** The Wi-Fi radio
   (WF200) hands packets to the kernel's smoltcp-based net
   service. *Code:* `xous-core/services/net/` (upstream).
2. **xous-net-bridge's reader thread** has a sync `tungstenite::WebSocket`
   wrapping a `std::net::TcpStream`; `read()` returns the next
   WS frame. *Code:* [`crates/xous-net-bridge/src/ws_pump.rs`](../crates/xous-net-bridge/src/ws_pump.rs)
   `reader_loop`. The TCP stream has a 5s read timeout — every
   5s of idle, the reader drops the WS mutex briefly so the
   writer thread (same file, `writer_loop`) can inject a
   keepalive frame. (See section 8 for why this dance.)
3. **libsignal-service-rs decodes the frame** as a
   `WebSocketMessage` protobuf and dispatches by type.
   `Type::Request` from the server is an envelope push;
   `Type::Response` is a reply to one of our own requests.
   *Code:* `src/websocket/mod.rs` in the libsignal-service-rs
   fork ([FORKS.md](FORKS.md)),
   `SignalWebSocketProcess::run` (upstream — we maintain a
   rev-pinned fork with a couple of patches we'd like to
   upstream; see the README's Upstream patches section).
4. **presage's `receive_messages` stream**
   (`presage/src/manager/registered.rs:572` in the presage fork,
   upstream) takes the inbound `Envelope`, runs it through
   `ServiceCipher::open_envelope()`. That call is in
   `libsignal-service-rs::cipher`, upstream.
5. **`signalapp/libsignal` decrypts the sealed-sender
   wrapping** (X3DH + Curve25519 + AES-CBC + HMAC) and the
   inner Double Ratchet message (`session_cipher::decrypt` —
   pure upstream). Result: a `Content` struct with a
   `DataMessage` body containing the plaintext.
6. **presage's stream yields the `Received::Content`** to its
   consumer (us).
7. **xas's `manager_task`** (in
   [`crates/xous-signal-worker/src/lib.rs`](../crates/xous-signal-worker/src/lib.rs))
   pulls the `Received::Content`, calls our `process_received`
   to flatten it into an IPC-friendly shape (string-typed
   sender, body, timestamp), and sends `Event::Message` over
   the async-channel.
8. **xas's GAM main loop** in
   [`crates/xous-app-signal/src/gam_app.rs`](../crates/xous-app-signal/src/gam_app.rs)
   `handle_worker_event` matches `Event::Message`, appends a
   new `ThreadMessage` to `App.messages`, rebuilds the
   `DialogueSummary` cache, and calls `app.render()` which
   walks the GAM TextView API to repaint the LCD.

The only steps we wrote are 2, 7, and 8 (and even step 2 mostly
just glues `tungstenite` + `rustls` + `std::net::TcpStream`
together). Steps 3–6 are all upstream code; we're a transport
+ storage backend underneath them.

## 5. Outbound send walkthrough

The mirror image, with one sharp edge worth knowing about.

1. **User types in the Thread compose buffer**, presses Enter.
   `gam_app.rs::handle_keys` builds an optimistic `ThreadMessage`
   with status `Pending` and sends `Cmd::SendMessage { recipient,
   body, timestamp }` to the worker.
2. **manager_task** routes the cmd to `handle_send`
   ([`xous-signal-worker/src/lib.rs`](../crates/xous-signal-worker/src/lib.rs)
   `handle_send`).
3. **`handle_send` calls `manager.send_message()`** (presage,
   upstream) inside a 6-attempt retry loop with exponential
   backoff (2s, 4s, 8s, 16s, 32s).
4. **presage builds and encrypts** a `DataMessage`. First-time
   sends to a recipient pull their prekey bundle (HTTPS GET
   `/v2/keys/<aci>/*`), run PQXDH to establish a Double Ratchet
   session, then encrypt the body. All cryptography is in
   `signalapp/libsignal` — we never touch a key ourselves.
5. **The encrypted envelope is pushed** as a
   `WebSocketRequestMessage` via libsignal-service-rs's WSS
   pipe. The worker awaits the server's response future.
6. **On `Ok(())`**, we emit `Event::SendComplete { timestamp }`.
   The UI matches by `timestamp` and flips the optimistic
   message from `..` Pending → `vv` Delivered. On `Err(e)`
   containing "websocket closing", we sleep + retry. Other
   errors surface as `Event::SendError { reason, timestamp }`.

The retry loop exists because Signal's edge servers rotate
WebSockets aggressively (~30-60s, code 1001 "Connection Idle
Timeout"), and on rv32 a single send pipeline often takes
longer than a WS lifetime. Retrying gives subsequent attempts a
chance to land on a fresh WS. It's a workaround, not the right
fix; the real fix (per-send fresh WS or proactive rotation
detection) is queued for a future release.

## 6. Where state lives

Three different stores, each with a clear scope:

- **PDDB-backed presage store** (`crates/presage-store-pddb/`).
  Implements presage's `Store` trait against Xous's PDDB. Holds
  Signal Protocol session keys, the Double Ratchet chain
  states, the registration record (ACI / PNI / phone),
  identity-key store, prekey store. Encrypted at rest with the
  user's PDDB password. **This is the security-critical
  storage.**
- **In-RAM `App.messages`** (`gam_app.rs::App`). A
  `Vec<ThreadMessage>` capped at `INBOX_CAPACITY = 5` (yes, 5;
  this is alpha). Lost on app restart. Persistence to PDDB is a
  filed chore.
- **Bridge-side caches.** `cached_account_info`
  (xous-signal-worker/src/lib.rs) holds the
  device-name/ACI/phone for the Profile screen so the UI doesn't
  have to round-trip to the manager every time. Lost on worker
  restart.

The presage `Store` trait is what isolates "Xous-specific
storage" from the protocol itself. Anything that touches Signal
protocol state goes through this trait. `presage-store-sled` and
`presage-store-sqlite` exist in the upstream tree as alternative
implementations; ours is just another conforming backend. **No
crypto is in the storage layer** — the keys we save are already
opaque blobs from libsignal's perspective; we only persist
already-encrypted-by-PDDB bytes.

## 7. Trust + threat model

What we trust, what we don't, what an attacker can do.

**We trust:**
- `signalapp/libsignal` for all Signal Protocol cryptography
  (Double Ratchet, X3DH, PQXDH, sealed sender, AES-GCM-SIV
  envelope sealing). This is the same code Signal's official
  apps use.
- `whisperfish/libsignal-service-rs` for the Signal HTTP/WSS
  surface, envelope cipher wiring, contact/profile decryption.
  Used in Whisperfish (SailfishOS Signal client) for years.
- `whisperfish/presage` for Manager state-machine and store
  trait design.
- `rustls` + `webpki-roots` for TLS verification, with a pinned
  CA — we trust *only* Signal's published production CA, not
  the system CA bundle. If `signalapp/libsignal` ships a new
  CA, our pinned CA needs to be updated. The pin is in
  `crates/xous-net-bridge/certs/signal-production.pem`.
- The Xous kernel, services, and PDDB encryption.
- The Precursor's hardware-rooted key management (the device
  generates and seals its own root keys without relying on
  factory-injected secrets).

**We do not trust:**
- Signal's server contents — same as any Signal client. We
  trust the server only to deliver opaque bytes.
- Anything in the user's Wi-Fi path (router, ISP, AP). All
  bytes are TLS-wrapped and additionally Signal-Protocol-
  wrapped end-to-end.
- The system CA bundle (we don't use it). A compromised root
  CA can't MITM us because we don't trust it.

**What an attacker can do:**
- *Wi-Fi-level MITM:* nothing meaningful. They see TLS-encrypted
  bytes to chat.signal.org. They can drop or delay packets;
  the worst they can do is degrade reliability. They cannot
  read or forge messages.
- *Signal server compromise:* see message metadata (who
  messages whom, timing, sizes — same as any Signal client).
  Cannot read message contents (Double Ratchet); cannot impersonate
  another user without their identity key (X3DH). Can serve a
  malicious prekey bundle to attempt a future-secrecy break,
  same as the official Signal apps.
- *PDDB password disclosure:* full conversation history (when
  we add persistence), session keys, registration record. Can
  impersonate the user against Signal until the linked-device
  slot is revoked. **This is the user's primary disclosure
  surface.** Reason for the project's emphasis on hardware-
  rooted trust — the password is the only software-side secret;
  everything else lives behind the device's sealed key
  hierarchy.
- *Compromised xas binary:* full game over, but the user can
  audit the binary's source (the project explicitly aims for
  reproducible builds — see BUILDING.md).
- *Compromised host kernel/hardware:* can read anything in RAM,
  including unsealed Signal session keys during use. This is
  the residual risk that Precursor's open-hardware design
  *minimizes* but cannot eliminate. xas's threat model assumes
  the device boots a known-good Xous image (verified via the
  loader signature chain).

## 8. ws_pump in detail (the only thread-architecture trick)

The most interesting piece of code in xas's transport stack is
`xous-net-bridge::ws_pump`. tungstenite's `WebSocket<S>` is
single-threaded by design — `read()` blocks until a frame
arrives, and you can't call `send()` while a `read()` is in
flight. But libsignal-service-rs needs to *both* receive
inbound frames AND inject outbound keepalives. So we split:

```
                  ws_outgoing channel             ws_incoming channel
  libsignal ──► async-channel::Sender    libsignal ◄── async-channel::Receiver
                          │                                    ▲
                          ▼                                    │
            ┌─────────────────────────┐         ┌──────────────────────────┐
            │  writer thread          │         │  reader thread           │
            │  (sync, tungstenite)    │         │  (sync, tungstenite)     │
            └────────────┬────────────┘         └────────────┬─────────────┘
                         │                                    │
                         ▼                                    │
              guard = ws.lock();             guard = ws.lock();
              guard.send(msg);               guard.read();
                         │                                    │
                         └──────► Arc<Mutex<WebSocket>> ◄─────┘
                                  (shared by both)
                                          │
                                          ▼
                                   rustls TcpStream
                                          │
                                          ▼
                                   smoltcp socket
```

Two `async-channel`s carry frames in/out (so the libsignal-
service async runtime can hand off without blocking). Two
threads share the `Arc<Mutex<WebSocket>>`. The TCP stream has a
**5s read timeout** set on it (`xous-net-bridge::tls.rs`); when
the reader's `ws.read()` returns `WouldBlock`/`TimedOut`, the
reader drops the mutex, sleeps 50ms, then re-acquires. The
50ms gap is the writer's window to inject a frame (typically a
keepalive `WebSocketRequestMessage` to `/v1/keepalive` that
libsignal-service-rs's keepalive timer queues every 55s).

Why two threads instead of an async event loop here? Because
tungstenite is sync-only and there's no good async WSS+rustls
crate that works on Xous. The Mutex+timeout dance is the
smallest abstraction over tungstenite that supports
bidirectional traffic.

The **5s read timeout** is also where a long-latent kernel/std
bug bit us: the timeout fires `respond_with_error(NetError::TimedOut)`
on the kernel side, which used to surface in std as a generic
`recv_slice failure` IO error rather than `ErrorKind::TimedOut`.
Without the encoding fix in
`xous-core/services/net/src/std_glue.rs::respond_with_error`
(see the README's Upstream patches section), every
WS dies within seconds. With the fix, ws_pump silently absorbs
the timeout and the WS lives until something actually goes
wrong.

## 9. Layers a `Cmd` (or `Event`) crosses

A common debugging move is "instrument the layer where the bug
might live." This requires knowing what layers there are. Here
are the two end-to-end traces, with file:line cites at each
hop, so you can pick where to put a `log::info!`.

### Outbound: `Cmd::SendMessage` from key-press to TLS bytes

1. **UI captures the keystroke** — `crates/xous-app-signal/src/gam_app.rs`
   handle_keys arm. Sends on the worker channel via
   `cmd_tx.send_blocking(Cmd::SendMessage { ... })`
   (`gam_app.rs:1031` and `:1084`).
2. **Worker dispatcher receives** — `crates/xous-signal-worker/src/lib.rs::worker_main`
   match arm `Ok(Cmd::SendMessage { recipient, body, timestamp })`.
   Forwards as a `WorkerOp::Send` on the internal op channel
   into `manager_task` (which owns the `Manager` from link/load
   time; sync and username-resolve ops travel the same channel).
3. **`manager_task` selects out of receive-stream** —
   `async fn manager_task`. When an op arrives on `op_rx`, it
   drops the receive-stream borrow and runs it via
   `run_manager_op` → `handle_send(&mut manager, send, ...)`.
4. **`handle_send` invokes presage** —
   (`async fn handle_send`). Parses the recipient (UUID or
   E.164), then calls `manager.send_message(...).await` inside
   a `catch_unwind` so a panic in libsignal becomes
   `Event::SendError("panic in send: ...")` rather than
   killing the worker.
5. **presage calls libsignal-service-rs** —
   `presage/src/manager/registered.rs` (presage fork). Uses
   the `Manager`'s identified WS to send, fetching prekey
   bundles via the `HttpClient` if first-send for the
   recipient.
6. **libsignal-service-rs uses our transport** —
   the libsignal-service-rs fork's WebSocket and HTTP
   code calls into `xous-net-bridge`'s `SyncHttpClient`
   (`crates/xous-net-bridge/src/http.rs:35` constructor;
   `:46` `execute`) and into the `WebSocketChannels` returned
   by `connect_websocket` (`http.rs:68`).
7. **`ws_pump` writer thread sends the frame** —
   `crates/xous-net-bridge/src/ws_pump.rs:240`
   (`fn writer_loop`). Receives the frame on its
   `async-channel`, takes the `Mutex<WebSocket<RustlsStream>>`,
   calls `ws.send(frame)` which writes through rustls to
   `std::net::TcpStream` to the kernel net service.
8. **Kernel net service to the wire.** From here you're in
   `xous-core/services/net/`, outside this repo.

### Inbound: a Signal-server message to `Event::Message` on the UI

1. **WS reader thread reads a frame** —
   `crates/xous-net-bridge/src/ws_pump.rs:135` (`reader_loop`).
   Calls `ws.read()` blocking; pushes the frame into the
   incoming `async-channel`.
2. **libsignal-service-rs polls the channel** in its
   `SignalWebSocketProcess::run` loop
   (`src/websocket/mod.rs` in the libsignal-service-rs fork),
   correlates response frames to outstanding requests, and
   surfaces protocol-level events to presage.
3. **presage's `receive_messages` stream yields** —
   inside the executor running on the worker thread.
4. **`manager_task` consumes the stream item** —
   `log::info!("worker: stream item received")`,
   then calls
   `process_received(item, &store, &event_tx, ...).await`.
5. **`process_received` decodes content + emits Event** —
   (`async fn process_received`). Parses the
   Content body, builds an `Event::Message { sender,
   sender_phone, sender_name, body, timestamp }`, and sends on
   `event_tx`.
6. **UI consumes the event** —
   `crates/xous-app-signal/src/gam_app.rs::handle_worker_event`.
   The event reaches the GAM main loop via the forwarder
   thread that pushes into a shared `Mutex<VecDeque<Event>>`.

### How to use these traces

When debugging, narrow to ONE layer first. If a `Cmd::SendMessage`
never reaches `handle_send` (no `worker/send: handle_send entered`
in UART), the bug is in steps 1–3. If it reaches `handle_send`
but never returns, the bug is in steps 4–7. The `worker:` /
`worker/link:` / `worker/send:` log prefixes (see
`xous-signal-worker/src/lib.rs`) are designed to make this
narrowing fast — grep UART for the prefix corresponding to the
layer.

## 10. Where to look for common bug classes

| Symptom | Most likely file |
|---|---|
| Send fails with `WebSocket closing while...` | `xous-signal-worker/src/lib.rs::handle_send` retry loop; or the underlying WS lifetime in the libsignal-service-rs fork's `src/websocket/mod.rs::SignalWebSocketProcess::run` ([FORKS.md](FORKS.md)) |
| Receive doesn't surface a message that the phone says was delivered | `xous-signal-worker/src/lib.rs::manager_task` and `process_received`; check `Received` enum variants |
| Linking hangs after QR scan | `presage/src/manager/linking.rs` in the presage fork; check ProvisionEnvelope decrypt + prekey gen + `POST /v1/devices/link` |
| LCD doesn't repaint after an event | `gam_app.rs::handle_worker_event` — confirm the event arm calls `app.render()` |
| New `Cmd` variant doesn't reach the worker | Check the dispatcher in `xous-signal-worker/src/lib.rs::worker_main`'s `match cmd_rx.recv()` |
| Profile screen says "(not loaded)" after restart | `xous-signal-worker/src/lib.rs::cached_account_info` + `Cmd::GetAccountInfo` handler — see if the worker cached it |

## 11. What this doc deliberately does not cover

- **Build / flash workflow** → [BUILDING.md](../BUILDING.md).
- **Why Precursor / why Signal** → README's "Why a Signal client on Precursor" section.
- **GAM rendering API** → read `gam_app.rs` directly; the
  comments at the top of the file explain the single-TextView
  text-mode pattern.
- **Signal Protocol crypto details** → upstream
  [`signalapp/libsignal`](https://github.com/signalapp/libsignal)
  docs.
- **Xous kernel internals** (memory, scheduling, syscall ABI)
  → [Xous Book](https://betrusted.io/xous-book/), chapters 3
  and 4.
- **Long bug-history narrative** → `git log`.
- **What's broken or planned** → the README's "Feature support" matrix; deeper roadmap items live with the maintainer.

## 12. Architectural invariants (checkable)

Claims the architecture makes that a reviewer can verify
mechanically. If one of these stops holding, that's either a bug
or a deliberate design change that must update this list.

- **No cryptography is implemented in this tree.** First-party
  crates call libsignal / rustls / ring; they never implement
  primitives. Check: `grep -ri "fn encrypt\|fn decrypt\|fn sign"
  crates/` returns nothing load-bearing.
- **The UI crate does no network I/O.** `crates/xous-app-signal`
  has no dependency on `xous-net-bridge`, tungstenite, or rustls;
  every network effect goes through a `Cmd` to the worker. Check:
  its Cargo.toml.
- **The storage layer holds no cleartext protocol secrets of its
  own.** `presage-store-pddb` persists opaque blobs handed to it
  by presage/libsignal; encryption at rest is PDDB's job. Check:
  no cipher deps in its Cargo.toml.
- **The dependency forks are pin-frozen** and each fork's delta vs
  its upstream pin is plain git history — reproducible from the
  rev pins in `Cargo.lock` and auditable via the compare URLs in
  [FORKS.md](FORKS.md).
- **Worker-owned mutable state has a single owner.** The presage
  `Manager` lives inside `manager_task`; nothing else holds `&mut`
  access to it (completed by the worker-op-channel refactor).
- **cfg-gating between hosted and hardware is surgical** —
  function/statement level, never whole-module forks. Check:
  `grep -rn 'cfg(target_os = "xous")' crates/ | wc -l` stays small
  and no `mod foo_hosted;` / `mod foo_hw;` pairs exist.
