# xous-signal-worker

The worker-thread crate. Owns a long-lived OS thread that runs
`presage::Manager` on a `LocalExecutor`, and exposes a `Cmd` /
`Event` channel surface to the rest of xas.

## What's here

- **`src/lib.rs`** — `run_signal_worker(store, cmd_rx, event_tx)`
  spawn point + the worker's main loop. Dispatches `Cmd`s
  (`LinkDevice`, `StartReceive`, `SendMessage`, `GetAccountInfo`,
  `Shutdown`) and emits `Event`s (`LinkUrl`, `LinkComplete`,
  `Message`, `SendComplete`, `SendError`, `AccountInfo`, …).
  Also home of `manager_task` (the receive-stream + send
  multiplexer that runs inside the executor) and `catch_unwind`
  around `manager.send_message` so panics in libsignal don't
  kill the worker.
- **`src/cmd.rs`** — the `Cmd` and `Event` enum definitions
  (8 + 13 variants). The thin, audit-friendly interface
  between UI and worker.

## Why this crate exists separately

Two reasons:

1. **The UI is single-threaded and sync; presage is async.**
   This crate is the boundary that lets the GAM main loop send
   `Cmd::SendMessage` and receive `Event::SendComplete` without
   ever touching async/`Send`/locks itself. Both directions
   flow over `async-channel`s; the worker thread does
   `recv_blocking` / `send_blocking` on its end, and the
   executor inside the thread does `recv` / `send`.
2. **Crash isolation.** If libsignal panics, only this thread
   dies; the UI catches the channel close and surfaces a
   `SendError`. The binary keeps running.

## Who depends on this crate

- `xous-app-signal` (the binary) — spawns the worker, holds the
  channel ends.

The UI code (`gam_app`) never imports this crate directly;
main spawns the worker and passes each side its channel ends.
