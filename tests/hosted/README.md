# tests/hosted — running hosted-mode tests

Hosted mode runs the full Xous kernel + services + apps as a
single Linux process, with the GAM rendered to a minifb window
labelled "Precursor". It boots in seconds, uses your real Wi-Fi
via the host kernel, and talks to the real Signal server. It's
the workhorse for UI iteration and most logic-bug fixes — see
[`../README.md`](../README.md) for how it compares to the other
testing approaches.

## Prerequisites

- [`../../BUILDING.md`](../../BUILDING.md) sections 0 and 1 done
  (Rust toolchain, repos cloned with the `repos/xous-core`
  symlink in place)
- `xset q` returns without error (X11 display reachable; over
  SSH use `ssh -X`)
- A real Signal account with `signal-cli` installed as the test
  peer (BUILDING.md section 0 "Required for hosted path")

## Scripts in this folder

| File | Purpose |
|---|---|
| `test_link_qr.sh` | Headless smoke test: boots hosted, drives launcher to xas link screen, gates on the provisioning URL appearing in the kernel log. The cheapest end-to-end check. |
| `test_send_receive.sh` | Full send/receive integration test against `signal-cli`. Six phases: PDDB-truncate guard (refs #14), boot + automated link via `signal-cli addDevice`, receive 5 messages, idle for one server-side reauth cycle, post-idle receive proof. Per-phase exit codes (0 PASS, 2 #14 regression, 3 link, 4 recv, 5 idle, 6 post-idle). Needs `signal-cli` registered on **both** `TEST_PEER_NUMBER` and `TEST_XAS_NUMBER` so it can play sender AND primary-that-approves-the-link. Phase 4 (send-from-xas) deferred — needs a compose keystroke driver. |
| `test_signal_cli_echo.sh` | Phase 0: signal-cli bidirectional echo. Catches bad account state BEFORE xas testing. NL→US + US→NL, each timed; PASS if <10 s per direction. Exit codes 0 (both), 1 (only NL→US), 2 (only US→NL), 3 (neither). Halt the rest of the pipeline if this fails. |
| `test_xas_round_trip.py` | xas-side round-trip after Phase 0 PASS. At launch, removes any pre-existing linked devices from the xas primary (clean state per run). Phase 1 auto-link via `signal-cli addDevice`, auto-dismisses the QR modal via `XSendEvent` so `gam_app` drains `Event::LinkComplete`. Round 1: peer→xas + xas reply ×2. Round 2: xas→peer + peer reply ×2. Each step timed; summary at exit. xas-side sends prompt the maintainer to type into the thread; timing anchors on `worker/send: handle_send entered`. |
| `test_xas_round_trip_pcap.py` | Wraps `test_xas_round_trip.py` + concurrent `tcpdump` capture filtered to `.signal.org` IPs on :443. Pcap archived alongside the inner test's logs. Reports TCP-level census (SYN/FIN/RST count) at exit. |
| `drive_link.py` | Helper used by `test_link_qr.sh` to script keystrokes into the minifb window. |
| `scan_receive.sh` | Boots hosted with a longer hold so you can scan the QR from your phone and verify a receive end-to-end. |
| `test_helpers.sh` | Shared bash helpers (sourced by the other scripts). |
| `test_env.example` | Template for `tests/hosted/test_env` (gitignored) — copy and fill in before running scripts that need a peer phone number. |

## Running the headless link smoke test

```sh
cd /path/to/xous-app-signal
INSPECT_HOLD=900 bash tests/hosted/test_link_qr.sh
```

`INSPECT_HOLD` keeps the kernel alive for that many seconds
after the QR code appears, so you can scan it from your phone
and observe the rest of the link flow interactively. Skip it
(or set to a small value) if you only want to validate that xas
reaches the QR-display stage.

The script writes its kernel log to a temp directory whose path
it prints on startup. Save that path if you need to diff
against a known-good run.

## Running ad-hoc hosted with signal-cli as peer

For send/receive testing you'll want a non-headless session.
Build xas first:

```sh
cd /path/to/xous-app-signal
cargo build --release -p xous-app-signal --features pddb-real,hosted
```

Then from the **xous-core** directory:

```sh
cd /path/to/xous-core
cargo xtask run xas:../xous-app-signal/target/release/xas
```

Once the minifb window appears: launcher → Apps → xas → Link
device. Scan the QR from your phone. Then send a message from
your other Signal account to your linked phone — it should
appear in xas's home screen within seconds. Send a reply to
verify the outbound path.

`signal-cli` makes a useful test peer because you can script
sends/receives from a separate terminal:

```sh
# In a side terminal — assumes signal-cli is registered to a
# different Signal account than the one xas links to
signal-cli -u +SECONDARY_NUMBER send -m "hello from side terminal" +PRIMARY_NUMBER
signal-cli -u +SECONDARY_NUMBER receive
```
