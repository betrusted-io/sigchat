#!/usr/bin/env bash
# Headless hosted-mode regression test: drive xas through the link
# flow until either Event::LinkUrl is emitted (PASS) or a timeout
# fires (FAIL).
#
# Pass criterion: the worker logs `worker/link: URL received from
# libsignal: sgnl://linkdevice?...` AND gam_app logs
# `xas/gam_app: link URL = sgnl://linkdevice?...`. Both lines mean
# the URL was generated and routed all the way to the UI's modal-
# open path.
#
# This test does NOT scan the QR (no real phone in headless CI),
# so a successful `LinkComplete` is not expected. The test
# specifically checks that the QR data made it to the UI; what
# happens after (envelope arrival or timeout) is outside scope.
#
# Prerequisites:
# - Xous-core checkout at $XOUS_CORE_DIR (default
#   ~/precursor-signal/repos/xous-core), `xas` branch checked out.
# - xas binary built for hosted WITH `--features link-uri-uart` at
#   target/release/xas (default $XAS_BIN_PATH): the URL log lines
#   this test greps are behind that default-off feature (default
#   builds log only the URL length — the URL is the link credential
#   and would otherwise leak on UART).
#   `cargo build --release -p xous-app-signal \
#     --features pddb-real,hosted,link-uri-uart`
# - X11 display reachable as $DISPLAY (default localhost:10.0;
#   the test launches Xous with this DISPLAY exported and uses
#   XSendEvent via Python ctypes for keystroke injection).
# - python3 + libX11.so.6 available.
#
# Exit codes:
#   0 — pass
#   1 — generic failure
#   2 — Xous never finished booting
#   3 — could not find Precursor X11 window
#   4 — link URL never emitted within $LINK_TIMEOUT seconds

set -u
set -o pipefail

XOUS_CORE_DIR="${XOUS_CORE_DIR:-$HOME/precursor-signal/repos/xous-core}"
XAS_BIN_PATH="${XAS_BIN_PATH:-$HOME/precursor-signal/xous-app-signal/target/release/xas}"
export DISPLAY="${DISPLAY:-localhost:10.0}"
LINK_TIMEOUT="${LINK_TIMEOUT:-90}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-180}"
# Hosted has no real WF200 radio; wlan_status() returns Unknown
# and xas's no-internet preflight would otherwise route Link to
# Screen::NoInternet and never emit the link URL. Production code
# still runs the preflight; this env var is the documented escape
# hatch for hosted/CI runs.
export XAS_BYPASS_PREFLIGHT=1

LOG_DIR="$(mktemp -d -t xas-hosted-test.XXXXXX)"
KERNEL_LOG="$LOG_DIR/xous-kernel.log"
DRIVE_LOG="$LOG_DIR/drive.log"

cleanup() {
    pkill -f "xous-kernel" 2>/dev/null || true
    pkill -f "cargo xtask run" 2>/dev/null || true
    if [ "${KEEP_LOGS:-0}" = "1" ]; then
        echo "Logs preserved: $LOG_DIR" >&2
    else
        rm -rf "$LOG_DIR"
    fi
}
trap cleanup EXIT

echo "==> tests/hosted/test_link_qr.sh"
echo "    XOUS_CORE_DIR=$XOUS_CORE_DIR"
echo "    XAS_BIN_PATH=$XAS_BIN_PATH"
echo "    DISPLAY=$DISPLAY"
echo "    LOG_DIR=$LOG_DIR"

# Sanity: binary exists and X11 reachable.
if [ ! -x "$XAS_BIN_PATH" ]; then
    echo "ERROR: xas binary not found at $XAS_BIN_PATH" >&2
    exit 1
fi
if ! xset q >/dev/null 2>&1; then
    echo "ERROR: X server not reachable on $DISPLAY" >&2
    exit 1
fi

# Step 1: kill any in-flight Xous, then launch fresh.
pkill -f "xous-kernel" 2>/dev/null || true
pkill -f "cargo xtask run" 2>/dev/null || true
sleep 1

# Restore PDDB to a clean unlinked state before each run so the test
# always exercises the *fresh-link* path. Without this, a successful
# previous run leaves registration data in PDDB; the next run hits
# the auto-load branch and no fresh QR is emitted (the test then
# false-FAILs). A separate `test_reattach.sh` covers the auto-load
# path.
#
# `WIPE_PDDB=0` opts out (e.g. when intentionally testing auto-load
# from outside this script).
PDDB_HOSTED_BIN="${PDDB_HOSTED_BIN:-$XOUS_CORE_DIR/tools/pddb-images/hosted.bin}"
PDDB_BACKUP_BIN="${PDDB_BACKUP_BIN:-$XOUS_CORE_DIR/tools/pddb-images/hosted_backup.bin}"
if [ "${WIPE_PDDB:-1}" = "1" ] && [ -f "$PDDB_BACKUP_BIN" ]; then
    echo "==> restoring PDDB from backup ($PDDB_BACKUP_BIN -> $PDDB_HOSTED_BIN)"
    cp "$PDDB_BACKUP_BIN" "$PDDB_HOSTED_BIN"
fi

echo "==> launching hosted Xous"
(
    cd "$XOUS_CORE_DIR"
    cargo xtask run "xas:$XAS_BIN_PATH" >"$KERNEL_LOG" 2>&1
) &
XOUS_BG_PID=$!

echo "    Xous bg PID=$XOUS_BG_PID"

# Step 2: wait for boot — services finish coming up when status
# logs "starting main loop". Generous timeout because cold builds
# can take a couple of minutes.
echo "==> waiting up to ${BOOT_TIMEOUT}s for Xous boot"
WAIT=0
while [ $WAIT -lt $BOOT_TIMEOUT ]; do
    if grep -q "starting main loop" "$KERNEL_LOG" 2>/dev/null; then
        echo "    boot signal seen at t=${WAIT}s"
        break
    fi
    sleep 2
    WAIT=$((WAIT + 2))
done
if ! grep -q "starting main loop" "$KERNEL_LOG" 2>/dev/null; then
    echo "ERROR: Xous never booted within ${BOOT_TIMEOUT}s" >&2
    tail -20 "$KERNEL_LOG" >&2
    exit 2
fi

# Wait an extra few seconds for shellchat to register the launcher
# manifest and gam to settle.
sleep 4

# Step 3: confirm Precursor X11 window is up.
WIN_HEX="$(xdotool search --name "Precursor" 2>/dev/null | head -1)"
if [ -z "$WIN_HEX" ]; then
    echo "ERROR: Precursor X11 window not found" >&2
    exit 3
fi
echo "==> Precursor window=$WIN_HEX"

# Step 4: drive the link flow via XSendEvent (drive_link.py calls
# libX11 directly via ctypes).
echo "==> driving keystrokes to xas"
python3 "$(dirname "$0")/drive_link.py" "$WIN_HEX" >"$DRIVE_LOG" 2>&1
DRIVE_EC=$?
echo "    drive exit code=$DRIVE_EC"
if [ $DRIVE_EC -ne 0 ]; then
    echo "ERROR: keystroke driver failed" >&2
    cat "$DRIVE_LOG" >&2
    exit 1
fi

# Step 4b: accept the device-name modal. drive_link.py hands off
# after selecting Link (see its trailing comment): a blind Enter
# races the modal render and can land on the still-active Menu, so
# retry-Enter every 3s until the worker logs
# `Cmd::LinkDevice received` — the marker that gam_app forwarded
# the accepted device name. Mirrors the loop in
# test_xas_round_trip.py.
echo "==> retry-Enter until 'Cmd::LinkDevice received'"
ACCEPT_DEADLINE=$((SECONDS + 60))
ACCEPTED=0
while [ $SECONDS -lt $ACCEPT_DEADLINE ]; do
    if grep -q "worker: Cmd::LinkDevice received" "$KERNEL_LOG" 2>/dev/null; then
        ACCEPTED=1
        break
    fi
    python3 "$(dirname "$0")/drive_link.py" "$WIN_HEX" --press-enter >>"$DRIVE_LOG" 2>&1 || true
    sleep 3
done
if [ $ACCEPTED -ne 1 ]; then
    echo "ERROR: device-name modal never accepted ('Cmd::LinkDevice received' not in log)" >&2
    exit 4
fi
echo "    device-name modal accepted"

# Step 5: poll the kernel log for the URL emission. PASS as soon
# as both worker and gam_app log it; FAIL on timeout.
# Both grep targets require the binary to be built with
# `--features link-uri-uart` (URL logging is default-off).
echo "==> waiting up to ${LINK_TIMEOUT}s for link URL emission"
WAIT=0
SAW_WORKER=0
SAW_GAMAPP=0
while [ $WAIT -lt $LINK_TIMEOUT ]; do
    if grep -q "worker/link: URL received from libsignal:" "$KERNEL_LOG" 2>/dev/null; then
        SAW_WORKER=1
    fi
    if grep -q "xas/gam_app: link URL = sgnl://linkdevice" "$KERNEL_LOG" 2>/dev/null; then
        SAW_GAMAPP=1
    fi
    if [ $SAW_WORKER -eq 1 ] && [ $SAW_GAMAPP -eq 1 ]; then
        break
    fi
    sleep 1
    WAIT=$((WAIT + 1))
done

echo
echo "==> result"
echo "    worker URL log: $SAW_WORKER (expect 1)"
echo "    gam_app URL log: $SAW_GAMAPP (expect 1)"
echo
echo "==> link-related lines in kernel log:"
grep -E "worker/link|gam_app: link URL|gam_app: starting|generating qrcode|provisioning|LinkUrl|LinkComplete|LinkError|Sink closed" "$KERNEL_LOG" || echo "(no link lines found)"

RESULT_RC=4
if [ $SAW_WORKER -eq 1 ] && [ $SAW_GAMAPP -eq 1 ]; then
    echo
    echo "PASS: link URL reached the UI."
    RESULT_RC=0
else
    echo
    echo "FAIL: link URL did not reach the UI within ${LINK_TIMEOUT}s." >&2
    if grep -q "link URL received (" "$KERNEL_LOG" 2>/dev/null; then
        echo "HINT: found the redacted-form line — rebuild the xas binary with --features link-uri-uart." >&2
    fi
    echo "(set KEEP_LOGS=1 to keep $LOG_DIR for triage)"
fi

# `INSPECT_HOLD=NN` (seconds) keeps the kernel alive so the QR
# modal stays visible for inspection — useful when debugging
# whether the QR rendered, when scanning from a real phone, or
# when verifying the persistence loop end-to-end. The cleanup trap
# fires on exit and reaps the kernel after this sleep.
if [ -n "${INSPECT_HOLD:-}" ]; then
    echo
    echo "==> holding kernel up for ${INSPECT_HOLD}s (INSPECT_HOLD set) — Ctrl-C to exit"
    sleep "$INSPECT_HOLD"
fi

exit "$RESULT_RC"
