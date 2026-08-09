#!/usr/bin/env bash
# Hosted-mode send/receive integration test.
#
# Drives the full xas lifecycle against `signal-cli` as the test peer:
# boot → #14 PDDB-truncate guard → link → receive 5 → idle for one
# server-side reauth cycle → post-idle receive proof.
#
# Phases run sequentially; first failure exits with a per-phase code
# so a wrapper can attribute the failure to a specific path.
#
# Prerequisites — see tests/hosted/test_env.example. Both
# TEST_PEER_NUMBER and TEST_XAS_NUMBER must be Signal accounts that
# signal-cli is registered on (`signal-cli -a $N listDevices` works
# for both). The test uses TEST_PEER_NUMBER as the sender and
# TEST_XAS_NUMBER as the primary that approves the xas link.
#
# Exit codes:
#   0 — all phases passed
#   1 — generic / setup failure
#   2 — #14 PDDB-truncate regression
#   3 — link flow failed (URL never emitted, or signal-cli addDevice
#       errored, or no LinkComplete within timeout)
#   4 — receive failed (fewer than RECEIVE_COUNT messages surfaced)
#   5 — Stage I idle path broke (indefinite 403 loop without
#       SignalAuthExpired emit)
#   6 — post-idle receive proof failed
#
# Send-from-xas (Phase 4 in the design doc) is not yet implemented —
# requires a keystroke driver for the compose UI. Documented inline.

set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test_helpers.sh
source "$SCRIPT_DIR/test_helpers.sh"

XOUS_CORE_DIR="${XOUS_CORE_DIR:-$(xas_repo_root)/xous-core}"
XAS_BIN_PATH="${XAS_BIN_PATH:-$(xas_repo_root)/target/release/xas}"
export DISPLAY="${DISPLAY:-localhost:10.0}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-180}"
LINK_TIMEOUT="${LINK_TIMEOUT:-90}"
RECEIVE_TIMEOUT_PER_MSG="${RECEIVE_TIMEOUT_PER_MSG:-30}"
RECEIVE_COUNT="${RECEIVE_COUNT:-5}"
IDLE_DURATION="${IDLE_DURATION:-420}"
PDDB_TRUNCATE_TIMEOUT="${PDDB_TRUNCATE_TIMEOUT:-180}"
export XAS_BYPASS_PREFLIGHT=1

LOG_DIR="$(mktemp -d -t xas-send-receive.XXXXXX)"
KERNEL_LOG="$LOG_DIR/xous-kernel.log"
PCAP="$LOG_DIR/signal.pcap"
SIGNAL_CLI_LOG="$LOG_DIR/signal-cli.log"
SUMMARY="$LOG_DIR/summary.txt"

# Per-phase result captured into $SUMMARY as a tab-separated row.
record_phase() {
    local name="$1" status="$2" detail="$3"
    printf '%s\t%s\t%s\n' "$name" "$status" "$detail" >> "$SUMMARY"
}

cleanup() {
    pkill -f "xous-kernel" 2>/dev/null || true
    pkill -f "cargo xtask run" 2>/dev/null || true
    # tcpdump runs as $USER after -Z drop, so plain kill works.
    pkill -x tcpdump 2>/dev/null || true
    if [ "${KEEP_LOGS:-0}" = "1" ]; then
        echo "Logs preserved: $LOG_DIR" >&2
        printf '%s\n' "--- summary ---" "$(cat "$SUMMARY" 2>/dev/null || echo '(empty)')" >&2
    else
        rm -rf "$LOG_DIR"
    fi
}
trap cleanup EXIT

echo "==> tests/hosted/test_send_receive.sh"
echo "    XOUS_CORE_DIR=$XOUS_CORE_DIR"
echo "    XAS_BIN_PATH=$XAS_BIN_PATH"
echo "    DISPLAY=$DISPLAY"
echo "    LOG_DIR=$LOG_DIR"

# -----------------------------------------------------------------
# Setup
# -----------------------------------------------------------------

if ! xas_load_env; then
    echo "ERROR: tests/hosted/test_env not found (copy from test_env.example)" >&2
    exit 1
fi
xas_require_env TEST_PEER_NUMBER TEST_XAS_NUMBER || exit 1
xas_require_cmd signal-cli || exit 1
xas_require_cmd xdotool || exit 1
xas_require_cmd python3 || exit 1
xas_require_cmd tcpdump || exit 1

if [ ! -x "$XAS_BIN_PATH" ]; then
    echo "ERROR: xas binary not found at $XAS_BIN_PATH" >&2
    exit 1
fi
if ! xset q >/dev/null 2>&1; then
    echo "ERROR: X server not reachable on $DISPLAY" >&2
    exit 1
fi

# Two-account signal-cli requirement: both PEER and XAS_PRIMARY
# must be registered on the local signal-cli installation.
if ! signal-cli -a "$TEST_PEER_NUMBER" listDevices >/dev/null 2>&1; then
    echo "ERROR: signal-cli not registered on TEST_PEER_NUMBER=$TEST_PEER_NUMBER" >&2
    exit 1
fi
if ! signal-cli -a "$TEST_XAS_NUMBER" listDevices >/dev/null 2>&1; then
    echo "ERROR: signal-cli not registered on TEST_XAS_NUMBER=$TEST_XAS_NUMBER" >&2
    echo "       (need signal-cli to play 'primary' so addDevice can approve xas's link)" >&2
    exit 1
fi

# -----------------------------------------------------------------
# Phase 2 (run first as a cheap fail-fast): #14 PDDB-truncate guard
# -----------------------------------------------------------------
echo
echo "==> Phase 2: PDDB put-truncate guard (refs #14)"

pkill -f "xous-kernel" 2>/dev/null || true
pkill -f "cargo xtask run" 2>/dev/null || true
sleep 1

(
    cd "$XOUS_CORE_DIR"
    env XAS_PDDB_TRUNCATE_TEST=1 cargo xtask run "xas:$XAS_BIN_PATH" \
        >"$LOG_DIR/phase2-kernel.log" 2>&1
) &
PHASE2_PID=$!

# Phase 2's xas exits on its own after the test runs. Wait for the
# kernel to exit too (xtask cleans up). Bounded to avoid hangs.
WAIT=0
while [ $WAIT -lt $PDDB_TRUNCATE_TIMEOUT ]; do
    if grep -qE "XAS_PDDB_TRUNCATE_TEST: (Pass|Fail|Error)" \
            "$LOG_DIR/phase2-kernel.log" 2>/dev/null; then
        break
    fi
    sleep 2
    WAIT=$((WAIT + 2))
done

# Capture the result line before tearing the kernel down.
PHASE2_LINE="$(grep -oE 'XAS_PDDB_TRUNCATE_TEST: [^$]*' \
    "$LOG_DIR/phase2-kernel.log" 2>/dev/null | head -1)"

pkill -f "xous-kernel" 2>/dev/null || true
pkill -f "cargo xtask run" 2>/dev/null || true
wait "$PHASE2_PID" 2>/dev/null || true
sleep 1

if [ -z "$PHASE2_LINE" ]; then
    echo "FAIL: Phase 2 — XAS_PDDB_TRUNCATE_TEST did not emit a result within ${PDDB_TRUNCATE_TIMEOUT}s" >&2
    record_phase "Phase 2 (#14)" "FAIL" "no result emitted"
    exit 2
fi
echo "    $PHASE2_LINE"
if [[ "$PHASE2_LINE" != *"Pass"* ]]; then
    echo "FAIL: Phase 2 — PDDB truncate test did not pass (refs #14)" >&2
    record_phase "Phase 2 (#14)" "FAIL" "$PHASE2_LINE"
    exit 2
fi
record_phase "Phase 2 (#14)" "PASS" "$PHASE2_LINE"

# -----------------------------------------------------------------
# Phase 1: boot + link via signal-cli addDevice
# -----------------------------------------------------------------
echo
echo "==> Phase 1: boot + automated link"

# Restore PDDB from backup if one exists; otherwise the next boot
# bootstraps a fresh empty PDDB. Without restoration, a successful
# previous run leaves registration data behind and we'd skip the
# fresh-link path that this phase needs to exercise.
PDDB_HOSTED_BIN="${PDDB_HOSTED_BIN:-$XOUS_CORE_DIR/tools/pddb-images/hosted.bin}"
PDDB_BACKUP_BIN="${PDDB_BACKUP_BIN:-$XOUS_CORE_DIR/tools/pddb-images/hosted_backup.bin}"
if [ "${WIPE_PDDB:-1}" = "1" ]; then
    if [ -f "$PDDB_BACKUP_BIN" ]; then
        echo "    restoring PDDB from $PDDB_BACKUP_BIN"
        cp "$PDDB_BACKUP_BIN" "$PDDB_HOSTED_BIN"
    else
        echo "    wiping $PDDB_HOSTED_BIN (no backup; fresh bootstrap)"
        rm -f "$PDDB_HOSTED_BIN"
    fi
fi

# Start pcap before xas opens any WS — captures the full link
# handshake too.
IPS="$(getent ahosts chat.signal.org storage.signal.org cdsi.signal.org \
       | awk '{print $1}' | sort -u)"
BPF_FILTER="$(echo "$IPS" | awk 'BEGIN{ORS=" or "}{print "host", $1}' \
              | sed 's/ or $//')"
IFACE="${IFACE:-$(ip route get 1.1.1.1 2>/dev/null \
                  | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}')}"
if [ -n "$IFACE" ] && [ -n "$BPF_FILTER" ]; then
    setsid nohup sudo -n tcpdump -Z "$USER" -i "$IFACE" -U -w "$PCAP" \
        "$BPF_FILTER and port 443" </dev/null \
        >"$LOG_DIR/tcpdump.log" 2>&1 &
    disown
    sleep 1
    if ! pgrep -x tcpdump >/dev/null 2>&1; then
        echo "    (pcap capture did not start; continuing without it)" >&2
    else
        echo "    pcap capturing → $PCAP (iface=$IFACE)"
    fi
else
    echo "    (no outbound iface or BPF filter; skipping pcap)"
fi

(
    cd "$XOUS_CORE_DIR"
    cargo xtask run "xas:$XAS_BIN_PATH" >"$KERNEL_LOG" 2>&1
) &
XOUS_BG_PID=$!
echo "    Xous bg PID=$XOUS_BG_PID"

# Wait for boot.
echo "    waiting up to ${BOOT_TIMEOUT}s for boot"
WAIT=0
while [ $WAIT -lt $BOOT_TIMEOUT ]; do
    if grep -q "starting main loop" "$KERNEL_LOG" 2>/dev/null; then
        echo "    boot at t=${WAIT}s"
        break
    fi
    sleep 2
    WAIT=$((WAIT + 2))
done
if ! grep -q "starting main loop" "$KERNEL_LOG" 2>/dev/null; then
    echo "FAIL: Phase 1 — Xous never booted within ${BOOT_TIMEOUT}s" >&2
    record_phase "Phase 1 (link)" "FAIL" "no boot"
    exit 3
fi
sleep 4

WIN_HEX="$(xdotool search --name "Precursor" 2>/dev/null | head -1)"
if [ -z "$WIN_HEX" ]; then
    echo "FAIL: Phase 1 — Precursor X11 window not found" >&2
    record_phase "Phase 1 (link)" "FAIL" "no X11 window"
    exit 3
fi

# Drive launcher → Apps → xas → Link.
echo "    driving keystrokes to xas"
python3 "$SCRIPT_DIR/drive_link.py" "$WIN_HEX" >"$LOG_DIR/drive.log" 2>&1
DRIVE_EC=$?
if [ $DRIVE_EC -ne 0 ]; then
    echo "FAIL: Phase 1 — keystroke driver returned $DRIVE_EC" >&2
    record_phase "Phase 1 (link)" "FAIL" "drive_link exit $DRIVE_EC"
    exit 3
fi

# Wait for the sgnl:// URL to appear in the kernel log.
echo "    waiting up to ${LINK_TIMEOUT}s for link URL emission"
WAIT=0
LINK_URL=""
while [ $WAIT -lt $LINK_TIMEOUT ]; do
    LINK_URL="$(grep -oE 'sgnl://linkdevice\?[^ ]+' "$KERNEL_LOG" 2>/dev/null | head -1)"
    if [ -n "$LINK_URL" ]; then
        echo "    link URL emitted at t=${WAIT}s"
        break
    fi
    sleep 1
    WAIT=$((WAIT + 1))
done
if [ -z "$LINK_URL" ]; then
    echo "FAIL: Phase 1 — link URL never emitted within ${LINK_TIMEOUT}s" >&2
    record_phase "Phase 1 (link)" "FAIL" "no URL"
    exit 3
fi

# Strip any trailing log decoration (amp;, ANSI, etc) so signal-cli
# receives a clean URL. The `[^ ]+` regex above already stops at
# whitespace; defensively trim a trailing ampersand-amp escape if
# the worker logged it HTML-encoded.
LINK_URL="${LINK_URL//&amp;/&}"

echo "    approving link via signal-cli addDevice"
if ! signal-cli -a "$TEST_XAS_NUMBER" addDevice --uri "$LINK_URL" \
        >>"$SIGNAL_CLI_LOG" 2>&1; then
    echo "FAIL: Phase 1 — signal-cli addDevice rejected the URL" >&2
    tail -5 "$SIGNAL_CLI_LOG" >&2
    record_phase "Phase 1 (link)" "FAIL" "addDevice failed"
    exit 3
fi

# Wait for xas to log LinkComplete.
echo "    waiting up to ${LINK_TIMEOUT}s for LinkComplete"
WAIT=0
while [ $WAIT -lt $LINK_TIMEOUT ]; do
    if grep -q "xas/gam_app: LinkComplete" "$KERNEL_LOG" 2>/dev/null; then
        echo "    LinkComplete at t=${WAIT}s"
        break
    fi
    sleep 1
    WAIT=$((WAIT + 1))
done
if ! grep -q "xas/gam_app: LinkComplete" "$KERNEL_LOG" 2>/dev/null; then
    echo "FAIL: Phase 1 — LinkComplete never logged within ${LINK_TIMEOUT}s" >&2
    record_phase "Phase 1 (link)" "FAIL" "no LinkComplete"
    exit 3
fi
record_phase "Phase 1 (link)" "PASS" "linked"

# Mark the point in the kernel log after which we count inbound
# messages — useful for the post-idle proof in Phase 6, which needs
# to ignore inbounds from Phase 3.
PHASE3_START_LINE="$(wc -l < "$KERNEL_LOG")"

# -----------------------------------------------------------------
# Phase 3: receive RECEIVE_COUNT messages from signal-cli
# -----------------------------------------------------------------
echo
echo "==> Phase 3: receive $RECEIVE_COUNT messages from signal-cli"

declare -a RECEIVE_LATENCIES_MS=()
PHASE3_PASS=0
for i in $(seq 1 "$RECEIVE_COUNT"); do
    MSG_BODY="test_send_receive phase3 msg#$i $(date +%s%N)"
    SEND_START_MS=$(date +%s%3N)
    if ! signal-cli -a "$TEST_PEER_NUMBER" send -m "$MSG_BODY" "$TEST_XAS_NUMBER" \
            >>"$SIGNAL_CLI_LOG" 2>&1; then
        echo "FAIL: Phase 3 msg #$i — signal-cli send rejected" >&2
        record_phase "Phase 3 (recv)" "FAIL" "send failed at msg #$i"
        exit 4
    fi
    # Wait for the corresponding inbound surface in the kernel log.
    WAIT=0
    SEEN=0
    while [ $WAIT -lt "$RECEIVE_TIMEOUT_PER_MSG" ]; do
        # Count "inbound message from" lines that landed after
        # PHASE3_START_LINE — each unique signal-cli send produces
        # exactly one. We require at least $i such lines.
        COUNT=$(tail -n +"$PHASE3_START_LINE" "$KERNEL_LOG" 2>/dev/null \
                | grep -c "xas/gam_app: inbound message from")
        if [ "$COUNT" -ge "$i" ]; then
            RECV_MS=$(date +%s%3N)
            RECEIVE_LATENCIES_MS+=("$((RECV_MS - SEND_START_MS))")
            SEEN=1
            break
        fi
        sleep 1
        WAIT=$((WAIT + 1))
    done
    if [ "$SEEN" -eq 0 ]; then
        echo "FAIL: Phase 3 msg #$i — never surfaced within ${RECEIVE_TIMEOUT_PER_MSG}s" >&2
        record_phase "Phase 3 (recv)" "FAIL" "msg #$i timeout"
        exit 4
    fi
done

# Compute median latency.
PHASE3_MEDIAN_MS=$(printf '%s\n' "${RECEIVE_LATENCIES_MS[@]}" \
    | sort -n | awk 'BEGIN{c=0} {a[c++]=$1} END{print a[int(c/2)]}')
echo "    received $RECEIVE_COUNT/$RECEIVE_COUNT (median ${PHASE3_MEDIAN_MS} ms)"
PHASE3_PASS=1
record_phase "Phase 3 (recv)" "PASS" "$RECEIVE_COUNT/$RECEIVE_COUNT, median=${PHASE3_MEDIAN_MS}ms"

# -----------------------------------------------------------------
# Phase 4 (DEFERRED): send N messages from xas to signal-cli
# -----------------------------------------------------------------
# Not implemented in this revision. Needs a keystroke driver for the
# compose UI (navigate to thread, focus compose, type body, send,
# return). drive_link.py covers only the navigation up to the link
# screen.
#
# Skeleton planning:
#   - extend drive_link.py (or a new drive_compose.py) to:
#       * focus the contact row in the home screen
#       * Enter → Thread view
#       * type the test body via XSendEvent
#       * Enter → send
#   - poll `signal-cli -a $TEST_PEER_NUMBER receive` for each body
#   - measure pipeline_ms in the kernel log between attempt 1 and
#     SendComplete; record median.
echo
echo "==> Phase 4: send-from-xas — DEFERRED (no compose driver yet)"
record_phase "Phase 4 (send)" "SKIP" "compose driver TBD"

# -----------------------------------------------------------------
# Phase 5: idle for one server-side reauth cycle
# -----------------------------------------------------------------
echo
echo "==> Phase 5: idle ${IDLE_DURATION}s, watch for code=4401 + Stage I"

PHASE5_START_LINE="$(wc -l < "$KERNEL_LOG")"
sleep "$IDLE_DURATION"

# Slice the kernel log for the idle window only.
IDLE_SLICE="$LOG_DIR/idle-slice.log"
tail -n +"$PHASE5_START_LINE" "$KERNEL_LOG" > "$IDLE_SLICE"

CODE_4401="$(grep -c 'websocket closed code=4401' "$IDLE_SLICE" || true)"
CODE_4409="$(grep -c 'websocket closed code=4409' "$IDLE_SLICE" || true)"
CODE_1001="$(grep -c 'websocket closed code=1001' "$IDLE_SLICE" || true)"
SETTLING="$(grep -c 'prev_close=Some(4401).*extra_delay_ms=10000' "$IDLE_SLICE" || true)"
AUTH_EXPIRED="$(grep -c 'Event::SignalAuthExpired' "$IDLE_SLICE" || true)"
CONFLICTING="$(grep -c 'Event::SignalConflictingDevice' "$IDLE_SLICE" || true)"
LOOP_403="$(grep -c '4401-then-403' "$IDLE_SLICE" || true)"

echo "    code=4401 closes: $CODE_4401"
echo "    code=4409 closes: $CODE_4409"
echo "    code=1001 closes: $CODE_1001"
echo "    Stage I settling-delay log lines: $SETTLING"
echo "    4401-then-403 markers: $LOOP_403"
echo "    SignalAuthExpired emits: $AUTH_EXPIRED"
echo "    SignalConflictingDevice emits: $CONFLICTING"

# Pass criterion (per design doc): no indefinite 403 loop. Either
# receive resumed (next phase verifies), OR SignalAuthExpired fired.
# If 4401 fired AND 4401-then-403 markers exist BUT no
# SignalAuthExpired emit AND no receive_messages OK since the last
# 4401, that's a Stage I failure.
PHASE5_PASS=1
if [ "$CODE_4401" -gt 0 ]; then
    LAST_4401_LINE_REL=$(grep -n 'websocket closed code=4401' "$IDLE_SLICE" | tail -1 | cut -d: -f1)
    POST_4401_OK=$(tail -n +"$LAST_4401_LINE_REL" "$IDLE_SLICE" \
                   | grep -c 'receive_messages OK' || true)
    if [ "$POST_4401_OK" -eq 0 ] && [ "$AUTH_EXPIRED" -eq 0 ]; then
        echo "FAIL: Phase 5 — 4401 fired but no recovery (no receive_messages OK and no SignalAuthExpired)" >&2
        PHASE5_PASS=0
    fi
fi

if [ "$PHASE5_PASS" -eq 1 ]; then
    record_phase "Phase 5 (idle)" "PASS" \
        "4401=$CODE_4401 4409=$CODE_4409 1001=$CODE_1001 stage1-recovered"
else
    record_phase "Phase 5 (idle)" "FAIL" \
        "4401=$CODE_4401 no-recovery"
    exit 5
fi

# -----------------------------------------------------------------
# Phase 6: post-idle receive proof
# -----------------------------------------------------------------
echo
echo "==> Phase 6: post-idle receive proof"
PHASE6_START_LINE="$(wc -l < "$KERNEL_LOG")"
PHASE6_BODY="test_send_receive phase6 $(date +%s%N)"
if ! signal-cli -a "$TEST_PEER_NUMBER" send -m "$PHASE6_BODY" "$TEST_XAS_NUMBER" \
        >>"$SIGNAL_CLI_LOG" 2>&1; then
    echo "FAIL: Phase 6 — signal-cli send rejected" >&2
    record_phase "Phase 6 (post-idle)" "FAIL" "send rejected"
    exit 6
fi
WAIT=0
SEEN=0
while [ $WAIT -lt "$RECEIVE_TIMEOUT_PER_MSG" ]; do
    COUNT=$(tail -n +"$PHASE6_START_LINE" "$KERNEL_LOG" 2>/dev/null \
            | grep -c "xas/gam_app: inbound message from")
    if [ "$COUNT" -ge 1 ]; then
        SEEN=1
        break
    fi
    sleep 1
    WAIT=$((WAIT + 1))
done
if [ "$SEEN" -eq 0 ]; then
    echo "FAIL: Phase 6 — post-idle inbound never surfaced within ${RECEIVE_TIMEOUT_PER_MSG}s" >&2
    record_phase "Phase 6 (post-idle)" "FAIL" "no inbound after idle"
    exit 6
fi
record_phase "Phase 6 (post-idle)" "PASS" "surfaced within ${WAIT}s"

# -----------------------------------------------------------------
# Final summary
# -----------------------------------------------------------------
echo
echo "==> SUMMARY"
column -t -s $'\t' "$SUMMARY"
echo
echo "PASS: all phases completed."
exit 0
