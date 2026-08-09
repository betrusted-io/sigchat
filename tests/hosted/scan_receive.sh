#!/usr/bin/env bash
# tests/hosted/scan_receive.sh
#
# Hosted-mode receive test. signal-cli sends a uniquely-marked
# message; xas's worker should pull it off the WS, decrypt, and
# emit `Event::Message` (logged as "xas/gam_app: inbound message
# from <uuid>").
#
# *** PRECONDITION (hosted mode has no link persistence yet) ***
#
# This script does NOT link xas — it assumes xas was just linked
# in the *previous* run of this same kernel boot, and the worker is
# still alive holding a Manager<Registered> in memory.
#
# Practical workflow until hosted-PDDB-persistence lands (TESTING_SIGNAL_CLI.md):
#   1. Boot hosted xas: cargo xtask run xas:.../target/release/xas
#   2. Drive Link, scan QR with the test phone, accept on phone.
#   3. While the SAME kernel is still up, run this script in another
#      terminal. It will signal-cli send → and watch the kernel's
#      stdout log file for the inbound message line.
#
# Args: $1 = path to the kernel's stdout log file (e.g. the file
#       cargo xtask is writing to).
#       $2 = optional message body (default: "Test").
#
# Exit codes:
#   0 = inbound observed in log within timeout
#   1 = no inbound seen; signal-cli send may have failed too
#   2 = setup failure (env, prerequisites, log file missing)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test_helpers.sh
source "$SCRIPT_DIR/test_helpers.sh"

KERNEL_LOG="${1:-}"
MESSAGE_TEXT="${2:-Test}"

if [[ -z "$KERNEL_LOG" ]]; then
    echo "usage: scan_receive.sh <kernel-log-path> [message-text]" >&2
    exit 2
fi
if [[ ! -f "$KERNEL_LOG" ]]; then
    echo "Kernel log not found: $KERNEL_LOG" >&2
    echo "Pass the file cargo xtask run is writing to." >&2
    exit 2
fi

if ! xas_load_env; then
    echo "tests/hosted/test_env not found." >&2
    echo "Copy test_env.example -> test_env and configure." >&2
    exit 2
fi

xas_require_env TEST_PEER_NUMBER TEST_XAS_NUMBER || exit 2
xas_require_cmd signal-cli || exit 2

# Topology pre-check: signal-cli must be linked on the peer account.
# If signal-cli isn't on the right account we'd be sending from the
# wrong identity and the test would silently false-fail.
echo "=== Topology check ==="
if ! xas_verify_linked_device "$TEST_PEER_NUMBER" "signal-cli"; then
    echo "Topology check failed." >&2
    exit 2
fi
echo ""

# Gate: refuse to send until the worker is in receive mode. Look for
# the diagnostic line (added in xous-signal-worker for the receive
# debug session). If the user hasn't linked yet, this never appears
# and we time out — exit 2 with a clear hint.
echo "=== Waiting for xas receive loop to be up ==="
WAIT=0
while (( WAIT < 60 )); do
    if grep -q "manager_task — receive_messages OK" "$KERNEL_LOG" 2>/dev/null; then
        echo "  Receive stream open at t=${WAIT}s"
        break
    fi
    sleep 2
    WAIT=$((WAIT + 2))
done
if ! grep -q "manager_task — receive_messages OK" "$KERNEL_LOG" 2>/dev/null; then
    echo "ERROR: worker never reached receive_messages OK." >&2
    echo "  Did you link xas yet? Hosted mode currently doesn't" >&2
    echo "  persist link state across boots — re-link via the GAM" >&2
    echo "  menu in this same kernel before running this script." >&2
    exit 2
fi
echo ""

# Per-run unique marker so we don't false-positive on stale log lines.
TS=$(date +%s)
MARKER="${MESSAGE_TEXT} [recv-${TS}]"

# Pre-step: clear signal-cli's session for the xas UUID so the next
# send issues a fresh PreKey-bundle. Without this, signal-cli reuses
# its stored session and emits a SignalMessage which a freshly-linked
# xas may not be able to decrypt cleanly. (B2-sibling priming flake
# from the previous project.)
echo "=== Clearing signal-cli session for $TEST_XAS_NUMBER ==="
xas_clear_signal_cli_sessions "$TEST_PEER_NUMBER" "$TEST_XAS_NUMBER" || true
echo ""

# Note where in the log we are now, so we don't false-positive on
# inbound events from earlier in the kernel's life.
LOG_OFFSET=$(wc -c < "$KERNEL_LOG")

echo "=== Sending marker via signal-cli ==="
echo "$ signal-cli -a $TEST_PEER_NUMBER send -m '$MARKER' $TEST_XAS_NUMBER"
if ! signal-cli -a "$TEST_PEER_NUMBER" send -m "$MARKER" "$TEST_XAS_NUMBER"; then
    echo "ERROR: signal-cli send failed" >&2
    exit 1
fi
echo ""

echo "=== Watching kernel log for inbound (90s timeout) ==="
WAIT=0
FOUND=""
while (( WAIT < 90 )); do
    # Tail from the offset we recorded above so we only see new lines.
    FOUND="$(tail -c +"$((LOG_OFFSET + 1))" "$KERNEL_LOG" 2>/dev/null \
        | grep -F "inbound message from" | head -1 || true)"
    if [[ -n "$FOUND" ]]; then
        break
    fi
    sleep 5
    WAIT=$((WAIT + 5))
done

if [[ -z "$FOUND" ]]; then
    echo "RESULT: FAIL (no inbound message log line in 90s)"
    echo ""
    echo "Last 10 worker/manager_task lines:"
    grep -E "worker:|manager_task" "$KERNEL_LOG" | tail -10
    exit 1
fi

echo "=== Match found ==="
echo "$FOUND"
echo ""
echo "RESULT: PASS"
exit 0
