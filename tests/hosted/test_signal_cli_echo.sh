#!/usr/bin/env bash
# Phase 0: signal-cli bidirectional echo. Catches bad account state
# BEFORE we waste cycles on xas. Two directions, one marker each,
# timed.
#
# See tests/hosted/test_env.example for TEST_PEER_NUMBER (NL peer)
# and TEST_XAS_NUMBER (US primary that xas links to as a secondary).
# Both must be registered + operational on local signal-cli; see
# `signal-cli --output=plain-text listAccounts`.
#
# Exit codes:
#   0 — both directions PASS (<10 s)
#   1 — only NL→US PASS
#   2 — only US→NL PASS
#   3 — neither direction PASS
#   64 — setup / prerequisite failure

set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test_helpers.sh
source "$SCRIPT_DIR/test_helpers.sh"

ECHO_TIMEOUT="${ECHO_TIMEOUT:-30}"
ECHO_PASS_LATENCY_MS="${ECHO_PASS_LATENCY_MS:-10000}"

LOG_DIR="$(mktemp -d -t xas-signal-cli-echo.XXXXXX)"
NL_TO_US_LOG="$LOG_DIR/nl-to-us.log"
US_TO_NL_LOG="$LOG_DIR/us-to-nl.log"

cleanup() {
    if [ "${KEEP_LOGS:-0}" = "1" ]; then
        echo "Logs preserved: $LOG_DIR" >&2
    else
        rm -rf "$LOG_DIR"
    fi
}
trap cleanup EXIT

echo "==> tests/hosted/test_signal_cli_echo.sh"
echo "    LOG_DIR=$LOG_DIR"

if ! xas_load_env; then
    echo "ERROR: tests/hosted/test_env not found (copy from test_env.example)" >&2
    exit 64
fi
xas_require_env TEST_PEER_NUMBER TEST_XAS_NUMBER || exit 64
xas_require_cmd signal-cli || exit 64
xas_require_cmd python3 || exit 64

# Verify both accounts are listed locally — failures here mean the
# user hasn't registered one or both, which would surface as a
# confusing "send failed" in the test body.
if ! signal-cli -a "$TEST_PEER_NUMBER" listDevices >/dev/null 2>&1; then
    echo "ERROR: TEST_PEER_NUMBER not registered on local signal-cli" >&2
    exit 64
fi
if ! signal-cli -a "$TEST_XAS_NUMBER" listDevices >/dev/null 2>&1; then
    echo "ERROR: TEST_XAS_NUMBER not registered on local signal-cli" >&2
    exit 64
fi

# Run one direction: sender sends a marker, receiver polls until the
# marker appears in the receive output (or times out). Emits the
# observed latency in ms. Returns 0 on PASS, 1 on FAIL.
#
# Args:
#   $1 — sender account (signal-cli -a)
#   $2 — receiver account (signal-cli -a)
#   $3 — label (printed in marker + log)
#   $4 — log file
run_direction() {
    local sender="$1" receiver="$2" label="$3" log="$4"
    local marker="echo-${label}-$(date +%s%N)-$RANDOM"
    local send_ms recv_ms latency_ms

    echo "--- $label ---" >>"$log"
    echo "marker=$marker" >>"$log"

    send_ms=$(date +%s%3N)
    if ! signal-cli -a "$sender" send -m "$marker" "$receiver" \
            >>"$log" 2>&1; then
        echo "  $label: SEND FAILED (sender=$sender)"
        return 1
    fi

    # Poll receive in 5 s chunks until the marker shows up or we
    # hit ECHO_TIMEOUT. Successive receive calls each grab any
    # messages queued since the last call, so we don't lose the
    # echo even if it arrives between polls.
    local waited=0
    while [ "$waited" -lt "$ECHO_TIMEOUT" ]; do
        local chunk=5
        if [ "$((waited + chunk))" -gt "$ECHO_TIMEOUT" ]; then
            chunk=$((ECHO_TIMEOUT - waited))
        fi
        # `receive --timeout N` polls for ~N seconds then returns
        # what was received in that window.
        if signal-cli -a "$receiver" receive --timeout "$chunk" \
                >>"$log" 2>&1; then
            if grep -qF "$marker" "$log"; then
                recv_ms=$(date +%s%3N)
                latency_ms=$((recv_ms - send_ms))
                echo "  $label: PASS latency=${latency_ms}ms"
                return 0
            fi
        fi
        waited=$((waited + chunk))
    done
    echo "  $label: FAIL — marker never appeared in receive within ${ECHO_TIMEOUT}s"
    return 1
}

# Drain any pending messages on both accounts first so leftover
# traffic from previous tests doesn't false-match a fresh marker.
echo "==> draining pending receive on both accounts"
signal-cli -a "$TEST_XAS_NUMBER" receive --timeout 2 >>"$LOG_DIR/drain.log" 2>&1 || true
signal-cli -a "$TEST_PEER_NUMBER" receive --timeout 2 >>"$LOG_DIR/drain.log" 2>&1 || true

echo
echo "==> NL → US"
NL_US_RC=0
run_direction "$TEST_PEER_NUMBER" "$TEST_XAS_NUMBER" "NL-to-US" "$NL_TO_US_LOG" \
    || NL_US_RC=1

echo
echo "==> US → NL"
US_NL_RC=0
run_direction "$TEST_XAS_NUMBER" "$TEST_PEER_NUMBER" "US-to-NL" "$US_TO_NL_LOG" \
    || US_NL_RC=1

echo
echo "==> RESULT"
if [ "$NL_US_RC" -eq 0 ] && [ "$US_NL_RC" -eq 0 ]; then
    echo "PASS: both directions deliver"
    exit 0
elif [ "$NL_US_RC" -eq 0 ]; then
    echo "FAIL: NL→US works, US→NL broken" >&2
    exit 2
elif [ "$US_NL_RC" -eq 0 ]; then
    echo "FAIL: US→NL works, NL→US broken" >&2
    exit 1
else
    echo "FAIL: both directions broken" >&2
    exit 3
fi
