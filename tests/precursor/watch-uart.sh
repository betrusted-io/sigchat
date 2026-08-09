#!/usr/bin/env bash
# Tail the UART log captured by a long-running screen session on the Pi.
#
# Prerequisites:
#   - PI_HOST set
#   - A screen session named 'uart' already running on the Pi against
#     the UART tty (e.g., /dev/ttyAMA0) writing to $PI_UART_LOG.
#     Set this up once on the Pi:
#       mkdir -p ~/uart-logs
#       screen -dmS uart -L -Logfile ~/uart-logs/precursor-uart.log /dev/ttyAMA0 115200
#
# Env vars (defaults shown):
#   PI_HOST=         (required)
#   PI_UART_LOG=~/uart-logs/precursor-uart.log
#   FOLLOW=1         (1 = tail -f, 0 = print last 200 lines and exit)
set -euo pipefail

PI_UART_LOG="${PI_UART_LOG:-~/uart-logs/precursor-uart.log}"
FOLLOW="${FOLLOW:-1}"

if [[ -z "${PI_HOST:-}" ]]; then
    echo "ERROR: PI_HOST not set." >&2
    echo "  export PI_HOST=pi@10.0.0.42" >&2
    exit 1
fi

# Confirm screen session is alive.
if ! ssh "$PI_HOST" 'screen -ls | grep -q "\.uart"'; then
    echo "WARNING: no screen session named 'uart' on $PI_HOST." >&2
    echo "  Start one with:" >&2
    echo "    ssh $PI_HOST 'mkdir -p ~/uart-logs && screen -dmS uart -L -Logfile ~/uart-logs/precursor-uart.log /dev/ttyAMA0 115200'" >&2
    echo "  Continuing — will tail the log file if it exists." >&2
fi

if ! ssh "$PI_HOST" "test -f $PI_UART_LOG"; then
    echo "ERROR: $PI_UART_LOG does not exist on $PI_HOST." >&2
    echo "  The screen session is probably not writing to where this script expects." >&2
    echo "  Override with:  PI_UART_LOG=/some/other/path bash tests/precursor/watch-uart.sh" >&2
    exit 1
fi

if [[ "$FOLLOW" == "1" ]]; then
    echo "==> tailing $PI_HOST:$PI_UART_LOG (Ctrl-C to stop)"
    ssh "$PI_HOST" "tail -F $PI_UART_LOG"
else
    echo "==> last 200 lines of $PI_HOST:$PI_UART_LOG"
    ssh "$PI_HOST" "tail -200 $PI_UART_LOG"
fi
