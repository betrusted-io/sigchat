#!/usr/bin/env bash
# Flash a built xous.img to a Precursor PVT2 via a Raspberry Pi rig.
#
# The Pi-side flash runs DETACHED (screen + nohup), so a dropped SSH
# connection cannot HUP a mid-write flash. This pattern was verified on
# hardware 2026-07-31: 22.5 min kernel-only flash, launch connection
# closed immediately, polled to completion, FLASH_RC=0, device booted.
# (usb_update.py's -k path never reads stdin — its input() prompts are
# only on the --enable-boot-wipe/--soc/--factory-new paths — so running
# it under nohup with stdin on /dev/null is safe.)
#
# Prerequisites:
#   - PI_HOST set (e.g., pi@10.0.0.42)
#   - usb_update.py already copied to $PI_FLASH_DIR on the Pi (see
#     tests/precursor/README.md "One-time Pi rig setup")
#   - screen installed on the Pi (apt-get install screen)
#   - Precursor in the loader window: lsusb on the Pi shows 1209:5bf0
#   - bash tests/precursor/build-and-bundle.sh has produced xous.img
#
# This script:
#   1. scp's xous.img to the Pi
#   2. Launches `python3 usb_update.py -k xous.img --bounce` on the Pi
#      inside a detached screen session, output to $FLASH_LOG, with an
#      `echo FLASH_RC=$?` sentinel appended when the flash exits
#   3. Polls session liveness + log tail every $POLL_INTERVAL seconds
#   4. Recovers the exit status from the FLASH_RC sentinel
#
# SAFETY:
#   - ONLY -k (kernel-only). Kernel-only is recoverable via USB. Never
#     edit this script to add -l or --soc/--factory-reset without
#     reading tests/precursor/README.md "Brick prevention" first.
#   - The flash takes ~25 minutes. Don't unplug the Precursor.
#   - This script NEVER kills a flash session — not on timeout, not on
#     poll failure. Interrupting a mid-write flash leaves the device
#     unbootable until reflashed. If a previous flash session is still
#     alive, the script refuses to start (it does not reap it).
#
# Env vars (defaults shown):
#   PI_HOST=          (required)
#   PI_FLASH_DIR=~/xous-flash
#   XOUS_CORE_DIR=../xous-core
#   XOUS_TARGET=riscv32imac-unknown-xous-elf
#   FLASH_LOG=$PI_FLASH_DIR/flash-$(date +%s).log   (on the Pi; /tmp is
#                     tmpfs on Raspberry Pi OS — logs there die on reboot)
#   FLASH_TIMEOUT=2700   seconds to poll before giving up (flash keeps
#                        running on the Pi regardless)
#   POLL_INTERVAL=30
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
XOUS_CORE_DIR="${XOUS_CORE_DIR:-$REPO_ROOT/../xous-core}"
XOUS_TARGET="${XOUS_TARGET:-riscv32imac-unknown-xous-elf}"
PI_FLASH_DIR="${PI_FLASH_DIR:-~/xous-flash}"
STAMP="$(date +%s)"
FLASH_LOG="${FLASH_LOG:-$PI_FLASH_DIR/flash-$STAMP.log}"
FLASH_TIMEOUT="${FLASH_TIMEOUT:-2700}"
POLL_INTERVAL="${POLL_INTERVAL:-30}"
SESSION="xas_flash_$STAMP"

if [[ -z "${PI_HOST:-}" ]]; then
    echo "ERROR: PI_HOST not set." >&2
    echo "  export PI_HOST=pi@10.0.0.42" >&2
    exit 1
fi

XOUS_IMG="$XOUS_CORE_DIR/target/$XOUS_TARGET/release/xous.img"
if [[ ! -f "$XOUS_IMG" ]]; then
    echo "ERROR: $XOUS_IMG not found. Run tests/precursor/build-and-bundle.sh first." >&2
    exit 1
fi

# Confirm the Precursor is visible on the Pi BEFORE we copy anything.
echo "==> Checking Precursor visibility on $PI_HOST"
if ! ssh "$PI_HOST" 'lsusb | grep -q "1209:5bf0"'; then
    echo "ERROR: Precursor not seen as 1209:5bf0 on the Pi." >&2
    echo "  - Check the device is in the loader window" >&2
    echo "  - Check USB cable is data-capable, not power-only" >&2
    echo "  - Check it's plugged into the Pi, not the laptop" >&2
    exit 1
fi
echo "    OK — 1209:5bf0 present"

echo "==> Checking screen + usb_update.py on $PI_HOST"
if ! ssh "$PI_HOST" 'command -v screen >/dev/null'; then
    echo "ERROR: screen not installed on the Pi (sudo apt-get install screen)." >&2
    exit 1
fi
if ! ssh "$PI_HOST" "test -f $PI_FLASH_DIR/usb_update.py"; then
    echo "ERROR: $PI_FLASH_DIR/usb_update.py not found on Pi." >&2
    echo "  Copy it once with:" >&2
    echo "    scp $XOUS_CORE_DIR/tools/usb_update.py $PI_HOST:$PI_FLASH_DIR/" >&2
    exit 1
fi
echo "    OK"

# Refuse to start if a previous xas_flash_* session is still alive.
# Deliberately NOT auto-killed: it could be a live flash from another
# terminal or operator. (`screen -wipe` only clears Dead entries.)
echo "==> Checking for live flash sessions on the Pi"
ssh "$PI_HOST" 'screen -wipe >/dev/null 2>&1 || true'
if ssh "$PI_HOST" 'screen -ls 2>/dev/null | grep -q "\.xas_flash_"'; then
    echo "ERROR: a previous xas_flash_* screen session is still alive on the Pi:" >&2
    ssh "$PI_HOST" 'screen -ls | grep "\.xas_flash_"' >&2
    echo "  If (and only if) you are certain it is not a live flash, end it with:" >&2
    echo "    ssh $PI_HOST 'screen -S <name> -X quit'" >&2
    exit 1
fi
echo "    OK — none"

echo "==> scp'ing xous.img to $PI_HOST:$PI_FLASH_DIR/"
scp "$XOUS_IMG" "$PI_HOST:$PI_FLASH_DIR/xous.img"

echo "==> Launching detached kernel-only flash (-k --bounce)"
echo "    session:   $SESSION"
echo "    log on Pi: $FLASH_LOG"
echo "    expect ~25 min; do not unplug the Precursor"
echo
ssh "$PI_HOST" "screen -dmS $SESSION bash -c 'cd $PI_FLASH_DIR && nohup python3 usb_update.py -k xous.img --bounce > $FLASH_LOG 2>&1; echo FLASH_RC=\$? >> $FLASH_LOG'"

if ! ssh "$PI_HOST" "screen -ls | grep -q '\.$SESSION'"; then
    # Very short flashes could legitimately finish already; check sentinel.
    if ! ssh "$PI_HOST" "grep -aq 'FLASH_RC=' $FLASH_LOG 2>/dev/null"; then
        echo "ERROR: flash session failed to start (no session, no log sentinel)." >&2
        exit 1
    fi
fi

# Poll. Tolerate transient SSH failures; NEVER kill the session.
# (grep -a / tr -d '\0': the log can contain stray binary bytes.)
ELAPSED=0
MISS=0
while (( ELAPSED < FLASH_TIMEOUT )); do
    if OUT=$(ssh -o ConnectTimeout=10 "$PI_HOST" "screen -ls 2>/dev/null; echo '---'; tail -c 300 $FLASH_LOG 2>/dev/null | tr -d '\0' | tail -c 120" 2>/dev/null); then
        MISS=0
        printf '    [%4ds] %s\n' "$ELAPSED" "$(echo "$OUT" | tail -1)"
        if ! echo "$OUT" | grep -q "\.$SESSION"; then
            break   # session ended — flash finished (or died); check sentinel
        fi
    else
        MISS=$((MISS + 1))
        echo "    [${ELAPSED}s] SSH poll failed ($MISS consecutive) — flash continues on the Pi"
        if (( MISS >= 10 )); then
            echo "ERROR: Pi unreachable for $((MISS * POLL_INTERVAL))s. The flash is still" >&2
            echo "running Pi-side. Re-check later with:" >&2
            echo "  ssh $PI_HOST 'screen -ls; grep -ao FLASH_RC=[0-9]* $FLASH_LOG | tail -1'" >&2
            exit 1
        fi
    fi
    sleep "$POLL_INTERVAL"
    ELAPSED=$((ELAPSED + POLL_INTERVAL))
done

if (( ELAPSED >= FLASH_TIMEOUT )); then
    echo "ERROR: flash still running after ${FLASH_TIMEOUT}s. NOT killing it —" >&2
    echo "interrupting a mid-write flash is brick-adjacent. Inspect with:" >&2
    echo "  ssh $PI_HOST 'screen -ls; tail -30 $FLASH_LOG'" >&2
    exit 1
fi

# Recover the exit status from the sentinel (screen swallows it).
RC_LINE="$(ssh "$PI_HOST" "grep -ao 'FLASH_RC=[0-9]*' $FLASH_LOG | tail -1" || true)"
echo
echo "==> Flash session ended. Last 30 lines of flash log:"
ssh "$PI_HOST" "tail -30 $FLASH_LOG | tr -d '\0'"

if [[ -z "$RC_LINE" ]]; then
    echo "ERROR: no FLASH_RC sentinel in $FLASH_LOG — flash outcome unknown." >&2
    echo "  Inspect: ssh $PI_HOST 'cat $FLASH_LOG'" >&2
    exit 1
fi
RC="${RC_LINE#FLASH_RC=}"
if [[ "$RC" != "0" ]]; then
    echo "Flash FAILED (usb_update.py exit $RC). Full log:" >&2
    echo "  ssh $PI_HOST 'cat $FLASH_LOG'" >&2
    exit "$RC"
fi

echo
echo "==> Flash complete (FLASH_RC=0). Precursor reboots into the new kernel."
echo "    Watch UART:  bash tests/precursor/watch-uart.sh"
