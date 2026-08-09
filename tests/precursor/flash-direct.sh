#!/usr/bin/env bash
# Flash a built xous.img to a Precursor PVT2 directly from this host
# (no Raspberry Pi). Use this when you don't have the Pi rig.
#
# Prerequisites:
#   - Precursor in loader window connected via USB to THIS host
#   - lsusb shows 1209:5bf0
#   - bash tests/precursor/build-and-bundle.sh has produced xous.img
#   - You have permission to talk to USB device 1209:5bf0
#     (a udev rule is the right long-term answer; sudo is the
#      short-term escape hatch)
#
# SAFETY:
#   - Kernel-only flash (-k). Recoverable via USB if anything goes wrong.
#     Do not edit this script to add -l or --soc/--factory-reset
#     without reading tests/precursor/README.md "Brick prevention" first.
#   - This ties up your laptop for ~25 minutes. The Pi-rig variant
#     (flash-via-pi.sh) frees the laptop during the flash.
#
# Env vars (defaults shown):
#   XOUS_CORE_DIR=../xous-core
#   XOUS_TARGET=riscv32imac-unknown-xous-elf
#   FLASH_LOG=/tmp/flash-$(date +%s).log
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
XOUS_CORE_DIR="${XOUS_CORE_DIR:-$REPO_ROOT/../xous-core}"
XOUS_TARGET="${XOUS_TARGET:-riscv32imac-unknown-xous-elf}"
FLASH_LOG="${FLASH_LOG:-/tmp/flash-$(date +%s).log}"

XOUS_IMG="$XOUS_CORE_DIR/target/$XOUS_TARGET/release/xous.img"
USB_UPDATE="$XOUS_CORE_DIR/tools/usb_update.py"

if [[ ! -f "$XOUS_IMG" ]]; then
    echo "ERROR: $XOUS_IMG not found. Run tests/precursor/build-and-bundle.sh first." >&2
    exit 1
fi

if [[ ! -f "$USB_UPDATE" ]]; then
    echo "ERROR: $USB_UPDATE not found." >&2
    echo "Set XOUS_CORE_DIR to your xous-core checkout." >&2
    exit 1
fi

echo "==> Checking Precursor visibility on this host"
if ! lsusb | grep -q "1209:5bf0"; then
    echo "ERROR: Precursor not seen as 1209:5bf0." >&2
    echo "  - Check device is in loader window (hold power for 5s during boot)" >&2
    echo "  - Check USB cable is data-capable" >&2
    exit 1
fi
echo "    OK — 1209:5bf0 present"

echo "==> Flashing kernel-only (-k --bounce)"
echo "    image: $XOUS_IMG"
echo "    log:   $FLASH_LOG"
echo "    expect ~25 min; do not unplug the Precursor"
echo

# Don't pipe through tee/head — it would close stdin and break usb_update.py.
# Redirect to file; tail at the end. -k = kernel only (recoverable).
python3 "$USB_UPDATE" -k "$XOUS_IMG" --bounce > "$FLASH_LOG" 2>&1
RC=$?

echo "==> Flash command exited with code $RC"
echo "    Last 30 lines of flash log:"
tail -30 "$FLASH_LOG"

if [[ $RC -ne 0 ]]; then
    echo
    echo "Flash FAILED. Full log: $FLASH_LOG" >&2
    exit $RC
fi

echo
echo "==> Flash complete. Precursor should reboot into the new kernel."
