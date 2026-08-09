#!/usr/bin/env bash
# Build xas + bundle a kernel image for Precursor PVT2 hardware.
#
# Output: <xous-core>/target/<target>/release/xous.img
#
# Env vars (defaults shown):
#   XOUS_CORE_DIR=../xous-core
#   XOUS_TARGET=riscv32imac-unknown-xous-elf
#   BUILD_LOG=/tmp/xous-build-$(date +%s).log
#
# Safe to re-run; cargo will skip unchanged crates.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
XOUS_CORE_DIR="${XOUS_CORE_DIR:-$REPO_ROOT/../xous-core}"
XOUS_TARGET="${XOUS_TARGET:-riscv32imac-unknown-xous-elf}"
BUILD_LOG="${BUILD_LOG:-/tmp/xous-build-$(date +%s).log}"
# SoC version pins. Override per device via env: see `lsusb -v | grep iSerial`
# while Precursor is in loader mode. Defaults match the latest stable PVT2 SoC
# documented in BUILDING.md §3.2.
GIT_DESCRIBE="${GIT_DESCRIBE:-v0.9.8-791-gc707f9d8}"
GIT_REV="${GIT_REV:-c707f9d8}"

if [[ ! -d "$XOUS_CORE_DIR" ]]; then
    echo "ERROR: xous-core not found at $XOUS_CORE_DIR" >&2
    echo "Set XOUS_CORE_DIR to your xous-core checkout." >&2
    exit 1
fi

# Preflight: gam's apps.rs must already register APP_NAME_XAS or the
# cargo build will fail with E0425 (or, worse, succeed with a bundle
# whose launcher doesn't see Signal — see BUILDING.md §2.1 and the
# §3 branch-selection note). Most common cause: xous-core checked out
# on a branch (e.g. dev) whose apps/manifest.json doesn't list xas.
APPS_RS="$XOUS_CORE_DIR/services/gam/src/apps.rs"
if [[ ! -f "$APPS_RS" ]] || ! grep -q '\bAPP_NAME_XAS\b' "$APPS_RS"; then
    echo "ERROR: $APPS_RS missing or lacks APP_NAME_XAS." >&2
    echo "  This is required by crates/xous-app-signal/src/gam_app.rs." >&2
    echo "  Likely cause: xous-core is on a branch whose apps/manifest.json" >&2
    echo "  doesn't register xas (e.g. dev). Switch to a branch that does" >&2
    echo "  (tunnell/xous-core@xas-integration), or hand-bootstrap apps.rs per" >&2
    echo "  BUILDING.md §2.1." >&2
    exit 1
fi

XAS_BIN="$REPO_ROOT/target/riscv32imac-unknown-xous-elf/release/xas"

echo "==> Building xas (release, hardware target)"
echo "    repo:        $REPO_ROOT"
echo "    xous-core:   $XOUS_CORE_DIR"
echo "    target:      $XOUS_TARGET"
echo "    build log:   $BUILD_LOG"
echo

# Step 1: build xas itself with the hardware sysroot.
cd "$REPO_ROOT"
cargo build --release \
    --target riscv32imac-unknown-xous-elf \
    -p xous-app-signal \
    --features pddb-real,precursor \
    > "$BUILD_LOG" 2>&1 || {
        echo "xas build FAILED — see $BUILD_LOG" >&2
        tail -50 "$BUILD_LOG" >&2
        exit 1
    }

if [[ ! -f "$XAS_BIN" ]]; then
    echo "ERROR: expected xas binary not found at $XAS_BIN" >&2
    echo "Check $BUILD_LOG for build errors." >&2
    exit 1
fi

echo "==> xas built: $XAS_BIN ($(du -h "$XAS_BIN" | cut -f1))"

# Step 2: bundle into a xous.img alongside vault + transientdisk.
# `xas:$XAS_BIN` (with the `xas:` prefix) is required — without it,
# xtask's CrateSpec parser records `name = None` and never adds xas
# to app_names. `vault` and `transientdisk` are co-resident apps
# matched by manifest.json entries on the xous-core fork.
echo "==> Bundling kernel image (cargo xtask app-image-xip)"
cd "$XOUS_CORE_DIR"
cargo xtask app-image-xip \
    "xas:$XAS_BIN" \
    vault \
    transientdisk \
    --kernel-feature big-heap \
    --gdb-stub \
    --git-describe "$GIT_DESCRIBE" \
    --git-rev "$GIT_REV" \
    >> "$BUILD_LOG" 2>&1 || {
        echo "image bundling FAILED — see $BUILD_LOG" >&2
        tail -50 "$BUILD_LOG" >&2
        exit 1
    }

XOUS_IMG="$XOUS_CORE_DIR/target/$XOUS_TARGET/release/xous.img"
if [[ ! -f "$XOUS_IMG" ]]; then
    echo "ERROR: expected xous.img not found at $XOUS_IMG" >&2
    echo "Check XOUS_TARGET (currently '$XOUS_TARGET')." >&2
    exit 1
fi

SHA="$(sha256sum "$XOUS_IMG" | cut -c1-12)"
SIZE="$(du -h "$XOUS_IMG" | cut -f1)"
echo
echo "==> Built kernel image:"
echo "    path:    $XOUS_IMG"
echo "    size:    $SIZE"
echo "    sha256:  ${SHA}…"
echo
echo "Next: bash tests/precursor/flash-via-pi.sh   (or flash-direct.sh)"
