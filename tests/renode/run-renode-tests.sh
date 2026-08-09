#!/usr/bin/env bash
# Renode test runner wrapper for the xas suite.
#
# For each requested robot, builds the xas rv32 ELF with the FEATURE SET
# THAT ROBOT EXPECTS (see the map below), re-bundles loader.bin/xous.img
# into the xous-core checkout ONLY when the (features, ELF) pair actually
# changed, then invokes `renode-test` against the robot. All robots boot
# the CI-grade tests/renode/xas-ci.resc machine (headless SoC + EC pair,
# per-run 0xFF flash scratch file, file-backed UART logs under
# target/xas-ci/).
#
# Usage:
#   tests/renode/run-renode-tests.sh                    # xas-smoke.robot
#   tests/renode/run-renode-tests.sh xas-probe.robot    # one robot
#   tests/renode/run-renode-tests.sh xas-smoke xas-probe
#   tests/renode/run-renode-tests.sh --all              # all 8, serially,
#                                                       # with a summary
#                                                       # table; ends by
#                                                       # restoring the
#                                                       # canonical image
#
# Feature map (robot -> cargo features for the xas ELF):
#   xas-smoke / xas-bulk-write-boot / xas-selective-sync /
#   xas-instrument-noise ........ pddb-real,precursor   (canonical)
#   xas-pddb-probe .............. precursor,probe-pddb
#   xas-probe ................... precursor,probe-flow
#   xas-send-batch .............. precursor,probe-send-batch
#   xas-echo .................... precursor,probe-echo
#                                 + IMAGE feature net/renode-minimal:
#                                 the kernel tree must be xous-core
#                                 branch xas-integration-net (or any
#                                 branch whose net service has that
#                                 feature; the bundle fails loudly
#                                 otherwise)
#
# Environment (defaults shown):
#   RENODE=renode-test          — renode-test binary
#   RENODE_CI_MODE=YES          — exported; keeps any showAnalyzer-style
#                                 path headless (xas-ci.resc is headless
#                                 by construction, but CI mode is the
#                                 right default everywhere)
#   XOUS_CORE_DIR=<workspace>/repos/xous-core
#                               — xous-core checkout to bundle into and
#                                 boot; exported so the robots and
#                                 xas-ci.resc resolve the same tree
#   XAS_FEATURES=<map>          — override the feature map (single-robot
#                                 runs only; ignored with a warning under
#                                 --all, which needs per-robot features)
#   GIT_DESCRIBE / GIT_REV      — passed to xtask so xous-sign-image
#                                 doesn't fail on `git describe` in a
#                                 tag-less fork checkout
#   SKIP_BUNDLE=1               — boot the existing xous.img as-is (no
#                                 ELF build, no bundle; only safe when
#                                 the bundled image already matches the
#                                 robot's expected features)
#   ROBOT_TIMEOUT_SECS=900      — hard WALL-clock cap per robot (final
#                                 backstop via timeout(1); each robot
#                                 additionally carries a 10-minute robot
#                                 `Test Timeout`)
#   RUSTUP_TOOLCHAIN            — honored if set (hosts whose stable
#                                 rustc has a stale rv32 sysroot need a
#                                 pinned toolchain for ALL rv32 builds)

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"          # the xas repo
xous_core_dir="${XOUS_CORE_DIR:-$repo_root/../repos/xous-core}"
git_describe="${GIT_DESCRIBE:-v0.9.21-0-g0000000}"
git_rev="${GIT_REV:-g0000000}"
robot_timeout="${ROBOT_TIMEOUT_SECS:-900}"
renode_bin="${RENODE:-renode-test}"

export RENODE_CI_MODE="${RENODE_CI_MODE:-YES}"
export XOUS_CORE_DIR="$xous_core_dir"

canonical_features="pddb-real,precursor"

all_robots=(
    xas-smoke.robot
    xas-bulk-write-boot.robot
    xas-selective-sync.robot
    xas-instrument-noise.robot
    xas-pddb-probe.robot
    xas-probe.robot
    xas-send-batch.robot
    xas-echo.robot
)

features_for() {
    case "$1" in
        xas-smoke.robot|xas-bulk-write-boot.robot|\
        xas-selective-sync.robot|xas-instrument-noise.robot)
            echo "$canonical_features" ;;
        xas-pddb-probe.robot)  echo "precursor,probe-pddb" ;;
        xas-probe.robot)       echo "precursor,probe-flow" ;;
        xas-send-batch.robot)  echo "precursor,probe-send-batch" ;;
        xas-echo.robot)        echo "precursor,probe-echo" ;;
        *)                     echo "" ;;
    esac
}

# Extra IMAGE-side (xtask --feature) flags per robot: features of the
# xous-core services baked into the bundle, on top of the fixed
# app-image-xip invocation. xas-echo needs net/renode-minimal (static
# IPv4 seed at boot) or smoltcp never gains an interface address and
# every 127.0.0.1 connect dies — which requires a kernel tree whose
# net service HAS that feature (xous-core branch xas-integration-net).
image_features_for() {
    case "$1" in
        xas-echo.robot)  echo "net/renode-minimal" ;;
        *)               echo "" ;;
    esac
}

usage() {
    sed -n '2,55p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

# --- Argument parsing ---
all_mode=0
robots=()
for arg in "$@"; do
    case "$arg" in
        --all)      all_mode=1 ;;
        -h|--help)  usage; exit 0 ;;
        -*)         echo "error: unknown option: $arg" >&2; exit 2 ;;
        *)          robots+=("$arg") ;;
    esac
done

if [ "$all_mode" = "1" ]; then
    if [ "${#robots[@]}" -gt 0 ]; then
        echo "error: --all takes no robot arguments" >&2
        exit 2
    fi
    robots=("${all_robots[@]}")
    if [ -n "${XAS_FEATURES:-}" ]; then
        echo "warning: XAS_FEATURES is ignored under --all (per-robot map applies)" >&2
        unset XAS_FEATURES
    fi
fi
[ "${#robots[@]}" -gt 0 ] || robots=(xas-smoke.robot)

# Accept names with or without the .robot suffix; validate existence.
for i in "${!robots[@]}"; do
    r="${robots[$i]}"
    [[ "$r" == *.robot ]] || r="$r.robot"
    robots[$i]="$r"
    if [ ! -f "$script_dir/$r" ]; then
        echo "error: Robot script not found: $script_dir/$r" >&2
        exit 2
    fi
done

# --- Preflight ---
if ! command -v "$renode_bin" >/dev/null 2>&1; then
    echo "error: $renode_bin not on PATH (override with RENODE=...)" >&2
    exit 2
fi
if [ ! -d "$xous_core_dir" ]; then
    echo "error: xous-core not found at $xous_core_dir" >&2
    echo "  Set XOUS_CORE_DIR, or create the repos/xous-core symlink per BUILDING.md §1." >&2
    exit 2
fi

elf="$repo_root/target/riscv32imac-unknown-xous-elf/release/xas"
image_dir="$xous_core_dir/target/riscv32imac-unknown-xous-elf/release"
stamp="$xous_core_dir/target/xas-ci-bundle.stamp"

# Build the ELF for $1 (a feature list), then bundle it into
# $xous_core_dir with the image-side xtask features in $2 (a
# space-separated list, possibly empty) — but skip the ~2 min bundle
# when the (features, image features, ELF hash) triple already matches
# what was last bundled and the image files exist.
ensure_image() {
    local features="$1" image_features="${2:-}"
    if [ "${SKIP_BUNDLE:-0}" = "1" ]; then
        echo "==> SKIP_BUNDLE=1: booting the existing xous.img as-is (expected features: $features — NOT verified)"
        return 0
    fi
    echo "==> building xas (rv32, --features $features)"
    ( cd "$repo_root" && cargo build --target riscv32imac-unknown-xous-elf --release \
        -p xous-app-signal --features "$features" )
    local sig
    sig="app-image-xip $features [$image_features] $(sha256sum "$elf" | awk '{print $1}')"
    if [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$sig" ] \
        && [ -f "$image_dir/xous.img" ] && [ -f "$image_dir/loader.bin" ]; then
        echo "==> image already bundled for [$features]; skipping re-bundle"
        return 0
    fi
    # Preflight: gam's apps.rs must register APP_NAME_XAS or the launcher
    # won't see Signal (same trap as BUILDING.md §2.1).
    local apps_rs="$xous_core_dir/services/gam/src/apps.rs"
    if [ ! -f "$apps_rs" ] || ! grep -q '\bAPP_NAME_XAS\b' "$apps_rs"; then
        echo "error: $apps_rs missing or lacks APP_NAME_XAS." >&2
        echo "  xous-core is likely on a branch whose apps/manifest.json doesn't" >&2
        echo "  register xas (e.g. upstream dev). Use a branch that does." >&2
        exit 2
    fi
    # app-image-xip, NOT app-image: the all-in-RAM app-image bundle
    # (~12.9 MB xous.img) exceeds the Precursor's 16 MiB RAM once every
    # service unpacks — under Renode the kernel OOM-panics
    # ("Couldn't allocate new page: OutOfMemory" -> KERNEL FAILURE ->
    # reboot loop) right after xas/usb start, short of the PDDB password
    # prompt. XIP executes services from flash-mapped addresses and is
    # the same bundle the hardware flash flow uses (BUILDING.md §3.2).
    echo "==> bundling xous.img (XIP) into $xous_core_dir (features: $features; image features: ${image_features:-none})"
    local extra_args=()
    local f
    for f in $image_features; do
        extra_args+=(--feature "$f")
    done
    ( cd "$xous_core_dir" && cargo xtask app-image-xip \
        "xas:$elf" \
        vault \
        transientdisk \
        --kernel-feature big-heap \
        "${extra_args[@]}" \
        --git-describe "$git_describe" \
        --git-rev "$git_rev" )
    printf '%s' "$sig" > "$stamp"
}

overall_rc=0
summary=()

# Run one robot under a hard wall-clock cap. renode-test writes its
# output/log/report into a per-robot results dir (gitignored).
run_robot() {
    local robot="$1" rc=0 t0 t1 verdict
    local results_dir="$script_dir/renode-results/${robot%.robot}"
    echo "==> $renode_bin $robot (wall cap: ${robot_timeout}s)"
    t0=$(date +%s)
    ( cd "$script_dir" && timeout -k 30 "$robot_timeout" \
        "$renode_bin" -r "$results_dir" "$robot" ) || rc=$?
    t1=$(date +%s)
    if [ "$rc" -eq 0 ]; then
        verdict="PASS"
    elif [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
        verdict="TIMEOUT"
        overall_rc=1
    else
        verdict="FAIL(rc=$rc)"
        overall_rc=1
    fi
    summary+=("$(printf '%-28s %-12s %6ds' "$robot" "$verdict" "$((t1 - t0))")")
}

for robot in "${robots[@]}"; do
    features="${XAS_FEATURES:-$(features_for "$robot")}"
    if [ -z "$features" ]; then
        echo "warning: no feature mapping for $robot; using canonical [$canonical_features]" >&2
        features="$canonical_features"
    fi
    ensure_image "$features" "$(image_features_for "$robot")"
    run_robot "$robot"
done

# Leave the tree in the canonical state after a full-suite run (the last
# probe bundle would otherwise linger in xous-core's target/).
if [ "$all_mode" = "1" ] && [ "${SKIP_BUNDLE:-0}" != "1" ]; then
    echo "==> restoring canonical image bundle"
    ensure_image "$canonical_features" ""
fi

echo
echo "==== renode suite summary ===="
printf '%s\n' "${summary[@]}"
echo "=============================="
exit "$overall_rc"
