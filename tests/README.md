# tests — choosing how to test a change

Three testing approaches are available for xas, plus pure unit
tests. Each has a different cost / coverage tradeoff. This file
helps you pick. Detailed how-to lives in the per-approach docs
linked below.

```
tests/
├── hosted/      ← Xous kernel running as a Linux process
├── renode/      ← rv32 SoC emulator harnesses
└── precursor/   ← real Precursor PVT2 hardware (manual, UART-observed)
```

Plus the in-repo unit-test suite (`cargo test --features hosted
-p xous-app-signal --bins`) — those live alongside the code
they exercise, not under `tests/`.

---

## At a glance

| Approach | Cost / cycle | What it covers | What it misses |
|---|---|---|---|
| **Unit tests** (`cargo test --features hosted -p xous-app-signal --bins`) | seconds | Pure data modules (dialogue summarization, read-state aggregation, name fallback ordering) | Anything touching IPC, network, GAM, PDDB |
| **Hosted** ([`tests/hosted/`](hosted/)) | seconds-to-minutes | Full Xous kernel + services + xas, real Wi-Fi via host kernel, real Signal-server round-trips, GAM rendered to a window | rv32 net stack bugs, WF200 SPI bugs, FPGA gateware bugs, real-PDDB-encryption interactions |
| **Renode** ([`tests/renode/`](renode/)) | minutes (slow emulator) | rv32 instruction-level fidelity, real loader, real kernel, almost-real net stack | WF200 SPI (no peripheral model), real Signal-server (no internet from inside the emulator without proxy work), wall-clock timing bugs |
| **Precursor** ([`tests/precursor/`](precursor/)) | ~30 min/cycle (build + flash) | Everything: rv32 net stack, WF200 SPI, FPGA gateware, real PDDB, real timing, real RF | Slow iteration; no breakpoints (UART only) |

---

## Pros / cons

### Unit tests

**Pros:** instantaneous feedback. No external dependencies (no
Wi-Fi, no Signal account, no hardware, no X11). The right test
to run on every commit. The right smoke check for a fresh
contributor's toolchain.

**Cons:** only covers pure-data modules. Anything that goes
through Xous IPC, the network stack, GAM, or PDDB is out of
scope.

**Run:** `cargo test --features hosted -p xous-app-signal --bins`

### Hosted

**Pros:** the workhorse. Boots in seconds, exercises the same
Signal-protocol code paths as hardware, uses your real Wi-Fi
via the host kernel, talks to the real Signal server, renders
the real GAM UI to a minifb window labelled "Precursor". Right
place for UI iteration and most logic-bug fixes.

**Cons:** doesn't catch rv32-specific issues — the std-side net
encoding bugs we hit on hardware were invisible here because
Linux's std net path is correct. Doesn't exercise the WF200
Wi-Fi chip, FPGA gateware, or real PDDB encryption code paths.

**Run:** see [`tests/hosted/README.md`](hosted/README.md). Cheapest
end-to-end is `bash tests/hosted/test_link_qr.sh` (boots
hosted, drives launcher to the QR screen, gates on the
provisioning URL appearing in kernel log).

### Renode

**Pros:** rv32 instruction-level fidelity. Catches some bugs
that hosted misses (anything sensitive to the rv32 ABI or
loader) without burning a 30-minute hardware flash cycle.

**Cons:** slow. No WF200 peripheral model — anything Wi-Fi-
adjacent doesn't repro. Reaching the real Signal server from
inside the emulator requires proxy plumbing we haven't set up.
Has historically not caught the bugs that bit us in production
(those were all timing-, scheduling-, or net-encoding-related).
**Not actively used in this project's day-to-day workflow.**

**Run:** `tests/renode/run-renode-tests.sh` — documented in
BUILDING.md step 2.7. Reach for it only when
you have a bug that repros on rv32 but not in hosted, and you
don't have a Precursor handy.

### Precursor (real hardware)

**Pros:** the only path that catches the full set of bugs that
matter for shipping. rv32 net stack, WF200 SPI, FPGA gateware,
real PDDB encryption, real RF timing — all live. UART log
captures every kernel message. Indispensable for the final
signoff before a release.

**Cons:** ~30 min per cycle (build + flash). No breakpoints —
debugging is via UART log analysis. Hardware can be bricked by
careless flashing (gateware/loader flashes need JTAG to
recover); always default to kernel-only (`-k`) flashes.

**Run:** see [`precursor/README.md`](precursor/README.md).
**Read its "Brick prevention" section before running any flash
command.**

---

## Branch convention (`main` vs `dev`)

| Branch | Purpose | What's allowed in |
|---|---|---|
| `main` | Released code. State of `main` is what an outside contributor following BUILDING.md will get. | Only commits that have come through `dev` and survived the release-cycle checks below. |
| `dev` | Active development. | Everything: feature branches, half-finished work, commits whose tests haven't landed yet. |

**All new development happens on `dev` (or feature branches off
`dev`).** `main` only moves when a release cycle completes:

1. Unit tests pass on `dev`
2. Hosted link smoke test runs clean
3. **A blind walk-through of [`../BUILDING.md`](../BUILDING.md)
   succeeds against the current `dev` tip** (catches "I changed
   the build flow and forgot to update the doc" regressions)
4. Hardware smoke test on a real Precursor — link, send,
   receive — passes
5. `dev` is fast-forward-merged to `main` and pushed

If a release-cycle check fails, fix on `dev` and re-run — don't
merge a partial release to `main`.

## Verification norms

Hosted PASS is a sanity check, not a ship gate. Real verification
for kernel-, net-, or transport-affecting changes is **rv32
hardware** (Pi rig flash + UART tail, [`tests/precursor/`](precursor/))
or **Renode** (`tests/renode/run-renode-tests.sh`): cold-path
timing, WS idle-close behavior, and the Xous custom allocator all
diverge from hosted x86_64. When framing a fix as ready, name the
target it was verified on.
