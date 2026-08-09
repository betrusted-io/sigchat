*** Comments ***
xas boot-smoke test (Robot Framework + Renode).

Boots the CI-grade xas-ci.resc machine (headless SoC + EC pair, per-run
0xFF flash scratch file) with the xas Signal client bundled into the
image via apps/manifest.json, and asserts the two log lines emitted at
the top of xas's main(). Like every other Xous PID, xas starts at boot —
no user interaction is needed to reach the asserted lines.

Run via:    tests/renode/run-renode-tests.sh                # this robot
            tests/renode/run-renode-tests.sh --all          # whole suite
The wrapper builds the right ELF variant (canonical pddb-real,precursor
for this robot), re-bundles the image only when needed, and exports
XOUS_CORE_DIR for the machine definition. To run renode-test by hand,
bundle first (BUILDING.md §2.7) and export XOUS_CORE_DIR.

Timeout model (all robots in this suite):
- Wait For Line On Uart timeouts are VIRTUAL-time seconds (host-speed
  independent).
- Test Timeout is WALL-clock: a stalled machine can never burn more than
  10 real minutes.
- 'PANIC in PID' is a registered failing UART string (fail-fast on any
  service death instead of burning the timeout).


*** Settings ***
Suite Setup                   Setup
Suite Teardown                Teardown
Test Teardown                 Test Teardown
Test Timeout                  10 minutes
Resource                      ${RENODEKEYWORDS}
Resource                      xas-ci-common.resource


*** Variables ***
${UART_TIMEOUT}               120
# A failed run's emulation snapshot (2 machines + 128 MiB file-backed
# flash) is huge and useless for triage; the console/kernel logs under
# target/xas-ci/ suffice. Overrides the renode-keywords default.
${CREATE_SNAPSHOT_ON_FAIL}    False


*** Test Cases ***
Should Boot And Run Xas
    Create Xas Ci Machine     xas-smoke
    # xas-ci.resc creates two UART-shaped peripherals on the SoC machine:
    # `sysbus.uart` (kernel-only output) and `sysbus.console` (the
    # xous-log-server destination: every log::info! from every app). The
    # asserted lines come from log::info! in xas's main(), so the tester
    # targets `sysbus.console` (wired up by Create Xas Ci Machine).
    Wait For Line On Uart     xas: starting
    Wait For Line On Uart     xas: worker started
    Console Log Should Be Clean And Contain
    ...                       xas: starting
    ...                       xas: worker started
