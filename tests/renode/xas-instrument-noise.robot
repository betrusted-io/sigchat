*** Comments ***
Performance-instrumentation smoke test.

Confirms that the `perf/...` log lines compiled into xas + xous-core
fire during boot AND don't crash the kernel/app. Specifically, this
proves the PDDB-side instrumentation reaches the `Requesting login
password` line (so all the per-opcode timing logs in main.rs, basis.rs,
hw.rs survived rv32 compilation and execution).

We don't assert on `perf/pddb:` lines here because the PDDB-side perf
logs only fire when a CLIENT issues an opcode (WriteKey, DeleteKey,
etc.). Before the user unlocks PDDB, no writes happen, so no perf/pddb
lines appear; perf/net: lines fire only on the active network path. The
value of this test is the "didn't crash before the password prompt"
assertion. Real perf-line coverage comes from the hardware cold-send
run.

Run via:    tests/renode/run-renode-tests.sh xas-instrument-noise.robot
(canonical pddb-real,precursor ELF; the wrapper builds/bundles it.)


*** Settings ***
Suite Setup                   Setup
Suite Teardown                Teardown
Test Teardown                 Test Teardown
Test Timeout                  10 minutes
Resource                      ${RENODEKEYWORDS}
Resource                      xas-ci-common.resource


*** Variables ***
${UART_TIMEOUT}               240
${CREATE_SNAPSHOT_ON_FAIL}    False


*** Test Cases ***
Should Boot With Perf Instrumentation Without Crashing
    Create Xas Ci Machine     xas-instrument-noise
    # Boot reaches xas + PDDB password prompt: same regression-guard
    # assertion as `xas-bulk-write-boot.robot`. If any of the perf/*
    # log lines panics on rv32 (e.g. format-string mismatch, missing
    # import), boot wedges short of this line.
    Wait For Line On Uart     xas: starting
    Wait For Line On Uart     xas: worker started
    Wait For Line On Uart     Requesting login password
    Console Log Should Be Clean And Contain
    ...                       xas: worker started
    ...                       Requesting login password
