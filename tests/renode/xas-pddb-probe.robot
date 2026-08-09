*** Comments ***
Exploratory PDDB IPC probe.

Boots the same machine as xas-smoke.robot, but expects xas built with
`--features precursor,probe-pddb`. The probe calls xous-core's PDDB
Mount Poller via raw `xous::send_message` (the same path a hand-rolled
PDDB client would take) and logs the result.

Run via:    tests/renode/run-renode-tests.sh xas-pddb-probe.robot
(the wrapper builds the probe-pddb ELF variant and re-bundles the image
automatically; a canonical-image run would fail the banner wait.)


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
Should Probe PDDB Mount Poller
    Create Xas Ci Machine     xas-pddb-probe
    Wait For Line On Uart     xas: starting
    Wait For Line On Uart     xas: worker started
    # Probe banner — confirms the feature flag took effect.
    Wait For Line On Uart     probe-pddb: starting PDDB mount-poller probe
    # Connection establishment; substring match on "connected to" so it
    # works regardless of how long the XousNames lookup takes.
    Wait For Line On Uart     probe-pddb: connected to PDDB Mount Poller
    # The result line — substring match on "Poll" so it captures
    # OK / FAIL / unexpected regardless of outcome (the outcome is what
    # we want logged).
    Wait For Line On Uart     probe-pddb: Poll
    Wait For Line On Uart     probe-pddb: probe done
    Console Log Should Be Clean And Contain
    ...                       probe-pddb: starting PDDB mount-poller probe
    ...                       probe-pddb: probe done
