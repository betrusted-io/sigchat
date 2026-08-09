*** Comments ***
`BufferingBackend` + `BatchGuard` smoke under Renode.

Boots the standard machine with xas built under
`--features precursor,probe-send-batch`. The probe drives a synthetic
"send-shaped" sequence of writes through `BufferingBackend` wrapping a
`MockBackend`, then a commit, then an abort path, logging UART lines
this robot asserts on.

The probe uses `MockBackend` rather than the real PDDB because the gen1
PDDB can't auto-mount in Renode (no rootkeys + no password modal
injection). The wrapper semantics are independent of the inner backend;
this probe validates that the abstraction compiles for rv32 and runs
under the real xous async runtime. The host-side
`cargo test -p presage-store-pddb` covers the same abstraction in unit
tests.

Run via:    tests/renode/run-renode-tests.sh xas-send-batch.robot
(the wrapper builds the probe-send-batch ELF variant and re-bundles the
image automatically; a canonical-image run would fail the banner wait.)


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
Should Buffer Writes Commit And Abort
    Create Xas Ci Machine     xas-send-batch
    # Baseline xas boot.
    Wait For Line On Uart     xas: starting
    Wait For Line On Uart     xas: worker started
    # Probe banner — confirms the feature flag took effect.
    Wait For Line On Uart     probe-send-batch: starting
    Wait For Line On Uart     probe-send-batch: backend constructed
    # batch begin
    Wait For Line On Uart     probe-send-batch: batch begin OK
    # three writes buffered, with count=3
    Wait For Line On Uart     probe-send-batch: 3 writes buffered
    # intra-batch read-through visible
    Wait For Line On Uart     probe-send-batch: intra-batch read-through OK
    # commit OK with replay count
    Wait For Line On Uart     probe-send-batch: commit OK
    # post-commit reads land
    Wait For Line On Uart     probe-send-batch: post-commit reads match
    # abort path works
    Wait For Line On Uart     probe-send-batch: abort path OK
    # final done line
    Wait For Line On Uart     probe-send-batch: probe done
    Console Log Should Be Clean And Contain
    ...                       probe-send-batch: starting
    ...                       probe-send-batch: probe done
