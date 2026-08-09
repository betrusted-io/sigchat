*** Comments ***
In-image TCP echo through the real on-target network stack (S1).

Boots the standard machine with xas built under
`--features precursor,probe-echo`. After `xas: worker started` the
probe spawns a `std::net::TcpListener` echo server on 127.0.0.1:7777
and drives four client cases (three patterned messages + one streamed
8 KiB payload), each verified byte-exact through the REAL path:
libstd -> services/net -> smoltcp loopback. Unlike xas-probe.robot
(pass-regardless reachability logging), every case here MUST pass:
each `XAS-ECHO: <name> FAIL` variant is a registered failing UART
string and the suite asserts `XAS-ECHO DONE: pass=4 fail=0`.

KERNEL-TREE REQUIREMENT: the bundled image must come from a xous-core
tree whose net service has the `net/renode-minimal` feature (branch
`xas-integration-net`), and the wrapper bundles this robot's image
with `--feature net/renode-minimal`. Without the feature's static
IPv4 seed, smoltcp never gains its 127.0.0.1/8 interface address (it
is only pushed when an IPv4 config lands, and no DHCP bind ever fires
on the closed renode switch) and every loopback connect times out.

Run via:    tests/renode/run-renode-tests.sh xas-echo.robot
(the wrapper builds the probe-echo ELF variant and re-bundles the
image — with net/renode-minimal — automatically; a canonical-image
run would fail the banner wait.)


*** Settings ***
Suite Setup                   Setup
Suite Teardown                Teardown
Test Teardown                 Test Teardown
Test Timeout                  10 minutes
Resource                      ${RENODEKEYWORDS}
Resource                      xas-ci-common.resource


*** Variables ***
# Boot + 4 echo cases; each case's socket I/O is bounded on-target at
# 20 s per call. Virtual seconds, so generous is cheap.
${UART_TIMEOUT}               240
${CREATE_SNAPSHOT_ON_FAIL}    False


*** Test Cases ***
Should Echo Bytes Through The On Target Stack
    Create Xas Ci Machine     xas-echo
    # Any case failure aborts the pending wait immediately instead of
    # burning the timeout.
    Register Failing Uart String    XAS-ECHO: msg-1 FAIL
    Register Failing Uart String    XAS-ECHO: msg-2 FAIL
    Register Failing Uart String    XAS-ECHO: msg-3 FAIL
    Register Failing Uart String    XAS-ECHO: bulk-8k FAIL
    # Baseline xas boot.
    Wait For Line On Uart     xas: starting
    Wait For Line On Uart     xas: worker started
    # Probe banner — confirms the feature flag took effect.
    Wait For Line On Uart     probe-echo: starting in-image TCP echo probe
    # Every case must PASS, in order.
    Wait For Line On Uart     XAS-ECHO: msg-1 PASS
    Wait For Line On Uart     XAS-ECHO: msg-2 PASS
    Wait For Line On Uart     XAS-ECHO: msg-3 PASS
    Wait For Line On Uart     XAS-ECHO: bulk-8k PASS
    Wait For Line On Uart     XAS-ECHO DONE: pass=4 fail=0
    # End-of-run audit. `Network config acquired` is the net service's
    # renode-minimal static seed landing — asserted here rather than in
    # the Wait sequence because its ordering vs the xas boot lines is
    # not deterministic.
    Console Log Should Be Clean And Contain
    ...                       Network config acquired
    ...                       probe-echo: starting in-image TCP echo probe
    ...                       XAS-ECHO DONE: pass=4 fail=0
