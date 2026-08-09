*** Comments ***
Exploratory network-reachability probe.

Boots the same machine as xas-smoke.robot, but expects xas built with
`--features precursor,probe-flow`. The probe fires after `xas: worker
started` and runs three TCP-connect attempts: Google DNS (8.8.8.8:53),
Cloudflare HTTPS (1.1.1.1:443), and Signal prod (chat.signal.org:443).
The emulated WF200 has no host uplink, so the connects are expected to
FAIL — the robot matches the per-target labels regardless of outcome
(the *outcome* is what we want logged) and only requires the probe to
run to completion.

Run via:    tests/renode/run-renode-tests.sh xas-probe.robot
(the wrapper builds the probe-flow ELF variant and re-bundles the image
automatically; a canonical-image run would fail the banner wait.)


*** Settings ***
Suite Setup                   Setup
Suite Teardown                Teardown
Test Teardown                 Test Teardown
Test Timeout                  10 minutes
Resource                      ${RENODEKEYWORDS}
Resource                      xas-ci-common.resource


*** Variables ***
# Probe budget: 3 connects x 10 s timeout each on top of boot; virtual
# seconds, so generous is cheap.
${UART_TIMEOUT}               240
${CREATE_SNAPSHOT_ON_FAIL}    False


*** Test Cases ***
Should Run Network Probe
    Create Xas Ci Machine     xas-probe
    # Boot lines, same as smoke. If these fail to appear we never
    # reached probe code anyway.
    Wait For Line On Uart     xas: starting
    Wait For Line On Uart     xas: worker started
    # Probe banner — confirms the feature flag took effect.
    Wait For Line On Uart     probe: starting network reachability probe
    # One Wait per probe target; substring match on the label matches
    # both "CONNECT OK" and "CONNECT FAIL".
    Wait For Line On Uart     probe: google-dns
    Wait For Line On Uart     probe: cloudflare-https
    Wait For Line On Uart     probe: signal-prod
    Wait For Line On Uart     probe: network probe done
    Console Log Should Be Clean And Contain
    ...                       probe: starting network reachability probe
    ...                       probe: network probe done
