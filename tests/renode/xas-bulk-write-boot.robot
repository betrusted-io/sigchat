*** Comments ***
Boot-regression test for hardware-flag builds with PDDB enabled.

Verifies that a canonical hardware-flag build (no auto-firing probe
features) boots far enough that PDDB finishes service registration and
reaches the password prompt — i.e. no `ServerNotFound` cascade in
unrelated services (llio, trng, modals, susres).

This test is the regression guard against re-introducing an auto-fire
that races with xous-names server registration during boot. xas
deliberately avoids calling `presage_store_pddb::PddbBackend::connect()`
immediately after spawning the worker; bulk-write benchmarking is
exposed via the shellchat `pddb bulk_probe` command (user-invoked after
PIN entry and PDDB mount), not via an auto-fire feature.

`Requesting login password` fires BEFORE the first-boot REQFMT format
prompt (verified against the upstream pddb-fs suite's console log), so
on the fresh 0xFF flash that xas-ci.resc's contract guarantees, reaching
it requires no keyboard injection. It can only appear after llio + trng
+ modals + susres have all registered with xous-names and PDDB's own
init has progressed to the password-unlock step.

Run via:    tests/renode/run-renode-tests.sh xas-bulk-write-boot.robot
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
Should Boot Bulk-Write Image Through PDDB Service Registration
    Create Xas Ci Machine     xas-bulk-write-boot
    # xas process starts (means xas's own boot is OK)
    Wait For Line On Uart     xas: starting
    Wait For Line On Uart     xas: worker started
    # PDDB has reached the point of waiting for the user. Failure mode
    # (the regression we guard against): a `ServerNotFound` cascade
    # aborts one of the prerequisite services before PDDB gets there,
    # and this line never appears within the UART timeout.
    Wait For Line On Uart     Requesting login password
    Console Log Should Be Clean And Contain
    ...                       xas: worker started
    ...                       Requesting login password
