*** Comments ***
Selective-dict-sync boot-regression test.

What this verifies (locally, in Renode): boot survives the dirty-set
tracking in `xous-core/services/pddb/src/backend/basis.rs`. Reaching
`Requesting login password` proves:
 - `BasisCacheEntry::sync` compiled with the dirty-set field and
   selective code path,
 - none of the mutation sites (key_update, key_remove, key_list_remove,
   dict_add, dict_remove, dict_delete) tripped a compile- or
   runtime-error on the `mark_dirty`/`mark_clean` calls,
 - the basis-init path through `BasisCacheEntry::mount` populates
   `dirty_dicts: HashSet::new()` cleanly.

What this DOES NOT verify (hardware-only): the `n_dicts=1` assertion —
that needs a mounted PDDB plus `pddb bulk_probe 1` in shellchat. On
hardware, the maintainer flashes this build, unlocks PDDB, runs
`pddb bulk_probe 1`, and greps the UART log for:

    perf/pddb: BasisCacheEntry::sync entry basis=".System"
      n_dicts=1 dirty_set_size=1 total_dicts=22 cleanup=false

Run via:    tests/renode/run-renode-tests.sh xas-selective-sync.robot
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
Should Boot Selective-Sync Kernel To Password Prompt
    Create Xas Ci Machine     xas-selective-sync
    # The dirty-set tracking is on the boot critical path — every
    # PDDB-internal sync that fires before mount goes through the
    # selective `BasisCacheEntry::sync(cleanup=false)` code path. If the
    # dirty-set HashSet broke construction or any mark_dirty call site
    # panics, boot wedges short of the password prompt.
    Wait For Line On Uart     xas: starting
    Wait For Line On Uart     xas: worker started
    Wait For Line On Uart     Requesting login password
    Console Log Should Be Clean And Contain
    ...                       xas: worker started
    ...                       Requesting login password
