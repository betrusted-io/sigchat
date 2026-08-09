*** Comments ***
Shared keywords/variables for the xas renode suite (all xas-*.robot files).

Every robot boots the same CI-grade machine definition (xas-ci.resc:
headless SoC + EC pair, no fixed ports) against the image bundled in
${XOUS_CORE_DIR}, with a per-robot, per-run 0xFF-filled flash scratch
file — the flash model writes through into its backing file, so a shared
or auto-created (zero-filled) backing file leaks state across runs and
stalls PDDB boot. Console/kernel UART output is file-backed under
<xas repo>/target/xas-ci/ for post-mortem grep and end-of-test
assertions.

Robots must define ${UART_TIMEOUT} (default Wait For Line On Uart
timeout, VIRTUAL-time seconds) and call `Create Xas Ci Machine <name>`
with their short name (used for the per-robot scratch/log file names).


*** Settings ***
Library                   OperatingSystem


*** Variables ***
# xous-core checkout that holds the bundled loader.bin/xous.img (and the
# emulation/ tree). run-renode-tests.sh exports XOUS_CORE_DIR; the default
# is the workspace repos/xous-core symlink (BUILDING.md §1), matching
# xas-ci.resc's own $ORIGIN-relative default.
${XOUS_CORE_DIR}          %{XOUS_CORE_DIR=${CURDIR}/../../../repos/xous-core}
${IMAGE_DIR}              ${XOUS_CORE_DIR}/target/riscv32imac-unknown-xous-elf/release
${WORKDIR}                ${CURDIR}/../../target/xas-ci
# MX66UM1G45G NOR flash: 128 MiB
${FLASH_SIZE}             ${134217728}


*** Keywords ***
Prepare Fresh Flash
    [Documentation]       Blank 0xFF NOR image; the flash model writes
    ...                   through into this file, so it is per-run.
    Create Directory      ${WORKDIR}
    Remove File           ${FLASH_FILE}
    Remove File           ${CONSOLE_LOG}
    Remove File           ${KERNEL_LOG}
    Evaluate              open(r'${FLASH_FILE}', 'wb').write(b'\\xff' * ${FLASH_SIZE})

Create Xas Ci Machine
    [Documentation]       Provision fresh flash, point xas-ci.resc at the
    ...                   image under test, and boot the headless SoC+EC
    ...                   pair. xas-ci.resc ends with 'start', and the
    ...                   first asserted line is several virtual seconds
    ...                   after reset, so creating the tester right after
    ...                   the include is safe. 'PANIC in PID' is a
    ...                   registered failing UART string: a dead service
    ...                   prints exactly that banner before the console
    ...                   goes silent, so it fails the pending wait
    ...                   immediately instead of burning the timeout.
    [Arguments]           ${name}
    Set Suite Variable    ${FLASH_FILE}     ${WORKDIR}/${name}-flash.bin
    Set Suite Variable    ${CONSOLE_LOG}    ${WORKDIR}/${name}-console.log
    Set Suite Variable    ${KERNEL_LOG}     ${WORKDIR}/${name}-kernel.log
    Prepare Fresh Flash
    Execute Command       $xous_core_root=@${XOUS_CORE_DIR}
    Execute Command       $image_dir=@${IMAGE_DIR}
    Execute Command       $flash_file=@${FLASH_FILE}
    Execute Command       $console_log=@${CONSOLE_LOG}
    Execute Command       $kernel_log=@${KERNEL_LOG}
    Execute Command       include @${CURDIR}/xas-ci.resc
    Create Terminal Tester    sysbus.console    machine=SoC    timeout=${UART_TIMEOUT}
    Register Failing Uart String    PANIC in PID

Console Log Should Be Clean And Contain
    [Documentation]       End-of-test audit of the file-backed console
    ...                   log (the backend flushes every write, so it is
    ...                   current): every listed line must appear, and no
    ...                   panic banner may appear anywhere in the run.
    [Arguments]           @{lines}
    ${log}=               Get File    ${CONSOLE_LOG}    encoding_errors=replace
    FOR    ${line}    IN    @{lines}
        Should Contain    ${log}    ${line}
    END
    Should Not Contain    ${log}    PANIC in PID
