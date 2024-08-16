#!/usr/bin/env bash

set -o errexit
set -o pipefail
if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

CWD="$(cd -P -- "$(dirname -- "$0")" && pwd -P)"

# : ${TARGET:=}
# : ${MAX_VERSION:=}
# : ${MIN_VERSION:=}
# : ${JSON_FILE:=}
: ${IDAPRO:=/Applications/IDA\ Pro\ 8.4/ida64.app/Contents/MacOS/idat64}
: ${SCRIPT:="$CWD/generate/generate.py"}
: ${FILETYPE:=}
: ${KERN_FILETYPE:='Mach-O file (EXECUTE). ARM64e-kpauth0'}
: ${KEXT_FILETYPE:='Fat Mach-O file, 2. ARM64e-kpauth0'}


help() {
    echo 'Usage: run.sh KERNELCACHE_PATH

This script runs the generate.py script in "headless mode" IDA Pro.

[SUPPORTED ENVIRONMENT VARIABLES]
    TARGET: The target binary. (e.g. com.apple.driver.AppleHIDKeyboard)
    MAX_VERSION: The maximum version of the target binary.
    MIN_VERSION: The minimum version of the target binary.
    JSON_FILE: The path to the JSON file. (e.g. /path/to/sig.json)

'
    exit 0
}


main() {
    # Parse arguments
    while test $# -gt 0; do
        case "$1" in
        -h | --help)
            help
            ;;
        -k | --kernel)
            FILETYPE=$KERN_FILETYPE
            shift
            ;;
        -x | --kext)
            FILETYPE=$KEXT_FILETYPE
            shift
            ;;
        -i | --idb)
            shift        
            "${IDAPRO}" -A -P -S"$SCRIPT" -L/tmp/ida.log $1
            exit 0
            ;;
        *)
            break
            ;;
        esac
    done    
    MACHO_PATH="$1"
    echo "  🚀 Starting... $MACHO_PATH"
    # IDA Help: Command line switches - https://www.hex-rays.com/products/ida/support/idadoc/417.shtml
    "${IDAPRO}" -P- -A -B -T"$FILETYPE" -S"$SCRIPT" -o'/tmp/tmp.i64' -L/tmp/ida.log $MACHO_PATH
    echo "  🎉 Done!"
}

main "$@"
