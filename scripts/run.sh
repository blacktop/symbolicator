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
# : ${IDAPRO:=/Applications/IDA\ Pro\ 8.4/ida64.app/Contents/MacOS/idat64}
: ${IDAPRO:=/Applications/IDA\ Professional\ 9.3.app/Contents/MacOS/idat}
: ${SCRIPT:="$CWD/generate/generate.py"}
: ${FILETYPE:=}
: ${KERN_FILETYPE:='Mach-O file (EXECUTE). ARM64e-kpauth0'}
: ${KEXT_FILETYPE:=}
: ${IDA_LOG:=/tmp/ida.log}
IDAPYTHON_EXIT=86


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


detect_arm64e_filetype() {
    local macho_path="$1"
    local file_info
    local first_line
    local entry
    local rest
    local auth_suffix="kpauth0"
    local thin_filetype=""
    local arch_index=0
    local found_arm64e=0
    local arch

    if ! file_info="$(file "$macho_path" 2>/dev/null)"; then
        return 1
    fi

    if [[ "$file_info" != *"arm64e"* ]]; then
        return 1
    fi

    first_line="${file_info%%$'\n'*}"
    if [[ "$file_info" == *"universal binary"* ]]; then
        rest="$first_line"
        while [[ "$rest" == *"["* ]]; do
            rest="${rest#*[}"
            entry="${rest%%]*}"
            arch="${entry%%:*}"
            arch_index=$((arch_index + 1))
            if [[ "$arch" == "arm64e" ]]; then
                found_arm64e=1
                break
            fi
            rest="${rest#*]}"
        done
        if [[ "$found_arm64e" -ne 1 ]]; then
            return 1
        fi
    else
        entry="$first_line"
    fi

    if [[ "$entry" == *"kext bundle"* ]]; then
        thin_filetype="KEXT_BUNDLE"
        auth_suffix="kpauth0"
    elif [[ "$entry" == *"bundle"* ]]; then
        thin_filetype="BUNDLE"
        auth_suffix="pauth0"
    elif [[ "$entry" == *"executable"* ]]; then
        thin_filetype="EXECUTE"
    else
        return 1
    fi

    if [[ "$file_info" == *"universal binary"* ]]; then
        echo "Fat Mach-O file, $arch_index. ARM64e-$auth_suffix"
    else
        echo "Mach-O file ($thin_filetype). ARM64e-$auth_suffix"
    fi
}


run_ida() {
    local macho_path="$1"
    local status
    shift

    : >"$IDA_LOG"
    if "${IDAPRO}" "$@" -S"$SCRIPT" -o'/tmp/tmp.i64' -L"$IDA_LOG" "$macho_path"; then
        return 0
    else
        status=$?
    fi
    if [[ "$status" -ne 0 ]]; then
        if tail -n 80 "$IDA_LOG" 2>/dev/null | grep -q "Couldn't initialize IDAPython"; then
            echo "    - IDAPython is not configured; run idapyswitch for this IDA install"
            return "$IDAPYTHON_EXIT"
        fi
        return "$status"
    fi
}


main() {
    local macho_kind=""

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
            macho_kind="kext"
            shift
            ;;
        -i | --idb)
            shift
            "${IDAPRO}" -A -P -S"$SCRIPT" -L"$IDA_LOG" "$1"
            exit 0
            ;;
        *)
            break
            ;;
        esac
    done
    MACHO_PATH="$1"
    if [[ "$macho_kind" == "kext" ]]; then
        if [[ -n "$KEXT_FILETYPE" ]]; then
            FILETYPE="$KEXT_FILETYPE"
        elif ! FILETYPE="$(detect_arm64e_filetype "$MACHO_PATH")"; then
            echo "    - Could not determine an arm64e IDA file type for $MACHO_PATH"
            exit 1
        fi
    fi
    echo "  > Starting... $MACHO_PATH"
    echo "    - IDA file type: $FILETYPE"
    # IDA Help: Command line switches - https://www.hex-rays.com/products/ida/support/idadoc/417.shtml
    run_ida "$MACHO_PATH" -P- -A -B -T"$FILETYPE"
    echo "    - Done 🎉"
}

main "$@"
