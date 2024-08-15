#!/usr/bin/env bash

set -o errexit
set -o pipefail
if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

CWD="$(cd -P -- "$(dirname -- "$0")" && pwd -P)"

: ${GHIDRA_SCRIPT:=$CWD/Symbolicate.java}
: ${GHIDRA_SCRIPTS_FOLDER:=$HOME/ghidra_scripts}

if [[ "${1-}" =~ ^-*h(elp)?$ ]]; then
    echo 'Usage: install.sh GHIDRA_SCRIPT

This script installs a Ghidra script.
'
    exit
fi

main() {
    echo "  🚀 Installing $GHIDRA_SCRIPT to $GHIDRA_SCRIPTS_FOLDER"
    mkdir -p "$GHIDRA_SCRIPTS_FOLDER"
    cp "$GHIDRA_SCRIPT" "$GHIDRA_SCRIPTS_FOLDER"
    echo "  🎉 Done!"
}

main "$@"
