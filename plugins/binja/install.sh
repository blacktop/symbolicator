#!/usr/bin/env bash

set -o errexit
set -o pipefail
if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

CWD="$(cd -P -- "$(dirname -- "$0")" && pwd -P)"

: ${BN_PLUGIN:=$CWD}
: ${BN_PLUGIN_FOLDER:=$HOME/Library/Application\ Support/Binary\ Ninja/plugins/ipsw}

if [[ "${1-}" =~ ^-*h(elp)?$ ]]; then
    echo 'Usage: install.sh BN_PLUGIN

This script installs an Binary Ninja plugin.
'
    exit
fi


main() {
    echo "  🚀 Installing $BN_PLUGIN to $BN_PLUGIN_FOLDER"
    mkdir -p "$BN_PLUGIN_FOLDER"
    cp -r "$BN_PLUGIN"/* "$BN_PLUGIN_FOLDER"
    echo "  🎉 Done!"
}

main "$@"
