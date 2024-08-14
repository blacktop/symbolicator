#!/usr/bin/env bash

set -o errexit
set -o pipefail
if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

CWD="$(cd -P -- "$(dirname -- "$0")" && pwd -P)"

: ${IDA_PLUGIN_JSON:=$CWD/ida-plugin.json}
: ${IDA_PLUGIN_FILE:=$CWD/symbolicate.py}
: ${IDA_PLUGIN_FOLDER:=$HOME/.idapro/plugins/}
# : ${IDA_PLUGIN_FOLDER:=$HOME/.idapro/plugins/symbolicate}

if [[ "${1-}" =~ ^-*h(elp)?$ ]]; then
    echo 'Usage: install.sh IDA_PLUGIN

This script installs an IDA Pro plugin.
'
    exit
fi


main() {
    echo "  🚀 Installing $IDA_PLUGIN_FILE to $IDA_PLUGIN_FOLDER"
    # TODO: change to the NEW way once IDA Pro 9.0 comes out
    # mkdir -p "$IDA_PLUGIN_FOLDER"
    # cp "$IDA_PLUGIN_JSON" "$IDA_PLUGIN_FOLDER"
    # cp "$IDA_PLUGIN_FILE" "$IDA_PLUGIN_FOLDER"
    cp "$IDA_PLUGIN_FILE" "$IDA_PLUGIN_FOLDER"
    echo "  🎉 Done!"
}

main "$@"
