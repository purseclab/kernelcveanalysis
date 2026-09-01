#!/bin/sh

cd "$(dirname $0)"

set -- \
    "cuttle_server/cuttle_cli" \
    "kdebug" \
    "kexploit" \
    "object_db" \
    "kpatch" \
    "kartifact"

for package in "$@"
do
    echo "Installing tools in '$package'..."
    uv tool install --reinstall --editable "$package"
done
