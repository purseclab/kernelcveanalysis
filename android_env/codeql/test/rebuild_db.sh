#!/bin/sh

cd "$(dirname $0)"

rm -rf test_db
codeql database create test_db --language=java --command ./build.sh
