#!/bin/sh

codeql query run query_test.ql --database test_db --output output.bqrs
codeql bqrs decode output.bqrs --output=output.csv --format=csv
cat output.csv
