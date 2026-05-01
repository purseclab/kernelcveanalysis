#!/bin/sh

cd "$(dirname $0)"

mkdir -p files
# python3 -m http.server 8067 --bind 0.0.0.0 --directory ./files
python3 http_server.py --interface 0.0.0.0 --port 8067
