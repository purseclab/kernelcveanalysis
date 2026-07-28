#!/usr/bin/env bash

set -euo pipefail

# Each Docker container runs exactly one internal Cuttlefish instance numbered
# 1, so only provision the first set of Ethernet, mobile, and Wi-Fi interfaces.
num_cvd_accounts=1 /etc/init.d/cuttlefish-host-resources start

exec "$@"
