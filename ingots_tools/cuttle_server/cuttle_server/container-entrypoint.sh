#!/usr/bin/env bash

set -euo pipefail

readonly OPERATOR_SOCKET=/run/cuttlefish/operator
readonly OPERATOR_START_TIMEOUT_SEC=10

# The cuttlefish-base init scripts always exit 0, even when individual setup
# steps fail, so check for the resources launch_cvd needs instead of trusting
# their exit codes.
require_interfaces() {
    local missing=()
    local name
    for name in "$@"; do
        if ! ip link show dev "${name}" >/dev/null 2>&1; then
            missing+=("${name}")
        fi
    done
    if (( ${#missing[@]} > 0 )); then
        echo "cuttlefish-entrypoint: missing network interfaces: ${missing[*]}" >&2
        exit 1
    fi
}

wait_for_operator() {
    local deadline=$(( SECONDS + OPERATOR_START_TIMEOUT_SEC ))
    until [[ -S "${OPERATOR_SOCKET}" ]]; do
        if (( SECONDS >= deadline )); then
            echo "cuttlefish-entrypoint: operator socket ${OPERATOR_SOCKET} did not appear" >&2
            cat /run/cuttlefish/operator.log >&2 2>/dev/null || true
            exit 1
        fi
        sleep 0.2
    done
}

# Each Docker container runs exactly one internal Cuttlefish instance numbered
# 1, so only provision the first set of Ethernet, mobile, and Wi-Fi interfaces.
num_cvd_accounts=1 /etc/init.d/cuttlefish-host-resources start
require_interfaces \
    cvd-ebr cvd-etap-01 \
    cvd-mtap-01 \
    cvd-wbr cvd-wtap-01 cvd-wifiap-01

# launch_cvd runs webRTC (the host end of the guest display and audio), which
# registers with the operator. Run a per-container operator for it.
/etc/init.d/cuttlefish-operator start
wait_for_operator

# Everything above needs root. Cuttlefish itself runs as the host user that
# launched the container (the cuttle_server user), so files it writes into
# bind-mounted host paths such as the runtime root keep host-mode ownership.
run_uid="${CUTTLE_CONTAINER_UID:?CUTTLE_CONTAINER_UID must be set}"
run_gid="${CUTTLE_CONTAINER_GID:?CUTTLE_CONTAINER_GID must be set}"

# Give the host ids names so getpwuid()/getgrgid() lookups behave as on the host.
if ! getent group "${run_gid}" >/dev/null; then
    echo "cuttle:x:${run_gid}:" >> /etc/group
fi
if ! getent passwd "${run_uid}" >/dev/null; then
    echo "cuttle:x:${run_uid}:${run_gid}::${HOME}:/bin/bash" >> /etc/passwd
fi
chown "${run_uid}:${run_gid}" "${HOME}"

# TAPs are created with group cvdnetwork, and /dev/kvm and the vhost devices
# are owned by kvm and cvdnetwork, matching the host-mode group membership.
kvm_gid="$(getent group kvm | cut -d: -f3)"
cvdnetwork_gid="$(getent group cvdnetwork | cut -d: -f3)"
exec setpriv \
    --reuid="${run_uid}" \
    --regid="${run_gid}" \
    --groups="${kvm_gid},${cvdnetwork_gid}" \
    -- "$@"
