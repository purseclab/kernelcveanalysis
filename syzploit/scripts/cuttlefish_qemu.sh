#!/usr/bin/env bash
#
# cuttlefish_qemu.sh
#
# Launches Cuttlefish with QEMU instead of crosvm and optionally runs syzploit
# test/pipeline commands against it.
#
# Why QEMU?  crosvm's GDB stub only supports a single CPU, making it unusable
# for exploits that need multiple CPUs.  QEMU supports multi-CPU GDB.
#
# This script:
#   1. Creates a QEMU wrapper that injects the necessary flags
#      (audio fix, vsock device, MTE disable, GDB port, nokaslr)
#   2. Launches Cuttlefish with `--vm_manager qemu_cli`
#   3. Waits for boot and optionally runs a syzploit command
#   4. Cleans up the wrapper on exit
#
# Usage:
#   # Just boot Cuttlefish with QEMU + GDB
#   ./cuttlefish_qemu.sh --cf-dir ~/cuttlefish \
#       --kernel ~/kernel/Image --initramfs ~/kernel/initramfs.img
#
#   # Boot and run syzploit test-cuttlefish
#   ./cuttlefish_qemu.sh --cf-dir ~/cuttlefish \
#       --kernel ~/kernel/Image --initramfs ~/kernel/initramfs.img \
#       --bug-id abc123def456 --syzkall-kernel android-5-10
#
#   # Full pipeline
#   ./cuttlefish_qemu.sh --cf-dir ~/cuttlefish \
#       --kernel ~/kernel/Image --initramfs ~/kernel/initramfs.img \
#       --bug-id abc123def456 --pipeline
#
# Requirements:
#   - qemu-system-aarch64 installed (apt install qemu-system-arm)
#   - Cuttlefish host tools built (https://source.android.com/docs/devices/cuttlefish/get-started)
#   - sudo access (to move qemu binary and create wrapper)
#   - syzploit installed (pip install -e .) if --bug-id is used

set -euo pipefail

# ============================================================================
# Defaults
# ============================================================================
CF_DIR=""                    # Cuttlefish home directory (contains bin/launch_cvd)
KERNEL_PATH=""               # Path to kernel Image
INITRAMFS_PATH=""            # Path to initramfs.img
GDB_PORT=1234                # GDB server port
EXTRA_KERNEL_CMDLINE="nokaslr"
NUM_CPUS=2                   # Number of guest CPUs

# syzploit integration
BUG_ID=""                    # If set, run syzploit after boot
SYZKALL_KERNEL="android-5-10"
ARCH="arm64"
RUN_PIPELINE=false           # Run pipeline-cuttlefish instead of test-cuttlefish
SSH_HOST="localhost"
SSH_PORT=22
ADB_PORT=6520
INSTANCE=""
SYZPLOIT_EXTRA_ARGS=""

# QEMU binary
QEMU_BIN=""                  # Auto-detected
QEMU_WRAPPER_INSTALLED=false
QEMU_REAL_SUFFIX=".syzploit_real"

# ============================================================================
# Argument parsing
# ============================================================================
usage() {
    cat <<'USAGE'
Usage: cuttlefish_qemu.sh [OPTIONS]

Boot Options:
  --cf-dir DIR           Cuttlefish home directory (required)
  --kernel PATH          Path to kernel Image (required)
  --initramfs PATH       Path to initramfs.img (required)
  --gdb-port PORT        GDB port (default: 1234)
  --cpus N               Number of guest CPUs (default: 2)
  --extra-cmdline STR    Extra kernel cmdline (default: "nokaslr")
  --no-gdb               Disable GDB server

syzploit Integration:
  --bug-id ID            Bug ID to test (enables syzploit after boot)
  --syzkall-kernel NAME  Kernel name (default: android-5-10)
  --arch ARCH            Architecture (default: arm64)
  --pipeline             Run pipeline-cuttlefish instead of test-cuttlefish
  --ssh-host HOST        SSH host (default: localhost)
  --ssh-port PORT        SSH port (default: 22)
  --adb-port PORT        ADB port (default: 6520)
  --instance N           Cuttlefish instance number (auto-calculates ADB port)
  --syzploit-args "..."  Extra args to pass to syzploit command

Other:
  --help                 Show this help
USAGE
    exit 0
}

ENABLE_GDB=true

while [[ $# -gt 0 ]]; do
    case "$1" in
        --cf-dir)       CF_DIR="$2"; shift 2 ;;
        --kernel)       KERNEL_PATH="$2"; shift 2 ;;
        --initramfs)    INITRAMFS_PATH="$2"; shift 2 ;;
        --gdb-port)     GDB_PORT="$2"; shift 2 ;;
        --cpus)         NUM_CPUS="$2"; shift 2 ;;
        --extra-cmdline) EXTRA_KERNEL_CMDLINE="$2"; shift 2 ;;
        --no-gdb)       ENABLE_GDB=false; shift ;;
        --bug-id)       BUG_ID="$2"; shift 2 ;;
        --syzkall-kernel) SYZKALL_KERNEL="$2"; shift 2 ;;
        --arch)         ARCH="$2"; shift 2 ;;
        --pipeline)     RUN_PIPELINE=true; shift ;;
        --ssh-host)     SSH_HOST="$2"; shift 2 ;;
        --ssh-port)     SSH_PORT="$2"; shift 2 ;;
        --adb-port)     ADB_PORT="$2"; shift 2 ;;
        --instance)     INSTANCE="$2"; shift 2 ;;
        --syzploit-args) SYZPLOIT_EXTRA_ARGS="$2"; shift 2 ;;
        --help|-h)      usage ;;
        *)              echo "Unknown option: $1"; usage ;;
    esac
done

# ============================================================================
# Validation
# ============================================================================
if [[ -z "$CF_DIR" ]]; then
    echo "ERROR: --cf-dir is required"
    exit 1
fi
if [[ -z "$KERNEL_PATH" ]]; then
    echo "ERROR: --kernel is required"
    exit 1
fi
if [[ -z "$INITRAMFS_PATH" ]]; then
    echo "ERROR: --initramfs is required"
    exit 1
fi

CF_DIR="$(realpath "$CF_DIR")"
KERNEL_PATH="$(realpath "$KERNEL_PATH")"
INITRAMFS_PATH="$(realpath "$INITRAMFS_PATH")"

if [[ ! -f "$CF_DIR/bin/launch_cvd" ]]; then
    echo "ERROR: $CF_DIR/bin/launch_cvd not found. Is --cf-dir correct?"
    exit 1
fi
if [[ ! -f "$KERNEL_PATH" ]]; then
    echo "ERROR: Kernel image not found: $KERNEL_PATH"
    exit 1
fi
if [[ ! -f "$INITRAMFS_PATH" ]]; then
    echo "ERROR: initramfs not found: $INITRAMFS_PATH"
    exit 1
fi

# ============================================================================
# Locate QEMU binary
# ============================================================================
find_qemu() {
    # Check if wrapper is already installed from a previous run
    for candidate in /usr/bin/qemu-system-aarch64 /usr/local/bin/qemu-system-aarch64; do
        if [[ -f "${candidate}${QEMU_REAL_SUFFIX}" ]]; then
            QEMU_BIN="$candidate"
            echo "[+] Found existing QEMU wrapper at $QEMU_BIN (real binary: ${QEMU_BIN}${QEMU_REAL_SUFFIX})"
            return 0
        fi
    done

    # Find the real binary
    QEMU_BIN="$(command -v qemu-system-aarch64 2>/dev/null || true)"
    if [[ -z "$QEMU_BIN" ]]; then
        echo "ERROR: qemu-system-aarch64 not found. Install with:"
        echo "  sudo apt install qemu-system-arm"
        exit 1
    fi

    # Resolve symlinks to get the actual binary path
    QEMU_BIN="$(realpath "$QEMU_BIN")"
    echo "[+] Found QEMU at: $QEMU_BIN"
}

# ============================================================================
# QEMU Wrapper Management
# ============================================================================
# The wrapper intercepts the qemu command that Cuttlefish spawns and injects
# flags for: audio fix, vsock, MTE disable, GDB, and debug logging.

install_qemu_wrapper() {
    local real_qemu="${QEMU_BIN}${QEMU_REAL_SUFFIX}"

    # If wrapper already installed, skip
    if [[ -f "$real_qemu" ]]; then
        echo "[+] QEMU wrapper already installed"
        QEMU_WRAPPER_INSTALLED=true
        # Update the wrapper in case flags changed
        write_wrapper
        return 0
    fi

    echo "[+] Installing QEMU wrapper..."
    echo "    Moving $QEMU_BIN -> $real_qemu"

    sudo mv "$QEMU_BIN" "$real_qemu"
    write_wrapper
    QEMU_WRAPPER_INSTALLED=true
    echo "[+] QEMU wrapper installed"
}

write_wrapper() {
    local real_qemu="${QEMU_BIN}${QEMU_REAL_SUFFIX}"
    local gdb_arg=""

    if [[ "$ENABLE_GDB" == true ]]; then
        gdb_arg="-gdb tcp::${GDB_PORT}"
    fi

    local wrapper_content
    wrapper_content=$(cat <<WRAPPER_EOF
#!/bin/bash
# Auto-generated QEMU wrapper for Cuttlefish (by syzploit cuttlefish_qemu.sh)
# Real binary: ${real_qemu}
# Generated: $(date -Iseconds)

real_qemu="${real_qemu}"

args=()
for arg in "\$@"; do
    # Disable Memory Tagging Extension (causes issues with vsock)
    new_arg="\${arg//mte=on/mte=off}"

    # Replace AC97 audio device with dummy backend
    if [[ "\$new_arg" == AC97* ]]; then
        args+=("AC97,audiodev=audio_none")
        continue
    fi

    args+=("\$new_arg")
done

# Inject additional devices and options
args+=( -device vhost-vsock-pci,guest-cid=69 )
args+=( -audiodev driver=none,id=audio_none )
args+=( -d guest_errors,unimp,cpu_reset -D /tmp/qemu_cuttlefish.log )
${gdb_arg:+args+=( ${gdb_arg} )}

exec "\$real_qemu" "\${args[@]}"
WRAPPER_EOF
    )

    echo "$wrapper_content" | sudo tee "$QEMU_BIN" > /dev/null
    sudo chmod +x "$QEMU_BIN"
}

remove_qemu_wrapper() {
    local real_qemu="${QEMU_BIN}${QEMU_REAL_SUFFIX}"
    if [[ -f "$real_qemu" ]]; then
        echo "[+] Restoring original QEMU binary..."
        sudo mv "$real_qemu" "$QEMU_BIN"
        echo "[+] QEMU wrapper removed"
    fi
}

# ============================================================================
# Cuttlefish Management
# ============================================================================
stop_cuttlefish() {
    echo "[+] Stopping Cuttlefish..."
    (cd "$CF_DIR" && HOME="$CF_DIR" ./bin/stop_cvd 2>/dev/null) || true
    sleep 2
}

start_cuttlefish() {
    echo ""
    echo "============================================"
    echo "  Launching Cuttlefish with QEMU"
    echo "============================================"
    echo "  Kernel:     $KERNEL_PATH"
    echo "  Initramfs:  $INITRAMFS_PATH"
    echo "  VM Manager: qemu_cli"
    echo "  CPUs:       $NUM_CPUS"
    echo "  GDB:        ${ENABLE_GDB} (port ${GDB_PORT})"
    echo "  Extra args: $EXTRA_KERNEL_CMDLINE"
    echo "============================================"
    echo ""

    local launch_args=(
        -kernel_path "$KERNEL_PATH"
        -initramfs_path "$INITRAMFS_PATH"
        -vm_manager qemu_cli
        -cpus "$NUM_CPUS"
    )

    # Cuttlefish's own --gdb_port flag controls crosvm's stub.
    # For QEMU, we inject GDB via the wrapper instead.  But we still pass
    # the flag so Cuttlefish knows GDB is available:
    if [[ "$ENABLE_GDB" == true ]]; then
        launch_args+=( --gdb_port "$GDB_PORT" )
    fi

    if [[ -n "$EXTRA_KERNEL_CMDLINE" ]]; then
        launch_args+=( -extra_kernel_cmdline "$EXTRA_KERNEL_CMDLINE" )
    fi

    echo "[+] Running: HOME=$CF_DIR ./bin/launch_cvd ${launch_args[*]}"
    echo ""

    cd "$CF_DIR"
    HOME="$CF_DIR" ./bin/launch_cvd "${launch_args[@]}" --daemon &
    local launch_pid=$!

    # Wait for boot
    echo "[+] Waiting for Cuttlefish to boot..."
    local waited=0
    local max_wait=300  # 5 minutes

    while (( waited < max_wait )); do
        # Check if launch_cvd exited with error
        if ! kill -0 "$launch_pid" 2>/dev/null; then
            wait "$launch_pid" || true
            # launch_cvd with --daemon exits after boot, so this is normal
            break
        fi

        # Check if ADB device is online
        if adb devices 2>/dev/null | grep -q "0.0.0.0:${ADB_PORT}.*device"; then
            echo "[+] ADB device online at 0.0.0.0:${ADB_PORT}"
            break
        fi

        # Check boot_complete
        local boot_done
        boot_done=$(adb -s "0.0.0.0:${ADB_PORT}" shell getprop sys.boot_completed 2>/dev/null || true)
        if [[ "$boot_done" == "1" ]]; then
            echo "[+] Boot completed!"
            break
        fi

        sleep 5
        waited=$((waited + 5))
        if (( waited % 30 == 0 )); then
            echo "[+] Still waiting for boot... (${waited}s / ${max_wait}s)"
        fi
    done

    if (( waited >= max_wait )); then
        echo "[!] WARNING: Boot timeout after ${max_wait}s. Cuttlefish may still be starting."
    fi

    # Give the system a moment to stabilize
    sleep 5

    echo ""
    echo "[+] Cuttlefish should be running"

    if [[ "$ENABLE_GDB" == true ]]; then
        echo "[+] GDB server available at localhost:${GDB_PORT}"
        echo "    Connect with: gdb -ex 'target remote :${GDB_PORT}'"
    fi

    echo "[+] ADB should be at: adb connect 0.0.0.0:${ADB_PORT}"
    echo "[+] QEMU log: /tmp/qemu_cuttlefish.log"
    echo ""
}

# ============================================================================
# syzploit Integration
# ============================================================================
run_syzploit() {
    if [[ -z "$BUG_ID" ]]; then
        return 0
    fi

    echo ""
    echo "============================================"
    echo "  Running syzploit"
    echo "============================================"
    echo ""

    # Build the syzploit command
    local cmd="syzploit"

    if [[ "$RUN_PIPELINE" == true ]]; then
        cmd="$cmd pipeline-cuttlefish"
    else
        cmd="$cmd test-cuttlefish"
    fi

    cmd="$cmd $BUG_ID"
    cmd="$cmd --syzkall-kernel $SYZKALL_KERNEL"
    cmd="$cmd --arch $ARCH"
    cmd="$cmd --ssh-host $SSH_HOST"
    cmd="$cmd --ssh-port $SSH_PORT"
    cmd="$cmd --gdb-port $GDB_PORT"
    cmd="$cmd --persistent --already-running"
    cmd="$cmd --kernel-image $KERNEL_PATH"

    if [[ -n "$INSTANCE" ]]; then
        cmd="$cmd --instance $INSTANCE"
    else
        cmd="$cmd --adb-port $ADB_PORT"
    fi

    if [[ -n "$SYZPLOIT_EXTRA_ARGS" ]]; then
        cmd="$cmd $SYZPLOIT_EXTRA_ARGS"
    fi

    echo "[+] Running: $cmd"
    echo ""

    eval "$cmd"
}

# ============================================================================
# Cleanup
# ============================================================================
cleanup() {
    local exit_code=$?
    echo ""
    echo "[+] Cleaning up..."

    # Only stop Cuttlefish if we started it
    if [[ "$CUTTLEFISH_STARTED" == true ]]; then
        stop_cuttlefish
    fi

    # Restore QEMU binary
    if [[ "$RESTORE_QEMU_ON_EXIT" == true ]]; then
        remove_qemu_wrapper
    fi

    exit "$exit_code"
}

# ============================================================================
# Main
# ============================================================================
CUTTLEFISH_STARTED=false
RESTORE_QEMU_ON_EXIT=false

main() {
    echo ""
    echo "============================================"
    echo "  syzploit Cuttlefish+QEMU Launcher"
    echo "============================================"
    echo ""

    # Find QEMU binary
    find_qemu

    # Install the QEMU wrapper
    install_qemu_wrapper

    # Ask user if they want to auto-restore on exit
    # (For repeated use, you may want to keep the wrapper installed)
    if [[ -t 0 ]]; then
        echo ""
        echo "[?] Remove QEMU wrapper on exit? (y/N)"
        echo "    (Say 'N' to keep it for repeated runs)"
        read -r -t 10 answer || answer="n"
        if [[ "$answer" =~ ^[Yy] ]]; then
            RESTORE_QEMU_ON_EXIT=true
        fi
    fi

    # Register cleanup
    trap cleanup EXIT INT TERM

    # Stop any existing Cuttlefish
    stop_cuttlefish

    # Start Cuttlefish with QEMU
    start_cuttlefish
    CUTTLEFISH_STARTED=true

    # Run syzploit if bug-id is provided
    if [[ -n "$BUG_ID" ]]; then
        run_syzploit
    else
        echo "[+] No --bug-id specified. Cuttlefish is running."
        echo "[+] You can now run syzploit manually, e.g.:"
        echo ""
        echo "    syzploit test-cuttlefish <BUG_ID> \\"
        echo "        --persistent --already-running \\"
        echo "        --gdb-port ${GDB_PORT} --adb-port ${ADB_PORT} \\"
        echo "        --kernel-image ${KERNEL_PATH}"
        echo ""
        echo "[+] Or connect GDB directly:"
        echo "    gdb vmlinux -ex 'target remote :${GDB_PORT}'"
        echo ""
        echo "[+] Press Ctrl+C to stop Cuttlefish and clean up."
        echo ""

        # Keep script running so cleanup trap fires on Ctrl+C
        while true; do
            sleep 60
        done
    fi
}

main
