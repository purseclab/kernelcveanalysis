#!/usr/bin/env bash
#
# deploy_cuttlefish.sh
#
# Deploys Cuttlefish management scripts to a remote host for use with syzploit.
#
# This script:
#   1. Generates the instance scripts (gdb_run.sh, run.sh, stop.sh) locally
#   2. Copies them + the QEMU wrapper script to the remote host via SCP
#   3. Optionally installs the QEMU wrapper on the remote host (for QEMU mode)
#
# After deployment, you can use syzploit pipeline-cuttlefish with:
#   --start-cmd "cd <remote-dir> && ./gdb_run.sh <N>"
#   --stop-cmd  "cd <remote-dir> && ./stop.sh <N>"
#
# Usage:
#   # Deploy with crosvm (default):
#   ./deploy_cuttlefish.sh \
#       --ssh-host INGOTS-ARM \
#       --kernel /home/user/kernel/Image \
#       --initramfs /home/user/kernel/initramfs.img \
#       --cf-dir /home/user/cuttlefish \
#       --remote-dir /home/user/cuttlefish_workspace
#
#   # Deploy with QEMU + install the QEMU wrapper:
#   ./deploy_cuttlefish.sh \
#       --ssh-host INGOTS-ARM \
#       --kernel /home/user/kernel/Image \
#       --initramfs /home/user/kernel/initramfs.img \
#       --cf-dir /home/user/cuttlefish \
#       --remote-dir /home/user/cuttlefish_workspace \
#       --qemu --install-qemu-wrapper
#
#   # Then run the pipeline:
#   uv run syzploit pipeline-cuttlefish <BUG_ID> \
#       --ssh-host INGOTS-ARM --instance 20 \
#       --start-cmd "cd /home/user/cuttlefish_workspace && ./gdb_run.sh 20" \
#       --stop-cmd "cd /home/user/cuttlefish_workspace && ./stop.sh 20"

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ============================================================================
# Defaults
# ============================================================================
SSH_HOST=""
SSH_PORT=22
SSH_USER=""                  # Empty = use ~/.ssh/config
KERNEL_PATH=""               # Path on the REMOTE host
INITRAMFS_PATH=""            # Path on the REMOTE host
CF_DIR=""                    # Cuttlefish dir on the REMOTE host
REMOTE_DIR=""                # Where to put the scripts on the remote host
GDB_PORT=1234
NUM_CPUS=6
EXTRA_KERNEL_CMDLINE="androidboot.selinux=permissive"
USE_QEMU=true                # Default to qemu_cli (multi-CPU GDB support)
INSTALL_QEMU_WRAPPER=false

# Local paths to kernel/initramfs to upload (optional)
LOCAL_KERNEL=""
LOCAL_INITRAMFS=""

# ============================================================================
# Argument parsing
# ============================================================================
usage() {
    cat <<'USAGE'
Usage: deploy_cuttlefish.sh [OPTIONS]

Required:
  --ssh-host HOST        Remote host (SSH alias or hostname)
  --cf-dir DIR           Cuttlefish home directory on remote host
  --remote-dir DIR       Directory on remote host to deploy scripts into

Kernel paths (on the REMOTE host):
  --kernel PATH          Path to kernel Image on remote host
  --initramfs PATH       Path to initramfs.img on remote host (optional)

Upload local kernel/initramfs to remote (optional):
  --local-kernel PATH    Local kernel Image to upload
  --local-initramfs PATH Local initramfs.img to upload
  (When used, --kernel/--initramfs default to <remote-dir>/Image and <remote-dir>/initramfs.img)

Options:
  --ssh-port PORT        SSH port (default: 22)
  --ssh-user USER        SSH user (default: from ~/.ssh/config)
  --gdb-port PORT        GDB port (default: 1234)
  --cpus N               Number of guest CPUs (default: 6)
  --extra-cmdline STR    Extra kernel cmdline (default: "androidboot.selinux=permissive")
  --qemu                 Use qemu_cli (default: enabled)
  --no-qemu              Use crosvm instead of qemu_cli
  --install-qemu-wrapper Install the QEMU wrapper on the remote host (requires sudo)
  --help                 Show this help
USAGE
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ssh-host)             SSH_HOST="$2"; shift 2 ;;
        --ssh-port)             SSH_PORT="$2"; shift 2 ;;
        --ssh-user)             SSH_USER="$2"; shift 2 ;;
        --kernel)               KERNEL_PATH="$2"; shift 2 ;;
        --initramfs)            INITRAMFS_PATH="$2"; shift 2 ;;
        --local-kernel)         LOCAL_KERNEL="$2"; shift 2 ;;
        --local-initramfs)      LOCAL_INITRAMFS="$2"; shift 2 ;;
        --cf-dir)               CF_DIR="$2"; shift 2 ;;
        --remote-dir)           REMOTE_DIR="$2"; shift 2 ;;
        --gdb-port)             GDB_PORT="$2"; shift 2 ;;
        --cpus)                 NUM_CPUS="$2"; shift 2 ;;
        --extra-cmdline)        EXTRA_KERNEL_CMDLINE="$2"; shift 2 ;;
        --qemu)                 USE_QEMU=true; shift ;;
        --no-qemu)              USE_QEMU=false; shift ;;
        --install-qemu-wrapper) INSTALL_QEMU_WRAPPER=true; shift ;;
        --help|-h)              usage ;;
        *)                      echo "Unknown option: $1"; usage ;;
    esac
done

# ============================================================================
# Validate
# ============================================================================
if [[ -z "$SSH_HOST" ]]; then
    echo "ERROR: --ssh-host is required"; exit 1
fi
if [[ -z "$CF_DIR" ]]; then
    echo "ERROR: --cf-dir is required"; exit 1
fi
if [[ -z "$REMOTE_DIR" ]]; then
    echo "ERROR: --remote-dir is required"; exit 1
fi

# If uploading local kernel files, set remote paths to the upload destination
if [[ -n "$LOCAL_KERNEL" ]]; then
    if [[ ! -f "$LOCAL_KERNEL" ]]; then
        echo "ERROR: Local kernel not found: $LOCAL_KERNEL"; exit 1
    fi
    [[ -z "$KERNEL_PATH" ]] && KERNEL_PATH="$REMOTE_DIR/Image"
fi
if [[ -n "$LOCAL_INITRAMFS" ]]; then
    if [[ ! -f "$LOCAL_INITRAMFS" ]]; then
        echo "ERROR: Local initramfs not found: $LOCAL_INITRAMFS"; exit 1
    fi
    [[ -z "$INITRAMFS_PATH" ]] && INITRAMFS_PATH="$REMOTE_DIR/initramfs.img"
fi

if [[ -z "$KERNEL_PATH" ]]; then
    echo "ERROR: --kernel or --local-kernel is required"; exit 1
fi

# Build SSH options
SSH_OPTS=(-o StrictHostKeyChecking=no -o ConnectTimeout=10)
[[ "$SSH_PORT" != "22" ]] && SSH_OPTS+=(-p "$SSH_PORT")
[[ -n "$SSH_USER" ]] && SSH_OPTS+=(-l "$SSH_USER")
SCP_OPTS=("${SSH_OPTS[@]}")
[[ "$SSH_PORT" != "22" ]] && SCP_OPTS+=(-P "$SSH_PORT")

ssh_cmd() {
    ssh "${SSH_OPTS[@]}" "$SSH_HOST" "$@"
}

scp_cmd() {
    scp "${SCP_OPTS[@]}" "$@"
}

VM_MANAGER="crosvm"
if [[ "$USE_QEMU" == true ]]; then
    VM_MANAGER="qemu_cli"
fi

echo ""
echo "============================================"
echo "  Deploying Cuttlefish scripts"
echo "============================================"
echo "  Remote host:   $SSH_HOST"
echo "  Remote dir:    $REMOTE_DIR"
echo "  CF dir:        $CF_DIR"
echo "  Kernel:        $KERNEL_PATH"
echo "  Initramfs:     ${INITRAMFS_PATH:-(not set, using Cuttlefish default)}"
echo "  VM Manager:    $VM_MANAGER"
echo "  GDB Port:      $GDB_PORT"
echo "============================================"
echo ""

# ============================================================================
# Step 1: Test SSH connectivity
# ============================================================================
echo "[+] Testing SSH connectivity to $SSH_HOST..."
if ! ssh_cmd "echo ok" > /dev/null 2>&1; then
    echo "ERROR: Cannot connect to $SSH_HOST via SSH"
    echo "       Make sure $SSH_HOST is in ~/.ssh/config or use --ssh-user"
    exit 1
fi
echo "[+] SSH connection OK"

# ============================================================================
# Step 2: Create remote directory
# ============================================================================
echo "[+] Creating remote directory: $REMOTE_DIR"
ssh_cmd "mkdir -p '$REMOTE_DIR'"

# ============================================================================
# Step 3: Upload kernel/initramfs if local paths provided
# ============================================================================
if [[ -n "$LOCAL_KERNEL" ]]; then
    echo "[+] Uploading kernel Image..."
    scp_cmd "$LOCAL_KERNEL" "$SSH_HOST:$REMOTE_DIR/Image"
    echo "    $(du -h "$LOCAL_KERNEL" | cut -f1) uploaded"
fi
if [[ -n "$LOCAL_INITRAMFS" ]]; then
    echo "[+] Uploading initramfs..."
    scp_cmd "$LOCAL_INITRAMFS" "$SSH_HOST:$REMOTE_DIR/initramfs.img"
    echo "    $(du -h "$LOCAL_INITRAMFS" | cut -f1) uploaded"
fi

# ============================================================================
# Step 4: Generate instance scripts locally in a temp dir, then upload
# ============================================================================
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "[+] Generating instance scripts..."
GEN_ARGS=(
    --kernel "$KERNEL_PATH"
    --cf-dir "$CF_DIR"
    --output-dir "$TMPDIR"
    --gdb-port "$GDB_PORT"
    --vm-manager "$VM_MANAGER"
    --cpus "$NUM_CPUS"
    --extra-cmdline "$EXTRA_KERNEL_CMDLINE"
)
[[ -n "$INITRAMFS_PATH" ]] && GEN_ARGS+=(--initramfs "$INITRAMFS_PATH")

"$SCRIPT_DIR/gen_cuttlefish_scripts.sh" "${GEN_ARGS[@]}"

echo "[+] Uploading instance scripts..."
scp_cmd "$TMPDIR/gdb_run.sh" "$TMPDIR/run.sh" "$TMPDIR/stop.sh" \
        "$TMPDIR/cuttlefish_instance.conf" \
        "$SSH_HOST:$REMOTE_DIR/"

# Make scripts executable on the remote side
ssh_cmd "chmod +x '$REMOTE_DIR/gdb_run.sh' '$REMOTE_DIR/run.sh' '$REMOTE_DIR/stop.sh'"

# ============================================================================
# Step 5: Upload QEMU wrapper installer if using qemu_cli
# ============================================================================
if [[ "$USE_QEMU" == true ]]; then
    # Upload install_qemu_wrapper.sh (generated by gen_cuttlefish_scripts.sh
    # or copied from the scripts/ dir alongside this script)
    if [[ -f "$TMPDIR/install_qemu_wrapper.sh" ]]; then
        echo "[+] Uploading install_qemu_wrapper.sh..."
        scp_cmd "$TMPDIR/install_qemu_wrapper.sh" "$SSH_HOST:$REMOTE_DIR/"
        ssh_cmd "chmod +x '$REMOTE_DIR/install_qemu_wrapper.sh'"
    elif [[ -f "$SCRIPT_DIR/install_qemu_wrapper.sh" ]]; then
        echo "[+] Uploading install_qemu_wrapper.sh..."
        scp_cmd "$SCRIPT_DIR/install_qemu_wrapper.sh" "$SSH_HOST:$REMOTE_DIR/"
        ssh_cmd "chmod +x '$REMOTE_DIR/install_qemu_wrapper.sh'"
    else
        echo "[!] WARNING: install_qemu_wrapper.sh not found"
        echo "[!] You'll need to install the QEMU wrapper manually."
    fi
fi

# ============================================================================
# Step 6: Install QEMU wrapper on remote host (optional, needs sudo)
# ============================================================================
if [[ "$INSTALL_QEMU_WRAPPER" == true ]]; then
    echo ""
    echo "[+] Installing QEMU wrapper on $SSH_HOST..."
    echo "    This moves the real qemu-system-aarch64 binary and creates"
    echo "    a wrapper that injects GDB, vsock, audio, and MTE fixes."
    echo "    See Cuttlefish_with_gdb.md for details."
    echo ""

    ssh_cmd "cd '$REMOTE_DIR' && sudo ./install_qemu_wrapper.sh"
fi

# ============================================================================
# Step 7: Verify deployment
# ============================================================================
echo ""
echo "[+] Verifying deployment on $SSH_HOST..."
ssh_cmd "ls -la '$REMOTE_DIR/'" 2>/dev/null | head -20

# Check that launch_cvd exists
if ssh_cmd "test -f '$CF_DIR/bin/launch_cvd'" 2>/dev/null; then
    echo "[+] ✓ launch_cvd found at $CF_DIR/bin/launch_cvd"
else
    echo "[!] ✗ launch_cvd NOT found at $CF_DIR/bin/launch_cvd"
    echo "    Make sure Cuttlefish is built/installed at $CF_DIR"
fi

# Check kernel
if ssh_cmd "test -f '$KERNEL_PATH'" 2>/dev/null; then
    echo "[+] ✓ Kernel found at $KERNEL_PATH"
else
    echo "[!] ✗ Kernel NOT found at $KERNEL_PATH"
fi

# Check initramfs (if specified)
if [[ -n "$INITRAMFS_PATH" ]]; then
    if ssh_cmd "test -f '$INITRAMFS_PATH'" 2>/dev/null; then
        echo "[+] ✓ Initramfs found at $INITRAMFS_PATH"
    else
        echo "[!] ✗ Initramfs NOT found at $INITRAMFS_PATH"
    fi
fi

# Check QEMU if needed
if [[ "$USE_QEMU" == true ]]; then
    if ssh_cmd "command -v qemu-system-aarch64" > /dev/null 2>&1; then
        echo "[+] ✓ qemu-system-aarch64 found"
    else
        echo "[!] ✗ qemu-system-aarch64 NOT found"
    fi
fi

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "============================================"
echo "  Deployment complete!"
echo "============================================"
echo ""
echo "Run the syzploit pipeline with:"
echo ""
echo "  uv run syzploit pipeline-cuttlefish <BUG_ID> \\"
echo "      --syzkall-kernel upstream \\"
echo "      --dynamic-analysis \\"
echo "      --arch arm64 \\"
echo "      --ssh-host $SSH_HOST \\"
echo "      --setup-tunnels \\"
echo "      --instance <N> \\"
echo "      --no-persistent \\"
echo "      --start-cmd \"cd $REMOTE_DIR && ./gdb_run.sh <N>\" \\"
echo "      --stop-cmd \"cd $REMOTE_DIR && ./stop.sh <N>\" \\"
echo "      --exploit-start-cmd \"cd $REMOTE_DIR && ./run.sh <N>\""
echo ""
echo "To update kernel/initramfs later:"
echo "  $0 --ssh-host $SSH_HOST --cf-dir $CF_DIR --remote-dir $REMOTE_DIR \\"
echo "      --local-kernel /path/to/new/Image \\"
echo "      --local-initramfs /path/to/new/initramfs.img"
echo ""
