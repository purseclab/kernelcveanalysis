#!/bin/bash
# install_qemu_wrapper.sh — Install/update the QEMU wrapper for Cuttlefish
#
# This does exactly what Cuttlefish_with_gdb.md describes:
#   1. Finds qemu-system-aarch64
#   2. Moves it to qemu-system-aarch64.real
#   3. Creates a wrapper script in its place that:
#      - Disables MTE (mte=on -> mte=off)
#      - Replaces AC97 audio with dummy backend
#      - Adds a virtio-vsock PCI device (fixes "transport message failed")
#      - Enables QEMU debug logging to /tmp/qemu.log
#      - Injects GDB server (-gdb tcp::<PORT>) when GDB_PORT env var is set
#
# Usage:
#   sudo ./install_qemu_wrapper.sh          # Install wrapper
#   sudo ./install_qemu_wrapper.sh --remove  # Restore original binary
#   sudo ./install_qemu_wrapper.sh --status  # Check current state

SUFFIX=".real"

# ---- Find QEMU binary ----
find_qemu() {
    for candidate in /usr/bin/qemu-system-aarch64 /usr/local/bin/qemu-system-aarch64; do
        # Already wrapped — real binary moved aside
        if [[ -f "${candidate}${SUFFIX}" ]]; then
            echo "$candidate"
            return 0
        fi
        # Not yet wrapped — check it's an actual ELF binary
        if [[ -f "$candidate" ]] && file "$candidate" | grep -q "ELF"; then
            echo "$candidate"
            return 0
        fi
    done
    # Fallback to PATH lookup
    command -v qemu-system-aarch64 2>/dev/null || true
}

QEMU_BIN="$(find_qemu)"
if [[ -z "$QEMU_BIN" ]]; then
    echo "ERROR: qemu-system-aarch64 not found"
    echo "Install with: sudo apt install qemu-system-arm"
    exit 1
fi

REAL_QEMU="${QEMU_BIN}${SUFFIX}"

# ---- Status mode ----
if [[ "${1:-}" == "--status" ]]; then
    if [[ -f "$REAL_QEMU" ]]; then
        echo "[+] QEMU wrapper IS installed"
        echo "    Wrapper:     $QEMU_BIN"
        echo "    Real binary: $REAL_QEMU"
    else
        echo "[-] QEMU wrapper is NOT installed"
        echo "    Binary: $QEMU_BIN"
    fi
    exit 0
fi

# ---- Remove mode ----
if [[ "${1:-}" == "--remove" ]]; then
    if [[ -f "$REAL_QEMU" ]]; then
        echo "[+] Restoring: $REAL_QEMU -> $QEMU_BIN"
        mv "$REAL_QEMU" "$QEMU_BIN"
        echo "[+] Original QEMU binary restored"
    else
        echo "[!] No wrapper found (looking for $REAL_QEMU)"
    fi
    exit 0
fi

# ---- Install mode ----
if [[ $(id -u) -ne 0 ]]; then
    echo "ERROR: Must run as root (sudo ./install_qemu_wrapper.sh)"
    exit 1
fi

# Step 1: Move real binary aside (like the doc: mv .../qemu-system-aarch64 .../qemu-system-aarch64.real)
if [[ ! -f "$REAL_QEMU" ]]; then
    echo "[+] Moving $QEMU_BIN -> $REAL_QEMU"
    mv "$QEMU_BIN" "$REAL_QEMU"
else
    echo "[+] Real binary already at $REAL_QEMU (updating wrapper)"
fi

# Step 2: Write the wrapper script to a temp file, then mv into place.
# Using mv avoids "Text file busy" errors when QEMU is still running —
# mv replaces the directory entry atomically without writing to the open file.
echo "[+] Writing QEMU wrapper: $QEMU_BIN"
TMPWRAPPER="$(mktemp "${QEMU_BIN}.tmp.XXXXXX")"
cat > "$TMPWRAPPER" <<EOF
#!/bin/bash
# QEMU wrapper for Cuttlefish — see Cuttlefish_with_gdb.md
# Real binary: $REAL_QEMU

real_qemu="$REAL_QEMU"

args=()
for arg in "\$@"; do
  # Disable memory tagging (step 3 from Cuttlefish_with_gdb.md)
  new_arg="\${arg//mte=on/mte=off}"

  # Replace AC97 device with dummy audio backend (step 1)
  if [[ "\$new_arg" == AC97* ]]; then
    args+=("AC97,audiodev=audio_none")
    continue
  fi

  args+=("\$new_arg")
done

# Add virtio-vsock PCI device (step 2 — fixes "transport message failed")
args+=( -device vhost-vsock-pci,guest-cid=69 )
args+=( -audiodev driver=none,id=audio_none )
args+=( -d guest_errors,unimp,cpu_reset -D /tmp/qemu.log )

# Inject GDB server if GDB_PORT is set in environment AND -gdb not already present
# (Cuttlefish may already pass -gdb via --gdb_port; avoid duplicate)
has_gdb=false
for a in "\$@"; do
    [[ "\$a" == "-gdb" ]] && has_gdb=true
done
if [[ -n "\${GDB_PORT:-}" ]] && ! \$has_gdb; then
    args+=( -gdb "tcp::\$GDB_PORT" )
fi

exec "\$real_qemu" "\${args[@]}"
EOF

chmod 755 "$TMPWRAPPER"
mv "$TMPWRAPPER" "$QEMU_BIN"

echo "[+] QEMU wrapper installed successfully"
echo ""
echo "  Wrapper:     $QEMU_BIN"
echo "  Real binary: $REAL_QEMU"
echo "  QEMU log:    /tmp/qemu.log"
echo ""
echo "  To remove:  sudo $0 --remove"
echo "  To check:   sudo $0 --status"
echo ""
echo "  GDB support: gdb_run.sh automatically exports GDB_PORT."
echo "  Manual use:   export GDB_PORT=1234 before launching Cuttlefish."
