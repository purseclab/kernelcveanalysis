#!/bin/bash
# docker-entrypoint.sh
# Installs kexploit extras at runtime if ingots_tools is mounted.

set -e

KEXPLOIT_MARKER="/workspace/syzploit/.kexploit_installed"

# Check if ingots_tools is mounted and kexploit pyproject.toml exists
if [ -f /workspace/ingots_tools/kexploit/pyproject.toml ]; then
    # Only re-install if not already done (or if ingots_tools changed)
    INGOTS_MTIME=$(stat -c %Y /workspace/ingots_tools/kexploit/pyproject.toml 2>/dev/null || echo 0)
    MARKER_MTIME=$(stat -c %Y "$KEXPLOIT_MARKER" 2>/dev/null || echo 0)

    if [ "$INGOTS_MTIME" -gt "$MARKER_MTIME" ] || [ ! -f "$KEXPLOIT_MARKER" ]; then
        echo "[entrypoint] ingots_tools detected — installing kexploit packages..."
        cd /workspace/syzploit
        uv pip install \
            -e /workspace/ingots_tools/kexploit_utils \
            -e /workspace/ingots_tools/kexploit \
            2>&1 | tail -10
        touch "$KEXPLOIT_MARKER"
        echo "[entrypoint] kexploit integration ready."
    else
        echo "[entrypoint] kexploit already installed (use rm $KEXPLOIT_MARKER to force reinstall)."
    fi
else
    echo "[entrypoint] ingots_tools not mounted — running without kexploit integration."
fi

exec "$@"
