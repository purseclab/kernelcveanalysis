#!/bin/bash

set -eu

# VMLINUX="${VMLINUX:-/home/jack/Documents/college/purdue/research/linux_build/build_out/lakitu_defconfig_no_modules_modified__x86_64__gcc-10/vmlinux}"
VMLINUX="./vmlinux"
KERNEL_SRC="${KERNEL_SRC:-/home/jack/Documents/college/purdue/research/linux_src/linux_stable}"
GDB_PORT="${GDB_PORT:-12345}"
GDB_BIN="${GDB_BIN:-pwndbg}"

if [ ! -f "$VMLINUX" ]; then
	echo "error: vmlinux not found: $VMLINUX" >&2
	exit 1
fi

if [ ! -d "$KERNEL_SRC" ]; then
	echo "error: kernel source tree not found: $KERNEL_SRC" >&2
	exit 1
fi

exec "$GDB_BIN" \
	-ex "file $VMLINUX" \
	-ex "set substitute-path /src $KERNEL_SRC" \
	-ex "directory $KERNEL_SRC" \
	-ex "target remote :$GDB_PORT" \
	"$@"
