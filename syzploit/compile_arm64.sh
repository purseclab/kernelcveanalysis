#!/bin/sh

# arg 1 is source file
# arg 2 is binary destination file

# change ANDROID_NDK_HOME to point to ndk inststallation
ANDROID_NDK_HOME="/workspace/android_sdk/ndk/25.2.9519653/"
ARCH="aarch64"
TOOLCHAIN="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64"
TARGET="${ARCH}-linux-android"
API="30"

CC="${TOOLCHAIN}/bin/${TARGET}${API}-clang"
CXX="${TOOLCHAIN}/bin/${TARGET}${API}-clang++"

# Fallback to system cross-compiler if NDK is not available
if [ ! -x "$CC" ]; then
    CC="$(which aarch64-linux-gnu-gcc 2>/dev/null)"
    if [ -z "$CC" ]; then
        echo "ERROR: No ARM64 cross-compiler found" >&2
        exit 1
    fi
fi

echo $CC

$CC -Wno-unknown-warning-option $EXTRA_CFLAGS $1 -pthread -static -o $2

