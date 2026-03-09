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

echo $CC

$CC $1 -pthread -static -o $2

