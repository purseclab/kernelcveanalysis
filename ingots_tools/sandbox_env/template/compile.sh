#!/bin/sh

ARCH="aarch64"
TOOLCHAIN="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64"
TARGET="${ARCH}-linux-android"
API="30"

CC="${TOOLCHAIN}/bin/${TARGET}${API}-clang"
CXX="${TOOLCHAIN}/bin/${TARGET}${API}-clang++"

echo $CC

cd "$(dirname $0)"

# CC=gcc
# make a static binary which runs a shell when root is acheived
$CC exploit.c -o exploit $(./common/payload-flags --static --shell)
