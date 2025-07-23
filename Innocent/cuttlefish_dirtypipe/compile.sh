#!/bin/sh

# change ANDROID_NDK_HOME to point to ndk inststallation
ANDROID_NDK_HOME="/home/willi/research/bianchi_research/android-ndk-r27c/"
ARCH="aarch64"
TOOLCHAIN="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64"
TARGET="${ARCH}-linux-android"
API="30"

CC="${TOOLCHAIN}/bin/${TARGET}${API}-clang"
CXX="${TOOLCHAIN}/bin/${TARGET}${API}-clang++"

echo $CC

cd "$(dirname $0)"

python3 gen_constants.py $1 $2
$CC dirtypipe.c -o dirtypipe

