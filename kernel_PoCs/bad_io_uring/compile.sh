#!/bin/sh

# change ANDROID_NDK_HOME to point to ndk inststallation
ANDROID_NDK_HOME="/home/jack/Documents/college/purdue/research/android_sdk/ndk/25.2.9519653/"
ARCH="aarch64"
TOOLCHAIN="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64"
TARGET="${ARCH}-linux-android"
API="30"

CC="${TOOLCHAIN}/bin/${TARGET}${API}-clang"
CXX="${TOOLCHAIN}/bin/${TARGET}${API}-clang++"

echo $CC

cd "$(dirname $0)"

# CC=gcc
$CC exp_cuttlefish.c -o bad_io_uring.so -llog -shared -fpic

# nix-shell -p glibc.static --run "gcc -static exp_cuttlefish.c -o bad_io_uring"

