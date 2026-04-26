#!/bin/sh

# change ANDROID_NDK_HOME to point to ndk inststallation
CC=gcc

echo $CC

cd "$(dirname $0)"

# CC=gcc
# $CC exp_cuttlefish.c -o bad_io_uring.so -llog -shared -fpic
# $CC exp_cuttlefish.c -o bad_io_uring -static
$CC exp_x86.c -o bad_dst_cache $(../../common/payload-flags --static --listening-shell --port 1340)

# nix-shell -p glibc.static --run "gcc -static exp_cuttlefish.c -o bad_io_uring"

