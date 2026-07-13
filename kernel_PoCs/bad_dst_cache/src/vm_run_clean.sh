#!/bin/sh

cd /mnt/testvm-share || exit 1

export BAD_DST_MAX_ATTEMPTS="${BAD_DST_MAX_ATTEMPTS:-5}"
export BAD_DST_GET_ROOT="${BAD_DST_GET_ROOT:-0}"
export BAD_DST_RUN_ROOT_PAYLOAD="${BAD_DST_RUN_ROOT_PAYLOAD:-0}"

exec ./bad_dst_cache_clean
