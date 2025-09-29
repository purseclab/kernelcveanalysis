#!/bin/sh

compile_android read_file.c read_file || exit 1
compile_android dump_seccomp_filter.c dump_seccomp_filter || exit 1
