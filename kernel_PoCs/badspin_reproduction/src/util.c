#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sched.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/epoll.h>
#include <sys/uio.h>
#include <limits.h>
#include <stdlib.h>
#include <linux/ioctl.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <ctype.h>
#include "util.h"

void *zalloc(size_t sz) {
    return calloc(1, sz);
}

void close_all_fds_except_stdio(void) {
    long max_fds = sysconf(_SC_OPEN_MAX);
    if (max_fds < 0) {
        max_fds = 1024;
    }

    for (int fd = 3; fd < max_fds; fd++) {
        close(fd);
    }
}

int get_fdtable_size(void) {
    char buf[4096];
    int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        return -1;
    }

    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        return -1;
    }
    buf[n] = '\0';

    char *line = strstr(buf, "FDSize:");
    if (line == NULL) {
        return -1;
    }

    int fdsize = -1;
    sscanf(line, "FDSize:%d", &fdsize);
    return fdsize;
}

int pin_to_cpu(int cpu) {
    int rc;
    int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    cpu_set_t *cpu_setp = CPU_ALLOC(num_cpus);
    size_t size = CPU_ALLOC_SIZE(num_cpus);
    CPU_ZERO_S(size, cpu_setp);
    if (cpu >= 0 && cpu < num_cpus) {
        CPU_SET_S(cpu, size, cpu_setp);
    } else {
        for (int i = 0; i < num_cpus; i++) {
            CPU_SET_S(i, size, cpu_setp);
        }
    }

    rc = sched_setaffinity(0, size, cpu_setp);
    // if (rc) {
    //     printf("cpu %d failed to be pinned (num cpus = %d)\n", cpu, num_cpus);
    //     perror("sched_setaffinity");
    // }
    CPU_FREE(cpu_setp);
    return rc;
}

void wait_for_x() {
    int c = 0;
    do {
        c = getchar();
    } while (c != 'x' && c != 'X');
}

#define ROW_SZ 16
void hexdump(void *buf, size_t sz) {
    uint8_t *start = buf;
    uint8_t *end = start + sz;
    uint8_t *p = start;
    uint8_t *prev_p = p;

    while (p < end) {
        printf("%02x ", *p);
        if (((p-start) + 1) % ROW_SZ == 0) {
            while (prev_p <= p) {
                if (isprint(*prev_p)) {
                    printf("%c", (char)*prev_p);
                } else {
                    printf(".");
                }
                prev_p++;
            }
            printf("\n");
        }
        p++;
    }
    if (sz % ROW_SZ != 0) {
        for (int i = 0; i < (sz % ROW_SZ); i++) {
            printf("   ");
        }
        while (prev_p <= p) {
            if (isprint(*prev_p)) {
                printf("%c", (char)*prev_p);
            } else {
                printf(".");
            }
            prev_p++;
        }
        printf("\n");
    }
}
