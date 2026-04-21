#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <sched.h>
#include <string.h>
#include <assert.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

typedef uint64_t u64;
typedef int64_t i64;
typedef uint32_t u32;
typedef int32_t i32;
typedef uint16_t u16;
typedef int16_t i16;
typedef uint8_t u8;
typedef int8_t i8;

typedef size_t usize;

#define LOG(fmt, ...) do { \
    printf(fmt "\n", ##__VA_ARGS__); \
} while(0)

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

#define CHECK(x, n) ({                  \
    __typeof__(x) __res = (x);          \
    if (__res != n) {   \
        LOG("SYSCHK(" #x ") = %d\n", __res);\
        int error_val = errno;            \
        LOG("errno: %d\n", error_val);    \
        exit(1);                          \
    }                                   \
    __res;                              \
})

int open_connected_ipv6_udp_socket() {
    int socket_fd = SYSCHK(socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP));

    struct sockaddr_in6 addr = { 0 };
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(1337);
    SYSCHK(inet_pton(AF_INET6, "::1", &addr.sin6_addr));

    SYSCHK(connect(socket_fd, (struct sockaddr*)&addr, sizeof(addr)));

    return socket_fd;
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

void panic(const char *msg) {
    puts(msg);
    exit(1);
}

void check_mtu(int socket) {
  int result = 0;
  u32 result_len = sizeof(result);
  printf("%d\n", getsockopt(socket, SOL_IPV6, IPV6_MTU, &result, &result_len));
  printf("mtu: %d\n", result);
}

int main() {
  int socket = open_connected_ipv6_udp_socket();

  check_mtu(socket);
  int one = 1;
  SYSCHK(setsockopt(socket, SOL_SOCKET, SO_CNX_ADVICE, &one, sizeof(one)));
  check_mtu(socket);
}
