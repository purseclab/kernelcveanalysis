#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

typedef uint32_t u32;

#define BODY_SIZE 0x1000
#define CMSG_SIZE 0x100

#define LOG(fmt, ...) do { \
    printf(fmt "\n", ##__VA_ARGS__); \
} while (0)

#define SYSCHK(x) ({ \
    __typeof__(x) __res = (x); \
    if (__res == (__typeof__(x))-1) { \
        fprintf(stderr, "SYSCHK(%s) failed: %s\n", #x, strerror(errno)); \
        exit(1); \
    } \
    __res; \
})

struct test_context {
    int sockets[2];
    char msg_a[BODY_SIZE];
    char msg_b[BODY_SIZE];
    char control_payload[CMSG_SIZE];
    useconds_t dump_delay_us;
    const char *slab_name;
    int cpu;
    atomic_bool pre_dump_done;
    atomic_bool send_done;
};

static void set_sockopt_or_warn(int fd, int level, int optname, const void *optval, socklen_t optlen, const char *optname_str) {
    if (setsockopt(fd, level, optname, optval, optlen) == -1) {
        fprintf(stderr, "warning: setsockopt(%s) failed: %s\n", optname_str, strerror(errno));
    }
}

static void pin_current_thread_to_cpu_or_warn(int cpu) {
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) == -1) {
        fprintf(stderr, "warning: sched_setaffinity(cpu=%d) failed: %s\n", cpu, strerror(errno));
    }
}

static void print_slab_info(const char *slab_name) {
    FILE *fp = fopen("/proc/slabinfo", "r");
    char line[0x1000];
    bool found = false;

    if (fp == NULL) {
        fprintf(stderr, "warning: fopen(/proc/slabinfo) failed: %s\n", strerror(errno));
        return;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char name[256];

        if (sscanf(line, "%255s", name) != 1) {
            continue;
        }
        if (strcmp(name, slab_name) == 0) {
            fputs(line, stdout);
            found = true;
            break;
        }
    }

    if (!found) {
        fprintf(stderr, "warning: slab '%s' not found in /proc/slabinfo\n", slab_name);
    }

    if (fclose(fp) != 0) {
        fprintf(stderr, "warning: fclose(/proc/slabinfo) failed: %s\n", strerror(errno));
    }
}

static void send_cmsg_payload(int fd, void *body, size_t body_len, void *control, size_t control_len) {
    struct iovec iov = {
        .iov_base = body,
        .iov_len = body_len,
    };
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = control,
        .msg_controllen = control_len,
    };

    SYSCHK(sendmsg(fd, &msg, 0));
}

static void *sender_thread(void *arg) {
    struct test_context *ctx = arg;

    pin_current_thread_to_cpu_or_warn(ctx->cpu);

    while (!atomic_load_explicit(&ctx->pre_dump_done, memory_order_acquire)) {
        sched_yield();
    }

    LOG("sender: sendmsg message 1 (body=%zu, cmsg=%zu)", sizeof(ctx->msg_a), sizeof(ctx->control_payload));
    send_cmsg_payload(ctx->sockets[1], ctx->msg_a, sizeof(ctx->msg_a), ctx->control_payload, sizeof(ctx->control_payload));

    LOG("sender: sendmsg message 2 (body=%zu, cmsg=%zu)", sizeof(ctx->msg_b), sizeof(ctx->control_payload));
    send_cmsg_payload(ctx->sockets[1], ctx->msg_b, sizeof(ctx->msg_b), ctx->control_payload, sizeof(ctx->control_payload));

    atomic_store_explicit(&ctx->send_done, true, memory_order_release);

    return NULL;
}

static void *slabinfo_thread(void *arg) {
    struct test_context *ctx = arg;

    pin_current_thread_to_cpu_or_warn(ctx->cpu);

    usleep(ctx->dump_delay_us);
    LOG("slabinfo thread: before send, printing slab '%s'", ctx->slab_name);
    print_slab_info(ctx->slab_name);

    atomic_store_explicit(&ctx->pre_dump_done, true, memory_order_release);
    while (!atomic_load_explicit(&ctx->send_done, memory_order_acquire)) {
        sched_yield();
    }

    usleep(ctx->dump_delay_us);
    LOG("slabinfo thread: after send, printing slab '%s'", ctx->slab_name);
    print_slab_info(ctx->slab_name);

    return NULL;
}

int main(int argc, char **argv) {
    struct test_context ctx = {
        .dump_delay_us = 200000,
        .slab_name = "kmalloc-256",
        .cpu = 0,
        .pre_dump_done = false,
        .send_done = false,
    };
    pthread_t sender_tid;
    pthread_t slabinfo_tid;
    char recv_buf[BODY_SIZE];
    char initial_msg[BODY_SIZE];
    u32 buf_size = 0x800;

    if (argc > 1) {
        ctx.slab_name = argv[1];
    }
    if (argc > 2) {
        ctx.cpu = atoi(argv[2]);
    }

    memset(initial_msg, 'I', sizeof(initial_msg));
    memset(ctx.msg_a, 'A', sizeof(ctx.msg_a));
    memset(ctx.msg_b, 'B', sizeof(ctx.msg_b));
    memset(ctx.control_payload, 0, sizeof(ctx.control_payload));

    {
        struct cmsghdr *control_header = (struct cmsghdr *)&ctx.control_payload[0];
        control_header->cmsg_len = sizeof(ctx.control_payload);
        control_header->cmsg_level = 0;
        control_header->cmsg_type = 0;
    }

    pin_current_thread_to_cpu_or_warn(ctx.cpu);

    SYSCHK(socketpair(AF_UNIX, SOCK_DGRAM, 0, ctx.sockets));
    set_sockopt_or_warn(ctx.sockets[1], SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size), "SO_SNDBUF");
    set_sockopt_or_warn(ctx.sockets[0], SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size), "SO_RCVBUF");

    LOG("main: priming socket with initial write (%zu bytes)", sizeof(initial_msg));
    SYSCHK(write(ctx.sockets[1], initial_msg, sizeof(initial_msg)));

    SYSCHK(pthread_create(&sender_tid, NULL, sender_thread, &ctx));
    SYSCHK(pthread_create(&slabinfo_tid, NULL, slabinfo_thread, &ctx));

    SYSCHK(pthread_join(sender_tid, NULL));
    SYSCHK(pthread_join(slabinfo_tid, NULL));

    for (int i = 0; i < 3; i++) {
        ssize_t got = SYSCHK(read(ctx.sockets[0], recv_buf, sizeof(recv_buf)));
        LOG("main: drained datagram %d (%zd bytes, first byte '%c')", i + 1, got, recv_buf[0]);
    }

    SYSCHK(close(ctx.sockets[0]));
    SYSCHK(close(ctx.sockets[1]));

    return 0;
}
