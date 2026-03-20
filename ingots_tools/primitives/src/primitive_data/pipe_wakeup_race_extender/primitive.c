#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

typedef struct {
    int pipe_fds[2];
    int target_cpu;
    int lowprio_nice;
    int highprio_nice;
    pthread_t helper_thread;
    volatile int helper_armed;
} pipe_wakeup_race_extender_ctx_t;

static int pipe_wakeup_race_extender_pin_to_cpu(int cpu) {
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) < 0) {
        return -errno;
    }

    return 0;
}

static void *pipe_wakeup_race_extender_helper_main(void *opaque) {
    pipe_wakeup_race_extender_ctx_t *ctx = opaque;
    uint8_t byte;

    (void)pipe_wakeup_race_extender_pin_to_cpu(ctx->target_cpu);
    (void)setpriority(PRIO_PROCESS, 0, ctx->highprio_nice);
    ctx->helper_armed = 1;
    (void)read(ctx->pipe_fds[0], &byte, 1);
    return NULL;
}

int init_pipe_wakeup_race_extender(pipe_wakeup_race_extender_ctx_t *ctx,
                                   int target_cpu, int lowprio_nice,
                                   int highprio_nice) {
    if (!ctx || target_cpu < 0) {
        return -EINVAL;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->pipe_fds[0] = -1;
    ctx->pipe_fds[1] = -1;
    ctx->target_cpu = target_cpu;
    ctx->lowprio_nice = lowprio_nice;
    ctx->highprio_nice = highprio_nice;

    if (pipe(ctx->pipe_fds) < 0) {
        return -errno;
    }

    return 0;
}

int execute_pipe_wakeup_race_extender_arm(pipe_wakeup_race_extender_ctx_t *ctx) {
    if (!ctx) {
        return -EINVAL;
    }

    ctx->helper_armed = 0;
    if (pthread_create(&ctx->helper_thread, NULL,
                       pipe_wakeup_race_extender_helper_main, ctx) != 0) {
        return -errno;
    }

    while (!ctx->helper_armed) {
        sched_yield();
    }

    return 0;
}

int execute_pipe_wakeup_race_extender_prepare_lowprio(
    pipe_wakeup_race_extender_ctx_t *ctx) {
    if (!ctx) {
        return -EINVAL;
    }

    if (pipe_wakeup_race_extender_pin_to_cpu(ctx->target_cpu) < 0) {
        return -EIO;
    }
    if (setpriority(PRIO_PROCESS, 0, ctx->lowprio_nice) < 0) {
        return -errno;
    }

    return 0;
}

int execute_pipe_wakeup_race_extender_fire(pipe_wakeup_race_extender_ctx_t *ctx) {
    uint8_t byte = 'W';

    if (!ctx) {
        return -EINVAL;
    }

    if (write(ctx->pipe_fds[1], &byte, 1) != 1) {
        return -EIO;
    }

    return 0;
}

int execute_pipe_wakeup_race_extender_wait(pipe_wakeup_race_extender_ctx_t *ctx) {
    if (!ctx) {
        return -EINVAL;
    }

    if (pthread_join(ctx->helper_thread, NULL) != 0) {
        return -errno;
    }

    return 0;
}

void cleanup_pipe_wakeup_race_extender(pipe_wakeup_race_extender_ctx_t *ctx) {
    if (!ctx) {
        return;
    }

    if (ctx->pipe_fds[0] >= 0) {
        close(ctx->pipe_fds[0]);
    }
    if (ctx->pipe_fds[1] >= 0) {
        close(ctx->pipe_fds[1]);
    }

    memset(ctx, 0, sizeof(*ctx));
}
