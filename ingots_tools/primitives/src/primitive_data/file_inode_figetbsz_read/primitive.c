#define _GNU_SOURCE
#include <errno.h>
#include <linux/fs.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/ioctl.h>

typedef int (*file_inode_figetbsz_retarget_fn)(void *opaque, uint64_t target);

typedef struct {
    int fd;
    void *opaque;
    file_inode_figetbsz_retarget_fn retarget;
    uint64_t superblock_block_size_offset;
} file_inode_figetbsz_read_ctx_t;

int init_file_inode_figetbsz_read(file_inode_figetbsz_read_ctx_t *ctx, int fd,
                                  void *opaque,
                                  file_inode_figetbsz_retarget_fn retarget,
                                  uint64_t superblock_block_size_offset) {
    if (!ctx || fd < 0 || !retarget) {
        return -EINVAL;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->fd = fd;
    ctx->opaque = opaque;
    ctx->retarget = retarget;
    ctx->superblock_block_size_offset = superblock_block_size_offset;
    return 0;
}

int execute_file_inode_figetbsz_read_u32(file_inode_figetbsz_read_ctx_t *ctx,
                                         uint64_t address, uint32_t *value) {
    int out = 0;

    if (!ctx || !value) {
        return -EINVAL;
    }
    if ((address & 0x3) != 0) {
        return -EINVAL;
    }

    if (ctx->retarget(ctx->opaque, address - ctx->superblock_block_size_offset) < 0) {
        return -EIO;
    }
    if (ioctl(ctx->fd, FIGETBSZ, &out) < 0) {
        /*
         * Some targets return an error for zero or malformed fake values.
         * Callers typically treat that as a zero read and retry if needed.
         */
        *value = 0;
        return 0;
    }

    *value = (uint32_t)out;
    return 0;
}

int execute_file_inode_figetbsz_read_u64(file_inode_figetbsz_read_ctx_t *ctx,
                                         uint64_t address, uint64_t *value) {
    uint32_t lo;
    uint32_t hi;

    if (!ctx || !value) {
        return -EINVAL;
    }

    if (execute_file_inode_figetbsz_read_u32(ctx, address, &lo) < 0 ||
        execute_file_inode_figetbsz_read_u32(ctx, address + 4, &hi) < 0) {
        return -EIO;
    }

    *value = ((uint64_t)hi << 32) | lo;
    return 0;
}

int execute_file_inode_figetbsz_read(file_inode_figetbsz_read_ctx_t *ctx,
                                     uint64_t address, void *buf, size_t size) {
    uint8_t *cursor = buf;
    size_t i;

    if (!ctx || !buf) {
        return -EINVAL;
    }

    for (i = 0; i < size; i += sizeof(uint32_t)) {
        uint32_t value = 0;
        size_t chunk = size - i;

        if (execute_file_inode_figetbsz_read_u32(ctx, address + i, &value) < 0) {
            return -EIO;
        }
        if (chunk > sizeof(value)) {
            chunk = sizeof(value);
        }
        memcpy(cursor + i, &value, chunk);
    }

    return 0;
}

void cleanup_file_inode_figetbsz_read(file_inode_figetbsz_read_ctx_t *ctx) {
    if (!ctx) {
        return;
    }

    memset(ctx, 0, sizeof(*ctx));
}
