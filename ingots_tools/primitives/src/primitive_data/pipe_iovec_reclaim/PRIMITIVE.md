# Pipe IOVEC Reclaim Primitive

This primitive uses blocked `readv()` calls on pipes to force the kernel to allocate kmalloc-backed `iovec` arrays, then releases those allocations in bulk so the freed page can be reclaimed with pipe pages. In the `bad_io_uring` exploit family, this is the stage that puts a pipe-backed page on top of a page containing `struct pipe_buffer` entries; once that overlap exists, `pipe_buffer_rw` becomes the next primitive in the chain.

## Preconditions

- You need a bug that frees or exposes a page in a kmalloc cache that can also hold the `iovec` array size you choose.
- The target kernel must allocate `readv()` state for pipe reads from kmalloc rather than embedding everything on the stack.
- You need to know how many `iovec` elements to request so `sizeof(struct iovec) * count` lands in the desired kmalloc cache.
- You need enough control over thread scheduling to keep many `readv()` calls blocked at once.
- You need a reclaim target after the free step, typically many pipes whose pages you can fill with controlled data.

## Usage

1. Call `init_pipe_iovec_reclaim` with the number of spray workers, the number of `iovec` elements per worker, and the number of reclaim pipes to prepare.
2. Call `execute_pipe_iovec_arm_spray` to start worker threads and park them on a gate read.
3. Call `execute_pipe_iovec_start_spray` to let all workers enter blocked `readv()` calls. At that point the kernel-side `iovec` arrays should be allocated and pinned in the target kmalloc cache.
4. Trigger your bug while the spray is active.
5. Call `execute_pipe_iovec_release_spray` to satisfy the blocked `readv()` calls and free the kmalloc-backed arrays.
6. Call `execute_pipe_iovec_reclaim_pipe_pages` to fill reclaim pipes with page-backed data. If the reclaimed page contains `struct pipe_buffer` entries, hand the overlap to `pipe_buffer_rw`.

## Key Concepts

- Each `struct iovec` is 16 bytes on amd64 and aarch64, so the total allocation size is `16 * iovec_count`.
- The kernel allocates the `iovec` array before the `readv()` call actually consumes pipe data, so a blocked read can still pin the kmalloc object in place.
- Releasing many blocked reads in reverse order tends to free a large amount of same-cache state quickly, which is useful for page-level reclaim attempts.
- The reclaim phase is separate from the spray phase. This primitive only creates and releases the kmalloc pressure; the exploit-specific bug determines which freed page becomes reclaimable.

## How It Works

Each worker owns a pipe and waits for a one-byte gate value. Once released, the worker immediately calls `readv()` on the same pipe with a large user-controlled `iovec` array. The kernel copies that array into a kmalloc object sized by `sizeof(struct iovec) * count`, then blocks because the pipe no longer contains enough data to satisfy the full vectored read.

That blocked state keeps a large set of same-cache allocations alive while the exploit triggers a bug elsewhere. When the exploit is ready to free the cache pressure, it writes enough bytes into each worker pipe to let the pending `readv()` finish, which frees the kmalloc-backed `iovec` arrays. Immediately afterward, the primitive fills many reclaim pipes with 4 KiB writes so the kernel allocates pipe-backed pages into freshly freed memory. If those reclaimed pages overlap a vulnerable target such as a pipe-buffer array, a follow-on primitive can operate on the overlap directly.
