# Pipe IOVEC Heap Spray Primitive

This primitive sprays kmalloc caches with kernel copies of `struct iovec` arrays by parking many `readv()` calls on pipes. Each blocked call keeps one kmalloc-backed `iovec` array alive in the cache selected by `sizeof(struct iovec) * iovec_count`, which makes this a useful generic heap spray for UAF and overlap setups.

## Preconditions

- The target kernel must allocate the `readv()` iovec state from kmalloc for the vector count you choose, rather than keeping it on the stack.
- You need enough threads or processes to hold many blocked `readv()` calls at once.
- You need to choose `iovec_count` so `sizeof(struct iovec) * iovec_count` lands in the kmalloc cache you want to pressure.
- You need a kernel bug or heap layout goal that benefits from many same-cache allocations remaining live while the bug is triggered.

## Usage

1. Call `init_pipe_iovec_heap_spray` with the number of workers, the desired `iovec_count`, and a userspace buffer to reference from the vectors.
2. Call `execute_pipe_iovec_heap_spray_arm` to create worker pipes and start worker threads.
3. Call `execute_pipe_iovec_heap_spray_start` to release the workers into blocked `readv()` calls. At this point the kmalloc-backed `iovec` arrays are live and occupying the target cache.
4. Trigger your bug or heap-shaping sequence while the spray is active.
5. Call `cleanup_pipe_iovec_heap_spray` or `execute_pipe_iovec_heap_spray_release` when you want to let the blocked reads complete and free the spray objects.

## Key Concepts

- `struct iovec` is 16 bytes on amd64 and aarch64, so the backing allocation size is `16 * iovec_count`.
- A pipe read can block after the kernel has already copied the user `iovec` array, which is what makes this useful as a persistent spray.
- Unlike `pipe_iovec_reclaim`, this primitive stops at “keep the kmalloc objects alive.” It does not try to free them in a particular order or reclaim the freed page with pipe pages.

## How It Works

Each worker owns a pipe and waits on a small gate message. Once released, the worker calls `readv()` on that pipe with a user-controlled `iovec` array. The kernel first copies the array into a kmalloc object sized by the total vector count, then attempts to service the read. Because the pipe does not contain enough bytes to satisfy the full vectored read, the syscall blocks and the kmalloc allocation remains live.

By repeating this across many workers, the primitive fills a chosen kmalloc cache with same-shaped, attacker-triggered allocations. The exploit can then trigger a UAF, shape the freelist, or wait for a vulnerable object to land adjacent to the spray. When the spray is no longer needed, writing enough bytes into each worker pipe lets the blocked reads finish and frees the `iovec` arrays.
