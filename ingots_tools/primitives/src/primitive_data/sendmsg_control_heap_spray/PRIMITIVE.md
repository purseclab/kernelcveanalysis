# `sendmsg()` Control-Buffer Heap Spray Primitive

This primitive sprays kmalloc caches with kernel copies of ancillary data passed through `sendmsg()`. It is closely related to `pipe_iovec_heap_spray`: both techniques rely on the kernel copying attacker-controlled metadata into kmalloc-backed objects and then holding those objects live while a blocking I/O operation stays in flight.

## Preconditions

- The target kernel must copy Unix socket control buffers into kmalloc-backed memory for the ancillary-data size you choose.
- You need enough sockets or threads to keep many `sendmsg()` calls blocked at once.
- You need to choose a control buffer size that lands in the cache you want to pressure.
- The spray transport must be configured so the sending thread blocks after the kernel copies the control buffer. The badnode adaptation does this by pre-filling the Unix socket send buffer.

## Usage

1. Call `init_sendmsg_control_heap_spray` with the number of workers, control-buffer size, a user payload buffer, and a data-buffer size used to fill the socket.
2. Call `execute_sendmsg_control_heap_spray_arm` to create socketpairs and worker threads.
3. Call `execute_sendmsg_control_heap_spray_start` to release all workers into blocked `sendmsg()` calls.
4. Trigger your bug or heap layout step while the spray is active.
5. Call `execute_sendmsg_control_heap_spray_release` to drain the peer sockets and let the blocked sends complete.

## Key Concepts

- This is the same broad idea as `pipe_iovec_heap_spray`, but the copied object is ancillary data rather than an iovec array.
- The notes in `CVEs_analysis/Techniques.md` about cache targeting and same-cache pressure apply here too.
- `sendmsg()` control sprays can be a better fit when the target cache size is awkward for iovec sprays or when a socket-based transport already exists in the exploit.

## How It Works

Each worker owns a Unix datagram socketpair and waits on a small control pipe. Before the worker is released, the sender socket is pre-filled so an additional `sendmsg()` cannot complete immediately. When the worker finally issues `sendmsg()`, the kernel copies the user-supplied ancillary data into a kmalloc-backed control buffer and then blocks waiting for space in the socket buffer.

That leaves many same-sized control-buffer allocations live in the kernel at once. Once the exploit no longer needs the spray, the peer sockets are drained, which lets each blocked `sendmsg()` finish and frees the control-buffer allocations. This gives a reusable kmalloc spray with transport behavior very similar to the existing pipe-iovec spray primitive.
