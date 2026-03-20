# `msg_msg` Heap Spray Primitive

This primitive sprays kernel heap memory with SysV message queue messages. A sent message allocates a `msg_msg` header plus attacker-controlled data, and larger messages may extend into `msg_seg` objects. The result is a flexible Linux heap spray with mostly controlled bytes after the header.

## Preconditions

- The target kernel must allow SysV message queues to unprivileged users.
- You need a target cache size that can be reached by choosing an appropriate message payload length.
- You must account for the fact that the first bytes of a `msg_msg` object are message metadata, not attacker data.
- On newer kernels, `msg_msg` is often placed in its own kmalloc cache or cache group instead of the generic kmalloc cache. That makes it less reliable as a cross-cache reclaim primitive than older exploit writeups may suggest.
- If you plan to use `msg_seg`, the message size must exceed the inline payload capacity of a single `msg_msg`.

## Usage

1. Call `init_msg_msg_heap_spray` with the number of message queues to create, the payload size per message, and the number of spray rounds.
2. Fill `ctx->payload` with the controlled bytes you want copied into each message.
3. Call `execute_msg_msg_heap_spray_send` to enqueue one message per queue for each spray round.
4. Use `execute_msg_msg_heap_spray_recv_one` to selectively free messages from a chosen queue, or `cleanup_msg_msg_heap_spray` to drain and remove every queue.

## Key Concepts

- `msg_msg` gives variable-sized heap allocations with a large attacker-controlled region, but the first part of the object is kernel metadata.
- Large sprays are easy to scale because one process can create many queues and send many messages per queue.
- Cache placement depends on kernel version and configuration. Newer kernels frequently isolate `msg_msg`, so it should not be treated as a universal generic-cache spray.

## How It Works

Each `msgsnd()` call copies user data into a freshly allocated kernel message object. Small messages fit entirely inside a single `msg_msg`, while larger ones spill into linked `msg_seg` chunks. By creating many queues and sending one or more same-sized messages to each, an exploit can fill a target allocator bucket with repeated `msg_msg` allocations.

The primitive also supports selective receive. `msgrcv()` frees the kernel message it dequeues, which makes `msg_msg` useful not just for spraying but also for controlled release of sprayed objects. The main limitation is allocator isolation on newer kernels: the technique remains useful, but often no longer lands in the same general-purpose cache as older exploits assumed.
