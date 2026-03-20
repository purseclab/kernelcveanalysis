# `tty_write_buffer` Heap Spray Primitive

This primitive sprays the heap with `tty_write_buffer` objects by opening many PTY masters and writing controlled data to them. It is especially useful for `kmalloc-1k` targets and appears in Android Binder exploitation notes as a way to reclaim `binder_proc` or related `kmalloc-1k` objects.

## Preconditions

- The target system must expose `/dev/ptmx` to the attacker.
- The target object should be compatible with the cache size used for `tty_write_buffer` on the target kernel, commonly `kmalloc-1k`.
- You need enough PTY masters to keep many write buffers alive simultaneously.
- The exact amount of user control depends on the TTY path, but the sprayed buffer contents are largely attacker-chosen.

## Usage

1. Call `init_tty_write_buffer_heap_spray` with the number of PTYs to open and the write size per PTY.
2. Fill `ctx->payload` with the bytes you want written into each TTY buffer.
3. Call `execute_tty_write_buffer_heap_spray` to open `/dev/ptmx` repeatedly and write the payload to each PTY.
4. Keep the PTY descriptors open while the target object is reclaimed or adjacent memory is shaped.
5. Call `cleanup_tty_write_buffer_heap_spray` to close the PTYs and release the sprayed buffers.

## Key Concepts

- This primitive is strongest when the target object is in `kmalloc-1k` or an adjacent cache layout that benefits from PTY buffer pressure.
- Unlike `msg_msg`, the sprayed bytes are not preceded by a large inline kernel header inside the sprayed object itself.
- The badspin notes use this spray in combination with fake-file layouts, but the primitive itself is just the heap spray stage.

## How It Works

Writing to a PTY causes the kernel to allocate a `tty_write_buffer` and copy user bytes into it. By opening many PTY masters through `/dev/ptmx` and issuing same-sized writes to each one, an exploit can fill the relevant allocator bucket with largely controlled TTY write buffers.

Those buffers remain live while the PTY file descriptors stay open and the write path retains the buffered data. That makes the primitive useful both for reclaiming freed `kmalloc-1k` objects and for building adjacent fake-object layouts that later primitives can target.
