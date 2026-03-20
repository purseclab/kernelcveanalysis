# Pipe Buffer Linear-Map Read/Write Primitive

This primitive assumes you already have a heap overlap on a live `struct pipe_buffer` or on the page that contains an array of pipe buffers. From that point, it captures a legitimate `pipe_buffer` template, leaks the `page` and `ops` pointers from the live entry, derives the `vmemmap` region that contains `struct page` objects, and retargets subsequent pipe reads and writes at attacker-chosen physical pages. Once the linear mapping base is known, the same primitive becomes arbitrary read/write over linear-mapped kernel memory.

## Preconditions

- You already control a read/write overlap on a live `struct pipe_buffer`, or on the 4 KiB page that contains it.
- The overlap lets you read the original entry and rewrite the surrounding page after modifying selected fields.
- You have a victim pipe with a valid populated buffer entry; the primitive preserves the original `ops`, `flags`, and `private` fields from that entry instead of fabricating them.
- You know the byte offset of the target `pipe_buffer` within the overlapped page, or you can hedge by rewriting several adjacent entries in the same array.
- The target kernel uses the 40-byte `struct pipe_buffer` layout used by the `bad_io_uring` exploits in this repository.
- The target kernel keeps `struct page` objects in `vmemmap`, with a known or leakable base for the relevant region.
- If you want linear-map wrappers instead of raw physical access, you also need the linear-map base.

## Usage

1. Use your bug-specific overlap or a separate reclaim primitive to gain read/write access to the page that contains the victim pipe-buffer array.
2. Call `init_pipe_buffer_rw` with the victim pipe FDs, callbacks that read and rewrite the overlapped page, and the byte offset of the target `pipe_buffer`.
3. Call `execute_pipe_buffer_capture_template` to save a legitimate `pipe_buffer` entry. This leaks both the live `page` pointer and the live `ops` pointer.
4. Set `vmemmap` information with either `execute_pipe_buffer_set_vmemmap_base` or `execute_pipe_buffer_set_vmemmap_base_from_leak`.
5. If you have the linear-map base, set it with `execute_pipe_buffer_set_linear_base`.
6. Use `execute_pipe_buffer_read_phys` / `execute_pipe_buffer_write_phys` for raw physical access, or `execute_pipe_buffer_read_linear` / `execute_pipe_buffer_write_linear` for linear-map virtual addresses.

## Key Concepts

- `pipe_buffer->page` is a `struct page *`, not a direct kernel virtual address. The primitive converts a physical page frame number into the corresponding `struct page` pointer in `vmemmap`.
- A leaked legitimate `pipe_buffer->page` value anchors the `vmemmap` region. On targets where `VMEMMAP_START` is known, use it directly. Otherwise, the leaked `page` pointer can be masked or aligned down to the surrounding `vmemmap` region using target-specific knowledge.
- A leaked legitimate `pipe_buffer->ops` value is the cleanest starting point for KASLR recovery because it points at a stable operations table such as `anon_pipe_buf_ops`.
- Pipe buffers are allocated as arrays of 40-byte entries. The allocation size is `40 * 2^n`, so these arrays can land in normal kmalloc caches depending on pipe capacity and kernel configuration.

## How It Works

The core observation is that the pipe code trusts the `page`, `offset`, and `len` fields of a live `struct pipe_buffer`. If an overlap lets you rewrite those fields while preserving the rest of a legitimate entry, the next `read()` from the pipe will copy bytes from the backing page described by the forged `page` and `offset`, and the next `write()` with `len = 0` will treat the buffer as empty and copy attacker data into that backing page.

Because `page` is a `struct page *`, the primitive first leaks a legitimate `pipe_buffer` entry and reuses it as a template. The leaked `page` pointer reveals a real address inside `vmemmap`, which is enough to recover the region that stores `struct page` objects. Once `vmemmap` is known, any physical page frame can be translated into the matching `struct page *` and installed into the live `pipe_buffer`.

From there, the primitive naturally gives physical read/write. If the attacker also knows the linear-map base, any linear-mapped kernel address can be translated to a physical offset and passed through the same page-retargeting logic. That is the version used by `bad_io_uring` to read kernel globals, leak layout information, and ultimately modify sensitive kernel objects.
