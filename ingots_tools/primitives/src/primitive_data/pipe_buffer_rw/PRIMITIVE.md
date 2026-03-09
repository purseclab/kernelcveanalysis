# Pipe Buffer Read/Write Primitive

This primitive leverages the `pipe_buffer` structure in the Linux kernel to achieve arbitrary memory read and write. By corrupting the `page` pointer within a `pipe_buffer`, an attacker can redirect pipe I/O operations (read/write) to any kernel memory address.

## Preconditions

1.  **Vulnerability**: A Use-After-Free (UAF) or Double Free vulnerability affecting an object in a slab cache that can also host `pipe_buffer` objects (e.g., `kmalloc-1024`, `kmalloc-192`, or `kmalloc-256` depending on the kernel version and configuration).
2.  **Slab Reclamation**: The ability to reclaim the freed slab containing the `pipe_buffer` with controlled data. This is often achieved using the "Page Spray" technique, where kernel pages are sprayed to overlap with the freed slab.
3.  **Address Translation**: To perform arbitrary read/write, the attacker must be able to convert a virtual address into its corresponding `struct page` pointer. This typically requires knowing the `vmemmap` base (for 1:1 mapping of `struct page` arrays) or the `linear_base` (for kernels without `vmemmap`).
4.  **KASLR Bypass (Optional but common)**: Reading the `ops` field of an uncorrupted `pipe_buffer` can leak a pointer to `anon_pipe_buf_ops`, which allows calculating the kernel base.

## Usage

1.  **Initialize**: Call `init_pipe_buffer_rw` to set up the necessary context.
2.  **Trigger Corruption**: Use a vulnerability (like UAF) and a spray technique (like Page Spray) to overwrite a `pipe_buffer` in the kernel with a crafted structure.
3.  **Arbitrary Read**: Use `execute_pipe_buffer_read` which updates the corrupted `pipe_buffer->page` and then calls `read()` on the pipe.
4.  **Arbitrary Write**: Use `execute_pipe_buffer_write` which updates the corrupted `pipe_buffer->page` and then calls `write()` on the pipe.

## Key Concepts

*   **`struct pipe_buffer`**: Contains `struct page *page`, `unsigned int offset`, `unsigned int len`, and `const struct pipe_buf_operations *ops`.
*   **Arbitrary Read**: By setting `page` to the target address's page, `offset` to the offset within the page, and `len` to the number of bytes to read, a subsequent `read()` from the pipe will fetch data from that target memory.
*   **Arbitrary Write**: By setting `page` to the target address's page, `offset` to the target offset, and `len` to 0, the next `write()` to the pipe will treat the buffer as empty and write user-provided data directly into the target memory.
*   **Page Spray**: Reclaiming freed slab pages by spraying buddy allocator pages. If the spray uses shared memory (e.g., `io_uring` buffers), the attacker can directly modify the "reclaimed" kernel object from userspace.
