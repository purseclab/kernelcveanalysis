# Pipe Spray Primitive

This primitive allows you to spray the kernel heap with controlled data using pipe buffers. When data is written to a pipe, the kernel allocates `pipe_buffer` structures on the heap. By creating many pipes and writing specific data to them, you can fill holes in the heap or position your data adjacent to a vulnerable object.

## Usage

1.  **Initialize**: Call the `spray_pipes` function with the desired number of pipes and the data buffer you want to spray.
2.  **Trigger**: The primitive handles the creation of pipes and writing of data.
3.  **Cleanup**: You may need to close the pipes later to free the allocated objects, depending on your exploit strategy.

## Key Concepts

*   **Pipe Buffers**: Each write to a pipe allocates a `pipe_buffer` structure.
*   **KMALLOC caches**: Ensure the size of your write lands in the target `kmalloc` cache (e.g., `kmalloc-1024`, `kmalloc-192`).
