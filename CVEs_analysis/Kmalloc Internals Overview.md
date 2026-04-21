https://kernel-internals.org/mm/slab/

Kmalloc divided into caches, each a certain size/align object.
Default `kmalloc` calls into a bucketed cache, which has many caches of different size.
`GFP_KERNEL_ACCOUNT` results in `kmalloc` using `kmalloc-cg` caches if those are enabled.
Some dynamically sized objects have their own variables sized bucket cache, like `msg_msg`. (only in newer kernels, introduced v6.11)

`CONFIG_SLUB_TINY` works a bit differently, and seems to remove a lot of the fast path cases.

## Percpu Global State (`struct kmem_cache_cpu`)

- fast path freelist pointer: stored in global state rather than per clab
- active slab: fast path frozen slab

The percpu fast path freelist pointer is in the kmalloc cache cpu local data itself, not in the cache.

## Allocating

Fast Path:
If the kmalloc cache has a percpu forzen cache, and it is not full, just update freelist.

Regular Path:

## Freeing

Fast Path:
If the object is in the percpu frozen cache, it is just 1 lockless freelist update.

Regular Path:
TODO


## Large Allocations

Calling regular `kmalloc` with size over largest default bucket size just gets pages straight from page allocator
- obtains contigous memory folio, and returns address directly in liner mapping

`kfree` when called gets the folio of virtaddr and checks if it has a slab associated with it.
If it doesn't, `kfree` just treats it as large allocation and decrements refcount of folio, potentially freeing it to page allocator.

## Page Allocator

TODO: write in details

Just the relevent part is, in addition to budy allocator, there is a per cpu per page order size cache of recently used pages.
Makes cross cache on same cpu easier.