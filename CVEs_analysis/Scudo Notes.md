https://rocm.docs.amd.com/projects/llvm-project/en/docs-7.2.3/LLVM/llvm/html/ScudoHardenedAllocator.html

# Attack Notes

Major blockers according to deepseek review from prior traces in order:
- block order randomization
- size class seperation
- guard pages on secondary allocations
- checksum on header
- standard mmap randomization and region randomization

Other characteristics:
- cookie shared across zygote, and region addresses also shared by all zygote children
- only class is used to determine where / how to free block, no checks if it is in correct region for class
	- presumable this could allow cross cache type things
- checksum only checked on free, old value overwritten

### Ideas

- exhaust region oom, now frees are deterministic (sort of, if can sync them)
	- allocate at least enough to fill up, may be difficult
- side channel of when next page allocation happen?
- if u have local app cookie, have oob read, can leak based on crc value, and brute force which address in 256 MiB gets observed crc
- maybe remote cookie brute force? sounds not to viable with address also changing
	- with browsers in play, and renderer rce dime a dozen, can maybe assume we leak scudo init state

#### Checksum Remote Leak stuff

- only 1 leak of crc needed to forge apparently
- multiple leaks can get realtive offsets of objects to eachother

Prior Neil work:
- the big chunk fake free
	- useful to put a chunk in a region, and not have a guard page blocking overflow

Allocator metadata attack only useful for cross size caches?
- TODO: see if possible

# Allocation Header

TODO, it is straightforward, with a crc on random 4 byte secret and header and heap address, no pointer in allocation

# Randomness

- global cookie 4 byte value from os rng
- per size class rng state, init from rng, then uses xorshift for future values
- startup permutations are fixed by zygote

# Regions

At startup, bug region reserved, split into size classes, which are essentially a giant array of same size blocks, lazily allocated
- regions have 1-16 page random start offset
- regions also pick a random 256 MiB class size, it is permuted at startup
- have a bump opinter which is used to allocate new ones in the region when freelist exhausted
	- exhausting whole region is oom error, no new region allocated
	- allocates at most 52 elements at once in challenge 7.1 config
		- shuffled in order
- periodially scan for fully unallocated pages, madvise to return to kernel

# Tracking Blocks

### Per CPU

Per CPU structure holds stack (implemented as array) of pointers, push or pop for allocation, 1 per size class
- on exhaust or fill for free, transfer a batch from backend allocator

### Global

- Region has mutex, and freelist of batches (which are having arrays of blocks)
	- seperate region batches are allocated from
- BatchGroup represents 1 MiB region, and can have many transfer batches

# Large Regions

- regions bigger then min size get mmapped double sided guard pages
	- also keeps a cache of them for frees

# Metadata Storage

- static object scudo::Allocator in libc, includes the cookie
- thread cache can live in tls, or configured shared can live in array in static libc
	- cahlenge 7.1 has static one
	- static selected randomly at startup, stored in TLS a pointer
		- if try locking fails, can select another one