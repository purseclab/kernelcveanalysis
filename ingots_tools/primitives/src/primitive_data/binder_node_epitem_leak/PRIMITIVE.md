# Binder Node to Epitem Leak Primitive

This primitive turns a Binder-node use-after-free into a kernel-pointer leak by reclaiming freed `binder_node` objects with `struct epitem`. When a pending Binder transaction later reflects the stale node back to userspace, the driver copies two adjacent fields from the overlapped object. In the badnode exploit chain, those fields line up with the `epitem` list pointers, which leaks both a `struct epitem` address and the `struct file` that owns it.

## Preconditions

- You already have a Binder bug that frees `binder_node` objects while leaving at least one pending Binder message that still references them.
- You can create many UAF nodes in one run so a page of Binder allocations becomes reclaimable.
- The target kernel can reclaim the freed Binder-node page with `struct epitem` objects created via `epoll_ctl(EPOLL_CTL_ADD, ...)`.
- You can open duplicate file descriptors that map to the same `struct file`, so two `epitem` objects are linked off one file and the list-head pointers become meaningful leak material.
- The target layout matches the offsets used by the badnode reproduction: `epitem` list head at offset 88, controlled epitem user data at offset 120, and `struct file` epoll list head at offset `0xe0`.

## Usage

1. Call `init_binder_node_epitem_leak` with the number of file pairs to prepare and the Binder callbacks that drive the bug.
2. Call `execute_binder_node_epitem_prepare_files` to create timerfds, duplicate each one, and register both ends with epoll so the kernel allocates `epitem` objects.
3. Call `execute_binder_node_epitem_leak` with the Binder base node ID and node count. The primitive triggers the UAF, drains the expected Binder bookkeeping reads, reclaims with epitems, and inspects each reflected Binder object for the two leaked pointers.
4. Read `ctx->epitem_addr` and `ctx->file_addr` once the primitive returns success. Those addresses can feed later Binder read/write primitives.

## Key Concepts

- The leak works because Binder reflects `ptr` and `cookie` from a node-like object back to userspace when delivering a Binder object. If the freed node has been reclaimed with a different object, those reads expose adjacent fields from the replacement object.
- Two `epitem` allocations per `struct file` matter because the linked-list pointers are what make the leak useful. A lone `epitem` does not give the same structure.
- The primitive only handles the cross-cache leak stage. It does not corrupt `file->inode`, build arbitrary read, or walk kernel task lists.

## How It Works

The exploit first creates a large set of dangling `binder_node` references. It then reclaims the freed nodes with epoll registrations backed by duplicate timerfds, which allocates `struct epitem` objects in place of the old nodes. When the stale Binder transactions are read back, Binder still interprets the reclaimed memory as a node-like object and copies two words back to userspace.

The primitive filters those reflected words with simple alignment checks. An `epitem` leak lands at the offset of the embedded list head, while the accompanying `struct file` leak lands at the offset of the file's epoll-link list head. Once both addresses are recovered, later primitives can target the correct `epitem` and `struct file` for follow-on read or write setup.
