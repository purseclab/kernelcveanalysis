# `FIGETBSZ` File-Inode Read Gadget

This primitive turns an already-corrupted `struct file->f_inode` pointer into a kernel read gadget using `ioctl(fd, FIGETBSZ, ...)`. In the badnode chain, the corrupted file points into a fake inode/superblock layout whose `s_blocksize` field is attacker-selectable, which makes `FIGETBSZ` return 32 bits from a chosen kernel address.

## Preconditions

- You already control the target file's `f_inode` pointer.
- You have some way to retarget the fake inode or fake superblock backing data before each `FIGETBSZ` call.
- The target file descriptor accepts `FIGETBSZ`.
- The read granularity is 32 bits. Wider reads must be stitched together from repeated calls.
- The target address should be aligned as required by the fake layout you build around the inode and superblock fields.

## Usage

1. Call `init_file_inode_figetbsz_read` with the corrupted file descriptor and a callback that updates the fake inode target before each read.
2. Call `execute_file_inode_figetbsz_read_u32` with the address you want to read.
3. Call `execute_file_inode_figetbsz_read_u64` when you want two adjacent 32-bit reads stitched into one 64-bit value.
4. Use `execute_file_inode_figetbsz_read` for bulk reads built from repeated 32-bit operations.

## Key Concepts

- `FIGETBSZ` returns the block size from the file's inode superblock path. If `f_inode` no longer points at a real inode, the kernel follows attacker-chosen pointers instead.
- This primitive does not implement the inode corruption step. It starts after the exploit already owns `f_inode`.
- The retarget callback is intentionally generic so this primitive can work with epitem-backed layouts, fake inode objects, or any other controllable backing structure.

## How It Works

When `FIGETBSZ` runs, the kernel walks through the file's inode to the superblock and copies the superblock block size back to userspace. If an exploit has already redirected `f_inode`, that walk no longer reflects the original file metadata. Instead, it reads whichever memory the attacker arranged behind the fake inode and superblock pointers.

The primitive uses a callback to retarget that fake layout before each ioctl. In the badnode adaptation, the callback is effectively an `epoll_ctl(EPOLL_CTL_MOD, ...)` update that changes a controlled `epitem` field so the superblock block-size read lands on a chosen kernel address. Repeating the gadget gives a stable 32-bit arbitrary read, and adjacent reads can be combined into 64-bit values.
