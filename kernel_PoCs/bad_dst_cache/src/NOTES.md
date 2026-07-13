# Best Kprobe-Assisted Root Run

Best minimal kprobe run so far:

- Folder: `old/2026-05-07_current_source_kprobe_only_cnxret_getroot_smp2/`
- Binary: current `bad_dst_cache` from the May 7 current-source build.
- Kernel/run shape: `--smp 2`, `nokaslr`, `mtu_expires=1`, unprivileged exploit via wrapper.
- Cleanup/reliability knobs:
  - `BAD_DST_CPU1_BLOCK_THREADS=1024`
  - `BAD_DST_LEAK_VULN_PIPES_ON_CLEAN_FAIL=1`
  - `BAD_DST_PIPE_CORRUPT_FIONREAD_MIN=0xc0000000`
  - Raised fd and pipe page limits before dropping privileges.
- Kprobe set:
  - only `sock_setsockopt+0xf00` (`cnxret`)

Result:

- `pipefail=1`
- `arb=1`
- `root=1`
- Root reached on attempt 2.

Important output:

```text
found corrupted pipe FIONREAD source=current index=2 size=0xc3c3c3c3
pipe probe leak accepted: page_index=135 probe=0x2b8 pipe_base=0x240 active_before=3 page=0xffffea000088b4c0 ops=0xffffffff827bf740 offset=0x0 len=0x4 flags=0x4141414100000010
Arb R/W setup
found current task: 0xffff888006de9c80
current task creds: real_cred=0xffff888006ceb840 cred=0xffff888006ceb840
capability sets overwritten
now uid/gid/euid/egid: 0/0/0/0
```

Trace evidence:

```text
p:kprobes/cnxret sock_setsockopt+3840 ...
bad_dst_cache ... cnxret ... old_ref=1 old_obs=-1 old_ops=0xffffffff836b8a40 old_flags=0x0
bad_dst_cache ... cnxret ... old_ref=1 old_obs=-1 old_ops=0xffffffff836b8a40 old_flags=0x0
```

Interpretation:

- `cnxret` is currently the minimal known kprobe-assisted setup.
- It likely works by adding cost immediately after the negative-advice call returns and before `sk_dst_cache` is assigned NULL.
- A no-kprobe run with the same wrapper reached `BAD_DST_MAX_ATTEMPTS=96` with `pipefail=6`, `arb=0`, `root=0`.

## Best No-Cnxret / No-Kprobe Root Run

Best no-`cnxret` result so far:

- Folder: `old/2026-05-07_no_cnxret_no_kprobe_earlytimer_smp2/`
- Kprobe set: none; `kprobe_events.actual` is empty.
- Timer sweep:
  - `BAD_DST_TIMER_SWEEP_START_NS=25000`
  - `BAD_DST_TIMER_SWEEP_STEP_NS=4096`
  - `BAD_DST_TIMER_SWEEP_COUNT=20`
  - `BAD_DST_MAX_ATTEMPTS=120`
- Result:
  - `pipefail=21`
  - `arb=1`
  - `root=1`
  - Root reached on attempt 45.

Important output:

```text
found corrupted pipe FIONREAD source=current index=7 size=0xc3c3c3c3
pipe probe leak accepted: page_index=114 probe=0x5b8 pipe_base=0x540 active_before=3 page=0xffffea0000910e40 ops=0xffffffff827bf740 offset=0x0 len=0x4 flags=0x4141414100000010
Arb R/W setup
now uid/gid/euid/egid: 0/0/0/0
```

Repeat status:

- `old/2026-05-07_no_cnxret_no_kprobe_earlytimer_repeat_smp2/`: no kprobes, same early timer sweep, stopped at `pipefail=30`, `arb=0`, `root=0`.
- `old/2026-05-07_no_cnxret_no_kprobe_earlytimer_lockoracle_smp2/`: no kprobes plus unprivileged lock oracle, stopped at `pipefail=30`, `arb=0`, `root=0`, but did produce one `dst_release underflow` from `ipv4_negative_advice -> sock_setsockopt+0xf00`.

Interpretation:

- `cnxret` is not strictly required; the early timer sweep has achieved root with no kprobes.
- Reliability is still weak. The no-kprobe path can land the stale-dst invalid-free, but pipe-buffer overlap is the current unreliable stage.

## Reclaim Tuning Notes

Allocator read, May 7:

- `pipe_resize_ring()` allocates `nr_slots * sizeof(struct pipe_buffer)`.
- On x86_64, a 4-slot pipe ring is 160 bytes.
- With the local `ARCH_DMA_MINALIGN=128` source patch, 160-byte pipe rings route to `kmalloc-256`; the remaining `kmalloc-192` string in `vmlinux` is not enough to prove this path is using kmalloc-192.
- Pipe page backing allocations are order-0 page allocations and should use the same non-movable migratetype as kmalloc slab pages in this setup.
- Both known root runs landed the fake pipe ring at cmsg object offset `0x40` (`pipe_base=0x240` and `pipe_base=0x540`), so offset 64 is the clean allocator target.

Tuning result:

- Raising only pipe volume did not improve reliability.
- `BAD_DST_PAGE_PIPES=6144` plus `BAD_DST_VULN_PIPES=1024` still missed the pipe-page overlap on the first candidate and left the trigger unreleasable.
- The known best kprobe run already used `page=3072 vuln=256`, so the source keeps `0xc00` as the SMP default while raising the max to `0x1800`. Larger one-off runs can still request `BAD_DST_PAGE_PIPES=6144`, but that did not help in the tested run.

Current hypothesis:

- The main miss is not insufficient page-pipe spray volume.
- The more likely issue is slab-page purity: the containing `kmalloc-256` page may still have live non-spray objects when sendmsg cmsgs are freed, so the page never reaches the buddy allocator and pipe backing pages never overwrite the fake pipe ring.
- False race candidates also pollute reclaim testing. The lock oracle proves the socket lock is blocked, but does not prove the stale-dst invalid-free happened.

## Post-Socket / Slab-Purity Knobs

Added May 7:

- `BAD_DST_BASE_PRE_SOCKETS`
- `BAD_DST_ALIGN_PAD_SPAN`
- `BAD_DST_POST_SOCKETS`
- `BAD_DST_OPEN_POST_BEFORE_PIPE_PREP`

The new `BAD_DST_OPEN_POST_BEFORE_PIPE_PREP=1` mode opens post sockets immediately after the vulnerable socket and before optional pre-race pipe allocation. This tests whether prepared pipe rings were contaminating the vulnerable rtable slab page tail.

Tested runs:

- `old/2026-05-07_post_before_pipe_cnxret_smp2/`: post-before-pipe, post=256, first candidate pipe miss.
- `old/2026-05-07_post_before_pipe_fixed64_post1024_cnxret_smp2/`: post-before-pipe, post=1024, fixed offset 64, first candidate pipe miss.
- `old/2026-05-07_prepare_pipes_after_candidate_cnxret_smp2/`: no pre-race pipe prep, post sockets before pipe prep inside exploit path, first candidate pipe miss.
- `old/2026-05-07_cnxret_align1_current_smp2/`: fixed align_pad=1, first candidate pipe miss.

Interpretation:

- The knobs are useful for future sweeps, but these ordering changes did not fix reclaim reliability.
- The next useful check is a stronger debug oracle for whether the fake unaligned free produced a pipe ring and whether the containing slab page was discarded to buddy.

## Progressive Pulse Status, May 18/19

Best timing variant from the blocker sweep:

- Folder: `old/2026-05-18_progressive_16block_prerace_cleanup_smp2_run1/`
- Settings: 16 CPU1 futex blockers, progressive pulse to `setsockopt_enter`, post-block repin after 4 blockers, `mtu_expires=0`, `BAD_DST_PRE_RACE_CLEANUP_FNHE=1`, `BAD_DST_NUM_SPRAY=512`.
- Result: `attempt_count=9`, `candidate_count=3`, `pipe_fail_count=3`, no arb/root.
- Important signal: attempts 3 and 8 reached the fake-dst invalid-free path with `dst_release refcnt:-1` from `udp_sendmsg`; critical time dropped to about 222-299 ms.

Longer root-payload-enabled run:

- Folder: `old/2026-05-18_progressive_16block_prerace_cleanup_root_smp2_run2/`
- Host-log counts before panic: `attempt=72`, `candidate=21`, `pipefail=20`, `arb=0`, `root=0`.
- Failure mode: repeated clean pipe misses, then attempt 72 panicked in `sk_dst_check` with RIP `0x100000001`.

Current read:

- Race timing is good enough to repeatedly hit the fake-dst free path.
- The main blocker is still reclaim/page overlap, plus a new stale/corrupted dst reuse crash after many misses.

## No-Kprobe Progressive Pulse Check, May 19

- Folder: `old/2026-05-19_progressive_16block_prerace_cleanup_nokprobe_root_smp2_run1/`
- `kprobe_events.actual` has 0 lines.
- Result: `attempt_count=120`, `candidate_count=2`, `pipe_fail_count=2`, `arb=0`, `root=0`.
- Strong signal: attempt 46 produced `dst_release underflow` with call trace `ipv4_negative_advice -> sock_setsockopt+0xf00`, then a clean pipe miss.
- Current conclusion: progressive pulsing can hit the race without kprobes, but this exact 16-block/pre-cleanup parameter set is not reliable without kprobe timing effects.
