# Bad dst_cache Exploit Running Log

## 2026-05-02 Initial review

### Scope
- Kept exploit code read-only.
- Started local review from `BUG.md`, `notes.md`, `exp_x86.c`, `rtable.h`, `rt6_info.h`, and the longer CVE notes at `../../CVEs_analysis/kernel exploit POCs/Bad dst_cache (CVE-2024-36971).md`.
- Kernel source reviewed under `/home/jack/Documents/college/purdue/research/linux_src/linux_stable`.
- Test kernel artifacts in this folder:
  - `bzImage`: Linux 5.10.107+ x86_64.
  - `vmlinux`: x86_64, debug info present, not stripped.

### Relevant kernel paths confirmed
- Vulnerable order is present in `include/net/sock.h`:
  - `__dst_negative_advice()` calls `dst->ops->negative_advice(dst)` before updating `sk->sk_dst_cache`.
  - Safe helpers `__sk_dst_set()` / `sk_dst_set()` clear or replace `sk_dst_cache` before dropping the old reference.
- Userspace trigger is `SO_CNX_ADVICE` in `net/core/sock.c`.
  - Local source also has test-only `SO_CNX_ADVICE` values `67` and `69` that directly call `dst_release(sk->sk_dst_cache)`.
- IPv4 trigger condition is in `net/ipv4/route.c:ipv4_negative_advice()`.
  - It drops the route if `dst->obsolete > 0`, `RTCF_REDIRECTED`, or `dst.expires` is set.
- PMTU/FNHE path is viable for marking/expiring IPv4 cached routes:
  - `__udp4_lib_err()` handles ICMP frag-needed and calls `ipv4_sk_update_pmtu()`.
  - `__ip_rt_update_pmtu()` creates/updates an FNHE with `fnhe_expires = jiffies + ip_rt_mtu_expires`.
  - `fill_route_from_fnhe()` copies `fnhe_expires` into `rt->dst.expires`.
  - `find_exception()` deletes expired FNHE state and flushes bound routes.
- UDP send path uses the lockless non-corking path:
  - `udp_sendmsg()` calls `sk_dst_check()` for connected sockets before route rebuild.
  - `sk_dst_check()` uses `dst->ops->check()` and, when it returns `NULL`, clears the socket dst and drops references.
- Fake dst free path is plausible:
  - `dst_release()` reaches zero by `call_rcu()`.
  - `dst_destroy()` calls `metadata_dst_free()` when `DST_METADATA` is set.
  - `metadata_dst_free()` calls `kfree(md_dst)` for `METADATA_HW_PORT_MUX`.

### Layouts verified from `vmlinux`
- `struct dst_entry`: size `112`, `ops` offset `8`, `flags` offset `56`, `obsolete` offset `58`, `__refcnt` offset `64`, `lwtstate` offset `80`, `rcu_head` offset `88`.
- `struct rtable`: size `176`; `ip_dst_cache` is created with `SLAB_HWCACHE_ALIGN`, so the effective cache object is expected to round to `192`.
- `struct metadata_dst`: `type` offset `112`, size `200`.
- `struct pipe_buffer`: size `40`; `page` offset `0`, `offset` `8`, `len` `12`, `ops` `16`, `flags` `24`, `private` `32`.
- Symbol observations from `vmlinux`:
  - `dst_blackhole_ops`: `0xffffffff836a8e40`.
  - `ipv4_dst_blackhole_ops`: `0xffffffff836b7b40`.
  - `anon_pipe_buf_ops`: `0xffffffff827bf3c0`.

### Initial issues / risks
- The test kernel config extracted from `bzImage` has `CONFIG_PREEMPT_NONE=y`. The timerfd race-widening idea should not preempt a running `setsockopt()` syscall in the vulnerable window on this kernel. The current `#define DEBUG` path in `exp_x86.c` avoids this by using the local `SO_CNX_ADVICE == 67` hook, so debug heap exploitation and the real race need to be treated as separate milestones.
- The fake dst free in `sk_dst_check()` still goes through `dst_release()` and therefore `call_rcu()`. The current `usleep(10 * 1000)` after triggering the invalid dst may be too short or noisy unless RCU callback completion is observed or forced indirectly.
- The cross-cache overlap depends on the stale 192-byte `rtable` slot landing at the chosen offset inside a 256-byte sendmsg control allocation. Current fake dst is at `payload + 64`; this is only one of the possible modulo-256 alignments. The `NUM_PRE_SOCKETS` / `NUM_POST_SOCKETS` grooming needs confirmation with runtime tracing or crash-state inspection.
- `exp_x86.c` hardcodes `dst_blackhole_ops` (`0xffffffff836a8e40`), not `ipv4_dst_blackhole_ops`. That looks acceptable for the `check()` call and metadata free path, but the naming in notes should be kept precise because Android/KCFI validation depends on using a real, type-compatible function pointer.
- The exploit hardcodes x86 test-kernel address constants and disables KASLR through `run_testvm.sh --nokaslr`. The Android/aarch64 target still needs a separate plan for `dst_ops` and pipe ops addresses or a leak.
- Local source has test-only edits in `net/core/sock.c` for `SO_CNX_ADVICE == 67/69`; any result using those values should be labelled as a harness result, not a real bug trigger.

### Checkpoints
- No checkpoint created yet; no exploit code changes have been made in this pass.

## 2026-05-02 Debug-67 retry reliability

### Changes made
- Created baseline backups before changing the retry path:
  - `old/2026-05-02_debug67_before_reliability_exp_x86.c`
  - `old/2026-05-02_debug67_before_reliability_RUNNING_LOG.md`
- Added small environment parsing helpers in `exp_x86.c` for bounded timing/sweep knobs.
- Reworked the `#define DEBUG` path around `SO_CNX_ADVICE == 67` into a retry loop:
  - Logs attempt, alignment pad, pre-socket count, and post-socket count.
  - Sweeps `NUM_BASE_PRE_SOCKETS + align_pad`, with `align_pad` cycling over `0..20`.
  - Supports `BAD_DST_ALIGN_PAD` and `BAD_DST_MAX_ATTEMPTS` when those env vars are present in the guest.
  - Leaves the debug-67 socket unclosed after a miss because the harness intentionally leaves the socket lock held; closing it deadlocks.
- Made the sendmsg spray reusable across retries:
  - `do_spray()` now requires parked spray threads, resets `spray_count`, starts all spray workers, then waits.
  - `free_spray()` now waits for spray workers to park again after draining, so per-sendmsg control allocations have been released before the next reset.
  - `reset_spray()` drains the actual sprayed datagrams and restores the filler datagrams for the next attempt.
- Replaced the invalid-free trigger send from a normal `write()` to `send(..., MSG_PROBE)`.
  - `MSG_PROBE` still enters the UDP `sk_dst_check()` path, so the fake obsolete dst is released.
  - It avoids the later `ip_setup_cork()` / `dst_mtu()` dereference that can panic when a miss leaves an unusable stale route.
  - Added a guarded userspace definition for `MSG_PROBE` (`0x10`) because glibc headers do not expose the kernel-only constant.
- Increased the post-invalid-free RCU wait from 10 ms to an env-configurable default of 1 second (`BAD_DST_FAKE_DST_RCU_US`).

### Verification
- `gcc -fsyntax-only exp_x86.c ...` passed.
- `nix-shell -p glibc.static --run ./compile_x86.sh` passed; remaining output is existing warning noise around format specifiers and ignored return values.
- Ran the x86 test kernel under `testvm` with `--nokaslr --smp 1` and the tap networking setup.
  - First bounded run:
    - attempt 1, `align_pad=0`: hit `dst_release underflow`, missed pipe corruption, returned to retry.
    - attempt 2, `align_pad=1`: hit `dst_release underflow`, missed pipe corruption, returned to retry.
    - attempt 3, `align_pad=2`: found corrupted pipe, printed KASLR/vmemmap/physical base, reached `Arb R/W setup`.
  - Second bounded run:
    - attempts 1-4, `align_pad=0..3`: each hit the invalid-free path and missed pipe corruption without panicking.
    - attempt 5, `align_pad=4`: found corrupted pipe and reached `Arb R/W setup`.
- The previous bad-miss crash shape (`ip_setup_cork()` dereferencing a bad route after normal send/write) did not recur in either bounded run with `MSG_PROBE`.

### Current issues / notes
- The run still emits `dst_release underflow` warnings on misses and on the winning attempt. That is expected for the debug harness because the fake/stale dst reference accounting is the thing being driven, but it will taint the test log.
- `root_payload()` remains commented out; after `Arb R/W setup` the debug build intentionally sleeps forever. The host-side `timeout` kills QEMU after the milestone.
- Host env vars like `BAD_DST_MAX_ATTEMPTS` do not automatically propagate through the current `testvm --autorun ./bad_dst_cache` invocation. Use host-side `timeout` or an autorun wrapper if bounded in-guest attempts are needed.
- The winning alignment is not fixed across boots in this setup. The sweep is necessary: observed wins were `align_pad=2` and `align_pad=4`.
- This milestone is still a local harness result using test-only `SO_CNX_ADVICE == 67`, not the real timerfd/preemption race.

## 2026-05-02 SMP-6 sanity check

### Test
- Ran the same built debug binary with the same tap networking and `--nokaslr`, but changed QEMU to `--smp 6`.
- Command shape:
  - `timeout 180s testvm run bzImage --nokaslr --smp 6 --net tap ... --autorun ./bad_dst_cache`

### Result
- Kernel booted with 6 CPUs (`smpboot: Total of 6 processors activated`).
- The debug-67 trigger and invalid-free path remained stable:
  - Attempts 1 through 21 completed `debug triggered` -> `trigger kmalloc-256 invalid free` -> `dst_release underflow` -> reclaim phase -> `FAIL: could not corrupt pipe`.
  - No `ip_setup_cork()` panic or other kernel crash occurred.
- The run timed out during attempt 22, after wrapping the alignment sweep back to `align_pad=0`.
- No pipe corruption / `Arb R/W setup` was reached within one full `0..20` alignment sweep on 6 CPUs.

### Interpretation
- This is a useful negative sanity check: the debug trigger itself is reliable under 6 CPUs, and `MSG_PROBE` is still preventing bad-miss panics.
- The current pipe-reclaim/grooming is materially less reliable under SMP allocator noise. The next likely work is to add SMP-aware grooming, such as pinning the main allocator sequence more deliberately, widening the pre/post socket or pipe spray search space, or adding per-CPU allocator drain/fill steps.

## 2026-05-02 Userspace synchronize_rcu via membarrier

### Source verification
- Verified `kernel/sched/membarrier.c` in the local 5.10 tree:
  - `MEMBARRIER_CMD_GLOBAL` rejects `nohz_full`, then calls `synchronize_rcu()` when `num_online_cpus() > 1`, then returns 0.
- Verified `net/core/dst.c`:
  - `dst_release()` calls `call_rcu(&dst->rcu_head, dst_destroy_rcu)` when the refcount reaches zero.
- Verified `kernel/rcu/tree.c` and `kernel/rcu/update.c`:
  - `synchronize_rcu()` waits for a grace period through `wait_rcu_gp(call_rcu)`.
  - `__wait_rcu_gp()` queues an RCU callback and waits for that callback completion.
- Interpretation: the syscall is a real userspace way to force the RCU grace-period edge on SMP in this kernel. For this exploit, the callback we care about is queued by the same pinned userspace thread before the membarrier call, so this should remove fixed-sleep guessing for the `dst_release()` RCU free paths. It is not a full solution for per-CPU slab freelist placement.

### Changes made
- Added `synchronize_rcu_from_user()` in `exp_x86.c`.
  - Uses `syscall(SYS_membarrier, MEMBARRIER_CMD_GLOBAL, 0, -1)`.
  - Only uses it when more than one CPU is online, matching the kernel branch.
  - Can be disabled with `BAD_DST_USE_MEMBARRIER_RCU=0`.
  - Falls back to the old sleep behavior on failure or single-CPU runs.
- Added `wait_for_rcu_callbacks()` and replaced both fixed RCU sleeps:
  - after closing the pre/post route sockets (`rtable free`);
  - after the fake dst invalid-free (`fake dst free`).
- With membarrier active, `BAD_DST_RTABLE_RCU_US` and `BAD_DST_FAKE_DST_RCU_US` are now optional extra sleeps, defaulting to 0. On fallback they keep the old 1 second default.

### Verification
- `gcc -fsyntax-only exp_x86.c ...` passed.
- `nix-shell -p glibc.static --run ./compile_x86.sh` passed; only existing warning noise remains.
- Ran `timeout 180s testvm run bzImage --nokaslr --smp 6 ... --autorun ./bad_dst_cache`.
  - Guest printed `membarrier MEMBARRIER_CMD_GLOBAL RCU sync enabled`, confirming the syscall path was active.
  - Attempts 1 through 28 completed the invalid-free/reclaim path without kernel crash.
  - The run timed out on attempt 29.
  - No `found corrupted pipe FIONREAD` / `Arb R/W setup` occurred.

### Current interpretation
- The membarrier path is valid and useful; it made attempts faster and removed the fixed RCU sleep guess.
- It did not solve the SMP-6 pipe reclaim miss. That makes pure RCU delay less likely as the primary issue. The remaining suspect is SMP allocator/cache placement: freed objects and pipe buffers are likely not staying on the same CPU freelist/page sequence often enough.

## 2026-05-02 One-CPU RCU delay check

### Source note
- On this kernel, `membarrier(MEMBARRIER_CMD_GLOBAL)` does not call `synchronize_rcu()` when only one CPU is online.
- `synchronize_rcu()` itself can also return immediately on single-CPU non-preemptible RCU paths because a blocking wait is already a grace-period boundary.
- For `--smp 1`, the practical userspace control is therefore a delay that lets queued `call_rcu()` callbacks run after the syscall path returns.

### Changes made
- Updated `wait_for_rcu_callbacks()` so single-CPU runs use an explicit delay-only path.
- Default single-CPU RCU wait is now 50 ms for both:
  - the rtable free wait after closing pre/post sockets;
  - the fake dst free wait after the `MSG_PROBE` invalid-free trigger.
- The delay is still tunable through the existing `BAD_DST_RTABLE_RCU_US` and `BAD_DST_FAKE_DST_RCU_US` env vars.
- The guest logs `single CPU RCU wait uses delay-only path` once so it is obvious which path ran.

### Verification
- `gcc -fsyntax-only exp_x86.c ...` passed.
- `nix-shell -p glibc.static --run ./compile_x86.sh` passed; remaining output is existing warning noise.
- Used a temporary testvm share wrapper with `BAD_DST_RTABLE_RCU_US=50000` and `BAD_DST_FAKE_DST_RCU_US=50000` before making the 50 ms path the default:
  - Run 1, `--smp 1`: reached `Arb R/W setup` on attempt 3.
  - Run 2, `--smp 1`: reached `Arb R/W setup` on attempt 8.
- Rebuilt with the 50 ms single-CPU default and ran normal `--autorun ./bad_dst_cache`:
  - Guest logged `single CPU RCU wait uses delay-only path`.
  - Reached `Arb R/W setup` on attempt 2.

### Current interpretation
- 50 ms is reliable enough in these one-CPU sanity runs and much cheaper than the old 1 second fallback.
- It does not make the pipe overlap deterministic; the alignment sweep is still needed, as seen by wins at attempts 2, 3, and 8.

## 2026-05-02 SMP post-membarrier RCU delay

### Checkpoint
- Backed up the pre-change files:
  - `old/2026-05-02_before_smp_rcu_post_sync_delay_exp_x86.c`
  - `old/2026-05-02_before_smp_rcu_post_sync_delay_RUNNING_LOG.md`

### Change
- Updated the SMP `membarrier(MEMBARRIER_CMD_GLOBAL)` success path in `wait_for_rcu_callbacks()`.
- Default post-sync delay is now 50 ms instead of 0.
- The existing per-stage overrides still control the delay:
  - `BAD_DST_RTABLE_RCU_US`
  - `BAD_DST_FAKE_DST_RCU_US`
- Setting either env var to `0` restores no-delay behavior for that stage.

### Verification
- Built with `nix-shell -p glibc.static --run ./compile_x86.sh`; build passed with existing warning noise.
- Ran:
  - `timeout 240s testvm run bzImage --nokaslr --smp 6 --net tap --network-tap tap0testvm --network-host-ip 192.168.10.1 --network-ip 192.168.10.2/24 --network-gateway 192.168.10.1 --network-dns 1.1.1.1 --autorun ./bad_dst_cache`
- Result:
  - Guest booted with 6 CPUs.
  - `membarrier MEMBARRIER_CMD_GLOBAL RCU sync enabled` printed once.
  - Attempts 1 through 39 completed the debug trigger, invalid-free warning, pipe reclaim attempt, and retry path without crashing.
  - Attempt 40 reached the post-invalid-free reclaim phase before the host timeout terminated QEMU.
  - No pipe corruption / `Arb R/W setup` was reached.

### Current interpretation
- The additional post-sync delay did not fix the SMP-6 miss.
- This makes the remaining issue look more like SMP allocator/cache placement than a simple RCU callback timing problem.

## 2026-05-02 SMP allocator grooming and pipe reclaim fixes

### Checkpoint
- Backed up the pre-change files:
  - `old/2026-05-02_before_smp_allocator_grooming_exp_x86.c`
  - `old/2026-05-02_before_smp_allocator_grooming_RUNNING_LOG.md`
- Saved the post-change SMP-6 arbitrary read/write milestone:
  - `old/2026-05-02_smp_allocator_grooming_smp6_arb_rw_exp_x86.c`
  - `old/2026-05-02_smp_allocator_grooming_smp6_arb_rw_RUNNING_LOG.md`

### Changes made
- Added an SMP-only allocator grooming stage after `setup_spray()`:
  - churns blocking `sendmsg()` control-message allocations on every CPU to populate/evict kmalloc-256 partials;
  - churns pipe-buffer allocations on every CPU to populate kmalloc-192 partials;
  - holds a small number of cmsg and pipe-buffer allocations per CPU so each CPU has local active slab pressure before the real attempt starts.
- Added tunables for that stage:
  - `BAD_DST_SMP_GROOM`, default enabled on SMP;
  - `BAD_DST_GROOM_CHURN_CMSG_PER_CPU`, default `32`;
  - `BAD_DST_GROOM_CHURN_PIPE192_PER_CPU`, default `48`;
  - `BAD_DST_GROOM_HOLD_CMSG_PER_CPU`, default `8`;
  - `BAD_DST_GROOM_HOLD_PIPE192_PER_CPU`, default `4`;
  - `BAD_DST_GROOM_BLOCK_US`, default `200000`.
- Added optional IRQ affinity pinning to CPU0 through `BAD_DST_PIN_IRQS_CPU0`, default enabled on SMP.
- Increased the file limit setup from `16384` to `32768`, since the SMP run now opens more pipes and may intentionally leak some pipes across failed attempts.
- Increased SMP defaults for pipe reclaim:
  - page pipes: `0xc00`;
  - vuln pipes: `0x40`.
  - Single-CPU defaults remain smaller.
- Replaced the single-thread page-pipe write loop with `reclaim_pipe_pages()`.
  - `BAD_DST_PAGE_RECLAIM_PERCPU` controls whether to use pinned reclaim workers.
  - `BAD_DST_PAGE_RECLAIM_CPU0_PCT` now defaults to `100`, because the spray free path is CPU0-pinned and the successful page needs to be pulled from CPU0's page allocator path first.
- Added `BAD_DST_LEAK_VULN_PIPES_ON_FAIL`, default enabled on SMP.
  - This intentionally leaks the vuln pipes after a missed `FIONREAD` detection instead of closing them.
  - Reason: a miss can still leave corrupted pipe state around, and closing those pipes triggered a SLUB `kfree()` BUG in `free_pipe_info`.

### Verification
- `gcc -fsyntax-only exp_x86.c ... -Wall -Wextra` passed with the existing warning noise.
- `nix-shell -p glibc.static --run ./compile_x86.sh` passed.
- First SMP-6 grooming test without `-no-reboot`:
  - Boot 1 missed a few attempts, then hit `kernel BUG at mm/slub.c:4118` from `kfree()` during `free_pipe_info` while closing vuln pipes after a miss.
  - Boot 2 reached `found corrupted pipe FIONREAD` and `Arb R/W setup` on attempt 2 before I killed the sleeping VM.
- After adding `BAD_DST_LEAK_VULN_PIPES_ON_FAIL`, ran SMP-6 with `--qemu-arg -no-reboot` and the page reclaim split still at 50 percent CPU0:
  - 40 attempts completed without a kernel panic.
  - No pipe hit occurred.
- Changed the default page reclaim split to 100 percent CPU0 and rebuilt.
- Ran SMP-6 again with `--qemu-arg -no-reboot`:
  - Attempts 1 through 9 missed and leaked vuln pipes instead of closing them.
  - Attempt 10 with `align_pad=9 pre=1801 post=256` reached:
    - `found corrupted pipe FIONREAD`
    - `kaslr base: ffffffff81000000`
    - `vmemmap base: fffffffeffe00000`
    - `physical base address: 200000`
    - `Arb R/W setup`
  - The VM was left in the exploit success sleep and then manually killed from the host.

### Current interpretation
- The SMP allocator/cache-placement theory looks correct enough to act on: the same code path that missed consistently before can now reach arbitrary read/write on `--smp 6`.
- The current SMP path is still probabilistic, not deterministic. The best observed run hit on attempt 10; an earlier 50 percent CPU0 page reclaim split missed for 40 attempts.
- The `free_pipe_info` panic is useful evidence: after a failed visible `FIONREAD` check, some pipe objects can still be damaged. Leaking vuln pipes on SMP misses is intentional until the detection/cleanup path is made more precise.
- The CPU0-heavy page reclaim default matches the current CPU pinning: spray threads and `free_spray()` run on CPU0, so the target page is most likely returned through CPU0's allocator path. If later traces show the final page free lands on another CPU, lower `BAD_DST_PAGE_RECLAIM_CPU0_PCT` or run a small sweep.

## 2026-05-02 Vuln pipe active-ring setup

### Checkpoint
- Backed up the pre-change files:
  - `old/2026-05-02_before_vuln_pipe_active_ring_exp_x86.c`
  - `old/2026-05-02_before_vuln_pipe_active_ring_RUNNING_LOG.md`
- Saved the post-change SMP-6 arbitrary read/write milestone:
  - `old/2026-05-02_vuln_pipe_active_ring_smp6_arb_rw_exp_x86.c`
  - `old/2026-05-02_vuln_pipe_active_ring_smp6_arb_rw_RUNNING_LOG.md`

### Kernel check
- Checked `/home/jack/Documents/college/purdue/research/linux_src/linux_stable/fs/pipe.c`.
- `pipe_ioctl(FIONREAD)` sums `pipe->bufs[tail & mask].len` for active entries from `tail` to `head`.
- `pipe_resize_ring()` computes active occupancy, allocates a new ring, copies active entries, then sets `tail = 0` and `head = n`.
- Therefore, if each vuln pipe has exactly one unread byte before the resize, the resized pipe-buffer array should have exactly one active slot at index 0. If that array is later reclaimed by an `A` page, `FIONREAD` should observe the overwritten `len` field.

### Changes made
- Removed the vuln-pipe `pipe_prefault()` write/read cycle from the active exploit path.
- Added `pipe_write_one_active_buffer()` and now leave one unread byte in each vuln pipe before the cross-cache phase.
- Added `pipe_readable_bytes()` and `verify_vuln_pipes_active()`.
- `verify_vuln_pipes_active()` checks every vuln pipe has `FIONREAD == 1`:
  - once after initial one-byte setup;
  - once after resizing to the four-page pipe-buffer ring, before freeing the cmsg spray.
- Added `BAD_DST_VERIFY_VULN_PIPE_ACTIVE`, default enabled, to disable those checks if the extra ioctls become noisy during future tuning.
- Reused `pipe_readable_bytes()` for the final corrupted-pipe scan.

### Verification
- `gcc -fsyntax-only exp_x86.c ... -Wall -Wextra` passed with existing warning noise.
- `nix-shell -p glibc.static --run ./compile_x86.sh` passed with existing warning noise.
- Ran SMP-6 with `--qemu-arg -no-reboot`:
  - No `vuln pipe active check failed` messages occurred.
  - Attempts 1 through 8 missed and leaked vuln pipes.
  - Attempt 9 with `align_pad=8 pre=1800 post=256` reached:
    - `found corrupted pipe FIONREAD`
    - `kaslr base: ffffffff81000000`
    - `vmemmap base: fffffffeffe00000`
    - `physical base address: 200000`
    - `Arb R/W setup`
  - The VM was left in the exploit success sleep and then manually killed from the host.

### Current interpretation
- The active-ring setup is now explicit and verified.
- This does not prove every miss is clean, but it removes the specific ambiguity where a reclaimed pipe-buffer array might not have had an active entry visible to `FIONREAD`.
- The successful SMP-6 run after the change suggests the extra `FIONREAD == 1` checks do not break the timing badly on this test kernel.

## 2026-05-03 Testvm dumped preempt config

### Files
- Dumped the current test kernel config with:
  - `testvm run bzImage --dump-config old/2026-05-03_testvm_dump_config_before_preempt.config --qemu-arg -no-reboot`
- Saved the minimally edited preemptible-kernel config as:
  - `old/2026-05-03_testvm_dump_config_preempt.config`

### Change
- Applied only the preemption model diff:
  - `CONFIG_PREEMPT_NONE=y` -> `# CONFIG_PREEMPT_NONE is not set`
  - kept `# CONFIG_PREEMPT_VOLUNTARY is not set`
  - `# CONFIG_PREEMPT is not set` -> `CONFIG_PREEMPT=y`
- Left `CONFIG_HZ=1000`, `NO_HZ`, and unrelated debug/hardening options unchanged.

### Note
- This is the hand-edited dumped config. Running it through `make olddefconfig` in the kernel tree should derive selected symbols such as `CONFIG_PREEMPTION=y` and `CONFIG_PREEMPT_COUNT=y`.

## 2026-05-03 New preempt kernel debug-67 check

### Checkpoint
- Backed up the pre-offset-update files:
  - `old/2026-05-03_before_new_kernel_preempt_offsets_exp_x86.c`
  - `old/2026-05-03_before_new_kernel_preempt_offsets_RUNNING_LOG.md`
- Backed up the pre-ring-size experiment files:
  - `old/2026-05-03_before_vuln_pipe_ring_pages_exp_x86.c`
  - `old/2026-05-03_before_vuln_pipe_ring_pages_RUNNING_LOG.md`
- Backed up the invalid 5-page ring state before reverting it:
  - `old/2026-05-03_before_revert_invalid_vuln_pipe_ring_exp_x86.c`
  - `old/2026-05-03_before_revert_invalid_vuln_pipe_ring_RUNNING_LOG.md`

### Kernel/config facts
- `new_kernel/bzImage` boots as `Linux version 5.10.107+ ... SMP PREEMPT`.
- Extracted config confirms:
  - `CONFIG_PREEMPT=y`
  - `CONFIG_PREEMPTION=y`
  - `CONFIG_PREEMPT_COUNT=y`
  - `CONFIG_PREEMPT_RCU=y`
  - `CONFIG_DEBUG_PREEMPT=y`
- Updated x86 hardcoded symbols for this kernel:
  - `anon_pipe_buf_ops`: `0xffffffff827bf640`
  - `dst_blackhole_ops`: `0xffffffff836a8980`
  - `_stext`: unchanged at `0xffffffff81000000`.

### Verification
- Built with `nix-shell -p glibc.static --run ./compile_x86.sh`; build passed with existing warning noise.
- Ran `new_kernel/bzImage` with `--smp 6 --nokaslr --qemu-arg -no-reboot` and tap networking.
  - The test-only `SO_CNX_ADVICE == 67` hook triggered reliably enough to reach the invalid-free path.
  - The guest printed `debug triggered` and then hit the expected `dst_release` underflow warning during the `MSG_PROBE` send.
  - Attempts 1 through 7 missed pipe corruption.
  - Attempt 8 panicked during `free_spray()` in `sock_kfree_s()` / `kfree()` at `mm/slub.c:4118`.
- Ran the same preempt kernel with `--smp 1`.
  - The debug-67 trigger and invalid-free warning still worked.
  - Attempt 2 panicked at the same `sock_kfree_s()` / `kfree()` site.

### Issue found
- The panic is not a debug-trigger failure. The 67 path reaches the intended refcount-underflow/invalid-free sequence on the preempt kernel.
- The panic occurs when freeing sprayed sendmsg control buffers after the page has already stopped being a slab page. In this kernel, `kfree()` BUGs if the pointer page is neither `PageSlab` nor compound.
- A test change tried to resize vuln pipes to five pipe-buffer slots so the pipe-buffer array would directly target kmalloc-256. That is not viable with `F_SETPIPE_SZ`: pipe capacities are rounded to a power-of-two number of pages, so a 5-page request returns 8 pages. The exact-size check failed before the exploit path continued.
- Reverted the default vuln pipe ring back to 4 pages and added a guard so `BAD_DST_VULN_PIPE_RING_PAGES` must be a power of two. The 5-page idea should be treated as rejected for this harness unless the pipe ring allocation path is changed.

### Focused align-pad checks
- Created tiny testvm share wrappers so environment variables can be passed without packing the whole 2.2G working directory:
  - `run_preempt_align8.sh`
  - `run_preempt_align9.sh`
  - `vmshare_preempt_align8/`
  - `vmshare_preempt_align9/`
- `--smp 6`, `BAD_DST_ALIGN_PAD=8`, `BAD_DST_MAX_ATTEMPTS=1`:
  - debug-67 triggered;
  - `dst_release underflow` warning occurred at the `MSG_PROBE` invalid-free trigger;
  - the run reached `free_spray()`, page reclaim, and final `FIONREAD` scan;
  - no pipe corruption was found, but the miss was clean and did not panic.
- `--smp 6`, `BAD_DST_ALIGN_PAD=9`, `BAD_DST_MAX_ATTEMPTS=1`:
  - debug-67 triggered and the run reached `free_spray()`;
  - panicked again at `mm/slub.c:4118` from `sock_kfree_s()` / `____sys_sendmsg()`.

### Current interpretation
- The new PREEMPT kernel offsets and the debug-67 hook are good enough to reach the intended invalid-free path.
- The remaining PREEMPT-specific problem is the cmsg teardown stage after a missed pipe-buffer reclaim. If the fake freed slot is not consumed by a pipe-buffer allocation, `free_spray()` can make SLUB release the target page before every original cmsg allocation on that page has returned, and a later `sock_kfree_s()` sees a non-slab page.
- Align 8 is currently the safest tuning point for continued PREEMPT testing because it missed without panicking in the one-attempt check.

### Retry-loop check
- Added `run_preempt_align8_loop.sh` and `vmshare_preempt_align8_loop/` for a fixed-align retry test without `BAD_DST_MAX_ATTEMPTS`.
- The retry-loop run panicked on the first align-8 attempt at the same `sock_kfree_s()` / `kfree()` site, so the earlier clean align-8 miss is not stable.
- Added spray worker thread names (`spray%04zx`) with `prctl(PR_SET_NAME)` so future panics identify which spray slot reached the bad `sock_kfree_s()` free.
- Rebuilt with the spray thread names and reran focused checks:
  - align 8 one-attempt: clean miss again;
  - align 9 one-attempt: clean miss in that run.
- Ran the normal align sweep with named spray workers:
  - attempts 1 through 4 missed cleanly;
  - attempt 5 (`align_pad=4`) panicked at `mm/slub.c:4118`;
  - the crashing worker was `Comm: spray011c`, i.e. spray slot `0x11c` / `284`.
- Increased `MAX_VULN_PIPES` from `0x40` to `0x200` and added `run_preempt_vuln256.sh` to test denser vuln pipe-buffer reclaim with `BAD_DST_VULN_PIPES=256`.

### Pipe-buffer slab bucket probe
- Added `pipe_slab_probe.c` to confirm the runtime slab bucket used by pipe-buffer rings on this x86 PREEMPT kernel.
- The probe opens 512 pipes, sets 1-page rings, then resizes to 4-page rings and prints `/proc/slabinfo` deltas.
- Result:
  - before: `kmalloc-192` active objects `441`, `kmalloc-256` active objects `672`;
  - after 1-page rings: `kmalloc-192` active objects `945`, `kmalloc-256` unchanged at `672`;
  - after 4-page rings: `kmalloc-192` active objects `1449`, `kmalloc-256` unchanged at `672`.
- Conclusion: on this x86 kernel, the 4-slot `struct pipe_buffer` array is a `kmalloc-192` allocation. It does not directly consume the fake unaligned `kmalloc-256` free. The working primitive on this test kernel is therefore relying on cross-cache page movement, not same-cache fake-slot allocation.
- The `BAD_DST_VULN_PIPES=256` run matched that conclusion:
  - attempts 1 through 3 missed cleanly;
  - attempt 4 panicked at `mm/slub.c:4118`;
  - the crashing worker was `Comm: spray017d`.

## 2026-05-03 x86 kmalloc minimum alignment source patch

### Checkpoint
- Backed up the pre-change kernel header:
  - `old/2026-05-03_before_x86_kmalloc_minalign128_cache.h`
- Backed up the pre-change log:
  - `old/2026-05-03_before_x86_kmalloc_minalign128_RUNNING_LOG.md`

### Change
- Patched `/home/jack/Documents/college/purdue/research/linux_src/linux_stable/arch/x86/include/asm/cache.h` to define:
  - `ARCH_DMA_MINALIGN 128`
- Reason:
  - `include/linux/slab.h` derives `KMALLOC_MIN_SIZE` and `KMALLOC_SHIFT_LOW` from `ARCH_DMA_MINALIGN` when it is greater than 8.
  - `mm/slab_common.c:setup_kmalloc_cache_index_table()` already redirects 136..192 byte allocations to index 8 (`kmalloc-256`) when `KMALLOC_MIN_SIZE >= 128`.
  - This makes the x86 test build match the intended no-effective-`kmalloc-192` layout for the exploit test.

### Note
- This is a source patch, not a config change.
- I have not rebuilt the kernel in this step yet.

## 2026-05-03 Revert wrong-new-kernel changes

### Checkpoint
- Backed up the immediate pre-revert state:
  - `old/2026-05-03_before_revert_wrong_new_kernel_exp_x86.c`
  - `old/2026-05-03_before_revert_wrong_new_kernel_RUNNING_LOG.md`
  - `old/2026-05-03_before_revert_wrong_new_kernel_cache.h`

### Reverted
- Restored `exp_x86.c` from `old/2026-05-03_before_new_kernel_preempt_offsets_exp_x86.c`.
  - This removes the wrong-`new_kernel` hardcoded offsets, spray worker thread-name instrumentation, temporary `MAX_VULN_PIPES=0x200` tuning, and the invalid 5-page vuln-pipe ring experiment.
- Restored `/home/jack/Documents/college/purdue/research/linux_src/linux_stable/arch/x86/include/asm/cache.h` from `old/2026-05-03_before_x86_kmalloc_minalign128_cache.h`.
  - This removes the `ARCH_DMA_MINALIGN 128` source patch.
- Removed temporary wrong-kernel investigation artifacts:
  - `pipe_slab_probe`, `pipe_slab_probe.c`
  - `run_preempt_align8.sh`, `run_preempt_align9.sh`, `run_preempt_align8_loop.sh`, `run_preempt_vuln256.sh`
  - `vmshare_preempt_align8/`, `vmshare_preempt_align9/`, `vmshare_preempt_align8_loop/`, `vmshare_preempt_vuln256/`

### Kept
- Kept this running log and all `old/` checkpoints so the wrong-kernel investigation remains auditable.

### Verification
- Verified the kernel header has no remaining git diff after the revert.
- Verified temporary wrong-kernel probe/wrapper artifacts were removed.
- Rebuilt `bad_dst_cache` from the reverted `exp_x86.c` with:
  - `nix-shell -p glibc.static --run ./compile_x86.sh`
- The direct `./compile_x86.sh` path still fails outside Nix because the host shell lacks static libc for `-static`; the Nix build succeeds.

## 2026-05-03 Fix x86 no-kmalloc-192 build inputs

### Checkpoint
- Backed up the pre-fix files:
  - `old/2026-05-03_before_fix_kmalloc192_source_cache.h`
  - `old/2026-05-03_before_fix_kmalloc192_preempt_config`
  - `old/2026-05-03_before_fix_kmalloc192_RUNNING_LOG.md`

### Source Fix
- Re-added `ARCH_DMA_MINALIGN 128` to `/home/jack/Documents/college/purdue/research/linux_src/linux_stable/arch/x86/include/asm/cache.h`.
- Reason: in this 5.10 tree, `include/linux/slab.h` derives `KMALLOC_MIN_SIZE` and `KMALLOC_SHIFT_LOW` from `ARCH_DMA_MINALIGN` when it is greater than 8. This makes `setup_kmalloc_cache_index_table()` redirect 136..192 byte kmalloc requests to kmalloc-256.

### Config Fix
- Replaced `/home/jack/Documents/college/purdue/research/linux_build/2026-05-03_testvm_dump_config_preempt.config` with the cleaned generated `.config` from:
  - `/home/jack/Documents/college/purdue/research/linux_build/build_out/2026-05-03_testvm_dump_config_preempt__x86_64__gcc-10/.config`
- This removes the stray dumped dmesg line:
  - `[    9.884482] random: crng init done`
- It also keeps Kconfig-derived PREEMPT symbols (`CONFIG_PREEMPT_COUNT`, `CONFIG_PREEMPTION`, `CONFIG_PREEMPT_RCU`, `CONFIG_DEBUG_PREEMPT`, etc.) so `build_linux.py` no longer stops because input config and output `.config` differ.

### Build And Runtime Verification
- Reran the exact build command:
  - `python build_linux.py -c gcc-10 -a x86_64 -s ../../linux_src/linux_stable/ -o ../build_out/ --compile-commands -k ../2026-05-03_testvm_dump_config_preempt.config`
- Build completed successfully and produced `Kernel: arch/x86/boot/bzImage is ready (#2)`.
- Moved the stale pre-fix `new_kernel/` directory to:
  - `old/2026-05-03_before_fix_kmalloc192_new_kernel/`
- Copied the rebuilt artifacts into `new_kernel/`:
  - `/home/jack/Documents/college/purdue/research/linux_build/build_out/2026-05-03_testvm_dump_config_preempt__x86_64__gcc-10/arch/x86/boot/bzImage`
  - `/home/jack/Documents/college/purdue/research/linux_build/build_out/2026-05-03_testvm_dump_config_preempt__x86_64__gcc-10/vmlinux`
- Booted the rebuilt `build_out` kernel under `testvm` with a slabinfo check.
- Runtime `/proc/slabinfo` showed `kmalloc-128` and `kmalloc-256`, but no `kmalloc-192`, `kmalloc-rcl-192`, or `dma-kmalloc-192`.
- Saved the runtime check artifacts:
  - `old/2026-05-03_check_no_kmalloc192.sh`
  - `old/2026-05-03_check_no_kmalloc192.log`

## 2026-05-03 PREEMPT kernel exploit test

### Checkpoint
- Backed up the no-preempt-keyed exploit before changing hardcoded symbols:
  - `old/2026-05-03_before_preempt_kernel_constants_exp_x86.c`
  - `old/2026-05-03_before_preempt_kernel_constants_bad_dst_cache`
  - `old/2026-05-03_before_preempt_kernel_constants_RUNNING_LOG.md`

### Constant Update
- Updated `exp_x86.c` for the rebuilt PREEMPT/no-`kmalloc-192` kernel:
  - `anon_pipe_buf_ops`: `0xffffffff827bf740`
  - `dst_blackhole_ops`: `0xffffffff836a9c40`
- Rebuilt `bad_dst_cache` with:
  - `nix-shell -p glibc.static --run ./compile_x86.sh`

### Test Setup
- Created bounded guest wrappers so environment variables propagate inside testvm:
  - `old/2026-05-03_preempt_test_smp1/run.sh`
  - `old/2026-05-03_preempt_test_smp6/run.sh`
- Both wrappers used:
  - `BAD_DST_MAX_ATTEMPTS=21`
  - `BAD_DST_RTABLE_RCU_US=50000`
  - `BAD_DST_FAKE_DST_RCU_US=50000`

### Results
- PREEMPT, `--smp 1`:
  - command log: `old/2026-05-03_preempt_test_smp1.log`
  - attempts 1 through 6 missed cleanly;
  - attempt 7 printed `found corrupted pipe FIONREAD`;
  - reached `kaslr base: ffffffff81000000`, `physical base address: 200000`, and `Arb R/W setup`.
- PREEMPT, `--smp 6`:
  - command log: `old/2026-05-03_preempt_test_smp6.log`
  - SMP groom and `membarrier MEMBARRIER_CMD_GLOBAL RCU sync enabled` were active;
  - attempt 1 missed cleanly;
  - attempt 2 printed `found corrupted pipe FIONREAD`;
  - reached `kaslr base: ffffffff81000000`, `physical base address: 200000`, and `Arb R/W setup`.

### Interpretation
- With the corrected PREEMPT symbols and the rebuilt x86 kernel where `kmalloc-192` is absent, the debug-67 heap exploit works on the PREEMPT test kernel.
- The current `exp_x86.c` and `bad_dst_cache` are now keyed to `new_kernel/`, not the old no-preempt `bzImage`/`vmlinux`. The old no-preempt-keyed files are preserved in the checkpoint above.

## 2026-05-03 Real race trigger investigation

### Scope
- Kept exploit and kernel source read-only.
- Reviewed the real `SO_CNX_ADVICE == 1` path, socket locking behavior, the proposed `getsockopt()` oracle, UDP send fast path, and the generated PREEMPT test-kernel assembly in `new_kernel/vmlinux`.

### Kernel Control Flow
- `sock_setsockopt()` takes `lock_sock(sk)` before the option switch and releases it after the switch.
- The real trigger is `SO_CNX_ADVICE` with value `1`, which calls `dst_negative_advice(sk)` while the socket lock is held.
- The vulnerable order is still:
  - read `sk->sk_dst_cache`;
  - call `dst->ops->negative_advice(dst)`;
  - if the returned dst differs, store it back to `sk->sk_dst_cache`.
- IPv4 `ipv4_negative_advice()` calls `ip_rt_put()` / `dst_release()` and returns `NULL` when `dst->obsolete > 0`, `RTCF_REDIRECTED`, or `dst.expires` is set.
- In the rebuilt PREEMPT x86 kernel, the value-1 `SO_CNX_ADVICE` path is:
  - load `sk_dst_cache`;
  - indirect-call `negative_advice`;
  - compare returned pointer with old dst;
  - store returned pointer to `sk_dst_cache`;
  - clear tx queue / pending confirm;
  - release socket lock.
- The smallest post-return window is only a few instructions, but the useful window can also include the tail of `dst_release()` after the refcount reaches zero and before `negative_advice()` returns.

### Oracle Findings
- `getsockopt(..., SOL_SOCKET, SO_ERROR, ...)` is not a socket-lock oracle: `sock_getsockopt()` does not take `lock_sock()`.
- `getsockopt(..., IPPROTO_IP, IP_MTU, ...)` is a socket-lock oracle: `do_ip_getsockopt()` calls `lock_sock(sk)` before the `IP_MTU` case.
- If an `IP_MTU` oracle worker blocks, it proves another thread still owns `sk_lock`; it does not prove the dst refcount has already been dropped. It can also mean the trigger thread was preempted before or inside `negative_advice()`.
- `lock_sock()` waits in `TASK_UNINTERRUPTIBLE`, so a blocked oracle thread/process can be timed as an observation, but kill/cancel is not reliable cleanup until the original socket lock is released.

### UDP Fast Path
- Connected UDP send without corking reaches `sk_dst_check(sk, 0)` before taking the normal socket lock.
- `MSG_PROBE` still exercises `sk_dst_check()` / `dst->ops->check()` but avoids later payload/corking work.
- This explains why the debug-67 harness can keep the socket lock held and still drive the stale/fake dst through UDP send.

### Trigger Viability And Issues
- The timerfd + PREEMPT approach is viable on the PREEMPT test kernel, but the timing target is narrow.
- Main is pinned to CPU0, trigger starts pinned to CPU0 and SCHED_IDLE, and the CPU1 blocker exists in the non-DEBUG path. This matches the intended preempt-and-migrate scheme.
- IRQ affinity is currently pinned to CPU0 by default, which likely helps the timer interrupt and wakeup land on the same CPU as the trigger.
- On SMP, moving the trigger thread to CPU1 only keeps it frozen if CPU1 is continuously occupied by higher-priority work; the current CPU1 busy loop is normal priority while trigger is SCHED_IDLE, so that assumption is reasonable.
- A blocking `IP_MTU` oracle should be treated as a classifier for "preempted somewhere under the socket lock", not as a win condition.
- A practical next classifier would separate:
  - no block plus `IP_MTU == -ENOTCONN`: too late, `sk_dst_cache` already cleared;
  - no block plus valid `IP_MTU`: too early or trigger did not reach invalidation;
  - block: frozen under lock; then exploitation or a stronger dst-state oracle is needed to determine whether the ref was dropped.
- For test-kernel calibration only, ftrace/kprobes or direct assembly breakpoints around `dst_release()` / `sock_setsockopt+0xec8` could measure the timer offset. Those are calibration aids, not target techniques.

## 2026-05-03 Stronger race oracle investigation

### Strongest Non-Destructive Test-Kernel Oracle
- `/proc/<trigger_tid>/stack` is a strong candidate on the PREEMPT test kernel.
- The test config has `CONFIG_STACKTRACE=y`, `CONFIG_KALLSYMS=y`, `CONFIG_KALLSYMS_ALL=y`, and no forced lockdown. Reading the file requires `CAP_SYS_ADMIN`, which the initrd exploit environment should have.
- Unlike `/proc/<tid>/syscall`, `/proc/<tid>/stack` does not require the task to be sleeping. It can unwind a runnable but currently unscheduled trigger thread, which matches the SCHED_IDLE trigger + CPU1 blocker design.
- `/proc/<tid>/syscall` is not useful here because `task_current_syscall()` returns `-EAGAIN` for `TASK_RUNNING` tasks and proc prints `running`.
- `/proc/<tid>/wchan` is also not useful because it returns 0 for `TASK_RUNNING` tasks.

### Stack Oracle Interpretation For `new_kernel/vmlinux`
- Relevant symbols:
  - `sock_setsockopt`: `0xffffffff81c054a0`
  - `dst_release`: `0xffffffff81c2cd80`
  - `ipv4_negative_advice`: `0xffffffff81d8c310`
- In `sock_setsockopt`, the real `SO_CNX_ADVICE == 1` path reaches:
  - `sock_setsockopt+0xefb`: indirect call to `dst->ops->negative_advice`.
  - `sock_setsockopt+0xf00`: compare return value against the old dst.
  - `sock_setsockopt+0xf09`: store returned value into `sk_dst_cache`.
- A stack top around `dst_release` means the trigger is inside the ref-drop path. If it is after `dst_release+0x18`, the refcount decrement instruction has likely executed.
- A stack top around `ipv4_negative_advice+0x2a` or `sock_setsockopt+0xf00..0xf08` is the best signal: `negative_advice()` has returned `NULL`, but `sk_dst_cache` has not yet been cleared.
- A stack top at or after `sock_setsockopt+0xf09` means the lock may still be held, but the useful stale-pointer window is already gone.
- A stack top before the `negative_advice` call is a too-early timer hit.

### Other Candidate Oracles
- Kmsg underflow oracle:
  - On a sacrificial socket, a `send(..., MSG_PROBE)` after the route refcount reaches zero can cause `sk_dst_set()` to release the stale cached dst and print `dst_release underflow`.
  - This is a strong confirmation of "stale cached dst with zero refcount", but it is destructive because it consumes/replaces `sk_dst_cache`. It should not be used on the exploit attempt.
  - It may not fire immediately after `SO_CNX_ADVICE` if route/FNHE/table references still keep the original rtable refcount above zero.
- Tracefs/kprobe oracle:
  - The test config has `CONFIG_KPROBES=y`, `CONFIG_KPROBE_EVENTS=y`, `CONFIG_FTRACE=y`, `CONFIG_FUNCTION_TRACER=y`, `CONFIG_DYNAMIC_FTRACE=y`, `CONFIG_BPF_EVENTS=y`, and `CONFIG_PERF_EVENTS=y`.
  - Kprobes at `sock_setsockopt+0xf00` / `sock_setsockopt+0xf09`, or function-graph tracing around `ipv4_negative_advice()` and `dst_release()`, would be the most exact calibration aid.
  - This perturbs timing and is not a realistic target oracle; use only for offset calibration in the test VM.

### Rejected Or Weak Oracles
- `SOL_SOCKET/SO_ERROR`: no socket lock and no dst read.
- `IP_MTU`: good lock oracle, but blocked-or-not only says whether `sk_lock` is held.
- `udp_diag` / inet diag netlink: exposes socket state and queues, not `sk_dst_cache`.
- UDP ioctls `SIOCOUTQ` / `SIOCINQ`: queue-only, no dst path.
- ICMP PMTU delivery: updates PMTU and sets socket error in both early and post-drop cases; it does not cleanly distinguish whether the socket dst ref was already dropped.

## 2026-05-03 Real race trigger implementation

### Checkpoints
- `old/2026-05-03_before_real_race_trigger_exp_x86.c`
- `old/2026-05-03_before_stack_oracle_classifier_fix_exp_x86.c`
- `old/2026-05-03_before_bracketed_race_tuner_exp_x86.c`
- `old/2026-05-03_before_target_stack_calibration_knobs_exp_x86.c`

### Implemented
- Switched the x86 exploit to the real `SO_CNX_ADVICE == 1` trigger path by leaving `DEBUG` disabled.
- Added a reusable env parser and `BAD_DST_TIMER_INITIAL_NS` for fixed-offset calibration.
- Added a CPU1 blocker and trigger release path so the trigger can be preempted on CPU0, moved to CPU1, and held there while the main thread drives the post-race path.
- Added a `/proc/<trigger_tid>/stack` oracle for the test kernel:
  - classifies far early, near early, target, near late, and far late states;
  - treats `dst_release+>=0x18`, `ipv4_negative_advice+>=0x2a`, and `sock_setsockopt+0xf00..0xf08` as target;
  - treats `sock_setsockopt+0x1025..0x1036` as near-early because that is the out-of-line `prandom_u32()` detour that jumps back before the dst negative-advice call;
  - can print all stacks with `BAD_DST_STACK_ORACLE_VERBOSE=1` or only target stacks with `BAD_DST_STACK_ORACLE_VERBOSE_TARGET=1`.
- Added a bracketed timer tuner. Once it sees both an early and a late offset, it jumps to the midpoint instead of crawling one small decrement at a time.
- Added a forked `IP_MTU` lock oracle, but current results show it should only be treated as a weak secondary guard. In this VM it reports blocked even when the trigger stack is already in `pipe_read`, so the stack oracle is the real calibration signal.

### Test Results
- Rebuilt with `nix-shell -p glibc.static --run ./compile_x86.sh`. Only existing format/ignored-return warnings were emitted.
- `old/2026-05-03_real_race_stack_verbose_smp2_after_classifier.log` explained previous `unknown` classifications:
  - far early examples: `timerfd_settime`, `security_socket_setsockopt`, `__fget_light`;
  - far late examples: `pipe_read`, `exit_to_user_mode_prepare`;
  - the important classifier bug was `sock_setsockopt+0x1025/0x102a`, which is early despite its high numeric offset.
- `old/2026-05-03_real_race_bracket_smp2.log` hit target stack states multiple times under the real trigger:
  - candidates appeared on attempts 28, 34, 41, 63, 64, and 74;
  - all candidates reached the post-race exploit path but failed at pipe corruption.
- `old/2026-05-03_real_race_target_stack_smp2.log` confirmed the accepted target samples are real:
  - `dst_release+0x24`, `ipv4_negative_advice+0x2a`, `sock_setsockopt+0xf00`;
  - `__indirect_thunk_start+0x4` with caller `sock_setsockopt+0xf00`;
  - `dst_release+0x22`, `ipv4_negative_advice+0x2a`, `sock_setsockopt+0xf00`.

### Current Boundary
- The real timerfd/preemption trigger is now hitting the intended window on the PREEMPT test kernel.
- The current failure is no longer "cannot hit the race"; it is "race candidate reached, but post-race reclaim does not corrupt a pipe".
- Next investigation should focus on whether the PMTU/FNHE expiry is dropping the expected final rtable reference in the real-race path, and whether the kmalloc-256 to pipe-buffer reclaim still has the same object/page state as the debug-67 path.

### Hypothesis For Pipe Corruption Failure
- The strongest current explanation is fd inheritance from the forked `IP_MTU` lock oracle.
- The oracle child is forked after the pre-sockets and vulnerable socket are opened. If it blocks in `getsockopt(IP_MTU)`, it keeps inherited references to all pre-socket fds while the parent runs `try_run_main_exploit()`.
- `try_run_main_exploit()` then closes `ctx->pre_sockets` in the parent, but those sockets may not actually be destroyed because the blocked child still has duplicate fds. That changes the allocator state compared with the debug-67 path and can prevent the intended route-object slab/page from being released and reclaimed by the sendmsg/pipe-buffer sequence.
- A secondary issue is false-positive target classification for retpoline frames. A stack with top `__indirect_thunk_start` and caller `sock_setsockopt+0xf00` can be before the `negative_advice()` body has actually run, even though the caller return address looks like the target window.
- Target samples inside `dst_release+0x22/+0x24` prove the decrement path is reached, but they do not by themselves prove the later PMTU/FNHE expiry and allocator state match the debug path.

### Lock Oracle Test Result
- Added `BAD_DST_LOCK_ORACLE_CLOSE_FDS=1`; in the forked oracle child, all inherited fds >= 3 except the vulnerable socket are closed before `getsockopt(IP_MTU)`.
- Test log: `old/2026-05-03_real_race_fdclean_smp2.log`.
- Result: still failed at pipe corruption. It reached target candidates including `ipv4_negative_advice+0x2a` and still did not corrupt a pipe.
- Added `BAD_DST_LOCK_ORACLE=0` to skip the forked lock oracle entirely and rely only on the stack oracle.
- Test log: `old/2026-05-03_real_race_no_lock_oracle_smp2.log`.
- Result: still failed at pipe corruption. Attempt 7 hit a clean stack target at `ipv4_negative_advice+0x2a` / `sock_setsockopt+0xf00` with no oracle child at all.
- Conclusion: fd inheritance from the lock oracle is not the primary cause of the current pipe corruption failure.
- Updated suspicion: the real-race path is hitting the socket stale-pointer window, but the original rtable may not be becoming reclaimable in the same allocator state as the debug-67 path. Next useful check is a targeted stale-rtable/refcount oracle after PMTU/FNHE expiry, before the sendmsg spray.

### Fake Dst Ops Oracle
- Checkpoint before this diagnostic:
  - `old/2026-05-03_before_fake_ops_oracle_exp_x86.c`
  - `old/2026-05-03_before_fake_ops_oracle_RUNNING_LOG.md`
- Added environment controls for the fake `metadata_dst` sprayed into the sendmsg payload:
  - `BAD_DST_FAKE_DST_OFFSET`, default `64`;
  - `BAD_DST_FAKE_DST_OPS`, default `0xffffffff836a9c40`;
  - `BAD_DST_FAKE_DST_OBSOLETE`, default `1`;
  - `BAD_DST_FAKE_DST_REFCNT`, default `1`;
  - `BAD_DST_FAKE_DST_FLAGS`, default `0xffff`;
  - `BAD_DST_FAKE_DST_TYPE`, default `METADATA_HW_PORT_MUX`.
- Diagnostic intent: run with `BAD_DST_FAKE_DST_OPS=0x4141414141414141`. If the race candidate reaches the sprayed fake dst, `MSG_PROBE` should fault when `sk_dst_check()` calls through the poisoned ops table. If the run still reaches the pipe-corruption failure without crashing, then the sendmsg spray probably did not reclaim the stale rtable object in that candidate.
- First poison-ops run:
  - Test log: `old/2026-05-03_real_race_fake_ops_oracle_smp2.log`.
  - Attempt 16 reached a target-classified stack, but it was the questionable timer-interrupt/retpoline shape (`rt_cpu_seq_show+0xd0/0xd0` with caller `sock_setsockopt+0xf00`), not a clean `dst_release` or `ipv4_negative_advice` frame.
  - With `BAD_DST_FAKE_DST_OPS=0x4141414141414141`, the run did not fault at `MSG_PROBE`; it continued to `FAIL: could not corrupt pipe`.
  - This supports treating that retpoline-shaped stack as too weak for the reclaim oracle, but it does not yet prove what happens on a clean target-frame candidate.

### Strong Stack Target Filter
- Checkpoint before this filter:
  - `old/2026-05-03_before_strong_stack_target_filter_exp_x86.c`
  - `old/2026-05-03_before_strong_stack_target_filter_RUNNING_LOG.md`
- Added `BAD_DST_STRONG_STACK_TARGET_ONLY=1` for diagnostics. When enabled, a bare `sock_setsockopt+0xf00..0xf08` stack is classified as `unknown`; only stacks that include `dst_release` or `ipv4_negative_advice` can satisfy `BAD_DST_REQUIRE_STACK_TARGET=1`.
- Reason: the poison-ops reclaim oracle should only run on clean target frames. The retpoline/timer-interrupt symbolization can look like the post-`negative_advice()` return address before the callee has actually completed.
- Strong-filter poison run:
  - Test log: `old/2026-05-03_real_race_fake_ops_strong_stack_smp2.log`.
  - With fixed `BAD_DST_TIMER_INITIAL_NS=67194`, `BAD_DST_STRONG_STACK_TARGET_ONLY=1`, and `BAD_DST_FAKE_DST_OPS=0x4141414141414141`, attempts 1-96 produced no clean target frames.
  - The run mostly saw `too_late_far` or `unknown`; the previously accepted bare `sock_setsockopt+0xf00` shape was filtered out as intended.
  - This run did not exercise the poison fake-ops path. Next useful test is to re-enable timer autotuning with the strong filter so the poison oracle only fires on an actual `dst_release`/`ipv4_negative_advice` stack.
- Strong-filter autotuned poison run:
  - Test log: `old/2026-05-03_real_race_fake_ops_strong_autotune_smp2.log`.
  - The strict classifier produced clean candidates at attempts 23, 33, 44, and 74; attempt 44 included `dst_release+0x22/0x90` and `ipv4_negative_advice+0x2a/0x30`.
  - Each completed candidate reached `trigger kmalloc-256 invalid free...` with `BAD_DST_FAKE_DST_OPS=0x4141414141414141` and did not fault; each continued to `FAIL: could not corrupt pipe`.
  - Conclusion: on clean real-race candidates, `send(..., MSG_PROBE)` is not calling through the sprayed fake `dst.ops`. The stale socket dst pointer is therefore not pointing at the sendmsg-reclaimed payload at that point.
  - This shifts the main suspect away from the timer race and toward post-race lifetime/reclaim assumptions: either the original rtable still has a real reference, the stale pointer does not refer to the freed slot expected by the spray, or allocator grooming differs between the debug-67 path and the real race path before the sendmsg spray.

### Sendmsg Spray CPU Placement
- Checkpoint before this diagnostic:
  - `old/2026-05-03_before_spray_cpu_knob_exp_x86.c`
  - `old/2026-05-03_before_spray_cpu_knob_RUNNING_LOG.md`
- Added spray placement knobs:
  - `BAD_DST_SPRAY_CPU`, default `0`;
  - `BAD_DST_SPRAY_PERCPU`, default `0`.
- When `BAD_DST_SPRAY_PERCPU=1`, spray threads are distributed across online CPUs by thread index. This is a diagnostic for the possibility that the real-race rtable free is landing on a non-CPU0 SLUB freelist while the existing sendmsg spray only allocates on CPU0.
- Per-CPU spray poison run:
  - Test log: `old/2026-05-03_real_race_fake_ops_spray_percpu_smp2.log`.
  - With `BAD_DST_SPRAY_PERCPU=1`, strict stack filtering, autotune, and poisoned fake ops, attempts 1-100 produced no clean `dst_release`/`ipv4_negative_advice` target frames.
  - Result is inconclusive for allocator placement because the poison path was never exercised in that run.
- CPU1-only spray poison run:
  - Test log: `old/2026-05-03_real_race_fake_ops_spray_cpu1_smp2.log`.
  - With `BAD_DST_SPRAY_CPU=1`, clean candidates appeared at attempts 46 and 55.
  - Both candidates reached `trigger kmalloc-256 invalid free...` with poisoned fake ops and did not fault; both continued to `FAIL: could not corrupt pipe`.
  - Conclusion: simply moving the sendmsg spray from CPU0 to CPU1 does not make the stale dst pointer hit the sprayed fake object. CPU-local SLUB placement alone is unlikely to explain the real-race miss.

## 2026-05-03 Race Window Trace And Stack Oracle Recheck

### Checkpoints
- `old/2026-05-03_before_trace_marker_exp_x86.c`
- `old/2026-05-03_before_require_dst_release_frame_exp_x86.c`
- `old/2026-05-03_before_affinity_timing_markers_exp_x86.c`
- `old/2026-05-03_before_rt_cpu1_blocker_exp_x86.c`

### Added Diagnostics
- Added trace-marker writes around the real-race path:
  - attempt start, vulnerable socket open, before/after timerfd read, after trigger affinity move, stack oracle, lock oracle, candidate, and the main exploit stages.
- Added `BAD_DST_REQUIRE_DST_RELEASE_FRAME=1` so `ipv4_negative_advice` alone can be rejected unless the stack also proves the refcount-drop frame.
- Added `BAD_DST_STACK_ORACLE_VERBOSE_TARGET=1` and `BAD_DST_STRONG_STACK_TARGET_ONLY=1` to reduce retpoline-shaped false positives.
- Added kprobes for:
  - `sock_setsockopt+0xed6` (`cnxload`): reads `sk_dst_cache`;
  - `sock_setsockopt+0xf00` (`cnxret`): after `negative_advice()` returns, before the cache clear;
  - `sock_setsockopt+0xf09` (`cnxassign`): immediately before the `sk_dst_cache = ndst` store.

### Lock Oracle Finding
- The forked `IP_MTU` lock oracle is unreliable as currently implemented.
- With inherited fd cleanup enabled, it reports `blocked` on every attempt; the child can spend the timeout closing thousands of fds before reaching `getsockopt()`.
- With fd cleanup disabled and a 5 ms timeout, it still reports `blocked` on every attempt in the SMP2 runs. One run took about 104 ms despite `BAD_DST_LOCK_ORACLE_US=5000`.
- Treat it as a weak debugging signal only. It should not be used to accept a candidate without another state oracle.

### Important Trace Results
- Run folder: `old/2026-05-03_real_race_cnx_assign_trace_smp2`.
- `kprobe_events.actual` confirms `cnxload`, `cnxret`, and `cnxassign` all registered.
- The run did not accept a strict stack target before the wrapper deadline expired, but the trace proved the migration race window exists.
- Multiple attempts show this sequence:
  - `cnxload` on CPU0;
  - `cnxret` with `new=0x0` and `old_ref=1`;
  - main thread returns from `timerfd` and moves the trigger to CPU1;
  - `/proc/<tid>/stack` reports `unknown`;
  - `cnxassign` later executes on CPU1, sometimes several milliseconds later.
- Examples from the trace:
  - attempt 333: `cnxret` at 379.340878, `after_pin_trigger` at 379.341516, stack oracle `unknown` at 379.342433, `cnxassign` at 379.358087.
  - attempt 334: `cnxret` at 380.436696, `after_pin_trigger` at 380.437275, stack oracle `unknown` at 380.437801, `cnxassign` at 380.454098.
  - attempt 346: `cnxret` at 393.550672, `after_pin_trigger` at 393.551237, stack oracle `unknown` at 393.551693, `cnxassign` at 393.560953.
- These are real post-`negative_advice()` / pre-assignment windows. The current strict stack oracle is missing them.

### Kernel Code Explanation
- In `arch/x86/kernel/unwind_orc.c`, `__unwind_start()` refuses to unwind another task while `task_on_another_cpu(task)` is true.
- `task_on_another_cpu()` is `task != current && task->on_cpu` on SMP.
- Therefore `/proc/<tid>/stack` can return no useful frames when the trigger is actually running on CPU1. That matches the trace windows where `cnxassign` later appears on CPU1 and the stack oracle classified `unknown`.
- The CPU1 blocker was only normal-priority CFS while the trigger was `SCHED_IDLE`. On this kernel, `SCHED_IDLE` is still a very low-weight fair-scheduler task, not an absolute "never run while normal work is runnable" class.
- Next debugging step: make the CPU1 blocker optionally `SCHED_FIFO` on the test VM. If the blocker succeeds, the trigger should stay inactive after migration, `/proc/<tid>/stack` should become more reliable, and `cnxassign` should not run until explicit release.

## 2026-05-03 RT CPU1 Blocker And Real-Ops Recheck

### Checkpoint
- `old/2026-05-03_before_real_ops_trace_debug_RUNNING_LOG.md`

### RT Blocker Finding
- Added an optional CPU1 blocker using `SCHED_FIFO` priority 80, controlled by `BAD_DST_CPU1_BLOCK_RT` and `BAD_DST_CPU1_BLOCK_RT_PRIO`.
- Run folder: `old/2026-05-03_real_race_rt_blocker_trace_smp2`.
- With normal RT throttling, attempt 8 reached a target stack:
  - `asm_sysvec_apic_timer_interrupt+0x12/0x20`
  - `sock_setsockopt+0xf03/0x1050`
- Trace showed `cnxret` at 24.867097 and a target stack at 24.870495, but `cnxassign` still ran at 25.405406 because the kernel throttled the RT blocker.
- At the later `MSG_PROBE`, `sk_dst_check` saw `dst=0`, so the socket cache had already been cleared. This explains the previous pipe-corruption failures in the RT-blocker run.

### RT Throttling Disabled
- Run folder: `old/2026-05-03_real_race_rt_blocker_no_rt_throttle_smp2`.
- Wrapper set `/proc/sys/kernel/sched_rt_runtime_us` to `-1`.
- With `BAD_DST_FAKE_DST_OPS=0x4141414141414141`, the VM faulted in `sk_dst_check+0x4c` with `RAX=0x4141414141414141`.
- This proves the stale socket dst survived until `MSG_PROBE` and the sendmsg spray reclaimed the stale rtable slot at the expected fake-dst offset.
- The current race problem is therefore no longer "does the stale socket dst survive"; with RT throttling disabled, it does.

### Real Blackhole Ops Result
- Run folder: `old/2026-05-03_real_race_rt_blocker_real_ops_smp2`.
- Wrapper used the real `dst_blackhole_ops` pointer, kept the RT CPU1 blocker, and kept `sched_rt_runtime_us=-1`.
- Result: no pipe corruption within the attempt budget. `deadline_remaining` was `0`.
- It reached four accepted target candidates and all four entered the exploit body, but each ended with `FAIL: could not corrupt pipe`.
- The kernel emitted `dst_release underflow` warnings from `ipv4_negative_advice` / `sock_setsockopt`, which is consistent with releasing the frozen trigger after failed candidates rather than proof of the fake metadata-dst free.

### Code Reading
- `dst_blackhole_check()` returns `NULL`.
- `sk_dst_check()` increments the dst refcount with `sk_dst_get()`, calls `dst->ops->check(dst, cookie)`, then if it returns `NULL` resets `sk_dst_cache` and calls `dst_release()` twice for the same stale dst pointer.
- With fake refcount `1`, this should go `1 -> 2 -> 1 -> 0`, scheduling `dst_destroy_rcu`.
- `dst_destroy()` sees `DST_METADATA` in fake flags and calls `metadata_dst_free()`, which reaches `kfree(dst)` for `METADATA_HW_PORT_MUX`.
- Since `dst` is the stale rtable pointer inside the reclaimed sendmsg allocation, this should be the intended unaligned `kfree(payload + 64)` path.

### Current Hypothesis
- The race/reclaim into sendmsg is now proven on the test kernel.
- The remaining miss is likely after the blackhole `check()` path:
  - the unaligned free is not being reused by a vulnerable pipe-buffer ring;
  - or the pipe-buffer ring is allocated there but the containing sendmsg slab page does not become fully free when the spray is released;
  - or the page is freed but not reclaimed by the pipe backing-page spray on the CPU/cache path being exercised.
- Next diagnostic should trace `sk_dst_check`, `dst_release`, `dst_destroy`, and the exploit trace markers with real blackhole ops and RT throttling disabled, stopping after the first failed candidate.

## 2026-05-03 Fake-Dst Alignment And Retry Hardening

### Checkpoints
- `old/2026-05-03_before_mixed_fake_dst_payloads_exp_x86.c`
- `old/2026-05-03_before_mixed_fake_dst_payloads_RUNNING_LOG.md`
- `old/2026-05-03_before_timerfd_retry_timeout_exp_x86.c`
- `old/2026-05-03_before_timerfd_retry_timeout_RUNNING_LOG.md`
- `old/2026-05-03_before_scan_leaked_vuln_pipes_exp_x86.c`
- `old/2026-05-03_before_scan_leaked_vuln_pipes_RUNNING_LOG.md`

### Fake-Dst Alignment Finding
- `old/2026-05-03_fixed64_three_active_trace_smp2` showed the real-race path was often reaching sendmsg-reclaimed memory but landing at different offsets inside the 256-byte control-message object.
- Observed stale dst offsets:
  - offset `0`: unusable because the cmsg header occupies the beginning of the object;
  - offset `64`: usable with the original fake dst placement;
  - offset `128`: usable, but missed by fixed offset `64`;
  - offset `192`: unusable because `dst->__refcnt` overlaps the next object `cmsg_len=256`.
- Added mixed fake-dst spray mode with alternating payload variants at offsets `64` and `128`, controlled by `BAD_DST_FAKE_DST_OFFSET_MIX`.
- Reinitialized the payload buffers per attempt before building fake dst fields. This avoids stale fake fields when rotating or switching offsets.

### Timerfd Retry Hardening
- The mixed-payload run `old/2026-05-03_mixed_fake_dst_trace_smp2` exposed a retry hang where the main thread waited indefinitely for a timerfd read.
- Changed the timerfd to `TFD_NONBLOCK`, added explicit draining at attempt start, and replaced the blocking read with a bounded poll/read helper.
- Added `BAD_DST_TIMER_READ_TIMEOUT_US`, default `1000000`.
- On timeout, the attempt now cleans up the current race state, releases the frozen trigger best-effort, resets the spray, and retries.

### Three-Active Pipe Rings
- Kept vuln pipes with active buffers in the ring before page reclaim.
- The helper writes `0x1000 - 1`, then two full `0x1000` buffers after the initial one-byte buffer, leaving three active pipe buffers and one free slot in the 4-entry ring.
- This preserves an active corrupted ring shape while still leaving room for the later `"PWND"` write used to locate the pipe-buffer page.

### Successful Race Path
- Run folder: `old/2026-05-03_mixed_align5_timer_timeout_trace_smp2`.
- With `BAD_DST_ALIGN_PAD=5`, mixed fake dst offsets, RT CPU1 blocker, `sched_rt_runtime_us=-1`, and bounded timerfd read, attempt 3 reached:
  - `found corrupted pipe FIONREAD index=13 size=0xc3c3c3c3`
  - `kaslr base: ffffffff81000000`
  - `vmemmap base: fffffffeffe00000`
  - `physical base address: 200000`
  - `Arb R/W setup`
- Trace confirmed the intended fake dst path:
  - `skcheck` saw `ref=1 obs=1 ops=0xffffffff836a9c40 flags=0xffff`;
  - `skgot` saw ref incremented to `2`;
  - `sknull` saw the blackhole `check()` return `NULL`;
  - `pipe_resize_ring` later allocated a ring at the same stale dst address.
- The kernel panic after this run came from the wrapper killing the sleeping exploit, which closed corrupted pipe state. It is a teardown artifact, not a failure to reach the primitive.

### Dirty Retry Issue
- A follow-up no-kill run in `old/2026-05-03_mixed_align5_no_kill_success_smp2` crashed before artifacts synced.
- Serial output showed a `NULL` dereference in `sk_dst_check+0x4c`, consistent with a stale dst whose `obsolete` field was nonzero but whose `ops` pointer was `NULL`.
- Working interpretation: retry attempts that intentionally leak vulnerable pipes can leave corrupted or partially overwritten pipe state behind. Later attempts only scanned the current attempt's vuln pipes, so corruption of an older leaked pipe could be missed and later crash during unrelated cleanup or allocator reuse.

## 2026-05-03 Retained Leaked-Pipe Scan

### Change
- Added a retained vulnerable-pipe registry for retry diagnostics:
  - failed attempts that leak vuln pipes now record their `Pipe` descriptors instead of losing track of them;
  - corruption scan checks current pipes first, then retained leaked pipes;
  - stale leaked hits are ignored if they report corrupted `FIONREAD` but no current page-pipe marker is found.
- Added `BAD_DST_MAX_LEAKED_VULN_PIPES`, capped by the static registry size `0x2000`.
- If the registry fills, the exploit pauses instead of exiting and closing potentially corrupted pipe state.
- Current code checkpoint:
  - `old/2026-05-03_retained_leaked_pipe_scan_smp2_exp_x86.c`

### Verification
- Built with `nix-shell -p glibc.static --run ./compile_x86.sh`; build passed with existing warning noise.
- Run folder: `old/2026-05-03_retained_leaked_pipe_scan_smp2`.
- QEMU/testvm setup:
  - `new_kernel/bzImage`
  - `--nokaslr --smp 2 --net tap`
  - `sched_rt_runtime_us=-1`
  - mixed fake dst offsets `64,128`
  - `BAD_DST_ALIGN_PAD=5`
  - `BAD_DST_TIMER_READ_TIMEOUT_US=1000000`
- Result:
  - attempts 2, 3, and 4 were accepted race candidates but missed pipe corruption;
  - each miss leaked and recorded 64 vuln pipes, reaching `total=192`;
  - attempt 5 found a current corrupted pipe: `source=current index=3 size=0xc3c3c3c3`;
  - the exploit reached `Arb R/W setup`;
  - wrapper synced artifacts and powered off without an orderly kill.
- Trace highlights from attempt 5:
  - `skcheck`: `dst=0xffff88801b232540 ref=1 obs=1 ops=0xffffffff836a9c40 flags=0xffff`;
  - `skgot`: refcount became `2`;
  - `sknull`: blackhole check returned `0`;
  - `pipe_resize_ring`: one vuln pipe ring was allocated at `0xffff88801b232540`;
  - trace marker ended at `pipe_corrupt_success source=current index=3`.

### SMP6 Sanity Check
- Run folder: `old/2026-05-03_retained_leaked_pipe_scan_smp6`.
- The first `--smp 6` run used the default 512 MB guest memory and hit OOM before producing a useful exploit result. The wrapper and exploit were killed by the guest OOM killer. This was caused by the six-CPU kernel plus tracing buffers and spray setup, not by a kernel exploit crash.
- Re-ran as `old/2026-05-03_retained_leaked_pipe_scan_smp6_1g` with:
  - `--memory 1G`;
  - `--smp 6`;
  - ftrace buffer reduced from `65536` KB to `16384` KB;
  - same `BAD_DST_ALIGN_PAD=5`, mixed fake dst offsets, RT CPU1 blocker, and `sched_rt_runtime_us=-1`.
- Result:
  - attempt 2 was an accepted candidate and missed pipe corruption;
  - attempt 3 was classified `too_late_far`, and autotune bracketed the timer offset from `82207` down to `74700`;
  - attempts 4 and 5 were accepted candidates and missed pipe corruption;
  - attempts 2, 4, and 5 each retained 64 leaked vuln pipes, reaching `total=192`;
  - attempt 6 found `source=current index=12 size=0xc3c3c3c3` and reached `Arb R/W setup`;
  - wrapper synced artifacts and powered off.
- Trace highlights from attempt 6:
  - `skcheck`: `dst=0xffff88801b13ee40 ref=1 obs=1 ops=0xffffffff836a9c40 flags=0xffff`;
  - `skgot`: refcount became `2`;
  - `sknull`: blackhole check returned `0`;
  - `pipe_resize_ring`: a vuln pipe ring was allocated at `0xffff88801b13ee40`;
  - trace marker ended at `pipe_corrupt_success source=current index=12`.

### Current Interpretation
- The real race plus mixed fake-dst placement is now confirmed to reach the full pipe-buffer arbitrary read/write setup on the preempt test kernel.
- It also works under a 6-vCPU guest when the VM has enough memory for tracing and allocator pressure.
- The retained-pipe scan did not need to recover an old leaked pipe in this successful run, but it removes the main retry blind spot and makes later failed candidates easier to distinguish from stale pipe corruption.
- Remaining reliability work is allocator-side: reduce the number of accepted candidates that reach fake dst but miss the pipe-buffer/page reclaim phase.

## 2026-05-03 CFS Blocker Threads

### Goal
- Test whether the real race can be held without the privileged RT wrapper settings.
- Keep the trigger thread `SCHED_IDLE`, but replace the single `SCHED_FIFO` CPU1 blocker with many normal CFS spinner threads pinned to CPU1.
- Leave `/proc/sys/kernel/sched_rt_runtime_us` at the default value during these runs.

### Change
- Added configurable CPU1 blocker threads:
  - `BAD_DST_CPU1_BLOCK_RT=1` keeps the old `SCHED_FIFO` blocker path;
  - `BAD_DST_CPU1_BLOCK_RT=0` uses normal CFS spinner threads;
  - `BAD_DST_CPU1_BLOCK_THREADS=N` controls the count, capped at `256`.
- The trigger still waits for all blocker threads to be ready before arming the timerfd race.
- Added release tuning knobs needed for retrying after CFS over-holds:
  - `BAD_DST_CPU1_RELEASE_SLEEP_US`;
  - `BAD_DST_TRIGGER_RELEASE_TIMEOUT_US`.
- Checkpoint before this experiment:
  - `old/2026-05-03_before_cfs_blocker_threads_exp_x86.c`
  - `old/2026-05-03_before_cfs_blocker_threads_RUNNING_LOG.md`

### Verification
- Built with `nix-shell -p glibc.static --run ./compile_x86.sh`; build passed with existing warning noise.
- Run folder: `old/2026-05-03_cfs_blockers_smp2`.
  - Settings: `BAD_DST_CPU1_BLOCK_RT=0`, `BAD_DST_CPU1_BLOCK_THREADS=128`.
  - Result: attempt 1 was stack-classified as `too_early`, then the exploit failed to release the frozen trigger with the old short release timeout.
  - Trace showed the 128 CFS blockers could over-hold the idle trigger for a very long time: `cnxret` around `42.917s` and `cnxassign` around `161.128s`.
- Run folder: `old/2026-05-03_cfs_blockers_release_tuned_smp2`.
  - Settings: `BAD_DST_CPU1_BLOCK_RT=0`, `BAD_DST_CPU1_BLOCK_THREADS=128`, `BAD_DST_CPU1_RELEASE_SLEEP_US=50000`, `BAD_DST_TRIGGER_RELEASE_TIMEOUT_US=5000000`.
  - Result: several accepted target candidates were reached, but the wrapper stopped after repeated `FAIL: could not corrupt pipe` misses.
  - Best observed candidate held roughly `586 ms` past the stack oracle, but most holds were only a few milliseconds; this is usually not enough for the current multi-second post-race path before `MSG_PROBE`.
- Run folder: `old/2026-05-03_cfs_blockers_256_smp2`.
  - Settings: `BAD_DST_CPU1_BLOCK_RT=0`, `BAD_DST_CPU1_BLOCK_THREADS=256`, same release tuning, default `sched_rt_runtime_us=950000`.
  - Result: success on attempt 3:
    - `found corrupted pipe FIONREAD source=current index=4 size=0xc3c3c3c3`;
    - `kaslr base: ffffffff81000000`;
    - `vmemmap base: fffffffeffe00000`;
    - `physical base address: 200000`;
    - `Arb R/W setup`.
  - Trace highlights:
    - `skcheck` saw fake dst at `0xffff8880136ead80` with `ref=1 obs=1 ops=0xffffffff836a9c40 flags=0xffff`;
    - `skgot` incremented the fake dst refcount to `2`;
    - `sknull` returned `NULL` through the blackhole `check()` path;
    - `pipe_resize_ring` allocated a ring at `0xffff8880136ead80`;
    - trace marker ended at `pipe_corrupt_success source=current index=4`.

### Current Interpretation
- The easy CFS-blocker approach is viable in the SMP2 test VM: 256 normal CPU1 spinner threads held a `SCHED_IDLE` trigger long enough to reach the pipe-buffer arbitrary read/write setup.
- This run did not require `SCHED_FIFO` for the blocker thread and did not require setting `sched_rt_runtime_us=-1`.
- The test still used the root/debug wrapper for tracing, sysctl setup, IRQ pinning, and guest control. The result only proves the race-hold strategy can work without the RT scheduling primitive; it is not yet a fully unprivileged final exploit path.
- 128 blockers are marginal: they can hold the idle trigger, but retry/release behavior and hold duration are not reliable enough for the current exploit timing.

## 2026-05-03 Critical-Path Reduction

### Goal
- Reduce the amount of work between a real race candidate and `MSG_PROBE`, because CFS blocker holds are often shorter than the old post-race path.
- Preserve the working allocator order from `old/2026-05-03_cfs_blockers_256_smp2`.

### Code Changes
- Added timing/preparation knobs:
  - `BAD_DST_FAST_CRITICAL`;
  - `BAD_DST_PRE_RACE_EXPIRE_US`;
  - `BAD_DST_FNHE_EXPIRE_TOTAL_US`;
  - `BAD_DST_PREPARE_PAGE_PIPES_BEFORE_RACE`;
  - `BAD_DST_PREPARE_PIPES_BEFORE_RACE`;
  - `BAD_DST_EXPIRE_WITH_LOOKUP_ONLY`;
  - `BAD_DST_SPRAY_BLOCK_US`.
- Split pipe preparation into page-pipe and vuln-pipe phases. This allows pre-opening the 3072 page pipes before the race while keeping the 64 vulnerable pipe rings out of the allocator until after a candidate is accepted.
- Added `critical elapsed before MSG_PROBE` logging and trace markers.
- Set `BAD_DST_FAST_CRITICAL` default back to `0` so plain runs keep the older known-good behavior unless the timing experiment is explicitly enabled.
- Checkpoint before this experiment:
  - `old/2026-05-03_before_fast_critical_path_exp_x86.c`
  - `old/2026-05-03_before_fast_critical_path_RUNNING_LOG.md`
- Checkpoint before partial pipe prep:
  - `old/2026-05-03_before_partial_pipe_prep_exp_x86.c`
  - `old/2026-05-03_before_partial_pipe_prep_RUNNING_LOG.md`

### Failed Fast Variants
- `old/2026-05-03_fast_critical_cfs128_smp2`:
  - full pre-expiry and full pipe pre-open;
  - no success;
  - `critical elapsed before MSG_PROBE` improved to roughly `1.36-1.45s`, but `sk_dst_check` usually saw `NULL` or stale real dst memory rather than the fake dst.
- `old/2026-05-03_fast_critical_cfs128_spray100ms_smp2`:
  - same as above, with `BAD_DST_SPRAY_BLOCK_US=100000`;
  - crashed in `__skb_try_recv_from_queue` during UNIX dgram cleanup;
  - conclusion: 100 ms is too aggressive for the sendmsg spray guard.
- `old/2026-05-03_fast_critical_cfs256_smp2`:
  - full pre-expiry and full pipe pre-open with 256 CFS blockers;
  - no success;
  - critical time was roughly `1.33-1.39s`, but pre-opening vuln pipes perturbed allocator state and fake dst reclaim did not land.
- `old/2026-05-03_preexpire_only_cfs256_smp2`:
  - pre-expiry without pre-opened pipes;
  - no success;
  - critical time was roughly `1.44-1.54s`, but expiring the FNHE before the race was too early. After the race, `sk_dst_check` saw `NULL` or freed/stale dst objects, not the cmsg fake dst.
- `old/2026-05-03_page_prep_fast_cfs256_smp2`:
  - full pre-expiry plus page-pipe-only pre-open;
  - no success;
  - critical time was roughly `1.34-1.42s`, and page-only prep saved about `110-150ms`, but the too-early FNHE expiry still prevented fake dst reclaim.

### Working Fast Variant
- Run folder: `old/2026-05-03_partial_expire_page_prep_cfs256_smp2`.
- Settings:
  - `BAD_DST_CPU1_BLOCK_RT=0`;
  - `BAD_DST_CPU1_BLOCK_THREADS=256`;
  - default `sched_rt_runtime_us=950000`;
  - `BAD_DST_PRE_RACE_EXPIRE_US=700000`;
  - `BAD_DST_FNHE_EXPIRE_TOTAL_US=1300000`;
  - `BAD_DST_PREPARE_PAGE_PIPES_BEFORE_RACE=1`;
  - `BAD_DST_PREPARE_PIPES_BEFORE_RACE=0`;
  - `BAD_DST_EXPIRE_WITH_LOOKUP_ONLY=0`;
  - `BAD_DST_POST_RACE_SLEEP_US=0`;
  - `BAD_DST_POST_RACE_EXPIRE_US=0`;
  - default `BAD_DST_SPRAY_BLOCK_US=1000000`.
- Result:
  - success on attempt 10;
  - `found corrupted pipe FIONREAD source=current index=1 size=0xc3c3c3c3`;
  - `kaslr base: ffffffff81000000`;
  - reached `Arb R/W setup`;
  - `found_success=1`, `deadline_remaining=173`.
- Trace highlights:
  - candidate at `72.438131s`;
  - `run_exploit` at `73.036523s`, so the remaining FNHE wait was about `598ms`;
  - `critical_before_msg_probe` at `74.426983s`, `elapsed_us=1988731`;
  - `skcheck`: `dst=0xffff888015676d80 ref=1 obs=1 ops=0xffffffff836a9c40 flags=0xffff`;
  - `skgot`: refcount became `2`;
  - `sknull`: blackhole check returned `0`;
  - `pipe_corrupt_success source=current index=1`.

### Spray Guard Trim
- Run folder: `old/2026-05-03_partial_expire_page_prep_spray750ms_cfs256_smp2`.
- Same partial-expiry/page-prep settings, plus `BAD_DST_SPRAY_BLOCK_US=750000`.
- Result:
  - no success before the wrapper stopped after repeated pipe-corruption failures;
  - `critical elapsed before MSG_PROBE` improved to roughly `1.67-1.75s`;
  - `sk_dst_check` still saw `NULL` or stale real dst memory in the sampled candidates;
  - one `dst_release underflow` warning occurred.
- Current conclusion: keep the 1 second spray guard for reliability. The 750 ms guard is faster but did not preserve fake-dst reclaim in this run.

### Current Interpretation
- The valid timing optimization is partial FNHE expiry, not full pre-expiry. The FNHE reference must still be alive when the race decrements the socket dst reference; otherwise the rtable can be freed before the controlled cmsg reclaim.
- Page-pipe-only pre-open is useful and did not break the successful partial-expiry run. Full pipe pre-open is harmful because it puts the vuln pipe rings into the allocator too early.
- The reliable SMP2 CFS256 critical path is now about `1.9-2.0s` from candidate to `MSG_PROBE`, down from about `4.5s` in `old/2026-05-03_cfs_blockers_256_smp2`.

## 2026-05-03 Root payload implementation

### Changes made
- Added a root stage after `Arb R/W setup`.
  - Sets a unique task comm marker with `prctl(PR_SET_NAME, "bdstroot")`.
  - Discovers `task_struct` layout from `init_task` by finding `swapper/` and the task-list linkage.
  - Supports manual task layout overrides with `BAD_DST_TASKS_OFFSET`, `BAD_DST_REAL_CRED_OFFSET`, `BAD_DST_CRED_OFFSET`, and `BAD_DST_COMM_OFFSET`.
  - Walks the task list to find the current process and overwrites `cred` and `real_cred` UID/GID fields to zero.
  - Also overwrites `securebits` and, by default, grants all capability sets. This can be disabled with `BAD_DST_SET_CAPS=0`.
- Added SELinux hooks for Android-style targets:
  - `BAD_DST_DISABLE_SELINUX=0` skips the step.
  - `BAD_DST_SELINUX_WRITE_ADDR=<addr>` writes an exact address.
  - Compile-time `SELINUX_ENFORCING_OFFSET` and `SELINUX_STATE_OFFSET` are supported.
  - Compile-time `BAD_DST_NO_SELINUX` compiles the step out.
- Added root-stage runtime gates:
  - `BAD_DST_GET_ROOT=0` stops after arbitrary R/W setup.
  - `BAD_DST_RUN_ROOT_PAYLOAD=0` verifies credentials without launching the listening shell payload.
- Fixed test-kernel address translation for the pipe primitive:
  - x86 now defaults to `VMEMMAP_START=0xffffea0000000000`.
  - x86 now defaults to `LINEAR_BASE=0xffff888000000000`.
  - non-x86 keeps the previous Android-style defaults.
  - Added `BAD_DST_VMEMMAP_BASE` and `BAD_DST_LINEAR_BASE` overrides.
- Replaced the old "first non-A word" pipe-page scan with a marker-based scan:
  - Searches for the `PWND` marker written through the corrupted pipe.
  - Copies the saved `struct pipe_buffer` from the slot immediately before that marker.
  - Validates the leaked page pointer, ops pointer, KASLR candidate, offset, and length before accepting the primitive.

### Verification
- Normal x86 build passed:
  - `nix-shell -p glibc.static --run ./compile_x86.sh`
- Temporary debug-harness build passed:
  - `nix-shell -p glibc.static --run 'gcc -DDEBUG exp_x86.c -o bad_dst_cache_debug_root $(../../common/payload-flags --static --listening-shell --port 1340)'`
- Real race SMP2 test with root enabled and shell disabled:
  - Folder: `old/2026-05-03_root_cred_x86_addrfix_smp2`.
  - Used the same partial-expiry/page-pipe-prep settings as the prior best SMP2 run.
  - Result: repeated race candidates reached the fake-dst/free/reclaim path, but none reached a clean pipe-buffer primitive before I stopped the VM.
- Debug-67 SMP1 root tests:
  - Folder: `old/2026-05-03_root_cred_debug67_x86_addrfix_smp1`.
  - With the old scan, it reached `Arb R/W setup`, set comm to `bdstroot`, then crashed in `pipe_read` with `ops=0x4444444444444444`.
  - That confirms the earlier `size=0xc3c3c3c3` milestones were not a valid arbitrary R/W primitive; the scanner was copying marker/poison bytes as a fake `pipe_buffer`.
  - With the marker-based scan, the exploit did not accept that bogus pipe-buffer state in the tested run. A later miss faulted in `sk_dst_check` before a clean root attempt.

### Current issues
- The root credential overwrite code is implemented but not verified end-to-end because the pipe-buffer arbitrary R/W primitive has not produced a clean, validated overlap in these tests.
- The prior `Arb R/W setup` milestone should be treated as suspect when FIONREAD is `0xc3c3c3c3`; that appears to be SLUB poison or otherwise non-pipe-page state, not the intended pipe-page reclaim.
- Next practical step is to make the pipe-buffer reclaim oracle stricter and keep tuning the page reclaim until the marker scan accepts a real `pipe_buffer` leak. Only then can the credential overwrite be considered tested.

### Checkpoints
- `old/2026-05-03_before_root_payload_exp_x86.c`
- `old/2026-05-03_before_root_payload_RUNNING_LOG.md`
- `old/2026-05-03_root_payload_marker_scan_exp_x86.c`
- `old/2026-05-03_root_payload_marker_scan_RUNNING_LOG.md`

## 2026-05-03 Real pipe-buffer overlap fix

### Checkpoint
- Backed up the pre-change exploit and log:
  - `old/2026-05-03_before_real_pipe_overlap_fix_exp_x86.c`
  - `old/2026-05-03_before_real_pipe_overlap_fix_RUNNING_LOG.md`
- Saved the post-fix milestone:
  - `old/2026-05-03_real_pipe_probe_fix_exp_x86.c`
  - `old/2026-05-03_real_pipe_probe_fix_RUNNING_LOG.md`

### Issue found
- The marker-based scan was conceptually wrong.
  - Writing `"PWND"` to the corrupted pipe does not place those bytes in the reclaimed pipe-buffer page.
  - After the original pipe-buffer slots have been overwritten with `A`s, `pipe_write()` cannot merge into the old slots, so it creates the next `struct pipe_buffer` slot in the corrupted ring.
  - The data bytes go to that new slot's backing page, not to the ring page.
- This explains the earlier `ops=0x4444444444444444` crash.
  - The old first-non-`A` scan selected the newly-created valid slot, usually slot 3.
  - `read()` still consumed from tail slot 0.
  - The primitive setup had filled slot 0 with `D`s, so pipe read crashed on the bogus slot-0 ops pointer.

### Changes made
- Replaced the `"PWND"` data marker scan with a pipe-buffer probe scan.
  - The probe write still writes 4 bytes, but the scan now looks for the valid `struct pipe_buffer` created by that write.
  - The candidate must have a plausible `struct page *`, `anon_pipe_buf_ops`, `offset == 0`, `len == 4`, and `PIPE_BUF_FLAG_CAN_MERGE`.
  - The scan infers the beginning of the corrupted ring with:
    - `pipe_base = probe_offset - active_slots_before_probe * sizeof(struct pipe_buffer_t)`.
  - With the default three active slots, this subtracts `3 * 40` bytes so the primitive programs slot 0, slot 1, slot 2, and slot 3, instead of starting at the probe slot.
  - Added a default-on check that the prior active slots still look like reclaimed `A` data. It can be disabled with `BAD_DST_REQUIRE_RECLAIMED_PREV_PIPE_SLOTS=0`.
- Fixed x86 test-kernel physical base.
  - `new_kernel/vmlinux` loads `_stext` at physical `0x1000000`, not `0x200000`.
  - x86 now defaults `PHYS_BASE` to `0x1000000`.
  - Added runtime override `BAD_DST_PHYS_BASE`.

### Verification
- Normal build passed:
  - `nix-shell -p glibc.static --run ./compile_x86.sh`
- Temporary debug-67 build passed:
  - `nix-shell -p glibc.static --run 'gcc -DDEBUG exp_x86.c -o bad_dst_cache_debug_overlap $(../../common/payload-flags --static --listening-shell --port 1340)'`
- Debug-67 SMP1 before the physical-base fix:
  - Folder: `old/2026-05-03_pipe_probe_debug67_smp1`.
  - Attempt 17 accepted a real pipe-buffer probe:
    - `pipe probe leak accepted: page_index=155 probe=0x2b8 pipe_base=0x240 active_before=3`.
    - `ops=0xffffffff827bf740`.
  - Reached `Arb R/W setup` without the previous `D`-slot crash.
  - Root failed because static kernel reads used the wrong physical base.
- Debug-67 SMP1 after the physical-base fix:
  - Folder: `old/2026-05-03_pipe_probe_physfix_debug67_smp1`.
  - Attempt 8 accepted a real pipe-buffer probe:
    - `pipe probe leak accepted: page_index=151 probe=0x5b8 pipe_base=0x540 active_before=3`.
    - `ops=0xffffffff827bf740`.
  - Reached `Arb R/W setup`.
  - Discovered task layout:
    - `tasks=0x450 real_cred=0x708 cred=0x710 comm=0x720`.
  - Found current task and overwrote creds.
  - Confirmed root:
    - `now uid/gid/euid/egid: 0/0/0/0`.
- Non-debug SMP2 bounded race test:
  - Folder: `old/2026-05-03_pipe_probe_realrace_smp2`.
  - Ran `120` real race attempts.
  - Got three stack-target race candidates, but all three missed pipe corruption.
  - No pipe probe was reached in that bounded run.

### Current interpretation
- The pipe-buffer overlap logic is now real and usable on the debug-67 heap path.
- The previous `FIONREAD=0xc3c3c3c3` value was not inherently false; with three active slots it is exactly `3 * 0x41414141` modulo 32 bits. The false part was treating the newly-created probe slot as the first active slot.
- The remaining non-debug issue in the SMP2 test is race/candidate frequency and pipe reclaim probability, not the pipe-buffer primitive itself.

## 2026-05-03 Unprivileged race-path work

### Checkpoints
- Backed up the exploit and log before this round:
  - `old/2026-05-03_before_unpriv_timer_sweep_exp_x86.c`
  - `old/2026-05-03_before_unpriv_timer_sweep_RUNNING_LOG.md`
  - `old/2026-05-03_before_unpriv_futex_pulse_exp_x86.c`
  - `old/2026-05-03_before_unpriv_futex_pulse_RUNNING_LOG.md`

### Changes made
- Added a no-root timer sweep:
  - `BAD_DST_TIMER_SWEEP_START_NS`
  - `BAD_DST_TIMER_SWEEP_STEP_NS`
  - `BAD_DST_TIMER_SWEEP_COUNT`
- Added a no-root done oracle:
  - `BAD_DST_DONE_ORACLE=1` checks whether the trigger returned immediately after the timer and CPU migration.
  - This filters clear late misses without needing `/proc/<tid>/stack`.
- Increased CFS blocker capacity to `1024` threads and added small blocker stacks via `BAD_DST_CPU1_BLOCK_STACK`.
- Added optional futex-backed blocker release:
  - `BAD_DST_CPU1_BLOCK_FUTEX=1` makes blocker threads sleep on a futex while released, then wake and spin immediately when re-blocked.
  - This avoids the coarse `BAD_DST_CPU1_RELEASE_SLEEP_US` release gap when trying to pulse the trigger.
- Added optional CPU1 trigger pulsing:
  - `BAD_DST_RACE_PULSE_NS` for fixed pulses.
  - `BAD_DST_RACE_PULSE_SWEEP_COUNT`, `BAD_DST_RACE_PULSE_START_NS`, and `BAD_DST_RACE_PULSE_STEP_NS` for sweep testing.
  - The pulse briefly releases CPU1 blockers after the timer freeze, then wakes them again to re-freeze the SCHED_IDLE trigger.
- Build status:
  - `nix-shell -p glibc.static --run ./compile_x86.sh` passed after these edits.

### Unprivileged SMP2 runs
- Folder: `old/2026-05-03_unpriv_sweep_smp2`.
  - Exploit executed via `drop_exec` as UID 1000.
  - Settings: CFS blockers, no stack oracle, no lock oracle, timer sweep, 1024 blockers.
  - Result:
    - `6` failed pipe candidates before the wrapper hit a stuck trigger release.
    - `3` done-oracle late misses.
    - `0` pipe probes and `0` arbitrary R/W setups.
    - Critical window before `MSG_PROBE` was still about `1.9-2.0s`.
- Folder: `old/2026-05-03_unpriv_futex_pulse_smp2`.
  - Exploit executed via `drop_exec` as UID 1000.
  - Settings: futex blockers, pulse sweep, all pipe sets prepared before the race, `BAD_DST_SPRAY_BLOCK_US=500000`.
  - Result:
    - `28` failed pipe candidates before wrapper deadline.
    - `25` done-oracle late misses.
    - `0` pipe probes and `0` arbitrary R/W setups.
    - Critical window before `MSG_PROBE` was usually `1.37-1.52s`, so pipe pre-prep plus shorter spray guard helped.
    - No `dst_release underflow` warnings.

### Trace evidence
- Folder: `old/2026-05-03_unpriv_futex_pulse_trace_smp2`.
  - Wrapper mounted ftrace/kprobes as root, then ran the exploit through `drop_exec`.
  - This preserves unprivileged exploit execution while allowing root-only tracing.
- Initial trace without markers:
  - Saved as:
    - `old/2026-05-03_unpriv_futex_pulse_trace_smp2_nomarkers_exploit.log`
    - `old/2026-05-03_unpriv_futex_pulse_trace_smp2_nomarkers_trace.txt`
  - Counts:
    - `16` `cnxret` events.
    - `16` `cnxassign` events.
    - `0` fake-dst ops hits.
    - `0` metadata frees.
- Key race-path hit observed in the trace:
  - For socket `0xffff88801a0b1f80`, `sock_setsockopt+0xf00` (`cnxret`, after `negative_advice()` returned) occurred at `39.079816`.
  - The main thread then executed `sk_dst_check()` on the same socket at `40.526339`.
  - `sock_setsockopt+0xf09` (`cnxassign`, assignment of `sk_dst_cache`) did not occur until `47.319961`.
  - This means the dropped UID 1000 process did enter and hold the intended interval between `negative_advice()` returning and `sk_dst_cache` being assigned NULL.
- The trace still showed the real IPv4 dst ops (`0xffffffff836b8a40`) instead of the fake blackhole ops.
  - That is expected for these unprivileged runs because the dropped process could not set `/proc/sys/net/ipv4/route/mtu_expires`.
  - With the default long FNHE lifetime, the FNHE reference remains alive, so `sk_dst_check()` can still take a valid reference to the real route instead of observing freed/reclaimed memory.

### Current interpretation
- The unprivileged race path is now demonstrably hittable using SCHED_IDLE trigger + CFS blockers + futex pulse stepping.
- The missing pipe overlap in these runs is not evidence that the race interval was never reached; at least one traced attempt reached it and held it for several seconds.
- The immediate remaining work for full unprivileged exploitation is to handle the FNHE/MTU expiry setup without relying on a root sysctl write, then retune the fake-dst reclaim with the shorter critical path.

## 2026-05-04 Unprivileged run with privileged `mtu_expires=1` stub

### Checkpoints
- Backed up the log before recording this verification:
  - `old/2026-05-04_before_unpriv_mtu1_verification_RUNNING_LOG.md`
- Verification folder:
  - `old/2026-05-04_unpriv_mtu1_futex_pulse_smp2/`

### Setup
- Rebuilt the exploit with:
  - `nix-shell -p glibc.static --run ./compile_x86.sh`
- Created a root wrapper in the checkpoint share directory that writes:
  - `echo 1 > /proc/sys/net/ipv4/route/mtu_expires`
- The same wrapper then runs the exploit through `drop_exec`, so the exploit body executes as UID 1000 after the sysctl is set.
- Test VM command used `new_kernel/bzImage`, `--nokaslr`, `--smp 2`, `--memory 1G`, tap networking, and the checkpoint share directory.

### Result
- The privileged stub worked:
  - Synced guest file `mtu_expires_value` contains `1`.
  - `mtu_expires_set.err` is empty.
- The exploit still ran unprivileged after the stub:
  - The guest log contains the expected permission denial from the exploit's own post-drop attempt to write `/proc/sys/net/ipv4/route/mtu_expires`.
- The bounded run hit the wrapper deadline:
  - `deadline_remaining=0`
  - `found_probe=0`
  - `found_setup=0`
- Counts from the synced exploit log:
  - `45` race candidates.
  - `19` done-oracle late misses (`trigger already returned`).
  - `22` failed pipe candidates (`FAIL: could not corrupt pipe`).
  - `22` candidates logged `critical elapsed before MSG_PROBE`.
  - `0` accepted pipe probes.
  - `0` arbitrary R/W setups.
  - `0` `dst_release underflow` warnings in the host or synced logs.
- The host console log also showed long RCU stall warnings while the trigger thread was frozen in kernel context. The run eventually continued and powered off through the wrapper deadline.

### Current interpretation
- This verifies the wrapper behavior requested: `mtu_expires` can be set as root before dropping privileges, and the exploit then runs as an unprivileged process.
- It does not yet verify end-to-end unprivileged success on this configuration. With `mtu_expires=1`, this parameter set still produced race candidates but no confirmed fake-dst hit, pipe-buffer overlap, or arbitrary R/W setup.
- The next useful diagnostic is a root-only tracing wrapper that still drops privileges before running the exploit, with `mtu_expires=1` enabled, to distinguish race timing from FNHE expiry/reclaim failure.

## 2026-05-04 Root payload verification with privileged `mtu_expires=1` stub

### Checkpoints
- Backed up the current exploit and log before this verification:
  - `old/2026-05-04_before_unpriv_mtu1_root_payload_exp_x86.c`
  - `old/2026-05-04_before_unpriv_mtu1_root_payload_RUNNING_LOG.md`
- Real-race verification folder:
  - `old/2026-05-04_unpriv_mtu1_root_payload_smp2/`
- Debug-67 control folder:
  - `old/2026-05-04_debug67_drop_mtu1_root_payload_smp1/`

### Real-race SMP2 run
- Built the normal x86 exploit with:
  - `nix-shell -p glibc.static --run ./compile_x86.sh`
- Root wrapper behavior:
  - Wrote `1` to `/proc/sys/net/ipv4/route/mtu_expires`.
  - Verified the synced `mtu_expires_value` file contains `1`.
  - Ran the exploit through `drop_exec`, so the exploit process executed as UID 1000.
  - The guest log contains the expected post-drop permission denial from the exploit's own sysctl attempt.
- Root payload was enabled:
  - `BAD_DST_GET_ROOT=1`
  - `BAD_DST_RUN_ROOT_PAYLOAD=1`
  - A small verifier binary was included to connect to the listening shell and write the shell's `id`/`/proc/self/status` output back to the share if the payload started.
- Result:
  - The root payload did not start on the real-race path.
  - `found_probe=0`, `found_setup=0`, `found_root=0`, `found_listen=0`, `checker_started=0`.
  - The run reached attempt 80 before failing in `F_SETPIPE_SZ` with `errno=1` after many leaked failed pipe sets.
  - Counts:
    - `51` race candidates.
    - `29` timer/done-oracle late misses.
    - `50` pipe corruption failures.
    - `0` accepted pipe probes.
    - `0` arbitrary R/W setups.
    - `1` `dst_release underflow` warning, plus a later `dst_release: ... refcnt:-1` line.
- Interpretation:
  - Setting `mtu_expires=1` before dropping privileges is enough to get fake-dst/refcount symptoms on this unprivileged run.
  - It still does not make the real-race path reach the validated pipe-buffer overlap needed for arbitrary R/W and the root payload.
  - The immediate blocker remains pipe-page reclaim/reuse after the unaligned free, not the root payload itself.

### Debug-67 dropped-UID control
- Built a temporary debug harness without editing source:
  - `nix-shell -p glibc.static --run 'gcc -DDEBUG exp_x86.c -o old/2026-05-04_debug67_drop_mtu1_root_payload_smp1/share/bad_dst_cache $(../../common/payload-flags --static --listening-shell --port 1340)'`
- Ran it through the same root-stub/drop pattern:
  - Root wrapper set `mtu_expires=1`.
  - `drop_exec` ran the debug exploit as UID 1000.
  - Guest log again shows the expected post-drop sysctl permission denial.
- Result:
  - The debug harness reached a validated pipe-buffer overlap:
    - `pipe probe leak accepted: page_index=157 probe=0x8b8 pipe_base=0x840 active_before=3 ... ops=0xffffffff827bf740`.
  - Reached `Arb R/W setup`.
  - Discovered the task layout and found the marked current task.
  - Overwrote creds and logged:
    - `now uid/gid/euid/egid: 0/0/0/0`.
  - The root payload verifier connected to the spawned shell and wrote:
    - `root_payload_marker` containing `ROOT_PAYLOAD_MARKER`.
    - `root_payload_shell_output` beginning with `uid=0 gid=0`.
    - `/proc/self/status` in that output shows `Uid: 0 0 0 0`, `Gid: 0 0 0 0`, and full capability sets.
- Issue observed:
  - After the verifier shell exited, the kernel panicked in `free_pipe_info -> kfree`.
  - This is consistent with corrupted/leaked pipe state being closed after success. It does not invalidate the credential overwrite or payload-shell confirmation, but it means the post-success cleanup path still needs to avoid closing corrupted pipe resources.

### Current interpretation
- The privileged `mtu_expires=1` stub plus dropped-UID execution is verified.
- The root payload path is verified once the pipe-buffer primitive is reached, even when the exploit was started unprivileged through `drop_exec`.
- The real unprivileged race path still does not reliably reach the pipe-buffer primitive. The next work should focus on stabilizing the unaligned-free-to-pipe-buffer reclaim, and on preserving/leaking corrupted pipe state after success to avoid the debug-control cleanup panic.

## 2026-05-04 Status update: non-root race path with `mtu_expires=1`

### Checkpoint
- Backed up the log before this status update:
  - `old/2026-05-04_before_status_and_history_update_RUNNING_LOG.md`

### Process status
- Checked for stale VM/exploit processes after the interrupted run.
- No `testvm`, `qemu-system-x86_64`, or `bad_dst_cache` process was still running.

### Trace-assisted dropped-UID success
- Folder:
  - `old/2026-05-04_unpriv_mtu1_cfsblock_mix_skcheck_trace_smp2/`
- Setup:
  - Root wrapper set `/proc/sys/net/ipv4/route/mtu_expires=1`.
  - Exploit body ran through `drop_exec` as UID 1000.
  - Root-only ftrace/kprobe instrumentation was enabled for diagnosis.
  - CFS CPU1 blocker, mixed fake dst offsets `64,128`, `BAD_DST_VULN_PIPES=256`, pre-opened exploit pipes.
- Result:
  - Reached `Arb R/W setup` on real race attempt 4.
  - First 3 candidates reached the race but missed pipe corruption.
  - Attempt 4 produced:
    - `found corrupted pipe FIONREAD source=current index=15 size=0xc3c3c3c3`
    - `pipe probe leak accepted: page_index=134 probe=0x7f8 pipe_base=0x780 active_before=3 ... ops=0xffffffff827bf740`
    - `kaslr base: ffffffff81000000`
    - `Arb R/W setup`
  - Trace confirmed the intended fake-dst path:
    - `cnxret` for socket `0xffff88801bb70d80` saw old route `0xffff88801b7d8780`.
    - Later `sk_dst_check` on the same socket saw `dst=0xffff88801b7d8780 ref=1 obs=1 ops=0xffffffff836a9c40 flags=0xffff`.
    - `skgot` incremented that fake dst refcount to `2`.
    - `sknull` returned NULL through the fake blackhole ops.
- Interpretation:
  - This proves the real dropped-UID race can reach the fake dst and the pipe-buffer primitive when `mtu_expires=1` is set by the wrapper.
  - It is not yet a final no-root exploit result because the proof used root-only kprobes. The exploit process itself was unprivileged, but tracing may have perturbed timing/allocator behavior.

### No-trace exact rerun
- Folder:
  - `old/2026-05-04_unpriv_mtu1_cfsblock_mix_notrace_exact_smp2/`
- Setup:
  - Same exploit-side timing/config as the trace-assisted success.
  - No kprobes and no trace markers.
  - Root wrapper only set `mtu_expires=1`, then dropped to UID 1000.
- Result:
  - Ran 80 real-race attempts.
  - Counts:
    - `14` lock-held race candidates.
    - `66` timer/done-oracle late misses.
    - `14` `FAIL: could not corrupt pipe`.
    - `0` corrupted pipe detections.
    - `0` accepted pipe probes.
    - `0` arbitrary R/W setups.
  - Console showed one `dst_release underflow` in `ipv4_negative_advice`, then the run ended at:
    - `FAIL: reached BAD_DST_MAX_ATTEMPTS without winning real race`
    - `wrapper deadline_remaining=316`
- Interpretation:
  - The no-trace path still hits plausible candidates, but did not reproduce the trace-assisted fake-dst/pipe-buffer overlap in this bounded run.
  - The kprobes are likely changing timing enough to improve the fake-dst hit or downstream reclaim probability, or the success probability is still low enough that the trace run was lucky.

### No-trace CPU0-resize/leak variant
- Folder:
  - `old/2026-05-04_unpriv_mtu1_notrace_cpu0resize_leak_smp2/`
- Setup:
  - No kprobes.
  - Root wrapper set `mtu_expires=1`, then dropped to UID 1000.
  - Added allocator-pressure variants:
    - `BAD_DST_VULN_PIPE_RESIZE_PERCPU=0`
    - `BAD_DST_LEAK_VULN_PIPES_ON_CLEAN_FAIL=1`
    - `BAD_DST_MAX_LEAKED_VULN_PIPES=8192`
- Result:
  - Reached attempt 28 before stopping at `F_SETPIPE_SZ`.
  - Counts:
    - `13` lock-held race candidates.
    - `15` timer/done-oracle late misses.
    - `12` pipe corruption failures.
    - `0` corrupted pipe detections.
    - `0` accepted pipe probes.
    - `0` arbitrary R/W setups.
  - Leaked failed vuln pipe sets up to `3072` tracked pipes, then hit:
    - `SYSCHK(fcntl(pipe->write_fd, F_SETPIPE_SZ, size)) = -1`
    - `errno: 1`
  - Console also showed `dst_release underflow`/`refcnt:-1` warnings.
- Interpretation:
  - Leaking failed vuln pipes can preserve allocator pressure, but it quickly trips unprivileged pipe page accounting when the exploit keeps resizing pipes upward.
  - This variant is not a clean route to reliability unless the pipe accounting issue is avoided or the number/size of retained pipes is reduced.

### Root-payload history check
- Searched the `old/2026-05-04_unpriv_mtu1*` and root-payload archives for:
  - `Arb R/W setup`
  - `now uid/gid/euid/egid: 0/0/0/0`
  - `ROOT_PAYLOAD_MARKER`
  - `root_payload_shell_output`
- Confirmed positive root-payload run:
  - Folder: `old/2026-05-04_debug67_drop_mtu1_root_payload_smp1/`
  - This was the debug-67 control path, not the real race path.
  - Root wrapper set `mtu_expires=1`, then the debug exploit ran through `drop_exec`.
  - It reached:
    - `pipe probe leak accepted: page_index=157 probe=0x8b8 pipe_base=0x840 ...`
    - `Arb R/W setup`
    - `now uid/gid/euid/egid: 0/0/0/0`
  - Root shell verifier wrote:
    - `root_payload_marker` containing `ROOT_PAYLOAD_MARKER`
    - `root_payload_shell_output` beginning with `uid=0 gid=0`
    - `/proc/self/status` with `Uid: 0 0 0 0`, `Gid: 0 0 0 0`, and full capability sets.
- Confirmed negative real-race root-payload run:
  - Folder: `old/2026-05-04_unpriv_mtu1_root_payload_smp2/`
  - `mtu_expires_value=1`.
  - Payload flags were enabled:
    - `BAD_DST_GET_ROOT=1`
    - `BAD_DST_RUN_ROOT_PAYLOAD=1`
  - Synced result files:
    - `found_probe=0`
    - `found_setup=0`
    - `found_root=0`
    - `found_listen=0`
    - `checker_started=0`
  - The run hit many race candidates but never reached the pipe-buffer primitive.

### Current status
- Real dropped-UID race with `mtu_expires=1` is proven reachable through trace-assisted diagnostics.
- No-trace real-race execution is not yet reliable enough; the bounded no-trace runs did not reach arbitrary R/W.
- Root payload is verified once the pipe-buffer primitive is reached, but only on the debug-67 control so far.
- No archived run currently shows a real-race, no-kprobe, dropped-UID root shell.
- Immediate technical blocker remains reliability of fake-dst reclaim and/or unaligned-free-to-pipe-buffer reclaim without root-only tracing perturbing the timing.

## 2026-05-04 non-root timing perturbation work

### Checkpoints
- Saved pre-edit checkpoints:
  - `old/2026-05-04_before_cpu0_noise_exp_x86.c`
  - `old/2026-05-04_before_cpu0_noise_RUNNING_LOG.md`

### Code changes
- Added an optional userspace-only CPU0 noise mechanism to `exp_x86.c`.
- New environment controls:
  - `BAD_DST_CPU0_NOISE_THREADS`
  - `BAD_DST_CPU0_NOISE_AFTER_TIMER_ARM`
  - `BAD_DST_CPU0_NOISE_DURATION_NS`
  - `BAD_DST_CPU0_NOISE_SPIN_NS`
  - `BAD_DST_CPU0_NOISE_SLEEP_NS`
  - `BAD_DST_CPU0_NOISE_NICE`
- The noise threads pin to CPU0, wait on a futex epoch, and can be woken immediately after `timerfd_settime()` in the trigger thread. This is meant to reproduce the timing perturbation from the kprobe path without root-only tracing.
- Rebuilt with `nix-shell -p glibc.static --run ./compile_x86.sh`; build completed with existing warnings only.

### Lock oracle correction
- Important correction: with `BAD_DST_LOCK_ORACLE=0`, the current `race candidate: lock held with stack=unknown` line is misleading.
- The lock oracle state defaults to `LOCK_ORACLE_BLOCKED`, so disabled-oracle runs can label any still-running trigger as a candidate.
- Runs with `BAD_DST_LOCK_ORACLE=1` are the meaningful non-root confirmation that another process blocks in `getsockopt(IP_MTU)` while the vulnerable socket lock is held.

### CPU0-noise no-oracle run
- Folder:
  - `old/2026-05-04_unpriv_mtu1_cpu0_noise_smp2/`
- Setup:
  - No kprobes.
  - Wrapper set `/proc/sys/net/ipv4/route/mtu_expires=1`, then dropped to UID 1000.
  - `BAD_DST_CPU0_NOISE_THREADS=1`
  - `BAD_DST_CPU0_NOISE_AFTER_TIMER_ARM=1`
  - `BAD_DST_CPU0_NOISE_DURATION_NS=250000`
  - `BAD_DST_CPU0_NOISE_SPIN_NS=2000`
  - `BAD_DST_CPU0_NOISE_SLEEP_NS=5000`
  - `BAD_DST_LOCK_ORACLE=0`
- Result before manual stop:
  - `23` attempts.
  - `23` candidate lines, but these are not trustworthy because the lock oracle was disabled.
  - `22` pipe corruption failures.
  - `0` corrupted pipe detections, accepted pipe probes, or arbitrary R/W setups.

### CPU0-noise pulse no-oracle run
- Folder:
  - `old/2026-05-04_unpriv_mtu1_cpu0_noise_pulse_smp2/`
- Setup:
  - No kprobes.
  - Dropped to UID 1000 after setting `mtu_expires=1`.
  - Lighter CPU0 noise plus CPU1 futex pulse sweep.
  - `BAD_DST_LOCK_ORACLE=0`
- Result before manual stop:
  - `35` attempts.
  - `23` candidate lines, not trustworthy because the lock oracle was disabled.
  - `12` timer/done-oracle late misses.
  - `22` pipe corruption failures.
  - `0` corrupted pipe detections, accepted pipe probes, or arbitrary R/W setups.
- Interpretation:
  - The pulse can move attempts between still-running and already-returned states, but this run did not prove socket-lock holds.

### CPU0-noise lock-oracle run
- Folder:
  - `old/2026-05-04_unpriv_mtu1_cpu0_noise_lockoracle_smp2/`
- Setup:
  - No kprobes.
  - Dropped to UID 1000 after setting `mtu_expires=1`.
  - `BAD_DST_CPU0_NOISE_THREADS=1`
  - `BAD_DST_CPU0_NOISE_AFTER_TIMER_ARM=1`
  - `BAD_DST_CPU0_NOISE_DURATION_NS=220000`
  - `BAD_DST_CPU0_NOISE_SPIN_NS=1500`
  - `BAD_DST_CPU0_NOISE_SLEEP_NS=6000`
  - `BAD_DST_LOCK_ORACLE=1`
  - `BAD_DST_LOCK_ORACLE_US=20000`
- Result before manual stop:
  - `13` attempts.
  - `13` confirmed `lock oracle: blocked` results.
  - `12` pipe corruption failures.
  - `0` corrupted pipe detections, accepted pipe probes, or arbitrary R/W setups.
- Interpretation:
  - CPU0 noise can reproduce a real non-root socket-lock-held state without kprobes.
  - This is still too broad; a held lock does not prove the trigger is in the exact post-refcount-drop/pre-null subwindow.

### CPU0-noise pulse lock-oracle run
- Folder:
  - `old/2026-05-04_unpriv_mtu1_cpu0_noise_pulse_lockoracle_smp2/`
- Setup:
  - No kprobes.
  - Dropped to UID 1000 after setting `mtu_expires=1`.
  - `BAD_DST_CPU0_NOISE_THREADS=1`
  - `BAD_DST_CPU0_NOISE_AFTER_TIMER_ARM=1`
  - `BAD_DST_CPU0_NOISE_DURATION_NS=180000`
  - `BAD_DST_CPU0_NOISE_SPIN_NS=1500`
  - `BAD_DST_CPU0_NOISE_SLEEP_NS=6000`
  - `BAD_DST_CPU1_BLOCK_FUTEX=1`
  - `BAD_DST_LOCK_ORACLE=1`
  - `BAD_DST_LOCK_ORACLE_US=20000`
  - `BAD_DST_RACE_PULSE_SWEEP_COUNT=48`
  - `BAD_DST_RACE_PULSE_START_NS=5000`
  - `BAD_DST_RACE_PULSE_STEP_NS=1000`
  - `BAD_DST_RACE_PULSE_SETTLE_NS=10000`
- Result:
  - Ran the full `72` attempts.
  - `40` confirmed `lock oracle: blocked` results.
  - `32` timer/done-oracle late misses.
  - `40` pipe corruption failures.
  - `0` corrupted pipe detections, accepted pipe probes, or arbitrary R/W setups.
  - Ended with:
    - `FAIL: reached BAD_DST_MAX_ATTEMPTS without winning real race`
- Interpretation:
  - The userspace-only CPU0 noise plus pulse sweep does reproduce non-root socket-lock holds without kprobes.
  - It does not reproduce the trace-assisted arbitrary R/W path in this bounded run.
  - The lock oracle is too coarse for the exact race window: it identifies `sk_lock` held, but the target subwindow is narrower and likely after the refcount decrement. The current non-root timing mechanism may be stopping the trigger before or after that narrower point, or the downstream fake-dst/pipe reclaim still requires additional tuning.

### Updated status
- Non-root timing now has a proven broad oracle: CPU0 userspace noise can hold the trigger in a socket-locked state without kprobes.
- No-kprobe dropped-UID arbitrary R/W is still not reproduced.
- The next useful step is a stronger non-root oracle or calibration method for the post-refcount-drop subwindow, because `IP_MTU` lock blocking alone is not selective enough.

## 2026-05-04 close-read race ideas

### Kernel-side window
- The vulnerable sequence in `include/net/sock.h` is:
  - `dst = __sk_dst_get(sk);`
  - `ndst = dst->ops->negative_advice(dst);`
  - if `ndst != dst`, then `rcu_assign_pointer(sk->sk_dst_cache, ndst);`
- For the current IPv4 route, `ipv4_negative_advice()` drops the reference through `ip_rt_put(rt)` and returns `NULL` when `rt->dst.expires` is set.
- Therefore the useful stop point is after `ipv4_negative_advice()` returns with `ndst == NULL`, but before `rcu_assign_pointer(sk->sk_dst_cache, NULL)`.
- The successful trace-assisted run shows exactly this:
  - `cnxret` fires for the vulnerable socket.
  - There is no matching `cnxassign` before `MSG_PROBE`.
  - Later `sk_dst_check()` sees the sprayed fake dst (`obs=1`, fake ops, fake flags) and reaches the pipe-buffer primitive.
- Failed trace-assisted candidates generally show `cnxassign` shortly after `cnxret`, before `MSG_PROBE`, which clears the socket cache and removes the UAF.

### Current non-root timing issue
- `IP_MTU` lock blocking proves only that `sk_lock` is held.
- It does not distinguish these states:
  - stopped after `lock_sock()` but before `dst_negative_advice()`;
  - stopped inside or before `ipv4_negative_advice()`;
  - stopped at the useful post-`negative_advice`/pre-assign point;
  - stopped after the useful point but before release.
- The CPU0-noise runs mostly create the first broad condition, not the precise useful one.
- The current pulse path can also be harmful: `pulse_frozen_trigger()` briefly releases the CPU1 blockers, which can let a good candidate run past `rcu_assign_pointer()` before the main thread uses the stale pointer.

### Stronger ideas to try next
- Do a narrow timer sweep around the trace-assisted successful neighborhood (`timer_offset=91144`, `align_pad=3`) without pulse first, using the lock oracle only as a filter. The last CPU0-noise pulse run used a 4096 ns timer step and did not include `91144`; the trace/no-trace exact runs used 2048 ns steps.
- Add a mode that fixes `BAD_DST_ALIGN_PAD=3` and sweeps `BAD_DST_TIMER_SWEEP_START_NS` around roughly `90000..92500` with sub-microsecond steps, then repeats that small window many times. This accepts that the final window is instruction-scale and tries to sample it directly.
- Try removing or greatly shrinking `pulse_frozen_trigger()` for final attempts. Pulse is useful for mapping early/late behavior, but once a timer hit is in the right neighborhood it may advance the trigger past the assignment.
- Consider a per-trigger-thread timing source instead of wall-clock `timerfd`: `perf_event_open()` with a task/cpu-clock or cycle event attached to the trigger thread could generate an interrupt after a calibrated amount of kernel execution. This may be non-root depending on `perf_event_paranoid`/CAP_PERFMON policy, and it is more aligned to "instruction progress inside the syscall" than wall-clock time.
- A POSIX CPU-time timer targeting the trigger thread is another lower-probability variant to test. It may only deliver the signal on syscall exit, but it is worth checking whether it can set a reschedule point while the syscall is still executing on this kernel.
- Use kprobes only as a calibration tool to map `cnxret` timing for a given build/config, then remove them and run a tight non-root sweep around the measured offset. Do not treat kprobe-success rates as representative because the `cnxret` kprobe likely widens the exact window it is measuring.
- If no non-root timing source can reliably hit the tiny post-return/pre-assign interval, the practical fallback is to search for another vulnerable protocol/path where `negative_advice()` has a longer or more controllable gap before the socket cache is cleared. The patch covers IPv4, IPv6, and xfrm users, so the same bug class may have a slower path elsewhere.

## 2026-05-04 IPv6 path investigation

### Kernel behavior
- The vulnerable IPv6 ordering is the same core bug in `include/net/sock.h:__dst_negative_advice()`:
  - read `sk->sk_dst_cache`;
  - call `dst->ops->negative_advice(dst)`;
  - only afterward assign the returned pointer back to `sk->sk_dst_cache`.
- `net/ipv6/route.c:ip6_negative_advice()` has two cases:
  - non-`RTF_CACHE`: calls `dst_release(dst)` and returns `NULL`;
  - `RTF_CACHE`: only removes the exception and returns `NULL` if `rt6_check_expired(rt)` is true.
- `BUG.md` confirms the upstream fix special-cased IPv6:
  - non-`RTF_CACHE` now uses `sk_dst_reset(sk)`;
  - expired `RTF_CACHE` now does `dst_hold(dst)`, `sk_dst_reset(sk)`, then `rt6_remove_exception_rt(rt)`.
- `struct rt6_info` is not in generic kmalloc on this test kernel. `ip6_route_init()` creates a dedicated `ip6_dst_cache` with `sizeof(struct rt6_info)`.
- Current x86 `vmlinux` layout:
  - `struct rt6_info`: size `232`;
  - embedded `struct dst_entry`: offset `0`, size `112`;
  - `from`: offset `112`;
  - `sernum`: offset `120`;
  - `rt6i_idev`: offset `184`;
  - `rt6i_flags`: offset `192`;
  - `rt6i_uncached`: offset `200`;
  - `rt6i_uncached_list`: offset `216`.
- Important symbols in current `vmlinux`:
  - `ip6_dst_check`: `0xffffffff81e3af70`;
  - `ip6_negative_advice`: `0xffffffff81e3bc10`;
  - `dst_blackhole_check`: `0xffffffff81c078f0`;
  - `metadata_dst_free`: `0xffffffff81c07af0`;
  - `dst_blackhole_ops`: `0xffffffff836a8e40`;
  - `ip6_dst_blackhole_ops`: `0xffffffff836bea80`;
  - `ip6_dst_ops_template`: `0xffffffff836beb40`;
  - `anon_pipe_buf_ops`: `0xffffffff827bf3c0`.

### Route/refcount implications
- `connect(AF_INET6, SOCK_DGRAM)` reaches `ip6_datagram_dst_update()`, then `ip6_dst_lookup_flow()`, then `ip6_sk_dst_store_flow()`.
- For connected UDP sends, `udpv6_sendmsg()` reaches `ip6_sk_dst_lookup_flow()`, which calls `sk_dst_check()` before `ip6_sk_dst_check()`.
- `MSG_PROBE` is still useful for the fake-dst trigger because `ip6_append_data()` returns immediately for `MSG_PROBE`.
- Normal IPv6 output lookup uses `ip6_pol_route_output()`, not the input-side per-cpu route path. It searches the exception table first and otherwise creates an `rt6_info` with `ip6_create_rt_rcu()`.
- IPv6 PMTU can create `RTF_CACHE` exception routes through `ip6_rt_cache_alloc()` and `rt6_insert_exception()`, but this path needs runtime confirmation because exception ownership/refcounting differs from the simple non-`RTF_CACHE` `dst_release()` case.

### Fake dst considerations
- A fake IPv6 `rt6_info` can make `ip6_dst_check()` return `NULL` by setting:
  - `dst.obsolete != 0`;
  - `dst.ops` to an ops table whose `.check` passes KCFI;
  - `from = NULL`;
  - `sernum = 0`.
- Using `ip6_dst_blackhole_ops` is not automatically safe: its `.destroy = ip6_dst_destroy`, which calls `rt6_uncached_list_del()`, `in6_dev_put(rt6i_idev)` if non-null, and `fib6_info_release(from)`.
- Therefore a fake `rt6_info` using IPv6 ops must zero `rt6i_idev/from` and initialize `rt6i_uncached` as an empty list head, or destruction may dereference invalid list/device pointers.
- The generic `dst_blackhole_ops` / metadata-dst pattern is likely safer because `.check = dst_blackhole_check` returns `NULL` and `dst_destroy()` can route `DST_METADATA` objects into `metadata_dst_free()` instead of `ip6_dst_destroy()`. However `ip6_sk_dst_check()` rejects non-`AF_INET6` families only after `sk_dst_check()` returns a non-NULL dst, so for the invalidation trigger this may be acceptable.
- Existing `exp_x86.c` already uses the metadata-dst style for IPv4. Existing `exp_x86_ipv6.c` does not build a fake payload at all.

### IPv6 oracle and scaffold issues
- `getsockopt(IPV6_MTU)` is not a socket-lock oracle. It does an RCU read of `__sk_dst_get()` and does not call `lock_sock()`.
- Better IPv6 lock-oracle candidates are sticky-option getters such as `IPV6_DSTOPTS`, `IPV6_HOPOPTS`, `IPV6_RTHDRDSTOPTS`, and `IPV6_RTHDR`, which call `lock_sock()` in `ipv6_getsockopt()`.
- `exp_x86_ipv6.c` is an old scaffold:
  - it connects to `::1`;
  - it uses the lockless `IPV6_MTU` check as a heuristic;
  - it lacks the current IPv4 harness features: CPU0 noise, real lock oracle, pipe active-ring setup, robust pipe probe, root payload, and fake dst builder.
- Current test VM wrappers configure only IPv4 tap addresses. Any non-loopback IPv6 PMTU path will first need IPv6 addressing/router setup or an explicit local IPv6-only test plan.

### Plan
- First validate route/refcount behavior with tracing/debug only:
  - trace `ip6_negative_advice`, `dst_release`, `dst_destroy_rcu`/`ip6_dst_destroy`, `sk_dst_check`, and `rt6_remove_exception_rt`;
  - capture `rt6i_flags`, `dst->__refcnt`, `dst->ops`, and whether the cached socket dst is `RTF_CACHE` for `::1` and for a non-loopback peer.
- Prefer testing both IPv6 route modes:
  - non-`RTF_CACHE`, to see if `ip6_negative_advice()` directly drops the socket-owned final ref;
  - expired `RTF_CACHE`, to see if `rt6_remove_exception_rt()` provides a slightly wider or easier-to-control post-release path.
- Do not build on `exp_x86_ipv6.c` directly. If IPv6 looks promising, port the current `exp_x86.c` harness and swap only:
  - IPv6 socket creation and PMTU setup;
  - IPv6-safe lock oracle;
  - IPv6/metadata fake-dst payload builder;
  - IPv6 symbol constants.
- For fake dst, first test the safer metadata/generic blackhole choice in a debug harness. If it fails KCFI or family assumptions on Android, use `ip6_dst_blackhole_ops` with a correctly initialized fake `rt6_info`.
- Treat IPv6 as a candidate for a better trigger path, not yet a proven race solution. The key unknown is whether the IPv6 `negative_advice()` branch gives a longer exact window than IPv4 or merely reproduces the same tiny post-refdrop/pre-assign interval.

## 2026-05-06 Clean IPv4 race profile and networking retest

### Actions
- Added a compile-time/runtime clean IPv4 profile in `exp_x86.c`, enabled by `BAD_DST_CLEAN_RACE=1` or by building `exp_x86_clean.c`.
- Added `exp_x86_clean.c`, which includes `exp_x86.c` with `BAD_DST_CLEAN_PROFILE_DEFAULT=1`.
- Added `compile_x86_clean.sh` and rebuilt `bad_dst_cache_clean` with the same static payload flags as the normal x86 build.
- Created checkpoints:
  - `old/2026-05-06_before_clean_ipv4_profile_exp_x86.c`
  - `old/2026-05-06_before_clean_ipv4_profile_RUNNING_LOG.md`
  - `old/2026-05-06_clean_ipv4_profile_smp2_lockoracle_exp_x86.c`
  - `old/2026-05-06_clean_ipv4_profile_smp2_lockoracle_exp_x86_clean.c`
  - `old/2026-05-06_clean_ipv4_profile_smp2_lockoracle_compile_x86_clean.sh`
- Verified the host side after networking setup:
  - `icmp4_mtu_server.py -i br0testvm -p 6767` was running.
  - `tap0testvm` and `br0testvm` existed; `br0testvm` had `192.168.10.1/24`.
  - Both test VMs configured `eth0` as `192.168.10.2/24` and reported `testvm-host (192.168.10.1)` reachable.
- Ran `new_kernel/bzImage` with `--nokaslr --smp 2 --memory 1G --network tap --network-tap tap0testvm`.

### Clean profile run without lock oracle
- Artifact directory: `old/2026-05-06_clean_ipv4_profile_smp2/share`.
- Guest confirmed `/proc/sys/net/ipv4/route/mtu_expires = 1`.
- The autorun deadline expired after 240 seconds, with no kernel oops and no pipe corruption.
- Exploit log showed 33 exact `race candidate: lock held` entries, but this profile had `BAD_DST_LOCK_ORACLE=0`, so those were not trustworthy as real socket-lock evidence.
- All 33 candidate paths reached `FAIL: could not corrupt pipe`.
- Final state paused because the leaked-vuln-pipe registry reached 8192.

### Clean profile run with unprivileged lock oracle
- Artifact directory: `old/2026-05-06_clean_ipv4_profile_smp2_lockoracle/share`.
- Same networking and `mtu_expires=1` setup.
- Added environment override `BAD_DST_LOCK_ORACLE=1`, using the existing unprivileged `getsockopt(IP_MTU)` blocked-child oracle.
- Observed 37 attempts in 240 seconds:
  - 33 `lock oracle: blocked` results;
  - 33 `race candidate: lock held` results;
  - 4 `race miss after timer: trigger already returned` results;
  - 33 `FAIL: could not corrupt pipe` results.
- The clean profile is now reliably reaching a state where the socket lock remains held from userspace timing alone on SMP=2. This is stronger than the earlier "near hit" suspicion, but it still does not prove the timer lands after the dst refcount drop; it only proves the trigger thread has not released the socket lock.

### Insights
- The networking setup appears fixed for the IPv4 path. No connect/read syscheck failure appeared, the VM reached the host, and the exploit got through the initial UDP exchange and repeated PMTU/expiry sequence.
- Current blocker is distinguishing an exact post-refdrop hit from a lock-held-but-too-early hit, then validating the reclaim/free sequence. The fake-dst invalid-free stage is reached in the harness, but pipe-page overlap is not observed by the FIONREAD corruption probe.
- `critical elapsed before MSG_PROBE` was consistently about `1.66s` to `1.70s`, which is dominated by the intentional FNHE expiry/RCU timing. That elapsed time does not by itself mean the lock race was missed because the lock oracle child stayed blocked across the candidate.
- Both runs hit the same end condition: repeated `FAIL: could not corrupt pipe`, then leaked vuln-pipe registry exhaustion. Further work should focus on validating whether the fake dst is actually reclaimed by the cmsg spray and whether the subsequent unaligned free lands in the intended kmalloc-256 slab/page path.

### Issues / next checks
- Add a diagnostic pass that stops just after `MSG_PROBE` and inspects whether the fake dst free callback runs and whether a kmalloc-256 object from the cmsg spray is freed.
- Revisit the prepared pipe strategy after proving the fake dst object is actually in the socket dst cache. If the fake dst is not installed, tune the exact race window; if it is installed, focus on allocator placement, fake-dst offset/layout, and the pipe-buffer active-ring/FIONREAD probe.
- Consider re-enabling only lightweight trace markers for one run to correlate `before_msg_probe`, `after_fake_dst_rcu`, and pipe resize timing without perturbing the race window much.

## 2026-05-06 Race-window assembly/source inspection

### Tooling note
- Avoided further radare use on `vmlinux`; bounded `objdump --start-address/--stop-address` plus `nm` is sufficient for this inspection and avoids whole-kernel analysis overhead.

### Current `new_kernel/vmlinux` symbols
- `sock_setsockopt`: `0xffffffff81c054a0`
- `dst_release`: `0xffffffff81c2cd80`
- `ipv4_negative_advice`: `0xffffffff81d8c310`
- `xfrm_negative_advice`: `0xffffffff81e2c510`
- `rt6_remove_exception_rt`: `0xffffffff81e655b0`
- `ip6_negative_advice`: `0xffffffff81e656d0`

### IPv4 source path
- Vulnerable ordering is still the old `include/net/sock.h:__dst_negative_advice()`:
  - read `sk->sk_dst_cache`;
  - call `dst->ops->negative_advice(dst)`;
  - if returned dst differs, assign `sk->sk_dst_cache = ndst`.
- IPv4 `net/ipv4/route.c:ipv4_negative_advice()` drops the route reference via `ip_rt_put(rt)` / `dst_release()` and returns `NULL` when `rt->dst.expires` is set.
- Therefore the useful stop point is after `dst_release()` has decremented `dst->__refcnt`, but before `sock_setsockopt()` stores `NULL` to `sk->sk_dst_cache`.

### IPv4 x86 instruction window
- Relevant `sock_setsockopt()` sequence:
  - `0xffffffff81c06376`: load `sk->sk_dst_cache` from `sk+0x138`;
  - `0xffffffff81c06386`: load `dst->ops`;
  - `0xffffffff81c0638b`: load `ops->negative_advice`;
  - `0xffffffff81c0639b`: indirect call to `negative_advice`;
  - `0xffffffff81c063a0`: `cnxret`, compare returned dst with old dst;
  - `0xffffffff81c063a3`: not-taken branch for `ndst != dst`;
  - `0xffffffff81c063a9`: `cnxassign`, store returned pointer to `sk->sk_dst_cache`.
- `ipv4_negative_advice()` calls `dst_release()` at `0xffffffff81d8c335`, then returns `NULL` with `xor %eax,%eax; ret`.
- `dst_release()` decrements `dst->__refcnt` at `0xffffffff81c2cd98` with `lock xadd %ecx,0x40(%rdi)`.
- On the intended non-final-ref IPv4 path, after the `lock xadd` retires there are only about ten instructions before the `sk_dst_cache = NULL` store:
  - `sub`, two conditional branches, stack restore, `ret` from `dst_release`, `xor`, `ret` from `ipv4_negative_advice`, `cmp`, not-taken `je`, then the store.
- If only measuring from the old trace marker `cnxret` (`sock_setsockopt+0xf00`) to `cnxassign` (`+0xf09`), the post-return window is just two instructions before the store.
- This explains why the `getsockopt(IP_MTU)` lock oracle is too coarse: it accepts anything after `lock_sock()` but before `release_sock()`, while the exact post-refdrop/pre-assign interval is tiny.

### IPv4 cache-miss / stall opportunities
- The obvious dereferences all happen before the useful refcount drop:
  - `sk->sk_dst_cache` load;
  - `dst->ops` load;
  - `ops->negative_advice` load;
  - `rt->dst.expires` / flags checks inside `ipv4_negative_advice`;
  - the `dst->__refcnt` locked atomic operation.
- Slowing those can move the timing target, but it mostly widens the lock-held-too-early interval rather than the useful interval.
- The `sk_dst_cache` assignment at `sock_setsockopt+0xf09` is unlikely to be a good cache-miss lever because the same socket cacheline was loaded at `+0xed6` just before the call.
- There is no post-refdrop memory dereference on the non-final-ref IPv4 path before the assignment, only returns, branches, and stack cleanup.

### Potential race-widening paths
- IPv4 final-ref variant:
  - If the socket drop can make `dst->__refcnt` reach zero inside `dst_release()`, the function tail-jumps into `call_rcu()` before returning to `ipv4_negative_advice()`.
  - This could widen the after-refdrop/before-assign window and may remove the FNHE-expiry dependency, but it changes ownership assumptions and needs tracing to confirm when the RCU callback is actually queued relative to preemption.
- IPv6 expired `RTF_CACHE` exception path:
  - `ip6_negative_advice()` calls `rt6_remove_exception_rt(rt)` before returning `NULL`.
  - `fib6_nh_remove_exception()` holds `rt6_exception_lock` with `spin_lock_bh()`, finds the exception, calls `rt6_remove_exception()`, then unlocks.
  - `rt6_remove_exception()` performs `dst_release(&rt6_ex->rt6i->dst)` while still in that removal path, then does `kvfree_call_rcu()` and bucket accounting before returning.
  - Because `spin_lock_bh()` suppresses preemption until unlock, a timer interrupt that arrives while the lock is held can be deferred until after the exception removal has dropped the route reference but before `ip6_negative_advice()` returns to the vulnerable assignment site. This may substantially widen the practical timing window.
  - The downside remains the IPv6 reclaim problem: `rt6_info` is from the dedicated `ip6_dst_cache`, not generic kmalloc, so the fake-dst and pipe-reclaim strategy needs separate work.
- XFRM `xfrm_negative_advice()` is not promising for window width. It is essentially shorter than IPv4: check `dst->obsolete`, call `dst_release()`, return `NULL`.
- KCFI/indirect-call checks on Android likely add work before entering `negative_advice()`, not in the post-refdrop/pre-assign part that matters for IPv4. They may move calibration but probably do not widen the useful IPv4 window.

## 2026-05-06 IPv6 refcount audit

### Generic dst refs
- `dst_init()` sets `dst->__refcnt` to the allocator-supplied `initial_ref`.
- `ip6_dst_alloc()` calls `dst_alloc(..., initial_ref=1, initial_obsolete=DST_OBSOLETE_FORCE_CHK, ...)`, so every allocated `rt6_info` starts with one dst ref.
- `dst_hold()`, `dst_hold_safe()`, and `dst_clone()` increment `dst->__refcnt`.
- `dst_release()` decrements `dst->__refcnt`; reaching zero queues `dst_destroy_rcu()`.
- `ip6_dst_destroy()` releases IPv6 side resources: metrics, uncached-list membership, `rt6i_idev`, and the stored `from` `fib6_info` reference.

### Socket-cache refs
- `sk_dst_get()` takes a temporary ref with `atomic_inc_not_zero()`.
- `__sk_dst_get()` does not take a ref; `dst_negative_advice()` uses this lock-protected/no-ref accessor.
- `sk_dst_set()` stores the new pointer and releases the old socket-cache dst ref.
- `sk_setup_caps()` calls `sk_dst_set()`, so `ip6_dst_store()` consumes exactly one dst ref for the socket cache. It does not create a new ref by itself.
- `ip6_datagram_dst_update()` looks up a dst and passes it directly to `ip6_sk_dst_store_flow()`, so the lookup's returned ref becomes the socket-cache ref.
- `ip6_sk_dst_lookup_flow()` uses a different pattern for sends: if connected and it performs a fresh lookup, it stores `dst_clone(dst)` in the socket cache and returns the original lookup ref to the send path; the send path later `dst_release(dst)`.

### Normal non-RTF_CACHE connected UDP route
- The usual output lookup uses a per-cpu `RTF_PCPU` route when there is no PMTU exception.
- `ip6_rt_pcpu_alloc()` allocates the route with refcount 1 and stores it in `rt6i_pcpu`; that ref is the per-cpu route owner.
- `ip6_route_output_flags()` takes an additional ref before returning a normal refcounted dst to callers.
- After `connect()` / `ip6_datagram_dst_update()`, the socket consumes that returned ref. Normal steady state is therefore refcount 2:
  - one per-cpu route owner ref;
  - one socket-cache ref.
- `ip6_negative_advice()` on non-`RTF_CACHE` routes calls `dst_release(dst)` and returns `NULL`. For the normal per-cpu route this drops the socket ref from 2 to 1, not to zero, so the object is not freed by the race.

### PMTU-created RTF_CACHE exception
- `__ip6_rt_update_pmtu()` creates an exception only when `rt6_cache_allowed_for_pmtu(rt6)` is true: the current route is not already `RTF_CACHE` and is either `RTF_PCPU` or has a `from` route.
- `ip6_rt_cache_alloc()` allocates an `RTF_CACHE` `rt6_info` with initial dst refcount 1 and takes a `fib6_info` ref for `rt->from`.
- `rt6_insert_exception()` stores that `rt6_info` in an `rt6_exception`. It does not call `dst_hold()`; the initial dst ref is effectively the exception-table owner ref.
- A later lookup that finds this exception uses `rt6_find_cached_rt()` to find the pointer without taking a ref, then `ip6_hold_safe()` / `dst_hold_safe()` to give the caller a ref.
- If the connected socket caches the exception during a send:
  - exception table starts at refcount 1;
  - lookup returns a caller ref: refcount 2;
  - `ip6_sk_dst_lookup_flow()` stores `dst_clone(dst)` in the socket: refcount 3;
  - UDP send releases the caller ref at `out`: refcount 2.
- If the connected socket caches the exception through `ip6_datagram_dst_update()`, the lookup ref is consumed directly by the socket, also leaving steady-state refcount 2:
  - one exception-table ref;
  - one socket-cache ref.

### Removing PMTU exceptions
- `rt6_remove_exception()` removes the exception from the hash table and does:
  - `from = xchg(&rt6_ex->rt6i->from, NULL)`;
  - `fib6_info_release(from)`;
  - `dst_dev_put(&rt6_ex->rt6i->dst)`;
  - `hlist_del_rcu(&rt6_ex->hlist)`;
  - `dst_release(&rt6_ex->rt6i->dst)`;
  - `kfree_rcu(rt6_ex, rcu)`.
- That `dst_release()` drops the exception-table dst ref. It does not specifically drop the socket-cache ref.
- PMTU exception aging/GC (`rt6_age_examine_exception()`) also removes expired `RTF_EXPIRES` exceptions through `rt6_remove_exception()`, so it likewise drops the table ref and leaves any socket ref alive.

### Old vulnerable `ip6_negative_advice()` behavior
- For `RTF_CACHE` routes, old `ip6_negative_advice()` does:
  - if `rt6_check_expired(rt)` is true, call `rt6_remove_exception_rt(rt)`;
  - set local `dst = NULL`;
  - return `NULL` to `__dst_negative_advice()`.
- The old core `__dst_negative_advice()` then assigns `sk->sk_dst_cache = NULL` directly with `rcu_assign_pointer()`. It does not call `sk_dst_reset()` / `sk_dst_set()`, so it does not run the normal `dst_release(old_dst)` for the socket-cache reference.
- This means the expired `RTF_CACHE` IPv6 branch appears to clear the socket dst pointer without consuming the socket-owned dst reference. The only dst release in that branch is the one inside `rt6_remove_exception()`, which corresponds to removing the exception/table ownership.
- The upstream fix confirms this reading: the fixed IPv6 `RTF_CACHE` path does `dst_hold(dst); sk_dst_reset(sk); rt6_remove_exception_rt(rt);` with the comment "counteract the dst_release() in sk_dst_reset()". In other words, the fix makes the socket-cache clear obey RCU ordering while preserving the old branch's net refcount effect: the exception removal is the meaningful ref drop, not the socket-cache clear.
- Follow-up upstream/local-history check found `8b591bd522b7` / upstream `3301ab7d5aeb` ("net/ipv6: release expired exception dst cached in socket"). Its commit message explicitly confirms this was a dst leak: for an expired exception dst cached in a timing-out socket, with no other socket holding it, refcount is 2 (`dst_init()`/exception-table ownership + socket-cache ownership), and the socket-cache ref was not released by the old IPv6 negative-advice behavior.
- That follow-up removed the compensating `dst_hold()` from the post-CVE fixed `ip6_negative_advice()` path. The corrected fixed ordering is: under `rcu_read_lock()`, `sk_dst_reset(sk)` drops the socket-cache ref first, then `rt6_remove_exception_rt(rt)` drops the exception-table ref. If both refs existed, this becomes 2 -> 1 -> 0 and queues/free-after-RCU.
- If the socket-cached exception still has both normal refs (table + socket), `rt6_remove_exception_rt()` removes the exception and drops the table ref: refcount 2 -> 1. The object is still alive because the socket ref remains.
- If the exception table was already removed by aging/GC, the cached `RTF_CACHE` route can be at refcount 1 from the socket only, but `rt6_remove_exception_rt()` finds no exception and performs no dst release. The object still is not freed by `ip6_negative_advice()`.
- Therefore an ICMPv6 PMTU packet can create the two-ref exception state, and timeout/GC can drop the table ref, but I do not see a path where ICMPv6 alone gets the route to refcount 1 and then `ip6_negative_advice()` drops that last socket ref. The RTF_CACHE branch drops/removes the exception-table ownership, not the socket-cache ownership.

### Consequences for the IPv6 exploit idea
- The normal IPv6 connected UDP route starts at refcount 2 for exploit purposes: per-cpu owner + socket cache.
- The PMTU exception route also starts at refcount 2 once cached in the socket: exception table + socket cache.
- Non-`RTF_CACHE` negative advice can free only if the socket-cached route has no independent owner. I did not find that in the normal connected UDP output path.
- Expired `RTF_CACHE` negative advice may be useful as a wider timing window, but it does not appear to create the same "drop last ref while socket cache still points at freed object" primitive that IPv4 gives after the FNHE/table ref has expired.
- A potentially useful IPv6 direction would be to find a socket-cached non-`RTF_CACHE` `rt6_info` with refcount 1, or a separate way to make the RTF_CACHE branch drop the socket ref after the table ref is gone. I do not currently see either from the standard UDP + ICMPv6 PMTU path.

### IPv6 ordering idea: drop table ref after socket cache exists
- Considered whether we can first create a socket-cached exception, get `sk_dst_cache` down to a single socket-owned ref, and then use ICMPv6 PMTU to drop the exception/table ref later.
- If `ip6_negative_advice()` runs on an expired `RTF_CACHE` entry, it already calls `rt6_remove_exception_rt()` before returning `NULL`; the exception/table ref is the one dropped inside the negative-advice call. There is no remaining exception-table ref for a later ICMP packet to drop.
- ICMPv6 PMTU can replace an existing exception for the same `(daddr,saddr)` through `rt6_insert_exception()`: it finds an existing `rt6_ex` and calls `rt6_remove_exception()` before inserting the new exception. If a socket still caches the old exception, this can make the old exception refcount become 1.
- However the old socket-cached object remains an `RTF_CACHE` dst. Later old vulnerable `ip6_negative_advice()` on that object either finds no exception because `rt->from` was cleared by `rt6_remove_exception()`, or calls removal that does not release the socket ref. It then returns `NULL` and old `__dst_negative_advice()` clears `sk_dst_cache` without `dst_release(old_dst)`. This is still a leak path, not the useful stale-pointer UAF.
- The safe cache-validation paths (`sk_dst_check()` / `__sk_dst_check()`) can release a stale socket-cached exception after the table ref is gone, but they clear `sk_dst_cache` before the final release, so they do not recreate the vulnerable negative-advice ordering.

### IPv6 non-RTF_CACHE race plus PMTU insertion idea
- Revised idea from discussion: start with a normal non-`RTF_CACHE` socket-cached route at refcount 2 (`RTF_PCPU` owner + socket cache). Trigger old `ip6_negative_advice()` on that route, which calls `dst_release(dst)` before the core clears `sk_dst_cache`; during the race window this can leave refcount 1 while the socket cache still points at it.
- `rt6_insert_exception()` does not directly release that original `RTF_PCPU` route. It allocates/stores a separate `RTF_CACHE` exception and only removes an existing exception entry for the same key.
- But successful `rt6_insert_exception()` calls `fib6_update_sernum()` and comments "invalidate all cached dst". If the old pcpu route has `sernum != 0`, a later same-CPU `rt6_get_pcpu_route()` sees `!rt6_is_valid(pcpu_rt)`, `xchg`s the per-cpu slot to `NULL`, and calls `dst_release(&prev->dst)`. That could drop the remaining pcpu owner ref while the trigger thread has not yet cleared `sk_dst_cache`.
- A lookup for the same `(daddr,saddr)` after PMTU insertion will likely hit the new exception in `rt6_find_cached_rt()` and skip `rt6_get_pcpu_route()`. To release the invalidated pcpu route, the follow-up lookup likely needs to be for a different destination/source pair that resolves to the same underlying `res->nh` but has no matching exception entry.
- Important condition: `ip6_rt_pcpu_alloc()` sets `pcpu_rt->sernum = rt_genid_ipv6()` only when `f6i->nh` is set, i.e. the route uses a nexthop object. For ordinary embedded-`fib6_nh` routes, `sernum` appears to remain 0, and `rt6_get_pcpu_route()` will not release the pcpu dst just because `fib6_update_sernum()` changed the generation.
- Practical implication: this path may be viable only if the target route uses nexthop objects, or if another trigger can release the exact pcpu route ref without clearing `sk_dst_cache`. It also needs the releasing lookup to run on the same CPU as the stale pcpu route, because the owner ref is stored in `res->nh->rt6i_pcpu` per-cpu.

## 2026-05-06 19:10 EDT - static clean IPv4 build and 4-vCPU diagnostics

### Actions
- Re-ran `./compile_x86_clean.sh` after the static libc nix shell became available.
- Confirmed `bad_dst_cache_clean` builds as a statically linked x86-64 ELF.
- Copied `bad_dst_cache_clean` plus the VM wrapper into `/tmp/bad_dst_clean_share` to avoid sharing the whole source directory and its large `vmlinux`.
- Ran the clean IPv4 race profile under `testvm run bzImage --nokaslr --smp 4 --net tap ...` with the existing host ICMP4 MTU listener.
- Stopped only the QEMU/testvm processes from these runs after the exploit reached its terminal sleep.

### Results
- Build succeeds. Remaining compiler output is warnings only:
  - `%d` format strings used with `ssize_t` in the existing `SYSCHK`/`CHECK` logging macros.
  - ignored return value warnings on existing `write`/`read`/`system` calls.
- A 5-attempt clean run with the default clean profile reached the reclaim path every time, but every attempt failed with `FAIL: could not corrupt pipe`.
- That 5-attempt run had `BAD_DST_LOCK_ORACLE=0` and `BAD_DST_STACK_ORACLE=0`, so the log line `race candidate: lock held with stack=unknown` was not strong evidence that the real race landed.

### Diagnostic findings
- First 20-attempt 4-vCPU diagnostic enabled both lock and stack oracles. Every attempt classified the trigger stack as `too_late_far`, while the lock oracle reported `blocked`.
- The lock oracle result is likely contaminated in this setup: `run_ip_mtu_lock_oracle()` forks a child and, by default, closes inherited fds up to the current rlimit before calling `getsockopt(IP_MTU)`. With the exploit's thousands of sockets/pipes, a 20 ms timeout can classify the child as `blocked` before it even reaches `getsockopt`.
- Re-ran an 8-attempt diagnostic with `BAD_DST_LOCK_ORACLE=0`, `BAD_DST_STACK_ORACLE=1`, `BAD_DST_STACK_ORACLE_VERBOSE=1`, and `BAD_DST_DONE_ORACLE_SETTLE_US=1000`.
- In every attempt, including after autotune clamped `BAD_DST_TIMER_INITIAL_NS` down to `1`, the trigger stack was already past the vulnerable path:

```text
[<0>] exit_to_user_mode_prepare+0x9a/0xf0
[<0>] syscall_exit_to_user_mode+0x28/0x150
[<0>] entry_SYSCALL_64_after_hwframe+0x44/0xa9
```

or:

```text
[<0>] exit_to_user_mode_prepare+0x9a/0xf0
[<0>] irqentry_exit_to_user_mode+0x5/0x20
[<0>] asm_sysvec_apic_timer_interrupt+0x12/0x20
```

### Current interpretation
- The minified clean IPv4 path is compiling and running, but the current timerfd + post-expiration affinity migration is freezing the trigger thread too late on this 4-vCPU test kernel.
- The userspace done oracle can miss this too-late state because the thread can be on the syscall exit path before executing the userspace `trigger_done_counter` increment.
- The pipe corruption failures from the default clean profile are therefore consistent with false candidates, not necessarily reclaim failure after a real UAF.
- Next useful direction is to make the freeze/preemption mechanism happen inside the syscall window instead of reacting after the timerfd is observed in the main thread. Candidate approaches include signal/timer delivery to the trigger thread, a lower-latency same-process oracle/freeze, or adding a diagnostic kernel-only delay/probe to measure the exact window before designing the unprivileged path.

## 2026-05-06 21:32 EDT - scheduler/timerfd preemption model

### Local kernel source facts
- `timerfd_setup()` arms the timer with plain `HRTIMER_MODE_ABS` / `HRTIMER_MODE_REL`, not a pinned hrtimer mode (`fs/timerfd.c:180-208`).
- `timerfd_tmrproc()` calls `timerfd_triggered()`, which sets `ctx->expired`, increments `ctx->ticks`, and does `wake_up_locked_poll(&ctx->wqh, EPOLLIN)` (`fs/timerfd.c:63-79`).
- `wake_up_locked_poll()` reaches the poll waiter's wake function and ultimately `try_to_wake_up()` (`include/linux/wait.h:228-231`, `fs/select.c:210-217`, `kernel/sched/core.c:4809-4813`).
- Wakeup-preemption is real here:
  - `try_to_wake_up()` enqueues the waiter through `ttwu_queue()` (`kernel/sched/core.c:2991`).
  - `ttwu_do_wakeup()` calls `check_preempt_curr()` (`kernel/sched/core.c:2464-2471`).
  - if the woken task's sched class outranks the current task, `check_preempt_curr()` calls `resched_curr()` (`kernel/sched/core.c:1691-1696`).
  - for a same-CPU wakeup, `resched_curr()` sets both `TIF_NEED_RESCHED` and the preempt resched bit (`kernel/sched/core.c:607-622`).
- IRQ return can schedule immediately with `CONFIG_PREEMPTION=y`: `irqentry_exit_cond_resched()` checks `!preempt_count()` and `need_resched()`, then calls `preempt_schedule_irq()` (`kernel/entry/common.c:349-357`). `irqentry_exit()` invokes it when returning to interrupted kernel code with IRQs enabled (`kernel/entry/common.c:361-388`).
- The current target window is extremely small:
  - `sock_setsockopt(... SO_CNX_ADVICE=1)` calls `dst_negative_advice(sk)` (`net/core/sock.c:1194-1197`).
  - `__dst_negative_advice()` calls `dst->ops->negative_advice(dst)` and only after it returns does `rcu_assign_pointer(sk->sk_dst_cache, ndst)` (`include/net/sock.h:1938-1949`).
  - IPv4 `ipv4_negative_advice()` drops the ref with `ip_rt_put(rt)` and returns `NULL` when `dst->obsolete > 0` (`net/ipv4/route.c:859-874`).
  - `dst_release()` performs `atomic_dec_return()` and queues `call_rcu()` when the refcount reaches zero (`net/core/dst.c:169-180`).

### Interpretation
- The timerfd path should preempt a `SCHED_IDLE` trigger when the hrtimer interrupt lands while the trigger is still in preemptible kernel code.
- Scheduler/migration latency after the interrupt is not the key cost if the interrupt lands in the target window: the trigger instruction stream is paused by the interrupt, and `preempt_schedule_irq()` can switch to the main thread before resuming it.
- The current failed diagnostic therefore most likely means the hrtimer interrupt is not landing in the useful instruction window. With `BAD_DST_TIMER_INITIAL_NS=1`, the actual interrupt still appears to arrive after `setsockopt()` has passed the vulnerable path and reached syscall exit.
- This makes a pre-syscall busy delay plausible: arm the hrtimer first, then delay the trigger before `setsockopt()` so the syscall's vulnerable window is shifted later toward the actual hrtimer interrupt.
- This is a different parameter from `timer_offset`. Existing autotune can reduce the programmed expiry down to 1 ns, but it cannot make the hardware/interrupt delivery happen earlier than its real minimum latency.

### Plan
- Add a diagnostic-only trigger-side busy-wait parameter between `timerfd_settime()` and `setsockopt()`, e.g. `BAD_DST_PRE_SYSCALL_DELAY_NS`.
- Sweep/classify it with the stack oracle:
  - `too_late_far` means the hrtimer interrupt still lands after the vulnerable path; increase the pre-syscall delay.
  - pre-syscall / `timerfd_settime` / early stack means the timer fires before `setsockopt()` reaches the target; decrease the delay.
  - `dst_release` / `ipv4_negative_advice` target means the interrupt landed in the useful window.
- Keep the timer local during diagnostics:
  - set `/proc/sys/kernel/timer_migration=0` in the privileged test wrapper, or at least log it;
  - keep CPU0 non-idle when arming the timer, because `get_nohz_timer_target()` keeps non-pinned hrtimers on the current CPU when the current housekeeping CPU is non-idle (`kernel/sched/core.c:652-660`).
- Enable ftrace for one diagnostic run to confirm the sequence:
  - trace markers around `timerfd_settime`, pre-syscall delay start/end, and `setsockopt`;
  - `timer:hrtimer_start`, `timer:hrtimer_expire_entry`, `sched:sched_wakeup`, and `sched:sched_switch`;
  - optional function probes on `timerfd_tmrproc`, `ipv4_negative_advice`, `dst_release`, and `preempt_schedule_irq`.
- Do not rely on same-thread signal delivery as the main freeze primitive: `signal_wake_up_state()` sets `TIF_SIGPENDING`, but same-CPU/current signal delivery does not itself set `TIF_NEED_RESCHED`; it is normally handled on syscall/return-to-user paths, which is too late for this race (`kernel/signal.c:760-771`).

## 2026-05-06 21:51 EDT - pre-syscall timerfd timing diagnostics

### Actions
- Created checkpoints:
  - `old/2026-05-06_before_pre_syscall_delay_diag/`
  - `old/2026-05-06_before_presyscall_state_diag/`
  - `old/2026-05-06_before_thread_lock_oracle/`
  - `old/2026-05-06_after_presyscall_timing_thread_oracle/`
- Added `BAD_DST_PRE_SYSCALL_DELAY_*` controls to delay the trigger thread between `timerfd_settime()` and `setsockopt(SO_CNX_ADVICE)`.
- Added `BAD_DST_TRIGGER_TIMING_DIAG=1` shared-state instrumentation for trigger milestones:
  - `woken`
  - `timer_armed`
  - `pre_syscall_delay`
  - `setsockopt_enter`
  - `setsockopt_exit`
  - `done`
- Added `BAD_DST_LOCK_ORACLE_THREAD=1`, a pthread-based `getsockopt(IP_MTU)` oracle. This avoids the fork oracle's inherited-fd close loop and did not false-block on early cases.
- Built `bad_dst_cache_clean` successfully with the existing warning set only.
- Ran multiple `testvm run bzImage --nokaslr --smp 4 --net tap ...` diagnostics with `timer_migration=0`.

### Results
- Sanity run with `BAD_DST_TIMER_INITIAL_NS=1` and a 100 ms pre-syscall delay woke the main thread at `stage=woken` with no `timer_armed` timestamp. This means the 1 ns timer expires before `timerfd_settime()` returns; the old stack oracle's `exit_to_user_mode_prepare` classification was misleading here.
- Coarse sweep with 50 us pre-syscall delay and timer offsets 10-300 us:
  - 10-20 us: `woken` before `timerfd_settime()` completion.
  - 30-80 us: `pre_syscall_delay`, confirmed early.
  - around 90 us and 170-180 us: `setsockopt_enter` marker but no `setsockopt_exit` marker.
  - most larger offsets: `done`, already returned from the trigger syscall.
- Fork lock oracle with 5 ms timeout produced a false candidate on `stage=woken`; the child/fork path is still too noisy for this diagnostic.
- Thread lock oracle results were cleaner:
  - early stages (`woken`, `timer_armed`, `pre_syscall_delay`) returned `done_ok`.
  - `setsockopt_enter` marker cases returned `done_err errno=107` (`ENOTCONN`), not `blocked`.
  - no attempt produced a confirmed socket-lock-held race hit.
- Fine sweep over 95.000-104.750 us in 250 ns steps with 50 us pre-syscall delay found the same pattern:
  - early states returned `done_ok`;
  - `setsockopt_enter` states returned `ENOTCONN`;
  - occasional `done` states were already fully too late.

### Interpretation
- The pre-syscall delay approach is useful diagnostically: it brackets timer delivery and shows the stack oracle alone is not enough.
- The current userspace timerfd delivery jitter is larger than the useful vulnerable window. We can reliably land before the syscall or after negative advice has already made the socket report `ENOTCONN`, but I did not observe an intermediate lock-held state.
- The `setsockopt_enter` marker is userspace-side and only proves we passed the marker before the syscall wrapper returned; the thread lock oracle is the stronger signal. Its `ENOTCONN` results mean those samples are already beyond the useful socket-lock window.
- Current likely blocker: hrtimer delivery/preemption granularity in this QEMU/test kernel setup is too coarse to place the interrupt in the tiny `dst_release()` to `sk_dst_cache = NULL` window using this timerfd-only scheme.

### Next Ideas
- Use ftrace/kprobe diagnostics, not final exploit logic, to directly timestamp `timerfd_tmrproc`, `sock_setsockopt`, `ipv4_negative_advice`, `dst_release`, and socket unlock. This should quantify the real instruction/time gap.
- Try to extend the kernel-side window instead of only tuning timer expiry: cause a cache miss or slow path in `dst_release()` / `call_rcu()` vicinity, or force contention on data touched after `dst_release()` but before the socket cache clear.
- Try a lower-jitter trigger mechanism than timerfd if one exists unprivileged; timerfd can bracket the transition, but the fine sweep still jumps from too early to `ENOTCONN`.
## 2026-05-07 Trace-assisted rerun attempts for real-race root

### Checkpoint
- Backed up the log before this update:
  - `old/2026-05-07_before_rerun_trace_root_report_RUNNING_LOG.md`

### Goal
- Rerun the last strong trace-assisted real-race `Arb R/W setup` checkpoint and try to reproduce it with credential overwrite enabled.
- Baseline checkpoint used:
  - `old/2026-05-04_unpriv_mtu1_cfsblock_mix_skcheck_trace_smp2/`
- Kernel used for reruns:
  - `new_kernel/bzImage`
  - `5.10.107+ #2 SMP PREEMPT Sun May 3 07:40:16 UTC 2026`
  - `--smp 2`, `--memory 1G`, `--nokaslr`, tap networking.

### Rerun folders
- `old/2026-05-07_rerun_trace_root_from_skcheck_checkpoint_smp2/`
  - Copied the old successful checkpoint.
  - Enabled `BAD_DST_GET_ROOT=1` and `BAD_DST_RUN_ROOT_PAYLOAD=1`.
  - Added the prior root-shell checker to verify the listening root payload.
  - Result: stopped after 6 pipe-corruption failures. No `Arb R/W setup`, no root.
  - This run was a larger delta from the old success because it added the checker artifact and payload-shell verification.
- `old/2026-05-07_rerun_trace_getroot_min_delta_smp2/`
  - Copied the old successful checkpoint again.
  - Minimal delta: `BAD_DST_GET_ROOT=1`, `BAD_DST_RUN_ROOT_PAYLOAD=0`, `BAD_DST_DISABLE_SELINUX=0`.
  - Removed the early wrapper break on `Arb R/W setup` so the wrapper waits for `now uid/gid/euid/egid: 0/0/0/0` or root failure.
  - Attempt 3 ran 40 attempts under `--qemu-arg=-no-reboot`.
  - Result: 39 pipe-corruption failures, 1 timer miss, no accepted pipe probe, no `Arb R/W setup`, no root.
  - Synced artifacts:
    - `old/2026-05-07_rerun_trace_getroot_min_delta_smp2/share/exploit.log`
    - `old/2026-05-07_rerun_trace_getroot_min_delta_smp2/share/trace.txt`
    - `old/2026-05-07_rerun_trace_getroot_min_delta_smp2_attempt3.log`
- `old/2026-05-07_rerun_trace_arbrw_exact_smp2/`
  - Exact old wrapper copied from the successful checkpoint, with `BAD_DST_GET_ROOT=0`.
  - Result: 6 pipe-corruption failures, no `Arb R/W setup`.
  - This confirms the failure to reproduce is not caused by enabling the root overwrite.
- `old/2026-05-07_rerun_trace_getroot_cnxje_stack_smp2/`
  - Diagnostic root rerun with an extra kprobe at `sock_setsockopt+0xf03`, between the old `cnxret` probe at `+0xf00` and the `sk_dst_cache` store at `+0xf09`.
  - Also attempted stacktrace triggers on `cnxret` and `cnxje`.
  - Result: no root. It reached attempt 27, then panicked in `sk_dst_check+0x4c` with `ops == NULL`/NULL deref while consuming a stale dst.
  - The panic log is in:
    - `old/2026-05-07_rerun_trace_getroot_cnxje_stack_smp2.log`
  - The guest did not sync its shared `trace.txt` after the panic under `-no-reboot`, so only console output is available for that run.

### Trace comparison
- The original successful trace had the key pattern:
  - `cnxret` for the vulnerable socket.
  - No matching `cnxassign` before stale reuse.
  - Later `sk_dst_check` on the same socket saw the same dst address reclaimed as fake dst:
    - `ref=1 obs=1 ops=0xffffffff836a9c40 flags=0xffff`
  - `skgot` incremented the fake dst refcount and `sknull` returned NULL through fake ops.
- The 2026-05-07 minimal rerun mostly showed:
  - `cnxret`, then `cnxassign`, then later `sk_dst_check` on the same socket with `dst=0`.
  - This means the trigger thread usually ran through the `sk_dst_cache = NULL` store before the later UDP/send path.
- One minimal-rerun attempt did preserve the old pointer long enough:
  - `cnxret` at `188.689338` for `sk=0xffff88801bbe4480 old=0xffff88801b56c900`.
  - Later `sk_dst_check` on the same socket saw `dst=0xffff88801b56c900`, but its fields were `ref=0 obs=0 ops=0x0 flags=0x0`.
  - The delayed `cnxassign` came later.
  - Interpretation: the exact stale-cache window did occur at least once, but the reclaimed contents were not the fake dst payload, so it missed the fake-ops path and pipe primitive.

### Current interpretation
- The real-race/root rerun did not reproduce today.
- The failure is not from the later credential overwrite path; the exact old non-root wrapper also failed to reproduce `Arb R/W`.
- The trace-assisted race is still getting close:
  - Many attempts are real candidates with socket lock held.
  - Several attempts trigger fake-dst/free side effects, including `dst_release underflow`.
  - The stronger `+0xf03` probe run reached stale-cache use badly enough to crash in `sk_dst_check`.
- The current blocker is now downstream of broad lock-held detection:
  - Usually the trigger thread resumes far enough to execute `cnxassign` before stale reuse.
  - When stale reuse does occur, the old dst is not reliably reclaimed by the fake dst spray.
- Next useful directions:
  - Tune or simplify the fake-dst reclaim around the exact stale-cache window instead of only timer offsets.
  - Try a root-only diagnostic that captures the old dst address and fake spray placement/counts per attempt.
  - Consider using only the in-window `cnxret/cnxje` probes, without `sk_dst_check` probes, to change less of the later send path while still slowing the vulnerable window.

## 2026-05-07 Kernel identity check for PREEMPT and debug-67

### Checkpoint
- Backed up the log before this update:
  - `old/2026-05-07_before_kernel_identity_debug67_preempt_check_RUNNING_LOG.md`

### Kernel used in May 7 reruns
- The May 7 reruns used `new_kernel/bzImage`, not the older top-level `bzImage`.
- `file new_kernel/bzImage` reports:
  - `Linux kernel x86 boot executable bzImage, version 5.10.107+ ... #2 SMP PREEMPT Sun May 3 07:40:16 UTC 2026`
- The May 7 console logs and the original May 4 successful trace-assisted run all show the same boot version string:
  - `Linux version 5.10.107+ ... #2 SMP PREEMPT Sun May 3 07:40:16 UTC 2026`
- The older top-level `bzImage` is a different build:
  - `#1 SMP Mon Apr 27 21:55:53 UTC 2026`
  - Its embedded config has `CONFIG_PREEMPT_NONE=y`.

### Config verification
- Extracted embedded config from `new_kernel/bzImage` with `scripts/extract-ikconfig`.
- Relevant config values:
  - `CONFIG_PREEMPT=y`
  - `CONFIG_PREEMPTION=y`
  - `CONFIG_PREEMPT_COUNT=y`
  - `CONFIG_PREEMPT_RCU=y`
  - `CONFIG_HZ=1000`
  - `CONFIG_KPROBES=y`
  - `CONFIG_FTRACE=y`
  - `CONFIG_FUNCTION_TRACER=y`
  - `CONFIG_DEBUG_INFO=y`
  - `CONFIG_SLUB=y`

### Debug-67 verification
- Source at `linux_src/linux_stable/net/core/sock.c` still has the local debug hook:
  - `SO_CNX_ADVICE`
  - `val == 67`
  - `dst_release(sk->sk_dst_cache); return ret;`
- Binary disassembly of `new_kernel/vmlinux:sock_setsockopt` confirms the built kernel contains the debug hook:
  - compares `val` with `0x43`
  - loads `sk->sk_dst_cache` from `0x138(%rbx)`
  - calls `dst_release`
  - jumps directly to the return epilogue at `sock_setsockopt+0x13c`, bypassing the normal `release_sock` path.
- This matches the intended debug-67 behavior: decrement the dst refcount while leaving the socket lock held.

## 2026-05-07 Debug-67 root payload retest on PREEMPT kernel

### Checkpoint
- Backed up the log before this update:
  - `old/2026-05-07_before_debug67_root_payload_preempt_retest_RUNNING_LOG.md`

### Test
- Retested the debug-67 root-payload checkpoint against the PREEMPT kernel:
  - Kernel: `new_kernel/bzImage`
  - QEMU: `--smp 1 --memory 1G --nokaslr --qemu-arg=-no-reboot`
  - Checkpoint folder:
    - `old/2026-05-07_debug67_root_payload_preempt_retest_smp1/`
  - Binary/wrapper copied from:
    - `old/2026-05-04_debug67_drop_mtu1_root_payload_smp1/`
- This uses the already-built debug binary with the local `SO_CNX_ADVICE == 67` harness. Current `exp_x86.c` still has `DEBUG` commented out, so the current source was not rebuilt for this retest.

### Result
- Debug-67 path worked on the PREEMPT kernel.
- Attempts 1-3 reached `debug triggered` and missed pipe corruption.
- Attempt 4 reached:
  - `found corrupted pipe FIONREAD source=current index=14 size=0xc3c3c3c3`
  - `pipe probe leak accepted: page_index=9 probe=0x2b8 pipe_base=0x240 active_before=3 ...`
  - `kaslr base: ffffffff81000000`
  - `Arb R/W setup`
  - discovered task layout and current task
  - `now uid/gid/euid/egid: 0/0/0/0`
- Root payload marker and shell verifier output were created:
  - `root_payload_marker`: `ROOT_PAYLOAD_MARKER`
  - `root_payload_shell_output` shows `uid=0 gid=0`, `Uid: 0 0 0 0`, and full capability masks.

### Caveat
- The kernel panicked after success in `kfree -> free_pipe_info -> pipe_release -> __fput` while the shell/wrapper was exiting.
- This matches the previously observed post-success cleanup issue from corrupted pipe state. It does not invalidate the credential overwrite or payload-shell confirmation, but it means cleanup still needs to preserve/leak/avoid closing corrupted pipe resources.

### Interpretation
- The PREEMPT kernel, debug-67 hook, pipe primitive, arbitrary R/W setup, credential overwrite, and root payload are all still functional.
- The current real-race failure is therefore before the root payload stage:
  - usually the trigger thread reaches `cnxassign` before stale reuse, clearing `sk_dst_cache`;
  - when stale reuse does happen, the stale route is not reliably reclaimed by the fake dst payload.

## 2026-05-07 Futex wake timing experiment

### Checkpoints
- Backed up the source/log/binary before adding the futex wake timer:
  - `old/2026-05-07_before_futex_wake_timer/`
- Backed up the source/log/binary before adding direct trigger pinning from the futex waker:
  - `old/2026-05-07_before_futex_waker_direct_pin/`

### Code changes
- Added an optional futex-driven wake timer for the real race path.
- New knobs:
  - `BAD_DST_FUTEX_WAKE_TIMER=1`
  - `BAD_DST_FUTEX_WAKE_CPU`
  - `BAD_DST_FUTEX_WAKE_NICE`
  - `BAD_DST_FUTEX_WAKE_USE_SPIN`
  - `BAD_DST_FUTEX_WAKE_PIN_TRIGGER`
  - `BAD_DST_FUTEX_WAKE_PIN_CPU`
- The default timerfd path is unchanged when `BAD_DST_FUTEX_WAKE_TIMER=0`.
- Added timing diagnostics for futex request/wake/pin ages so timerfd and futex runs can be compared directly.
- Built with `nix-shell -p glibc.static --run ./compile_x86.sh`; build passed with only the existing warning noise.

### SMP2 futex wake run
- Folder:
  - `old/2026-05-07_futex_wake_timer_smp2/`
- Kernel:
  - `new_kernel/bzImage`
  - `--smp 2`
  - `--nokaslr`
- Wrapper set `mtu_expires=1`, then dropped privileges through `drop_exec`.
- Futex waker ran on CPU1 with 128 CFS CPU1 blockers.
- Results over 80 attempts:
  - `race candidate`: 16
  - `race miss after timer`: 72
  - `race miss before freeze`: 0
  - `FAIL: could not corrupt pipe`: 8
  - `Arb R/W setup`: 0
- Interpretation:
  - Futex wake can reach lock-held candidates when it shares CPU1 with blocker contention.
  - Several candidates stopped with `stage=setsockopt_enter` and a blocked lock oracle.
  - No pipe corruption was reached, so this did not reproduce a full stale-dst reclaim.

### SMP6 futex wake run
- Folder:
  - `old/2026-05-07_futex_wake_timer_smp6/`
- Kernel:
  - `new_kernel/bzImage`
  - `--smp 6`
  - `--nokaslr`
- Futex waker ran on CPU2, isolated from CPU0 trigger and CPU1 blockers.
- Results over 96 attempts:
  - `race candidate`: 0
  - `race miss after timer`: 96
  - `race miss before freeze`: 0
  - `Arb R/W setup`: 0
- Interpretation:
  - Clean isolated futex wake was consistently too late.
  - The main thread's wake-to-`sched_setaffinity()` latency is hundreds of microseconds, longer than the relevant socket-lock/refcount window.
  - The SMP2 candidates were likely helped by noisy CPU1 contention rather than by precise futex timing.

### SMP6 futex wake with direct trigger pin
- Folder:
  - `old/2026-05-07_futex_wake_directpin_smp6/`
- Change under test:
  - Futex timer thread calls `sched_setaffinity(trigger_tid, CPU1)` itself before waking main.
- Results over 96 attempts:
  - `race candidate`: 0
  - `race miss after timer`: 96
  - `race miss before freeze`: 0
  - `Arb R/W setup`: 0
- Interpretation:
  - Direct pinning from the waker did not help.
  - Timing diagnostics show the `sched_setaffinity()` call from the waker is itself expensive; `futex_pin` often occurs after `setsockopt_exit`.
  - This suggests same-process affinity migration is not a sufficiently sharp preemption mechanism for the exact window.

### Current conclusion
- The futex approach is useful as an oracle/timing experiment but does not currently improve the real race enough for the full exploit.
- It can create lock-held candidates in the noisy SMP2 topology, but the reliable, cleaner SMP6 topology arrives after the vulnerable syscall has already returned.
- If continuing this line, the next variants worth trying are:
  - a same-CPU low-priority futex waker to see whether wakeup preemption can interrupt the SCHED_IDLE trigger without starving it before the syscall;
  - using the futex timer only to trigger a cheaper operation than `sched_setaffinity()`;
  - returning to trace-assisted timing to identify whether candidates are actually in the refcount-decrement-before-null window or just somewhere else under the socket lock.

## 2026-05-07 kprobe-assisted retry

### Checkpoint
- Created `old/2026-05-07_before_kprobe_retry_work/` before switching back from the futex timing experiments.
- Reused the previously successful kprobe-assisted checkpoint binary from `old/2026-05-04_unpriv_mtu1_cfsblock_mix_skcheck_trace_smp2/` for an apples-to-apples retry before changing source again.

### Kprobe setup
- Kernel:
  - `new_kernel/bzImage`
  - `--smp 2`
  - `--nokaslr`
- Wrapper:
  - root phase sets `/proc/sys/net/ipv4/route/mtu_expires=1`
  - exploit runs through `drop_exec` as UID 1000
- Kprobes enabled:
  - `sk_dst_check`
  - `sk_dst_check+0x39`
  - `sk_dst_check+0x72`
  - `sock_setsockopt+0xf00`
  - `sock_setsockopt+0xf09`
- Main tuning change from the old success:
  - `BAD_DST_CPU1_BLOCK_THREADS=1024` instead of 256
  - CFS blockers, no sched-rt wrapper

### Arb/RW-only run
- Folder:
  - `old/2026-05-07_kprobe_1024block_arbrw_smp2/`
- Result:
  - `pipefail=18`
  - `arb=1`
  - Arb/RW reached on attempt 19.
- Relevant exploit output:
  - `found corrupted pipe FIONREAD source=current index=15 size=0xc3c3c3c3`
  - `pipe probe leak accepted: page_index=118 probe=0x5b8 pipe_base=0x540 active_before=3 page=0xffffea000085c4c0 ops=0xffffffff827bf740 offset=0x0 len=0x4 flags=0x4141414100000010`
  - `kaslr base: ffffffff81000000`
  - `physical base address: 1000000`
  - `Arb R/W setup`
- Trace pattern:
  - `cnxret` for vulnerable socket saw `old_ref=1` before `sk_dst_cache` assignment.
  - About one second later, `sk_dst_check` saw the same dst address reclaimed as fake dst with `ops=0xffffffff836a9c40`, `ref=1`, `obs=1`, `flags=0xffff`.
  - `skgot` incremented fake dst refcount to 2, `sknull` returned NULL, and `cnxassign` did not run until several seconds later.

### Get-root run
- Folder:
  - `old/2026-05-07_kprobe_1024block_getroot_smp2/`
- Result:
  - `pipefail=1`
  - `arb=1`
  - `root=1`
  - Arb/RW and root reached on attempt 2.
- Relevant exploit output:
  - `found corrupted pipe FIONREAD source=current index=14 size=0xc3c3c3c3`
  - `pipe probe leak accepted: page_index=126 probe=0xeb8 pipe_base=0xe40 active_before=3 page=0xffffea0000a1b8c0 ops=0xffffffff827bf740 offset=0x0 len=0x4 flags=0x4141414100000010`
  - `Arb R/W setup`
  - `found current task: 0xffff888006c7d580`
  - `current task creds: real_cred=0xffff888006ad69c0 cred=0xffff888006ad69c0`
  - `capability sets overwritten`
  - `SELinux disable requested but no SELinux offset/address is configured`
  - `now uid/gid/euid/egid: 0/0/0/0`
- Final trace pattern:
  - First attempt had `cnxret` and `cnxassign` close together and failed pipe corruption.
  - Second attempt:
    - `cnxret` at timestamp `17.089598` for `sk=0xffff888020967600`, `old=0xffff888020b29e40`, `old_ref=1`, normal `ip_dst_ops`.
    - `sk_dst_check` at timestamp `18.719655` saw `dst=0xffff888020b29e40`, `ref=1`, `obs=1`, `ops=0xffffffff836a9c40`, `flags=0xffff`.
    - `skgot` then incremented ref to 2.
    - `sknull` returned NULL.
    - `cnxassign` ran later at timestamp `23.493286`, after the fake dst path had already produced the invalid free and pipe overlap.

### Current kprobe conclusion
- The kprobe-assisted path is reproducible again on the preempt test kernel with `--smp 2`, `mtu_expires=1`, and 1024 CFS CPU1 blockers.
- The useful kprobe effect is not just observation. The `cnxret`/`cnxassign` probes strongly appear to widen the post-`dst_release()` / pre-`sk_dst_cache = NULL` interval enough for the userspace block/migration strategy to keep the trigger thread parked.
- The 1024-blocker variant is the current best debugging baseline:
  - Arb/RW-only: 1 success in 19 attempts.
  - Get-root: 1 success in 2 attempts.
- This does not prove the non-kprobe race is solved. It shows the reclaim and root payload are functional once the exact stale `sk_dst_cache` window is reached.

### Get-root repeat
- Folder:
  - `old/2026-05-07_kprobe_1024block_getroot_repeat2_smp2/`
- Result:
  - `pipefail=12`
  - `arb=1`
  - `root=1`
  - Arb/RW and root reached on attempt 13.
- Relevant exploit output:
  - `found corrupted pipe FIONREAD source=current index=15 size=0xc3c3c3c3`
  - `pipe probe leak accepted: page_index=118 probe=0xaf8 pipe_base=0xa80 active_before=3 page=0xffffea0000a2d7c0 ops=0xffffffff827bf740 offset=0x0 len=0x4 flags=0x4141414100000010`
  - `Arb R/W setup`
  - `found current task: 0xffff888006c00000`
  - `current task creds: real_cred=0xffff888006a25a80 cred=0xffff888006a25a80`
  - `capability sets overwritten`
  - `SELinux disable requested but no SELinux offset/address is configured`
  - `now uid/gid/euid/egid: 0/0/0/0`
- Final trace pattern:
  - Successful attempt had `cnxret` at timestamp `99.869265` for `sk=0xffff888020813600`, `old=0xffff8880283c4a80`, `old_ref=1`, normal `ip_dst_ops`.
  - `sk_dst_check` at timestamp `100.909735` saw the same `dst=0xffff8880283c4a80` reclaimed as fake dst with `ref=1`, `obs=1`, `ops=0xffffffff836a9c40`, `flags=0xffff`.
  - `skgot` incremented ref to 2, `sknull` returned NULL, and `cnxassign` ran at timestamp `106.289635`.
- Note:
  - The root payload paused for about two minutes after `capability sets overwritten` before printing the final UID line.
  - The first get-root run likely had the same pause: it powered off at kernel timestamp ~179s despite reaching Arb/RW near timestamp ~18s.
  - This makes the kprobe baseline operational, but the post-cred `setresgid`/`setresuid`/`setgid`/`setuid` sequence is worth instrumenting or optionally skipping in future source builds so a successful primitive can exit faster.

### Current-source kprobe runs
- Checkpointed current source/binary/log before rebuilding:
  - `old/2026-05-07_before_current_source_kprobe_build/`
- Rebuilt current `exp_x86.c` with:
  - `nix-shell -p glibc.static --run ./compile_x86.sh`
  - Build passed with the existing warning noise.

#### Plain current-source wrapper
- Folder:
  - `old/2026-05-07_current_source_kprobe_1024block_getroot_smp2/`
- Result:
  - Kernel panic on attempt 15 after repeated pipe-corruption misses.
- Failure:
  - Last exploit line before panic: `FAIL: could not corrupt pipe`
  - Panic: `anon_pipe_buf_release+0xb/0x50`
  - Faulting pointer was non-canonical.
- Interpretation:
  - Current source can reach the dangerous stale-dst state under kprobes, but a clean miss can still leave some pipe state corrupted below the `FIONREAD` acceptance threshold.
  - Closing all vuln pipes on a clean miss is unsafe in that state.

#### Leak clean misses plus high FIONREAD threshold
- Folder:
  - `old/2026-05-07_current_source_kprobe_1024block_getroot_leakclean_highfion_smp2/`
- Extra wrapper knobs:
  - `BAD_DST_LEAK_VULN_PIPES_ON_CLEAN_FAIL=1`
  - `BAD_DST_PIPE_CORRUPT_FIONREAD_MIN=0xc0000000`
- Result:
  - Avoided the earlier `anon_pipe_buf_release` panic.
  - Stopped in the exploit's fatal `SYSCHK` path around attempt 14:
    - `fcntl(F_SETPIPE_SZ)` returned `-1`
    - `errno=1`
- Interpretation:
  - Raising `BAD_DST_PIPE_CORRUPT_FIONREAD_MIN` rejects pointer-shaped false positives like `0xffff8880`; the reliable pipe-page overlaps are still the `0xc3c3c3c3` class.
  - Leaking 256 vuln pipes per clean miss consumes pipe pages, so unprivileged pipe accounting can block later `F_SETPIPE_SZ` calls before a successful overlap arrives.

#### Current-source get-root with pipe limits raised
- Folder:
  - `old/2026-05-07_current_source_kprobe_1024block_getroot_leakclean_highfion_pipelimits_smp2/`
- Extra wrapper setup before dropping privileges:
  - `ulimit -n 1048576`
  - `echo 1048576 > /proc/sys/fs/pipe-user-pages-soft`
  - `echo 1048576 > /proc/sys/fs/pipe-user-pages-hard`
- Extra exploit knobs:
  - `BAD_DST_LEAK_VULN_PIPES_ON_CLEAN_FAIL=1`
  - `BAD_DST_PIPE_CORRUPT_FIONREAD_MIN=0xc0000000`
- Result:
  - `pipefail=11`
  - `arb=1`
  - `root=1`
  - Arb/RW and root reached on attempt 12.
- Relevant exploit output:
  - `found corrupted pipe FIONREAD source=current index=9 size=0xc3c3c3c3`
  - `pipe probe leak accepted: page_index=122 probe=0x7f8 pipe_base=0x780 active_before=3 page=0xffffea0000a6c740 ops=0xffffffff827bf740 offset=0x0 len=0x4 flags=0x4141414100000010`
  - `Arb R/W setup`
  - `found current task: 0xffff888006c82ac0`
  - `current task creds: real_cred=0xffff8880069f56c0 cred=0xffff8880069f56c0`
  - `capability sets overwritten`
  - `now uid/gid/euid/egid: 0/0/0/0`
- Final trace pattern:
  - Successful attempt had `cnxret` at timestamp `86.617030` for `sk=0xffff8880226a8480`, `old=0xffff88802273d780`, `old_ref=1`, normal `ip_dst_ops`.
  - `sk_dst_check` at timestamp `87.644862` saw the same dst reclaimed as fake dst with `ref=1`, `obs=1`, `ops=0xffffffff836a9c40`, `flags=0xffff`.
  - `skgot` incremented fake dst ref to 2.
  - `sknull` returned NULL.
  - `cnxassign` ran at timestamp `93.026252`.
- Current-source conclusion:
  - The present `exp_x86.c` can get root on the kprobe-assisted path.
  - It needs cleanup-miss handling tightened. For current debug runs, the stable wrapper recipe is:
    - leak vuln pipes on clean misses;
    - only accept high `FIONREAD` values in the pipe-page pattern range;
    - raise pipe fd/page limits if many misses are expected.
  - Longer-term source fixes should avoid closing suspect pipe state after any invalid-free attempt and should avoid scanning stale leaked pipes as candidates unless the pipe-buffer probe can be validated safely.

## 2026-05-07 kprobe minimization

### Goal
- Remove kprobes until the current-source debug path stops working.
- Keep the same stable current-source wrapper settings:
  - `--smp 2`
  - `mtu_expires=1`
  - 1024 CFS CPU1 blockers
  - `BAD_DST_LEAK_VULN_PIPES_ON_CLEAN_FAIL=1`
  - `BAD_DST_PIPE_CORRUPT_FIONREAD_MIN=0xc0000000`
  - raised fd and pipe page limits before dropping privileges

### cnxret-only
- Folder:
  - `old/2026-05-07_current_source_kprobe_only_cnxret_getroot_smp2/`
- Kprobe set:
  - only `sock_setsockopt+0xf00` (`cnxret`)
- Result:
  - `pipefail=1`
  - `arb=1`
  - `root=1`
  - Arb/RW and root reached on attempt 2.
- Relevant output:
  - Attempt 1 reached invalid free and produced `dst_release underflow`, but missed pipe overlap.
  - Attempt 2:
    - `found corrupted pipe FIONREAD source=current index=2 size=0xc3c3c3c3`
    - `pipe probe leak accepted: page_index=135 probe=0x2b8 pipe_base=0x240 active_before=3 page=0xffffea000088b4c0 ops=0xffffffff827bf740 offset=0x0 len=0x4 flags=0x4141414100000010`
    - `Arb R/W setup`
    - `found current task: 0xffff888006de9c80`
    - `current task creds: real_cred=0xffff888006ceb840 cred=0xffff888006ceb840`
    - `capability sets overwritten`
    - `now uid/gid/euid/egid: 0/0/0/0`
- Trace:
  - exactly two `cnxret` events, both with `old_ref=1`.
  - No `sk_dst_check`, `cnxassign`, or metadata kprobes were active.

### No kprobes
- Folder:
  - `old/2026-05-07_current_source_no_kprobe_getroot_smp2/`
- Kprobe set:
  - none; `kprobe_events.actual` is empty.
- Result:
  - `pipefail=6`
  - `arb=0`
  - `root=0`
  - Reached `BAD_DST_MAX_ATTEMPTS=96` without winning.
- Behavior:
  - Most attempts were `race miss after timer: trigger already returned`.
  - A few lock-held candidates occurred late in the sweep, but all missed pipe corruption.
- Interpretation:
  - The current minimal kprobe-assisted setup is `cnxret` alone.
  - Removing `cnxret` makes the race much less reliable in this wrapper: it can sometimes freeze a lock-held socket, but did not reach the stale-dst invalid-free plus pipe-page overlap within 96 attempts.
  - This strongly suggests the useful debug effect is the probe cost at `sock_setsockopt+0xf00`, immediately after the vulnerable `dst_release()` return and before the `sk_dst_cache = NULL` assignment.

## 2026-05-07 project logging/checkpoint skill

### Checkpoint
- Created a pre-edit checkpoint:
  - `old/2026-05-07_before_running_log_checkpoint_skill/`
- Contents:
  - `RUNNING_LOG.md`
  - `exp_x86.c`
  - `bad_dst_cache`

### Change
- Added `SKILL.md` in the exploit source directory.
- Purpose:
  - Tell future agents how to update `RUNNING_LOG.md`.
  - Tell future agents how to create descriptive milestone checkpoints.
  - In the skill text, the checkpoint role is named `checkpoints/`; it notes that this checkout may still use `old/` on disk.

### Notes
- No exploit code was changed for this task.
- Existing checkpoint directory naming on disk was preserved.

## 2026-05-07 generic exploit skill update

### Checkpoint
- Created a pre-edit checkpoint:
  - `old/2026-05-07_before_generic_exploit_skill_update/`
- Contents:
  - `RUNNING_LOG.md`
  - `SKILL.md`

### Change
- Updated `SKILL.md` to be generic for exploit development and vulnerability research.
- Removed project-specific/tool-specific wording from the skill body and metadata.
- The skill now describes generic experiment logging, artifact capture, checkpoints, staging, and final-response checks.

## 2026-05-07 no-cnxret race/reclaim experiments

### Goal
- Try to get the exploit working without the `sock_setsockopt+0xf00` (`cnxret`) kprobe.
- Avoid probes that extend the vulnerable window between `ipv4_negative_advice()` returning and `sk_dst_cache = NULL`.
- Record a durable note for the best minimal kprobe-assisted root run.

### Disassembly check
- Confirmed with `gdb -batch -ex 'file new_kernel/vmlinux' -ex 'disassemble /r sock_setsockopt'`:
  - `sock_setsockopt+0xef8`: immediately before the negative-advice indirect call setup.
  - `sock_setsockopt+0xefb`: indirect call into `ipv4_negative_advice`.
  - `sock_setsockopt+0xf00`: return from negative advice, before assignment.
  - `sock_setsockopt+0xf09`: actual `mov %rax,0x138(%rbx)` assignment to `sk_dst_cache`.
  - `sock_setsockopt+0xf10`: after assignment.
- Interpretation:
  - The old `cnxret` probe at `+0xf00` directly extends the useful race window.
  - A probe at `+0xf09` would also extend the window because it fires before executing the store.
  - A post-assignment probe at `+0xf10` should not extend the target window, but can still create misleading lock-held oracles because the socket lock is held after `sk_dst_cache` is already NULL.

### Best kprobe-assisted note
- Added `NOTE.md`.
- It records the best minimal kprobe root run:
  - `old/2026-05-07_current_source_kprobe_only_cnxret_getroot_smp2/`
  - only `cnxret` active
  - `pipefail=1`, `arb=1`, `root=1`
  - root on attempt 2

### No cnxret, debug probes outside/after target window
- Folder:
  - `old/2026-05-07_no_cnxret_precall_afterassign_skcheck_smp2/`
- Probes:
  - `sock_setsockopt+0xef8` before the negative-advice call
  - `sock_setsockopt+0xf10` after assignment
  - post-race `sk_dst_check` metadata probes
- Result:
  - Many lock-held candidates and some `dst_release underflow` warnings.
  - No Arb/RW or root before leaked vuln pipe registry pressure.
- Interpretation:
  - This is useful debugging evidence, but `+0xf10` still changes post-window socket-lock timing and can inflate false lock-held candidates.

### No cnxret, precall-only debug probe
- Folder:
  - `old/2026-05-07_no_cnxret_precall_only_smp2/`
- Probe:
  - only `sock_setsockopt+0xef8`
- Result:
  - Some candidates and one `dst_release underflow` around attempt 66.
  - No Arb/RW or root before leaked vuln pipe registry pressure.
- Interpretation:
  - A pre-call probe can perturb timing enough to occasionally land the stale-dst invalid-free path, but did not produce pipe-page overlap in this run.

### No cnxret, no kprobes, early timer sweep
- Folder:
  - `old/2026-05-07_no_cnxret_no_kprobe_earlytimer_smp2/`
- Kprobes:
  - none; `kprobe_events.actual` is empty and trace has no kprobe events.
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
- Relevant output:
  - `found corrupted pipe FIONREAD source=current index=7 size=0xc3c3c3c3`
  - `pipe probe leak accepted: page_index=114 probe=0x5b8 pipe_base=0x540 active_before=3 page=0xffffea0000910e40 ops=0xffffffff827bf740 offset=0x0 len=0x4 flags=0x4141414100000010`
  - `Arb R/W setup`
  - `now uid/gid/euid/egid: 0/0/0/0`
- Kernel evidence:
  - A `dst_release underflow` warning occurred earlier in the same run, from `ipv4_negative_advice -> sock_setsockopt+0xf00`, confirming the exact stale-dst invalid-free path can be reached without probes.
- Interpretation:
  - `cnxret` is not strictly required.
  - The early timer sweep can get root with no kprobes on the preempt test kernel.
  - Reliability is still poor because the race can land without the final pipe-page overlap lining up.

### No cnxret, no kprobes, early timer repeat
- Folder:
  - `old/2026-05-07_no_cnxret_no_kprobe_earlytimer_repeat_smp2/`
- Wrapper delta:
  - same no-kprobe early timer sweep
  - stopped at 30 pipe-corruption misses to avoid leaked vuln pipe registry exhaustion
- Result:
  - `pipefail=30`
  - `arb=0`
  - `root=0`
  - `race candidate: lock held` count: 30
  - `race miss after timer` count: 36
  - `dst_release underflow` count: 0
- Interpretation:
  - This repeat did not reproduce root.
  - Because `BAD_DST_LOCK_ORACLE=0`, the `lock oracle: skipped` candidates include false positives where the trigger had not returned but was not necessarily stopped inside the useful stale-dst window.

### No cnxret, no kprobes, early timer plus lock oracle
- Folder:
  - `old/2026-05-07_no_cnxret_no_kprobe_earlytimer_lockoracle_smp2/`
- Wrapper delta:
  - same early timer sweep
  - `BAD_DST_LOCK_ORACLE=1`
  - stopped at 30 pipe-corruption misses
- Result:
  - `pipefail=30`
  - `arb=0`
  - `root=0`
  - `lock oracle: blocked` count: 30
  - `race miss after timer` count: 41
  - `dst_release underflow` count: 1
- Relevant evidence:
  - Attempt 66 had `lock oracle: blocked`.
  - Kernel logged `dst_release underflow` from `ipv4_negative_advice -> sock_setsockopt+0xf00`.
- Interpretation:
  - The no-`cnxret` path can hit the exact stale-dst invalid-free even with no kprobes.
  - The current blocker is reclaim/pipe-buffer overlap reliability after a landed race, not whether the race can ever land.
  - The lock oracle is a useful unprivileged filter for debugging and does not install probes in the vulnerable instruction window, but it did not improve overlap in this bounded run.
