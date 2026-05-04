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
