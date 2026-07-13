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

## 2026-05-07 05:54 EDT - kmalloc-256/pipe reclaim reliability pass

Goal:

- Closely re-read the relevant SLUB reclaim and buddy allocator code, then tune spray/pipe constants if there is a clear allocator reason to do so.

Kernel allocator observations:

- `fs/pipe.c::pipe_resize_ring()` uses `kcalloc(nr_slots, sizeof(struct pipe_buffer), GFP_KERNEL_ACCOUNT | __GFP_NOWARN)`, copies active slots, then `kfree()`s the old ring.
- On x86_64, `struct pipe_buffer` is 40 bytes, so a 4-slot pipe ring is 160 bytes.
- The test kernel source has the local x86 patch `ARCH_DMA_MINALIGN=128`. With `KMALLOC_MIN_SIZE=128`, `kmalloc_index()` maps 160-byte requests to index 8 (`kmalloc-256`), and `setup_kmalloc_cache_index_table()` also redirects 136..192 byte allocations to the 256-byte cache. `strings vmlinux` can still show `kmalloc-192`, but this exploit's 160-byte pipe ring should allocate from `kmalloc-256` on the patched x86 build.
- `mm/slub.c::__slab_free()` freezes a previously full, non-current slab page and puts it on the current CPU partial list when CPU partials are enabled. For 256-byte objects, `slub_cpu_partial()` allows about 13 partial objects per CPU before flushing to the node partial list.
- `free_spray()` can only release the page to the page allocator if all live objects in that kmalloc-256 slab page are freed. If the original rtable slab page still contains non-spray live objects, page-pipe backing pages cannot overwrite the fake pipe ring even when the fake unaligned free and pipe-ring allocation succeeded.
- `mm/page_alloc.c::free_unref_page_commit()` and `rmqueue_pcplist()` route order-0 frees/allocations through per-CPU page lists. Pipe backing pages are allocated from `alloc_page(GFP_HIGHUSER | __GFP_ACCOUNT)` in the pipe write path; `GFP_HIGHUSER` here is not movable, so a simple migratetype mismatch is probably not the main explanation for misses.
- Best successful pipe bases were both offset `0x40` within a 0x100 sendmsg cmsg object:
  - kprobe-assisted root: `pipe_base=0x240`
  - no-kprobe root: `pipe_base=0x540`
  This supports offset 64 as the good fake-dst placement. Offset 128 crosses the 256-byte object boundary for a 160-byte pipe ring and is probably less clean, but mixed 64/128 payloads can still be useful because many candidates are false positives and mixed payloads may avoid a destructive fake-free on misses.

Source/constant changes:

- Checkpoint before edits: `old/2026-05-07_before_reclaim_reliability_tuning/`.
- Raised runtime headroom in `exp_x86.c`:
  - `MAX_PAGE_PIPES`: `0xc00 -> 0x1800`
  - `MAX_VULN_PIPES`: `0x100 -> 0x400`
  - added SMP default/cap plumbing so large runs can request more pipes without rebuilding.
- Preserved the known-good SMP default page-pipe count at `0xc00` while raising the max to `0x1800`. The previous best kprobe-assisted root run already used `page=3072 vuln=256`; the important source change is preventing the raised max from also becoming the implicit SMP default.
- Rebuilt `bad_dst_cache` with `nix-shell -p glibc.static --run ./compile_x86.sh`; build succeeded with the existing `ssize_t`/ignored-return warning noise.

Experiments:

- `old/2026-05-07_reclaim_tune_fixed64_cpu0resize_smp2/`
  - Old binary, no kprobes, lock oracle wrapper.
  - Forced `BAD_DST_FAKE_DST_OFFSET=64`, disabled mixed/auto offset, forced `BAD_DST_VULN_PIPE_RESIZE_PERCPU=0`.
  - Result: first candidate reached `FAIL: could not corrupt pipe`, then `FAIL: trigger did not release after failed candidate`. VM was killed; serial log is authoritative.

- `old/2026-05-07_reclaim_tune_fixed64_only_smp2/`
  - Old binary, fixed offset 64 only, per-CPU pipe resize left enabled.
  - Result: same immediate pipe miss and unreleased trigger after first candidate.

- `old/2026-05-07_reclaim_tune_large_fixed64_cpu0resize_smp2/`
  - New binary with raised caps.
  - `BAD_DST_PAGE_PIPES=6144`, `BAD_DST_VULN_PIPES=1024`, fixed offset 64, CPU0-only resize.
  - Result: first candidate used `page=6144 vuln=1024`, reached `FAIL: could not corrupt pipe`, leaked 1024 vuln pipes, then trigger did not release. Larger pipe volume did not fix overlap.

- `old/2026-05-07_reclaim_tune_no_post_churn_mixed_smp2/`
  - New binary, no kprobes, mixed offsets, lock oracle, `BAD_DST_POST_RTABLE_CHURN_CPUS=0`, `BAD_DST_POST_RTABLE_CHURN_ROUNDS=0`.
  - Result: first candidate used `page=3072 vuln=256`, reached pipe miss and unreleased trigger. No `dst_release` warning was observed in the serial log, so this may still be a false lock-oracle candidate.

- `old/2026-05-07_reclaim_tune_current_cnxret_mixed_smp2/`
  - New binary with raised caps, known `cnxret` debug probe, mixed offsets.
  - Result: first candidate used `page=3072 vuln=256`, reached pipe miss and unreleased trigger. This did not reproduce the previous best kprobe-assisted root run, but comparison showed the page/vuln counts matched the best run; the miss is from current timing/state differences, not the 3072 page-pipe count itself.

- `old/2026-05-07_reclaim_tune_restored_page_default_cnxret_smp2/`
  - Intermediate correction run while checking the default. It used `page=1536 vuln=256`, reached pipe miss, and left the trigger unreleased.
  - This run is not a recommended configuration; the actual best-run comparison showed the successful kprobe path used `page=3072 vuln=256`, so the source was corrected again to keep SMP default `0xc00`.

Current interpretation:

- Pipe count by itself is not the main reclaim reliability blocker. 6144 page pipes and 1024 vulnerable pipe rings still missed on the first candidate.
- The likely allocator failure mode is that the fake pipe ring allocation can land in an unaligned fake-freed cmsg object, but the containing kmalloc-256 slab page does not become fully free when sprayed cmsgs are drained. If any rtable or unrelated kmalloc-256 object remains live on that page, buddy/page-pipe reclaim will not overwrite it.
- Another practical issue is candidate quality: the lock oracle can still produce candidates that are "socket lock blocked" without a confirmed stale-dst invalid-free. Running reclaim on those false candidates can leave the trigger unreleasable.
- Keep offset 64 as the clean target for allocator reasoning, but mixed 64/128 remains useful in the current retry loop because it seems less likely to make every false candidate destructive.

Next allocator-focused ideas:

- Add runtime knobs for the pre/post rtable socket counts so the rtable slab page can be groomed more deliberately without recompiling.
- Test reducing or disabling the post-rtable pipe churn only in a run where the race is confirmed by a non-window-expanding oracle; the no-post-churn run here did not confirm the stale-dst invalid-free.
- Consider a debug-only allocator trace around `kfree`/`kmem_cache_alloc`/`__free_pages` or SLUB statistics, but avoid carrying those probes into the final exploit because they will perturb allocation order.
- If continuing with no-kprobe operation, improve the candidate oracle before doing expensive reclaim, otherwise many failed allocator runs are probably polluted by false race candidates.

## 2026-05-07 - rtable slab-page purity knobs

Goal:

- Address the suspected slab-page purity issue: the fake pipe ring may be placed into an unaligned fake-freed cmsg object, but the containing kmalloc-256 page may still have live objects and therefore never be returned to buddy for pipe backing-page reclaim.

Source changes:

- Checkpoint before edits: `old/2026-05-07_before_post_before_pipe_groom/`.
- Added bounded runtime knobs in `exp_x86.c`:
  - `BAD_DST_BASE_PRE_SOCKETS` capped by `MAX_BASE_PRE_SOCKETS=4096`.
  - `BAD_DST_ALIGN_PAD_SPAN` capped by `MAX_ALIGN_PAD_SOCKETS=128`.
  - `BAD_DST_POST_SOCKETS` capped by `MAX_POST_SOCKETS=1024`.
- Added `BAD_DST_OPEN_POST_BEFORE_PIPE_PREP`.
  - When set, post sockets are opened immediately after the vulnerable socket and before optional pre-race pipe preparation.
  - Hypothesis: on the patched x86 kernel, prepared 4-slot pipe rings are kmalloc-256; if they are allocated after the vulnerable rtable but before post sockets, they can occupy the same slab-page tail that should instead be filled with closeable rtable objects.
- Added logging/tracing for rtable groom config and post-socket open timing.
- Rebuilt `bad_dst_cache`; build succeeded with the existing warning set.

Experiments:

- `old/2026-05-07_post_before_pipe_cnxret_smp2/`
  - Known `cnxret` wrapper plus `BAD_DST_OPEN_POST_BEFORE_PIPE_PREP=1`.
  - Runtime: `base_pre=1792 align_span=21 post=256 post_before_pipe=1`.
  - Result: first candidate reached `FAIL: could not corrupt pipe`, then `FAIL: trigger did not release after failed candidate`.

- `old/2026-05-07_post_before_pipe_fixed64_post1024_cnxret_smp2/`
  - Same post-before-pipe ordering, `BAD_DST_POST_SOCKETS=1024`, fixed fake-dst offset 64.
  - Runtime: `base_pre=1792 align_span=21 post=1024 post_before_pipe=1`.
  - Result: first candidate reached pipe miss and unreleased trigger.

- `old/2026-05-07_prepare_pipes_after_candidate_cnxret_smp2/`
  - Disabled pre-race pipe preparation: `BAD_DST_PREPARE_PIPES_BEFORE_RACE=0`.
  - Ordering: pre sockets, vulnerable socket, race candidate, post sockets, then pipe preparation inside `try_run_main_exploit()`.
  - Result: first candidate reached pipe miss and unreleased trigger.

- `old/2026-05-07_cnxret_align1_current_smp2/`
  - Fixed `BAD_DST_ALIGN_PAD=1` to skip the historically bad first alignment candidate.
  - Result: first candidate with `align_pad=1 pre=1793 post=256` still reached pipe miss and unreleased trigger.

Current interpretation:

- The new knobs are useful and should stay; they make the rtable page layout testable without rebuilding.
- These allocator-ordering changes did not, by themselves, fix the overlap. That weakens the "prepared pipes are contaminating the target slab page tail" hypothesis.
- The repeated first-candidate wedge means many of these runs may still be executing reclaim on candidates that are not confirmed stale-dst invalid-frees. The next useful debugging step is probably a confirmation oracle for the fake invalid-free/page-free path, not more blind pipe-count or post-socket sweeps.
- A debug-only allocator trace around the fake-free/reclaim phase, or a root-only tracepoint/kprobe counter for the exact stale-dst invalid-free plus slab-page discard, would be the fastest way to distinguish "fake pipe ring not allocated" from "ring allocated but slab page not discarded".

## 2026-05-07 13:41 EDT - kprobe race-window debugging

Goal:

- Use tracefs kprobes to separate false lock-oracle candidates from real SO_CNX_ADVICE race-window hits, and measure whether the userspace timing is reaching the narrow window before `sk_dst_cache` is assigned NULL.

Probe setup and confirmed offsets:

- `sock_setsockopt`: `ffffffff81c054a0`
- `dst_release`: `ffffffff81c2cd80`
- `metadata_dst_free`: `ffffffff81c2ce40`
- `ipv4_negative_advice`: `ffffffff81d8c310`
- `ipv4_dst_check`: `ffffffff81d8b890`
- `sock_setsockopt+0xec8`: SO_CNX_ADVICE negative-advice path entry.
- `sock_setsockopt+0xf00`: return from `ipv4_negative_advice`; this is the useful `cnxret` window where the old dst has had its refcount dropped but `sk_dst_cache` still points at it.
- `sock_setsockopt+0xf09`: assignment of the returned NULL to `sk_dst_cache`.

Checkpoints and experiments:

- `old/2026-05-07_alloc_kprobe_debug_cnxret_smp2/`
  - Heavy allocator/free/page probes plus old `cnxret`.
  - One candidate reached the reclaim path but no root.
  - `cnxret=0`, `metadata_dst_free=0`; this candidate was not a confirmed vulnerable-window hit.

- `old/2026-05-07_path_kprobe_debug_smp2/`
  - Path probes on `sock_setsockopt`, SO_CNX offsets, `ipv4_negative_advice`, `dst_release`, `metadata_dst_free`, and `ipv4_dst_check`.
  - Stopped after first MSG_PROBE diagnostic.
  - No `cnx*`, no `negadv`, no `metadata_dst_free`.
  - MSG_PROBE saw a normal IPv4 rtable with `obs=2` and normal IPv4 dst ops, then `dst_release` from ref 2 to ref 1. This was another false candidate.

- `old/2026-05-07_path_kprobe_lockoracle_msgprobe_loop_smp2/`
  - Same path probes, default fork-based lock oracle.
  - Found a major oracle issue: the fork child closes thousands of inherited fds before reaching `getsockopt()`, so the 50 ms timeout can report `blocked` even when the child is only slow in fd cleanup.
  - Use `BAD_DST_LOCK_ORACLE_THREAD=1` for this debugging, or disable inherited-fd cleanup with `BAD_DST_LOCK_ORACLE_CLOSE_FDS=0` if the fork oracle is kept.

- `old/2026-05-07_path_kprobe_thread_lockoracle_smp2/`
  - Switched to pthread lock oracle.
  - Attempt 1 reported `done_ok` instead of a false block, which confirms the fork-oracle false-positive diagnosis.
  - With 1024 CPU1 blocker threads, an early/late miss can wedge release because the SCHED_IDLE trigger does not promptly run after the CFS blockers wake/sleep.

- `old/2026-05-07_path_kprobe_thread_lockoracle_128block_smp2/`
  - Reduced to 128 blockers and a longer release timeout.
  - Completed 80 attempts without a root candidate.
  - `cnxenter`, `cnxret`, `cnxassign`, `negadv`, and `negadvret` all fired 80 times, but after main had already classified/released the attempt.
  - Confirmed the real refcount transition: `ipv4_negative_advice` enters with ref 2 and normal IPv4 ops; at `cnxret`, the old dst has ref 1 and the returned new dst is NULL; `cnxassign` then clears `sk_dst_cache`.

- `old/2026-05-07_path_kprobe_pulse_sweep_128block_smp2/`
  - Added a broad scheduler pulse sweep: 24 pulse lengths from 1.0 ms upward in 0.5 ms steps, 128 blockers, pthread oracle.
  - Completed 80 attempts with no MSG_PROBE candidate and no `metadata_dst_free`.
  - The pulse can drive the trigger through the SO_CNX path, but most hits finished before the main thread froze/checked the socket. Example timing: `cnxret` roughly 685 us after pulse start and `cnxassign` roughly 50 us later.

- `old/2026-05-07_path_kprobe_pulse_fine_128block_smp2/`
  - Fine sweep: 40 pulse lengths from 600 us upward in 25 us steps, no settle delay, 100 attempts.
  - No candidate/root, no `metadata_dst_free`.
  - `cnx*` and `negadv*` fired on every attempt.
  - Results split between too early, too late, and trigger-already-returned. No blocked pthread oracle was captured.

Current interpretation:

- The SO_CNX_ADVICE race path and kprobe offsets are correct. The critical state exists: after `ipv4_negative_advice` returns NULL, the old rtable has refcount 1 while `sk_dst_cache` still points to it, until the assignment at `sock_setsockopt+0xf09`.
- The previous fork-based lock oracle produced false positives because fd cleanup in the forked child can exceed the timeout. The pthread oracle is the cleaner debug oracle.
- With the current userspace scheduling strategy, timing misses are the immediate blocker. The trigger usually reaches `cnxret` only after the main thread has already judged the attempt too early, or it runs all the way through `cnxassign` before the main thread checks.
- The measured kprobe-assisted `cnxret -> cnxassign` interval is on the order of tens of microseconds and noisy. Tracefs kprobes can observe and slightly perturb this, but plain tracefs kprobes cannot deliberately park the triggering task inside the window. Doing that would require a custom kprobe handler path such as a debug kernel module or equivalent programmable instrumentation; that is useful for diagnosis but should not become part of the final exploit.
- No current kprobe-debug run observed `metadata_dst_free`, so these runs did not reach the later fake-dst invalid-free/root payload stage.

Next ideas:

- Keep using the pthread lock oracle for race-window debugging and avoid fork-oracle fd cleanup unless its timeout is made much larger.
- Try a less noisy hold/release mechanism than the current blocker-thread pulse: fewer blockers, futex-controlled blockers, or priority changes that let the trigger run into `cnxret` but delay return to userspace.
- For debug-only validation, a programmable probe/module that parks specifically at `sock_setsockopt+0xf00` would answer whether the reclaim/root path is still healthy when the exact race window is forced. Do not rely on that in the final exploit.

## 2026-05-07 15:17 EDT - timerfd/pre-syscall grid and SMP3 oracle CPU

Goal:

- Remove the scheduler pulse from the current race attempt and sweep two timing axes instead: coarse timerfd expiry and a fine pre-syscall busy delay in the trigger thread.
- Test the same root-enabled run on `--smp 3` with the pthread socket-lock oracle pinned to CPU2, so the oracle does not contend with the main thread, trigger thread, or CPU1 blocker set.

Source changes:

- Checkpoint before the timer/pre-syscall grid change: `old/2026-05-07_before_timer_presyscall_grid/`
- Added opt-in `BAD_DST_DELAY_GRID_SWEEP=1`. With this enabled, `BAD_DST_PRE_SYSCALL_DELAY_*` advances once per full timer sweep instead of diagonally changing both delay dimensions every attempt.
- Checkpoint before the oracle CPU pinning change: `old/2026-05-07_before_oracle_cpu_pin/`
- Added opt-in `BAD_DST_LOCK_ORACLE_CPU`. When set with `BAD_DST_LOCK_ORACLE_THREAD=1`, the pthread oracle pins itself to that CPU before running the `getsockopt()` lock check.
- Rebuilt with `nix-shell -p glibc.static --run './compile_x86.sh && ./compile_x86_clean.sh'`; build succeeded with the existing warning noise only.

Checkpoint and run:

- Main checkpoint/artifacts: `old/2026-05-07_timer_presyscall_grid_oraclecpu2_root_smp3/`
- Host console log: `old/2026-05-07_timer_presyscall_grid_oraclecpu2_root_smp3.log`
- Run used `testvm run new_kernel/bzImage --nokaslr --smp 3 --memory 1G --network tap ... --share-mode ext4 --sync-share-back`.
- Key runtime knobs:
  - `BAD_DST_RACE_PULSE_SWEEP_COUNT=0`
  - `BAD_DST_RACE_PULSE_NS=0`
  - `BAD_DST_DELAY_GRID_SWEEP=1`
  - `BAD_DST_TIMER_SWEEP_START_NS=85000`
  - `BAD_DST_TIMER_SWEEP_STEP_NS=2048`
  - `BAD_DST_TIMER_SWEEP_COUNT=16`
  - `BAD_DST_PRE_SYSCALL_DELAY_SWEEP_COUNT=12`
  - `BAD_DST_PRE_SYSCALL_DELAY_START_NS=35000`
  - `BAD_DST_PRE_SYSCALL_DELAY_STEP_NS=5000`
  - `BAD_DST_LOCK_ORACLE_THREAD=1`
  - `BAD_DST_LOCK_ORACLE_CPU=2`
  - `BAD_DST_LOCK_ORACLE_US=50000`
  - `BAD_DST_GET_ROOT=1`
  - `BAD_DST_RUN_ROOT_PAYLOAD=1`

Result:

- `mtu_expires` was confirmed as `1`.
- Kprobe setup errors were empty.
- 192 attempts completed.
- Pthread lock oracle results from `exploit.log`:
  - `done_ok`: 70
  - `done_err`: 122
  - `blocked`: 0
- Miss classification:
  - `too_early`: 70
  - `too_late`: 122
  - race candidates: 0
- Kprobe trace counts:
  - `cnxenter`: 192
  - `cnxret`: 192
  - `cnxassign`: 192
  - `negadv`: 192
  - `negadvret`: 192
  - `metadata_dst_free`: 0
- No fake-free/reclaim/root stage was reached:
  - `candidate_count`: 0
  - `pipe_fail_count`: 0
  - `arb_rw_count`: 0
  - `root_count`: 0

Current interpretation:

- SMP3 plus a dedicated oracle CPU made the oracle cleaner, but did not make the race land.
- This is not a pipe-buffer or allocator reclaim failure in this run. The exploit never reached a confirmed vulnerable-window candidate and never hit `metadata_dst_free`.
- The trace proves the trigger executes the SO_CNX negative-advice path every attempt. At `cnxret`, old dst refcount is 1 and the returned dst is NULL, but the userspace freeze/oracle still misses the short interval before `sk_dst_cache` is assigned NULL.
- This grid skewed late overall: 122 late misses vs 70 early misses. If continuing this exact approach, the next sweep should shift timing earlier or improve the CPU1 hold/release mechanism rather than changing pipe spray constants.

## 2026-05-07 15:41 EDT - kprobe-derived timer/pre-syscall delay adjustment

Goal:

- Adjust the timerfd and pre-syscall delay settings based on the previous SMP3 kprobe timing trace.
- In the prior trace, near misses clustered by the effective value `timer_offset - pre_syscall_delay`, mostly in the tens of microseconds. The successful no-kprobe run also hit at `timer_offset=41384` with `pre_syscall_delay=0`.
- Hypothesis: the explicit pre-syscall delay is counterproductive because it often lets main wake while the trigger is still in userspace. The next useful sweep should set `pre_syscall_delay=0` and sweep timer offsets directly around the effective 20-100 us window.

Trace-derived timing observations:

- In `old/2026-05-07_timer_presyscall_grid_oraclecpu2_root_smp3/share/trace.txt`, 36 attempts had the lock-oracle completion marker within 1 ms of `cnxret`.
- For those near attempts, `timer_offset - pre_syscall_delay` ranged from about 7 us to 77 us, with median about 31 us and upper quartile about 52 us.
- Many previous attempts showed `after_timer_read` while the trigger was still in `pre_syscall_delay`, confirming that the delay can freeze the trigger before `setsockopt()`.

Experiment 1: short oracle timeout, early effective sweep, SMP3

- Folder: `old/2026-05-07_adjusted_effective_timer_oracle_smp3/`
- Wrapper changes:
  - `--smp 3`
  - `BAD_DST_PRE_SYSCALL_DELAY_SWEEP_COUNT=0`
  - `BAD_DST_PRE_SYSCALL_DELAY_NS=0`
  - `BAD_DST_TIMER_SWEEP_START_NS=15000`
  - `BAD_DST_TIMER_SWEEP_STEP_NS=2048`
  - `BAD_DST_TIMER_SWEEP_COUNT=40`
  - `BAD_DST_CPU1_BLOCK_THREADS=1024`
  - `BAD_DST_LOCK_ORACLE_THREAD=1`
  - `BAD_DST_LOCK_ORACLE_CPU=2`
  - `BAD_DST_LOCK_ORACLE_US=800`
- Result:
  - First attempt at `timer_offset=15000` produced `lock oracle: blocked`.
  - It reached the reclaim path but failed pipe corruption, then failed to release the trigger.
  - Synced artifacts show 1 candidate, 1 pipe fail, 0 Arb/RW, 0 root.
  - Trace showed `sock_setsockopt` entry but no `cnxenter`, `cnxret`, `cnxassign`, `negadv`, or `metadata_dst_free`.
- Interpretation:
  - The shorter oracle timeout detects a lock hold, but the first offset parked the trigger too early, before the SO_CNX negative-advice path.

Experiment 2: later timer sweep, short oracle timeout, SMP3

- Folder: `old/2026-05-07_adjusted_later_timer_oracle_smp3/`
- Host console log: `old/2026-05-07_adjusted_later_timer_oracle_smp3.log`
- Wrapper changes from experiment 1:
  - `BAD_DST_CPU1_BLOCK_THREADS=128`
  - `BAD_DST_TIMER_SWEEP_START_NS=45000`
  - `BAD_DST_TIMER_SWEEP_STEP_NS=2048`
  - `BAD_DST_TIMER_SWEEP_COUNT=32`
  - `BAD_DST_LOCK_ORACLE_US=800`
- Result:
  - Killed manually after the leaked vuln pipe registry filled; the guest did not power off cleanly, so only the host console log is reliable.
  - 33 candidates, 33 pipe corruption misses, 0 Arb/RW, 0 root.
  - The diagnostic stages were still broad and early: many attempts reported `timer_armed` or `setsockopt_enter`, not a confirmed `cnxret` stage.
- Interpretation:
  - An 800 us lock-oracle timeout is too aggressive as a candidate gate. It turns normal socket-lock acquisition before SO_CNX negative advice into false candidates.

Experiment 3: no lock oracle, no pre-syscall delay, refined early timer sweep, SMP2

- Folder: `old/2026-05-07_adjusted_timer_no_oracle_smp2/`
- Host console log: `old/2026-05-07_adjusted_timer_no_oracle_smp2.log`
- Wrapper changes:
  - Based on the prior successful no-kprobe SMP2 wrapper.
  - `BAD_DST_LOCK_ORACLE=0`
  - `BAD_DST_PRE_SYSCALL_DELAY_SWEEP_COUNT=0`
  - `BAD_DST_PRE_SYSCALL_DELAY_NS=0`
  - `BAD_DST_TIMER_SWEEP_START_NS=25000`
  - `BAD_DST_TIMER_SWEEP_STEP_NS=2048`
  - `BAD_DST_TIMER_SWEEP_COUNT=40`
  - `BAD_DST_CPU1_BLOCK_THREADS=1024`
- Result:
  - First attempt at `timer_offset=25000` became a broad candidate and missed pipe corruption.
  - The trigger did not release after the failed candidate, so the VM was killed manually.
  - 1 candidate, 1 pipe fail, 0 Arb/RW, 0 root.

Current interpretation:

- The correct adjustment from the kprobe timing is still to remove the pre-syscall delay and sweep the effective timer window directly. That part is sound.
- The short lock-oracle timeout is useful as a diagnostic for millisecond-scale socket-lock holds, but it is not a good success oracle: it accepts states before `cnxret`.
- These runs did not disprove the old no-kprobe root timing. They show that the current wrappers can get trapped by early broad candidates and unreleased trigger state before enough offsets are explored.
- A better next wrapper should avoid spending the full reclaim path on candidates whose trigger stage is only `woken`, `timer_armed`, or `setsockopt_enter`. Either require a stronger debug-only `cnxret` confirmation when tuning, or add a cheap candidate rejection path for pre-SO_CNX stages before running the expensive spray/reclaim.

## 2026-05-07 15:58 EDT - fixed-delay variance measurement at timer_offset=41384

Goal:

- Measure variance when repeating one particular timing point instead of sweeping.
- Use the old successful no-kprobe timing point, `timer_offset=41384` and `pre_syscall_delay=0`, but run in a measurement-only mode so allocator/reclaim noise does not dominate the timing data.

Checkpoint:

- `old/2026-05-07_before_fixed_delay_measure_mode/`
- Contains the source, binaries, and log before adding the temporary measurement-only mode.

Source/build change:

- Added opt-in `BAD_DST_MEASURE_TIMING_ONLY=1` handling in the real race loop.
- In this mode, after timerfd wake and CPU migration, the main thread emits a `measure_release` trace marker, releases the frozen trigger, waits for it to finish, emits `measure_done`, cleans the per-attempt sockets/pipes/sprays, and continues.
- Rebuilt `bad_dst_cache` and `bad_dst_cache_clean` with `nix-shell -p glibc.static --run './compile_x86.sh && ./compile_x86_clean.sh'`.

Experiment 1: SMP2, 1024 blockers

- Folder: `old/2026-05-07_fixed_delay_variance_41384_smp2/`
- Host console log: `old/2026-05-07_fixed_delay_variance_41384_smp2.log`
- Wrapper settings:
  - `--smp 2`
  - `BAD_DST_TIMER_SWEEP_START_NS=41384`
  - `BAD_DST_TIMER_SWEEP_STEP_NS=0`
  - `BAD_DST_TIMER_SWEEP_COUNT=1`
  - `BAD_DST_PRE_SYSCALL_DELAY_SWEEP_COUNT=0`
  - `BAD_DST_PRE_SYSCALL_DELAY_NS=0`
  - `BAD_DST_CPU1_BLOCK_THREADS=1024`
  - `BAD_DST_MEASURE_TIMING_ONLY=1`
  - `BAD_DST_MAX_ATTEMPTS=200`
- Result:
  - Failed on attempt 1.
  - The trigger stage was `woken` with `armed=-1`, meaning the timer fired before the trigger had recorded the timer-armed timestamp.
  - The trigger did not release within the measurement timeout.
- Interpretation:
  - 1024 CPU1 blocker threads are too heavy/noisy for this measurement mode. They can prevent reliable cleanup after an early wake.

Experiment 2: SMP3, 128 blockers

- Folder: `old/2026-05-07_fixed_delay_variance_41384_smp3_128block/`
- Host console log: `old/2026-05-07_fixed_delay_variance_41384_smp3_128block.log`
- Synced artifacts:
  - `share/exploit.log`
  - `share/trace.txt`
  - `share/kprobe_events.actual`
- Wrapper differences from experiment 1:
  - `--smp 3`
  - `BAD_DST_CPU1_BLOCK_THREADS=128`
  - `BAD_DST_TRIGGER_RELEASE_TIMEOUT_US=15000000`
- Result:
  - Completed 200 measurement attempts.
  - Reached the SO_CNX negative-advice path on all 200 attempts with kprobe markers through `cnxassign`.
  - No root/reclaim path was attempted by design.
  - `after_timer_read` stage distribution: 154 `timer_armed`, 46 `woken`.
  - `after_pin_trigger` stage distribution: 154 `timer_armed`, 46 `woken`.

Timing stats from `exploit.log` age diagnostics:

- `after_timer_read` armed age, among attempts where armed timestamp existed: n=154, median 301.5 us, p90 483.5 us, max 773 us, stdev 108 us.
- `after_pin_trigger` armed age, among attempts where armed timestamp existed: n=154, median 909.5 us, p90 1085.4 us, max 1648 us, stdev 146.1 us.
- At `after_measure_release`, armed age: n=200, median 2939.5 us, p90 10740.2 us, max 13981 us, stdev 3786.3 us.
- Approximate timer-armed to `setsockopt_enter`: n=200, median 1619.5 us, p90 9647 us, max 12674 us, stdev 3872.9 us.
- Approximate timer-armed to `setsockopt_exit`: n=200, median 2000 us, p90 9974.7 us, max 13292 us, stdev 3863.6 us.
- Approximate `setsockopt` duration: n=200, median 359.5 us, p90 689.1 us, max 12847 us, stdev 995.2 us.

Timing stats from `trace.txt` kprobe/trace markers:

- `measure_release -> cnxret`: n=200, median 880 us, p90 9017.1 us, max 13131 us, stdev 3901.1 us.
- `measure_release -> sockopt`: n=200, median 692.5 us, p90 8925.6 us, max 10939 us, stdev 3899.2 us.
- `sockopt -> cnxret`: n=200, median 120 us, p90 368.1 us, max 3326 us, stdev 268 us.
- `cnxret -> cnxassign`: n=200, median 39 us, p90 117.3 us, max 1612 us, stdev 132.5 us.
- `after_timer_read -> after_pin_trigger`: n=200, median 396 us, p90 664.1 us, max 1204 us.
- `after_pin_trigger -> measure_release`: n=200, median 49 us, p90 73 us, max 572 us.

Interpretation:

- Repeating a single fixed delay is measurable and useful. At `timer_offset=41384` with 128 blockers, the dominant variance is scheduler wakeup/CPU1 contention after release, not the fixed nanosecond timer value itself.
- The distribution is bimodal: many attempts reach `cnxret` after `measure_release` in about 0.3-1 ms, while a large group lands around 8-10 ms.
- The fixed delay is therefore not stable enough to expect a narrow sub-100 us race hit under these blocker settings. It can still be useful for reproducing the old kprobe-assisted timing, but the blocker/release design needs to reduce the millisecond-scale scheduling tails before this becomes reliable without kprobes.

## 2026-05-07 16:15 EDT - fixed common-window repeat exploit run

Goal:

- Try one timing point repeatedly instead of sweeping offsets, using the old no-kprobe root-success timing point and the recent fixed-delay measurement center.
- Test whether repeated attempts at the common point produce better exploit results than spending attempts across a broad sweep.

Setup/checkpoint:

- Folder: `old/2026-05-07_fixed_common_41384_repeat_root_smp3_128block/`
- Host console log: `old/2026-05-07_fixed_common_41384_repeat_root_smp3_128block.log`
- Shared artifacts: `share/run.sh`, `share/exploit.log`, counters, binary, source snapshot.
- The wrapper sets `mtu_expires=1` before `drop_exec`; the exploit itself still runs after privilege drop.
- No kprobes were installed for this run.

Wrapper parameters:

- `--smp 3`, `--memory 1G`, `--nokaslr`
- `BAD_DST_TIMER_SWEEP_START_NS=41384`
- `BAD_DST_TIMER_SWEEP_STEP_NS=0`
- `BAD_DST_TIMER_SWEEP_COUNT=1`
- `BAD_DST_PRE_SYSCALL_DELAY_SWEEP_COUNT=0`
- `BAD_DST_PRE_SYSCALL_DELAY_NS=0`
- `BAD_DST_CPU1_BLOCK_THREADS=128`
- `BAD_DST_LOCK_ORACLE=0`
- `BAD_DST_DONE_ORACLE=1`
- `BAD_DST_PREPARE_PIPES_BEFORE_RACE=1`
- `BAD_DST_FAST_CRITICAL=1`
- `BAD_DST_LEAK_VULN_PIPES_ON_CLEAN_FAIL=0`
- `BAD_DST_LEAK_VULN_PIPES_ON_FAIL=0`
- `BAD_DST_MAX_ATTEMPTS=80`
- `BAD_DST_GET_ROOT=1`
- `BAD_DST_RUN_ROOT_PAYLOAD=0`

Result:

- Completed all 80 attempts cleanly.
- Candidates: 78.
- Done/late misses: 2.
- Misses before freeze: 0.
- Pipe corruption failures: 78.
- Arb/RW successes: 0.
- Root successes: 0.
- Trigger release failures: 0.
- `mtu_expires_value=1`.
- `critical elapsed before MSG_PROBE` among the 78 candidates: median about 1,158,839 us, p90 about 1,183,525 us, min 1,140,824 us, max 1,212,698 us.

Interpretation:

- Repeating the common fixed delay substantially improves candidate volume: 78/80 attempts entered the expensive candidate path.
- It did not improve end-to-end exploit reliability in this configuration. Every candidate failed at pipe corruption, so either most candidates are still false positives, or the race is landing but the reclaim/page-overlap path is not aligned under the current SMP3/128-blocker allocator state.
- Because lock oracle was disabled, a "candidate" here means "trigger not done yet", not confirmed `cnxret`/pre-assign freeze. The fixed delay appears to be good at keeping the trigger unfinished, but this run does not prove it freezes exactly inside the refcount-decrement-before-NULL window.
- Trace markers were not captured because the no-kprobe wrapper did not make `trace_marker` writable before dropping privileges. After the run, `share/run.sh` was patched to `chmod` trace markers and to accept `bad_dst_fixed_ns=`, `bad_dst_attempts=`, `bad_dst_blockers=`, and `bad_dst_deadline=` from the kernel command line for future fixed-point trials.

Next step:

- If repeating fixed points is kept, run a small matrix of fixed offsets around 35-55 us with a stronger but non-window-changing oracle or trace-marker-only diagnostics. The current 41384 ns point is useful for candidate throughput, but not enough by itself to distinguish exact-window hits from broad unfinished-trigger states.

## 2026-05-07 16:49 EDT - fixed 41384 ns with pthread lock oracle

Goal:

- Repeat the same fixed timing point as the previous run, but enable the pthread lock oracle.
- Test whether the previous 78/80 candidates were actual socket-lock-held states or just broad "trigger not done yet" states.

Setup/checkpoint:

- Folder: `old/2026-05-07_fixed_41384_pthread_lockoracle_smp3_128block/`
- Host console log: `old/2026-05-07_fixed_41384_pthread_lockoracle_smp3_128block.log`
- Shared artifacts: `share/run.sh`, `share/exploit.log`, counters, binary, source snapshot.
- Command shape:
  - `testvm run new_kernel/bzImage --nokaslr --smp 3 --memory 1G ... --share-dir old/2026-05-07_fixed_41384_pthread_lockoracle_smp3_128block/share --share-mode ext4 --sync-share-back --autorun-vm-path /mnt/testvm-share/run.sh`

Wrapper parameters:

- `BAD_DST_TIMER_SWEEP_START_NS=41384`
- `BAD_DST_TIMER_SWEEP_STEP_NS=0`
- `BAD_DST_TIMER_SWEEP_COUNT=1`
- `BAD_DST_PRE_SYSCALL_DELAY_NS=0`
- `BAD_DST_CPU1_BLOCK_THREADS=128`
- `BAD_DST_LOCK_ORACLE=1`
- `BAD_DST_LOCK_ORACLE_THREAD=1`
- `BAD_DST_LOCK_ORACLE_CPU=2`
- `BAD_DST_LOCK_ORACLE_US=50000`
- `BAD_DST_DONE_ORACLE=1`
- `BAD_DST_TRIGGER_TIMING_DIAG=1`
- `BAD_DST_MAX_ATTEMPTS=40`

Result:

- Completed all 40 attempts cleanly.
- Candidates: 0.
- Misses before freeze: 39.
- Done/late misses before oracle: 1.
- Pipe corruption failures: 0.
- Arb/RW successes: 0.
- Root successes: 0.
- Trigger release failures: 0.
- Pthread oracle outcomes:
  - `done_ok errno=0`: 15
  - `done_err errno=107` (`ENOTCONN`): 24
- Miss classification:
  - too early: 15
  - too late: 24
  - already done: 1
- Timing-diag stage distribution:
  - `after_timer_read`: 13 `woken`, 26 `timer_armed`, 1 `done`
  - `after_pin_trigger`: 13 `woken`, 26 `timer_armed`, 1 `done`
  - For attempts with an armed timestamp, `after_pin_trigger` armed age median was about 914 us, p90 about 1177 us, max 1383 us.

Interpretation:

- The pthread lock oracle completely filtered the previous high candidate rate at this timing point.
- This strongly suggests the prior fixed-41384 no-oracle run was mostly broad unfinished-trigger noise, not reliable socket-lock-held freezes.
- At this fixed offset, the oracle usually sees either the socket still unlocked (`done_ok`, classified too early) or the trigger already far enough through the path that `IP_MTU` reports `ENOTCONN` (`done_err`, classified too late).
- No expensive reclaim path ran, so there is no pipe-overlap evidence from this run.

Issue:

- `trace.txt` still contained only the ftrace header, even though `BAD_DST_TRACE_MARKERS=1` was enabled. The likely issue is non-root traversal/write permission on debugfs after `drop_exec`.
- After the run, `share/run.sh` was patched to also `chmod 755 /sys/kernel/debug "$TR"` before dropping privileges, in addition to making `trace_marker` writable.

Next step:

- Use the pthread oracle as the candidate gate for a narrow fixed-offset matrix around the common window. This should identify offsets that produce actual blocked-oracle candidates instead of spending minutes on broad false candidates.

## 2026-05-07 17:30 EDT - repeated pthread-oracle timing runs and futex/atomic timer experiments

Goal:

- Run a batch of fixed-window trials with the pthread lock oracle and keep adjusting the timing window.
- Try the existing futex/atomic busy-loop timer path as an alternative to timerfd.
- Look for oracle-confirmed lock-held candidates and any Arb/RW or root success.

Wrapper/script changes:

- Created host matrix runner: `old/2026-05-07_pthread_oracle_fixed_matrix/run_matrix.sh`
- Patched `old/2026-05-07_fixed_41384_pthread_lockoracle_smp3_128block/share/run.sh` to accept additional kernel cmdline knobs:
  - `bad_dst_futex_timer=`
  - `bad_dst_futex_pin_trigger=`
  - `bad_dst_pre_delay_ns=`
- Patched the matrix runner to pass those knobs through.
- No exploit-core source change was made in this batch; the futex path already existed in `exp_x86.c`.

Experiment 1: timerfd fixed-offset pthread-oracle matrix

- Folder: `old/2026-05-07_pthread_oracle_fixed_matrix/`
- Settings:
  - SMP3, 128 blockers
  - pthread lock oracle on CPU2
  - `BAD_DST_LOCK_ORACLE_US=5000`
  - 40 attempts per offset
  - timerfd path, no futex timer
- Results:
  - 25000 ns: 3/40 blocked candidates, 3 pipe fails, 0 Arb/RW/root
  - 33000 ns: 4/40 blocked candidates, 4 pipe fails, 0 Arb/RW/root
  - 38000 ns: 5/40 blocked candidates, 5 pipe fails, 0 Arb/RW/root
  - 43000 ns: 6/40 blocked candidates, 6 pipe fails, 0 Arb/RW/root
  - 48000 ns: 4/40 blocked candidates, 4 pipe fails, 0 Arb/RW/root
  - 55000 ns: 3/40 blocked candidates, 3 pipe fails, 0 Arb/RW/root
  - 65000 ns: 3/40 blocked candidates, 3 pipe fails, 0 Arb/RW/root
  - 85000 ns: 6/40 blocked candidates, 6 pipe fails, 0 Arb/RW/root
- Interpretation:
  - This is the first clean no-cnxret-kprobe set with repeated pthread-oracle blocked candidates.
  - Best short-run rates were around 43000 ns and 85000 ns at 6/40 each.

Experiment 2: focused timerfd repeats at best offsets

- Folder: `old/2026-05-07_pthread_oracle_focused_best_offsets/`
- Settings:
  - Same as experiment 1, but 100 attempts at each selected offset.
- Results:
  - 43000 ns: 8/100 blocked candidates, 8 pipe fails, 0 Arb/RW/root
  - 85000 ns: 12/100 blocked candidates, 12 pipe fails, 0 Arb/RW/root
- Interpretation:
  - 85000 ns held up slightly better in the longer repeat, but neither offset produced pipe corruption.

Experiment 3: futex/atomic busy-loop timer, no pre-syscall delay

- Folder: `old/2026-05-07_pthread_oracle_futex_spin_matrix/`
- Settings:
  - `BAD_DST_FUTEX_WAKE_TIMER=1`
  - futex timer thread on CPU2
  - futex timer thread pins the trigger to CPU1 at wake time
  - `BAD_DST_PRE_SYSCALL_DELAY_NS=0`
  - Offsets: 0, 1000, 5000, 10000, 25000, 50000 ns
  - 40 attempts per offset
- Results:
  - Every tested offset: 0 blocked candidates, 40/40 already-done misses.
- Timing evidence:
  - Even at `timer_offset=0`, diagnostics showed the trigger had already completed before main could act.
  - Example pattern: at `after_futex_timer`, stage was already `done`; `setsockopt_enter` had occurred roughly 1 ms before the futex pin.
- Interpretation:
  - The futex/atomic timer by itself is too late because the timer thread does not get scheduled/pin fast enough relative to the trigger's immediate `setsockopt()`.

Experiment 4: futex/atomic busy-loop timer with pre-syscall delay

- Folder: `old/2026-05-07_pthread_oracle_futex_predelay_matrix/`
- Settings:
  - Same futex timer as experiment 3
  - `BAD_DST_PRE_SYSCALL_DELAY_NS=1100000`
  - Offsets: 0, 25000, 50000, 100000, 200000, 400000 ns
  - 40 attempts per offset
- Results:
  - 0 ns: 5/40 blocked candidates, 5 pipe fails, 0 Arb/RW/root
  - 25000 ns: 5/40 blocked candidates, 5 pipe fails, 0 Arb/RW/root
  - 50000 ns: 1/40 blocked candidates, 1 pipe fail, 0 Arb/RW/root
  - 100000 ns: 4/40 blocked candidates, 4 pipe fails, 0 Arb/RW/root
  - 200000 ns: 4/40 blocked candidates, 4 pipe fails, 0 Arb/RW/root
  - 400000 ns: 0/40 blocked candidates, mostly already-done misses
- Interpretation:
  - Adding a pre-syscall busy delay makes the futex/atomic path viable for producing lock-held candidates.
  - It did not improve end-to-end results over timerfd; candidates still all failed at pipe corruption.

Overall result:

- Total from these batches:
  - Timerfd matrix: 34 blocked candidates / 320 attempts.
  - Focused timerfd repeats: 20 blocked candidates / 200 attempts.
  - Futex without pre-delay: 0 blocked candidates / 240 attempts.
  - Futex with 1.1 ms pre-delay: 19 blocked candidates / 240 attempts.
  - Arb/RW/root successes: 0.
- The race can be brought to a pthread-oracle-confirmed socket-lock-held state without cnxret kprobes.
- The current blocker is now after the oracle gate: every oracle-confirmed candidate still fails at pipe corruption. That can mean either:
  - the lock-held oracle is still accepting the wrong part of `sock_setsockopt()`, or
  - the race is landing often enough but the reclaim/page-overlap path is currently unreliable under these SMP3 allocator conditions.

Next ideas:

- Use a temporary kprobe timing run only around the best no-kprobe windows to classify where the blocked pthread-oracle candidates sit relative to `cnxret` and `cnxassign`.
- If many blocked candidates are pre-`cnxret`, tighten the oracle or shift later; if they are post-`cnxassign`, shift earlier.
- If blocked candidates are actually around `cnxret`, focus on reclaim reliability rather than timing.

## 2026-05-07 20:20 EDT - stage gate, 1024-blocker release, and pipe-miss diagnostics

Goal:

- Reduce expensive/destructive reclaim on obvious false candidates.
- Make the 1024-blocker mode releasable after early/late misses.
- Determine whether pipe corruption failures are threshold/partial-overwrite issues or complete misses.

Source changes:

- Added `BAD_DST_REQUIRE_SETSOCKOPT_ENTER_STAGE=1` to reject candidates unless the trigger thread is at `TRIGGER_STAGE_SETSOCKOPT_ENTER`.
- Added `BAD_DST_TRIGGER_REPIN_CPU0=0` so the trigger does not pin itself back to CPU0 after main temporarily moves it to CPU1 during release.
- Restored the ready-counter accounting around `release_frozen_trigger()`.
- Added `BAD_DST_CPU1_BLOCK_FUTEX=1` blocker mode to avoid the 1024-blocker sleep/wake storm starving a SCHED_IDLE trigger during release.
- Added pipe miss diagnostics that log max `FIONREAD` values across current and leaked vuln pipes when pipe corruption is not found.

Checkpoints/runs:

- `old/2026-05-07_stage_gate_earlytimer_current_smp2_128block_run1/`
- `old/2026-05-07_stage_gate_earlytimer_current_smp2_1024block_longrelease_run1/`
- `old/2026-05-07_stage_gate_earlytimer_current_smp2_1024block_repinfix_run1/`
- `old/2026-05-07_stage_gate_earlytimer_current_smp2_1024block_futexrelease_run1/`
- `old/2026-05-07_reclaim_cpu0_512pipes_stagegate_1024futex_run1/`

Results:

- 128 blockers + stage gate:
  - 120 attempts, 31 `setsockopt_enter` candidates, 31 pipe fails, 0 Arb/RW, 0 root, 0 release failures.
- 1024 blockers with the old sleep blocker mode:
  - The first `woken`-stage miss could not release the trigger, even with a long release timeout.
- 1024 blockers with trigger self-repin disabled but sleep blockers:
  - Still failed to release on the first `woken`-stage miss.
- 1024 blockers with futex blockers:
  - Release progressed instead of wedging. A console-observed long run produced many `setsockopt_enter` candidates and `dst_release underflow` warnings, then hit the leaked-vuln-pipe cap. The VM was interrupted before synced logs were copied back, so this is console evidence only.
- 1024 futex blockers + CPU0-only reclaim test:
  - 36 attempts, 12 `setsockopt_enter` candidates, 12 pipe fails, 0 Arb/RW, 0 root, 0 release failures.
  - Every pipe miss had normal pipe occupancy: `current_max=0x3000` and `leaked_max=0x3000`.

Interpretation:

- The stage gate and futex blocker release path are mechanically useful: they avoid many obvious early/late destructive attempts and make 1024-blocker recovery practical.
- `setsockopt_enter` is still too broad. The all-`0x3000` pipe miss pattern means the pipe rings are not being overwritten at all, not merely failing a high corruption threshold.
- The likely remaining split is:
  - false candidates are holding the socket lock outside the exact refcount-decrement-before-NULL window, or
  - the fake dst free happens but the kmalloc-256 slab page is not being returned to buddy before pipe page reclaim.

Next steps:

- Use debug-only kprobes to classify where no-kprobe candidates sit relative to `cnxret` and `cnxassign`.
- Prefer futex-blocker release for 1024-blocker runs.
- If kprobe classification shows candidates are mostly pre-`cnxret`, add a userspace-only pulse/fine delay after the stage gate before reclaim.
- If candidates are within the exact window, focus on slab-page purity and pipe/page reclaim ordering.

## 2026-05-08 - progressive entry pulse experiments

Goal:

- Improve no-kprobe race timing by pulsing the frozen SCHED_IDLE trigger forward until it reaches `TRIGGER_STAGE_SETSOCKOPT_ENTER`, then applying a smaller fine pulse before reclaim.

Source/checkpoints:

- Source changes are in `exp_x86.c`: added IPI storm knobs and `BAD_DST_PROGRESS_TO_SETSOCKOPT`.
- Checkpoints/runs:
  - `old/2026-05-08_ipi_storm_smp3_timerfd_sweep/`
  - `old/2026-05-08_ipi_storm_triggerstart_smp3_timerfd_sweep/`
  - `old/2026-05-08_ipi_triggerstart_pulse_smp3_sweep/`
  - `old/2026-05-08_progressive_entry_noipi_smp3_sweep/`
  - `old/2026-05-08_progressive_entry_noipi_128block_smp3_sweep/`
  - `old/2026-05-08_progressive_entry_smp2_nooracle_root/`
  - `old/2026-05-08_progressive_entry_smp2_8block_nooracle_root/`

Results:

- IPI storm from main, SMP3:
  - 120 attempts, 1 candidate, 1 pipe fail, 0 Arb/RW/root.
  - Mostly froze before the trigger armed or entered `setsockopt`.
- IPI storm started from trigger after timer arm, SMP3:
  - 120 attempts, 1 candidate, 1 pipe fail, 0 Arb/RW/root.
  - Avoided pre-arm stalls, but shifted timing later and still did not corrupt pipe buffers.
- Trigger-start IPI plus pulse sweep, SMP3:
  - 160 attempts, 0 candidates, 0 Arb/RW/root.
  - Pulse window mostly stayed too early or overshot to done.
- Progressive entry, 128 blockers, SMP3:
  - 160 attempts, 8 pthread-lock-oracle candidates, 8 pipe fails, 0 Arb/RW/root, 101 early/stage misses, 51 done misses.
  - All pipe misses were clean: current vuln pipes stayed at `FIONREAD=0x3000`; leaked pipes also stayed clean after the first miss.
- Progressive entry, 128 blockers, SMP2, no lock oracle:
  - Interrupted as unproductive. It spent most attempts at `timer_armed` through 240 progress pulses with no exact-entry candidates.
- Progressive entry, 8 blockers, SMP2, no lock oracle:
  - 160 attempts, 11 `setsockopt_enter` candidates, 11 pipe fails, 0 Arb/RW/root, 149 done misses, 0 release failures.
  - Candidate fine-pulse values included 0, 3500, 6000, 7500, 11500, 14000, 15000, 28000, 35500, 52500, and 57000 ns.

Interpretation:

- Reducing blockers from 128 to 8 makes the progressive pulse much more responsive. Trace markers show individual 2 us pulse requests usually taking hundreds of ns to a few us instead of hundreds of us, though occasional scheduler stalls remain.
- The 8-blocker SMP2 run creates many broad entry-stage candidates but still no pipe overwrite. Because the lock oracle was disabled, these should not be treated as proven socket-lock-held hits.
- The 128-blocker SMP3 run did prove socket-lock-held candidates with the pthread oracle, but all failed as clean pipe misses. This still points to either false candidates outside the exact refdrop-before-NULL window, or a stale-dst/free path that is not actually reached from those candidates.

Next steps:

- Repeat the 8-blocker SMP2 progressive run with the pthread lock oracle enabled on CPU0 and a short timeout, to see whether the broad entry-stage candidates actually hold the socket lock.
- If the lock oracle rejects most of them, tune the fine pulse smaller/earlier after `setsockopt_enter`.
- If the oracle accepts them but pipe misses remain clean, use a debug-only kprobe classification run around this exact wrapper to locate candidates relative to `cnxret`/`cnxassign`.

Follow-up strict oracle run:

- Folder: `old/2026-05-08_progressive_entry_smp2_8block_pthreadoracle_root/`
- Same 8-blocker SMP2 progressive wrapper, but with `BAD_DST_LOCK_ORACLE=1`, `BAD_DST_LOCK_ORACLE_THREAD=1`, `BAD_DST_LOCK_ORACLE_CPU=0`, and `BAD_DST_LOCK_ORACLE_US=5000`.
- Results:
  - `attempt_count`: 160
  - `candidate_count`: 12
  - `lock_blocked_count`: 12
  - `pipe_fail_count`: 12
  - `done_miss_count`: 145
  - `miss_before_freeze_count`: 3
  - `arb_rw_count`: 0
  - `root_count`: 0
  - `release_fail_count`: 0
- Interpretation:
  - The 8-blocker progressive path does produce real socket-lock-held states without kprobes.
  - However, every oracle-confirmed candidate still produced a clean pipe miss (`FIONREAD=0x3000` across current/leaked vuln pipes).
  - The likely problem is now finer than "socket lock held": we are probably freezing before `ipv4_negative_advice()` has dropped the dst ref, after `sk_dst_cache` has already been assigned NULL, or otherwise outside the stale-dst reclaimable window.
- Next step:
  - Run a debug-only kprobe classification using this exact 8-blocker wrapper to correlate accepted candidates with `cnxret`/`cnxassign`.

## 2026-05-07 21:45 EDT - kprobe classification and CPU0-noise hold attempts

Goal:

- Classify the 8-blocker progressive pthread-oracle candidates relative to the actual `ipv4_negative_advice()` return and `sk_dst_cache = NULL` assignment.
- Try to keep the trigger thread from advancing through the `cnxret` -> `cnxassign` gap long enough for stale-dst reclaim.

Debug classification run:

- Folder: `old/2026-05-08_progressive_8block_kprobe_classify_smp2/`
- Kprobes:
  - `cnxret sock_setsockopt+0xf00`
  - `cnxassign sock_setsockopt+0xf09`
  - `negadv ipv4_negative_advice`
  - `negadvret ipv4_negative_advice`
- Settings:
  - SMP2, 8 CPU1 futex blockers, progressive 2 us entry pulses, pthread lock oracle on CPU0, root payload enabled.
- Results:
  - `attempt_count`: 18
  - `candidate_count`: 8
  - `lock_blocked_count`: 8
  - `pipe_fail_count`: 8
  - `arb_rw_count`: 0
  - `root_count`: 0
- Key trace evidence:
  - Several accepted candidates were pre-`cnxret`; for example attempt 1 reported a candidate around 17.975s while `negadvret`/`cnxret`/`cnxassign` did not occur until 26.418s-26.421s.
  - Attempt 9 landed in the important post-refdrop/pre-NULL window: `negadvret` at about 57.324968s, `cnxret` at 57.324995s, lock-oracle candidate at about 57.330847s, and `cnxassign` at about 57.378787s.
  - The reclaim path did not run before `cnxassign`; `candidate_pipe_fail_release` started much later, around 65.983s.
- Interpretation:
  - The userspace path can reach the exact stale-dst window in debug, but the trigger is not being held there. It resumes through the NULL assignment long before the reclaim/fake-free path consumes the stale socket state.
  - Socket-lock-held is still too weak as an oracle: it accepts both pre-refdrop candidates and at least one exact-window candidate that is not frozen long enough.

CPU0-noise runs:

- Folder: `old/2026-05-08_progressive_8block_cpu0noise_hold_smp2/`
  - Woke CPU0 CFS noise after the final fine pulse.
  - Interrupted as unproductive; it mostly shifted attempts too late / already-done and did not show useful candidates before stopping.
- Folder: `old/2026-05-08_progressive_8block_cpu0noise_beforefine_smp2/`
  - Woke 8 CPU0 CFS noise threads before the final fine pulse.
  - Important knobs:
    - `BAD_DST_CPU0_NOISE_THREADS=8`
    - `BAD_DST_CPU0_NOISE_NICE=0`
    - `BAD_DST_CPU0_NOISE_DURATION_NS=2200000000`
    - `BAD_DST_CPU0_NOISE_SPIN_NS=500000`
    - `BAD_DST_CPU0_NOISE_SLEEP_NS=0`
    - `BAD_DST_CPU0_NOISE_BEFORE_FINE_PULSE=1`
    - `BAD_DST_CPU0_NOISE_AFTER_FINE_PULSE=0`
  - Results:
    - `attempt_count`: 100
    - `candidate_count`: 1
    - `lock_blocked_count`: 1
    - `pipe_fail_count`: 1
    - `done_miss_count`: 99
    - `arb_rw_count`: 0
    - `root_count`: 0
  - The single candidate clean-missed (`current_max=0x3000`, no leaked corruption). One logged critical section took about 1.98s before `MSG_PROBE`, so CPU0 CFS pressure slowed the main/reclaim side too much without proving a longer trigger hold.

Current interpretation:

- The likely blocker is no longer finding a socket-lock-held state; it is freezing the trigger precisely after refcount drop and keeping it frozen across the whole reclaim/fake-free sequence.
- CPU0 CFS noise is too blunt as currently used. A more direct next experiment is to repin the trigger to the blocked CPU after the CPU1 block state is re-enabled, because the trace suggests the trigger may continue on CPU0 after the pulse instead of being forced onto the busy CPU1 blocker set.

Next steps:

- Add an opt-in post-block repin loop around `pulse_frozen_trigger()` so the trigger is forced onto CPU1 again after blockers are active.
- Start with the same 8-blocker SMP2 progressive wrapper and pthread oracle, root payload enabled.

Follow-up post-block repin run:

- Source/checkpoint:
  - Checkpoint before edit: `old/2026-05-07_before_post_block_repin/`
  - Run folder: `old/2026-05-07_progressive_8block_postblock_repin_smp2/`
  - Added opt-in knobs in `exp_x86.c`: `BAD_DST_RACE_PULSE_REPIN_AFTER_BLOCK` and `BAD_DST_RACE_PULSE_REPIN_GAP_NS`.
- Settings:
  - SMP2, 8 CPU1 futex blockers, progressive 2 us entry pulses, pthread lock oracle, root payload enabled.
  - CPU0 noise disabled.
  - `BAD_DST_RACE_PULSE_REPIN_AFTER_BLOCK=8`
  - `BAD_DST_RACE_PULSE_REPIN_GAP_NS=0`
- Results:
  - `attempt_count`: 120
  - `candidate_count`: 5
  - `lock_blocked_count`: 5
  - `pipe_fail_count`: 5
  - `done_miss_count`: 113
  - `miss_before_freeze_count`: 2
  - `arb_rw_count`: 0
  - `root_count`: 0
- Candidate critical elapsed before `MSG_PROBE`: about 0.96s to 1.29s.
- All candidates were clean pipe misses (`current_max=0x3000`; leaked vuln pipes also stayed at `0x3000` after the first leak).
- Interpretation:
  - Repeated post-block `sched_setaffinity()` did not fix the hold or reclaim behavior.
  - The implementation applied the repin loop to every progressive 2 us pulse, which introduced extra millisecond-scale overhead before the final candidate path. That makes this run useful as a negative signal, but the cleaner experiment is to repin only after the final fine pulse.

Follow-up final-only repin run:

- Source/run folder: `old/2026-05-07_progressive_8block_final_repin_smp2/`
- Source adjustment:
  - Split `pulse_frozen_trigger_with_repin()` so normal progress pulses do not run the repin loop.
  - Only the final fine pulse passes `enable_post_block_repin=true`.
- Settings:
  - Same 8-blocker SMP2 progressive wrapper.
  - `BAD_DST_RACE_PULSE_REPIN_AFTER_BLOCK=8`
  - `BAD_DST_RACE_PULSE_REPIN_GAP_NS=0`
  - Root payload enabled, CPU0 noise disabled.
- Results:
  - `attempt_count`: 80
  - `candidate_count`: 1
  - `lock_blocked_count`: 1
  - `pipe_fail_count`: 1
  - `done_miss_count`: 77
  - `miss_before_freeze_count`: 2
  - `arb_rw_count`: 0
  - `root_count`: 0
- The single candidate was attempt 9 and clean-missed after `critical elapsed before MSG_PROBE: 1175165 us`.
- Interpretation:
  - Scoping repin to the final pulse removes the progress-pulse overhead, but it still does not keep a stale dst live long enough for the fake-free/page-reclaim sequence.
- Current evidence favors a stronger hold problem: after an oracle-confirmed candidate, the trigger either has already passed the useful `cnxret` -> `cnxassign` window or is not actually starved on CPU1 during the reclaim path.

## 2026-05-07 22:05 EDT - pre-race FNHE cleanup to shorten the hold requirement

Goal:

- Avoid needing to hold the trigger for the one-second PMTU/FNHE expiry delay after a race candidate.
- Test whether setting `mtu_expires=0`, waiting briefly, and forcing FNHE cleanup before the race leaves the socket as the final rtable reference so `ipv4_negative_advice()` frees immediately in the raced `setsockopt()`.

Source/checkpoints:

- Checkpoint before edit: `old/2026-05-07_before_pre_race_fnhe_cleanup/`
- Added `BAD_DST_PRE_RACE_CLEANUP_FNHE` to `exp_x86.c`.
- Run folder: `old/2026-05-07_pre_race_fnhe_cleanup_mtu0_fast_smp2/`

Run settings:

- Wrapper set `/proc/sys/net/ipv4/route/mtu_expires` to `0`; guest confirmed `mtu_expires_value=0`.
- `BAD_DST_PRE_RACE_EXPIRE_US=50000`
- `BAD_DST_PRE_RACE_CLEANUP_FNHE=1`
- `BAD_DST_FNHE_EXPIRE_TOTAL_US=0`
- `BAD_DST_RTABLE_RCU_US=5000`
- `BAD_DST_SPRAY_BLOCK_US=10000`
- SMP2, 8 CPU1 futex blockers, progressive entry pulses, pthread lock oracle, root payload enabled.

Results:

- `attempt_count`: 120
- `candidate_count`: 8
- `lock_blocked_count`: 8
- `pipe_fail_count`: 8
- `done_miss_count`: 112
- `miss_before_freeze_count`: 0
- `arb_rw_count`: 0
- `root_count`: 0

Evidence:

- The privileged wrapper successfully set `mtu_expires=0`; the unprivileged exploit process later still logged permission denied when its internal best-effort sysctl write ran after dropping privileges.
- Candidate-to-`MSG_PROBE` critical times dropped from roughly 1.0s-1.3s to 316ms-373ms, confirming the post-candidate FNHE wait was removed.
- All candidates still clean-missed pipe corruption (`current_max=0x3000`; leaked pipes stayed clean).

Interpretation:

- Pre-race FNHE cleanup is a useful direction because it shortens the required hold by about one second and produces more candidates.
- The remaining blocker is critical-path length before `MSG_PROBE`, now dominated by closing thousands of sockets and the `NUM_SPRAY=0xa00` sendmsg spray. To make this viable without a privileged scheduler freeze, the spray/close path likely needs to get well below the observed 300ms range.

Next step:

- Add an environment-controlled active sendmsg spray count (`BAD_DST_NUM_SPRAY`) so the reclaim spray can be tuned down quickly for timing experiments.

## 2026-05-07 22:20 EDT - active sendmsg spray-count tuning knob

Goal:

- Reduce post-candidate critical-path time after pre-race FNHE cleanup by tuning the active sendmsg spray size without recompiling between runs.

Source/checkpoint:

- Checkpoint before edit: `old/2026-05-07_before_active_spray_count/`
- Added `BAD_DST_NUM_SPRAY` to `exp_x86.c`.
- Rebuilt `bad_dst_cache` with `./compile_x86.sh`.

Implementation notes:

- `NUM_SPRAY` remains the maximum allocated spray socket array size.
- `spray_active_count` is initialized from `BAD_DST_NUM_SPRAY`, clamped to `[1, NUM_SPRAY]`, and used by setup/spray/free/reset loops.

Next run:

- Repeat the pre-race FNHE cleanup wrapper with `BAD_DST_NUM_SPRAY=512` first.
- Keep `mtu_expires=0`, `BAD_DST_PRE_RACE_CLEANUP_FNHE=1`, `BAD_DST_FNHE_EXPIRE_TOTAL_US=0`, and root payload enabled.

Follow-up spray-512 run:

- Run folder: `old/2026-05-07_pre_race_fnhe_cleanup_spray512_smp2/`
- Settings:
  - SMP2, no kprobes, `mtu_expires=0`.
  - `BAD_DST_NUM_SPRAY=512`
  - `BAD_DST_PRE_RACE_CLEANUP_FNHE=1`
  - `BAD_DST_FNHE_EXPIRE_TOTAL_US=0`
  - `BAD_DST_RTABLE_RCU_US=5000`
  - `BAD_DST_SPRAY_BLOCK_US=10000`
  - `BAD_DST_GET_ROOT=1`
- Results:
  - `attempt_count`: 120
  - `candidate_count`: 7
  - `lock_blocked_count`: 7
  - `pipe_fail_count`: 7
  - `done_miss_count`: 113
  - `arb_rw_count`: 0
  - `root_count`: 0
  - `release_fail_count`: 0
- Evidence:
  - Candidate critical times before `MSG_PROBE`: 198830 us to 226372 us.
  - Console showed a `dst_release underflow` in `udp_sendmsg` on attempt 53, proving at least one candidate reached the fake-dst invalid-free path.
  - All candidates still clean-missed pipe corruption (`current_max=0x3000`; leaked vuln pipes also stayed at `0x3000`).
- Interpretation:
  - Reducing the sendmsg spray to 512 shortened the post-candidate path and can preserve the stale socket long enough to reach the fake-dst path.
  - The current blocker is now pipe-buffer/page reclaim reliability, not only race timing.

Follow-up larger vuln-pipe / CPU0 resize run:

- Run folder: `old/2026-05-07_pre_race_fnhe_cleanup_spray512_vuln1024_cpu0resize_smp2/`
- Settings:
  - Same spray-512 pre-race cleanup setup.
  - `BAD_DST_VULN_PIPES=1024`
  - `BAD_DST_PAGE_PIPES=6144`
  - `BAD_DST_VULN_PIPE_RESIZE_PERCPU=0`
  - Captured `dmesg.txt` in addition to `trace.txt`.
- Results:
  - `attempt_count`: 42
  - `candidate_count`: 4
  - `lock_blocked_count`: 4
  - `pipe_fail_count`: 4
  - `done_miss_count`: 38
  - `arb_rw_count`: 0
  - `root_count`: 0
  - `release_fail_count`: 0
- Evidence:
  - Candidate critical times before `MSG_PROBE`: 195763 us to 225447 us.
  - `dmesg.txt` captured `dst_release underflow` and `dst_release: dst:(____ptrval____) refcnt:-1` for the attempt-41 candidate.
  - Attempt-41 trace timing:
    - `before_spray` 73.024650
    - `after_spray` 73.064611
    - `before_msg_probe` 73.066439
    - `after_msg_probe` 73.093455
    - `after_fake_dst_rcu` 74.098540
    - `after_pipe_resize` 74.149031
    - `after_free_spray` 75.038967
    - `after_pipe_page_reclaim` 75.143102
    - `pipe_corrupt_fail` 75.195112
- Interpretation:
  - More vulnerable pipes and CPU0-only ring resize did not improve overlap in this small sample.
  - Since `free_spray()` takes close to 0.9s in the large-vuln run but happens after the fake invalid free, the remaining problem looks like the fake-freed kmalloc-256 slot/page is not being turned into a vulnerable pipe ring that is later reclaimed by pipe backing pages.
  - The known no-kprobe root run in `old/2026-05-07_no_cnxret_no_kprobe_earlytimer_smp2/` needed 21 pipe misses before winning, so the current no-kprobe path may still need long repeated runs while reclaim is tuned.

## 2026-05-08 EDT - current race-technique status after timing/classification runs

Goal:

- Evaluate the newer non-root race-hold techniques: futex blocker release, pthread lock oracle, progressive entry pulses, post-block repin, CPU0 noise, pre-race FNHE cleanup, and kprobe-only classification of where candidates land.

Important implemented/debugged techniques:

- `BAD_DST_CPU1_BLOCK_FUTEX=1`: futex-gated CPU1 blockers so large blocker sets can release cleanly after a failed candidate.
- Pthread socket-lock oracle: preferred over fork oracle; it avoids fork setup noise and reliably tells whether the trigger thread is still holding the socket lock.
- Progressive entry/fine pulse approach: wakes the trigger in small pulses to walk it toward `ipv4_negative_advice()` instead of relying only on a coarse timerfd expiration.
- Post-block repin knobs: `BAD_DST_RACE_PULSE_REPIN_AFTER_BLOCK` and `BAD_DST_RACE_PULSE_REPIN_GAP_NS`, intended to force the trigger back onto the blocked CPU after a fine pulse.
- CPU0 noise knobs: tested as a way to slow the main/reclaim path or perturb scheduling.
- Pre-race FNHE cleanup: `BAD_DST_PRE_RACE_CLEANUP_FNHE=1` with `mtu_expires=0`/short expiry path, intended to avoid holding the race for the full post-candidate PMTU expiry delay.
- Active spray tuning: `BAD_DST_NUM_SPRAY` so the sendmsg spray can be reduced without recompiling.

Representative runs and results:

- `old/2026-05-08_current_oldtiming_1024futex_nokprobe_smp2/`
  - Current binary, no kprobes, old timer timing, 1024 futex blockers.
  - `attempt_count=21`, `candidate_count=20`, `pipe_fail_count=20`, `arb_rw_count=0`, `root_count=0`, `release_fail_count=0`.
  - All candidates were clean pipe misses (`current_max=0x3000`; leaked pipes also clean).
  - No `dst_release underflow`; likely false candidates.
- `old/2026-05-08_current_oldtiming_kprobe_classify_smp2/`
  - Added classification kprobes (`cnxret`, `cnxassign`, `skcheck`, `skgot`, `sknull`).
  - `attempt_count=5`, `candidate_count=3`, `pipe_fail_count=3`, no arb/root.
  - Trace showed `MSG_PROBE` / `skcheck` before `cnxret` on candidates; the real negative-advice return happened later during release. This means the old-timing candidates are generally too early.
- `old/2026-05-08_current_latewindow_kprobe_classify_smp2/`
  - Late timer window 85-115 us.
  - `attempt_count=4`, `candidate_count=4`, `pipe_fail_count=3`, no arb/root.
  - Same failure pattern: `skcheck` before `cnxret`; late timer window did not fix candidate placement.
- `old/2026-05-08_progressive_8block_kprobe_classify_smp2/`
  - Progressive pulse run with 8 blockers.
  - `attempt_count=18`, `candidate_count=8`, `pipe_fail_count=8`, no arb/root.
  - Some traces put `cnxret/cnxassign` before `critical_before_msg_probe`, which means this technique can get closer to the right region, but it often overshoots through the `sk_dst_cache = NULL` assignment before reclaim begins.
- `old/2026-05-07_pre_race_fnhe_cleanup_spray512_smp2/`
  - Pre-race FNHE cleanup plus `BAD_DST_NUM_SPRAY=512`.
  - `attempt_count=120`, `candidate_count=7`, `pipe_fail_count=7`, no arb/root.
  - Candidate critical times dropped to roughly 199-226 ms.
  - One `dst_release underflow` in `udp_sendmsg` proved at least one candidate reached the fake-dst invalid-free path.
- `old/2026-05-07_pre_race_fnhe_cleanup_spray512_vuln1024_cpu0resize_smp2/`
  - Larger vulnerable-pipe pool and CPU0-only pipe resize.
  - `attempt_count=42`, `candidate_count=4`, `pipe_fail_count=4`, no arb/root.
  - Captured `dst_release underflow` in dmesg, but pipe/page reclaim still missed.

Interpretation:

- The best new race-timing technique is the progressive pulse path; it can get near `cnxret/cnxassign`, unlike the old broad timer candidates that are often too early.
- The post-block repin and CPU0 noise variants did not materially improve reliability in the tested form.
- Pre-race FNHE cleanup is useful because it cuts the required post-candidate hold from about 1.0-1.3 seconds to about 200-370 ms, and it has produced real `dst_release underflow` evidence.
- Current blockers are split:
  - Timing: freeze after the refcount drop but before `sk_dst_cache = NULL`, without kprobes extending `cnxret`.
  - Reclaim: even when the fake-dst invalid-free happens, pipe-buffer/page overlap often still misses.

Next likely experiment:

- Continue from `old/2026-05-08_progressive_1024block_repin_kprobe_smp2/`, which was prepared but not launched.
- Run progressive pulses with 1024 futex blockers and final/post-block repin to see whether stronger starvation prevents the overshoot seen in the 8-blocker progressive run.
- Keep kprobes classification-only for this debug pass, then remove them once the candidate lands in the right window.

## 2026-05-14 EDT - progressive 1024-blocker repin checkpoint run

Goal:

- Run the prepared progressive-pulse + 1024 futex blocker + post-block repin checkpoint to test whether stronger starvation fixes the 8-blocker overshoot.

Checkpoint/run folder:

- Base prepared checkpoint: `old/2026-05-08_progressive_1024block_repin_kprobe_smp2/`
- Actual run folder: `old/2026-05-14_progressive_1024block_repin_kprobe_run1/`
- I copied the prepared checkpoint into the May 14 run folder, replaced the stale checkpoint binary with current `bad_dst_cache`, and patched only the run-folder wrapper.
- Binary used: `sha256 9642da5c82bc12acc2fc2c6b542365a11c3dfd1c114c18f21817d29eb321375f`.

Run command:

```sh
testvm run new_kernel/bzImage --nokaslr --smp 2 --memory 1G \
  --network tap --network-tap tap0testvm \
  --network-host-ip 192.168.10.1 --network-ip 192.168.10.2/24 \
  --network-gateway 192.168.10.1 --network-dns 1.1.1.1 \
  --share-dir old/2026-05-14_progressive_1024block_repin_kprobe_run1/share \
  --share-mode ext4 --sync-share-back \
  --autorun-vm-path /mnt/testvm-share/run.sh \
  --append bad_dst_attempts=60 --append bad_dst_deadline=500 --append bad_dst_pipe_fail_limit=3
```

Important settings:

- `BAD_DST_CPU1_BLOCK_THREADS=1024`
- `BAD_DST_CPU1_BLOCK_FUTEX=1`
- `BAD_DST_PROGRESS_TO_SETSOCKOPT=1`
- `BAD_DST_PROGRESS_PULSE_NS=2000`
- `BAD_DST_PROGRESS_MAX_PULSES=400`
- `BAD_DST_RACE_PULSE_REPIN_AFTER_BLOCK=8`
- `BAD_DST_RACE_PULSE_REPIN_GAP_NS=0`
- Kprobes: `cnxret`, `cnxassign`, `negadv`, `negadvret`
- `mtu_expires_value=1`
- Note: wrapper had `BAD_DST_GET_ROOT=1` but `BAD_DST_RUN_ROOT_PAYLOAD=0`, so this was a race-classification/debug run, not an actual root-payload run.

Results:

- `attempt_count=60`
- `candidate_count=0`
- `lock_blocked_count=0`
- `miss_before_freeze_count=57`
- `done_miss_count=3`
- `pipe_fail_count=0`
- `arb_rw_count=0`
- `root_count=0`
- `release_fail_count=0`
- Miss distribution:
  - `race miss before freeze: trigger stage timer_armed`: 34
  - `race miss before freeze: trigger stage woken`: 23
  - `race miss after timer: trigger already returned`: 3
- Trace counts:
  - `cnxret=60`
  - `cnxassign=60`
  - `negadv=60`
  - `negadvret=60`

Evidence and interpretation:

- Almost every attempt exhausted all 400 progress pulses without reaching the lock-oracle/candidate stage.
- The trigger was usually still at `timer_armed` or `woken` when the progress loop gave up.
- The kprobe events did still fire once per attempt, but after the exploit had already classified the attempt as a pre-freeze miss and released/cleaned up. Example from attempt 60: `progress_max` at trace time 223.851207, then `negadv`, `negadvret`, `cnxret`, and `cnxassign` at 223.892289-223.892412 on CPU1.
- This is the opposite failure mode from the 8-blocker progressive run: 1024 blockers are too strong for the current `2 us * 400` progress scheme, preventing forward progress instead of preventing overshoot.

Next step:

- Do not continue with 1024 blockers at the current pulse size.
- Sweep intermediate blocker counts or increase progress-pulse duration/max pulses. A reasonable next range is 32, 64, 128, and 256 blockers, with the same kprobe classification, looking for attempts where `cnxret/cnxassign` occurs near the final candidate path instead of after cleanup.

## 2026-05-18/19 EDT - progressive pulse blocker sweep and pre-race cleanup

Goal:

- Continue testing the progressive-pulse race trigger after the 1024-blocker run proved too strong.
- Sweep intermediate CPU1 blocker counts and then combine the best timing setting with pre-race FNHE cleanup.
- Keep kprobes for classification only in these debug runs: `cnxret`, `cnxassign`, `negadv`, `negadvret`.

Common setup:

- Kernel: `new_kernel/bzImage`, `--nokaslr --smp 2 --memory 1G`, tap networking on `tap0testvm`.
- Exploit binary: current `bad_dst_cache`, sha256 `9642da5c82bc12acc2fc2c6b542365a11c3dfd1c114c18f21817d29eb321375f`.
- Progressive knobs: `BAD_DST_PROGRESS_TO_SETSOCKOPT=1`, `BAD_DST_PROGRESS_PULSE_NS=2000`, `BAD_DST_PROGRESS_MAX_PULSES=400`, `BAD_DST_RACE_PULSE_REPIN_AFTER_BLOCK=4`, `BAD_DST_RACE_PULSE_REPIN_GAP_NS=0`.
- Root payload note: most classification runs set `BAD_DST_GET_ROOT=1` but `BAD_DST_RUN_ROOT_PAYLOAD=0`; the final long pre-cleanup run enabled `BAD_DST_RUN_ROOT_PAYLOAD=1` but never reached arb R/W.

Run results:

- `old/2026-05-18_progressive_64block_kprobe_smp2_run1/`
  - `attempt_count=18`, `candidate_count=8`, `pipe_fail_count=8`, `done_miss_count=10`, `arb_rw_count=0`, `root_count=0`, `mtu_expires_value=1`.
  - Candidates were generally too early. Trace showed `critical_before_msg_probe` before the associated `cnxret`; the real negative-advice return happened later during release.
- `old/2026-05-18_progressive_16block_kprobe_smp2_run1/`
  - `attempt_count=6`, `candidate_count=3`, `pipe_fail_count=3`, `done_miss_count=2`, `arb_rw_count=0`, `root_count=0`, `mtu_expires_value=1`.
  - Best timing among the plain `mtu_expires=1` sweep. Attempts included `dst_release` underflow evidence and one candidate with `cnxret` before `MSG_PROBE` and `cnxassign` after `MSG_PROBE`.
  - Critical times remained about 1.18-1.22 s because the run still waited for normal PMTU expiry.
- `old/2026-05-18_progressive_32block_kprobe_smp2_run1/`
  - `attempt_count=41`, `candidate_count=3`, `miss_before_freeze_count=2`, `done_miss_count=35`, `pipe_fail_count=3`, `arb_rw_count=0`, `root_count=0`, `mtu_expires_value=1`.
  - More overshoot than 16 blockers. Attempts 7/17/39 were lock-held candidates, but all were clean pipe misses (`current_max=0x3000`).

Pre-race cleanup run:

- `old/2026-05-18_progressive_16block_prerace_cleanup_smp2_run1/`
  - Based on the 16-blocker wrapper, with `mtu_expires=0`, `BAD_DST_PRE_RACE_CLEANUP_FNHE=1`, `BAD_DST_PRE_RACE_EXPIRE_US=50000`, `BAD_DST_FNHE_EXPIRE_TOTAL_US=0`, `BAD_DST_RTABLE_RCU_US=5000`, `BAD_DST_SPRAY_BLOCK_US=10000`, `BAD_DST_NUM_SPRAY=512`.
  - `attempt_count=9`, `candidate_count=3`, `pipe_fail_count=3`, `done_miss_count=5`, `arb_rw_count=0`, `root_count=0`.
  - Critical times dropped to 222-299 ms.
  - Attempts 3 and 8 showed the desired fake-dst/free behavior: `negadv/cnxret` before `MSG_PROBE`, `dst_release refcnt:-1` from `udp_sendmsg`, then clean pipe misses.

Long root-payload-enabled pre-cleanup run:

- `old/2026-05-18_progressive_16block_prerace_cleanup_root_smp2_run2/`
  - Same as the pre-race cleanup run, but `BAD_DST_RUN_ROOT_PAYLOAD=1` and the host command used `bad_dst_attempts=120`, `bad_dst_deadline=700`, `bad_dst_pipe_fail_limit=25`.
  - The VM panicked before a clean wrapper exit, so the synchronized share counters are missing; use `host.log` for this run.
  - Host log counts before the panic/reboot: `attempt=72`, `candidate=21`, `pipefail=20`, `lock_blocked=21`, `race_miss_before_freeze=3`, `race_miss_after_timer=48`, `arb=0`, `root=0`.
  - Repeated real fake-dst invalid-free evidence: many candidates logged `dst_release: dst:(____ptrval____) refcnt:-1`, with critical times mostly about 186-338 ms and one outlier at 451 ms.
  - Attempt 72 crashed with `BUG: unable to handle page fault for address: 0000000100000001`, RIP `0x100000001`, call trace through `sk_dst_check+0x55/0xb0` and `udp_sendmsg+0x783/0xc70`.
  - Interpretation: after many clean misses, the socket still hit a corrupted dst path, but not through the intended fake `dst_ops`/pipe-buffer overlap path. This looks like stale/corrupted dst reuse during `sk_dst_check`, not successful arbitrary R/W.

Current interpretation:

- Progressive pulsing with 16 CPU1 futex blockers is currently the strongest race-timing approach.
- Pre-race FNHE cleanup is clearly useful: it preserves real invalid-free behavior while shrinking the hold window from about 1.2 s to about 200-300 ms.
- The active blocker has shifted toward reclaim/page overlap. We can repeatedly reach the fake-dst invalid-free path, but pipe buffers still usually do not land on the relevant page; leaked vulnerable pipes remain clean at `current_max=0x3000`.
- The attempt-72 `sk_dst_check` crash is useful evidence that corrupted dst state persists into later socket use. It may be possible to turn this into an oracle or use it to distinguish "fake dst installed but wrong object/value" from "pipe page overlap missed".
- Source check: `net/core/sock_old.c::sk_dst_check()` does `dst = sk_dst_get(sk)` and, when `dst->obsolete` is set, directly calls `dst->ops->check(dst, cookie)`. The RIP `0x100000001` therefore most likely means the cached dst survived long enough for `dst->ops->check` to be read from corrupted object contents, rather than hitting the intended `ipv4_dst_blackhole_ops.check == dst_blackhole_check`.

Next ideas:

- Keep 16-block pre-cleanup as the timing baseline and focus on reclaim constants rather than more timing sweeps.
- Try reducing or eliminating leaked vulnerable-pipe accumulation after clean misses; the long run accumulated thousands of leaked vuln pipes and eventually crashed in `sk_dst_check`.
- Add debug-only kprobes/tracepoints around `sk_dst_check`, `dst_check`, and the fake-dst free path to identify whether `0x100000001` comes from a corrupted `dst->ops`, `dst->ops->check`, or a freelist/value overlay.
- For root runs, use a lower pipe-fail cap until the `sk_dst_check` corruption is understood, because a long run can panic before producing synced guest counters.

## 2026-05-19 EDT - no-kprobe progressive pulse validation

Goal:

- Test whether the 16-block pre-race-cleanup progressive-pulse technique still lands the race with no `cnxret`/`cnxassign`/`negadv` kprobes installed.

Run folder:

- `old/2026-05-19_progressive_16block_prerace_cleanup_nokprobe_root_smp2_run1/`
- Based on the previous 16-block pre-race-cleanup root wrapper, but with all kprobe event registration and enable lines removed.
- `kprobe_events.actual` has 0 lines.

Command:

```sh
testvm run new_kernel/bzImage --nokaslr --smp 2 --memory 1G \
  --network tap --network-tap tap0testvm \
  --network-host-ip 192.168.10.1 --network-ip 192.168.10.2/24 \
  --network-gateway 192.168.10.1 --network-dns 1.1.1.1 \
  --share-dir old/2026-05-19_progressive_16block_prerace_cleanup_nokprobe_root_smp2_run1/share \
  --share-mode ext4 --sync-share-back \
  --autorun-vm-path /mnt/testvm-share/run.sh \
  --append bad_dst_attempts=120 --append bad_dst_deadline=600 --append bad_dst_pipe_fail_limit=10
```

Important settings:

- `BAD_DST_CPU1_BLOCK_THREADS=16`
- `BAD_DST_PROGRESS_TO_SETSOCKOPT=1`
- `BAD_DST_RACE_PULSE_REPIN_AFTER_BLOCK=4`
- `mtu_expires=0`
- `BAD_DST_PRE_RACE_CLEANUP_FNHE=1`
- `BAD_DST_NUM_SPRAY=512`
- `BAD_DST_RUN_ROOT_PAYLOAD=1`
- Trace markers remained enabled, but no kprobes were installed.

Results:

- `attempt_count=120`
- `candidate_count=2`
- `lock_blocked_count=2`
- `miss_before_freeze_count=1`
- `done_miss_count=117`
- `pipe_fail_count=2`
- `arb_rw_count=0`
- `root_count=0`
- `release_fail_count=0`
- `mtu_expires_value=0`

Evidence:

- Attempt 46 was a real no-kprobe race-hit signal:
  - `race candidate: lock held`
  - `critical elapsed before MSG_PROBE: 191105 us`
  - kernel warning: `dst_release underflow`
  - call trace: `ipv4_negative_advice+0x2a/0x30` -> `sock_setsockopt+0xf00/0x1050`
  - `dst_release: dst:(____ptrval____) refcnt:-1`
  - then clean pipe miss: `current_max=0x3000`, `leaked_max=0x3000`, `leaked_count=256`
- Attempt 1 also produced a lock-held candidate and pipe miss, but no visible underflow in the host log.

Interpretation:

- This validates that the progressive-pulse method can land the race without `cnxret` or other kprobe window expansion.
- It is not currently reliable in the no-kprobe form: only 2 lock-held candidates in 120 attempts, and only one had strong underflow evidence.
- Removing the kprobes appears to shift timing toward overshoot/normal completion: 117/120 attempts were `trigger already returned`.
- Current no-kprobe pulse baseline is therefore "possible, not reliable." The next timing work should retune the pulse/final-delay sweep for the no-kprobe timing, probably around the observed attempt-46 region rather than carrying over the kprobe-tuned sweep unchanged.

## 2026-05-18 EDT - active kernel identity recheck

Goal:

- Answer whether current testing is using `new_kernel/` and summarize how that kernel differs from the original top-level kernel artifacts.

Checks performed:

- `file new_kernel/bzImage bzImage vmlinux new_kernel/vmlinux`
- `sha256sum new_kernel/bzImage bzImage new_kernel/vmlinux vmlinux bad_dst_cache`
- `scripts/extract-ikconfig` on both `new_kernel/bzImage` and top-level `bzImage`
- `nm -n` for `_stext`, `anon_pipe_buf_ops`, and `dst_blackhole_ops`
- `objdump` spot-check of `sock_setsockopt` for the debug-67 compare and `dst_release` call.

Findings:

- Recent experiment wrappers/logs use `new_kernel/bzImage`; older helper scripts `run_testvm.sh` and `debug_testvm.sh` still point at top-level `bzImage`, so those helpers would boot the old kernel unless edited or bypassed.
- `new_kernel/bzImage`: `5.10.107+ #2 SMP PREEMPT Sun May 3 07:40:16 UTC 2026`, sha256 `96e0bcd01a35cb0c689e7f78f4bbcd7176139688af286b4a2ad2a0106bf6a670`.
- Top-level `bzImage`: `5.10.107+ #1 SMP Mon Apr 27 21:55:53 UTC 2026`, sha256 `84e3fb33efd5077ee4f5e57dd477a38fcd545798b3e711b8fbe5fcb46f6bcc32`.
- The current `exp_x86.c` hardcoded symbols match `new_kernel/vmlinux`:
  - `_stext = 0xffffffff81000000`
  - `anon_pipe_buf_ops = 0xffffffff827bf740`
  - `dst_blackhole_ops = 0xffffffff836a9c40`
- The older top-level `vmlinux` has different symbol addresses:
  - `anon_pipe_buf_ops = 0xffffffff827bf3c0`
  - `dst_blackhole_ops = 0xffffffff836a8e40`
- Config diff is small and intentional:
  - old: `CONFIG_PREEMPT_NONE=y`
  - new: `CONFIG_PREEMPT=y`, `CONFIG_PREEMPT_COUNT=y`, `CONFIG_PREEMPTION=y`, `CONFIG_PREEMPT_RCU=y`, `CONFIG_TASKS_RCU=y`, `CONFIG_DEBUG_PREEMPT=y`
  - old inline unlock options were replaced by `CONFIG_UNINLINE_SPIN_UNLOCK=y`.
- Both extracted configs keep important shared options such as `CONFIG_HZ=1000`, `CONFIG_RANDOMIZE_BASE=y`, `CONFIG_KPROBES=y`, `CONFIG_FTRACE=y`, `CONFIG_FUNCTION_TRACER=y`, `CONFIG_DEBUG_INFO=y`, and `CONFIG_SLUB=y`.
- Current kernel source still has the x86 test compatibility patch `#define ARCH_DMA_MINALIGN 128`, which makes the rebuilt test kernel route 136..192 byte kmalloc requests to `kmalloc-256`; previous runtime slabinfo confirmed no effective `kmalloc-192` cache in the rebuilt `new_kernel`.
- Both top-level and `new_kernel` binaries contain the local debug-67 path in `sock_setsockopt`, but only `new_kernel` is the PREEMPT/no-effective-`kmalloc-192` build currently matched by the exploit constants.

Interpretation:

- The intended current target is `new_kernel/bzImage` plus `new_kernel/vmlinux`.
- Avoid the older top-level `bzImage` unless intentionally testing the non-PREEMPT/original bucket layout, because the current exploit binary/source constants are keyed to `new_kernel`.

## 2026-05-18 EDT - kernel post-race debug logging patch

Goal:

- Add diagnostic logging to `/home/jack/Documents/college/purdue/research/linux_src/linux_stable` without placing new logging in the race-critical `sock_setsockopt()` / `dst_negative_advice()` path.

Checkpoint:

- `old/2026-05-18_before_kernel_postrace_debug_logging/`
- Saved pre-edit copies of:
  - `RUNNING_LOG.md`
  - `net/core/dst.c`
  - `net/core/sock.c`
  - `net/ipv4/udp.c`
  - `fs/pipe.c`

Files changed:

- `/home/jack/Documents/college/purdue/research/linux_src/linux_stable/net/core/dst.c`
- `/home/jack/Documents/college/purdue/research/linux_src/linux_stable/net/core/sock.c`
- `/home/jack/Documents/college/purdue/research/linux_src/linux_stable/net/ipv4/udp.c`
- `/home/jack/Documents/college/purdue/research/linux_src/linux_stable/fs/pipe.c`

Added logging:

- `bad_dst_dbg dst_destroy_rcu`: logs suspicious dst destruction after RCU callback when `obsolete != 0` or `flags == 0xffff`.
- `bad_dst_dbg dst_blackhole_check`: logs fake/blackhole dst check calls, including dst pointer, refcount, obsolete, flags, ops, cookie, and CPU.
- `bad_dst_dbg sk_dst_check obsolete/reset` and `__sk_dst_check obsolete/reset`: logs only when cached dst is already obsolete, immediately around the post-race `dst->ops->check()` path.
- `bad_dst_dbg udp_sendmsg MSG_PROBE before/after sk_dst_check`: logs the exploit's post-race `MSG_PROBE` route check path.
- `bad_dst_dbg pipe_resize_ring`: logs 4-slot pipe ring resize with active occupancy, which corresponds to the pipe-buffer ring reclaim shape used by the exploit.

Race-impact note:

- No new logging was added to `sock_setsockopt()`, `dst_negative_advice()`, `ipv4_negative_advice()`, or `dst_release()`.
- `dst_release()` was intentionally left untouched because it is directly used by the vulnerable negative-advice path and would perturb the race window.
- The existing local debug-67 hook in `sock_setsockopt()` was already present in the source and was not part of this edit.

Validation:

- Ran `git -C /home/jack/Documents/college/purdue/research/linux_src/linux_stable diff --check -- net/core/dst.c net/core/sock.c net/ipv4/udp.c fs/pipe.c`; it produced no warnings.
- Did not compile in-place because the kernel source tree currently has no `.config` / `include/generated/autoconf.h`; use the existing `build_linux.py` flow for the real build verification.

## 2026-05-18 EDT - logged-kernel reclaim diagnostics

Goal:

- Boot the rebuilt logged kernel in `new_kernel/` and use the new post-race logging to separate race/fake-dst failures from pipe reclaim failures.

Kernel used:

- `new_kernel/bzImage`: `5.10.107+ #1 SMP PREEMPT Tue May 19 02:38:04 UTC 2026`
- `new_kernel/vmlinux` symbols:
  - `_stext = 0xffffffff81000000`
  - `anon_pipe_buf_ops = 0xffffffff827bf880`
  - `dst_blackhole_ops = 0xffffffff836a9e40`
  - `init_task = 0xffffffff83415940`

### No-kprobe race/reclaim diagnostic

Checkpoint:

- `old/2026-05-18_logged_kernel_reclaim_debug_nokprobe_run1/`

Command shape:

- `testvm run new_kernel/bzImage --nokaslr --smp 2 --memory 1G --network tap --network-tap tap0testvm ... --append bad_dst_attempts=120 --append bad_dst_deadline=650 --append bad_dst_pipe_fail_limit=4`

Result:

- `attempt_count=27`
- `candidate_count=4`
- `lock_blocked_count=4`
- `pipe_fail_count=4`
- `arb_rw_count=0`
- `root_count=0`

Evidence:

- One strong candidate hit a real `dst_release underflow` in `udp_sendmsg+0x854`, but the logged cached dst still looked like an old IPv4 route rather than the fake cmsg payload:
  - `UDP before sk_dst_check ... cached=ffff88801f5ffa80`
  - `UDP after sk_dst_check ... rt=0 cached=ffff88801f5ffa80`
  - no `bad_dst_dbg dst_blackhole_check`
- Other candidates either had `cached=0` by `MSG_PROBE` time or showed old-route fields (`ops=ffffffff836b8c40`, flags 0).
- No logged `flags=0xffff` / `ops=ffffffff836a9e40` fake dst was observed in this run.

Interpretation:

- For these no-kprobe samples, the main failure is usually before final pipe backing-page reclaim: either the stale socket cache is gone by the probe, or the sendmsg fake-dst reclaim did not overwrite the stale dst.

### sock_kmalloc kprobe diagnostic

Checkpoint:

- `old/2026-05-18_logged_kernel_reclaim_debug_sockkmalloc_run1/`

Changes:

- Added post-race allocation probes only:
  - `p:kmal sock_kmalloc sk=%di size=%si:s32`
  - `r10:kmalret sock_kmalloc ret=$retval:x64`
  - `p:kfree_s sock_kfree_s sk=%di mem=%si:x64 size=%dx:s32`
- Filtered `kmal` / `kfree_s` for size 256.
- Used `BAD_DST_FAKE_DST_OPS=0xffffffff836a9e40`, `BAD_DST_RUN_ROOT_PAYLOAD=0`, and `BAD_DST_SPRAY_BLOCK_US=100000`.

Result:

- `attempt_count=26`
- `candidate_count=3`
- `lock_blocked_count=3`
- `pipe_fail_count=2`
- `arb_rw_count=0`
- `root_count=0`

Evidence:

- Kprobe trace confirms the sendmsg cmsg spray really allocates many 256-byte `sock_kmalloc` objects.
- The candidates in this run all had `cached=0` by `MSG_PROBE`, so they did not test fake-dst reclaim against a stale cached route.

Interpretation:

- The spray mechanism is active; the remaining question is whether it lands on the stale dst page in the rare race-hit attempts.

### DEBUG=67 control and pipe-ops mismatch

Checkpoints:

- `old/2026-05-18_logged_kernel_debug67_reclaim_check_smp1/`
- `old/2026-05-18_before_pipe_ops_env_override/`

Initial DEBUG=67 control:

- Built `exp_x86.c` with `-DDEBUG` and ran SMP=1 with `BAD_DST_FAKE_DST_OPS=0xffffffff836a9e40`, root payload disabled.
- First run proved the forced stale-free path can hit the fake dst:
  - `sk_dst_check obsolete ... flags=0xffff ops=ffffffff836a9e40`
  - `bad_dst_dbg dst_blackhole_check dst=... flags=0xffff ops=ffffffff836a9e40`
  - `UDP after sk_dst_check ... cached=0`
- It then frequently failed with `FAIL: could not corrupt pipe`.
- One later attempt found a corrupted pipe, but rejected it:
  - `found corrupted pipe FIONREAD source=current index=14 size=0xc3c3c3c3`
  - `FAIL: corrupted pipe source=current index=14 had no matching pipe-buffer probe`

Root cause found:

- The rebuilt logged kernel moved `anon_pipe_buf_ops` from the exploit's compiled default `0xffffffff827bf740` to `0xffffffff827bf880`.
- The pipe-buffer probe uses `pipe_buffer->ops - PIPE_OPS_OFFSET` as a KASLR sanity check, so valid overlaps were rejected with the stale offset.

Code change:

- Updated `exp_x86.c` to allow `BAD_DST_PIPE_OPS` to override the compiled `PIPE_OPS_OFFSET` default.
- Checkpoint-local wrapper sets:
  - `BAD_DST_FAKE_DST_OPS=0xffffffff836a9e40`
  - `BAD_DST_PIPE_OPS=0xffffffff827bf880`

Validation after fix:

- Rebuilt DEBUG binary and reran SMP=1 with root payload disabled.
- Artifact: `old/2026-05-18_logged_kernel_debug67_reclaim_check_smp1/host_pipeops_fix.log`
- Result counts from host log:
  - `start trigger attempt`: 3
  - `FAIL: could not corrupt pipe`: 2
  - `dst_blackhole_check`: 1
  - `pipe probe leak accepted`: 1
  - `Arb R/W setup`: 1
  - `Kernel panic`: 0
- Accepted overlap:
  - `found corrupted pipe FIONREAD source=current index=14 size=0xc3c3c3c3`
  - `pipe probe leak accepted: page_index=158 probe=0x8b8 pipe_base=0x840 active_before=3 page=0xffffea00003a96c0 ops=0xffffffff827bf880 offset=0x0 len=0x4 flags=0x4141414100000010`
  - `kaslr base: ffffffff81000000`
  - `Arb R/W setup`

Interpretation:

- The apparent "corrupted pipe but no matching probe" failure on the rebuilt kernel was a stale symbol issue, not a reclaim design issue.
- With the pipe ops address corrected, the DEBUG=67 forced path can reach a valid arbitrary R/W setup on the logged kernel.

### DEBUG=67 root-payload control

Checkpoint:

- `old/2026-05-18_logged_kernel_debug67_root_pipeops_fix/`

Configuration:

- DEBUG=67 forced trigger.
- `BAD_DST_FAKE_DST_OPS=0xffffffff836a9e40`
- `BAD_DST_PIPE_OPS=0xffffffff827bf880`
- Root payload enabled.

Result:

- Host log: `old/2026-05-18_logged_kernel_debug67_root_pipeops_fix/host.log`
- Counts before manual stop after VM panic/reboot:
  - `start trigger attempt`: 14
  - `FAIL: could not corrupt pipe`: 13
  - `dst_blackhole_check`: 1
  - `pipe probe leak accepted`: 0
  - `Arb R/W setup`: 0
  - `now uid/gid/euid/egid`: 0
  - `Kernel panic`: 1

Panic:

- On attempt 14, after many clean pipe misses, kernel panicked while opening pipes:
  - `general protection fault, probably for non-canonical address ...`
  - `RIP: kmem_cache_alloc_trace+0xdd/0x2d0`
  - call trace: `alloc_pipe_info -> create_pipe_files -> do_pipe2`

Interpretation:

- Root was not reached in this run.
- This is a separate cleanup/retry reliability issue: failed reclaim attempts can leave corrupted kmalloc/slab state that later trips allocation. A future retry loop should either stop after a strong fake-dst/free signal, leak more potentially touched pipe state, or reboot/re-exec between aggressive DEBUG attempts rather than continuing indefinitely in the same kernel.

Current conclusions:

- The logged kernel instrumentation is useful and does not block the forced DEBUG=67 path.
- The symbol mismatch for `anon_pipe_buf_ops` was a real bug in the exploit diagnostics and is now fixed via `BAD_DST_PIPE_OPS`.
- Reclaim is possible on the logged kernel: one DEBUG=67 run reached valid pipe-buffer leak and `Arb R/W setup`.
- Reclaim is still stochastic, and failed attempts can corrupt allocator state enough to panic later attempts. The next practical work should improve failed-attempt isolation before using long root-payload retry loops.

### Race-change impact matrix

Goal:

- Compare the old no-kprobe root timing against the newer progressive trigger path while keeping the current logged kernel symbols fixed.
- Identify which race changes move the exploit closer to or farther from a useful stale `sk_dst_cache` at `udp_sendmsg(MSG_PROBE)`.

Checkpoint:

- `old/2026-05-19_race_change_matrix_prepare/`

Common setup:

- Kernel: `new_kernel/bzImage`
  - `5.10.107+ #1 SMP PREEMPT Tue May 19 02:38:04 UTC 2026`
  - `dst_blackhole_ops=0xffffffff836a9e40`
  - `anon_pipe_buf_ops=0xffffffff827bf880`
- QEMU: `testvm run new_kernel/bzImage --nokaslr --smp 2 --memory 1G --network tap --network-tap tap0testvm ...`
- Wrapper set `/proc/sys/net/ipv4/route/mtu_expires=1` before dropping privileges.
- Root payload disabled for the matrix; the goal was race/reclaim signal, not credential overwrite.
- Shared reclaim settings were restored to the old successful values where possible:
  - `BAD_DST_PRE_RACE_EXPIRE_US=700000`
  - `BAD_DST_FNHE_EXPIRE_TOTAL_US=1300000`
  - `BAD_DST_FAKE_DST_RCU_US=1000000`
  - `BAD_DST_SPRAY_BLOCK_US=250000`
  - `BAD_DST_NUM_SPRAY=2560`
  - `BAD_DST_PREPARE_PIPES_BEFORE_RACE=1`
  - `BAD_DST_VULN_PIPES=256`
  - `BAD_DST_LEAK_VULN_PIPES_ON_CLEAN_FAIL=1`
  - `BAD_DST_FAKE_DST_OPS=0xffffffff836a9e40`
  - `BAD_DST_PIPE_OPS=0xffffffff827bf880`

Variants:

- A: `old/2026-05-19_matrix_A_oldtimer_oldreclaim_currentkernel/`
  - Old successful timer/blocker settings: `BAD_DST_TIMER_SWEEP_START_NS=25000`, `BAD_DST_TIMER_SWEEP_STEP_NS=4096`, `BAD_DST_TIMER_SWEEP_COUNT=20`, `BAD_DST_CPU1_BLOCK_THREADS=1024`, no futex blockers, no lock oracle, no progress gate.
- B: `old/2026-05-19_matrix_B_progressive_oldreclaim_currentkernel/`
  - Progressive settings with old reclaim restored: `BAD_DST_CPU1_BLOCK_THREADS=16`, futex blocker enabled, timer sweep `5000 + 2048*n`, progress-to-setsockopt enabled, `BAD_DST_PROGRESS_PULSE_NS=2000`, `BAD_DST_RACE_PULSE_SWEEP_COUNT=120`, pthread lock oracle enabled, require setsockopt-enter stage.
- C: `old/2026-05-19_matrix_C_oldtimer_lockoracle_currentkernel/`
  - Same as A, but pthread lock oracle enabled.
- D: `old/2026-05-19_matrix_D_futex_timer_nopulse_currentkernel/`
  - Same futex/timer family as B, but progress gate, pulse sweep, setsockopt-enter requirement, and lock oracle disabled.

Results:

| Variant | Attempts | Candidates | Oracle blocked | MSG_PROBE cached non-NULL | MSG_PROBE cached NULL | Pipe misses | Arb R/W | Root | Notes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| A old timer/no oracle | 1 | 1 | 0 | 1 | 0 | 1 | 0 | 0 | Hit a stale cached route, but it was the old IPv4 route (`flags=0`, IPv4 dst ops), not fake dst. Trigger cleanup hung after miss. |
| B progressive gate+pulse+oracle | 58 | 4 | 4 | 0 | 4 | 4 | 0 | 0 | Oracle produced real blocked candidates, but all four were too late: `MSG_PROBE before sk_dst_check ... cached=0`. |
| C old timer+oracle | 1 | 1 | 1 | 1 | 0 | 1 | 0 | 0 | Lock oracle itself did not force lateness in this sample; still saw a non-NULL stale old route. Trigger cleanup hung after miss. |
| D futex/timer, no pulse/oracle | 6 | 6 | 0 | 3 | 3 | 5 | 0 | 0 | Removing progress/pulse gate brought back frequent non-NULL cached routes, but still no fake-dst reclaim. |

Important evidence:

- B candidates were cleaner from the oracle perspective but too late for exploitation:
  - attempt 17, 33, 37, 52: `lock oracle: blocked`
  - each corresponding `udp_sendmsg MSG_PROBE before sk_dst_check` had `cached=0000000000000000`
- A/C/D no-gate samples often had a stale cached dst at `MSG_PROBE`, but it was not the fake cmsg dst:
  - `sk_dst_check obsolete ... ref=2 obsolete=2 flags=0x0 ops=ffffffff836b8c40`
  - no `flags=0xffff ops=ffffffff836a9e40`
  - no `bad_dst_dbg dst_blackhole_check`
- No variant in this matrix hit pipe-buffer overlap or arbitrary R/W.

Interpretation:

- The most impactful negative change appears to be the progressive `setsockopt_enter` gate plus pulse/lock-oracle timing, not the lock oracle alone. It filters for real socket-lock blocking, but by the time the exploit performs the fake-dst free path the socket cache is usually already cleared.
- The old/no-gate timing family and the futex/no-pulse ablation more often reach `MSG_PROBE` with a non-NULL cached dst, so they are closer to the useful UAF timing window.
- The remaining major issue in those non-gated runs is not "socket cache already NULL"; it is that sendmsg fake-dst reclaim is not landing on the stale route object. The stale cached object still looks like a normal IPv4 route at `sk_dst_check`.
- The trigger-release hang is specific to the old candidate path in these samples and should be fixed before long retries, but it is probably secondary to the fake-dst reclaim miss.

Next steps:

- Prefer the old/no-gate or futex/no-pulse race path for the next root attempts.
- Keep the pthread oracle only as optional diagnostics, not as a required gate for the final timing path.
- Focus next on why the stale cached route remains an old route after the fake-dst spray: validate the exact dst address being freed, whether the cmsg spray lands in the same slab/page, and whether pipe/leaked-vuln cleanup is perturbing the kmalloc-256 reclaim before `MSG_PROBE`.

### SLUB slab-return investigation

Goal:

- Investigate whether clean pipe misses can be explained by the kmalloc slab not being returned to the page allocator even after all cmsg spray objects on that slab are freed.
- Record the most promising next approaches in `NOTE.md`.

Checkpoint:

- `old/2026-05-19_slab_reclaim_investigation_note/`

Files reviewed:

- `/home/jack/Documents/college/purdue/research/linux_src/linux_stable/mm/slub.c`
- `/home/jack/Documents/college/purdue/research/linux_src/linux_stable/mm/page_alloc.c`
- `exp_x86.c`

Kernel/config facts:

- Current config has `CONFIG_SLUB=y`, `CONFIG_SLUB_CPU_PARTIAL=y`, `CONFIG_SLAB_FREELIST_HARDENED=y`, and `CONFIG_SLUB_DEBUG=y`; `CONFIG_SLUB_DEBUG_ON` and `CONFIG_SLUB_STATS` are off.
- `set_cpu_partial()` sets `cpu_partial=13` for caches with `s->size >= 256 && < 1024`.
- `set_min_partial()` floors `min_partial` to `MIN_PARTIAL=5`, so `kmalloc-256` should keep at least 5 node partial slabs before discarding empty ones.

SLUB behavior relevant to this exploit:

- `__slab_free()` does not necessarily discard a slab when an object is freed.
- If a full slab first becomes partial and `CONFIG_SLUB_CPU_PARTIAL` is enabled, SLUB can freeze it and put it on the freeing CPU's per-CPU partial list with `put_cpu_partial()`.
- Later frees into a frozen slab can reduce `inuse` to 0 without immediately discarding it; the slab remains frozen until a CPU partial drain/unfreeze path runs.
- `unfreeze_partials()` discards an empty slab only when `n->nr_partial >= s->min_partial`; otherwise it adds the empty slab to the node partial list.
- `deactivate_slab()` has the same empty-slab rule: empty slabs are discarded only if the node already has at least `min_partial` partial slabs.
- Therefore "all cmsg objects freed" is not enough. The target `kmalloc-256` slab may remain in the CPU partial list or node partial list and never reach `discard_slab()`.

Page allocator behavior after SLUB discard:

- `discard_slab()` calls `free_slab()`, then `__free_slab()`, then `__free_pages()`.
- For order-0 slabs, `free_unref_page_commit()` places the page on the freeing CPU's per-CPU page list first.
- Order-0 pipe backing allocations use `rmqueue_pcplist()` first. That is good only if the pipe page allocations run on the same CPU whose PCP received the freed slab page, or if enough pages are drained/refilled to move it where the allocating CPU can see it.

Interpretation:

- The latest no-gate candidates often still had a non-NULL cached route at `MSG_PROBE`, but it was an old route object, not the fake cmsg dst. That points to fake-dst reclaim not landing on the stale route.
- Separately, even when the fake unaligned free succeeds, pipe-page overlap can fail if the fake pipe-ring slab page is retained by SLUB partial lists or by the wrong CPU's PCP page list.
- This makes the "kmalloc slab not freed" hypothesis plausible and worth testing directly.

Most promising next approaches recorded in `NOTE.md`:

- Use old/no-gate or futex/no-pulse race timing, not progressive gate+pulse as a required final path.
- Pre-fill `kmalloc-256` node partials so an empty target slab is discarded instead of retained under the 5-partial minimum.
- Force per-CPU partial drains after the target slab is likely empty.
- Keep cmsg allocation/free, invalid free, pipe ring allocation, and pipe page backing reclaim on CPU0 where possible; if a freed page lands on CPU1's PCP, CPU0-only reclaim can miss.
- Add debug-only probes/logging for `discard_slab`, `__free_slab`, `free_unref_page_commit`, and `rmqueue_pcplist` to prove whether the target page reaches SLUB discard and which CPU receives/reallocates it.

### Expire-FNHE-first / race-final-decrement implementation

Goal:

- Implement and test the variant where the FNHE expiry path drops the table reference before the race, so the raced `SO_CNX_ADVICE` / `ipv4_negative_advice()` path should perform the final `dst_release()` and execute the `call_rcu()` slow path before `sk_dst_cache` is nulled.

Checkpoints:

- Before edits: `old/2026-05-19_before_expire_first_race_second/`
- Implementation and diagnostic wrapper: `old/2026-05-19_expire_first_race_second_impl/`
- Test share directory used by `testvm`: `old/2026-05-19_expire_first_diag_run/share/`

Code changes:

- Added `trigger_pre_race_fnhe_expiry()` in `exp_x86.c`.
- Added knobs:
  - `BAD_DST_EXPIRE_FNHE_BEFORE_RACE=1` enables the new order.
  - `BAD_DST_PRE_RACE_FNHE_EXPIRE_US` controls the wait before issuing the lookup that expires FNHE; default is `1200000` when not otherwise configured.
  - `BAD_DST_PRE_RACE_FNHE_SETTLE_US` optionally sleeps after the expiry lookup.
  - `BAD_DST_PRE_RACE_FNHE_SYNC_RCU` optionally does a userland RCU sync after the expiry lookup; default off because the route table ref drop is synchronous and the final route free should happen in the raced path.
  - `BAD_DST_SKIP_POST_RACE_FNHE_CLEANUP` defaults to on when pre-race expiry is enabled, preventing the old post-race cleanup from racing against the new sequence.
- Added `vm_run_expire_first_diag.sh` for bounded `MSG_PROBE` diagnostics with the new sequence.
- Preserved the legacy `BAD_DST_PRE_RACE_CLEANUP_FNHE` behavior by making it imply the new mode if explicitly set.

Build:

- Plain `./compile_x86.sh` failed in the ambient shell because static libc was missing from the linker path.
- `nix-shell -p glibc.static --run './compile_x86.sh'` succeeded; warnings were the existing format/ignored-return warnings.

Diagnostic setup:

- Kernel: `new_kernel/bzImage`, `--nokaslr --smp 2 --memory 1G`, tap network on `tap0testvm`.
- ICMP4 server was already running on the host.
- Wrapper set:
  - `/proc/sys/net/ipv4/route/mtu_expires=1`
  - `BAD_DST_EXPIRE_FNHE_BEFORE_RACE=1`
  - `BAD_DST_PRE_RACE_FNHE_EXPIRE_US=1200000`
  - `BAD_DST_SKIP_POST_RACE_FNHE_CLEANUP=1`
  - `BAD_DST_EXPIRE_WITH_LOOKUP_ONLY=1`
  - `BAD_DST_STOP_AFTER_MSG_PROBE=1`
  - `BAD_DST_FAKE_DST_OFFSET_AUTO=0`
  - `BAD_DST_FAKE_DST_OFFSET=64`
  - `BAD_DST_FAKE_DST_OPS=0xffffffff836a9e40`
  - `BAD_DST_PIPE_OPS=0xffffffff827bf880`
  - old no-gate timer sweep family: start `25000`, step `4096`, count `20`
  - CFS blockers: `BAD_DST_CPU1_BLOCK_THREADS=1024`
  - release timeout increased to `5000000` after the first cleanup failure.

Results:

- First diagnostic run reached pre-race FNHE expiry, but auto fake-dst offset selected `192`, so `try_run_main_exploit()` skipped before `MSG_PROBE`. The trigger release then timed out; this was an artifact of aborting early with 1024 blockers and the short default release timeout.
- Second diagnostic run pinned fake-dst offset to `64` and reached `MSG_PROBE` without the lock oracle. It was not a confirmed race hit:
  - `MSG_PROBE before sk_dst_check ... cached=ffff88800fd776c0`
  - `sk_dst_check obsolete ... ref=2 obsolete=2 flags=0x0 ops=ffffffff836b8c40`
  - Interpretation: the pre-race expiry made the cached route obsolete, but without the oracle the main thread probably arrived before the trigger had performed the final decrement. The main thread consumed the obsolete route instead.
- Third diagnostic enabled the pthread lock oracle. Attempt 1 was classified as too early (`lock oracle: done_ok` / `race miss before freeze: too_early`) and cleanup initially timed out before the release-timeout fix.
- Fourth diagnostic with the longer release timeout produced a lock-oracle blocked candidate:
  - `lock oracle: blocked`
  - `race candidate: lock held`
  - `critical elapsed before MSG_PROBE: 620417 us`
  - `MSG_PROBE before sk_dst_check ... cached=ffff88800f95e6c0`
  - `sk_dst_check obsolete ... ref=3 obsolete=-1 flags=0x0 ops=ffffffff836b8c40`
  - `MSG_PROBE after sk_dst_check ... rt=ffff88800f95e6c0 cached=ffff88800f95e6c0`
- This did not hit fake-dst reclaim. The cached object visible to `MSG_PROBE` was a normal IPv4 route, not the cmsg fake dst (`flags` not `0xffff`, `ops` not `dst_blackhole_ops`).

Interpretation:

- The new ordering is implemented and can get to a lock-oracle candidate, but the first confirmed candidate did not prove that the raced trigger performed the final decrement in the intended window.
- The pre-race expiry path itself works enough to make the route obsolete; in the no-oracle diagnostic the main thread saw `obsolete=2`.
- The lock-oracle candidate still suffered from the same broad failure mode as prior runs: by `MSG_PROBE`, the stale cached pointer is not backed by the fake sendmsg payload. In this sample it looked like a normal IPv4 route.
- The next debugging target is to distinguish:
  - trigger frozen before final decrement despite lock oracle,
  - trigger reached final decrement but the freed route was reclaimed by normal route allocations before cmsg spray,
  - or `sk_dst_cache` was refreshed/reassigned before `MSG_PROBE`.
- The compiled-in kernel logging currently does not directly print the specific `fnhe_flush_routes()` route pointer/refcount or the specific `ipv4_negative_advice()` `ip_rt_put()` pointer/refcount, so those would be useful non-window-affecting logs for this new sequence.

### Kernel logging patch for reclaim/FNHE diagnosis

Goal:

- Add kernel-side diagnostics to the source tree at `/home/jack/Documents/college/purdue/research/linux_src/linux_stable` for the current reclaim failure investigation, without changing exploit code.

Checkpoint:

- `old/2026-05-20_kernel_logging_patch/`

Files changed:

- `net/ipv4/route.c`
- `mm/slub.c`
- `mm/page_alloc.c`

Logging added:

- IPv4 route/FNHE path:
  - `fnhe_flush_routes()` before/after `dst_dev_put()` and `dst_release()`.
  - `update_or_create_fnhe()` for FNHE create/update state.
  - `ipv4_negative_advice()` before/after `ip_rt_put()` on obsolete/redirect/expiry paths.
  - `ip_del_fnhe()` and `find_exception()` expiry path.
  - `rt_bind_exception()` before/after `dst_hold()` and when replacing an old FNHE route.
- SLUB allocator:
  - kmalloc-256-only logs for empty-slab decisions, `discard_slab()` paths, CPU partial insertion, and `__slab_free()` state after the successful cmpxchg.
- Page allocator:
  - ratelimited PCP free/alloc logs with PFN, migratetype, zone, PCP count, and CPU.

Notes:

- The negative-advice and route/FNHE logs are diagnostic and can perturb race timing, so use this kernel to explain allocator/FNHE behavior rather than measure final exploit reliability.
- The source tree did not have a local `.config` or build outputs, so no object compile was run from this tree. Verification done here was `git diff --check -- net/ipv4/route.c mm/slub.c mm/page_alloc.c`, which passed.

### Logging kernel diagnostic run

Goal:

- Boot the newly rebuilt logging kernel and use the added route/FNHE/SLUB/page allocator logs to explain why the current candidate does not reach fake-dst reclaim.

Checkpoints/artifacts:

- Failed launch due to missing shared binary: `old/2026-05-21_logging_kernel_reclaim_run1/`
- Useful diagnostic run: `old/2026-05-21_logging_kernel_reclaim_run2/`
  - Full serial log: `serial.log`
  - Filtered event log: `key_events.log`
  - Allocator excerpt: `allocator_excerpt.log`
  - Guest share: `share/`

Command/setup:

- Kernel: `new_kernel/bzImage`, version string `5.10.107+ #1 SMP PREEMPT Thu May 21 01:17:53 UTC 2026`.
- QEMU/testvm: `--nokaslr --smp 2 --memory 1G --network tap --network-tap tap0testvm --append ignore_loglevel`.
- Wrapper: `vm_run_expire_first_diag.sh`, with:
  - `BAD_DST_MAX_ATTEMPTS=6`
  - `BAD_DST_STOP_AFTER_MSG_PROBE=1`
  - `BAD_DST_GET_ROOT=0`
  - `BAD_DST_RUN_ROOT_PAYLOAD=0`
- ICMP4 MTU server was already running on `br0testvm`.

Run notes:

- First launch used `--autorun vm_run_expire_first_diag.sh`; testvm exposed only the wrapper, so the guest failed with `./bad_dst_cache: not found`. Retried with explicit `--share-dir`.
- Second run reached one lock-oracle candidate and then hung after `FAIL: trigger did not release after failed candidate`; the VM was killed manually after useful logs were captured.

Key evidence:

- FNHE creation/bind:
  - `fnhe_create fnhe=ffff88800fd6b480 ... pmtu=1200`
  - `rt_bind_exception_before_hold output rt=ffff88800fd6a3c0 ... ref=1`
  - `rt_bind_exception_after_hold output rt=ffff88800fd6a3c0 ... ref=2`
- Pre-race FNHE expiry worked as expected:
  - `fnhe_expired ... output=ffff88800fd6a3c0`
  - `fnhe_flush_before output rt=ffff88800fd6a3c0 ... ref=2 obsolete=-1`
  - `fnhe_flush_after_dev_put ... ref=2 obsolete=2`
  - `fnhe_flush_after_release ... ref=1 obsolete=2`
- Lock oracle reported a candidate:
  - `lock oracle: blocked`
  - `race candidate: lock held`
- No `negative_advice_put_before` / `negative_advice_put_after` logs appeared for the candidate.
- `MSG_PROBE` did not see the expired FNHE route:
  - expired FNHE route: `ffff88800fd6a3c0`
  - `MSG_PROBE before sk_dst_check ... cached=ffff88800fd6af00`
  - `sk_dst_check obsolete ... dst=ffff88800fd6af00 ref=3 obsolete=-1 flags=0x0 ops=ffffffff836b8ec0`
- The observed `MSG_PROBE` route is a normal route, not the fake dst:
  - fake-dst payload was configured with `flags=0xffff` and `ops=0xffffffff836a9e40`
  - `MSG_PROBE` observed `flags=0x0` and normal IPv4 route ops `0xffffffff836b8ec0`
- SLUB/page allocator logs show the kmalloc-256 cross-cache machinery is active:
  - CPU0 retained the first empty slabs up to `min_partial=5`, then discarded later empty kmalloc-256 slabs.
  - Several discarded kmalloc-256 pages were then allocated from PCP by CPU0 shortly after `MSG_PROBE`.

Interpretation:

- This run confirms the pre-race FNHE expiry sequence drops the exception-table route reference from 2 to 1 and marks it obsolete, but the race candidate did not reach the final `ipv4_negative_advice()` decrement before the main thread's `MSG_PROBE`.
- The pthread lock oracle is currently only proving that the trigger thread holds the socket lock somewhere in `setsockopt(SO_CNX_ADVICE)`. It is not strong enough to prove the trigger reached the exact post-`ip_rt_put()` / pre-null window.
- The reclaim machinery did discard and recycle kmalloc-256 pages, but not the stale route object needed for fake-dst reclaim in this sample. The main thread saw a different normal route in the same rough allocation region (`ffff88800fd6af00` instead of `ffff88800fd6a3c0`).
- Next useful debug step is to add a non-window-affecting progress marker before entering `ipv4_negative_advice()` or right before `dst_negative_advice()` is called, or make the trigger release/failure path robust enough that repeated candidates can be collected without hanging.
