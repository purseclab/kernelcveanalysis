# IPv6 Running Log

## 2026-05-06 IPv6 race harness start

### Checkpoint
- Backed up the old scaffold before replacing it:
  - `old/2026-05-06_before_ipv6_race_harness_exp_x86_ipv6.c`

### Goal
- Build a focused IPv6 trigger harness in `exp_x86_ipv6.c`.
- Do not implement fake-dst reclaim yet.
- First target is a reliable userspace race trigger/oracle loop that can repeatedly stop the `SO_CNX_ADVICE` syscall while the IPv6 socket lock is held.

### Kernel notes used
- IPv6 vulnerable path is still `include/net/sock.h:__dst_negative_advice()`.
- `net/ipv6/route.c:ip6_negative_advice()`:
  - non-`RTF_CACHE`: `dst_release(dst)` then returns `NULL`;
  - expired `RTF_CACHE`: `rt6_remove_exception_rt(rt)` then returns `NULL`.
- `rt6_remove_exception()` calls `dst_dev_put()`, removes the exception, then `dst_release(&rt6_ex->rt6i->dst)`.
- `getsockopt(IPV6_MTU)` is lockless and only useful as a cache visibility oracle.
- Sticky option getters such as `IPV6_DSTOPTS` call `lock_sock()` and can be used as the IPv6 socket lock oracle.

### Code milestone
- Replaced `exp_x86_ipv6.c` with a non-reclaim race harness.
- Features:
  - connected IPv6 UDP socket setup, defaulting to `::1:1337`;
  - trigger thread arms `timerfd` and calls `setsockopt(SO_CNX_ADVICE)`;
  - main thread wakes on the timer, pins the trigger to the freeze CPU, and runs oracles;
  - normal-priority blocker threads occupy the freeze CPU while the trigger thread runs as `SCHED_IDLE`;
  - lock oracle forks a child that calls `getsockopt(IPV6_DSTOPTS)` and treats timeout as blocked on `sk_lock`;
  - cache oracle calls `getsockopt(IPV6_MTU)` and classifies `visible`, `null`, or `error`;
  - optional destructive `MSG_PROBE` oracle exists behind `IPV6_RACE_MSG_PROBE_ORACLE=1`.

### Environment knobs
- `IPV6_RACE_ADDR`
- `IPV6_RACE_PORT`
- `IPV6_RACE_TRIGGER_CPU`
- `IPV6_RACE_FREEZE_CPU`
- `IPV6_RACE_BLOCKERS`
- `IPV6_RACE_MAX_ATTEMPTS`
- `IPV6_RACE_TIMER_START_NS`
- `IPV6_RACE_TIMER_STEP_NS`
- `IPV6_RACE_TIMER_SWEEP_COUNT`
- `IPV6_RACE_LOCK_ORACLE_US`
- `IPV6_RACE_TIMER_READ_TIMEOUT_US`
- `IPV6_RACE_RELEASE_TIMEOUT_US`
- `IPV6_RACE_SETTLE_US`
- `IPV6_RACE_ALIGN_SWEEP`
- `IPV6_RACE_SCHED_IDLE`
- `IPV6_RACE_MSG_PROBE_ORACLE`

### Open questions
- `lock=blocked cache=visible` is a useful candidate but not a complete proof of the exact post-refdrop/pre-assign window, because it can also mean the trigger stopped before `ip6_negative_advice()`.
- Need runtime data to see whether IPv6 has a broader userspace-tunable window than IPv4.

## 2026-05-06 IPv6 refcount / ICMPv6 PMTU investigation

### Question
- Whether IPv6 needs an ICMPv6 PMTU packet to get the route refcount down to 1 before racing `SO_CNX_ADVICE`.

### Kernel findings
- `ip6_dst_alloc()` calls `dst_alloc(..., initial_ref=1, ...)`, so every new `rt6_info` starts with one reference.
- Normal UDP output lookup uses the per-CPU route path:
  - `ip6_rt_pcpu_alloc()` allocates an `RTF_PCPU` route with the initial ref.
  - `ip6_route_output_flags_noref()` performs a no-ref lookup.
  - `ip6_route_output_flags()` then calls `dst_hold_safe()` for the caller/socket reference.
  - `ip6_sk_dst_store_flow()` / `sk_setup_caps()` stores that returned ref into `sk->sk_dst_cache` without taking another ref.
- Therefore a normal IPv6 socket-cached route is effectively at refcount 2:
  - one owner from the per-CPU route slot;
  - one owner from the socket cache.
- On a non-`RTF_CACHE` route, vulnerable `ip6_negative_advice()` calls `dst_release(dst)` and returns `NULL`. That drops the socket-owned ref to 1, then vulnerable `__dst_negative_advice()` clears `sk_dst_cache` without releasing anything else. This should not free the route in the normal per-CPU case.
- ICMPv6 PMTU can create an `RTF_CACHE` exception:
  - `rt6_cache_allowed_for_pmtu()` allows this for non-cache routes with `RTF_PCPU` or a `from` route.
  - `__ip6_rt_update_pmtu()` allocates `nrt6 = ip6_rt_cache_alloc(...)`, sets PMTU/expires, and inserts it with `rt6_insert_exception()`.
  - The exception route starts with refcount 1, owned by the exception table.
  - A later lookup of the same flow finds it through `rt6_find_cached_rt()`, and `ip6_route_output_flags()` takes the socket/caller ref, making it refcount 2 while cached by the socket.
- On an expired `RTF_CACHE` route, vulnerable `ip6_negative_advice()` calls `rt6_remove_exception_rt(rt)`. That removes the exception-table owner and `dst_release()`s the route, dropping 2 to 1, then vulnerable `__dst_negative_advice()` clears `sk_dst_cache` without dropping the remaining socket ref.
- Expired PMTU exceptions can also be purged by exception GC in `rt6_age_examine_exception()` before `SO_CNX_ADVICE` runs. In that case the exception-table ref has already been dropped; a later `rt6_remove_exception_rt(rt)` returns `-ENOENT`, and the vulnerable `RTF_CACHE` branch still returns `NULL` without releasing the socket-held ref.
- The upstream fix confirms this intended accounting: the fixed `RTF_CACHE` branch does `dst_hold(dst); sk_dst_reset(sk); rt6_remove_exception_rt(rt);`. The added hold counteracts the release in `sk_dst_reset()`, preserving the old net refcount behavior while fixing the clear-before-release ordering.

### Conclusion
- Plain IPv6 `SO_CNX_ADVICE` on a normal route is not expected to free the `rt6_info`; it only drops the socket/caller ref and leaves the per-CPU route ref.
- ICMPv6 PMTU is still needed if we want the IPv6 path to use the special `RTF_CACHE` exception branch, but it does not by itself make the object hit refcount 0 during the vulnerable call. It appears to take the exception-table ref from 2 to 1 and leave the socket ref orphaned after `sk_dst_cache` is cleared.
- For a real free/UAF on IPv6, we likely need either:
  - a route flavor where the socket-cached dst has no independent per-CPU/exception owner at the vulnerable release point;
  - a second mechanism that drops the remaining orphaned socket ref after the cache clear;
  - or runtime instrumentation showing a path where the socket receives the initial exception ref rather than an extra lookup ref.
- The IPv4 PMTU/`fnhe` trick does not map cleanly to IPv6 PMTU exceptions: IPv6 exception expiry can remove the table ref, but the `RTF_CACHE` negative-advice branch does not release the socket ref.

### Next verification if we continue
- Add temporary tracepoints/kprobes around `ip6_negative_advice()`, `rt6_remove_exception()`, `dst_release()`, and `dst_destroy()` to log `rt6i_flags`, `__refcnt`, and pointer identity for normal `RTF_PCPU` vs PMTU `RTF_CACHE` sockets.
- Specifically verify whether the socket-cached PMTU exception enters `ip6_negative_advice()` with `refcnt=2` as the code suggests.

## 2026-05-06 IPv6 UAF trigger path investigation

### Important correction
- `__dst_negative_advice()` uses `__sk_dst_get(sk)`, not `sk_dst_get(sk)`, so it does not take a temporary reference before calling `dst->ops->negative_advice(dst)`.
- Any `dst_release(dst)` inside a `negative_advice()` callback is therefore releasing the socket-cache reference itself.
- UAF requires the callback to drop the last ref while `sk->sk_dst_cache` still points to the dst, and then the triggering thread must be stopped before `__dst_negative_advice()` performs `rcu_assign_pointer(sk->sk_dst_cache, ndst)`.

### Pure IPv6 `ip6_negative_advice()` cases
- Normal UDP/TCP IPv6 route:
  - per-CPU `RTF_PCPU` route has an independent per-CPU owner;
  - socket cache holds a second ref;
  - non-`RTF_CACHE` `ip6_negative_advice()` drops the socket ref, leaving the per-CPU ref, so no free.
- ICMPv6 PMTU exception:
  - PMTU creates an `RTF_CACHE` exception with one exception-table ref;
  - socket lookup adds a socket ref;
  - expired `RTF_CACHE` `ip6_negative_advice()` removes the exception-table ref, leaving the socket ref orphaned after cache clear, so no free at that point.
- `FLOWI_FLAG_KNOWN_NH` uncached clone:
  - `ip6_pol_route()` can create an uncached `RTF_CACHE` clone whose initial ref is returned to the caller and not owned by the FIB/per-CPU table;
  - this is the right ownership shape for a socket-only dst after a connected send stores a clone and drops its local send ref;
  - however, the clone is still `RTF_CACHE` and is not in the exception table, so `rt6_remove_exception_rt()` returns failure and does not call `dst_release()`. Even if PMTU marks it expired, the `RTF_CACHE` branch does not free it.
- I have not found a plain, socket-cacheable `rt6_info` path that is both socket-only and non-`RTF_CACHE`.

### XFRM IPv6 path
- `ip6_dst_lookup_flow()` always runs through `xfrm_lookup_route()`.
- With a matching outbound XFRM policy/state, `xfrm_lookup_route()` returns an `xfrm_dst` allocated from `xfrm_dst_cache`, not a plain `ip6_dst_cache` object.
- `xfrm_alloc_dst()` starts the xfrm dst at refcount 1.
- `xfrm_bundle_create()` marks bundle dsts `DST_OBSOLETE_FORCE_CHK`.
- UDP connect stores the returned dst directly in `sk_dst_cache`; connected UDP send stores a clone and then drops the local send ref. In both cases the cached xfrm dst can be socket-only.
- Old `xfrm_negative_advice()` checks `dst->obsolete` and calls `dst_release(dst)` when nonzero, so a socket-only xfrm dst can hit refcount 0 inside the vulnerable callback before `__dst_negative_advice()` clears `sk_dst_cache`.

### Likely working UAF sequence for IPv6 via XFRM
- Configure an outbound IPv6 XFRM state and policy matching the socket flow. This requires `CONFIG_XFRM`, `CONFIG_XFRM_USER`, and normally `CAP_NET_ADMIN`; the current test configs have XFRM enabled.
- Create an IPv6 UDP or TCP socket whose route lookup matches that policy.
- Use `connect()` or an initial connected send to populate `sk->sk_dst_cache` with the xfrm dst.
- Trigger `setsockopt(SOL_SOCKET, SO_CNX_ADVICE, 1)`.
- Race-stop the trigger thread after `xfrm_negative_advice()` drops the last ref but before `__dst_negative_advice()` assigns `sk_dst_cache = NULL`.
- Wait for an RCU grace period so the xfrm dst is destroyed while the socket still contains the stale pointer.
- Reclaiming this object will not use the same heap strategy as plain `rt6_info`: it comes from `xfrm_dst_cache`, not `ip6_dst_cache` or kmalloc.

### Practical implications
- If the goal is only to prove an IPv6 UAF trigger, XFRM is the strongest candidate found so far.
- If the goal is to preserve the original `rt6_info` reclaim strategy, the current pure IPv6 route paths look blocked unless we find a socket-only non-`RTF_CACHE` `rt6_info` producer or another mechanism that releases the orphaned socket ref after the cache pointer is cleared.
