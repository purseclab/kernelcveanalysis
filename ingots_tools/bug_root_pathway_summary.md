# __dst_negative_advice() RCU lifetime bug — analysis and (non-operational) escalation discussion

## Bug in one sentence
The kernel clears `sk->sk_dst_cache` **after** calling a per-route `dst->ops->negative_advice()` callback; some callbacks drop the last reference via `dst_release()`, so the socket can temporarily retain an RCU-visible pointer to a `struct dst_entry`/`struct rt6_info` whose lifetime has ended, enabling a **use-after-free** under concurrency.

## What the upstream fix changes
Upstream replaces the old callback contract (`negative_advice(dst) -> new_dst`) with `negative_advice(sk, dst)` so the callback can enforce the safe protocol itself:

1. **Clear/replace** `sk->sk_dst_cache` (e.g. via `sk_dst_reset(sk)`), then
2. `dst_release(old_dst)`.

This ordering ensures readers will either see a valid dst pointer or `NULL`, never a freed-but-still-published pointer.

## Why this is reachable from unprivileged code
* Connected sockets cache a route in `sk->sk_dst_cache`.
* The `SOL_SOCKET/SO_CNX_ADVICE` socket option invokes `dst_negative_advice(sk)`.
* In this tree, IPv6’s `ip6_negative_advice()` unconditionally drops non-`RTF_CACHE` routes by calling `dst_release(dst)` and returning `NULL`, i.e. it can drop the last reference while the socket still publishes the pointer.

## Resulting primitive (high-level)
The race can yield a window where:

* one thread causes a `dst_entry` to become eligible for RCU-freeing, while
* another concurrent path still **dereferences** `sk->sk_dst_cache` (often under `rcu_read_lock()` but **without** taking a refcount) and uses fields in `struct dst_entry` / `struct rt6_info`.

After the RCU grace period, the underlying `rt6_info` object can be freed and potentially reallocated for another purpose while stale pointers remain observable. This is a classic setup for:

* **UAF read** (stale reads of fields like `dst->dev`, `_metrics`, `ops`, etc.), and
* **UAF write/corruption** (if any reachable code path writes through the stale pointer), depending on exact concurrent call paths and allocator reuse.

## Constraints relevant to “root” on Android kernels
The environment notes strong forward-edge CFI (KCFI) and that traditional ROP/JOP is impractical. Therefore, any privilege-escalation attempt would need to be **data-only**:

* obtain a controlled kernel read/write (even partial) through the UAF,
* then modify security-critical data (e.g., current task’s credentials/capabilities) rather than diverting control flow.

## Data-only escalation concept (non-operational)
A generic (conceptual) path from a dst UAF to root usually needs two ingredients:

1. **Heap reuse / type confusion**: the freed `rt6_info` object is reallocated as some other kernel object whose fields are meaningfully controllable from userspace (e.g., via spraying allocations of similar size/alignment). This can turn stale reads into infoleaks and/or set up corruption of targeted data.

2. **Write-what-where (or targeted overwrite)**: use a reachable write through the stale pointer (or through a reinterpreted object) to corrupt a chosen kernel value. For “root”, typical targets are:
   * the current process’s `struct cred` fields (UID/GID, effective caps), or
   * a pointer to credentials (swapping to init’s creds / a prepared cred), or
   * a security module state used for access checks.

If a reliable primitive is achieved, “winning” is typically confirmed by successfully performing an operation that requires elevated privilege (e.g., reading a protected file, mounting, etc.).

## Why a reliable LPE is not guaranteed from this bug alone
Even though UAFs are often exploitable, in this specific case there are practical hurdles:

* `dst_release()` uses `call_rcu()`, so the bug is a **lifetime/RCU** issue, not an immediate free; exploitation usually requires precise orchestration so the object is freed and reused while stale dereferences still happen.
* IPv4/IPv6 route objects live in dedicated slab caches (e.g., `ip6_dst_cache`), which can make cross-type replacement harder unless slab merging is possible and/or another same-size cache is controllable.
* Many code paths that merely *read* from the dst will only yield limited, noisy information; many code paths that *write* to dst/rt6_info are triggered by network feedback or privileged configuration.

Accordingly, the most robust impact from this bug in isolation may be kernel crashes (DoS). Turning it into a dependable root exploit depends heavily on allocator behavior, reachable writers, and device configuration.

## Defensive takeaway
* This is a real UAF exposure on connected sockets.
* The correct remediation is exactly what upstream did: ensure `sk_dst_cache` is cleared before releasing the last dst ref, and centralize the `NULL` check while moving reset logic into each `negative_advice` implementation.

(Deliberately omitting a step-by-step exploitation recipe or code.)
