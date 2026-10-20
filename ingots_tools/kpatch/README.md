# kpatch

WIP, we want to focus on finding lpe vs just manually looking up a few for ingots.

Everyone of course use llm to find lpe bug, requires hundreds of dollars possibly, not very cheap.
These automatically found commits land in kernel trees, so scanning to find them instead of finding them ourselves may be cheaper.

For ingots, something like looking only at CVEs and filtering is probably enough?
Many but not all lpe bugs are given a CVE, and we don't really care if CVE delayed a few weeks from patch.
More interesting overall is if you can find commit as soon as it hits some kernel tree, which would enable exploitation irl, and be an issue.
Since kernel requires patch before issuing cve.

## Filtering performance

The pipeline loads commit metadata while leaving original patches in SQLite,
spools compact preparation data and decisions to a temporary database, and
streams retained patches into the destination. It shares bounded caches of
Kbuild parses, source include analysis, and Git blob bytes. Complete history
is still traversed; these changes do not add new rejection rules.

Run the non-destructive, one-month benchmark from this directory:

```console
uv run python benchmarks/filter_pipeline.py --start 07-01-2026 --end 08-01-2026
```

It reports loading/filtering time, peak Python RSS, the largest child-process
peak RSS (MiB, on Linux), commit counts, and a SHA-256 of ordered commit IDs
and reduced patches. It consumes results without collecting them, never saves
filtered commits, and rejects ranges longer than 93 days.

### First optimization pass

For `[2026-07-01, 2026-08-01)`, using the local Linux repository and
`kernel.config`, single unprofiled runs measured:

| Metric | Before | After |
| --- | ---: | ---: |
| Load + filtering time | 870.7 s | 276.8 s |
| Peak Python RSS | 2,423.8 MiB | 996.9 MiB |
| Input / retained commits | 10,681 / 1,519 | 10,681 / 1,519 |

That is **3.15× faster** with **58.9% less peak Python memory**. Every retained
commit ID and reduced-patch hash matched, including output order. The shared
output SHA-256 was
`105cfdf8b8f3f60725ece7cb0ed9fe8f2f85d2fe6f6df6224ae98a57ec21f1d4`.
RSS excludes Git subprocesses; timings vary with hardware and filesystem cache.

### Further scalability pass (month-only validation)

The same `[2026-07-01, 2026-08-01)` input was tested again after the disk-backed
and streaming changes:

| Metric | Previous pass | Current |
| --- | ---: | ---: |
| Load + filtering time | 276.8 s | 276.1 s |
| Peak Python RSS | 996.9 MiB | 510.8 MiB |
| Largest child-process peak RSS | not recorded | 1,256.1 MiB |
| Input / retained commits | 10,681 / 1,519 | 10,681 / 1,519 |

Runtime is effectively unchanged; peak Python RSS is another **48.8% lower**.
The ordered output SHA-256 is unchanged. The largest child is the one-snapshot
Git include-index scan, measured separately at about 1.2 GiB; it is not Python
memory or an aggregate process-family measurement. Git file-reader processes
are recycled separately to prevent their caches accumulating across years.
No multi-year history was tested.

### Large-range memory model

Database-backed filtering no longer retains the full range's original patches,
compact parsed history, per-file decisions, or all reduced output patches in
RAM:

- Original patch strings are fetched on demand through one read-only SQLite
  snapshot (2 MiB page cache). The eager `GitDb.commits_between()` API remains
  available for callers that deliberately need all patch strings.
- History summaries and decisions live in disposable SQLite scratch storage
  with a 4 MiB page cache. Ordinary hunk bodies and binary payloads are skipped
  before parsing preparation metadata.
- Branch traversal defers copies until needed, visits smaller subtrees first,
  and reuses the parent snapshot for the largest child. Active saved snapshots
  are logarithmic in commit count, rather than proportional to deferred forks.
- Kbuild parses and content-keyed source analysis are shared across branches
  with 1,024- and 4,096-entry limits. Git blob bytes have a 16 MiB/4,096-entry
  LRU. One file-reader daemon is shared by streaming stages and recycled after
  8,192 reads so Git's own object caches do not accumulate for the entire run.
- The CLI streams commits directly to the destination transaction. It waits
  for the first filtered commit before starting the replacement transaction.
  Early termination/errors close iterators, readers, and scratch storage;
  failed writes roll back the destination.

**Remaining scaling:** commit metadata and the parent/child graph still grow
with commit count; the include index grows with distinct paths/edges. This is
not constant-memory processing, and multi-year operation has not been tested.
The benchmark remains capped at 93 days; the CLI has no such date-range cap.

Scratch storage uses Python's standard temporary directory (`TMPDIR` can
select another location). Use a disk-backed directory with enough free space,
not a RAM-backed tmpfs. Use a different destination database, including a
different inode: in-place filtering and hardlink aliases are rejected. Avoid
modifying the input during a run; lazy references retain a consistent read
snapshot and can block source writers in rollback-journal mode.

For custom consumers, use `iter_filter_commits()` with `contextlib.closing()`
when stopping early. `filter_commits()` intentionally collects a list;
collection-wide filters such as `CountFilter` remain materialization barriers
so their sampling semantics do not change.
