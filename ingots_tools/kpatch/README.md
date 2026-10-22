# kpatch

WIP, we want to focus on finding lpe vs just manually looking up a few for ingots.

Everyone of course use llm to find lpe bug, requires hundreds of dollars possibly, not very cheap.
These automatically found commits land in kernel trees, so scanning to find them instead of finding them ourselves may be cheaper.

For ingots, something like looking only at CVEs and filtering is probably enough?
Many but not all lpe bugs are given a CVE, and we don't really care if CVE delayed a few weeks from patch.
More interesting overall is if you can find commit as soon as it hits some kernel tree, which would enable exploitation irl, and be an issue.
Since kernel requires patch before issuing cve.

## Linux patch extraction and incremental updates

The raw, pre-filtering database is `db/all_commits.sqlite`. The `extract` command
creates a database or extends its continuous date range, inserting only missing
commits and preserving existing patches, scores, and ratings:

```console
uv run kpatch extract --repo linux --db db/all_commits.sqlite --start 01-01-2026
```

### Extract or extend a continuous date range

Use the same command to backfill an existing database. For example, extend the
source back to January 1, 2024 and include everything through the checkout's HEAD:

```console
uv run kpatch extract --repo linux --db db/all_commits.sqlite --start 01-01-2024
```

Dates are UTC **committer dates**, in `mm-dd-yyyy` format. Ranges include the
start and exclude the end. Omitting `--start` means all earlier history;
omitting `--end` means through HEAD. With neither date, `extract` includes the
entire history. It uses the current checkout and does not pull; run
`git -C linux pull --ff-only` first if needed.

```console
# Create a database or add an overlapping/adjacent explicit range:
uv run kpatch extract --repo linux --db db/all_commits.sqlite --start 01-01-2024 --end 01-01-2025

# Add only the earlier date interval, up to the stored coverage boundary:
uv run kpatch extract --repo linux --db db/all_commits.sqlite --start 01-01-2023 --end-at-stored-start

# Extend forward from the stored coverage boundary through HEAD:
uv run kpatch extract --repo linux --db db/all_commits.sqlite --start-at-stored-end

# Extend forward to an exclusive end date:
uv run kpatch extract --repo linux --db db/all_commits.sqlite --start-at-stored-end --end 01-01-2027

# Extend backward through all earlier history:
uv run kpatch extract --repo linux --db db/all_commits.sqlite --end-at-stored-start
```

- Each stored-boundary flag conflicts with its corresponding explicit date.
  Stored-boundary flags require existing
  commits; for an open coverage endpoint they use the earliest/latest stored
  committer timestamp instead.
- New and stored date ranges must overlap or touch. A disjoint range fails
  without changing rows or coverage metadata. Continuity refers to **requested
  date coverage**, not whether every day actually contains a commit.
- Existing nonempty databases must have complete, recorded extraction coverage
  (from `extract` or a synchronized `update`). Sparse/filtered databases
  and databases with unknown coverage are rejected rather than guessing from
  their earliest/latest commit timestamps.
- The combined continuous range is scanned at a pinned HEAD, inserting only
  missing commit IDs. This also captures late merges within existing coverage;
  even a contained request can therefore add newly reachable commits elsewhere
  in that coverage. Existing entries are never rewritten. Divergence from a
  recorded tip is rejected. Rows and coverage are committed atomically.
- An open-ended result records the expanded start boundary and synchronization
  checkpoint, so subsequent `update` commands need no `--start`. A bounded
  result remains end-capped; extend it through HEAD with `extract` before using
  `update`.

### Incremental updates

Keep that source database current without re-extracting existing patches:

```console
uv run kpatch update --repo linux --db db/all_commits.sqlite
```

`update` fast-forwards the checkout with `git pull --ff-only`, pins the resulting
HEAD, and atomically appends missing commits and its synchronization checkpoint.
It does **not** run filtering or update filtered databases. Existing commits,
patches, scores, and ratings are preserved. Merge commits retain the same
first-parent-patch / ordered-parent-ID representation as `extract`.

- For a legacy **uncapped** source database without a checkpoint, supply its
  actual original start date once: append `--start 01-01-2026`. Subsequent
  updates remember that boundary. Fresh empty-database extractions without
  `--end` record their checkpoint automatically.
- `--no-pull` updates from the checkout's current HEAD without network access.
- Updates use Git reachability, not the newest stored date, so late-merged
  commits with old or tied timestamps are not missed. Bootstrap exclusions are
  disk-backed; subsequent runs traverse only changes since the saved tip.
- Sparse/filtered histories, known end-capped extractions, incompatible start
  changes, and checkpoint rewinds/divergent histories are rejected. Do not
  bootstrap an old end-capped dataset as if it were an uncapped source.
- Git/extraction failures roll back both appended rows and the checkpoint. A
  successful pull itself is not rolled back if database extraction later fails.
  Normal database rewrites invalidate the checkpoint instead of risking skipped
  commits. Keep the Git objects for the saved tip available.

## Filtering performance

The pipeline loads commit metadata while leaving original patches in SQLite,
spools compact preparation data and decisions to a temporary database, and
streams retained patches into the destination. It shares bounded caches of
Kbuild parses, source include analysis, and Git blob bytes. Independent primary
history roots can run in separate processes. Complete history
is still traversed; these changes do not add new rejection rules.

Run the non-destructive, one-month benchmark from this directory:

```console
uv run python benchmarks/filter_pipeline.py --workers 4 --start 07-01-2026 --end 08-01-2026
```

It reports worker count, loading/filtering time, Python and largest-child
peak RSS, sampled whole-process-tree RSS/PSS (MiB, on Linux), commit counts,
and a SHA-256 of ordered commit IDs and reduced patches. RSS can count shared
pages repeatedly; PSS apportions shared pages. Tree peaks are sampled (RSS
0.25s, PSS 1s), not hard bounds. It consumes results without collecting them,
never saves filtered commits, and rejects ranges longer than 93 days.

### Parallel configuration filtering

The normal configuration CLI defaults to four workers:

```console
uv run kpatch filter --repo linux --db all_commits --dest filtered \
  --start 07-01-2026 --end 08-01-2026 config --config kernel.config --workers 4
```

`--workers 1` selects the serial reference path. The worker count must be
positive. Only the Kbuild/config history-decision phase is parallel; history
projection, global include indexing, `#if`/whitespace filtering, and the final
output writer stay centralized. With no kernel config there is no parallel
Kbuild phase. The Python `ConfigFilter(config, workers=...)` and
`filter_commit_time_range(..., workers=...)` APIs default to one worker; use
an `if __name__ == "__main__":` entry point when spawning from scripts.

- The coordinator prepares the complete selected history and global include
  index once. A validated compact index snapshot is loaded once per worker.
- Jobs are whole existing **first-parent root subtrees**, largest first, with
  at most `2 * workers` outstanding. Intra-root traversal and cached ownership
  discovery retain serial semantics; secondary merge parents are not state
  dependencies. This does not split arbitrary date windows or cold-start
  interior branches.
- Spawned workers open their own read-only summary reader and reusable Git
  reader/caches. Only compact headers for the assigned root are loaded—not
  the full input metadata/messages or lazy parent objects in every worker.
- Each job writes a closed temporary decision shard. The coordinator streams
  shard blobs into a separate decisions database, removes merged shards, and
  applies decisions in original commit order. There are no concurrent writers
  to the shared history/output databases.
- Failure or Ctrl-C cancels queued work and requests cancellation between
  commits; shutdown reaps worker Git children before deleting scratch files.
  A currently executing commit or initializer must finish before cancellation.

More workers duplicate include indexes, working caches, and Git processes.
Start with two or four, rather than assuming all logical CPUs will help.
A single dominant root limits concurrency; one-root inputs use the serial
path even when more workers were requested. Interior-fork checkpoint
parallelism and native/Rust acceleration are not implemented.

#### Measured multiprocessing comparison

Separate sequential runs on the same `[2026-07-01, 2026-08-01)` range (10,681
input commits) with the same configuration and memory sampler:

| Workers | Load + filtering | Speedup | Sampled tree RSS | Sampled tree PSS |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 296.2 s | 1.00× | 1,409.2 MiB | 1,389.0 MiB |
| 2 | 186.7 s | 1.59× | 1,476.0 MiB | 1,386.5 MiB |
| 4 | 135.2 s | **2.19×** | 2,626.3 MiB | 1,549.2 MiB |

All three runs retained the same 1,519 commits, with the same ordered output
SHA-256 shown below. Four workers reduced runtime from about 4m56s to 2m15s;
whole-tree PSS was about 1.51 GiB. Summed RSS is higher because Git's shared
file-backed mappings can be counted repeatedly. PSS/RSS are sampled estimates,
not hard memory limits. Only this one-month range and synthetic/unit fixtures
were tested; no multi-year runs were performed.

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
  LRU per process. Each worker has one file-reader daemon; parent streaming
  stages share their own reader. Daemons are recycled after 8,192 reads so
  Git's own object caches do not accumulate for the entire run.
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
