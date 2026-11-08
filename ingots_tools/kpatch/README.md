# kpatch

WIP, we want to focus on finding lpe vs just manually looking up a few for ingots.

Everyone of course use llm to find lpe bug, requires hundreds of dollars possibly, not very cheap.
These automatically found commits land in kernel trees, so scanning to find them instead of finding them ourselves may be cheaper.

For ingots, something like looking only at CVEs and filtering is probably enough?
Many but not all lpe bugs are given a CVE, and we don't really care if CVE delayed a few weeks from patch.
More interesting overall is if you can find commit as soon as it hits some kernel tree, which would enable exploitation irl, and be an issue.
Since kernel requires patch before issuing cve.

## Future filtering work

See [FUTURE_PRUNING_WORK.md](FUTURE_PRUNING_WORK.md) for sample estimates,
pruning criteria, and the proposed AST comparison approach.

Experimental unused-definition filters are available through
`filter config --source-pruning`. Identifier renames and bounded source reorders
require the separate lossy mode; numeric constant folding requires `--constant-branches`.
Target hardware inventory and general policy
reachability remain future work. A narrow,
opt-in compiler-backed policy stage is available through `kpatch policy` and
`filter config --policy-profile ...`; see the implementation notes and commands
in [FUTURE_PRUNING_WORK.md](FUTURE_PRUNING_WORK.md#compiler-backed-policy-prototype).

The policy profile can pin a raw installed seccomp filter using
`seccomp.filter_file` and `filter_sha256`. The ARM64 prototype resolves native
and compat syscall slots from compiler facts and requires universal denial.
Opaque callers and incomplete assembly/type-use coverage retain changes;
service-inclusive findings remain candidates. BTF-enabled targets retain policy
candidates until emitted metadata equivalence can be established. See the
[capture and review results](FUTURE_PRUNING_WORK.md#exact-seccomp-capture-and-entry-proof-review--resumed-2026-11-07).

Lossy source pruning recognizes consistent identifier substitutions and lexical
function-prototype, parameter and local-variable renames. Types, bounds,
attributes and implementation-reserved names stay observable. The separate
`--source-pruning-lossy --source-pruning-report decisions.jsonl` mode enables
comparisons and records their risks in JSONL. It can also assume explicitly
listed model or budget gaps in macro discovery; observed macro hazards and
search/read failures still retain the change. Missing macro bindings can change
runtime behavior, so these assumptions are recorded as lossy. Renaming tags, members, types or
symbols can change BTF, BPF CO-RE relocation and kallsyms behavior; source
references alone do not establish equivalence. See
[the source-pruning progress notes](FUTURE_PRUNING_WORK.md#source-pruning-correctness-and-binding-work).

- Detect hardware and driver features present on the target device, rather than
  relying only on enabled kernel configuration symbols. A configured driver can
  have no matching device; an accessible device can lack a particular feature.
- Track uses of changed header definitions in active compilation units. An
  included header currently survives even when its changed inline functions or
  structure fields are unused, including definitions for disabled subsystems.
- Detect behavior-preserving renames, reorders, and refactors beyond whitespace
  and comment equivalence. These change C tokens and require semantic analysis;
  they should not be rejected merely because their commit messages say cleanup.

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

### Configuration evidence

A base kernel config does not establish complete build inputs. Vendor modules,
forced includes, generated sources and raw-byte consumers can introduce other
inputs. Until that evidence is complete, the normal configuration stage retains
files, clears stale exclusive preprocessor modes and skips Kbuild/include
preparation. The config still supplies architecture data to source analysis.

`--config-observations` explicitly requests advisory Kbuild modes and requires
`--config` plus complete source history. It adds full-history/include scans;
those observations do not authorize configuration or `#if` exclusions. The
Python equivalents are `ConfigFilter(..., collect_observations=True)` and
`filter_commit_time_range(..., config_observations=True)`. Worker settings apply
only to that optional analysis. See the
[build-input and live-device findings](FUTURE_PRUNING_WORK.md#configuration-observations-and-live-module-closure--2026-11-07).

### Experimental source pruning

Add `--source-pruning` to `filter config` to run configuration, preprocessor
masking, `DeadCodeFilter`, whitespace cleanup, and finally `RenameFilter`
after merge filtering. It defaults to off. Start from the raw commit database
when rerunning the pipeline.

```console
uv run kpatch filter --repo linux --db all_commits --dest filtered_source --start 08-10-2026 --end 08-12-2026 config --config kernel.config --source-pruning
```

Add `--constant-branches` to include `ConstantConditionalFilter` before dead-code
pruning. It resolves numeric preprocessor conditions such as
`#if 0`, including nested groups and `#elif` chains. Unknown macro conditions
remain unresolved. It validates both complete original files, then compares
their complete projected source before publishing any masks. Active tokens,
macro effects, byte columns and physical line numbers must still match.
Commits with more than 256 eligible source files pass through this stage
without reads or masks, bounding extra work on tree-wide edits.
`--whitespace-line-numbers-lossy --whitespace-report PATH` separately permits
line-number differences and records their risks. Constant folding is off by
default because its measured additional yield is small and its cost is material;
see the measured coverage and cost in
[the constant-branch notes](FUTURE_PRUNING_WORK.md#numeric-preprocessor-branches-and-source-file-modes--2026-11-07).

Source filters require regular Git file modes on every existing side. When
patch metadata omits a mode, an exact historical tree lookup must establish it.
Symlink target text is retained even when it resembles C tokens or comments.

The default source stage retains identifier renames. With
`--source-pruning-lossy --source-pruning-report decisions.jsonl`, it uses
Tree-sitter C and complete parent/child token comparison to recognize consistent
identifier substitutions while preserving structure, values, and order. It
checks references outside the changed files and retains
exports, meaningful string changes, implicit function-name uses, and observed
macro hazards. Macro discovery preserves known bindings even when another
input is opaque. The default retains incomplete discovery; lossy mode can
assume listed model/budget gaps and records each assumption. Failed searches,
reads, malformed results and unsupported uncertainty reasons always retain.
Under the same explicit lossy option it recognizes bounded permutations of
adjacent unchanged static leaf helpers in the same file. Crossed helpers must have no calls or references
to one another; declarations and preprocessing directives are barriers.
Macro bindings are checked in both revisions, allowing only literal numeric
replacements for free expression identifiers. Calls, registration/init/section
effects, file moves, and statement/include/field/enum reorders remain excluded.
The decision uses complete masked source views after dead-code pruning, and
records an `independent_definition_reorder` edit mask. See
[UNUSED_CODE_AND_REORDER_PRUNING.md](UNUSED_CODE_AND_REORDER_PRUNING.md).

All source reorders assume code-address observations are irrelevant. An unchanged
callee can inspect its return address, and unchanged code can compare helper
addresses; either can change behavior after a source permutation. Reorders
therefore require `--source-pruning-lossy` and its audit report. The API also
requires an `on_pruned` callback to accept them. Every acceptance records the
code-address and unproved compiler-layout/instrumentation risks; there is no
measured false-removal bound for that assumption.

Whole-file physical line and byte-column checks protect unchanged code around
renames, diagnostics and reorders, including multiline macro invocations and
backslash continuations. Known macro aliases of location builtins, or observed
token pasting that prevents resolving them, retain the candidate. Diagnostic
exemptions cover only the recognized logging callee occurrences; evaluated
arguments and other uses of the same spelling stay observable.

In explicit lossy mode, an initial run of adjacent `switch` arms with one
immediate `return` each can also be permuted. A preceding complex arm can fall through, so later runs are
retained. Other arms, declarations and directives are barriers. The complete source must
otherwise match, and both revisions must pass the numeric macro guard. Type
definitions inside return expressions remain observable. These decisions use
`independent_return_case_reorder` edit masks in the same final stage.

The same opt-in stage also accepts diagnostic wording changes in standalone
standard `pr_*`, `dev_*`, and `printk` calls. The `pr_debug`, `dev_dbg`, and
`pr_cont` families are excluded;
format conversions (including kernel pointer extensions), control characters,
arguments, and other code remain significant. Local logger overrides and
nonstandard `pr_fmt`/`dev_fmt` expansions block the exemption. Caller bindings
of modeled forwarding helpers and C backends also block it, including possible
macro-generated declarations. Local token pasting/stringification retains the
candidate when backend bindings cannot be established. Directive checks handle
comments, continuations and digraphs; ordinary local variables named `file`,
`line` or `fmt` are distinct from macro overrides of those names. Only literal
concatenation with a final format parameter and standard module-name prefixes
is supported for these prefix macros. Return-value uses, unknown wrappers,
spliced/numeric-escape literals, and strings stored for later use are retained.
This is a diagnostic-text policy exemption under the standard kernel logging
API contract, not strict program equivalence. Included/generated macro overrides
remain a compiler-analysis limitation. The stage removes a whole commit only
when all remaining edits qualify; it does not erase individual changed log lines
from a commit that also changes behavior. See
[DIAGNOSTIC_STRING_PRUNING.md](DIAGNOSTIC_STRING_PRUNING.md) for the inspection
estimate, measured yield, and validation.

Stages preserve an immutable original patch and record typed edit masks or
code masks. Edit masks retain parent text when reconstructing a source;
code masks blank proven-irrelevant regions, including unchanged lines.
Rename comparison uses these complete-source views instead of reintroducing
discarded edits. Rejected candidates publish no new masks. See
[FILTER_MASKING.md](FILTER_MASKING.md) for the API and invariants.

Kbuild object membership and possible include edges supply positive evidence;
parser absence does not prove that a file is unused. Complete compiler and
build-input closure is currently unknown, so those contexts retain unlisted
files and do not authorize configuration-based code masks. Forced inputs,
assembler data and generated inputs require the ongoing build-tracing work.

The unused-definition stage considers changes confined to static functions,
simple macros, or standalone named structures. It searches for references in
both revisions, including unchanged consumers. Configuration and preprocessor
guards are used only with explicit complete context. It can remove a qualifying file from a mixed commit, or
mask individual unused functions while retaining other changes in the file.
The partial-function fallback is limited to eight candidates per file;
macros and types keep their more restrictive grouped checks. Whitespace cleanup
then removes comment-only remnants before rename detection.
Address-taking, strings, build metadata, and ambiguous references count as uses.
Unused-definition analysis retains files larger than 64 KiB to bound parsing
cost; rename comparison has a 2 MiB file limit. Named nested type definitions
and enumerators inside structures are retained because their names can escape
the enclosing definition. Definitions containing preprocessor directives or
pragmas are retained because their translation-time effects can escape the
definition. Direct line-number/counter macros also receive conservative handling.
The opaque-construct guard uses syntax tokens, so `asm` in an include path,
comment, or string no longer blocks an otherwise eligible unused definition.
Actual assembly, implicit function-name tokens, and macro stringification or
token pasting still block pruning.
Source-only absence checks also retain contexts with raw line splices that can
hide references. Before masking a definition, the stage checks moved LINE/COLUMN
aliases in the remaining code, preserving original byte and line coordinates.

Global-reference renames require a closed include and preprocessing spelling
context in both modes. This prerequisite runs before expensive global position
queries. The lossy flag retains its documented metadata and macro-discovery
assumptions for other eligible comparisons.

This is an experimental C-source reference model, not a whole-build proof.
Arbitrary nested token pasting, generated/forced includes, external modules,
and mixed input roles need stronger build-aware analysis. Before publishing a
source-based mask, all semantic stages share a positive raw-consumer check on
both original revisions. Recognized assembly `.incbin`/`.include` inputs and
explicit Make generator prerequisites retain the file, including comment-only
and C-inactive changes. Scan failures and budget limits also retain candidates.
The index is lazy, bounded and updated from revision deltas; ordinary C compiler
dependencies do not themselves veto pruning. An empty observation is not proof
that every build or external consumer has been found. For example, arbitrary
generator scripts and computed build rules still need a complete build-input
manifest. See [the masking API](FILTER_MASKING.md#raw-input-consumer-veto).
Unresolved inputs currently have a broad retention effect on kernel trees;
historical pruning measurements made before this veto are not current yields.
The separate `--unresolved-inputs-lossy --input-role-report PATH` mode can assume
supported unresolved Make/assembly expressions are irrelevant, after a full
recognized inventory. Observed raw consumers and scan failures still retain.
This can remove runtime-relevant changes and has no measured error-rate bound;
see [source-input assumptions](SOURCE_INPUT_ROLE_ASSUMPTIONS.md).
Consumer revision updates stream bounded raw diffs and batch only candidate
source paths for marker discovery, preserving complete facts across large
non-consumer changes. Read and protocol failures still retain the candidate.
Identifier renames with debug/BTF-name risks require the explicit lossy mode. Layout and
field-specific reachability are not inferred from absence of field accesses.

The stages share a bounded lazy reference index and Git blob reader. Exact
revision facts are cached in Git's `kpatch-references-v8.sqlite`; child revisions
can update changed files instead of rescanning the tree. The include scan seeds
plausible rename and header-helper queries using bounded substring patterns;
exact identifier checks follow the scan. Later queries use Git's fixed-string matcher.
High-frequency or unresolved references retain the
candidate. See [the masking update](benchmarks/ast_pruning/2026-10-25-masking/REPORT.md)
and [the original measurements](benchmarks/ast_pruning/2026-10-25/REPORT.md).

Macro discovery can read up to 32 additional complete files / 512 KiB when a
literal requested definition appears after its original read budget. Complete
file facts refine only that file's newly introduced opaque placeholders;
previous observations from other files and all budget uncertainty remain.
Read failures remain hard uncertainty. This uses the existing broad scan and
adds no second repository-wide search.

Git reference rows use a bounded binary parser: NUL terminates the path and
line-number fields, and newline terminates the source contents. This preserves
newlines in filenames and NUL bytes in source. Color and column formatting are
disabled explicitly. Malformed, truncated or oversized rows fail the scan;
they never establish absence. Both the default cache filename and query-key
namespace changed to v8, including when an explicit cache file is reused.
Exact tracked filenames use Git's literal pathspec mode, so names such as
`:(exclude)*` cannot hide references in incremental searches. Historical include
updates disable diff color and text conversion, and check parsed filenames
against the NUL-delimited changed-path list before updating the shared graph.

### Execution and progress display

Only `--config-observations` performs history/include preparation and computes
advisory modes before consuming the upstream commit stream. Normal config
filtering skips that preparation. The remaining stages are lazy:
commits pass through them without materializing each intermediate result.
Each stage currently owns a separate Rich progress display. Nested generators
can therefore show downstream bars before those stages receive input; later
totals are unknown. Parallel config progress advances when a root job finishes,
so it can pause while workers process a large root. A shared display with explicit
preparation tasks remains UI work; the bars do not represent separate full
passes or additional parallel workers.

### Benchmarking

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

### Whitespace and comment filtering

The whitespace stage checks diff hunks first. If a hunk starts inside a block
comment whose opener is outside the patch, it recovers comment context from the
complete source and rechecks the hunk. Ordinary code edits still avoid full-file
tokenization. Candidate no-ops are confirmed against complete parent/child
sources. Acceptance requires matching preprocessing tokens, logical whitespace
gaps and physical token locations, including when location macros come from an
included header. Excluded code is blanked while preserving its physical lines.
Strict decoding and unsupported syntax retain changes. Source reads reuse the
pipeline's bounded Git blob cache; layout facts have a separate bounded cache.
Recognized raw assembly and generator consumers veto acceptance even when the
C preprocessing tokens and locations match.
See [WHITESPACE_PRUNING.md](WHITESPACE_PRUNING.md) for the checks and limits.

The fix applies to subsequent runs. Regenerate existing filtered databases from
raw commits to apply the corrected pruning decisions.

`--whitespace-line-numbers-lossy` separately permits physical line numbers to
change while preserving supported tokens, whitespace gaps and byte columns.
Included line-number macros can affect runtime behavior, so this is an explicit
assumption, independent of `--source-pruning-lossy`. It requires its own report:

```console
uv run kpatch filter --repo linux --db all_commits --dest filtered_lossy config \
  --whitespace-line-numbers-lossy --whitespace-report whitespace-decisions.jsonl
```

The JSONL records distinguish strict removals from line-number assumptions,
include original-coordinate masks for the affected file and state the runtime
risk. Unknown syntax, token/gap changes and byte-column changes remain retained.
Reports and caches are validated together against source/build inputs, Git
metadata, databases and SQLite sidecars before any output is initialized.

### Parallel configuration observations

Advisory observation analysis defaults to four workers when explicitly enabled:

```console
uv run kpatch filter --repo linux --db all_commits --dest filtered \
  --start 07-01-2026 --end 08-01-2026 config --config kernel.config --config-observations --workers 4
```

`--workers 1` selects the serial reference path. The worker count must be
positive. Only the Kbuild/config history-decision phase is parallel; history
projection, global include indexing, `#if`/whitespace filtering, and the final
output writer stay centralized. Without `--config-observations` there is no
parallel Kbuild phase. The Python APIs default to one worker and require
`collect_observations=True` or `config_observations=True` respectively; use
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

These historical preparation measurements do not describe the current default
fast path. Separate sequential runs on the same `[2026-07-01, 2026-08-01)` range (10,681
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
