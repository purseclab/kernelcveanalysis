# Filter Handoff

This document summarizes the next deterministic filtering work for the
`kpatch` commit pipeline. It is intended to let another agent continue without
repeating the `db/filtered.sqlite` audit.

## Current pipeline

The composable pipeline currently has:

1. `MergeCommitFilter`
2. `ConfigFilter` (requires complete structured history)
3. `IfdefFilter`

`FilterContext.from_db_range()` loads the selected commits and creates
`StructuredCommits` only when merges were loaded and the source database is
marked `complete`. `FilterPipeline.requires_complete_history` is computed from
its member filters.

The database was produced with:

```console
uv run kpatch filter --repo linux --db db/all_commits.sqlite --dest filtered --config kernel.config --start 06-14-2026 --end 08-16-2026
```

The resulting `db/filtered.sqlite` contains 3,069 non-merge commits and 4,950
reduced file diffs. It is marked `sparse`; `db/all_commits.sqlite` is marked
`complete`.

## Audit findings

Simple subject, path, or diff-shape rules are generally unsafe:

- 386 commits modify only headers, including real security fixes.
- 592 commits have no retained removed lines, including added validation and
  lifetime checks.
- 135 commits have no retained added lines, including real fixes.
- Subjects containing `cleanup`, `unused`, `refactor`, `move`, `warning`, or
  `test` regularly contain meaningful behavior changes.
- `net/bpf/test_run.c` is userspace-accessible through `BPF_PROG_TEST_RUN`; do
  not reject every path containing `test`.

The following filters look worthwhile, in priority order.

## 1. Semantic no-op source filter

Add a filter for commits that change only comments, insignificant whitespace,
formatting, or source documentation while preserving the C preprocessing-token
stream.

The database audit found:

- 30 commits with identical tokens even when retaining every newline.
- 62 commits with identical tokens when non-directive newlines are ignored.
  This includes comment edits, blank-line cleanup, indentation, SPDX/license
  comment changes, and formatting-only initializer changes.

Recommended implementation:

1. Cheaply compare reconstructed old/new hunk token streams.
2. Only for candidates, read the complete old and new files through
   `RepositoryFileReader`.
3. Compare preprocessing tokens while discarding comments and whitespace.
4. Preserve preprocessing-directive line boundaries.
5. Conservatively retain unreadable files, binary changes, assembly, new or
   deleted files, and anything the lexer cannot confidently parse.

Ignoring ordinary newlines can alter source locations used by diagnostics or
macros. That is not expected to create or fix RCE behavior, but this should be
an explicit policy choice. For the strictest filter, use the 30-commit variant
that retains all newline tokens.

Prefer a real/compiler-compatible preprocessing-token lexer over regular
expressions in production. Tests should cover comments between identifiers,
escaped newlines, macro definitions, token pasting, string literals containing
comment markers, and preprocessor directives.

## 2. Kernel-source path filter

One userspace-only commit under `tools/lib/bpf/` leaked into the result:

```text
df3153758ddba58b546f9fc85e5274bfcaa0bf51
libbpf: fix -Wformat warnings from format/argument type mismatches
```

An allowlist-based `FileFilter` can remove ordinary `tools/` code by omitting
that root. Be careful with the existing `FileFilter`: it also rejects an entire
commit when any file has a non-default structural change. If the desired rule
is only a root allowlist, either separate that behavior or add a dedicated path
filter.

Do not automatically treat every `tools/` subtree as irrelevant without a
policy decision. Host build tools such as `tools/objtool` can affect generated
kernel metadata and validation. A conservative first rule can reject known
userspace products such as `tools/lib/bpf` and `tools/testing/selftests`, while
retaining build-critical host tools.

## 3. Optional production-test filter

Linux tests are distributed throughout the tree rather than stored in one
directory:

- `tools/testing/selftests/` contains userspace kselftests.
- `lib/kunit/` and `include/kunit/` contain KUnit infrastructure.
- Individual KUnit tests commonly use `*_test.c`, `*_kunit.c`, or subsystem
  test directories.
- Other in-kernel selftests occur under `lib/`, drivers, networking, and
  architecture code.

Four commits in the current database appear confined to KUnit/test-only code:

```text
9fdbdb528488403146ee56d6904e96955edde860
f47180b0e9cc59e1989adb093a4b94187642b405
0efe609ef5b6ab286ec296369365efd2b9ce774f
07a88e2bcd5b5bd7881b2e12b6aad1897a7ee1de
```

This should be an optional threat-model policy filter, not a generic substring
check. Combine:

- known test-only roots;
- Kbuild/Kconfig dependency on `KUNIT`;
- registration macros such as `kunit_test_suite(...)`;
- test filename conventions.

Only eliminate a commit when every retained file is proven test-only. Keep
`net/bpf/test_run.c` and other runtime/user-facing test interfaces.

## 4. Exact patch deduplication

Before classifiers or LLM calls, deduplicate identical normalized reduced
patches. This does not decide whether a commit is security-relevant, but avoids
paying repeatedly for cherry-picks or equivalent patches. Preserve provenance
by recording all commit IDs represented by a canonical patch.

Start with exact normalized hashes; similarity-based deduplication can be added
later and should be evaluated for false merges.

## 5. Rename-only semantic comparison (later)

Rename commits are not a large immediate source of reduction:

- 5 of 3,069 commits contain Git file-rename metadata (0.16%).
- None is solely a hunk-free file rename.
- 51 subjects explicitly contain `rename` (1.66%).
- 84 subjects contain `move`.

A permissive whole-file comparison that allowed consistent one-to-one
identifier substitution produced 74 candidates (2.4%), but it was unsafe. It
also classified real behavior changes such as:

```text
ext4_get_resuid          -> ext4_get_resgid
list_del                 -> list_del_rcu
VM_FAULT_RETRY           -> VM_FAULT_SIGBUS
cond_resched             -> cond_resched_tasks_rcu_qs
rcu_dereference          -> rcu_dereference_bh
```

Do not implement rename filtering as textual alpha-renaming. A safe version
needs symbol-aware AST binding or normalized compiler IR/object comparison. It
must distinguish renamed local/internal declarations and their references from
substitution of external functions, constants, hooks, UAPI names, configuration
symbols, and macros. Also account for token pasting/stringification, exported
symbols, BTF/kallsyms, `__func__`, and file renames affecting `__FILE__`.

Given its modest upper bound, do the no-op, path, test-policy, and dedup filters
first.

## Rules not recommended as hard filters

Do not hard-filter solely on:

- commit-message words;
- headers-only changes;
- additions-only or deletions-only changes;
- `Fixes:` or `Cc: stable` presence/absence;
- file or subject names containing `test`;
- generic logging changes;
- `new file` changes;
- apparent cleanup/removal of unused code.

These can be useful classifier features or ranking signals, but the audit found
security-relevant counterexamples in these categories.

## Suggested validation

For each new deterministic filter:

1. Report the number and percentage of eliminated commits.
2. Store or print the eliminated commit IDs and subjects for review.
3. Test mixed commits where only some files match the rule.
4. Verify that filtering uses the reduced mutable diff while any history state
   continues to use `FilteredCommit.original` and complete structured history.
5. Compare against the known LPE/RCE dataset before enabling the rule by
   default.

The database audit itself made no source changes; this file is the handoff of
the findings.
