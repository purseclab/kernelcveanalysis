# Diagnostic string pruning

Implemented on 2026-11-06 in the existing opt-in `RenameFilter`, enabled by
`filter config --source-pruning`. The default pipeline is unchanged.

## Inspection before implementation

The survey used all **26,670** non-merge survivors in
`db/filtered_after_2025.sqlite`, rather than extrapolating from the earlier
100-commit sample. A cheap token-shape scan found **108 candidates** whose
remaining C/header edits could match if identifier and string-literal changes
were ignored. This scan was only candidate discovery: hunk boundaries inside
comments produced two false positives, for example.

Manual inspection happened before the implementation was written and predicted
**11 additional removals: 10 diagnostic-wording commits and one rename with a
diagnostic update**. That is **0.0412% of the 26,670 survivors**, or 10.2% of the
108 broad candidates. It is not an estimate of all kernel commits.

| Inspection category | Commits | Treatment |
| --- | ---: | --- |
| Standard logging wording only | 10 | Expected to prune |
| Rename plus logging wording | 1 | Expected to prune after normal rename/reference checks |
| Format-specifier changes | 25 | Retain: conversion, width, precision, or pointer handling changes |
| Newline or logging-control changes | 7 | Retain |
| Unrecognized diagnostic wrappers or dynamic debug | 13 | Retain; no assumption that the string is unused by logic |
| Trace output or userspace interfaces | 19 | Retain |
| Names, resource selection, or other behavior | 21 | Retain |
| Other code changes | 7 | Retain |
| Module metadata | 2 | Retain |
| Backslash-spliced wording literal | 1 | Retain initially |
| Comment-only scan false positives | 2 | Already removable by whitespace cleanup |
| **Total** | **108** | |

Examples retained include `%pK` to `%p` updates, `%pOFn` to `%pOFP`, crypto
algorithm selection, procfs option strings, device match names, and trace event
labels. A string's surrounding AST use determines eligibility; keywords such
as "error" in its contents do not.

The original classifications and patches are preserved in
[inspection.json](benchmarks/diagnostic_strings/2026-11-06/inspection.json).

## Implementation

The final comparison stage first uses its existing cheap hunk-shape gate,
allowing string-literal differences as candidates. Identifier-only candidates
keep the existing comparison path and avoid the new string analysis.

For a string candidate, Tree-sitter finds format arguments supplied directly to
standard kernel logging calls used as standalone statements. Supported levels
are `emerg`, `alert`, `crit`, `err`, `warn`, `notice`, and `info`, for `pr_*` and
`dev_*`, including `_once` and `_ratelimited`; `printk` is also recognized.
`pr_debug`, `dev_dbg`, `pr_cont`, arbitrary wrappers, panic/warning primitives,
and formatting into buffers or virtual files are excluded.

Eligible literals are replaced in temporary comparison views by a canonical
signature retaining every format conversion, kernel `%p` extension, and the
ordered control bytes. Adjacent ordinary literals can be combined; standard
`KERN_*` prefixes remain explicit. Widths, precision, length modifiers, and
arguments remain significant. Unknown formats, wide/prefixed literals, numeric
escapes, and physical backslash splices remain literal and block pruning when
changed. Local logger declarations/redefinitions and nonstandard `pr_fmt` or
`dev_fmt` expansions block the exemption. Prefix macros support only pure
literal/module-name concatenation ending with the single format parameter.
Local overrides of the trusted module-name and log-level prefixes also block it.

The comparator then checks complete source token streams after the existing
edit/code masks. Wording-only commits need no symbol-reference query. If names
also change, the existing declaration-anchored mapping and both-revision
outside-reference checks still apply. A code change elsewhere keeps the whole
commit; this implementation does not partially remove individual logging edits.
Existing 2 MiB source limits, direct line/counter protections, and conservative
handling of invalid original-patch/source pairs remain in force.

Successful decisions use `diagnostic_wording` or
`consistent_rename_and_diagnostics`. They produce whole-file **edit masks**,
not code masks for logging calls. Normalization is temporary, so a failed
comparison publishes no diagnostic exclusions.

This is an explicit diagnostic-wording policy under the standard kernel logging
API contract, not strict program equivalence. Log output, diagnostic metadata,
and external log consumers can observe wording changes. Included/generated
macro overrides remain a limitation of this source-level model; local checks
are not compiler-resolved macro bindings.

## Candidate confirmation

The candidate check confirmed **all 11 predicted additional removals**. It
loaded each original patch from `db/all_commits.sqlite`, selected the files
present in the saved filtered patch using edit masks, and applied fresh ifdef
and whitespace masks before comparing complete Git source versions. It did
not pretend that the saved reduced patch was an original full-file edit.

This isolated check reused the saved file selection; it did not rerun Kbuild
or the dead-definition stage over all 26,670 commits. Two comment-only
candidates disappeared before comparison in both modes, leaving 106 comparison
inputs: the old rule retained all 106; the new rule retained 95. The other 95
inputs were unchanged by the new rule.

| Commit | Change |
| --- | --- |
| `052e97d9b771` | Initrd deprecation warning wording |
| `7f7a793d71da` | Pinctrl "paramers" typo |
| `4134bb726efd` | GRE "demultiplexor" typo |
| `eca641304134` | Restarting-tasks message wording |
| `97c03ec2c0e0` | GIC register name in diagnostic text/comments |
| `c01ae95eeb14` | UVC warning wording |
| `3a11167d918a` | PCI "missing or malformed" diagnostic |
| `38e8cc1c7938` | Pinctrl diagnostic grammar |
| `98c790b10076` | Workqueue helper renames plus log-message wording |
| `6a2804112d98` | BUG message capitalization |
| `c4c405023635` | Thermal diagnostic typo |

Detailed outcomes and masks are in
[candidate-results.json](benchmarks/diagnostic_strings/2026-11-06/candidate-results.json)
and [decisions.json](benchmarks/diagnostic_strings/2026-11-06/decisions.json).

## Fresh pipeline checks and cost

Two targeted UTC committer-date windows were rerun from the raw source database,
including merge/config/ifdef/dead/whitespace/rename stages and four config
workers. Before runs force the original identifier-only candidate gate; both
modes keep the other source-pruning rules enabled. Reference-cache files were
separate for before/after. Each after mode has one cold and one warm run.

| Window, end exclusive | Raw commits | Before survivors | After survivors | Before seconds | After cold | After warm |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 2026-03-06 to 2026-03-07 | 349 | 43 | 42 | 31.51 | 35.20 | 30.51 |
| 2026-08-07 to 2026-08-08 | 733 | 145 | 144 | 49.89 | 48.81 | 38.09 |
| **Combined** | **1,082** | **188** | **186** | **81.40** | **84.01** | **68.60** |

The two new removals were exactly the predicted workqueue and thermal commits.
Cold filtering time was approximately 3.2% higher in aggregate. Python peak RSS
was 152.2 to 155.7 MiB in March and 169.0 to 169.1 MiB in August. Sampled total
process-tree RSS/PSS remained comparable; these samples are not hard memory
bounds. These are single-run, targeted windows with ordinary system/cache noise,
not a statistical speed claim or a random estimate of yield. Wording-only
decisions need no reference scan; the newly accepted workqueue rename required
one additional cold scan. Warm timings benefit from cached reference facts.

The JSON results are under
[benchmarks/diagnostic_strings/2026-11-06](benchmarks/diagnostic_strings/2026-11-06/).
The existing `benchmarks/filter_pipeline.py` runner produced the measurements;
the comparison wrapper only overrides `_hunk_rename_candidate` with its original
identifier-only behavior for before runs. Commit databases were opened read-only.

## Validation

- **488 unit tests passed**, including 12 new tests covering diagnostic wording,
  mixed rename/wording, masks, preserved behavior changes, format conversions,
  log-level changes, macro overrides, consumed return values, dynamic debug,
  splices/escapes, and whole-commit retention.
- Mypy passed for the four affected source modules and the audit helper.
- `git diff --check` passed.
- The audit checked all 11 new decisions plus the existing dead-definition
  decision in the fresh windows, with complete-source token comparisons and
  fresh global spelling searches for renamed/unused symbols. Its diagnostic
  normalization shares the production policy helper; it is not an independent
  proof of that policy. See
  [verification.json](benchmarks/diagnostic_strings/2026-11-06/verification.json).

The experiment confirms the small predicted yield for this narrow rule. Most
"string-only" candidates have formats, interfaces, wrappers, or actual data
semantics that this implementation deliberately keeps.
