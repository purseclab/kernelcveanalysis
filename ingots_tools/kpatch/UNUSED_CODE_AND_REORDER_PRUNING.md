# Unused-code guards and independent reordering

Implemented in the existing opt-in `--source-pruning` pipeline. Its order stays
merge → config → ifdef → dead code → whitespace → final comparison. The final
comparison is still `RenameFilter`; there is no extra stage or progress bar.
Identifier substitutions and source reorders require `--source-pruning-lossy`
and an audit report. BTF/CO-RE and kallsyms can make names observable; source
permutations can change observable function and callsite addresses. Default
filtering retains reorders. The API requires both `lossy=True` and an
`on_pruned` callback to accept them.

## Code-address assumption

Identical source bodies and isolated control flow do not prove emitted-layout
equivalence. Compiled controls demonstrate two behavior changes removed by the
former default: immediate-return case reordering changes an unchanged callee's
observed return address, and moving call-free leaf definitions changes an
unchanged function-address comparison. These are runtime effects, beyond BTF or
debug names. Restricting the new check to a directly spelled builtin in the
moved code would miss the unchanged observer.

Both reorder rules now require the explicit lossy option and an audit callback.
Every accepted reorder is marked `lossy=true` and records
`function_and_callsite_addresses_may_change_runtime_behavior` and
`compiler_generated_layout_and_instrumentation_not_proven_equivalent`, in
addition to any macro-discovery assumptions. Default or unaudited comparisons
publish no new masks. Callback failures propagate. No low error-rate bound is
claimed. Existing source-shape and macro guards remain required in lossy mode.

## Unused definitions

The opaque-construct guard now inspects syntax tokens rather than searching
raw bytes for `asm`, implicit function-name tokens, or macro operators. An
include such as `<asm/memory.h>`, a comment mentioning assembly, or a literal
containing `##` no longer blocks an otherwise eligible unused definition.
Actual assembly, implicit function-name constructs, macro stringification and
token pasting still retain the candidate. Ambiguous parser tokens also retain it.

This fixes a guard; it does not replace the reference proof. Both revisions
still need the existing spelling/reference/configuration checks. The 64 KiB
file limit, prefix/suffix guards, macro/type restrictions, and bounded partial
function analysis remain. Enumerators, generated declarations, global functions
and recursive whole-program dead-code elimination have not been added.

## Independent helper reordering

The opt-in `independent_definition_reorder` rule accepts a permutation of adjacent
static leaf function definitions in the same file when:

- Each helper's complete signature and body have identical preprocessing tokens.
- Functions that cross each other have no references to one another, including
  address-taking. Calls in a candidate helper retain it conservatively.
- Nothing except whitespace/comments separates the helper definitions. Includes,
  declarations, preprocessor boundaries, registrations and ineligible functions
  act as barriers. Nothing outside the reordered runs changes in the active view.
- Direct line/counter macros, assembly, pragmas, implicit function-name tokens,
  token pasting/stringification and init/section/attribute cases are absent.
- Both revisions pass a repository macro-definition check. Ordinary free
  expression identifiers may expand only to literal numeric token expressions;
  function/local/type/field names must have no potentially active macro binding.
  Observed aliases and function-like macros retain the candidate. Unknown
  discovery retains by default; explicit lossy mode may assume only the listed
  model/budget gaps and records those premises in its audit report.

Macro lookup normalizes comments and backslash continuations, handles ordinary
and digraph directive spellings, and reuses existing Kbuild decisions for
disabled translation units. Header definitions remain conservative. Typed
observations preserve known bindings together with any discovery uncertainty,
including positive recovery from unsupported source layouts. A later known
binding is not lost because an earlier file was opaque. Search/read failures,
malformed rows and unrecognized uncertainty reasons cannot be assumed away.
Facts are cached by revision/name independently of the current mask ledger;
parsed file facts also use a bounded content-hash cache across revisions.

Full-source position checks cover code outside the compared region as well as
multiline invocation extents and physical byte columns. Observed location
aliases and macro operators that prevent resolving them retain the candidate.
Only accepted logging callee occurrences receive the diagnostic-text exemption.
The same spelling in an argument or unrelated expression is still checked.

Comparison uses full original Git sources with the existing code/edit masks
applied. In particular, an unused helper added alongside a reorder can be
removed first even when the rendered remaining hunk has fragments of functions.
The reduced hunk is only a candidate gate, never the equivalence proof.

Every remaining changed file must qualify before the commit is removed.
Successful reorders produce whole-file **edit masks**; the helpers remain live
code. Failed comparisons publish no speculative code masks. The rule does not
combine a reorder with a separate rename or logging-wording exemption.

## Adjacent terminal switch arms

With the same audited assumption, `independent_return_case_reorder` accepts
permutations within the initial run of switch arms that each contain exactly
one return statement. Every case label
and return expression must remain identical. Complex arms, fallthrough,
declarations and directives are barriers; an unchanged warning/default arm
can stay after a reordered run. Later runs are unsupported: a preceding complex
arm can fall through into the run's first return, making its position significant.
Ranges and stacked labels are unsupported.

Return expressions cannot introduce tag or enumerator definitions, including
inside `sizeof`: those definitions can change a later arm's name bindings.
Statement expressions, assembly, pragmas and position-dependent constructs
also retain the change. Both revisions pass the same macro guard, with keyword
spellings protected from macro bindings. All source outside canonicalized runs
must have equal preprocessing tokens. The rule uses edit masks and adds no stage.

## Bounds and assumptions

The hunk gate is limited to 256 KiB of changed text; full reorder comparisons
to 512 KiB per file, 16 KiB per helper and 128 eligible helpers. Macro queries
are lazy, with at most 64 names per proof, 128 source files / 2 MiB of source
per scan and 4,096 matched directive records. Explicit lossy discovery uses
512 files / 8 MiB / 16,384 records and audits any assumed budget gap. Both modes
have a 512-entry observation cache and a parsed-file cache limited to 256 files,
16 MiB input and 16,384 definitions. Over-budget or unresolved queries retain
by default. The existing shared blob
reader and incremental spelling index remain in use; no whole-kernel AST is kept.

A separate positive-evidence allowance reads at most 32 complete files / 512 KiB
after a literal requested definition is encountered beyond the baseline read
budget. A size precheck bounds these reads. Certain full-file facts can replace
only newly introduced row placeholders; earlier same-name opacity from another
file remains. Baseline counters, limits, uncertainty and row-boundary behavior
are preserved, and read failures stay nonassumable. The additional evidence
comes from the same repository scan.

Unused-definition checks reject raw phase-two spelling contexts and verify
remaining-code LINE/COLUMN dependencies with the candidate spans blanked at
their original offsets. Raw global-reference renames require complete literal
include/spelling context even in lossy mode; failed context checks run before
expensive global location queries. External/generated input closure remains a
separate model limitation.

This remains an experimental C-source model. Kbuild input closure is currently
unknown, so parser absence and captured configuration do not authorize masks.
Explicit complete CPP context is required for configuration projection.
Compiler keyword macros, generated or forced includes, command-line definitions,
arbitrary preprocessing tricks, external modules and debug/BTF observability
need stronger compiler-aware analysis. A file can also be embedded as raw data
by assembly or consumed by a generator; even comment equivalence then needs a
complete input-role contract. It is not a whole-build proof. Include ordering, field/enum ordering, other switch ordering, statement
ordering, file moves, call-dependent helpers and semantic refactors remain work.

## Validation and measurement

The latest code-address controls and audit requirement are described above;
the historical measurements below refer to their own source snapshots. Actual
public-pipeline fixtures now retain both address counterexamples by default and
require the explicit audited assumption for removal. See
[the current verification](FUTURE_PRUNING_WORK.md#source-reordering-and-code-address-observations--2026-11-07).

Regression coverage includes harmless assembly text versus actual assembly,
macro operators, exact helpers and dependency/call barriers, masking an unused
addition before reordering, a structurally incomplete reduced hunk, numeric and
position-sensitive macros, macro capture, continued/comment-separated/digraph
directives, disabled translation units, changed bodies and file moves.

The pruning verifier independently replays mask coordinates. Reorder validation
shares the production reorder/macro policy helpers; it is not an independent
implementation of C equivalence. Previously excluded unused definitions must
be verified before a dependent reorder decision.

The 2026-11-07 switch inventory examined all 26,670 IDs in the legacy retained
cohort. Of 191 case-label patches, seven had token-permutation hunks in every
stored file; one matched complete original sources and passed conservative
macro/configuration checks: `3c3af563b317` (hrtimer). Its raw file set already
equals the stored set, and exact parent/child Kbuild modes are enabled. Independent
inspection confirmed unchanged clock-to-base mappings and default behavior.
This is one concrete new removal, not a fresh Kbuild replay of all 26,670 IDs.
Independent compiled enum-binding and preceding-fallthrough counterexamples
were retained after review. Earlier results are saved under `before-fallthrough-fix/`.
Evidence is in `benchmarks/switch_reordering/2026-11-07/`.

Measurement uses the frozen 100 surviving commits reviewed in
[PRUNING_SAMPLE_REVIEW_2026_11_06.md](PRUNING_SAMPLE_REVIEW_2026_11_06.md), rebuilt
from original raw patches and inherited legacy file/config selection. It is not
a new population-wide Kbuild run. The original review and its percentages stay
frozen; these changes do not implement its full source/build candidate pool.

| Change | Additional whole commits removed from those 100 |
| --- | ---: |
| Syntax-aware unused-definition guard | 0 |
| Independent static-helper reorder | 1 |
| **Total** | **1 / 100 (1%)** |

The removal is `05849fc5d842` (`mmc: card: add mmc_card_blk_no_cmd23`).
The existing dead-code pass already masks the new unused
`mmc_card_blk_no_cmd23`; the new rule then proves the remaining reorder of
`mmc_card_disable_cd` and `mmc_card_nonstd_func_interface`. Their referenced
quirk macros have literal numeric replacements. An unrelated parameter-name
macro in an unconfigured x86 assembly translation unit does not block it.
All 99 retained patches are byte-identical to their frozen pre-change outputs.
The existing three partial dead-code decisions remain unchanged.

The unused-definition guard fix is exercised by focused fixtures, but it does
not establish any additional removal in this cohort. The arm64 memory header,
for example, also contains actual assembly, so its harmless assembly text was
not the only retention reason. The trace-printk cross-file move, binding-aware
field rename, generated declarations, enum members, global definitions and
semantic cleanups remain retained. The earlier 8% rename/reorder estimate was
a broader manual opportunity pool, not the yield of this narrow rule.

With reference caches already primed, one sequential pair took 88.97 seconds
before versus 78.02 seconds after, with 100 versus 99 output commits. This
shared host also had unrelated compilation load; these single timings do not
establish a speedup. Reference-index repository scans were 10 and 11,
respectively; the latter count excludes the two new macro-guard scans. The
macro cache is currently bounded in-memory, not an incremental on-disk index.
This is not an end-to-end config-stage benchmark or a measured memory bound.

Validation: **514 tests pass**, mypy passes for the five affected production /
verification modules, and `git diff --check` passes. Audit replay verifies all
four recorded decisions (the three existing unused-definition decisions and
the new reorder); its shared-policy limitation is described above. Evidence,
baseline source, runner and hashes are saved under
`benchmarks/source_pruning_easy/2026-11-06/final/` (the existing ignored benchmark
artifact directory).

## Latest full-original comparison replay

The 85-candidate results in this section predate the caller-binding repair.
That repair rechecks the eleven accepted originals and retains one additional
GIC wording commit: seven default removals and ten lossy removals remain. The
wider 85/full-cohort counts have not been recomputed. See the
[later evidence](FUTURE_PRUNING_WORK.md#logger-binding-repair-and-further-bounds--2026-11-07).

Later safety work supersedes the earlier yield figures for the current source
snapshot. A full 26,670-ID structural screen found 85 complete-patch comparison
candidates. Replaying those actual original parent/child sources with current
production guards removes eight by default and eleven with explicit lossy mode.
Only one ID is new versus the historical ten diagnostic removals:
`ab017a15fdb2`, a prototype-parameter rename. The two other mode differences
restore old diagnostic exemptions under explicit incomplete-macro assumptions.
No body rename or reorder from the historical relaxed candidate union passes
the current guards. The new removal is 0.00375% of the legacy retained cohort,
and remains conditional on incomplete preprocessing inputs.

The default replay takes 49.34 seconds; lossy takes 874.77 seconds for the 85
candidates with the benchmark's reader rotation/cache setup. This is not a full
pipeline benchmark or a proven memory bound. Full results and inspection are in
`benchmarks/lossy_yield/2026-11-07/current-production-replay/`; the detailed
[latest progress notes](FUTURE_PRUNING_WORK.md#partial-macro-facts-and-source-positions--resumed-2026-11-07)
include the risk, timing and memory limits. The current frozen snapshot passes
1,018 tests, all 58 Python source files pass mypy, and all 59 Python/C++ package
sources match the built wheel.
