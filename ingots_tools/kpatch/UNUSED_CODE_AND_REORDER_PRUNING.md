# Unused-code guards and helper reordering

Implemented in the existing opt-in `--source-pruning` pipeline. Its order stays
merge → config → ifdef → dead code → whitespace → final comparison. The final
comparison is still `RenameFilter`; there is no extra stage or progress bar.

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

The new `independent_definition_reorder` rule accepts a permutation of adjacent
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
  Unknown bindings, aliases and function-like macros retain the candidate.

Macro lookup normalizes comments and backslash continuations, handles ordinary
and digraph directive spellings, and reuses existing Kbuild decisions for
disabled translation units. Header definitions remain conservative. Facts are
cached by revision/name independently of the current mask ledger.

Comparison uses full original Git sources with the existing code/edit masks
applied. In particular, an unused helper added alongside a reorder can be
removed first even when the rendered remaining hunk has fragments of functions.
The reduced hunk is only a candidate gate, never the equivalence proof.

Every remaining changed file must qualify before the commit is removed.
Successful reorders produce whole-file **edit masks**; the helpers remain live
code. Failed comparisons publish no speculative code masks. The rule does not
combine a reorder with a separate rename or logging-wording exemption.

## Bounds and assumptions

The hunk gate is limited to 256 KiB of changed text; full reorder comparisons
to 512 KiB per file, 16 KiB per helper and 128 eligible helpers. Macro queries
are lazy, with at most 64 names per proof, 32 source files / 512 KiB of source
per scan, 4,096 matched directive records and a 512-entry in-memory cache.
Over-budget or unresolved queries retain the commit. The existing shared blob
reader and incremental spelling index remain in use; no whole-kernel AST is kept.

This remains a raw-source kernel analysis under the existing build model,
including its assumption about independently compiled translation units.
Compiler keyword macros, generated or forced includes, command-line definitions,
arbitrary preprocessing tricks, external modules and debug/BTF observability
need stronger compiler-aware analysis. It is not a general proof of identical
binaries. Include ordering, field/enum ordering, switch ordering, statement
ordering, file moves, call-dependent helpers and semantic refactors remain work.

## Validation and measurement

Regression coverage includes harmless assembly text versus actual assembly,
macro operators, exact helpers and dependency/call barriers, masking an unused
addition before reordering, a structurally incomplete reduced hunk, numeric and
position-sensitive macros, macro capture, continued/comment-separated/digraph
directives, disabled translation units, changed bodies and file moves.

The pruning verifier independently replays mask coordinates. Reorder validation
shares the production reorder/macro policy helpers; it is not an independent
implementation of C equivalence. Previously excluded unused definitions must
be verified before a dependent reorder decision.

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
