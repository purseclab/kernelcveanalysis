# Filter masks and source views

Filtering keeps a lazy, deeply immutable snapshot of the input patch in
`FilteredCommit.original_diff`. Stages add typed decisions instead of changing
the original file list or rewriting hunks. The original `GitCommit` still owns
its metadata; scores and ratings can be updated independently.

## Two mask types

| Type | Meaning | Source-analysis effect |
| --- | --- | --- |
| `EditMask` | Ignore a modification, without claiming the surrounding code is inactive. | Reconstruct the child using the parent's text for suppressed edits. Declarations and scope remain available. |
| `CodeMask` | Complete source lines have been established as irrelevant on a particular revision side. | Blank those lines in full-source analysis, including unchanged lines. Preserve their byte lengths and CR/LF characters. |

`LineRange(start, end)` uses one-based, end-exclusive **original** physical
line coordinates. Old and new ranges are independent. File identities, revision
sides, reasons, and ranges are explicit frozen data classes/enums. Public mask
collections are immutable tuples; internal lookups are indexed by file/path.

Masks are assertions by the producing analysis. A type does not prove a policy
decision: a caller may exclude code only after establishing its irrelevance.
Edit exclusions alone never hide foreign references from the reference index.

```python
from kpatch.filter import LineRange, MaskReason, SourceSide

# Ignore modifications while retaining the parent's declaration.
commit.mask_edits(
    file,
    old_lines=(LineRange(10, 11),),
    new_lines=(LineRange(10, 12),),
    reason=MaskReason.WHITESPACE,
)

# Exclude an entire proven-inactive region, including unchanged references.
commit.mask_code(file, SourceSide.OLD, (LineRange(20, 30),), MaskReason.IFDEF)
commit.mask_code(file, SourceSide.NEW, (LineRange(21, 34),), MaskReason.IFDEF)
```

## Views

- `original_diff`: immutable original text, files, and hunks.
- `remaining_diff()` / `diff`: the lazily cached, valid reduced patch for
  ordinary consumers. Treat this returned `Diff` as read-only; producers must
  use the mask methods. Mutating its lists bypasses mask provenance.
- `changed_lines(file, side)`: remaining changed lines in original coordinates,
  so AST definitions are never located using shifted rendered hunk offsets.
- `effective_sources(file, SourceVersions(old, new))`: full parent and a child
  reconstructed by applying the remaining edits. Suppressed deletions retain
  parent text; suppressed additions disappear.
- `active_sources(file, SourceVersions(old, new))`: blank code masks in the
  original versions, then replay edit masks. This does not resurrect inactive
  old code. An optional tuple of extra code masks supports a pure preview;
  rename detection publishes those masks only after a successful proof.

Source replay verifies original hunk payloads, counts, unchanged gaps, and EOF
against both repository versions. A mismatch causes source-pruning stages to
retain the candidate. Code masks preserve source positions, while edit replay
can change the reconstructed child's line positions.

Patch rendering lives in one place. Masked deletions become context, masked
insertions disappear, and headers/counts/offsets are regenerated. Opaque binary
changes, file modes, and rename/copy metadata remain unless an entire file's
edits are explicitly masked. Partial deletions get appropriate file headers.
Ambiguous partial selection involving a missing-final-newline marker retains
the original file patch rather than emitting a malformed patch or concatenating
unrelated lines. Full suppression remains possible.

## Stage responsibilities and order

With `--source-pruning`, the shared factory builds:

```text
merge → config → ifdef → dead code → whitespace → rename
```

The final stage also applies the narrow diagnostic-wording policy described in
[DIAGNOSTIC_STRING_PRUNING.md](DIAGNOSTIC_STRING_PRUNING.md). It compares temporary
normalized source views and records whole-file **edit** masks only after the
whole remaining commit qualifies. Diagnostic wording never produces a code
mask: the logging call and its argument evaluation remain live. Decisions use
`diagnostic_wording` or `consistent_rename_and_diagnostics` to distinguish the
policy exemption from an identifier-only rename.

The same final stage accepts bounded same-file permutations of adjacent
unchanged independent static leaf helpers. It checks the complete active source
pair, including dead-code masks, even when a reduced hunk alone is not a valid
function. It records `independent_definition_reorder` **edit** masks only after
all remaining files qualify and both revisions pass the macro guard. It never
excludes the reordered helpers as inactive code. No additional pipeline stage
or progress bar is added. See [the reorder rules](UNUSED_CODE_AND_REORDER_PRUNING.md).

- **Config:** mask excluded edits; exclude code only for proven-unused compilation
  files on the appropriate revision sides. Build metadata exclusions stay edit
  masks, and copying a file does not exclude its unchanged source. Preserve
  build modes for surviving files.
- **Ifdef:** record complete inactive source regions separately for the old
  and new build modes. Unknown conditions remain active conservatively.
- **Dead code:** use original coordinates and check references in both
  revisions. Mask whole-line definitions only when adjacent active code cannot
  be erased. Support partial function pruning with an eight-candidate fallback
  limit, keeping grouped checks for macros/types. Partial proofs require a
  consumer scope of at most 256 paths or preseeded reference facts. Defer name-only definition
  changes to the cheaper rename stage.
- **Whitespace:** consume the reduced patch and reconstruct its full sources
  for confirmation. Running after dead code clears residual documentation
  edits. Ordinary classifier input also uses the remaining patch when masks
  exist.
- **Rename:** compare full masked AST/token views, enforce consistent
  declaration-anchored substitutions, and check foreign references in both
  revisions, including macro collisions for local substitutions. Existing code masks apply to reference sites; edit masks do not
  establish that a foreign caller is irrelevant.

For example, a file can contain an active helper rename and an unrelated
unused function body change. Dead-code analysis masks the unused definition;
rename analysis sees the remaining helper rename with full declaration context.
A live value change in the same file still prevents rename pruning.

## Safety and performance boundaries

- Preserve changes that move direct `__LINE__` occurrences or involve direct
  counter macros conservatively. Inactive text can still affect translation
  metadata through line positions.
- Do not mask a definition sharing a physical line with neighboring active
  code. Keep nested tags/enumerators and definitions with preprocessor or pragma
  effects that can escape their C scope.
- Query/cache raw references independently of masks, then evaluate the current
  configuration and code exclusions. A live prefetched symbol cannot abort an
  unrelated requested search. Incremental updates use actual Git deltas,
  including removed files and build fragments, rather than trusting a possibly
  reduced input file list. Version 4 invalidates older reference facts.
- Positive reference probes inspect likely changed/header consumers first,
  with enforced limits of 16 inspected sources and 256 graph nodes. Failure to
  find a reference in that sample never establishes absence.
- Keep existing 64 KiB unused-definition and 2 MiB rename file limits, bounded
  reference caches, and a shared Git blob reader. Build source views only for
  plausible candidates, without retaining whole-kernel ASTs.

This remains an experimental source-reference analysis. Arbitrary generated
names, macro expansion, external modules, and BTF/debug observability need
stronger build-aware analysis for compiler-level equivalence.

Mask provenance belongs to a pipeline run. Final `materialize()` exports the
reduced ordinary commit for the existing database format; it does not persist
all mask metadata. Rerun context-sensitive filtering from `all_commits`, or
retain the original patch and mask history when implementing resumable stages.
The benchmark's pruning decisions include mask snapshots for independent replay.

See [the masking benchmark report](benchmarks/ast_pruning/2026-10-25-masking/REPORT.md).
