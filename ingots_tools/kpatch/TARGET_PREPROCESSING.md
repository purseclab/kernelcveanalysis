# Target-preprocessed equivalence

`TargetPreprocessorFilter` compares the compiler-expanded inputs of the actual
parent and child revisions. It can remove redundant includes, equivalent
preprocessor guards and unused macro-definition changes without treating each
syntax transformation as a separate rule. BTF/debug provenance is outside its
relevance scope. Actual expanded values, declarations, executable tokens and
semantic pragma effects remain significant.

Enable it independently of the security-policy stage:

```console
uv run kpatch filter --repo /path/to/linux --db all_commits --dest preprocessed \
  config --config /path/to/build/.config \
  --preprocess-build-context /path/to/context.json \
  --preprocess-report /path/to/preprocessing.jsonl \
  --preprocess-cache /path/to/preprocessing.sqlite
```

Create the context using the existing `kpatch policy build-context` command.
It pins the source/build roots, configuration, compilation database, generated
inputs and compiler version. The context can describe an explicitly chosen
reference build; it need not claim identity with an Android binary. Compiler
errors and missing commands remain unknown rather than being guessed away.
Keep outputs and caches outside the source/build directories.

Comparisons stay within that prepared build epoch. Each revision may overlay
at most 256 modified files and 8 MiB relative to the context baseline; added or
deleted paths and changes to build descriptions require a new context. These
limits bound per-commit work and are reported as unknown results. Long histories
that cross build epochs need separate prepared contexts.

The kernel include/build model finds possible consumers of changed headers.
Every modeled active consumer must have a compilation command and matching
expanded input on both revisions. Positive supplied inputs from `--build-inputs`
remain consumers even if the base configuration omits them. The model assumes
ordinary kernel source/include conventions; it does not claim exhaustive
coverage of arbitrary external build scripts.

The comparison uses fresh compiler expansion rather than source strings after
earlier masks. A previous edit mask therefore never fabricates compiler input.
Matching inputs publish whole-file **edit masks**, leaving the code live for
later analyses. Different tokens, unsupported pragma effects, incomplete source
updates, missing consumers, nonregular/structural changes and resource limits
retain the affected file. Other files in the same commit may still qualify.

Macro-definition and invocation spelling are not hashed independently: an
unused definition or an equivalent invocation may legitimately differ. Values
of expanded `__LINE__`, `__COUNTER__` and related builtins still appear in the
token stream. Compiler-evaluated source-location builtins remain position
sensitive. Pragmas are hashed in order; unresolved macro-dependent pragmas and
pragma operators remain unsupported. This is separate from the policy stage's
stricter fingerprint outside excluded runtime spans, which also preserves
preprocessing events inside those spans.

The first comparison indexes actual compiler dependencies for the recorded
build once. Revision deltas select dirty translation units through that reverse
index; new dependencies discovered while recompiling those units join the
revision's consumer set. Both revisions must agree for every affected consumer.
The 128-unit comparison limit applies to affected units, so a larger compilation
database does not by itself prevent pruning. Inventory limits are 65,536 units
and eight million dependency edges. The configured build model also checks
for live source inputs missing from the compilation database, including inputs
with forced headers. An incomplete inventory retains the affected changes.

Successful results are cached by compiler/build identity, main-source contents
and exact dependency hashes. Changed headers invalidate cached results even
when the main C file is unchanged. The memory cache keeps 32 successful entries.
The optional compressed SQLite cache preserves the current baseline for each
command and up to four historical variants per unit, within a 1 GiB payload
budget. A full cache skips writes rather than discarding baseline records needed
by the current inventory. Unknown results do not become equivalence facts.
Shared source readers and include graphs are reused across the pipeline.

JSONL records identify the original commit/file, compiler-context hash,
translation units, paired digests and the reason for exclusion or retention.
Known raw-data/generator consumers still veto a C-source comparison. The
existing `--unresolved-inputs-lossy --input-role-report PATH` option may assume
its named unresolved operand classes; those assumptions remain explicit and
audited, independently of accepting BTF/debug differences.

A native 130-unit control (one affected header consumer and 129 unrelated
units) took 16.95 s cold and 7.96 s with a fresh stage and its persistent cache.
The cold pass performed 131 preprocessing extractions; the warm pass performed
none and recorded 131 cache hits. Each pass compared one affected consumer.
This small synthetic control verifies reuse and the affected-unit limit; it
does not estimate whole-kernel throughput or pruning yield. Its saved results
are in `benchmarks/target_preprocessing_index/2026-11-08/results.json`.
