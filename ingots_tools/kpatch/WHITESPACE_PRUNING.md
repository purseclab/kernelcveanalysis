# Whitespace pruning

The whitespace stage removes supported C/C++ comment and formatting edits only
when the remaining complete source versions have equal preprocessing tokens,
logical token separation and physical token locations. A file does not need to
spell a location builtin directly: an included macro can expand to `__LINE__`
or `__builtin_COLUMN()`. Macro stringification can also observe spaces between
otherwise identical tokens.

## Comparison

The existing hunk check remains an inexpensive rejection step. A hunk beginning
inside a block comment can recover the opener from complete source context.
Every acceptance then uses `LayoutComparer`; comment stripping and token-value
equality alone no longer accept a file.

The shared lexer streams typed spans after standard backslash-newline splicing.
Each span identifies its token and whether logical whitespace or a comment
precedes it. The comparison hashes token kinds, spellings and gaps, plus every
real token's physical start/end line and UTF-8 byte column. It maps token starts
after a removed splice and token ends before that splice. Directive boundaries
and optional ordinary newline tokens remain significant; their columns and
trailing trivia do not. An explicit newline already separates tokens, so the
gap immediately following it is normalized; all other gaps remain significant.

Angle header names are atomic, with their exact internal bytes preserved.
The lexer advances past the whole header instead of emitting its contents as
additional ordinary tokens. This also prevents a comment-looking filename
from consuming the following source.

Code masks blank excluded code at its original physical lines. They are not
replayed as discarded edits: removing an added inactive line from the comparison
would hide a subsequent line-number change. Previously established edit masks
retain their explicit edit-projection semantics.

## Bounds and unsupported input

The comparison accepts at most 2 MiB and 131,072 emitted tokens per source.
The token budget is enforced while lexing. Its cache contains typed digest
facts, including failed scans, with at most 512 entries and 16 MiB of represented
source input. Cached facts do not retain source buffers or token arrays.
Git source reads continue to use the pipeline's shared bounded blob reader.

Invalid UTF-8, NUL, BOM, trigraph spellings, bare CR, GNU whitespace-before-newline
splices, unsupported tokens, unclosed complete-source comments/literals and
ambiguous multiline directive comments retain the edit. Ordinary unchanged
standard splices are supported. C++ raw literals, header-unit imports,
`__has_include`, `__has_include_next`, `__has_embed` and `#embed` require lexical
contexts this implementation does not model, so they also retain changes.
Non-ASCII whitespace outside literals/comments is unsupported.

## Scope

Every existing side must have a regular Git mode (`100644` or `100755`). Missing
patch modes require an exact historical tree lookup; unresolved modes retain
the change. Symlinks named like C files are excluded because their blob bytes
are link targets, where comment-looking text can select a different file.

This certifies the modeled C/C++ source observations for fixed surrounding
inputs. It does not establish whole-build input closure. A generator, assembler
or program can read a source/header as raw bytes; source equivalence does not
justify pruning that separate role. Unpinned forced inputs and build-time source
metadata remain part of the existing source-analysis limits.

Before accepting a file, the shared raw-input index checks both original
historical versions for recognized assembly and Make generator consumers.
Positive consumers, recognized unresolved inputs, scan errors and budget limits
retain the candidate, including in line-number-lossy mode. The index uses bounded
revision and content caches; unchanged consumer facts can survive revision
updates. Per-file parser-budget failures remain cached uncertainties, while
aggregate inventory failures prevent reuse of an incomplete snapshot.
An empty observation does not prove that arbitrary scripts or external inputs
cannot consume this file. See [the shared API](FILTER_MASKING.md#raw-input-consumer-veto).
The independent [input-role assumption mode](SOURCE_INPUT_ROLE_ASSUMPTIONS.md)
can waive specified local unsupported expressions after a full recognized
inventory and a mandatory lossy audit. It does not waive observed consumers,
failed scans or the whitespace/line-number checks.

Token columns are physical UTF-8 byte columns, as exercised against the installed
GCC/Clang controls. This is not a claim about every frontend's visual diagnostic
column convention. Moving code or changing its token gaps is conservatively
retained, even when a particular build might not observe the difference.

## Explicit line-number assumption

The default remains strict. The separate `--whitespace-line-numbers-lossy`
option, with mandatory `--whitespace-report`, permits only the physical line
coordinates to differ. Token kinds/spellings, logical gaps, directive boundaries,
physical byte columns, supported-input checks and resource limits still apply.
It does not enable other lossy source-pruning rules.

The cached complete fact has a framed token/gap/column digest and a separate
ordered line digest. Strict comparison checks both; the explicit relaxed method
checks the first. Both use the same complete scan and bounded cache.

This is an assumption, not a runtime-equivalence proof. An included `__LINE__`
alias can control a branch, array size, preprocessing condition or generated
name. Compiled controls demonstrate a changed return value accepted only by the
lossy option. There is no measured upper bound on its false-removal rate.

Every pruned file receives an audit record. Strict acceptances stay labeled
`whitespace_or_comments`, `lossy=false`; additional acceptances use
`whitespace_line_numbers_lossy`, `lossy=true`, with explicit runtime-risk reasons.
Each record contains only the affected file's original-coordinate masks. The
programmatic lossy mode also requires a decision callback; callback failures
propagate rather than silently omitting an audit.

Report/cache validation covers all destinations before opening any: source,
build and Git metadata roots, protected inputs, SQLite sidecars, aliases and
overlapping output paths. Linked-worktree metadata outside the checkout is
protected as well. Existing destination-name symlinks are rejected.
