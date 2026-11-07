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
trailing trivia do not.

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

This certifies the modeled C/C++ source observations for fixed surrounding
inputs. It does not establish whole-build input closure. A generator, assembler
or program can read a source/header as raw bytes; source equivalence does not
justify pruning that separate role. Unpinned forced inputs and build-time source
metadata remain part of the existing source-analysis limits.

Token columns are physical UTF-8 byte columns, as exercised against the installed
GCC/Clang controls. This is not a claim about every frontend's visual diagnostic
column convention. Moving code or changing its token gaps is conservatively
retained, even when a particular build might not observe the difference.
