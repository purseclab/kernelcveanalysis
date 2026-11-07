"""Bounded C preprocessing-token and physical-layout equivalence.

Equal token spelling, whitespace gaps and physical token coordinates preserve
the source observations modeled by this filter. This does not certify programs
which consume the original source bytes through a separate raw-input role.
"""

from collections import OrderedDict
from collections.abc import Iterator
from dataclasses import dataclass
from hashlib import sha256
import re
from struct import pack

from .c_lexer import (
    CTokenKind,
    CTokenSpan,
    CTokenizationError,
    iter_c_token_spans,
    preprocessor_directive_text,
)


# Match the existing source-analysis envelope. Spans stream into one digest;
# even a source below the byte cap cannot allocate an unbounded token list.
_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_MAX_TOKENS = 131072
_CACHE_ENTRIES = 512
_CACHE_INPUT_BYTES = 16 * 1024 * 1024
_STANDARD_SPLICE = re.compile(r"\\(?:\r\n|\n)")
_GNU_SPLICE = re.compile(rb"\\[^\S\r\n]+(?:\r\n|\n|\r)")
_BARE_CR = re.compile(rb"\r(?!\n)")
_HEADER_OPERATORS = frozenset({"__has_include", "__has_include_next", "__has_embed"})
_SEMANTIC_NEWLINES = frozenset({CTokenKind.DIRECTIVE_NEWLINE, CTokenKind.NEWLINE})


@dataclass(frozen=True, slots=True)
class LayoutStats:
    scans: int
    cache_hits: int
    unsupported_scans: int
    cache_entries: int
    cache_input_bytes: int


@dataclass(frozen=True, slots=True)
class _LayoutFact:
    body_digest: bytes
    line_digest: bytes
    token_count: int


@dataclass(frozen=True, slots=True)
class _CachedLayout:
    input_bytes: int
    fact: _LayoutFact | None


class _SpliceMap:
    """Map increasing logical offsets without building per-character tables."""

    def __init__(self, source: str) -> None:
        self._matches: Iterator[re.Match[str]] = _STANDARD_SPLICE.finditer(source)
        self._next = next(self._matches, None)
        self._removed = 0

    def physical(self, logical: int, *, right_bias: bool) -> int:
        while self._next is not None:
            cut = self._next.start() - self._removed
            if cut > logical or cut == logical and not right_bias:
                break
            self._removed += self._next.end() - self._next.start()
            self._next = next(self._matches, None)
        return logical + self._removed


class _PhysicalCursor:
    def __init__(self, source: str) -> None:
        self.source = source
        self._character = 0
        self._byte = 0
        self._line_start = 0
        self.line = 1

    @property
    def column(self) -> int:
        return self._byte - self._line_start + 1

    def advance(self, character: int) -> None:
        if not self._character <= character <= len(self.source):
            raise CTokenizationError("Token spans are not in physical source order")
        chunk = self.source[self._character:character].encode()
        newline = chunk.rfind(b"\n")
        if newline >= 0:
            self.line += chunk.count(b"\n")
            self._line_start = self._byte + newline + 1
        self._byte += len(chunk)
        self._character = character


def _unsupported(source: bytes) -> bool:
    return (b"\0" in source or b"??" in source or b"\xef\xbb\xbf" in source
            or _BARE_CR.search(source) is not None or _GNU_SPLICE.search(source) is not None)


def _token_frame(span: CTokenSpan) -> bytes:
    kind, value = span.token.kind.value.encode(), span.token.value.encode()
    gap = span.whitespace_before if span.token.kind not in _SEMANTIC_NEWLINES else False
    return pack(">II?", len(kind), len(value), gap) + kind + value


class LayoutComparer:
    """Cache complete typed facts, never raw source or partial token scans.

    Cache accounting bounds both entry count and the input bytes represented by
    those facts. Unsupported inputs compare false, including identical inputs.
    """

    def __init__(self, *, ignore_non_directive_newlines: bool = True) -> None:
        self.ignore_non_directive_newlines = ignore_non_directive_newlines
        self._cache: OrderedDict[bytes, _CachedLayout] = OrderedDict()
        self._cache_input_bytes = 0
        self._scans = 0
        self._cache_hits = 0
        self._unsupported_scans = 0

    @property
    def stats(self) -> LayoutStats:
        return LayoutStats(self._scans, self._cache_hits, self._unsupported_scans,
                           len(self._cache), self._cache_input_bytes)

    def equivalent(self, old: bytes, new: bytes) -> bool:
        first, second = self._fact(old), self._fact(new)
        return first is not None and second is not None and first == second

    def equivalent_ignoring_line_numbers(self, old: bytes, new: bytes) -> bool:
        """Ignore physical lines while preserving tokens, gaps and byte columns.

        This explicitly permits changes observed through line-number builtins
        and included aliases. Complete-source support and bounds still apply.
        """
        first, second = self._fact(old), self._fact(new)
        return (first is not None and second is not None
                and first.body_digest == second.body_digest
                and first.token_count == second.token_count)

    def _fact(self, source: bytes) -> _LayoutFact | None:
        if len(source) > _MAX_SOURCE_BYTES:
            self._scans += 1
            self._unsupported_scans += 1
            return None
        key = sha256(source).digest()
        if key in self._cache:
            self._cache_hits += 1
            self._cache.move_to_end(key)
            return self._cache[key].fact
        self._scans += 1
        fact = self._scan(source)
        if fact is None:
            self._unsupported_scans += 1
        self._cache[key] = _CachedLayout(len(source), fact)
        self._cache_input_bytes += len(source)
        while len(self._cache) > _CACHE_ENTRIES or self._cache_input_bytes > _CACHE_INPUT_BYTES:
            _, old = self._cache.popitem(last=False)
            self._cache_input_bytes -= old.input_bytes
        return fact

    def _scan(self, source: bytes) -> _LayoutFact | None:
        if _unsupported(source):
            return None
        try:
            text = source.decode("utf-8", errors="strict")
            if preprocessor_directive_text(text, strict_multiline=True) is None:
                return None
            return self._token_digest(text)
        except (UnicodeError, CTokenizationError):
            return None

    def _token_digest(self, source: str) -> _LayoutFact | None:
        body_digest = sha256(b"kpatch:pp-layout:body:v1\0")
        line_digest = sha256(b"kpatch:pp-layout:lines:v1\0")
        mapper, cursor = _SpliceMap(source), _PhysicalCursor(source)
        count = 0
        for span in iter_c_token_spans(source, self.ignore_non_directive_newlines, _MAX_TOKENS):
            if span.token.kind is CTokenKind.OTHER or (
                span.token.kind is CTokenKind.IDENTIFIER and span.token.value in _HEADER_OPERATORS
            ):
                return None
            body_digest.update(_token_frame(span))
            if span.token.kind not in _SEMANTIC_NEWLINES:
                cursor.advance(mapper.physical(span.start, right_bias=True))
                first_line, first_column = cursor.line, cursor.column
                cursor.advance(mapper.physical(span.end, right_bias=False))
                body_digest.update(pack(">II", first_column, cursor.column))
                line_digest.update(pack(">II", first_line, cursor.line))
            count += 1
        return _LayoutFact(body_digest.digest(), line_digest.digest(), count)
