"""Physical macro-use positions, including multiline invocation extents."""

from bisect import bisect_right
from collections import defaultdict
from dataclasses import dataclass
import re

from .whitespace.c_lexer import _MASTER_RE, preprocessor_directive_text, tokenize_c_source


_SPLICE = re.compile(r"\\(?:\r\n|\n)")
_MAX_TOKENS = 131072
_MAX_DEPTH = 128


@dataclass(frozen=True, slots=True)
class PositionChanges:
    lines: frozenset[str]
    columns: frozenset[str]


@dataclass(frozen=True, slots=True)
class SourcePositionExemptions:
    old: frozenset[int] = frozenset()
    new: frozenset[int] = frozenset()


@dataclass(frozen=True, slots=True)
class _PositionedToken:
    kind: str
    value: str
    offset: int
    start_line: int
    start_column: int
    end_line: int
    end_column: int


@dataclass(frozen=True, slots=True)
class _Group:
    start: int
    end: int
    names: frozenset[str]


@dataclass(slots=True)
class _OpenGroup:
    start: int
    names: set[str]


def _tokens(source: bytes) -> tuple[_PositionedToken, ...] | None:
    text = source.decode()
    if preprocessor_directive_text(text) is None or tokenize_c_source(text) is None:
        return None
    cuts: list[int] = []
    removed = [0]
    for splice in _SPLICE.finditer(text):
        cuts.append(splice.start() - removed[-1])
        removed.append(removed[-1] + len(splice.group()))
    logical = _SPLICE.sub("", text)
    line_starts = [0, *(match.end() for match in re.finditer(b"\n", source))]
    previous_char = previous_byte = 0

    def physical(offset: int) -> tuple[int, int, int]:
        nonlocal previous_char, previous_byte
        character = offset + removed[bisect_right(cuts, offset)]
        byte = previous_byte + len(text[previous_char:character].encode())
        previous_char, previous_byte = character, byte
        line = bisect_right(line_starts, byte)
        return byte, line, byte - line_starts[line - 1] + 1

    result: list[_PositionedToken] = []
    for match in _MASTER_RE.finditer(logical):
        if match.lastgroup in {"WHITESPACE", "NEWLINE", "BLOCK_COMMENT", "LINE_COMMENT"}:
            continue
        if len(result) >= _MAX_TOKENS:
            return None
        offset, first_line, first_column = physical(match.start())
        _, last_line, last_column = physical(match.end())
        result.append(_PositionedToken(match.lastgroup or "", match.group(), offset, first_line, first_column,
                                       last_line, last_column))
    return tuple(result)


def _groups(tokens: tuple[_PositionedToken, ...], exemptions: frozenset[int]) -> tuple[_Group, ...] | None:
    """Conservatively associate aliases/arguments with closing parentheses.

    GCC and Clang can use different ends of a multiline macro invocation for
    __LINE__. Include all names in a balanced group and contiguous identifier
    aliases immediately preceding it. Extra C declaration groups only retain.
    """
    stack: list[_OpenGroup] = []
    result: list[_Group] = []
    preceding: set[str] = set()
    for index, token in enumerate(tokens):
        if token.kind == "IDENTIFIER":
            if token.offset not in exemptions:
                preceding.add(token.value)
                if stack:
                    stack[-1].names.add(token.value)
            continue
        if token.kind == "PUNCT" and token.value == "(":
            if len(stack) >= _MAX_DEPTH:
                return None
            stack.append(_OpenGroup(index, preceding.copy()))
        elif token.kind == "PUNCT" and token.value == ")":
            if not stack:
                return None
            group = stack.pop()
            result.append(_Group(group.start, index, frozenset(group.names)))
            if stack:
                stack[-1].names.update(group.names)
        preceding.clear()
    return None if stack else tuple(result)


@dataclass(frozen=True, slots=True, order=True)
class _Site:
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    kind: str


def _sites(tokens: tuple[_PositionedToken, ...], ignored: frozenset[str],
           exemptions: frozenset[int]) -> dict[str, tuple[_Site, ...]] | None:
    groups = _groups(tokens, exemptions)
    if groups is None:
        return None
    positions: defaultdict[str, list[_Site]] = defaultdict(list)
    size = 0
    for token in tokens:
        if token.kind == "IDENTIFIER" and token.value not in ignored and token.offset not in exemptions:
            positions[token.value].append(_Site(token.start_line, token.start_column,
                                               token.end_line, token.end_column, "identifier"))
            size += 1
    for group in groups:
        first, last = tokens[group.start], tokens[group.end]
        site = _Site(first.start_line, first.start_column, last.end_line, last.end_column, "parentheses")
        for name in group.names - ignored:
            positions[name].append(site)
            size += 1
            if size > 262144:
                return None
    return {name: tuple(sorted(sites)) for name, sites in positions.items()}


def changed_identifier_positions(old: bytes, new: bytes, ignored: frozenset[str], *,
                                 exemptions: SourcePositionExemptions = SourcePositionExemptions()) -> PositionChanges | None:
    """Compare occurrence extents by spelling, including code outside a reorder.

    Reorder proofs separately guard every name inside their permutation. This
    also keeps unchanged macro uses elsewhere observable when whitespace moves.
    Parenthesized extents cover both GCC's invocation-start and Clang's
    invocation-end location behavior without reconstructing macro expansion.
    """
    first, second = _tokens(old), _tokens(new)
    if first is None or second is None:
        return None
    before, after = _sites(first, ignored, exemptions.old), _sites(second, ignored, exemptions.new)
    if before is None or after is None:
        return None
    names = before.keys() | after.keys()
    lines = frozenset(name for name in names
                      if tuple((site.kind, site.start_line, site.end_line) for site in before.get(name, ()))
                      != tuple((site.kind, site.start_line, site.end_line) for site in after.get(name, ())))
    columns = frozenset(name for name in names
                        if tuple((site.kind, site.start_column, site.end_column) for site in before.get(name, ()))
                        != tuple((site.kind, site.start_column, site.end_column) for site in after.get(name, ())))
    return PositionChanges(lines, columns)
