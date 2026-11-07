"""Bounded candidate ranges for environment-independent CPP branch folding.

These ranges are not masking proofs. Callers must validate the complete original
lexer and compare the complete projected outside layout before applying them.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from hashlib import sha256
import re
from typing import TYPE_CHECKING

from .masking import LineRange

if TYPE_CHECKING:
    from .ifdef_filter import _LogicalLine


_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_MAX_PHYSICAL_LF = 65536
_MAX_NESTING = 128
_MAX_GROUPS = 2048
_CACHE_ENTRIES = 512
_CACHE_INPUT_BYTES = 16 * 1024 * 1024
_DIRECTIVE = re.compile(r"^[ \t]*(?:#|%:)[ \t]*([A-Za-z_][A-Za-z_0-9]*)(.*)$")
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")
_CONTROLS = frozenset({"if", "ifdef", "ifndef", "elif", "else", "endif"})
_HINT_SPLICE = re.compile(rb"\\(?:\r\n|\n)")
_HINT_UNSUPPORTED = re.compile(rb"\r(?!\n)|[\0\v\f]|\\[ \t]+(?:\r\n|\n|\r)")
_HINT_CONDITION = re.compile(
    rb"(?:#|%:)[ \t]*(?:/\*|[\\\x80-\xff]|if\b[ \t]*(?:[0-9(+\-!~]|/\*|[\\\x80-\xff]))"
)


def may_have_numeric_condition(source: bytes) -> bool:
    """Cheap necessary hint for nonempty scanner candidates, never a proof.

    Every resolved group starts with a numeric ``#if``. Standard splices are
    removed before searching; comments that can separate its directive tokens
    force a full scan. Unanchored matching deliberately overcounts text inside
    comments/literals and after leading comments. Validation remains mandatory.
    """
    if b"??" in source or b"\xef\xbb\xbf" in source or _HINT_UNSUPPORTED.search(source):
        return True
    logical = _HINT_SPLICE.sub(b"", source) if b"\\" in source else source
    return _HINT_CONDITION.search(logical) is not None


@dataclass(frozen=True, slots=True)
class ConstantBranchCandidates:
    inactive: tuple[LineRange, ...]


@dataclass(frozen=True, slots=True)
class ConstantConditionalStats:
    scans: int
    cache_hits: int
    unsupported_scans: int
    cache_entries: int
    cache_input_bytes: int


@dataclass(frozen=True, slots=True)
class _CachedCandidates:
    input_bytes: int
    candidates: ConstantBranchCandidates | None


@dataclass(slots=True)
class _Arm:
    control: LineRange
    condition: bool | None
    children: list[_Group] = field(default_factory=list)


@dataclass(slots=True)
class _Group:
    arms: list[_Arm]
    ending: LineRange | None = None
    has_else: bool = False


def _condition(expression: str) -> bool | None:
    # These modules also use the whitespace package during initialization.
    from .cpp_expression import evaluate_cpp_expression

    value = evaluate_cpp_expression(expression)
    return value.value != 0 if value is not None else None


def _parse(lines: tuple[_LogicalLine, ...]) -> list[_Group] | None:
    roots: list[_Group] = []
    stack: list[_Group] = []
    groups = 0
    for line in lines:
        text = line.text
        leading = text.lstrip(" \t")
        if text.lstrip().startswith(("#", "%:")) and not leading.startswith(("#", "%:")):
            return None
        if not leading.startswith(("#", "%:")):
            continue
        if not text.isascii():
            return None
        match = _DIRECTIVE.fullmatch(text)
        if match is None:
            continue
        name, expression = match[1], match[2].strip(" \t")
        if name not in _CONTROLS:
            if name.startswith(("if", "elif", "else", "endif")):
                return None
            continue
        control = LineRange(line.first_line, line.stop_line)
        if name in {"if", "ifdef", "ifndef"}:
            if not expression or name != "if" and _IDENTIFIER.fullmatch(expression) is None:
                return None
            groups += 1
            if groups > _MAX_GROUPS or len(stack) >= _MAX_NESTING:
                return None
            condition = _condition(expression) if name == "if" else None
            group = _Group([_Arm(control, condition)])
            (stack[-1].arms[-1].children if stack else roots).append(group)
            stack.append(group)
            continue
        if not stack:
            return None
        group = stack[-1]
        if name == "elif":
            if group.has_else or not expression:
                return None
            group.arms.append(_Arm(control, _condition(expression)))
        elif name == "else":
            if group.has_else or expression:
                return None
            group.has_else = True
            group.arms.append(_Arm(control, True))
        else:
            if expression:
                return None
            group.ending = control
            stack.pop()
    return None if stack else roots


def _collect(groups: list[_Group], ranges: list[LineRange]) -> None:
    for group in groups:
        selected: int | None = None
        resolved = True
        for index, arm in enumerate(group.arms):
            if arm.condition is None:
                resolved = False
                break
            if arm.condition:
                selected = index
                break
        if not resolved:
            for arm in group.arms:
                _collect(arm.children, ranges)
            continue
        assert group.ending is not None
        ranges.append(group.ending)
        for index, arm in enumerate(group.arms):
            ranges.append(arm.control)
            if index == selected:
                _collect(arm.children, ranges)
                continue
            stop = (group.arms[index + 1].control.start
                    if index + 1 < len(group.arms) else group.ending.start)
            if arm.control.end < stop:
                ranges.append(LineRange(arm.control.end, stop))


def _merge(ranges: list[LineRange]) -> tuple[LineRange, ...]:
    result: list[LineRange] = []
    for item in sorted(ranges, key=lambda value: value.start):
        if result and item.start <= result[-1].end:
            result[-1] = LineRange(result[-1].start, max(result[-1].end, item.end))
        else:
            result.append(item)
    return tuple(result)


class ConstantConditionalScanner:
    """Cache complete candidate facts without retaining original source bytes."""

    def __init__(self) -> None:
        self._cache: OrderedDict[bytes, _CachedCandidates] = OrderedDict()
        self._cache_input_bytes = 0
        self._scans = 0
        self._cache_hits = 0
        self._unsupported_scans = 0

    @property
    def stats(self) -> ConstantConditionalStats:
        return ConstantConditionalStats(self._scans, self._cache_hits, self._unsupported_scans,
                                        len(self._cache), self._cache_input_bytes)

    def scan(self, source: bytes) -> ConstantBranchCandidates | None:
        if len(source) > _MAX_SOURCE_BYTES:
            self._scans += 1
            self._unsupported_scans += 1
            return None
        key = sha256(source).digest()
        if key in self._cache:
            self._cache_hits += 1
            self._cache.move_to_end(key)
            return self._cache[key].candidates
        self._scans += 1
        candidates = self._scan(source)
        if candidates is None:
            self._unsupported_scans += 1
        self._cache[key] = _CachedCandidates(len(source), candidates)
        self._cache_input_bytes += len(source)
        while len(self._cache) > _CACHE_ENTRIES or self._cache_input_bytes > _CACHE_INPUT_BYTES:
            _, removed = self._cache.popitem(last=False)
            self._cache_input_bytes -= removed.input_bytes
        return candidates

    def _scan(self, source: bytes) -> ConstantBranchCandidates | None:
        from .ifdef_filter import _logical_lines

        if source.count(b"\n") > _MAX_PHYSICAL_LF:
            return None
        try:
            logical = _logical_lines(source.decode("utf-8", errors="strict"))
        except UnicodeError:
            return None
        if logical is None:
            return None
        groups = _parse(logical)
        if groups is None:
            return None
        ranges: list[LineRange] = []
        _collect(groups, ranges)
        return ConstantBranchCandidates(_merge(ranges))
