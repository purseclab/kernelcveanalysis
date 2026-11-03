"""Original-coordinate masks and centralized patch/source projections."""

from bisect import bisect_right
from collections.abc import Iterable
from dataclasses import dataclass, replace
from enum import StrEnum
import re

from ..diff import Diff, DiffChunk, DiffFile, DiffFileType


class SourceSide(StrEnum):
    OLD = "old"
    NEW = "new"


class MaskReason(StrEnum):
    CONFIG = "configuration"
    IFDEF = "inactive_preprocessor_branch"
    WHITESPACE = "whitespace_or_comments"
    DEAD_CODE = "unreferenced_definition"
    RENAME = "consistent_rename"
    FILE_SELECTION = "file_selection"


@dataclass(frozen=True, slots=True)
class LineRange:
    """Original physical lines, one-based and end-exclusive."""

    start: int
    end: int

    def __post_init__(self) -> None:
        if self.start < 1 or self.end <= self.start:
            raise ValueError("Expected a nonempty one-based line range")


def line_ranges(numbers: Iterable[int]) -> tuple[LineRange, ...]:
    output: list[LineRange] = []
    for number in sorted(set(numbers)):
        if output and output[-1].end == number:
            output[-1] = LineRange(output[-1].start, number + 1)
        else:
            output.append(LineRange(number, number + 1))
    return tuple(output)


@dataclass(frozen=True, slots=True)
class FileIdentity:
    path: str
    old_path: str | None

    @classmethod
    def of(cls, file: DiffFile) -> "FileIdentity":
        return cls(file.file, file.old_file)


@dataclass(frozen=True, slots=True)
class EditMask:
    """Ignore modifications; source reconstruction retains parent text."""

    file: FileIdentity
    reason: MaskReason
    old_lines: tuple[LineRange, ...] = ()
    new_lines: tuple[LineRange, ...] = ()
    whole_file: bool = False


@dataclass(frozen=True, slots=True)
class CodeMask:
    """Exclude complete source lines proven irrelevant on this revision side.

    Unlike an edit mask this also excludes unchanged code from AST analysis.
    Callers must establish that every token on these lines can be ignored.
    """

    file: FileIdentity
    side: SourceSide
    reason: MaskReason
    lines: tuple[LineRange, ...] = ()
    whole_file: bool = False


@dataclass(frozen=True, slots=True)
class SourceVersions:
    old: bytes
    new: bytes


def line_macro_locations(source: bytes) -> tuple[int, ...]:
    return tuple(number for number, line in enumerate(source.split(b"\n"), 1)
                 for _ in range(line.count(b"__LINE__")))


@dataclass(frozen=True, slots=True)
class HunkSnapshot:
    header: str
    lines: tuple[str, ...]
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    section: str | None

    def mutable(self) -> DiffChunk:
        return DiffChunk(self.header, list(self.lines), self.old_start, self.old_count,
                         self.new_start, self.new_count, self.section)


@dataclass(frozen=True, slots=True)
class FileSnapshot:
    file: str
    old_file: str | None
    old_mode: str | None
    new_mode: str | None
    change_type: DiffFileType
    binary: bool
    header_lines: tuple[str, ...]
    chunks: tuple[HunkSnapshot, ...]

    def mutable(self) -> DiffFile:
        return DiffFile(self.file, self.old_file, self.old_mode, self.new_mode,
                        self.change_type, self.binary, list(self.header_lines),
                        [chunk.mutable() for chunk in self.chunks])


@dataclass(frozen=True, slots=True)
class PatchSnapshot:
    text: str
    files: tuple[FileSnapshot, ...]

    @classmethod
    def parse(cls, text: str) -> "PatchSnapshot":
        parsed = Diff.parse(text)
        files = tuple(FileSnapshot(
            f.file, f.old_file, f.old_mode, f.new_mode, f.change_type, f.binary,
            tuple(f.header_lines), tuple(HunkSnapshot(
                c.header, tuple(c.lines), c.old_start, c.old_count, c.new_start, c.new_count, c.section,
            ) for c in f.chunks),
        ) for f in parsed.files)
        return cls(text, files)


class IgnoredLines:
    def __init__(self, ranges: Iterable[LineRange] = (), *, whole_file: bool = False):
        merged: list[LineRange] = []
        for span in sorted(ranges, key=lambda span: (span.start, span.end)):
            if merged and span.start <= merged[-1].end:
                merged[-1] = LineRange(merged[-1].start, max(merged[-1].end, span.end))
            else:
                merged.append(span)
        self.ranges = tuple(merged)
        self.starts = tuple(span.start for span in merged)
        self.whole_file = whole_file

    def contains(self, line: int) -> bool:
        index = bisect_right(self.starts, line) - 1
        return self.whole_file or (index >= 0 and line < self.ranges[index].end)

    def blank(self, source: bytes) -> bytes:
        if not self.ranges and not self.whole_file:
            return source
        return b"".join(re.sub(rb"[^\r\n]", b" ", line) if self.contains(number) else line
                        for number, line in enumerate(_physical_lines(source), 1))


def ignored_lines(
    identity: FileIdentity, side: SourceSide, edits: Iterable[EditMask], codes: Iterable[CodeMask],
) -> IgnoredLines:
    ranges: list[LineRange] = []
    whole = False
    for edit in edits:
        if edit.file == identity:
            whole |= edit.whole_file
            ranges.extend(edit.old_lines if side is SourceSide.OLD else edit.new_lines)
    for code in codes:
        if code.file == identity and code.side is side:
            whole |= code.whole_file
            ranges.extend(code.lines)
    return IgnoredLines(ranges, whole_file=whole)


def changed_lines(file: DiffFile, side: SourceSide, ignored: IgnoredLines) -> frozenset[int]:
    changed: set[int] = set()
    prefix = "-" if side is SourceSide.OLD else "+"
    for chunk in file.chunks:
        number = chunk.old_start if side is SourceSide.OLD else chunk.new_start
        for line in chunk.lines:
            if line.startswith(prefix) and not ignored.contains(number):
                changed.add(number)
            if line.startswith((" ", prefix)):
                number += 1
    return frozenset(changed)


def ambiguous_eof_projection(file: DiffFile, old: IgnoredLines, new: IgnoredLines) -> bool:
    """Keep the original edit block when partial EOF selection is ambiguous."""
    if not any(line.startswith("\\") for chunk in file.chunks for line in chunk.lines):
        return False
    all_old = changed_lines(file, SourceSide.OLD, IgnoredLines())
    all_new = changed_lines(file, SourceSide.NEW, IgnoredLines())
    kept_old = changed_lines(file, SourceSide.OLD, old)
    kept_new = changed_lines(file, SourceSide.NEW, new)
    return bool(kept_old or kept_new) and (kept_old != all_old or kept_new != all_new)


def project_file(file: DiffFile, old: IgnoredLines, new: IgnoredLines) -> DiffFile | None:
    """Render masked deletions as context and omit masked insertions."""

    if not old.ranges and not new.ranges and not old.whole_file and not new.whole_file:
        return file
    if ambiguous_eof_projection(file, old, new):
        return file
    chunks: list[DiffChunk] = []
    delta = 0
    inactive_deletion = False
    for chunk in file.chunks:
        old_line, new_line = chunk.old_start, chunk.new_start
        before = delta
        lines: list[str] = []
        selected, previous = False, False
        for line in chunk.lines:
            if line.startswith("-"):
                keep = not old.contains(old_line)
                lines.append(line if keep else " " + line[1:])
                delta -= keep
                selected |= keep
                inactive_deletion |= not keep
                old_line += 1
                previous = True
            elif line.startswith("+"):
                keep = not new.contains(new_line)
                if keep:
                    lines.append(line)
                    delta += 1
                    selected = True
                new_line += 1
                previous = keep
            elif line.startswith(" "):
                lines.append(line)
                old_line += 1
                new_line += 1
                previous = True
            elif line.startswith("\\") and previous:
                lines.append(line)
        if not selected:
            continue
        old_count = sum(line.startswith((" ", "-")) for line in lines)
        new_count = sum(line.startswith((" ", "+")) for line in lines)
        start = chunk.old_start + before + (old_count == 0 and new_count > 0) - (new_count == 0 and old_count > 0)
        start = max(start, 0)
        suffix = " " + chunk.section if chunk.section else ""
        header = f"@@ -{chunk.old_start},{old_count} +{start},{new_count} @@{suffix}"
        chunks.append(DiffChunk(header, lines, chunk.old_start, old_count, start, new_count, chunk.section))
    if not chunks:
        return file if file.binary or file.mode_changed or file.change_type in (DiffFileType.RENAME, DiffFileType.COPY) else None
    partial_delete = file.change_type is DiffFileType.DELETE and inactive_deletion
    header_lines = [line for line in file.header_lines if not line.startswith("index ")
                    and not (partial_delete and line.startswith("deleted file mode "))]
    if partial_delete:
        header_lines = [f"+++ b/{file.file}" if line.startswith("+++ ") else line for line in header_lines]
    return replace(file, chunks=chunks, header_lines=header_lines,
                   change_type=DiffFileType.DEFAULT if partial_delete else file.change_type)


def _physical_lines(source: bytes) -> list[bytes]:
    # bytes.splitlines also splits bare CR; Git line coordinates are LF-based.
    parts = source.split(b"\n")
    return [part + b"\n" for part in parts[:-1]] + ([parts[-1]] if parts[-1] else [])


def replay_sources(
    file: DiffFile, sources: SourceVersions, old_edits: IgnoredLines, new_edits: IgnoredLines,
    old_code: IgnoredLines, new_code: IgnoredLines,
) -> SourceVersions:
    """Reconstruct a child from original coordinates, checking both originals.

    Code masks blank both originals before replay. Only edit masks revert
    modifications here; reverting inactive code would resurrect old references.
    """

    raw_old, raw_new = _physical_lines(sources.old), _physical_lines(sources.new)
    old = _physical_lines(old_code.blank(sources.old))
    new = _physical_lines(new_code.blank(sources.new))
    result: list[bytes] = []
    old_pos = new_pos = 0
    for chunk in file.chunks:
        old_start = chunk.old_start - (chunk.old_count > 0)
        new_start = chunk.new_start - (chunk.new_count > 0)
        if old_start < old_pos or new_start < new_pos:
            raise ValueError("Overlapping or out-of-order source hunks")
        if raw_old[old_pos:old_start] != raw_new[new_pos:new_start]:
            raise ValueError("Patch does not describe the supplied source versions")
        result.extend(new[new_pos:new_start])
        old_pos, new_pos = old_start, new_start
        for line in chunk.lines:
            if line.startswith("\\"):
                continue
            if not line.startswith((" ", "-", "+")):
                raise ValueError("Invalid source hunk line")
            prefix, text = line[0], line[1:].encode()
            if prefix in (" ", "-"):
                if old_pos >= len(raw_old) or raw_old[old_pos].removesuffix(b"\n").removesuffix(b"\r") != text:
                    raise ValueError("Old source context mismatch")
            if prefix in (" ", "+"):
                if new_pos >= len(raw_new) or raw_new[new_pos].removesuffix(b"\n").removesuffix(b"\r") != text:
                    raise ValueError("New source context mismatch")
            if prefix == " ":
                result.append(new[new_pos])
            elif prefix == "-" and old_edits.contains(old_pos + 1):
                result.append(old[old_pos])
            elif prefix == "+" and not new_edits.contains(new_pos + 1):
                result.append(new[new_pos])
            old_pos += prefix != "+"
            new_pos += prefix != "-"
        if old_pos != old_start + chunk.old_count or new_pos != new_start + chunk.new_count:
            raise ValueError("Source hunk counts do not match")
    if raw_old[old_pos:] != raw_new[new_pos:]:
        raise ValueError("Unrepresented source changes after the last hunk")
    result.extend(new[new_pos:])
    return SourceVersions(b"".join(old), b"".join(result))
