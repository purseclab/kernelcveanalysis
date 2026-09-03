from dataclasses import dataclass
from difflib import SequenceMatcher
from enum import StrEnum
import re
from typing import Self


_HUNK_HEADER_RE = re.compile(
    r"^@@ -(\d+(?:,\d+)?) \+(\d+(?:,\d+)?) @@(.*)$"
)


def _line_ending(line: str) -> tuple[str, str]:
    if line.endswith("\r\n"):
        return line[:-2], "\r\n"
    if line.endswith("\n"):
        return line[:-1], "\n"
    return line, ""


def _split_git_path_pair(value: str) -> tuple[str, str]:
    """Split the two optionally C-quoted paths in a ``diff --git`` line."""

    if not value:
        raise ValueError("invalid diff --git header: missing paths")

    if value.startswith('"'):
        escaped = False
        for index, character in enumerate(value[1:], start=1):
            if character == '"' and not escaped:
                remainder = value[index + 1 :]
                if not remainder.startswith(" "):
                    break
                return value[: index + 1], remainder.lstrip()
            if character == "\\":
                escaped = not escaped
            else:
                escaped = False
        raise ValueError("invalid diff --git header: unterminated quoted path")

    first, separator, second = value.partition(" ")
    if not separator or not second:
        raise ValueError("invalid diff --git header: missing second path")
    return first, second.lstrip()


def _with_git_side_prefix(value: str, prefix: str) -> str:
    """Canonicalize an ``a/`` or ``b/`` path for one side of a Git diff."""

    offset = 1 if value.startswith('"') else 0
    if value[offset : offset + 2] in ("a/", "b/"):
        return f"{value[:offset]}{prefix}{value[offset + 2:]}"
    return value


def _invert_binary_payload(lines: list[str]) -> list[str]:
    section_starts = [
        index
        for index, line in enumerate(lines)
        if _line_ending(line)[0].startswith(("literal ", "delta "))
    ]
    if len(section_starts) != 2:
        raise ValueError(
            "GIT binary patch must contain forward and reverse payloads"
        )

    first, second = section_starts
    return lines[:first] + lines[second:] + lines[first:second]


def _invert_hunk_lines(lines: list[str]) -> list[str]:
    inverted: list[str] = []
    changes: list[tuple[str, list[str]]] = []

    def flush_changes() -> None:
        for original_prefix, inverse_prefix in (("+", "-"), ("-", "+")):
            for prefix, unit in changes:
                if prefix != original_prefix:
                    continue
                body, ending = _line_ending(unit[0])
                inverted.append(f"{inverse_prefix}{body[1:]}{ending}")
                inverted.extend(unit[1:])
        changes.clear()

    index = 0
    while index < len(lines):
        body = _line_ending(lines[index])[0]
        if body.startswith(("+", "-")):
            unit = [lines[index]]
            index += 1
            if index < len(lines) and _line_ending(lines[index])[0].startswith("\\"):
                unit.append(lines[index])
                index += 1
            changes.append((body[0], unit))
            continue

        flush_changes()
        inverted.append(lines[index])
        index += 1

    flush_changes()
    return inverted


def _hunk_end(
    lines: list[str], start: int, old_count: int, new_count: int
) -> int:
    index = start
    while index < len(lines) and (old_count or new_count):
        body = _line_ending(lines[index])[0]
        if body.startswith("\\"):
            index += 1
            continue
        if body.startswith("+"):
            new_count -= 1
        elif body.startswith("-"):
            old_count -= 1
        else:
            old_count -= 1
            new_count -= 1
        index += 1

    while index < len(lines) and _line_ending(lines[index])[0].startswith("\\"):
        index += 1
    return index


def invert_diff(patch_text: str) -> str:
    """Return a patch that reverses the supplied Git or unified diff.

    Text hunks, paths, modes, rename metadata, object IDs, and Git binary
    payloads are reversed. Copy diffs cannot be represented as a standalone
    inverse without the copied file's complete post-image, so they are
    rejected instead of producing a patch that only partially undoes them.
    """

    lines = patch_text.splitlines(keepends=True)
    if any(
        _line_ending(line)[0].startswith(("copy from ", "copy to "))
        for line in lines
    ):
        raise ValueError(
            "copy diffs cannot be inverted without the copied file contents"
        )

    inverted: list[str] = []
    index = 0

    while index < len(lines):
        line = lines[index]
        body, ending = _line_ending(line)

        if body == "GIT binary patch":
            block_end = index + 1
            while block_end < len(lines):
                candidate = _line_ending(lines[block_end])[0]
                if candidate.startswith("diff --git "):
                    break
                block_end += 1
            inverted.append(line)
            inverted.extend(_invert_binary_payload(lines[index + 1 : block_end]))
            index = block_end
            continue

        if body.startswith("diff --git "):
            old_path, new_path = _split_git_path_pair(body[len("diff --git ") :])
            inverse_old = _with_git_side_prefix(new_path, "a/")
            inverse_new = _with_git_side_prefix(old_path, "b/")
            inverted.append(f"diff --git {inverse_old} {inverse_new}{ending}")
            index += 1
            continue

        if match := re.match(
            r"^index ([0-9a-fA-F]+)\.\.([0-9a-fA-F]+)(.*)$", body
        ):
            old_object, new_object, suffix = match.groups()
            inverted.append(f"index {new_object}..{old_object}{suffix}{ending}")
            index += 1
            continue

        if body.startswith("new file mode "):
            inverted.append(f"deleted file mode {body[14:]}{ending}")
            index += 1
            continue
        if body.startswith("deleted file mode "):
            inverted.append(f"new file mode {body[18:]}{ending}")
            index += 1
            continue

        if body.startswith("old mode ") and index + 1 < len(lines):
            next_body, next_ending = _line_ending(lines[index + 1])
            if next_body.startswith("new mode "):
                inverted.append(f"old mode {next_body[9:]}{ending}")
                inverted.append(f"new mode {body[9:]}{next_ending}")
                index += 2
                continue

        if body.startswith("rename from ") and index + 1 < len(lines):
            next_body, next_ending = _line_ending(lines[index + 1])
            if next_body.startswith("rename to "):
                inverted.append(f"rename from {next_body[10:]}{ending}")
                inverted.append(f"rename to {body[12:]}{next_ending}")
                index += 2
                continue

        if body.startswith("--- ") and index + 1 < len(lines):
            next_body, next_ending = _line_ending(lines[index + 1])
            if next_body.startswith("+++ "):
                inverse_old = _with_git_side_prefix(next_body[4:], "a/")
                inverse_new = _with_git_side_prefix(body[4:], "b/")
                inverted.append(f"--- {inverse_old}{ending}")
                inverted.append(f"+++ {inverse_new}{next_ending}")
                index += 2
                continue

        if match := _HUNK_HEADER_RE.match(body):
            old_range, new_range, section = match.groups()
            inverted.append(f"@@ -{new_range} +{old_range} @@{section}{ending}")
            old_count = int(old_range.split(",", 1)[1]) if "," in old_range else 1
            new_count = int(new_range.split(",", 1)[1]) if "," in new_range else 1
            hunk_end = _hunk_end(lines, index + 1, old_count, new_count)
            inverted.extend(_invert_hunk_lines(lines[index + 1 : hunk_end]))
            index = hunk_end
            continue

        if match := re.match(r"^Binary files (.+) and (.+) differ$", body):
            old_path, new_path = match.groups()
            inverse_old = _with_git_side_prefix(new_path, "a/")
            inverse_new = _with_git_side_prefix(old_path, "b/")
            inverted.append(
                f"Binary files {inverse_old} and {inverse_new} differ{ending}"
            )
            index += 1
            continue

        inverted.append(line)
        index += 1

    return "".join(inverted)


class DiffFileType(StrEnum):
    """The structural change represented by a file diff."""

    DEFAULT = "default"
    NEW = "new"
    DELETE = "delete"
    RENAME = "rename"
    COPY = "copy"


@dataclass(slots=True)
class DiffChunk:
    header: str
    lines: list[str]
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    section: str | None

    @property
    def line_count(self) -> int:
        return len(self.lines)

    @property
    def changed_line_count(self) -> int:
        return sum(line.startswith(("+", "-")) for line in self.lines)


@dataclass(slots=True)
class DiffFile:
    file: str
    old_file: str | None
    old_mode: str | None
    new_mode: str | None
    change_type: DiffFileType
    binary: bool
    header_lines: list[str]
    chunks: list[DiffChunk]

    @property
    def mode_changed(self) -> bool:
        """Whether both modes are known and differ."""

        return (
            self.old_mode is not None
            and self.new_mode is not None
            and self.old_mode != self.new_mode
        )


@dataclass(slots=True)
class Diff:
    text: str
    files: list[DiffFile]

    @classmethod
    def parse(cls, patch_text: str) -> Self:
        """Parse a unified diff into files and hunks."""

        lines = patch_text.splitlines()
        file_starts = [
            index for index, line in enumerate(lines) if line.startswith("diff --git ")
        ]
        if not file_starts and lines:
            file_starts = [
                index
                for index, line in enumerate(lines[:-1])
                if line.startswith("--- ") and lines[index + 1].startswith("+++ ")
            ]

        def parse_path(value: str, prefix: str) -> str | None:
            value = value.split("\t", 1)[0].strip()
            if value == "/dev/null":
                return None
            return value.removeprefix(prefix)

        parsed_files: list[DiffFile] = []
        for file_index, start in enumerate(file_starts):
            end = file_starts[file_index + 1] if file_index + 1 < len(file_starts) else len(lines)
            file_lines = lines[start:end]
            hunk_starts = [
                index for index, line in enumerate(file_lines) if line.startswith("@@ ")
            ]
            header_end = hunk_starts[0] if hunk_starts else len(file_lines)
            header_lines = file_lines[:header_end]
            diff_old_path = None
            diff_new_path = None
            patch_old_path = None
            patch_new_path = None
            saw_old_path = False
            saw_new_path = False
            rename_from = None
            rename_to = None
            copy_from = None
            copy_to = None
            old_mode = None
            new_mode = None

            for line in header_lines:
                if line.startswith("--- "):
                    patch_old_path = parse_path(line[4:], "a/")
                    saw_old_path = True
                elif line.startswith("+++ "):
                    patch_new_path = parse_path(line[4:], "b/")
                    saw_new_path = True
                elif line.startswith("rename from "):
                    rename_from = parse_path(line[12:], "")
                elif line.startswith("rename to "):
                    rename_to = parse_path(line[10:], "")
                elif line.startswith("copy from "):
                    copy_from = parse_path(line[10:], "")
                elif line.startswith("copy to "):
                    copy_to = parse_path(line[8:], "")
                elif match := re.match(r"^(new file mode|deleted file mode|old mode|new mode) (\d+)$", line):
                    mode_kind, mode = match.groups()
                    if mode_kind in ("deleted file mode", "old mode"):
                        old_mode = mode
                    else:
                        new_mode = mode
                elif match := re.match(
                    r"^index [0-9a-fA-F]+\.\.[0-9a-fA-F]+ (\d+)$", line
                ):
                    # An index mode without separate old/new mode headers
                    # applies to both sides of an ordinary content change.
                    if old_mode is None and new_mode is None:
                        old_mode = new_mode = match.group(1)

            if file_lines:
                diff_match = re.match(r"^diff --git (.+?) (.+)$", file_lines[0])
                if diff_match:
                    diff_old_path = parse_path(diff_match.group(1), "a/")
                    diff_new_path = parse_path(diff_match.group(2), "b/")

            old_path = patch_old_path if saw_old_path else diff_old_path
            new_path = patch_new_path if saw_new_path else diff_new_path

            if rename_from is not None or rename_to is not None:
                change_type = DiffFileType.RENAME
            elif copy_from is not None or copy_to is not None:
                change_type = DiffFileType.COPY
            elif any(line.startswith("new file mode ") for line in header_lines):
                change_type = DiffFileType.NEW
            elif any(line.startswith("deleted file mode ") for line in header_lines):
                change_type = DiffFileType.DELETE
            elif saw_old_path and saw_new_path and old_path is None and new_path is not None:
                # Raw unified diffs do not necessarily include Git's
                # "new file mode" metadata.
                change_type = DiffFileType.NEW
            elif saw_old_path and saw_new_path and old_path is not None and new_path is None:
                change_type = DiffFileType.DELETE
            else:
                change_type = DiffFileType.DEFAULT

            if change_type is DiffFileType.RENAME:
                file = rename_to or new_path or ""
                old_file = rename_from or old_path
            elif change_type is DiffFileType.COPY:
                file = copy_to or new_path or ""
                old_file = copy_from or old_path
            elif change_type is DiffFileType.NEW:
                file = new_path or diff_new_path or ""
                old_file = None
            elif change_type is DiffFileType.DELETE:
                file = old_path or diff_old_path or ""
                old_file = None
            else:
                file = new_path or old_path or ""
                old_file = None

            binary = any(
                line == "GIT binary patch"
                or line.startswith("Binary files ")
                for line in file_lines
            )

            chunks: list[DiffChunk] = []
            for chunk_index, chunk_start in enumerate(hunk_starts):
                chunk_end = (
                    hunk_starts[chunk_index + 1]
                    if chunk_index + 1 < len(hunk_starts)
                    else len(file_lines)
                )
                chunk_header = file_lines[chunk_start]
                chunk_match = re.match(
                    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: ?(.*))?$",
                    chunk_header,
                )
                if chunk_match is None:
                    continue
                chunks.append(
                    DiffChunk(
                        header=chunk_header,
                        lines=file_lines[chunk_start + 1 : chunk_end],
                        old_start=int(chunk_match.group(1)),
                        old_count=int(chunk_match.group(2) or "1"),
                        new_start=int(chunk_match.group(3)),
                        new_count=int(chunk_match.group(4) or "1"),
                        section=chunk_match.group(5) or None,
                    )
                )

            parsed_files.append(
                DiffFile(
                    file=file,
                    old_file=old_file,
                    old_mode=old_mode,
                    new_mode=new_mode,
                    change_type=change_type,
                    binary=binary,
                    header_lines=header_lines,
                    chunks=chunks,
                )
            )

        return cls(text=patch_text, files=parsed_files)

    def inverse(self) -> Self:
        """Return a parsed diff that undoes this diff."""

        return type(self).parse(invert_diff(self.text))

    def diff_similarity(self, other: Self) -> float:
        """Compare corresponding files after combining all of their hunks."""

        self_files = {file.file: file for file in self.files}
        other_files = {file.file: file for file in other.files}
        if len(self_files) != len(self.files) or len(other_files) != len(other.files):
            return 0.0
        if set(self_files) != set(other_files):
            return 0.0

        weighted_similarity = 0.0
        total_changed_lines = 0
        for path, self_file in self_files.items():
            other_file = other_files[path]
            self_lines = [
                line
                for chunk in self_file.chunks
                for line in chunk.lines
            ]
            other_lines = [
                line
                for chunk in other_file.chunks
                for line in chunk.lines
            ]
            changed_lines = max(
                sum(line.startswith(("+", "-")) for line in self_lines),
                sum(line.startswith(("+", "-")) for line in other_lines),
                1,
            )
            similarity = SequenceMatcher(
                None,
                self_lines,
                other_lines,
                autojunk=False,
            ).ratio()
            weighted_similarity += similarity * changed_lines
            total_changed_lines += changed_lines

        return weighted_similarity / total_changed_lines if total_changed_lines else 1.0
