from dataclasses import dataclass
from difflib import SequenceMatcher
from enum import StrEnum
import re
from typing import Self


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
    def path(self) -> str:
        """Compatibility alias for the target file path."""

        return self.file

    @property
    def old_path(self) -> str | None:
        """Compatibility view of the pre-change path."""

        if self.change_type is DiffFileType.NEW:
            return None
        if self.change_type in (DiffFileType.RENAME, DiffFileType.COPY):
            return self.old_file
        return self.file

    @property
    def new_path(self) -> str | None:
        """Compatibility view of the post-change path."""

        if self.change_type is DiffFileType.DELETE:
            return None
        return self.file

    @property
    def kind(self) -> DiffFileType:
        """Short alias for :attr:`change_type`."""

        return self.change_type

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

    def diff_similarity(self, other: Self) -> float:
        """Compare corresponding files after combining all of their hunks."""

        self_files = {file.path: file for file in self.files}
        other_files = {file.path: file for file in other.files}
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
