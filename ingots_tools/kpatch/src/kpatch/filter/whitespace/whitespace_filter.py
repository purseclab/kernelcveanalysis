from collections.abc import Callable, Generator, Iterable
from dataclasses import dataclass
from itertools import chain
from typing import ClassVar

from .c_lexer import (
    source_line_starts_in_block_comment,
    tokenize_c_source,
)
from .layout import LayoutComparer
from ..base import (
    FilterContext,
    FilteredCommit,
    StreamingCommitFilter,
    repository_file_reader,
)
from ...diff import DiffChunk, DiffFile, DiffFileType
from ..masking import MaskReason, SourceVersions

_C_SOURCE_EXTENSIONS = (
    ".c",
    ".h",
    ".cpp",
    ".hpp",
    ".cc",
    ".cxx",
    ".C",
    ".H",
)


def _is_c_source_file(path: str) -> bool:
    """Return whether path is a C/C++ source or header file (excluding assembly)."""
    return any(path.endswith(ext) for ext in _C_SOURCE_EXTENSIONS) and not path.endswith(
        (".S", ".s")
    )


@dataclass(frozen=True, slots=True)
class WhitespaceFilterStats:
    """Summary metrics of filtered commits and files."""

    processed_commits: int
    eliminated_commits: int
    pruned_files: int


class WhitespaceFilter(StreamingCommitFilter):
    """Filter out changes that only modify comments, formatting, or whitespace.

    Pruning requires identical supported preprocessing tokens, token separation,
    and physical token locations. Included macros can observe both whitespace
    and locations even when the changed file contains no explicit observer.
    """

    name: ClassVar[str] = "Filtering whitespace and comments"

    def __init__(self, ignore_non_directive_newlines: bool = True):
        self.ignore_non_directive_newlines = ignore_non_directive_newlines
        self._layout = LayoutComparer(
            ignore_non_directive_newlines=ignore_non_directive_newlines,
        )
        self._read_file: Callable[[str, str], bytes] | None = None
        self._processed_commits = 0
        self._eliminated_commits = 0
        self._pruned_files = 0

    def stats(self) -> WhitespaceFilterStats:
        return WhitespaceFilterStats(
            processed_commits=self._processed_commits,
            eliminated_commits=self._eliminated_commits,
            pruned_files=self._pruned_files,
        )

    def is_chunk_noop(
        self,
        chunk: DiffChunk,
        *,
        old_in_comment: bool = False,
        new_in_comment: bool = False,
    ) -> bool:
        """Cheaply check if hunk changes are identical under C tokenization."""
        old_lines: list[str] = []
        new_lines: list[str] = []
        for line in chunk.lines:
            if line.startswith("-"):
                old_lines.append(line[1:])
            elif line.startswith("+"):
                new_lines.append(line[1:])
            elif line.startswith(" "):
                old_lines.append(line[1:])
                new_lines.append(line[1:])

        old_text = ("/*\n" if old_in_comment else "") + "\n".join(old_lines)
        new_text = ("/*\n" if new_in_comment else "") + "\n".join(new_lines)

        t_old = tokenize_c_source(
            old_text,
            ignore_non_directive_newlines=self.ignore_non_directive_newlines,
        )
        t_new = tokenize_c_source(
            new_text,
            ignore_non_directive_newlines=self.ignore_non_directive_newlines,
        )
        if t_old is None or t_new is None:
            return False
        return t_old == t_new

    def _is_noop_file(
        self,
        commit: FilteredCommit,
        context: FilterContext,
        diff_file: DiffFile,
    ) -> bool:
        """Return whether the remaining edit preserves supported source layout."""
        # Conservatively retain non-C source, assembly, binary, mode changes, and structural changes
        if not _is_c_source_file(diff_file.file) and (
            diff_file.old_file is None or not _is_c_source_file(diff_file.old_file)
        ):
            return False
        if diff_file.binary or diff_file.mode_changed:
            return False
        if diff_file.change_type is not DiffFileType.DEFAULT:
            return False
        if not diff_file.chunks:
            return False

        # A hunk can begin inside a block comment whose opener is outside the
        # patch. A local mismatch then needs source context, not rejection.
        mismatched_chunks = (
            chunk for chunk in diff_file.chunks if not self.is_chunk_noop(chunk)
        )
        mismatched_chunk = next(mismatched_chunks, None)
        if (
            mismatched_chunk is not None
            and mismatched_chunk.old_start <= 1
            and mismatched_chunk.new_start <= 1
        ):
            return False

        parent_id = (
            commit.original.parent.commit_id
            if commit.original.parent is not None
            else None
        )
        if parent_id is None:
            return False

        read_func = (
            self._read_file
            if self._read_file is not None
            else context.repo.read_file
        )

        old_path = diff_file.old_file or diff_file.file
        try:
            old_bytes = read_func(parent_id, old_path)
            new_bytes = read_func(commit.original.commit_id, diff_file.file)
            if commit.has_masks(diff_file):
                # Excluded code remains blank at its original physical lines.
                # Reverting it as an edit would conceal location changes after
                # an insertion in an inactive branch.
                sources = commit.active_sources(diff_file, SourceVersions(old_bytes, new_bytes))
                old_bytes, new_bytes = sources.old, sources.new
            old_source = old_bytes.decode("utf-8", errors="strict")
            new_source = new_bytes.decode("utf-8", errors="strict")

            # Ordinary code edits still avoid tokenizing complete files. The
            # pipeline's shared blob reader reuses sources read by IfdefFilter.
            if mismatched_chunk is not None:
                for chunk in chain((mismatched_chunk,), mismatched_chunks):
                    old_line = chunk.old_start + (chunk.old_count == 0)
                    new_line = chunk.new_start + (chunk.new_count == 0)
                    old_in_comment = source_line_starts_in_block_comment(old_source, old_line)
                    new_in_comment = source_line_starts_in_block_comment(new_source, new_line)
                    if not (old_in_comment or new_in_comment):
                        return False
                    if not self.is_chunk_noop(
                        chunk, old_in_comment=old_in_comment, new_in_comment=new_in_comment,
                    ):
                        return False

            # Equal token values alone miss included __LINE__/COLUMN aliases
            # and macro stringification. Every acceptance uses the complete
            # bounded layout certificate; an unsupported result retains edits.
            return self._layout.equivalent(old_bytes, new_bytes)
        except Exception:
            # Conservatively retain on unreadable files or missing git objects
            return False

    def filter_mutable_commit(
        self,
        commit: FilteredCommit,
        context: FilterContext,
    ) -> FilteredCommit | None:
        self._processed_commits += 1
        retained: list[DiffFile] = []
        for diff_file in commit.diff.files:
            if self._is_noop_file(commit, context, diff_file):
                self._pruned_files += 1
                commit.mask_file(diff_file, MaskReason.WHITESPACE)
            else:
                retained.append(diff_file)

        if not retained:
            self._eliminated_commits += 1
            return None

        return commit

    def iter_filter_mutable_commits(
        self,
        commits: Iterable[FilteredCommit],
        context: FilterContext,
        show_progress: bool = True,
        *,
        total: int | None = None,
    ) -> Generator[FilteredCommit, None, None]:
        with repository_file_reader(context) as reader:
            self._read_file = reader.read_file
            try:
                yield from super().iter_filter_mutable_commits(
                    commits,
                    context,
                    show_progress=show_progress,
                    total=total,
                )
            finally:
                self._read_file = None


SourceNoopFilter = WhitespaceFilter
