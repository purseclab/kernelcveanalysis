from collections.abc import Callable
from dataclasses import dataclass
from typing import ClassVar

from .c_lexer import tokenize_c_source
from ..base import CommitFilter, FilterContext, FilteredCommit
from ..repository_file import RepositoryFileReader
from ...diff import DiffChunk, DiffFile, DiffFileType

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


class WhitespaceFilter(CommitFilter):
    """Filter out changes that only modify comments, formatting, or whitespace.

    Diff files whose old and new versions yield identical ISO C preprocessing
    token streams are pruned from the diff. Commits with no remaining modified files
    are eliminated entirely.
    """

    name: ClassVar[str] = "Filtering whitespace and comments"

    def __init__(self, ignore_non_directive_newlines: bool = True):
        self.ignore_non_directive_newlines = ignore_non_directive_newlines
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

    def _is_chunk_noop(self, chunk: DiffChunk) -> bool:
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

        old_text = "\n".join(old_lines)
        new_text = "\n".join(new_lines)

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
        """Return True if diff_file does not semantically alter code tokens."""
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

        # Fast pre-check: every hunk must pass local token equivalence
        for chunk in diff_file.chunks:
            if not self._is_chunk_noop(chunk):
                return False

        # Candidate passed fast check: confirm against complete file sources
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
            old_source = old_bytes.decode("utf-8", errors="replace")
            new_source = new_bytes.decode("utf-8", errors="replace")

            t_old = tokenize_c_source(
                old_source,
                ignore_non_directive_newlines=self.ignore_non_directive_newlines,
            )
            t_new = tokenize_c_source(
                new_source,
                ignore_non_directive_newlines=self.ignore_non_directive_newlines,
            )
            if t_old is None or t_new is None:
                return False
            return t_old == t_new
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
            else:
                retained.append(diff_file)

        if not retained:
            self._eliminated_commits += 1
            return None

        commit.diff.files = retained
        return commit

    def filter_mutable_commits(
        self,
        commits: list[FilteredCommit],
        context: FilterContext,
        show_progress: bool = True,
    ) -> list[FilteredCommit]:
        with RepositoryFileReader(context.repo) as reader:
            self._read_file = reader.read_file
            try:
                return super().filter_mutable_commits(
                    commits,
                    context,
                    show_progress=show_progress,
                )
            finally:
                self._read_file = None


SourceNoopFilter = WhitespaceFilter
