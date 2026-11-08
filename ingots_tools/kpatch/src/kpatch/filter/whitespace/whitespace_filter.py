from collections.abc import Callable, Generator, Iterable
from dataclasses import dataclass, replace
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
from ..input_role_models import SourceRoleDecision, SourceRoleStatus
from ..masking import EditMask, FileIdentity, MaskReason, SourceVersions
from ..pruning_decision import PruningDecision
from ..source_roles import SourceMaskPlan, decorate_source_decision, publish_source_masks, source_role_decision
from ..source_modes import regular_source_change

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


@dataclass(frozen=True, slots=True)
class _WhitespaceProof:
    reason: MaskReason
    roles: SourceRoleDecision


class WhitespaceFilter(StreamingCommitFilter):
    """Filter out changes that only modify comments, formatting, or whitespace.

    Pruning requires identical supported preprocessing tokens, token separation,
    and physical token locations. Included macros can observe both whitespace
    and locations even when the changed file contains no explicit observer.
    Explicit lossy line-number pruning preserves columns but assumes line
    observations are irrelevant, and requires an audit callback.
    """

    name: ClassVar[str] = "Filtering whitespace and comments"

    def __init__(
        self, ignore_non_directive_newlines: bool = True, *,
        line_numbers_lossy: bool = False,
        on_pruned: Callable[[PruningDecision], None] | None = None,
    ) -> None:
        if line_numbers_lossy and on_pruned is None:
            raise ValueError("Lossy whitespace line-number pruning requires a decision callback")
        self.ignore_non_directive_newlines = ignore_non_directive_newlines
        self.line_numbers_lossy = line_numbers_lossy
        self.on_pruned = on_pruned
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

    def _noop_proof(
        self,
        commit: FilteredCommit,
        context: FilterContext,
        diff_file: DiffFile,
    ) -> _WhitespaceProof | None:
        """Classify equivalence or the explicit, audited line-number assumption."""
        # Conservatively retain non-C source, assembly, binary, mode changes, and structural changes
        if not _is_c_source_file(diff_file.file) and (
            diff_file.old_file is None or not _is_c_source_file(diff_file.old_file)
        ):
            return None
        if diff_file.binary or diff_file.mode_changed:
            return None
        if diff_file.change_type is not DiffFileType.DEFAULT:
            return None
        if not diff_file.chunks:
            return None

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
            return None

        parent_id = (
            commit.original.parent.commit_id
            if commit.original.parent is not None
            else None
        )
        if parent_id is None:
            return None
        if not regular_source_change(diff_file, context.repo, parent_id, commit.original.commit_id):
            return None

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
                        return None
                    if not self.is_chunk_noop(
                        chunk, old_in_comment=old_in_comment, new_in_comment=new_in_comment,
                    ):
                        return None

            # Equal token values alone miss included __LINE__/COLUMN aliases
            # and macro stringification. Every acceptance uses the complete
            # bounded layout certificate; an unsupported result retains edits.
            reason: MaskReason | None = None
            if self._layout.equivalent(old_bytes, new_bytes):
                reason = MaskReason.WHITESPACE
            elif self.line_numbers_lossy and self._layout.equivalent_ignoring_line_numbers(old_bytes, new_bytes):
                reason = MaskReason.WHITESPACE_LINES_LOSSY
            if reason is not None:
                roles = source_role_decision(commit, diff_file, context)
                if roles.status is not SourceRoleStatus.BLOCKED:
                    return _WhitespaceProof(reason, roles)
            return None
        except Exception:
            # Conservatively retain on unreadable files or missing git objects
            return None

    def filter_mutable_commit(
        self,
        commit: FilteredCommit,
        context: FilterContext,
    ) -> FilteredCommit | None:
        self._processed_commits += 1
        retained: list[DiffFile] = []
        for diff_file in commit.diff.files:
            proof = self._noop_proof(commit, context, diff_file)
            if proof is not None:
                mask = EditMask(FileIdentity.of(diff_file), proof.reason, whole_file=True)
                publish_source_masks(commit, context, SourceMaskPlan((proof.roles,), (mask,)))
                self._pruned_files += 1
                self._record(commit, diff_file, proof)
            else:
                retained.append(diff_file)

        if not retained:
            self._eliminated_commits += 1
            return None

        return commit

    def _record(self, commit: FilteredCommit, file: DiffFile, proof: _WhitespaceProof) -> None:
        if self.on_pruned is None:
            return
        lossy = proof.reason is MaskReason.WHITESPACE_LINES_LOSSY
        risks = (
            "source_line_number_observations_may_change_runtime_behavior",
            "included_macros_may_observe_changed_lines",
        ) if lossy else ()
        identity = FileIdentity.of(file)
        self.on_pruned(decorate_source_decision(PruningDecision(
            commit.original.commit_id, (file.file,), proof.reason.value, (),
            tuple(mask for mask in commit.edit_masks if mask.file == identity),
            tuple(mask for mask in commit.code_masks if mask.file == identity),
            lossy, risks,
        ), (proof.roles,)))

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
                    replace(context, file_reader=reader),
                    show_progress=show_progress,
                    total=total,
                )
            finally:
                self._read_file = None


SourceNoopFilter = WhitespaceFilter
