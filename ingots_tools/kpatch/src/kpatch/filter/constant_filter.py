"""Whole-file source equivalence after folding numeric CPP conditionals."""

from collections.abc import Callable, Generator, Iterable
from dataclasses import dataclass
import subprocess
from typing import ClassVar

from .base import FilterContext, FilteredCommit, StreamingCommitFilter, repository_file_reader
from .constant_conditionals import ConstantConditionalScanner, may_have_numeric_condition
from .masking import CodeMask, FileIdentity, MaskReason, SourceSide, SourceVersions
from .pruning_decision import PruningDecision
from .source_modes import regular_source_change
from .whitespace.layout import LayoutComparer
from .whitespace.whitespace_filter import _is_c_source_file
from ..diff import DiffFile, DiffFileType


_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_MAX_FILES_PER_COMMIT = 256


def _eligible(file: DiffFile) -> bool:
    return (file.change_type is DiffFileType.DEFAULT and not file.binary
            and not file.mode_changed and bool(file.chunks)
            and _is_c_source_file(file.file))


@dataclass(frozen=True, slots=True)
class ConstantFilterStats:
    processed_commits: int
    eliminated_commits: int
    pruned_files: int
    source_prechecks: int
    source_precheck_skips: int
    budget_skipped_commits: int


@dataclass(frozen=True, slots=True)
class _ConditionalProof:
    masks: tuple[CodeMask, ...]
    reason: MaskReason


class ConstantConditionalFilter(StreamingCommitFilter):
    """Fold environment-independent conditions, then prove the outside layout.

    Candidate ranges alone never authorize masks. Both complete originals must
    use the supported lexer, and the complete projected pair must compare equal.
    A failed whole-file proof leaves every candidate range unmasked.
    """

    name: ClassVar[str] = "Filtering constant preprocessor branches"

    def __init__(
        self, on_pruned: Callable[[PruningDecision], None] | None = None, *,
        line_numbers_lossy: bool = False,
        on_line_numbers_assumed: Callable[[PruningDecision], None] | None = None,
    ) -> None:
        if line_numbers_lossy and on_line_numbers_assumed is None:
            raise ValueError("Lossy constant-branch line-number pruning requires a decision callback")
        self.on_pruned = on_pruned
        self.line_numbers_lossy = line_numbers_lossy
        self.on_line_numbers_assumed = on_line_numbers_assumed
        self._scanner = ConstantConditionalScanner()
        self._layout = LayoutComparer()
        self._read_file: Callable[[str, str], bytes] | None = None
        self._processed = self._eliminated = self._pruned = 0
        self._source_prechecks = self._source_precheck_skips = 0
        self._budget_skipped = 0

    def stats(self) -> ConstantFilterStats:
        return ConstantFilterStats(self._processed, self._eliminated, self._pruned,
                                   self._source_prechecks, self._source_precheck_skips,
                                   self._budget_skipped)

    def _proof(
        self, commit: FilteredCommit, file: DiffFile, context: FilterContext,
    ) -> _ConditionalProof | None:
        parent = commit.original.parent
        if parent is None or not _eligible(file):
            return None
        revision = commit.original.commit_id
        if not regular_source_change(file, context.repo, parent.commit_id, revision):
            return None
        read = self._read_file or context.repo.read_file
        old_path = file.old_file or file.file
        raw = SourceVersions(read(parent.commit_id, old_path), read(revision, file.file))
        if max(len(raw.old), len(raw.new)) > _MAX_SOURCE_BYTES:
            return None
        old_source = commit.code_source(old_path, SourceSide.OLD, raw.old)
        new_source = commit.code_source(file.file, SourceSide.NEW, raw.new)
        self._source_prechecks += 1
        if not may_have_numeric_condition(old_source) and not may_have_numeric_condition(new_source):
            self._source_precheck_skips += 1
            return None
        old = self._scanner.scan(old_source)
        new = self._scanner.scan(new_source)
        if old is None or new is None or not (old.inactive or new.inactive):
            return None
        # Erasing a branch must never conceal unsupported original spellings,
        # malformed literals, raw strings, header operands or token overruns.
        if not all(self._layout.equivalent(source, source) for source in (raw.old, raw.new)):
            return None
        identity = FileIdentity.of(file)
        masks = tuple(
            CodeMask(identity, side, MaskReason.CONSTANT_BRANCH, ranges)
            for side, ranges in ((SourceSide.OLD, old.inactive), (SourceSide.NEW, new.inactive))
            if ranges
        )
        sources = commit.active_sources(file, raw, extra_code_masks=masks)
        if self._layout.equivalent(sources.old, sources.new):
            return _ConditionalProof(masks, MaskReason.CONSTANT_BRANCH)
        if self.line_numbers_lossy and self._layout.equivalent_ignoring_line_numbers(sources.old, sources.new):
            return _ConditionalProof(masks, MaskReason.CONSTANT_BRANCH_LINES_LOSSY)
        return None

    def _publish(self, commit: FilteredCommit, file: DiffFile, proof: _ConditionalProof) -> None:
        for mask in proof.masks:
            commit.mask_code(file, mask.side, mask.lines, mask.reason)
        commit.mask_file(file, proof.reason)
        self._pruned += 1
        lossy = proof.reason is MaskReason.CONSTANT_BRANCH_LINES_LOSSY
        callback = self.on_line_numbers_assumed if lossy else self.on_pruned
        if callback is None:
            return
        identity = FileIdentity.of(file)
        risks = (
            "source_line_number_observations_may_change_runtime_behavior",
            "included_macros_may_observe_changed_lines",
        ) if lossy else ()
        callback(PruningDecision(
            commit.original.commit_id, (file.file,), proof.reason.value, (),
            tuple(mask for mask in commit.edit_masks if mask.file == identity),
            tuple(mask for mask in commit.code_masks if mask.file == identity),
            lossy, risks,
        ))

    def filter_mutable_commit(self, commit: FilteredCommit, context: FilterContext) -> FilteredCommit | None:
        self._processed += 1
        if commit.original.is_merge:
            return commit
        files = commit.diff.files
        # Bound extra work before reads or mode lookups. Large tree-wide edits
        # pass through unchanged; a skipped budget is never a masking proof.
        if sum(_eligible(file) for file in files) > _MAX_FILES_PER_COMMIT:
            self._budget_skipped += 1
            return commit
        for file in files:
            try:
                proof = self._proof(commit, file, context)
            except (OSError, UnicodeError, ValueError, RuntimeError, subprocess.SubprocessError):
                proof = None
            if proof is not None:
                self._publish(commit, file, proof)
        if commit.diff.files:
            return commit
        self._eliminated += 1
        return None

    def iter_filter_mutable_commits(
        self, commits: Iterable[FilteredCommit], context: FilterContext,
        show_progress: bool = True, *, total: int | None = None,
    ) -> Generator[FilteredCommit, None, None]:
        with repository_file_reader(context) as reader:
            self._read_file = reader.read_file
            try:
                yield from super().iter_filter_mutable_commits(commits, context, show_progress, total=total)
            finally:
                self._read_file = None
