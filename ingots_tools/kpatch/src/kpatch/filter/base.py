from abc import ABC
from collections.abc import Generator, Iterable
from contextlib import ExitStack, closing, contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from .reference_index import ReferenceIndex

from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TaskProgressColumn,
    TextColumn,
    TimeRemainingColumn,
)

from .repository_file import RepositoryFileReader
from .masking import (
    CodeMask, EditMask, FileIdentity, IgnoredLines, LineRange, MaskReason,
    FileSnapshot, PatchSnapshot, SourceSide, SourceVersions, changed_lines, ignored_lines,
    ambiguous_eof_projection, project_file, replay_sources,
)
from ..diff import Diff, DiffFile
from ..git import (
    CommitParent,
    GitCommit,
    GitDb,
    GitRepo,
    HistoryKind,
    StructuredCommits,
)


@dataclass(frozen=True, slots=True)
class FileBuildModes:
    old: str | None = None
    new: str | None = None


def diff_file_key(diff_file: DiffFile) -> tuple[str | None, str]:
    return diff_file.old_file, diff_file.file


@dataclass(slots=True, init=False)
class FilteredCommit:
    """A mutable filtering view paired with its immutable source commit."""

    original: GitCommit
    _snapshot: PatchSnapshot | None = field(default=None, repr=False)
    _diff: Diff | None = field(default=None, repr=False)
    _edit_masks: list[EditMask] = field(default_factory=list, repr=False)
    _code_masks: list[CodeMask] = field(default_factory=list, repr=False)
    _file_edits: dict[FileIdentity, list[EditMask]] = field(default_factory=dict, repr=False)
    _file_codes: dict[FileIdentity, list[CodeMask]] = field(default_factory=dict, repr=False)
    _code_paths: dict[SourceSide, dict[str, list[CodeMask]]] = field(default_factory=dict, repr=False)
    _original_files: dict[FileIdentity, FileSnapshot] = field(default_factory=dict, repr=False)
    build_modes: dict[tuple[str | None, str], FileBuildModes] = field(
        default_factory=dict
    )

    def __init__(
        self,
        original: GitCommit,
        build_modes: dict[tuple[str | None, str], FileBuildModes] | None = None,
    ) -> None:
        self.original = original
        self._snapshot = None
        self._diff = None
        self._edit_masks = []
        self._code_masks = []
        self._file_edits = {}
        self._file_codes = {}
        self._code_paths = {side: {} for side in SourceSide}
        self._original_files = {}
        self.build_modes = build_modes if build_modes is not None else {}

    @classmethod
    def from_commit(cls, commit: GitCommit) -> "FilteredCommit":
        return cls(original=commit)

    @property
    def diff(self) -> Diff:
        """Read the remaining patch; producers record masks instead of mutating it."""
        return self.remaining_diff()

    @property
    def original_diff(self) -> PatchSnapshot:
        if self._snapshot is None:
            self._snapshot = PatchSnapshot.parse(self.original.diff_str)
            self._original_files = {FileIdentity(file.file, file.old_file): file for file in self._snapshot.files}
        return self._snapshot

    @property
    def edit_masks(self) -> tuple[EditMask, ...]:
        return tuple(self._edit_masks)

    @property
    def code_masks(self) -> tuple[CodeMask, ...]:
        return tuple(self._code_masks)

    def mask_file(self, file: DiffFile, reason: MaskReason) -> None:
        mask = EditMask(FileIdentity.of(file), reason, whole_file=True)
        self._edit_masks.append(mask)
        self._file_edits.setdefault(mask.file, []).append(mask)
        self._diff = None

    def has_masks(self, file: DiffFile) -> bool:
        identity = FileIdentity.of(file)
        return identity in self._file_edits or identity in self._file_codes

    def code_masks_for(self, file: DiffFile) -> tuple[CodeMask, ...]:
        return tuple(self._file_codes.get(FileIdentity.of(file), ()))

    def mask_edits(
        self, file: DiffFile, old_lines: tuple[LineRange, ...],
        new_lines: tuple[LineRange, ...], reason: MaskReason,
    ) -> None:
        if old_lines or new_lines:
            mask = EditMask(FileIdentity.of(file), reason, old_lines, new_lines)
            self._edit_masks.append(mask)
            self._file_edits.setdefault(mask.file, []).append(mask)
            self._diff = None

    def mask_code(
        self, file: DiffFile, side: SourceSide, lines: tuple[LineRange, ...],
        reason: MaskReason, *, whole_file: bool = False,
    ) -> None:
        if lines or whole_file:
            mask = CodeMask(FileIdentity.of(file), side, reason, lines, whole_file)
            self._code_masks.append(mask)
            self._file_codes.setdefault(mask.file, []).append(mask)
            path = file.old_file or file.file if side is SourceSide.OLD else file.file
            self._code_paths[side].setdefault(path, []).append(mask)
            self._diff = None

    def _ignored(self, file: DiffFile, side: SourceSide, *, include_code: bool = True) -> IgnoredLines:
        identity = FileIdentity.of(file)
        return ignored_lines(identity, side, self._file_edits.get(identity, ()),
                             self._file_codes.get(identity, ()) if include_code else ())

    def remaining_diff(self) -> Diff:
        if self._diff is None:
            files: list[DiffFile] = []
            for snapshot in self.original_diff.files:
                identity = FileIdentity(snapshot.file, snapshot.old_file)
                if any(mask.whole_file for mask in self._file_edits.get(identity, ())):
                    continue
                file = snapshot.mutable()
                projected = project_file(file, self._ignored(file, SourceSide.OLD), self._ignored(file, SourceSide.NEW))
                if projected is not None:
                    files.append(projected)
            self._diff = Diff("", files)
            self._diff.synchronize_text()
        return self._diff

    def original_file(self, file: DiffFile) -> DiffFile:
        identity = FileIdentity.of(file)
        _ = self.original_diff
        if identity not in self._original_files:
            raise ValueError("File is not part of the original patch")
        return self._original_files[identity].mutable()

    def changed_lines(self, file: DiffFile, side: SourceSide) -> frozenset[int]:
        return changed_lines(self.original_file(file), side, self._ignored(file, side))

    def code_source(self, path: str, side: SourceSide, source: bytes) -> bytes:
        masks = self._code_paths[side].get(path, ())
        return IgnoredLines((span for mask in masks for span in mask.lines),
                            whole_file=any(mask.whole_file for mask in masks)).blank(source)

    def effective_sources(self, file: DiffFile, sources: SourceVersions) -> SourceVersions:
        original = self.original_file(file)
        old, new = self._ignored(file, SourceSide.OLD), self._ignored(file, SourceSide.NEW)
        if ambiguous_eof_projection(original, old, new):
            old, new = IgnoredLines(), IgnoredLines()
        return replay_sources(original, sources, old, new,
                              IgnoredLines(), IgnoredLines())

    def active_sources(
        self, file: DiffFile, sources: SourceVersions, *, extra_code_masks: tuple[CodeMask, ...] = (),
    ) -> SourceVersions:
        codes = self.code_masks_for(file) + extra_code_masks
        old_code = ignored_lines(FileIdentity.of(file), SourceSide.OLD, (), codes)
        new_code = ignored_lines(FileIdentity.of(file), SourceSide.NEW, (), codes)
        original = self.original_file(file)
        old = self._ignored(file, SourceSide.OLD, include_code=False)
        new = self._ignored(file, SourceSide.NEW, include_code=False)
        if ambiguous_eof_projection(original, old, new):
            old, new = IgnoredLines(), IgnoredLines()
        return replay_sources(original, sources, old, new, old_code, new_code)

    def synchronize_diff(self) -> None:
        if self._diff is not None:
            self._diff.synchronize_text()

    def materialize(self) -> GitCommit:
        """Return an ordinary commit containing the filtered first-parent diff."""

        self.diff.synchronize_text()
        if not self.original.parents:
            if self.diff.text:
                raise ValueError("Cannot attach a diff to a parentless commit")
            return self.original

        first_parent = self.original.parents[0]
        parents = (
            CommitParent(first_parent.commit_id, self.diff.text),
            *self.original.parents[1:],
        )
        return replace(self.original, parents=parents)


@dataclass(frozen=True, slots=True)
class FilterContext:
    repo: GitRepo
    structured_commits: StructuredCommits | None = None
    commits: list[GitCommit] = field(default_factory=list)
    file_reader: RepositoryFileReader | None = None
    reference_index: "ReferenceIndex | None" = None

    @classmethod
    def from_db_range(
        cls,
        gitdb: GitDb,
        gitrepo: GitRepo,
        start: datetime | None = None,
        end: datetime | None = None,
        include_merges: bool = True,
    ) -> "FilterContext":
        commits = gitdb.load_lazy_commits(
            start,
            end,
            include_merges=include_merges,
        )
        structured_commits = (
            StructuredCommits.from_commits(commits)
            if include_merges and gitdb.history_kind is HistoryKind.COMPLETE
            else None
        )
        return cls(
            repo=gitrepo,
            structured_commits=structured_commits,
            commits=commits,
        )


@contextmanager
def repository_file_reader(
    context: FilterContext,
) -> Generator[RepositoryFileReader, None, None]:
    """Borrow a pipeline's reader, or own one for a standalone filter call."""

    if context.file_reader is not None:
        yield context.file_reader
        return

    with RepositoryFileReader(context.repo) as reader:
        yield reader


def filter_progress(name: str, total: int | None, show_progress: bool) -> Progress:
    return Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        TimeRemainingColumn(),
        disable=not show_progress or total == 0,
    )


class CommitFilter(ABC):
    name: ClassVar[str]
    requires_reference_index: ClassVar[bool] = False

    @property
    def requires_complete_history(self) -> bool:
        return False

    def _validate_name(self) -> None:
        if not getattr(self, "name", "").strip():
            raise ValueError("Commit filters must define a nonempty name")

    def filter_commits(
        self,
        commits: list[GitCommit],
        context: FilterContext,
        show_progress: bool = True,
    ) -> list[GitCommit]:
        """Collect filtered commits, closing all stages even on failure."""

        with closing(
            self.iter_filter_commits(
                commits, context, show_progress=show_progress, total=len(commits)
            )
        ) as filtered:
            return list(filtered)

    def iter_filter_commits(
        self,
        commits: Iterable[GitCommit],
        context: FilterContext,
        show_progress: bool = True,
        *,
        total: int | None = None,
    ) -> Generator[GitCommit, None, None]:
        """Filter lazily; callers stopping early must close the generator."""

        if self.requires_complete_history and context.structured_commits is None:
            raise ValueError(
                f"{type(self).__name__} requires complete history and "
                "structured commit history"
            )
        mutable_commits = (FilteredCommit.from_commit(commit) for commit in commits)
        with closing(mutable_commits), closing(
            self.iter_filter_mutable_commits(
                mutable_commits, context, show_progress=show_progress, total=total
            )
        ) as filtered:
            for commit in filtered:
                yield commit.materialize()

    def iter_filter_mutable_commits(
        self,
        commits: Iterable[FilteredCommit],
        context: FilterContext,
        show_progress: bool = True,
        *,
        total: int | None = None,
    ) -> Generator[FilteredCommit, None, None]:
        """Preserve collection-wide semantics for existing batch filters."""

        yield from self.filter_mutable_commits(
            list(commits), context, show_progress=show_progress
        )

    def filter_mutable_commits(
        self,
        commits: list[FilteredCommit],
        context: FilterContext,
        show_progress: bool = True,
    ) -> list[FilteredCommit]:
        self._validate_name()
        filtered: list[FilteredCommit] = []
        with filter_progress(self.name, len(commits), show_progress) as progress:
            task = progress.add_task(self.name, total=len(commits))
            for commit in commits:
                result = self.filter_mutable_commit(commit, context)
                if result is not None:
                    result.synchronize_diff()
                    filtered.append(result)
                progress.advance(task)
        return filtered

    def filter_mutable_commit(
        self,
        commit: FilteredCommit,
        context: FilterContext,
    ) -> FilteredCommit | None:
        """Filter or modify a single mutable commit view.

        Defaults to returning the commit unchanged (identity function). Subclasses
        that filter commits individually override this method. Subclasses that
        filter collections as a whole override filter_mutable_commits instead.
        """
        return commit


class StreamingCommitFilter(CommitFilter):
    """A filter whose decisions can be made one mutable commit at a time."""

    def filter_mutable_commits(
        self,
        commits: list[FilteredCommit],
        context: FilterContext,
        show_progress: bool = True,
    ) -> list[FilteredCommit]:
        with closing(
            self.iter_filter_mutable_commits(
                commits, context, show_progress=show_progress, total=len(commits)
            )
        ) as filtered:
            return list(filtered)

    def iter_filter_mutable_commits(
        self,
        commits: Iterable[FilteredCommit],
        context: FilterContext,
        show_progress: bool = True,
        *,
        total: int | None = None,
    ) -> Generator[FilteredCommit, None, None]:
        self._validate_name()
        with filter_progress(self.name, total, show_progress) as progress:
            task = progress.add_task(self.name, total=total)
            for commit in commits:
                result = self.filter_mutable_commit(commit, context)
                progress.advance(task)
                if result is not None:
                    result.synchronize_diff()
                    yield result


class FilterPipeline(StreamingCommitFilter):
    name: ClassVar[str] = "Filtering commit pipeline"

    def __init__(self, filters: list[CommitFilter], *, reference_cache_path: Path | None = None):
        self.filters = list(filters)
        self.reference_cache_path = reference_cache_path

    @property
    def requires_complete_history(self) -> bool:
        return any(
            commit_filter.requires_complete_history
            for commit_filter in self.filters
        )

    def iter_filter_mutable_commits(
        self,
        commits: Iterable[FilteredCommit],
        context: FilterContext,
        show_progress: bool = True,
        *,
        total: int | None = None,
    ) -> Generator[FilteredCommit, None, None]:
        self._validate_name()
        with repository_file_reader(context) as reader, ExitStack() as stack:
            stage_context = replace(context, file_reader=reader)
            if context.reference_index is None and any(stage.requires_reference_index for stage in self.filters):
                from .reference_index import ReferenceIndex
                reference_index = ReferenceIndex(context.repo, reader.read_file, self.reference_cache_path)
                stack.callback(reference_index.close)
                stage_context = replace(stage_context, reference_index=reference_index)
            filtered = commits
            for commit_filter in self.filters:
                stage = commit_filter.iter_filter_mutable_commits(
                    filtered,
                    stage_context,
                    show_progress=show_progress,
                    total=total,
                )
                stack.callback(stage.close)
                filtered = stage
                # Earlier stages may reject commits, so later totals are unknown.
                total = None
            yield from filtered
