from abc import ABC
from collections.abc import Generator, Iterable
from contextlib import ExitStack, closing, contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import ClassVar

from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TaskProgressColumn,
    TextColumn,
    TimeRemainingColumn,
)

from .repository_file import RepositoryFileReader
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
    _diff: Diff | None = field(default=None, repr=False)
    build_modes: dict[tuple[str | None, str], FileBuildModes] = field(
        default_factory=dict
    )

    def __init__(
        self,
        original: GitCommit,
        diff: Diff | None = None,
        build_modes: dict[tuple[str | None, str], FileBuildModes] | None = None,
    ) -> None:
        self.original = original
        self._diff = diff
        self.build_modes = build_modes if build_modes is not None else {}

    @classmethod
    def from_commit(cls, commit: GitCommit) -> "FilteredCommit":
        return cls(original=commit)

    @property
    def diff(self) -> Diff:
        """Parse only when a filter needs the patch, without caching on original."""

        if self._diff is None:
            self._diff = Diff.parse(self.original.diff_str)
        return self._diff

    @diff.setter
    def diff(self, value: Diff) -> None:
        self._diff = value

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

    def __init__(self, filters: list[CommitFilter]):
        self.filters = list(filters)

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
