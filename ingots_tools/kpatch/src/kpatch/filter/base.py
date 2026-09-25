from abc import ABC, abstractmethod
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


@dataclass(slots=True)
class FilteredCommit:
    """A mutable filtering view paired with its immutable source commit."""

    original: GitCommit
    diff: Diff
    build_modes: dict[tuple[str | None, str], FileBuildModes] = field(
        default_factory=dict
    )

    @classmethod
    def from_commit(cls, commit: GitCommit) -> "FilteredCommit":
        return cls(original=commit, diff=Diff.parse(commit.diff_str))

    def synchronize_diff(self) -> None:
        self.diff.synchronize_text()

    def materialize(self) -> GitCommit:
        """Return an ordinary commit containing the filtered first-parent diff."""

        self.synchronize_diff()
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

    @classmethod
    def from_db_range(
        cls,
        gitdb: GitDb,
        gitrepo: GitRepo,
        start: datetime | None = None,
        end: datetime | None = None,
        include_merges: bool = True,
    ) -> "FilterContext":
        commits = gitdb.commits_between(
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


def filter_progress(name: str, total: int, show_progress: bool) -> Progress:
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
        if self.requires_complete_history and context.structured_commits is None:
            raise ValueError(
                f"{type(self).__name__} requires complete history and "
                "structured commit history"
            )
        mutable_commits = [FilteredCommit.from_commit(commit) for commit in commits]
        filtered = self.filter_mutable_commits(
            mutable_commits,
            context,
            show_progress=show_progress,
        )
        return [commit.materialize() for commit in filtered]

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


class FilterPipeline(CommitFilter):
    name: ClassVar[str] = "Filtering commit pipeline"

    def __init__(self, filters: list[CommitFilter]):
        self.filters = list(filters)

    @property
    def requires_complete_history(self) -> bool:
        return any(
            commit_filter.requires_complete_history
            for commit_filter in self.filters
        )

    def filter_mutable_commits(
        self,
        commits: list[FilteredCommit],
        context: FilterContext,
        show_progress: bool = True,
    ) -> list[FilteredCommit]:
        filtered = commits
        for commit_filter in self.filters:
            filtered = commit_filter.filter_mutable_commits(
                filtered,
                context,
                show_progress=show_progress,
            )
        return filtered
