from collections.abc import Callable, Generator, Iterable, Iterator
from dataclasses import dataclass
import posixpath
from typing import ClassVar

from ..base import (
    StreamingCommitFilter,
    FileBuildModes,
    FilterContext,
    FilteredCommit,
    diff_file_key,
    filter_progress,
    repository_file_reader,
)
from ..config_filter import (
    ConfigValue,
    KbuildMakefileCache,
    KbuildState,
    KernelConfig,
    SourceAnalysisCache,
)
from ..source_filter import SourceIncludeIndex
from ...diff import Diff, DiffFile, DiffFileType
from ...git import GitCommit, StructuredCommits
from .history import ConfigHistoryStore, FileDecision, parse_history_diff


@dataclass(frozen=True, slots=True)
class _HistoryState:
    commit_id: str
    state: KbuildState


@dataclass(slots=True)
class _PendingBranch:
    state: KbuildState
    children: list[str]


def _primary_subtree_sizes(structured: StructuredCommits) -> dict[str, int]:
    order: list[str] = []
    pending = list(structured.root_commits)
    while pending:
        commit_id = pending.pop()
        order.append(commit_id)
        pending.extend(structured.commit_children[commit_id].primary_children)

    sizes: dict[str, int] = {}
    for commit_id in reversed(order):
        sizes[commit_id] = 1 + sum(
            sizes[child]
            for child in structured.commit_children[commit_id].primary_children
        )
    return sizes


def _next_branch(pending: list[_PendingBranch]) -> _HistoryState | None:
    if not pending:
        return None
    branch = pending[-1]
    child = branch.children.pop()
    if branch.children:
        # Copy only the branch about to run, not every deferred sibling.
        state = KbuildState.copy(branch.state)
    else:
        state = branch.state
        pending.pop()
    return _HistoryState(child, state)


def _walk_history(
    structured: StructuredCommits,
    create_state: Callable[[str], KbuildState],
) -> Iterator[_HistoryState]:
    """Yield parent-before-child states; the caller advances each yielded state.

    Finish smaller subtrees first and reuse the base state for the largest.
    At most one saved state per light edge remains live: O(log N) snapshots,
    rather than eagerly copying an arbitrarily wide/deep stack of siblings.
    """

    sizes = _primary_subtree_sizes(structured)
    for root in sorted(structured.root_commits, key=lambda key: (sizes[key], key)):
        pending: list[_PendingBranch] = []
        current: _HistoryState | None = _HistoryState(root, create_state(root))
        while current is not None:
            yield current
            children = structured.commit_children[current.commit_id].primary_children
            if len(children) == 1:
                current = _HistoryState(children[0], current.state)
                continue
            if children:
                pending.append(
                    _PendingBranch(
                        current.state,
                        sorted(children, key=lambda key: sizes[key], reverse=True),
                    )
                )
            current = _next_branch(pending)


class ConfigFilter(StreamingCommitFilter):
    """Filter mutable commits through the configured Kbuild graph."""

    name: ClassVar[str] = "Filtering kernel configuration"

    @property
    def requires_complete_history(self) -> bool:
        return True

    def __init__(self, config: KernelConfig):
        self.config = config
        self._store: ConfigHistoryStore | None = None
        self._prepared_context: tuple[int, int] | None = None

    @staticmethod
    def _history_diff(commit: GitCommit) -> Diff:
        """Keep file metadata and changed directives, not entire history patches."""

        return parse_history_diff(commit.diff_str)

    @staticmethod
    def _changed_paths(diff: Diff) -> set[str]:
        return {
            path
            for diff_file in diff.files
            for path in (diff_file.file, diff_file.old_file)
            if path is not None
        }

    @staticmethod
    def _needs_parent(
        diff_file: DiffFile,
        build_description_changed: bool,
        include_targets: frozenset[str],
    ) -> bool:
        old_file = diff_file.old_file or diff_file.file
        return diff_file.change_type in (
            DiffFileType.DELETE,
            DiffFileType.RENAME,
        ) or (
            diff_file.change_type is DiffFileType.DEFAULT
            and (build_description_changed or old_file in include_targets)
        )

    def _decide_commit(
        self,
        state: KbuildState,
        commit: GitCommit,
        diff: Diff,
    ) -> dict[tuple[str | None, str], FileDecision]:
        changed_paths = self._changed_paths(diff)
        build_description_changed = any(
            posixpath.basename(path).startswith(("Kbuild", "Makefile"))
            or posixpath.splitext(path)[1] in (".mk", ".mak")
            for path in changed_paths
        )
        include_targets = (
            state.source_includes.dependent_targets(changed_paths)
            if state.source_includes is not None
            else frozenset()
        )

        old_modes: dict[tuple[str | None, str], ConfigValue | None] = {}
        needs_parent: dict[tuple[str | None, str], bool] = {}
        for diff_file in diff.files:
            key = diff_file_key(diff_file)
            check_parent = self._needs_parent(
                diff_file, build_description_changed, include_targets
            )
            needs_parent[key] = check_parent
            old_modes[key] = (
                state.get(diff_file.old_file or diff_file.file)
                if check_parent
                and state.file_included(diff_file.old_file or diff_file.file)
                else None
            )

        state.update_filter_state(diff, commit.commit_id)
        if commit.is_merge:
            return {}

        decisions: dict[tuple[str | None, str], FileDecision] = {}
        for diff_file in diff.files:
            key = diff_file_key(diff_file)
            new_mode = (
                None
                if diff_file.change_type is DiffFileType.DELETE
                else (
                    state.get(diff_file.file)
                    if state.file_included(diff_file.file)
                    else None
                )
            )
            old_mode = old_modes[key]
            if (
                not needs_parent[key]
                and diff_file.change_type
                not in (DiffFileType.NEW, DiffFileType.COPY)
            ):
                old_mode = new_mode
            if old_mode is not None or new_mode is not None:
                decisions[key] = FileDecision(old=old_mode, new=new_mode)
        return decisions

    def _populate_history(
        self, structured: StructuredCommits, store: ConfigHistoryStore
    ) -> set[str]:
        source_paths: set[str] = set()
        for commit in structured.commits.values():
            diff = self._history_diff(commit)
            source_paths.update(self._changed_paths(diff))
            store.add_history(commit.commit_id, diff)
        store.commit()
        return source_paths

    def _source_includes(
        self,
        context: FilterContext,
        structured: StructuredCommits,
        store: ConfigHistoryStore,
        source_paths: set[str],
    ) -> SourceIncludeIndex | None:
        if not structured.commits or getattr(context.repo, "repo", None) is None:
            return None
        snapshot = max(
            structured.commits.values(), key=lambda commit: commit.committer_date
        ).commit_id
        source_includes = SourceIncludeIndex.from_repository(
            context.repo, snapshot, self.config.srcarch, source_paths
        )
        for diff in store.iter_history():
            source_includes.add_diff(diff)
        return source_includes

    @staticmethod
    def _parent_or_self(structured: StructuredCommits, commit_id: str) -> str:
        parent = structured.commits[commit_id].parent
        return commit_id if parent is None else parent.commit_id

    def _collect_decisions(
        self,
        context: FilterContext,
        structured: StructuredCommits,
        store: ConfigHistoryStore,
        source_includes: SourceIncludeIndex | None,
        show_progress: bool,
    ) -> None:
        makefile_cache = KbuildMakefileCache(self.config)
        source_cache = (
            SourceAnalysisCache(self.config, source_includes)
            if source_includes is not None
            else None
        )
        total = len(structured.commits)
        with repository_file_reader(context) as file_reader:
            def create_state(commit_id: str) -> KbuildState:
                return KbuildState(
                    context.repo,
                    self.config,
                    self._parent_or_self(structured, commit_id),
                    source_includes,
                    file_reader.read_file,
                    makefile_cache=makefile_cache,
                    source_analysis_cache=source_cache,
                )

            with filter_progress(self.name, total, show_progress) as progress:
                task = progress.add_task(self.name, total=total)
                for visit in _walk_history(structured, create_state):
                    decisions = self._decide_commit(
                        visit.state,
                        structured.commits[visit.commit_id],
                        store.get_history(visit.commit_id),
                    )
                    store.add_decisions(visit.commit_id, decisions)
                    progress.advance(task)
        store.commit()

    def _close_preparation(self) -> None:
        if self._store is not None:
            self._store.close()
            self._store = None
        self._prepared_context = None

    def _prepare(self, context: FilterContext, *, show_progress: bool) -> None:
        structured = context.structured_commits
        if structured is None:
            raise ValueError("ConfigFilter requires complete structured commit history")
        context_key = (id(context.repo), id(structured))
        if self._prepared_context == context_key:
            return

        self._close_preparation()
        if not structured.commits:
            self._prepared_context = context_key
            return
        store = ConfigHistoryStore()
        self._store = store
        try:
            paths = self._populate_history(structured, store)
            source_includes = self._source_includes(context, structured, store, paths)
            paths.clear()
            self._collect_decisions(
                context, structured, store, source_includes, show_progress
            )
        except BaseException:
            self._close_preparation()
            raise
        self._prepared_context = context_key

    def filter_mutable_commit(
        self, commit: FilteredCommit, context: FilterContext
    ) -> FilteredCommit | None:
        self._prepare(context, show_progress=False)
        if self._store is None:
            return None
        decisions = self._store.get_decisions(commit.original.commit_id)
        if not decisions:
            return None

        retained: list[DiffFile] = []
        modes: dict[tuple[str | None, str], FileBuildModes] = {}
        for diff_file in commit.diff.files:
            key = diff_file_key(diff_file)
            decision = decisions.get(key)
            if decision is None:
                continue
            retained.append(diff_file)
            modes[key] = FileBuildModes(old=decision.old, new=decision.new)

        if not retained:
            return None
        commit.diff.files = retained
        commit.build_modes.update(modes)
        return commit

    def iter_filter_mutable_commits(
        self,
        commits: Iterable[FilteredCommit],
        context: FilterContext,
        show_progress: bool = True,
        *,
        total: int | None = None,
    ) -> Generator[FilteredCommit, None, None]:
        self._validate_name()
        self._close_preparation()
        try:
            self._prepare(context, show_progress=show_progress)
            for commit in commits:
                result = self.filter_mutable_commit(commit, context)
                if result is not None:
                    result.synchronize_diff()
                    yield result
        finally:
            self._close_preparation()


__all__ = ["ConfigFilter"]
