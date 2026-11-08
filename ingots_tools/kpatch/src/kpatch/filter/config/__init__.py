from collections.abc import Callable, Generator, Iterable, Iterator
from dataclasses import dataclass, replace
import subprocess
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
    KbuildMakefileCache,
    KbuildState,
    KernelConfig,
    SourceAnalysisCache,
)
from ..source_filter import SourceIncludeIndex
from ..masking import MaskReason, SourceSide
from ..input_role_models import InputInventoryState
from ..source_modes import regular_source_change
from ...diff import Diff, DiffFile, DiffFileType
from ...git import GitCommit, StructuredCommits
from .decisions import changed_paths, decide_commit
from .history import ConfigHistoryStore, HistoryCommit, parse_history_diff
from .parallel import collect_parallel_decisions
from .traversal import HistoryState, walk_history


@dataclass(frozen=True, slots=True)
class _TraversalGraph:
    primary_children: dict[str, list[str]]
    subtree_sizes: dict[str, int]
    root_commits: tuple[str, ...]


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


def _walk_history(
    structured: StructuredCommits,
    create_state: Callable[[str], KbuildState],
) -> Iterator[HistoryState]:
    """Adapt existing metadata without copying messages or loading patches."""

    graph = _TraversalGraph(
        primary_children={
            commit_id: children.primary_children
            for commit_id, children in structured.commit_children.items()
        },
        subtree_sizes=_primary_subtree_sizes(structured),
        root_commits=tuple(structured.root_commits),
    )
    yield from walk_history(graph, create_state)


class ConfigFilter(StreamingCommitFilter):
    """Filter configured inputs using the modeled Kbuild/include relationships.

    Explicit observation mode records the same decisions without applying them.
    """

    name: ClassVar[str] = "Filtering kernel configuration"

    @property
    def requires_complete_history(self) -> bool:
        return True

    def __init__(
        self, config: KernelConfig, workers: int = 1, *, collect_observations: bool = False,
    ) -> None:
        if workers < 1:
            raise ValueError("workers must be at least 1")
        self.config = config
        self.workers = workers
        self.collect_observations = collect_observations
        self._store: ConfigHistoryStore | None = None
        self._prepared_context: tuple[int, int] | None = None

    @staticmethod
    def _history_diff(commit: GitCommit) -> Diff:
        """Keep file metadata and changed directives, not entire history patches."""

        return parse_history_diff(commit.diff_str)

    def _populate_history(
        self, structured: StructuredCommits, store: ConfigHistoryStore, context: FilterContext
    ) -> set[str]:
        source_paths: set[str] = set()
        sizes = _primary_subtree_sizes(structured)
        for commit in structured.commits.values():
            if context.reference_index is not None:
                patch = commit.diff_str
                if not commit.is_merge:
                    context.reference_index.observe_patch(patch)
                diff = parse_history_diff(patch)
            else:
                diff = self._history_diff(commit)
            source_paths.update(changed_paths(diff))
            store.add_history(
                HistoryCommit.from_commit(commit), diff, sizes[commit.commit_id]
            )
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
        references = context.reference_index
        names = references.begin_bootstrap(snapshot) if references is not None else frozenset()
        source_includes = SourceIncludeIndex.from_repository(
            context.repo, snapshot, self.config.srcarch, source_paths,
            reference_names=names,
            reference_hit=references.bootstrap_hit if references is not None and names else None,
            prefer_pcre=True,
        )
        if references is not None:
            references.finish_bootstrap()
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
        if self.workers > 1 and len(structured.root_commits) > 1:
            if source_includes is None:
                raise ValueError(
                    "Parallel configuration filtering requires a filesystem Git repository"
                )
            sizes = _primary_subtree_sizes(structured)
            collect_parallel_decisions(
                self.config,
                context.repo.repo,
                store,
                source_includes,
                {root: sizes[root] for root in structured.root_commits},
                self.workers,
                show_progress,
            )
            return

        self._collect_serial_decisions(
            context, structured, store, source_includes, show_progress
        )

    def _collect_serial_decisions(
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
                    decisions = decide_commit(
                        visit.state,
                        HistoryCommit.from_commit(structured.commits[visit.commit_id]),
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
            paths = self._populate_history(structured, store, context)
            source_includes = self._source_includes(context, structured, store, paths)
            if context.reference_index is not None and source_includes is not None:
                snapshot = max(structured.commits.values(), key=lambda commit: commit.committer_date).commit_id
                context.reference_index.bind_includes(source_includes, snapshot)
            paths.clear()
            self._collect_decisions(
                context, structured, store, source_includes, show_progress
            )
        except BaseException:
            self._close_preparation()
            raise
        self._prepared_context = context_key

    @staticmethod
    def _known_input_veto(
        commit: FilteredCommit, file: DiffFile, context: FilterContext,
    ) -> bool:
        """Preserve observed raw consumers and operationally incomplete scans."""

        versions: list[tuple[str, str]] = []
        parent = commit.original.parent
        if file.change_type is not DiffFileType.NEW:
            if parent is None:
                return True
            versions.append((parent.commit_id, file.old_file or file.file))
        if file.change_type is not DiffFileType.DELETE:
            versions.append((commit.original.commit_id, file.file))
        full_context = replace(context, full_input_inventory=True)
        try:
            for revision, path in versions:
                observed = context.input_roles.lookup(full_context, revision, path)
                if (observed.state is not InputInventoryState.FULL
                        or observed.consumers or observed.failures):
                    return True
        except (OSError, ValueError, subprocess.SubprocessError):
            return True
        return False

    def filter_mutable_commit(
        self, commit: FilteredCommit, context: FilterContext
    ) -> FilteredCommit | None:
        commit.build_modes.clear()
        # Merges have no single parent/child view. Reject before deferred parse.
        if commit.original.is_merge:
            return None
        if not commit.diff.files:
            return None
        self._prepare(context, show_progress=False)
        if self._store is None:
            return None
        decisions = self._store.get_decisions(commit.original.commit_id)
        retained: list[DiffFile] = []
        modes: dict[tuple[str | None, str], FileBuildModes] = {}
        for diff_file in commit.diff.files:
            key = diff_file_key(diff_file)
            decision = decisions.get(key)
            if decision is None and self.collect_observations:
                retained.append(diff_file)
                continue
            if decision is None:
                # Only modeled regular source inputs are configuration masks.
                # Structural/build/data changes remain available to later stages.
                candidate = (diff_file.change_type in (DiffFileType.DEFAULT, DiffFileType.NEW, DiffFileType.DELETE)
                             and not diff_file.binary and not diff_file.mode_changed
                             and diff_file.file.endswith((".c", ".h", ".S", ".s"))
                             and ".lds" not in diff_file.file
                             and regular_source_change(diff_file, context.repo,
                                                       commit.original.parent.commit_id if commit.original.parent else None,
                                                       commit.original.commit_id))
                if not candidate or self._known_input_veto(commit, diff_file, context):
                    retained.append(diff_file)
                    modes[key] = FileBuildModes(complete=False)
                    continue
                commit.mask_file(diff_file, MaskReason.CONFIG)
                if diff_file.file.endswith((".c", ".h", ".S", ".s")) and ".lds" not in diff_file.file:
                    for side in SourceSide:
                        if (side is SourceSide.OLD and diff_file.change_type in (DiffFileType.NEW, DiffFileType.COPY)
                                or side is SourceSide.NEW and diff_file.change_type is DiffFileType.DELETE):
                            continue
                        commit.mask_code(diff_file, side, (), MaskReason.CONFIG, whole_file=True)
                continue
            retained.append(diff_file)
            modes[key] = FileBuildModes(old=decision.old, new=decision.new, complete=decision.complete)

        if not retained:
            return None
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
            with repository_file_reader(context) as reader:
                active_context = replace(context, file_reader=reader)
                self._prepare(active_context, show_progress=show_progress)
                for commit in commits:
                    result = self.filter_mutable_commit(commit, active_context)
                    if result is not None:
                        result.synchronize_diff()
                        yield result
        finally:
            self._close_preparation()


__all__ = ["ConfigFilter"]
