from dataclasses import dataclass
import posixpath
from typing import ClassVar

from ..base import (
    CommitFilter,
    FileBuildModes,
    FilterContext,
    FilteredCommit,
    diff_file_key,
    filter_progress,
)
from ..config_filter import (
    ConfigValue,
    KbuildMakefileCache,
    KbuildState,
    KernelConfig,
)
from ..repository_file import RepositoryFileReader
from ..source_filter import SourceIncludeIndex
from ...diff import Diff, DiffFile, DiffFileType
from ...git import GitCommit, StructuredCommits


@dataclass(frozen=True, slots=True)
class _FileDecision:
    old: ConfigValue | None
    new: ConfigValue | None


class ConfigFilter(CommitFilter):
    """Filter mutable commits through the configured Kbuild graph."""

    name: ClassVar[str] = "Filtering kernel configuration"

    @property
    def requires_complete_history(self) -> bool:
        return True

    def __init__(self, config: KernelConfig):
        self.config = config
        self._decisions: dict[
            str,
            dict[tuple[str | None, str], _FileDecision],
        ] = {}
        self._prepared_context: tuple[int, int] | None = None

    @staticmethod
    def _history_diff(commit: GitCommit) -> Diff:
        """Keep file metadata and changed directives, not entire history patches.

        Kbuild traversal only needs paths and change types. The source include
        index additionally needs changed include lines; other hunk contents and
        rendered patch text would just duplicate the immutable source commits.
        """

        diff = Diff.parse(commit.diff_str)
        diff.text = ""
        for diff_file in diff.files:
            diff_file.header_lines = []
            directives = []
            for chunk in diff_file.chunks:
                chunk.lines = [
                    line
                    for line in chunk.lines
                    if line.startswith(("+", "-"))
                    and line[1:].lstrip().startswith("#")
                ]
                if chunk.lines:
                    directives.append(chunk)
            diff_file.chunks = directives
        return diff

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
    ) -> dict[tuple[str | None, str], _FileDecision]:
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
                diff_file,
                build_description_changed,
                include_targets,
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

        decisions: dict[tuple[str | None, str], _FileDecision] = {}
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
                decisions[key] = _FileDecision(old=old_mode, new=new_mode)
        return decisions

    def _source_includes(
        self,
        context: FilterContext,
        structured: StructuredCommits,
        history_diffs: dict[str, Diff],
    ) -> SourceIncludeIndex | None:
        originals = structured.commits.values()
        if not structured.commits or getattr(context.repo, "repo", None) is None:
            return None
        source_paths = {
            path
            for diff in history_diffs.values()
            for diff_file in diff.files
            for path in (diff_file.file, diff_file.old_file)
            if path is not None
        }
        snapshot = max(
            originals,
            key=lambda commit: commit.committer_date,
        ).commit_id
        source_includes = SourceIncludeIndex.from_repository(
            context.repo,
            snapshot,
            self.config.srcarch,
            source_paths,
        )
        for diff in history_diffs.values():
            source_includes.add_diff(diff)
        return source_includes

    @staticmethod
    def _parent_or_self(structured: StructuredCommits, commit_id: str) -> str:
        parent = structured.commits[commit_id].parent
        return commit_id if parent is None else parent.commit_id

    def _prepare(
        self,
        context: FilterContext,
        *,
        show_progress: bool,
    ) -> None:
        structured = context.structured_commits
        if structured is None:
            raise ValueError(
                "ConfigFilter requires complete structured commit history"
            )
        context_key = (id(context.repo), id(structured))
        if self._prepared_context == context_key:
            return

        self._decisions = {}
        if not structured.commits:
            self._prepared_context = context_key
            return

        history_diffs = {
            commit_id: self._history_diff(commit)
            for commit_id, commit in structured.commits.items()
        }
        source_includes = self._source_includes(
            context, structured, history_diffs
        )
        total = len(structured.commits)
        makefile_cache = KbuildMakefileCache(self.config)
        with RepositoryFileReader(context.repo) as file_reader:
            stack = [
                (
                    commit_id,
                    KbuildState(
                        context.repo,
                        self.config,
                        self._parent_or_self(structured, commit_id),
                        source_includes,
                        file_reader.read_file,
                        makefile_cache=makefile_cache,
                    ),
                )
                for commit_id in structured.root_commits
            ]
            with filter_progress(self.name, total, show_progress) as progress:
                task = progress.add_task(self.name, total=total)
                while stack:
                    current_id, state = stack.pop()
                    while True:
                        current = structured.commits[current_id]
                        self._decisions[current_id] = self._decide_commit(
                            state,
                            current,
                            history_diffs[current_id],
                        )
                        progress.advance(task)

                        children = structured.commit_children[current_id]
                        if not children.primary_children:
                            break
                        current_id = children.primary_children[0]
                        for child in children.primary_children[1:]:
                            stack.append((child, KbuildState.copy(state)))

        self._prepared_context = context_key

    def filter_mutable_commit(
        self,
        commit: FilteredCommit,
        context: FilterContext,
    ) -> FilteredCommit | None:
        self._prepare(context, show_progress=False)
        decisions = self._decisions.get(commit.original.commit_id, {})
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
            modes[key] = FileBuildModes(
                old=decision.old,
                new=decision.new,
            )

        if not retained:
            return None
        commit.diff.files = retained
        commit.build_modes.update(modes)
        return commit

    def filter_mutable_commits(
        self,
        commits: list[FilteredCommit],
        context: FilterContext,
        show_progress: bool = True,
    ) -> list[FilteredCommit]:
        self._validate_name()
        self._prepared_context = None
        self._prepare(context, show_progress=show_progress)
        filtered: list[FilteredCommit] = []
        for commit in commits:
            result = self.filter_mutable_commit(commit, context)
            if result is not None:
                result.synchronize_diff()
                filtered.append(result)
        return filtered


__all__ = ["ConfigFilter"]
