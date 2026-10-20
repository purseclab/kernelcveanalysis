"""Configuration decisions shared by serial traversal and root workers."""

import posixpath

from ..base import diff_file_key
from ..config_filter import ConfigValue, KbuildState
from ...diff import Diff, DiffFile, DiffFileType
from .history import FileDecision, HistoryCommit


type FileKey = tuple[str | None, str]


def changed_paths(diff: Diff) -> set[str]:
    return {
        path
        for diff_file in diff.files
        for path in (diff_file.file, diff_file.old_file)
        if path is not None
    }


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


def decide_commit(
    state: KbuildState,
    commit: HistoryCommit,
    diff: Diff,
) -> dict[FileKey, FileDecision]:
    """Advance a branch state and decide its changed files without filter I/O."""

    paths = changed_paths(diff)
    build_description_changed = any(
        posixpath.basename(path).startswith(("Kbuild", "Makefile"))
        or posixpath.splitext(path)[1] in (".mk", ".mak")
        for path in paths
    )
    include_targets = (
        state.source_includes.dependent_targets(paths)
        if state.source_includes is not None
        else frozenset()
    )

    old_modes: dict[FileKey, ConfigValue | None] = {}
    needs_parent: dict[FileKey, bool] = {}
    for diff_file in diff.files:
        key = diff_file_key(diff_file)
        check_parent = _needs_parent(
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

    decisions: dict[FileKey, FileDecision] = {}
    for diff_file in diff.files:
        key = diff_file_key(diff_file)
        new_mode = (
            None
            if diff_file.change_type is DiffFileType.DELETE
            else state.get(diff_file.file) if state.file_included(diff_file.file) else None
        )
        old_mode = old_modes[key]
        if not needs_parent[key] and diff_file.change_type not in (
            DiffFileType.NEW,
            DiffFileType.COPY,
        ):
            old_mode = new_mode
        if old_mode is not None or new_mode is not None:
            decisions[key] = FileDecision(old=old_mode, new=new_mode)
    return decisions
