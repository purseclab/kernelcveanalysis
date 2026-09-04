from datetime import datetime
from pathlib import Path
import posixpath

from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TaskProgressColumn,
    TextColumn,
    TimeRemainingColumn,
)

from .file_filter import FileFilter
from .config_filter import ConfigFilter, KernelConfig, ConfigValue
from .ifdef_filter import diff_file_touches_active_code, get_active_lines
from .repository_file import RepositoryFileReader
from .source_filter import SourceIncludeIndex
from ..diff import DiffFileType
from ..git import GitRepo, GitDb, StructuredCommits, GitCommit, save_commits_to_db

# pre classifier / llm filtering

# filters in individual commit
# returns true to include
def filter_commit(
    config_filter: ConfigFilter,
    commit: GitCommit,
) -> bool:
    parent_commit_id = (
        commit.parent.commit_id if commit.parent is not None else None
    )

    changed_paths = {
        path
        for diff_file in commit.diff.files
        for path in (diff_file.file, diff_file.old_file)
        if path is not None
    }
    build_description_changed = any(
        posixpath.basename(path).startswith(("Kbuild", "Makefile"))
        or posixpath.splitext(path)[1] in (".mk", ".mak")
        for path in changed_paths
    )
    include_targets = (
        config_filter.source_includes.dependent_targets(changed_paths)
        if config_filter.source_includes is not None
        else frozenset()
    )
    parent_checked: set[int] = set()

    try:
        # we don't care about merge commits
        if commit.is_merge:
            return False

        for index, file in enumerate(commit.diff.files):
            old_file = file.old_file or file.file
            needs_parent = file.change_type in (
                DiffFileType.DELETE,
                DiffFileType.RENAME,
            ) or (
                file.change_type is DiffFileType.DEFAULT
                and (build_description_changed or old_file in include_targets)
            )
            if needs_parent:
                parent_checked.add(index)
            if needs_parent and config_filter.file_included(old_file):
                is_module = config_filter.get(old_file) == ConfigValue.MODULE
                if diff_file_touches_active_code(
                    repo=config_filter.repo,
                    parent_commit=parent_commit_id,
                    current_commit=commit.commit_id,
                    diff_file=file,
                    config=config_filter.config,
                    is_module=is_module,
                    check_new=False,
                    read_file=config_filter.read_file,
                ):
                    return True
    finally:
        config_filter.update_filter_state(commit.diff, commit.commit_id)

    for index, file in enumerate(commit.diff.files):
        if config_filter.file_included(file.file):
            is_module = config_filter.get(file.file) == ConfigValue.MODULE
            if diff_file_touches_active_code(
                repo=config_filter.repo,
                parent_commit=parent_commit_id,
                current_commit=commit.commit_id,
                diff_file=file,
                config=config_filter.config,
                is_module=is_module,
                check_old=(
                    index not in parent_checked
                    and file.change_type is not DiffFileType.COPY
                ),
                read_file=config_filter.read_file,
            ):
                return True

    return False

def filter_commits(
    repo: GitRepo,
    kernel_config: KernelConfig,
    all_commits: list[GitCommit],
    show_progress: bool = True,
) -> list[GitCommit]:
    out: list[GitCommit] = []
    commits = StructuredCommits.from_commits(all_commits)

    source_includes: SourceIncludeIndex | None = None
    if all_commits and getattr(repo, "repo", None) is not None:
        source_paths = {
            path
            for commit in all_commits
            for diff_file in commit.diff.files
            for path in (diff_file.file, diff_file.old_file)
            if path is not None
        }
        snapshot = max(
            all_commits,
            key=lambda commit: commit.committer_date,
        ).commit_id
        source_includes = SourceIncludeIndex.from_repository(
            repo,
            snapshot,
            kernel_config.srcarch,
            source_paths,
        )
        for commit in all_commits:
            source_includes.add_diff(commit.diff)

    # need a bit of a hack sinde parent could be none on root, but would basically never happen
    def parent_or_self(commit: str) -> str:
        parent = commits.commits[commit].parent

        if parent is None:
            return commit
        else:
            return parent.commit_id

    total_commits = len(commits.commits)

    with RepositoryFileReader(repo) as file_reader:
        commit_stack = [
            (
                commit,
                ConfigFilter(
                    repo,
                    kernel_config,
                    parent_or_self(commit),
                    source_includes,
                    file_reader.read_file,
                ),
            )
            for commit in commits.root_commits
        ]

        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TimeRemainingColumn(),
            disable=not show_progress or total_commits == 0,
        ) as progress:
            task = progress.add_task("Filtering commits", total=total_commits)

            while len(commit_stack) > 0:
                current_commit_id, current_filter = commit_stack.pop()

                while True:
                    current_commit = commits.commits[current_commit_id]

                    if filter_commit(current_filter, current_commit):
                        out.append(current_commit)

                    progress.advance(task)

                    children = commits.commit_children[current_commit_id]

                    if len(children.primary_children) == 0:
                        break
                    else:
                        current_commit_id = children.primary_children[0]

                        for child in children.primary_children[1:]:
                            filter_copy = ConfigFilter.copy(current_filter)
                            # commit in stack is child, filter still is set on parents, matching initial stack construction
                            commit_stack.append((child, filter_copy))

    return out

def filter_commit_time_range(
    repo: GitRepo,
    db: GitDb,
    destination_db_name: str,
    kernel_config_path: Path | None,
    start_date: datetime,
    end_date: datetime,
    show_progress: bool = True,
):
    all_commits = db.commits_between(start_date, end_date, include_merges=True)
    non_merge_commits = [commit for commit in all_commits if not commit.is_merge]

    if kernel_config_path is not None:
        kernel_config = KernelConfig(kernel_config_path.read_text())
        filtered_commits = filter_commits(
            repo, kernel_config, all_commits, show_progress=show_progress
        )
    else:
        filtered_commits = non_merge_commits

    print(f"Original commit count: {len(all_commits)}")
    print(f"Number of non merge commits: {len(non_merge_commits)}")
    print(f"Filtered commit count: {len(filtered_commits)}")

    save_commits_to_db(destination_db_name, filtered_commits)



__all__ = [
    "FileFilter",
    "filter_commits",
    "filter_commit_time_range",
    "get_active_lines",
    "diff_file_touches_active_code",
]
