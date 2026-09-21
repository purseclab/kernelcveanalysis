from datetime import datetime
from pathlib import Path

from .base import (
    CommitFilter,
    FileBuildModes,
    FilterContext,
    FilteredCommit,
    FilterPipeline,
)
from .config import ConfigFilter
from .config_filter import ConfigValue, KernelConfig
from .file_filter import FileFilter
from .ifdef_filter import (
    IfdefFilter,
    diff_file_touches_active_code,
    get_active_lines,
)
from .merge_filter import MergeCommitFilter
from ..git import (
    GitCommit,
    GitDb,
    GitRepo,
    StructuredCommits,
    save_commits_to_db,
)


def filter_commits(
    repo: GitRepo,
    kernel_config: KernelConfig,
    all_commits: list[GitCommit],
    show_progress: bool = True,
) -> list[GitCommit]:
    """Apply the configured kernel and preprocessor pipeline."""

    structured = StructuredCommits.from_commits(all_commits)
    context = FilterContext(repo, structured, tuple(all_commits))
    return FilterPipeline(
        [
            MergeCommitFilter(),
            ConfigFilter(kernel_config),
            IfdefFilter(kernel_config),
        ]
    ).filter_commits(
        all_commits,
        context,
        show_progress=show_progress,
    )


def filter_commit_time_range(
    repo: GitRepo,
    db: GitDb,
    destination_db_name: str,
    kernel_config_path: Path | None,
    start_date: datetime,
    end_date: datetime,
    show_progress: bool = True,
) -> None:
    context = FilterContext.from_db_range(
        db,
        repo,
        start_date,
        end_date,
        include_merges=True,
    )
    all_commits = list(context.commits)
    non_merge_count = sum(not commit.is_merge for commit in all_commits)

    if kernel_config_path is not None:
        kernel_config = KernelConfig(kernel_config_path.read_text())
        filtered_commits = FilterPipeline(
            [
                MergeCommitFilter(),
                ConfigFilter(kernel_config),
                IfdefFilter(kernel_config),
            ]
        ).filter_commits(
            all_commits,
            context,
            show_progress=show_progress,
        )
    else:
        filtered_commits = MergeCommitFilter().filter_commits(
            all_commits,
            context,
            show_progress=show_progress,
        )

    print(f"Original commit count: {len(all_commits)}")
    print(f"Number of non merge commits: {non_merge_count}")
    print(f"Filtered commit count: {len(filtered_commits)}")

    save_commits_to_db(destination_db_name, filtered_commits)


__all__ = [
    "CommitFilter",
    "ConfigFilter",
    "ConfigValue",
    "FileBuildModes",
    "FileFilter",
    "FilterContext",
    "FilteredCommit",
    "FilterPipeline",
    "IfdefFilter",
    "KernelConfig",
    "MergeCommitFilter",
    "diff_file_touches_active_code",
    "filter_commits",
    "filter_commit_time_range",
    "get_active_lines",
]
