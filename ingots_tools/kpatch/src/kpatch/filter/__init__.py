from contextlib import closing
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .base import (
    CommitFilter,
    FileBuildModes,
    FilterContext,
    FilteredCommit,
    FilterPipeline,
    StreamingCommitFilter,
)
from .config import ConfigFilter
from .config_filter import ConfigValue, KernelConfig
from .count_filter import CountFilter
from .file_filter import FileFilter
from .ifdef_filter import (
    IfdefFilter,
    diff_file_touches_active_code,
    get_active_lines,
)
from .jev import JevFilter
from .merge_filter import MergeCommitFilter
from .score_filter import ScoreFilter
from .whitespace import (
    CToken,
    CTokenKind,
    SourceNoopFilter,
    WhitespaceFilter,
    WhitespaceFilterStats,
    tokenize_c_source,
)
from ..git import (
    GitDb,
    GitRepo,
    save_commits_to_db,
    _path_for_db_name,
)

@dataclass
class RunFilterArgs:
    repo: GitRepo
    db: GitDb
    destination_db_name: str
    start_date: datetime | None = None
    end_date: datetime | None = None

def run_filter(
    args: RunFilterArgs,
    filter: CommitFilter,
    *,
    show_progress: bool = True,
) -> None:
    destination = _path_for_db_name(args.destination_db_name)
    if args.db.db.resolve() == destination.resolve() or (
        destination.exists() and args.db.db.samefile(destination)
    ):
        raise ValueError("Streaming filtering requires a destination different from the source")
    context = FilterContext.from_db_range(
        args.db,
        args.repo,
        args.start_date,
        args.end_date,
        include_merges=True,
    )
    if filter.requires_complete_history and context.structured_commits is None:
        raise ValueError("Filtering requires complete history and structured commit history")
    all_commits = context.commits
    non_merge_count = sum(not commit.is_merge for commit in all_commits)

    print(f"Original commit count: {len(all_commits)}")
    print(f"Number of non merge commits: {non_merge_count}")
    with closing(
        filter.iter_filter_commits(
            all_commits,
            context,
            show_progress=show_progress,
            total=len(all_commits),
        )
    ) as filtered_commits:
        filtered_count = save_commits_to_db(args.destination_db_name, filtered_commits)
    print(f"Filtered commit count: {filtered_count}")

def filter_commit_time_range(
    repo: GitRepo,
    db: GitDb,
    destination_db_name: str,
    kernel_config_path: Path | None,
    start_date: datetime,
    end_date: datetime,
    *,
    show_progress: bool = True,
) -> None:
    if kernel_config_path is not None:
        kernel_config = KernelConfig(kernel_config_path.read_text())
        filter = FilterPipeline(
            [
                MergeCommitFilter(),
                ConfigFilter(kernel_config),
                IfdefFilter(kernel_config),
                WhitespaceFilter(),
            ]
        )
    else:
        filter = FilterPipeline(
            [
                MergeCommitFilter(),
                WhitespaceFilter(),
            ]
        )

    run_filter(
        RunFilterArgs(
            repo=repo,
            db=db,
            destination_db_name=destination_db_name,
            start_date=start_date,
            end_date=end_date,
        ),
        filter,
        show_progress=show_progress,
    )


__all__ = [
    "CToken",
    "CTokenKind",
    "CommitFilter",
    "ConfigFilter",
    "ConfigValue",
    "CountFilter",
    "FileBuildModes",
    "FileFilter",
    "FilterContext",
    "FilteredCommit",
    "FilterPipeline",
    "IfdefFilter",
    "JevFilter",
    "KernelConfig",
    "MergeCommitFilter",
    "RunFilterArgs",
    "ScoreFilter",
    "SourceNoopFilter",
    "StreamingCommitFilter",
    "WhitespaceFilter",
    "WhitespaceFilterStats",
    "diff_file_touches_active_code",
    "filter_commit_time_range",
    "get_active_lines",
    "tokenize_c_source",
]
