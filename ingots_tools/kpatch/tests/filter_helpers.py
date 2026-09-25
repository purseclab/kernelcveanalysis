from kpatch.filter import (
    ConfigFilter,
    FilterContext,
    FilterPipeline,
    IfdefFilter,
    MergeCommitFilter,
    WhitespaceFilter,
)
from kpatch.filter.config_filter import KernelConfig
from kpatch.git import GitCommit, GitRepo, StructuredCommits


def filter_commits(
    repo: GitRepo,
    kernel_config: KernelConfig,
    all_commits: list[GitCommit],
    show_progress: bool = True,
) -> list[GitCommit]:
    """Apply the configured kernel and preprocessor pipeline for tests."""

    structured = StructuredCommits.from_commits(all_commits)
    context = FilterContext(repo, structured, all_commits)
    return FilterPipeline(
        [
            MergeCommitFilter(),
            ConfigFilter(kernel_config),
            IfdefFilter(kernel_config),
            WhitespaceFilter(),
        ]
    ).filter_commits(
        all_commits,
        context,
        show_progress=show_progress,
    )
