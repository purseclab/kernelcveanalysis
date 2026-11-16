from kpatch.filter import (
    ConfigFilter,
    FilterContext,
    FilterPipeline,
    IfdefFilter,
    MergeCommitFilter,
    WhitespaceFilter,
)
from kpatch.filter.config_filter import KernelConfig
from kpatch.filter.input_role_models import InputInventoryState, RawInputObservation
from kpatch.git import GitCommit, GitRepo, StructuredCommits


class FixtureSourceRoles:
    """Model supplied in-memory CPP buffers without external raw consumers.

    This fixture has no Git tree to scan. Its empty observation is not a
    certificate of build/input closure; real-Git tests use the default index.
    """

    def lookup(self, context: FilterContext, revision: str, path: str) -> RawInputObservation:
        return RawInputObservation(InputInventoryState.FULL)


def filter_commits(
    repo: GitRepo,
    kernel_config: KernelConfig,
    all_commits: list[GitCommit],
    show_progress: bool = True,
) -> list[GitCommit]:
    """Apply the configured kernel and preprocessor pipeline for tests."""

    structured = StructuredCommits.from_commits(all_commits)
    context = FilterContext(repo, structured, all_commits, input_roles=FixtureSourceRoles())
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
