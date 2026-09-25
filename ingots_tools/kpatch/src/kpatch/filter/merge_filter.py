from typing import ClassVar

from .base import CommitFilter, FilterContext, FilteredCommit


class MergeCommitFilter(CommitFilter):
    """Remove merge commits from the candidate stream."""

    name: ClassVar[str] = "Filtering merge commits"

    def filter_mutable_commit(
        self,
        commit: FilteredCommit,
        context: FilterContext,
    ) -> FilteredCommit | None:
        return None if commit.original.is_merge else commit


__all__ = ["MergeCommitFilter"]
