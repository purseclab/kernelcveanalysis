from typing import ClassVar

from .base import CommitFilter, FilterContext, FilteredCommit


class ScoreFilter(CommitFilter):
    """Keep commits meeting a minimum score, optionally including unscored ones."""

    name: ClassVar[str] = "Filtering by score"

    def __init__(self, threshold: float, allow_missing_score: bool = False):
        self.threshold = threshold
        self.allow_missing_score = allow_missing_score

    def filter_mutable_commit(
        self,
        commit: FilteredCommit,
        context: FilterContext,
    ) -> FilteredCommit | None:
        score = commit.original.score
        if score is None:
            return commit if self.allow_missing_score else None
        return commit if score >= self.threshold else None


__all__ = ["ScoreFilter"]
