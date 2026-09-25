from typing import ClassVar
import random

from .base import CommitFilter, FilterContext, FilteredCommit


class CountFilter(CommitFilter):
    """Filter that selects n commits randomly and discards the rest.

    Intended for testing and sampling pipelines without processing the entire dataset.
    """

    name: ClassVar[str] = "Sampling commit count"

    def __init__(self, count: int, seed: int | None = None, *, n: int | None = None):
        selected_count = n if n is not None else count
        if selected_count < 0:
            raise ValueError("Count must be a non-negative integer")
        self.count = selected_count
        self.seed = (
            seed if seed is not None else random.randrange(1, (1 << 31) - 1)
        )

    def filter_mutable_commits(
        self,
        commits: list[FilteredCommit],
        context: FilterContext,
        show_progress: bool = True,
    ) -> list[FilteredCommit]:
        self._validate_name()
        if self.count >= len(commits):
            return list(commits)

        rng = random.Random(self.seed)
        selected_indices = sorted(rng.sample(range(len(commits)), self.count))
        return [commits[i] for i in selected_indices]
