from typing import ClassVar

from ..base import CommitFilter, FilterContext, FilteredCommit



class JevFilter(CommitFilter):
    name: ClassVar[str] = "Jev Filter"
    requires_complete_history: ClassVar[bool] = False

    def filter_mutable_commit(
        self,
        commit: FilteredCommit,
        context: FilterContext,
    ) -> FilteredCommit | None:
        return None

__all__ = ["JevFilter"]
