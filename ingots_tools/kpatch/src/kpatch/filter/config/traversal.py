"""The shared, light-first first-parent history walk."""

from collections.abc import Callable, Collection, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from ..config_filter import KbuildState


class PrimaryHistoryGraph(Protocol):
    @property
    def primary_children(self) -> Mapping[str, Sequence[str]]: ...

    @property
    def subtree_sizes(self) -> Mapping[str, int]: ...

    @property
    def root_commits(self) -> Collection[str]: ...


@dataclass(frozen=True, slots=True)
class HistoryState:
    commit_id: str
    state: KbuildState


@dataclass(slots=True)
class _PendingBranch:
    state: KbuildState
    children: list[str]


def _next_branch(pending: list[_PendingBranch]) -> HistoryState | None:
    if not pending:
        return None
    branch = pending[-1]
    child = branch.children.pop()
    if branch.children:
        # Copy the branch about to run, never all the deferred siblings.
        state = KbuildState.copy(branch.state)
    else:
        state = branch.state
        pending.pop()
    return HistoryState(child, state)


def walk_history(
    history: PrimaryHistoryGraph,
    create_state: Callable[[str], KbuildState],
) -> Iterator[HistoryState]:
    """Yield parent-before-child states; the caller advances each yielded state.

    Preserve the original traversal and state reuse exactly: finish smaller
    subtrees first, then consume the saved base state for the largest subtree.
    Only O(log N) light-edge snapshots remain live, even for very wide trees.
    """

    sizes = history.subtree_sizes
    for root in sorted(history.root_commits, key=lambda key: (sizes[key], key)):
        pending: list[_PendingBranch] = []
        current: HistoryState | None = HistoryState(root, create_state(root))
        while current is not None:
            yield current
            children = history.primary_children[current.commit_id]
            if len(children) == 1:
                current = HistoryState(children[0], current.state)
                continue
            if children:
                pending.append(
                    _PendingBranch(
                        current.state,
                        sorted(children, key=lambda key: sizes[key], reverse=True),
                    )
                )
            current = _next_branch(pending)
