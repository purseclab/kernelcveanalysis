from typing import ClassVar
from dataclasses import dataclass

from ..base import CommitFilter, FilterContext, FilteredCommit
from .extended_diff import build_input_state
from .jev_api import NoulQuestion, ChoiceQuestion, ScoreQuestion, jev

@dataclass
class InputState:
    patch_decsription: str
    # mapping from patched files to patch contents for that file
    # patch contents is diff, but all patched functions have entirety of function body included
    patched_files: dict[str, str]
    # functions determined important / close in call chain to patched functions, as additional context
    context_functions: list[str]

class JevFilter(CommitFilter):
    name: ClassVar[str] = "Jev Filter"
    requires_complete_history: ClassVar[bool] = False

    def filter_mutable_commit(
        self,
        commit: FilteredCommit,
        context: FilterContext,
    ) -> FilteredCommit | None:
        state = build_input_state(commit, context, max_context_items=15)

        questions = [
            NoulQuestion(
                name="destructor_logic",
                instructions="Does this patch introduce changes related to when destructors are called?",
                true_criteria="Logic, control flow, ordering, or flags around when destructors are called is affected by the patch",
                false_criteria="Patch has no clear impact on when and how destructors are called",
            ),
            NoulQuestion(
                name="refcount_logic",
                instructions="Does this patch introduce changes around how reference count of objects are managed?",
                true_criteria="How and when reference counts are incramented is affected by the patch",
                false_criteria="Patch has no clear impact on reference count management of any object",
            ),
            NoulQuestion(
                name="locking_and_synchronization",
                instructions="Does this patch introduce changes affecting how locking, atomic synchronization, or rcu is used?",
                true_criteria="Locking construct usage is changed, reordered, or added",
                false_criteria="Patch has no clear impact on locking or synchronization",
            ),
            NoulQuestion(
                name="permission_checks",
                instructions="Does this patch introduce additional permissions checks or refactor existing ones?",
                true_criteria="New or refactored permissions checks related to unix permissions, seccomp, selinux, namespaces, or other linux permission constructs",
                false_criteria="Patch has no clear impact on permissions checks",
            ),
            NoulQuestion(
                name="bounds_checks",
                instructions="Does this patch change bounds checking logic or fix any bounds check issues?",
                true_criteria="Patch updates logic related to checking array or loop indicies, adds additional checks on lengths, or other indexing related checks",
                false_criteria="Patch has no clear impact on indexing or length bounds checks",
            ),
            NoulQuestion(
                name="uninitialized_variables",
                instructions="Does this patch fix any issues with uninitialized variables, struct fields, or memory?",
            ),
        ]

        return None

__all__ = ["InputState", "JevFilter"]
