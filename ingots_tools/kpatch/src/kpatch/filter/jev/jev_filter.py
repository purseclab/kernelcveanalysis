from typing import ClassVar
from dataclasses import asdict, dataclass

from ..base import CommitFilter, FilterContext, FilteredCommit
from .jev_api import NoulQuestion, NoulResult, jev

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

    def filter_mutable_commit(
        self,
        commit: FilteredCommit,
        context: FilterContext,
    ) -> FilteredCommit | None:
        from .extended_diff import build_input_state

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
                true_criteria="The patch initializes data before use or prevents uninitialized data from being read or exposed",
                false_criteria="The patch does not address an uninitialized-data issue",
            ),
            NoulQuestion(
                name="integer_arithmetic",
                instructions="Does this patch fix incorrect integer arithmetic, conversion, or overflow that could affect sizes, offsets, or limits?",
                true_criteria="The patch corrects an arithmetic or conversion error with security-relevant consequences",
                false_criteria="The patch does not address a security-relevant integer error",
            ),
            NoulQuestion(
                name="information_disclosure",
                instructions="Does this patch prevent unintended disclosure of kernel or another user's data?",
                true_criteria="The patch closes a path that could expose data to an unauthorized recipient",
                false_criteria="The patch does not address unintended data exposure",
            ),
            NoulQuestion(
                name="bugfix_patch",
                instructions="Does this patch fix an existing defect or incorrect behavior?",
                true_criteria="The patch corrects a bug in existing behavior",
                false_criteria="The patch only adds a feature, refactors code, or changes behavior without fixing a defect",
            ),
            NoulQuestion(
                name="security_patch",
                instructions="Does this patch fix or mitigate a plausible security vulnerability?",
                true_criteria="The patch corrects a vulnerability or mitigates an exploitable security weakness",
                false_criteria="The patch is unrelated to a security weakness, even if it fixes an ordinary bug",
            ),
        ]

        results = jev(asdict(state), questions)
        security_result = results["security_patch"]
        if not isinstance(security_result, NoulResult):
            raise ValueError("Jev returned a non-noul security_patch answer")
        commit.original.score = security_result.noul
        return commit

__all__ = ["InputState", "JevFilter"]
