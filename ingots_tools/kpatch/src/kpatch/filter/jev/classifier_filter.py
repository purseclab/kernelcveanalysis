from typing import ClassVar

from ..base import FilterContext, FilteredCommit, StreamingCommitFilter
from .jev_api import ChoiceQuestion, ChoiceResult, NoulQuestion, NoulResult, jev


MODEL = "openai/gpt-6-luna-decisions"
FIX_TYPE_CRITERIA = {
    "none": "No demonstrated security weakness is fixed: feature, cleanup, ordinary correctness or performance fix, or insufficient evidence of attacker reachability.",
    "lifetime_race": "A use-after-free, double free, stale reference, missing lock, or race allows unsafe access to an object.",
    "bounds": "An out-of-bounds read or write, buffer overrun, or missing length validation permits access outside an object.",
    "integer": "Arithmetic, sign conversion, truncation, or shift error produces a security-relevant size, offset, or limit.",
    "disclosure": "Uninitialized or otherwise unintended kernel or cross-user data is exposed without a more specific bounds or lifetime root cause.",
    "authorization": "A missing or incorrect permission, capability, namespace, or lockdown check grants access to a protected operation or resource.",
    "other_security": "A demonstrated security fix whose primary cause fits none of the categories above.",
}
QUESTIONS = (
    NoulQuestion(
        name="security_fix",
        instructions="Does this patch fix or mitigate a plausible security vulnerability?",
        true_criteria="The patch corrects a vulnerability or mitigates an exploitable security weakness.",
        false_criteria="The patch is unrelated to a security weakness, even if it fixes an ordinary bug.",
    ),
    ChoiceQuestion(
        name="fix_type",
        instructions="What is the primary root-cause category of the security assessment?",
        criteria=FIX_TYPE_CRITERIA,
    ),
)


def selected_fix_type(score: float, probabilities: dict[str, float]) -> str:
    """Apply the benchmark's binary cutoff before choosing a root cause."""

    if score < 0.5:
        return "none"
    return max(
        (fix_type for fix_type in FIX_TYPE_CRITERIA if fix_type != "none"),
        key=probabilities.__getitem__,
    )


class ClassifierFilter(StreamingCommitFilter):
    """Score security fixes and store root-cause probabilities in numeric ratings."""

    name: ClassVar[str] = "Classifier Filter"

    def filter_mutable_commit(
        self,
        commit: FilteredCommit,
        context: FilterContext,
    ) -> FilteredCommit | None:
        original = commit.original
        patch = commit.remaining_diff().text if commit.edit_masks or commit.code_masks else original.diff_str
        state = f"COMMIT MESSAGE:\n{original.message}\nPATCH:\n{patch}"
        answers = jev(state, QUESTIONS, model=MODEL, timeout=75.0)
        security = answers["security_fix"]
        fix_type = answers["fix_type"]
        if not isinstance(security, NoulResult) or not isinstance(fix_type, ChoiceResult):
            raise ValueError("OpenRouter returned unexpected classifier answer types")

        score = security.noul
        selected = selected_fix_type(score, fix_type.probabilities)
        original.score = score
        # Ratings are numeric in GitCommit; the one-hot key records the chosen type.
        original.ratings = {
            "security_fix": score,
            **{
                f"fix_type_{name}": probability
                for name, probability in fix_type.probabilities.items()
            },
            f"selected_fix_type_{selected}": 1.0,
        }
        return commit


__all__ = ["ClassifierFilter", "selected_fix_type"]
