import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import Mock, patch

from kpatch.filter import ClassifierFilter, FilterContext, FilteredCommit, MaskReason
from kpatch.filter.jev import ChoiceResult, NoulResult, selected_fix_type
from kpatch.filter.jev.classifier_filter import FIX_TYPE_CRITERIA, QUESTIONS
from kpatch.filter.jev.jev_api import jev
from kpatch.git import CommitParent, GitCommit, GitRepo


class ClassifierFilterTests(unittest.TestCase):
    def setUp(self) -> None:
        date = datetime(2024, 1, 1, tzinfo=UTC)
        self.commit = GitCommit(
            "commit", "", "", date, date,
            (CommitParent("first", "+first-parent patch"),
             CommitParent("second", "+second-parent patch")),
            "Fix bug\n\nSigned-off-by: Maintainer",
        )
        self.view = FilteredCommit.from_commit(self.commit)
        self.context = FilterContext(GitRepo(Path("unused")))

    def test_classifier_receives_remaining_patch_after_masking(self) -> None:
        patch_text = "".join(
            f"diff --git a/{name}.c b/{name}.c\n--- a/{name}.c\n+++ b/{name}.c\n@@ -1 +1 @@\n-int {name} = 1;\n+int {name} = 2;\n"
            for name in ("ignored", "retained")
        )
        self.commit.parents = (CommitParent("first", patch_text),)
        view = FilteredCommit(self.commit)
        view.mask_file(view.diff.files[0], MaskReason.FILE_SELECTION)
        answers = {"security_fix": NoulResult("noul", 0.1),
                   "fix_type": ChoiceResult("choice", "none", {"none": 1.0}, 1.0)}
        with patch("kpatch.filter.jev.classifier_filter.jev", return_value=answers) as classify:
            ClassifierFilter().filter_mutable_commit(view, self.context)
        state = classify.call_args.args[0]
        self.assertNotIn("ignored.c", state)
        self.assertIn("retained.c", state)
        self.assertEqual(self.commit.diff_str, patch_text)

    def test_luna_decision_sets_score_and_selected_fix_type(self) -> None:
        probabilities = {name: 0.02 for name in FIX_TYPE_CRITERIA}
        probabilities.update(none=0.52, bounds=0.37, integer=0.06)
        answers = {
            "security_fix": NoulResult("noul", 0.83),
            "fix_type": ChoiceResult("choice", "none", probabilities, 0.52),
        }

        with patch(
            "kpatch.filter.jev.classifier_filter.jev", return_value=answers
        ) as call_jev:
            result = ClassifierFilter().filter_mutable_commit(self.view, self.context)

        self.assertIs(result, self.view)
        self.assertEqual(self.commit.score, 0.83)
        self.assertEqual(self.commit.ratings["security_fix"], 0.83)
        self.assertEqual(self.commit.ratings["fix_type_none"], 0.52)
        self.assertEqual(self.commit.ratings["fix_type_bounds"], 0.37)
        self.assertEqual(self.commit.ratings["selected_fix_type_bounds"], 1.0)
        self.assertEqual(
            set(self.commit.ratings),
            {"security_fix", "selected_fix_type_bounds"}
            | {f"fix_type_{name}" for name in FIX_TYPE_CRITERIA},
        )
        sent_state, questions = call_jev.call_args.args
        self.assertEqual(
            sent_state,
            "COMMIT MESSAGE:\nFix bug\n\nSigned-off-by: Maintainer\n"
            "PATCH:\n+first-parent patch",
        )
        self.assertEqual(questions, QUESTIONS)
        self.assertEqual(
            call_jev.call_args.kwargs,
            {"model": "openai/gpt-6-luna-decisions", "timeout": 75.0},
        )

    def test_below_cutoff_selects_none_even_when_choice_prefers_bounds(self) -> None:
        probabilities = {name: 0.01 for name in FIX_TYPE_CRITERIA}
        probabilities["bounds"] = 0.8
        answers = {
            "security_fix": NoulResult("noul", 0.49),
            "fix_type": ChoiceResult("choice", "bounds", probabilities, 0.8),
        }

        with patch("kpatch.filter.jev.classifier_filter.jev", return_value=answers):
            ClassifierFilter().filter_mutable_commit(self.view, self.context)

        self.assertEqual(self.commit.score, 0.49)
        self.assertEqual(self.commit.ratings["selected_fix_type_none"], 1.0)
        self.assertEqual(selected_fix_type(0.5, probabilities), "bounds")

    def test_requests_openrouter_decisions_with_exact_questions(self) -> None:
        response = Mock()
        response.json.return_value = {
            "answers": {
                "security_fix": {"type": "noul", "noul": 0.83},
                "fix_type": {
                    "type": "choice",
                    "choice": "bounds",
                    "probabilities": {"none": 0.2, "bounds": 0.8},
                    "confidence": 0.8,
                },
            },
        }
        with patch("kpatch.filter.jev.jev_api.requests.post", return_value=response) as post:
            answers = jev(
                "COMMIT MESSAGE:\nFix bug\nPATCH:\n+fix",
                QUESTIONS,
                api_key="test-token",
                model="openai/gpt-6-luna-decisions",
            )

        self.assertEqual(answers["security_fix"], NoulResult("noul", 0.83))
        self.assertEqual(post.call_args.args[0], "https://openrouter.ai/api/alpha/decisions")
        self.assertEqual(post.call_args.kwargs["headers"]["Authorization"], "Bearer test-token")
        self.assertEqual(
            post.call_args.kwargs["json"],
            {
                "model": "openai/gpt-6-luna-decisions",
                "state": "COMMIT MESSAGE:\nFix bug\nPATCH:\n+fix",
                "questions": {
                    "security_fix": {
                        "type": "noul",
                        "instructions": "Does this patch fix or mitigate a plausible security vulnerability?",
                        "criteria": {
                            "true": "The patch corrects a vulnerability or mitigates an exploitable security weakness.",
                            "false": "The patch is unrelated to a security weakness, even if it fixes an ordinary bug.",
                        },
                    },
                    "fix_type": {
                        "type": "choice",
                        "instructions": "What is the primary root-cause category of the security assessment?",
                        "criteria": FIX_TYPE_CRITERIA,
                    },
                },
            },
        )


if __name__ == "__main__":
    unittest.main()
