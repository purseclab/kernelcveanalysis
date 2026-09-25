import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from kpatch.filter import FilterContext, FilteredCommit
from kpatch.filter.jev import InputState, JevFilter, NoulResult
from kpatch.git import GitCommit, GitRepo


class JevFilterTests(unittest.TestCase):
    def test_jev_security_answer_sets_commit_score(self) -> None:
        date = datetime(2024, 1, 1, tzinfo=UTC)
        commit = GitCommit("commit", "", "", date, date, (), "Fix bug")
        view = FilteredCommit.from_commit(commit)
        context = FilterContext(GitRepo(Path("unused")))
        state = InputState("Fix bug", {"kernel/foo.c": "patch"}, ["helper"])

        with (
            patch(
                "kpatch.filter.jev.extended_diff.build_input_state",
                return_value=state,
            ) as build_state,
            patch(
                "kpatch.filter.jev.jev_filter.jev",
                return_value={"security_patch": NoulResult("noul", 0.83)},
            ) as call_jev,
        ):
            result = JevFilter().filter_mutable_commit(view, context)

        self.assertIs(result, view)
        self.assertEqual(commit.score, 0.83)
        build_state.assert_called_once_with(view, context, max_context_items=15)
        sent_state, questions = call_jev.call_args.args
        self.assertEqual(
            sent_state,
            {
                "patch_decsription": "Fix bug",
                "patched_files": {"kernel/foo.c": "patch"},
                "context_functions": ["helper"],
            },
        )
        self.assertTrue(
            {
                "uninitialized_variables",
                "bugfix_patch",
                "security_patch",
                "integer_arithmetic",
                "information_disclosure",
            }
            <= {question.name for question in questions}
        )


if __name__ == "__main__":
    unittest.main()
