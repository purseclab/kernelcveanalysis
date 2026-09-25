import unittest
from datetime import UTC, datetime
from pathlib import Path

from kpatch.filter import FilterContext, FilterPipeline, ScoreFilter
from kpatch.git import GitCommit, GitRepo


class ScoreFilterTests(unittest.TestCase):
    def test_threshold_and_missing_scores_in_pipeline(self) -> None:
        date = datetime(2024, 1, 1, tzinfo=UTC)
        commits = [
            GitCommit(name, "", "", date, date, (), "", score)
            for name, score in (
                ("below", 0.49),
                ("equal", 0.5),
                ("above", 0.75),
                ("missing", None),
            )
        ]
        context = FilterContext(GitRepo(Path("unused")))

        for allow_missing, expected in (
            (False, ["equal", "above"]),
            (True, ["equal", "above", "missing"]),
        ):
            with self.subTest(allow_missing_score=allow_missing):
                result = FilterPipeline(
                    [ScoreFilter(0.5, allow_missing_score=allow_missing)]
                ).filter_commits(commits, context, show_progress=False)
                self.assertEqual([commit.commit_id for commit in result], expected)
                self.assertEqual(result[0].score, 0.5)


if __name__ == "__main__":
    unittest.main()
