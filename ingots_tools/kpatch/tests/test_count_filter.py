from datetime import UTC, datetime
from pathlib import Path
import unittest

from kpatch.filter import CountFilter, FilterContext, FilterPipeline
from kpatch.git import CommitParent, GitCommit, GitRepo


class MemoryGitRepo(GitRepo):
    def __init__(self, files: dict[str, str] | None = None):
        self.files = files or {}

    def read_file(self, commit: str, path: str) -> bytes:
        raise FileNotFoundError(f"{commit}:{path}")


class CountFilterTests(unittest.TestCase):
    @staticmethod
    def make_commit(commit_id: str) -> GitCommit:
        date = datetime(2024, 1, 1, tzinfo=UTC)
        return GitCommit(
            commit_id,
            "Author",
            "author@example.com",
            date,
            date,
            (CommitParent("parent", "diff"),),
            f"Commit {commit_id}",
        )

    def test_selects_exact_count_of_commits(self) -> None:
        commits = [self.make_commit(f"c{i}") for i in range(10)]
        context = FilterContext(MemoryGitRepo())

        f = CountFilter(count=3, seed=42)
        result = f.filter_commits(commits, context, show_progress=False)

        self.assertEqual(len(result), 3)
        orig_ids = {c.commit_id for c in commits}
        self.assertTrue(all(c.commit_id in orig_ids for c in result))

    def test_deterministic_with_same_seed(self) -> None:
        commits = [self.make_commit(f"c{i}") for i in range(20)]
        context = FilterContext(MemoryGitRepo())

        f1 = CountFilter(count=5, seed=12345)
        f2 = CountFilter(count=5, seed=12345)

        res1 = [c.commit_id for c in f1.filter_commits(commits, context, show_progress=False)]
        res2 = [c.commit_id for c in f2.filter_commits(commits, context, show_progress=False)]

        self.assertEqual(res1, res2)

    def test_different_seeds_produce_different_samples(self) -> None:
        commits = [self.make_commit(f"c{i}") for i in range(50)]
        context = FilterContext(MemoryGitRepo())

        f1 = CountFilter(count=10, seed=1)
        f2 = CountFilter(count=10, seed=2)

        res1 = [c.commit_id for c in f1.filter_commits(commits, context, show_progress=False)]
        res2 = [c.commit_id for c in f2.filter_commits(commits, context, show_progress=False)]

        self.assertNotEqual(res1, res2)

    def test_auto_generates_seed_if_none(self) -> None:
        f = CountFilter(count=5)
        self.assertIsInstance(f.seed, int)
        self.assertGreater(f.seed, 0)

    def test_retains_all_if_count_greater_or_equal(self) -> None:
        commits = [self.make_commit(f"c{i}") for i in range(5)]
        context = FilterContext(MemoryGitRepo())

        f = CountFilter(count=10, seed=42)
        result = f.filter_commits(commits, context, show_progress=False)
        self.assertEqual(len(result), 5)
        self.assertEqual([c.commit_id for c in result], [c.commit_id for c in commits])

    def test_count_zero_returns_empty(self) -> None:
        commits = [self.make_commit(f"c{i}") for i in range(5)]
        context = FilterContext(MemoryGitRepo())

        f = CountFilter(count=0, seed=42)
        result = f.filter_commits(commits, context, show_progress=False)
        self.assertEqual(result, [])

    def test_negative_count_raises_error(self) -> None:
        with self.assertRaises(ValueError):
            CountFilter(count=-1)

    def test_supports_n_parameter(self) -> None:
        commits = [self.make_commit(f"c{i}") for i in range(10)]
        context = FilterContext(MemoryGitRepo())

        f = CountFilter(10, n=3, seed=42)
        result = f.filter_commits(commits, context, show_progress=False)
        self.assertEqual(len(result), 3)

    def test_pipeline_integration(self) -> None:
        commits = [self.make_commit(f"c{i}") for i in range(10)]
        context = FilterContext(MemoryGitRepo())

        pipeline = FilterPipeline([CountFilter(count=4, seed=99)])
        result = pipeline.filter_commits(commits, context, show_progress=False)
        self.assertEqual(len(result), 4)


if __name__ == "__main__":
    unittest.main()
