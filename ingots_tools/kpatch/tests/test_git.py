import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Iterable, Iterator

from kpatch.git import (
    LOG_FIELD_SEPARATOR,
    LOG_MESSAGE_END,
    LOG_RECORD_START,
    GitCommit,
    GitDb,
    GitRepo,
    GitStore,
    extract_to_db,
)


class FakeRepo:
    def __init__(self, commits: list[GitCommit]):
        self.commits = commits

    def iter_commits_between(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> Iterator[GitCommit]:
        for commit in self.commits:
            if (start is None or start <= commit.committer_date) and (
                end is None or commit.committer_date < end
            ):
                yield commit


class FakeDb:
    def __init__(self) -> None:
        self.commits: list[GitCommit] = []

    def store_commits(self, commits: Iterable[GitCommit]) -> int:
        count = 0
        for commit in commits:
            self.commits.append(commit)
            count += 1
        return count


class GitRepoTests(unittest.TestCase):
    def test_parses_separate_author_name_and_email(self) -> None:
        metadata = LOG_FIELD_SEPARATOR.join(
            value.encode()
            for value in (
                "a" * 40,
                "Alice Example",
                "alice@example.com",
                "2024-01-01T01:00:00+00:00",
                "2024-01-01T02:00:00+00:00",
                "",
                "Subject\n",
            )
        )
        record = LOG_RECORD_START + metadata + LOG_MESSAGE_END

        class StubGitRepo(GitRepo):
            def _iter_git_records(self, args: list[str]) -> Iterator[bytes]:
                yield record

        commit = StubGitRepo(Path("unused")).commits_between()[0]

        self.assertEqual(commit.author_name, "Alice Example")
        self.assertEqual(commit.author_email, "alice@example.com")


class GitDbTests(unittest.TestCase):
    def test_stores_and_queries_commits(self) -> None:
        start = datetime(2024, 1, 1, tzinfo=UTC)
        end = datetime(2024, 1, 2, tzinfo=UTC)
        older = GitCommit(
            commit_id="older",
            author_name="Alice",
            author_email="alice@example.com",
            author_date=start + timedelta(hours=1),
            committer_date=start + timedelta(hours=2),
            parents=("parent",),
            message="Older commit\n",
            diff_str="diff --git a/old b/old\n",
        )
        newer = GitCommit(
            commit_id="newer",
            author_name="Bob",
            author_email="bob@example.com",
            author_date=start + timedelta(hours=3),
            committer_date=datetime(2024, 1, 2, 1, tzinfo=UTC),
            parents=(),
            message="Newer commit\n",
            diff_str="diff --git a/new b/new\n",
        )
        at_end = GitCommit(
            commit_id="at-end",
            author_name="Carol",
            author_email="carol@example.com",
            author_date=end,
            committer_date=end,
            parents=(),
            message="Boundary commit\n",
            diff_str="",
        )

        with tempfile.TemporaryDirectory() as directory:
            db = GitDb(Path(directory) / "nested" / "commits.sqlite")
            self.assertIsInstance(db, GitStore)
            db.store_commits([older, newer, at_end])

            self.assertEqual(db.commits_between(start, end), [older])
            self.assertEqual(
                db.commits_between(start, end + timedelta(days=1)),
                [newer, at_end, older],
            )
            self.assertEqual(db.commits_between(end), [newer, at_end])
            self.assertEqual(db.commits_between(end=end), [older])
            self.assertEqual(db.commits_between(), [newer, at_end, older])

    def test_storing_a_commit_again_updates_it(self) -> None:
        date = datetime(2024, 1, 1, tzinfo=UTC)
        commit = GitCommit(
            commit_id="commit",
            author_name="Alice",
            author_email="alice@example.com",
            author_date=date,
            committer_date=date,
            parents=(),
            message="Original\n",
            diff_str="original diff\n",
        )
        updated = GitCommit(
            commit_id=commit.commit_id,
            author_name=commit.author_name,
            author_email=commit.author_email,
            author_date=commit.author_date,
            committer_date=commit.committer_date,
            parents=commit.parents,
            message="Updated\n",
            diff_str="updated diff\n",
        )

        with tempfile.TemporaryDirectory() as directory:
            db = GitDb(Path(directory) / "commits.sqlite")
            db.store_commits([commit])
            db.store_commits([updated])

            self.assertEqual(db.commits_between(date, date + timedelta(days=1)), [updated])

    def test_queries_require_timezone_aware_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db = GitDb(Path(directory) / "commits.sqlite")

            with self.assertRaises(ValueError):
                db.commits_between(datetime(2024, 1, 1), datetime(2024, 1, 2, tzinfo=UTC))


class ExtractToDbTests(unittest.TestCase):
    def test_streams_commits_into_db(self) -> None:
        start = datetime(2024, 1, 1, tzinfo=UTC)
        end = start + timedelta(days=1)
        commits = [
            GitCommit("at-start", "", "", start, start, (), "", ""),
            GitCommit("at-end", "", "", end, end, (), "", ""),
        ]
        repo = FakeRepo(commits)
        db = FakeDb()

        processed = extract_to_db(repo, db, start, end)

        self.assertEqual(processed, 1)
        self.assertEqual([commit.commit_id for commit in db.commits], ["at-start"])


if __name__ == "__main__":
    unittest.main()
