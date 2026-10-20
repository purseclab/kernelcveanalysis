import tempfile
import unittest
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
import sqlite3
from typing import Iterable, Iterator
from unittest.mock import patch

from kpatch.git import (
    LOG_FIELD_SEPARATOR,
    LOG_MESSAGE_END,
    LOG_RECORD_START,
    CommitParent,
    GitCommit,
    GitDb,
    GitRepo,
    GitStore,
    HistoryKind,
    StructuredCommits,
    extract_to_db,
)


class FakeRepo:
    def __init__(self, commits: list[GitCommit]):
        self.commits = commits
        self.include_merges = False

    def iter_commits_between(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        include_merges: bool = False,
    ) -> Iterator[GitCommit]:
        self.include_merges = include_merges
        for commit in self.commits:
            if commit.is_merge and not include_merges:
                continue
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
        self.assertIsNone(commit.score)
        self.assertEqual(commit.ratings, {})

    def test_include_merges_controls_git_log_and_marks_merge_commits(self) -> None:
        metadata = LOG_FIELD_SEPARATOR.join(
            value.encode()
            for value in (
                "a" * 40,
                "Alice Example",
                "alice@example.com",
                "2024-01-01T01:00:00+00:00",
                "2024-01-01T02:00:00+00:00",
                f"{'b' * 40} {'c' * 40}",
                "Merge topic\n",
            )
        )
        first_diff = b"diff --git a/first b/first\n"
        record = LOG_RECORD_START + metadata + LOG_MESSAGE_END + first_diff

        class StubGitRepo(GitRepo):
            args: list[str]

            def _iter_git_records(self, args: list[str]) -> Iterator[bytes]:
                self.args = args
                yield record

        repo = StubGitRepo(Path("unused"))
        commit = repo.commits_between(include_merges=True)[0]

        self.assertNotIn("--no-merges", repo.args)
        self.assertIn("--diff-merges=first-parent", repo.args)
        self.assertTrue(commit.is_merge)
        self.assertEqual(commit.parent, commit.parents[0])
        self.assertEqual(commit.diff_str, first_diff.decode())
        self.assertEqual(commit.parents[1].diff_str, "")

        repo.commits_between()
        self.assertIn("--no-merges", repo.args)

class GitDbTests(unittest.TestCase):
    def test_history_kind_defaults_and_updates_atomically(self) -> None:
        date = datetime(2024, 1, 1, tzinfo=UTC)
        commit = GitCommit(
            "commit",
            "",
            "",
            date,
            date,
            (CommitParent("parent", ""),),
            "",
        )
        with tempfile.TemporaryDirectory() as directory:
            db = GitDb(Path(directory) / "commits.sqlite")
            self.assertIs(db.history_kind, HistoryKind.UNKNOWN)

            db.store_commits([commit], HistoryKind.COMPLETE)
            self.assertIs(db.history_kind, HistoryKind.COMPLETE)

            db.replace_commits([commit], HistoryKind.SPARSE)
            self.assertIs(db.history_kind, HistoryKind.SPARSE)

    def test_extract_marks_real_database_as_complete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db = GitDb(Path(directory) / "commits.sqlite")

            extract_to_db(FakeRepo([]), db)

            self.assertIs(db.history_kind, HistoryKind.COMPLETE)

    def test_existing_database_requires_history_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "commits.sqlite"
            connection = sqlite3.connect(path)
            try:
                connection.execute(
                    "CREATE TABLE commits (commit_id TEXT PRIMARY KEY)"
                )
                connection.commit()
            finally:
                connection.close()

            with self.assertRaisesRegex(RuntimeError, "database_metadata"):
                GitDb(path)

    def test_stores_and_queries_commits(self) -> None:
        start = datetime(2024, 1, 1, tzinfo=UTC)
        end = datetime(2024, 1, 2, tzinfo=UTC)
        older = GitCommit(
            commit_id="older",
            author_name="Alice",
            author_email="alice@example.com",
            author_date=start + timedelta(hours=1),
            committer_date=start + timedelta(hours=2),
            parents=(CommitParent("parent", "diff --git a/old b/old\n"),),
            message="Older commit\n",
            score=0.75,
            ratings={"security_patch": 0.75, "bounds_checks": 0.91},
        )
        newer = GitCommit(
            commit_id="newer",
            author_name="Bob",
            author_email="bob@example.com",
            author_date=start + timedelta(hours=3),
            committer_date=datetime(2024, 1, 2, 1, tzinfo=UTC),
            parents=(CommitParent("", "diff --git a/new b/new\n"),),
            message="Newer commit\n",
        )
        at_end = GitCommit(
            commit_id="at-end",
            author_name="Carol",
            author_email="carol@example.com",
            author_date=end,
            committer_date=end,
            parents=(),
            message="Boundary commit\n",
        )
        merge = GitCommit(
            commit_id="merge",
            author_name="Dave",
            author_email="dave@example.com",
            author_date=start + timedelta(hours=4),
            committer_date=start + timedelta(hours=5),
            parents=(
                CommitParent("parent-1", "first-parent diff\n"),
                CommitParent("parent-2", ""),
            ),
            message="Merge commit\n",
        )

        with tempfile.TemporaryDirectory() as directory:
            db = GitDb(Path(directory) / "nested" / "commits.sqlite")
            self.assertIsInstance(db, GitStore)
            db.store_commits([older, newer, at_end, merge])

            self.assertEqual(db.commits_between(start, end), [older])
            self.assertEqual(db.commits_between(start, end)[0].score, 0.75)
            self.assertEqual(
                db.commits_between(start, end)[0].ratings,
                {"security_patch": 0.75, "bounds_checks": 0.91},
            )
            self.assertIsNone(db.commits_between(end)[0].score)
            self.assertEqual(db.commits_between(end)[0].ratings, {})
            self.assertEqual(
                db.commits_between(start, end, include_merges=True),
                [merge, older],
            )
            self.assertEqual(
                db.commits_between(start, end + timedelta(days=1)),
                [newer, at_end, older],
            )
            self.assertEqual(db.commits_between(end), [newer, at_end])
            self.assertEqual(db.commits_between(end=end), [older])
            self.assertEqual(db.commits_between(), [newer, at_end, older])

    def test_iterator_preserves_tied_order_and_all_parent_edges(self) -> None:
        date = datetime(2024, 1, 1, tzinfo=UTC)
        root = GitCommit("root", "", "", date, date, (), "")
        branches = [
            GitCommit(
                branch,
                "",
                "",
                date,
                date,
                (CommitParent("root", f"{branch} patch"),),
                "",
            )
            for branch in ("left", "right", "side")
        ]
        merge = GitCommit(
            "merge",
            "",
            "",
            date,
            date,
            tuple(
                CommitParent(branch.commit_id, f"patch from {branch.commit_id}")
                for branch in branches
            ),
            "",
        )
        commits = [root, *branches, merge]

        with tempfile.TemporaryDirectory() as directory:
            db = GitDb(Path(directory) / "commits.sqlite")
            db.store_commits(commits)

            loaded = list(db.iter_commits_between(include_merges=True))

            self.assertEqual(loaded, list(reversed(commits)))
            self.assertEqual(db.commits_between(include_merges=True), loaded)
            self.assertEqual(
                list(db.iter_commits_between()),
                [*reversed(branches), root],
            )
            history = StructuredCommits.from_commits(loaded)
            self.assertEqual(history.root_commits, {"root"})
            self.assertEqual(history.leaf_commits, {"merge", "right", "side"})
            self.assertEqual(
                history.commit_children["root"].primary_children,
                ["side", "right", "left"],
            )
            self.assertEqual(
                history.commit_children["left"].primary_children, ["merge"]
            )
            for branch in ("right", "side"):
                self.assertEqual(
                    history.commit_children[branch].secondary_children,
                    ["merge"],
                )

    def test_iterator_reads_only_current_commit_and_lookahead(self) -> None:
        date = datetime(2024, 1, 1, tzinfo=UTC)
        commits = [
            GitCommit(
                str(index),
                "",
                "",
                date,
                date + timedelta(seconds=index),
                (CommitParent("root", f"patch {index}"),),
                "",
            )
            for index in range(100)
        ]
        with tempfile.TemporaryDirectory() as directory:
            db = GitDb(Path(directory) / "commits.sqlite")
            db.store_commits(commits)
            connection = sqlite3.connect(db.db)
            rows_read = 0

            def track_row(cursor: sqlite3.Cursor, row: tuple[object, ...]) -> sqlite3.Row:
                nonlocal rows_read
                rows_read += 1
                return sqlite3.Row(cursor, row)

            connection.row_factory = track_row
            with (
                patch.object(db, "_connect", return_value=connection) as connect,
                closing(db.iter_commits_between()) as iterator,
            ):
                connect.assert_not_called()
                self.assertEqual(rows_read, 0)
                self.assertEqual(next(iterator), commits[-1])
                self.assertLessEqual(rows_read, len(commits[-1].parents) + 1)

            with self.assertRaisesRegex(sqlite3.ProgrammingError, "closed"):
                connection.execute("SELECT 1")

    def test_iterator_closes_connection_when_exhausted(self) -> None:
        date = datetime(2024, 1, 1, tzinfo=UTC)
        commit = GitCommit("commit", "", "", date, date, (), "")
        with tempfile.TemporaryDirectory() as directory:
            db = GitDb(Path(directory) / "commits.sqlite")
            for commits in ([], [commit]):
                with self.subTest(count=len(commits)):
                    db.replace_commits(commits)
                    connection = sqlite3.connect(db.db)
                    connection.row_factory = sqlite3.Row
                    with patch.object(db, "_connect", return_value=connection):
                        self.assertEqual(list(db.iter_commits_between()), commits)

                    with self.assertRaisesRegex(sqlite3.ProgrammingError, "closed"):
                        connection.execute("SELECT 1")

    def test_iterator_validates_merge_flag_and_closes_on_error(self) -> None:
        date = datetime(2024, 1, 1, tzinfo=UTC)
        commit = GitCommit("commit", "", "", date, date, (), "")
        with tempfile.TemporaryDirectory() as directory:
            db = GitDb(Path(directory) / "commits.sqlite")
            db.store_commits([commit])
            connection = sqlite3.connect(db.db)
            connection.row_factory = sqlite3.Row
            connection.execute("UPDATE commits SET is_merge = 1")
            connection.commit()

            with patch.object(db, "_connect", return_value=connection):
                with self.assertRaisesRegex(ValueError, "merge flag"):
                    next(db.iter_commits_between(include_merges=True))

            with self.assertRaisesRegex(sqlite3.ProgrammingError, "closed"):
                connection.execute("SELECT 1")

    def test_storing_a_commit_again_updates_it(self) -> None:
        date = datetime(2024, 1, 1, tzinfo=UTC)
        commit = GitCommit(
            commit_id="commit",
            author_name="Alice",
            author_email="alice@example.com",
            author_date=date,
            committer_date=date,
            parents=(CommitParent("parent", "original diff\n"),),
            message="Original\n",
        )
        updated = GitCommit(
            commit_id=commit.commit_id,
            author_name=commit.author_name,
            author_email=commit.author_email,
            author_date=commit.author_date,
            committer_date=commit.committer_date,
            parents=(CommitParent("parent", "updated diff\n"),),
            message="Updated\n",
            score=0.5,
            ratings={"security_patch": 0.5},
        )

        with tempfile.TemporaryDirectory() as directory:
            db = GitDb(Path(directory) / "commits.sqlite")
            db.store_commits([commit])
            db.store_commits([updated])

            self.assertEqual(db.commits_between(date, date + timedelta(days=1)), [updated])

            updated.score = None
            updated.ratings = {}
            db.store_commits([updated])
            self.assertIsNone(db.commits_between()[0].score)
            self.assertEqual(db.commits_between()[0].ratings, {})

            with closing(sqlite3.connect(db.db)) as connection:
                parent_rows = connection.execute(
                    """
                    SELECT parent_index, parent_commit_id, diff
                    FROM commit_parents
                    WHERE commit_id = ?
                    """,
                    (commit.commit_id,),
                ).fetchall()
            self.assertEqual(parent_rows, [(0, "parent", "updated diff\n")])

    def test_replace_commits_removes_rows_from_previous_filter_run(self) -> None:
        date = datetime(2024, 1, 1, tzinfo=UTC)
        stale = GitCommit("stale", "", "", date, date, (), "")
        replacement = GitCommit(
            "replacement",
            "",
            "",
            date,
            date,
            (CommitParent("parent", "replacement diff\n"),),
            "",
        )

        with tempfile.TemporaryDirectory() as directory:
            db = GitDb(Path(directory) / "commits.sqlite")
            db.store_commits([stale])

            stored = db.replace_commits([replacement])

            self.assertEqual(stored, 1)
            self.assertEqual(db.commits_between(), [replacement])
            with closing(sqlite3.connect(db.db)) as connection:
                parent_rows = connection.execute(
                    "SELECT commit_id FROM commit_parents"
                ).fetchall()
            self.assertEqual(parent_rows, [("replacement",)])

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
            GitCommit("at-start", "", "", start, start, (), ""),
            GitCommit(
                "merge",
                "",
                "",
                start,
                start + timedelta(hours=1),
                (
                    CommitParent("parent-1", "first diff"),
                    CommitParent("parent-2", ""),
                ),
                "",
            ),
            GitCommit("at-end", "", "", end, end, (), ""),
        ]
        repo = FakeRepo(commits)
        db = FakeDb()

        processed = extract_to_db(repo, db, start, end)

        self.assertEqual(processed, 2)
        self.assertEqual(
            [commit.commit_id for commit in db.commits],
            ["at-start", "merge"],
        )
        self.assertTrue(repo.include_merges)


if __name__ == "__main__":
    unittest.main()
