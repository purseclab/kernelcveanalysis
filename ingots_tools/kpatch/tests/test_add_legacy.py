from contextlib import closing
from pathlib import Path
import sqlite3
import subprocess
from tempfile import TemporaryDirectory
import unittest

from kpatch.add import add_to_db
from kpatch.git import GitDb, GitRepo, extract_to_db
from kpatch.update_state import read_extraction_bounds

from test_add import day, git


class LegacyBoundedAddTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.repository = self.directory / "repository"
        self.repository.mkdir()
        git(self.repository, "init", "-q", "-b", "main")
        git(self.repository, "config", "user.name", "Test Author")
        git(self.repository, "config", "user.email", "author@example.test")
        git(self.repository, "config", "commit.gpgSign", "false")
        self.ids: list[str] = []
        for offset in range(5):
            git(
                self.repository, "commit", "--allow-empty", "-q", "-m",
                f"commit {offset}", date=day(offset),
            )
            self.ids.append(git(self.repository, "rev-parse", "HEAD"))
        self.repo = GitRepo(self.repository)
        self.db = GitDb(self.directory / "commits.sqlite")
        extract_to_db(self.repo, self.db, day(2), day(4))
        with closing(self.db._connect()) as connection, connection:
            bounds = read_extraction_bounds(connection)
            assert bounds is not None
            connection.execute(
                "UPDATE database_metadata SET value = ? WHERE key = 'bounded_extraction'",
                (bounds.model_dump_json(exclude={"tip_commit"}),),
            )

    def snapshot(self) -> tuple[str, ...]:
        with closing(sqlite3.connect(self.db.db)) as connection:
            return tuple(connection.iterdump())

    def test_legacy_bounds_accept_reachable_history_and_upgrade_provenance(self) -> None:
        result = add_to_db(self.repo, self.db, day(1), day(5))
        self.assertEqual(result.added_commits, 2)
        with closing(self.db._connect()) as connection:
            bounds = read_extraction_bounds(connection)
        assert bounds is not None
        self.assertEqual(bounds.tip_commit, self.ids[-1])

    def test_legacy_bounds_reject_rewind_preserving_database(self) -> None:
        before = self.snapshot()
        git(self.repository, "checkout", "--detach", self.ids[2])
        with self.assertRaisesRegex(ValueError, "diverges"):
            add_to_db(self.repo, self.db, day(1), day(4))
        self.assertEqual(self.snapshot(), before)

    def test_legacy_bounds_reject_divergence_preserving_database(self) -> None:
        before = self.snapshot()
        git(self.repository, "checkout", "--detach", self.ids[2])
        git(self.repository, "commit", "--allow-empty", "-q", "-m", "diverged", date=day(4))
        with self.assertRaisesRegex(ValueError, "diverges"):
            add_to_db(self.repo, self.db, day(1), day(5))
        self.assertEqual(self.snapshot(), before)

    def test_legacy_bounds_reject_missing_ids_preserving_database(self) -> None:
        before = self.snapshot()
        unrelated = self.directory / "unrelated"
        unrelated.mkdir()
        git(unrelated, "init", "-q", "-b", "main")
        git(unrelated, "config", "user.name", "Other Author")
        git(unrelated, "config", "user.email", "other@example.test")
        git(unrelated, "-c", "commit.gpgSign=false", "commit", "--allow-empty", "-q", "-m", "other", date=day(3))
        with self.assertRaises(subprocess.CalledProcessError):
            add_to_db(GitRepo(unrelated), self.db, day(1), day(5))
        self.assertEqual(self.snapshot(), before)

    def test_contains_commits_checks_stdin_ids_as_positive_revisions(self) -> None:
        self.assertTrue(self.repo.contains_commits(iter(self.ids), self.ids[-1]))
        self.assertFalse(self.repo.contains_commits(iter(self.ids), self.ids[2]))
        self.assertTrue(self.repo.contains_commits(iter(()), self.ids[-1]))

    def test_contains_commits_reports_missing_ids_even_after_unreachable_id(self) -> None:
        with self.assertRaises(subprocess.CalledProcessError):
            self.repo.contains_commits(iter((self.ids[-1], "1" * 40)), self.ids[2])

    def test_bounded_extraction_uses_pinned_tip_if_checkout_moves(self) -> None:
        repository = self.repository
        pinned_tip = self.ids[-1]
        new_database = GitDb(self.directory / "pinned.sqlite")
        rewind_tip = self.ids[2]

        class MovingRepo(GitRepo):
            def resolve_head(self) -> str:
                tip = super().resolve_head()
                git(repository, "checkout", "--detach", rewind_tip)
                return tip

        extract_to_db(MovingRepo(repository), new_database, day(1), day(5))
        stored = {commit.commit_id for commit in new_database.commits_between()}
        self.assertEqual(stored, set(self.ids[1:]))
        with closing(new_database._connect()) as connection:
            bounds = read_extraction_bounds(connection)
        assert bounds is not None
        self.assertEqual(bounds.tip_commit, pinned_tip)


if __name__ == "__main__":
    unittest.main()
