from datetime import UTC, datetime
import os
from pathlib import Path
import sqlite3
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from typer.testing import CliRunner

from kpatch.add import AddResult
from kpatch.cli import app
from kpatch.git import GitDb


class AddCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.database_path = self.directory / "commits.sqlite"
        self.database_path.touch()
        self.arguments = [
            "add", "--repo", str(self.directory), "--db", str(self.database_path),
        ]
        self.start = datetime(2026, 1, 1, tzinfo=UTC)
        self.end = datetime(2026, 2, 1, tzinfo=UTC)
        self.outcome = AddResult(
            added_commits=7, total_commits=107,
            start_date=self.start, end_date=self.end, tip_commit="a" * 40,
        )

    def test_explicit_dates_are_forwarded_and_counts_are_reported(self) -> None:
        with (
            patch("kpatch.cli.GitDb") as database,
            patch("kpatch.cli.add_to_db", return_value=self.outcome) as add,
            patch("kpatch.cli.run_filter") as filter_commits,
        ):
            result = CliRunner().invoke(
                app, self.arguments + ["--start", "01-01-2026", "--end", "02-01-2026"],
            )
        self.assertEqual(result.exit_code, 0, result.output)
        database.assert_called_once_with(self.database_path)
        add.assert_called_once()
        repository, passed_database, start, end = add.call_args.args
        self.assertEqual(repository.repo, self.directory)
        self.assertIs(passed_database, database.return_value)
        self.assertEqual(start, self.start)
        self.assertEqual(end, self.end)
        self.assertEqual(add.call_args.kwargs, {
            "start_at_stored_end": False, "end_at_stored_start": False,
        })
        filter_commits.assert_not_called()
        self.assertIn("Added 7 commits; 107 total", result.output)

    def test_start_at_stored_end_flag_is_forwarded(self) -> None:
        with (
            patch("kpatch.cli.GitDb"),
            patch("kpatch.cli.add_to_db", return_value=self.outcome) as add,
        ):
            result = CliRunner().invoke(
                app, self.arguments + ["--start-at-stored-end", "--end", "02-01-2026"],
            )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(add.call_args.args[2:], (None, self.end))
        self.assertEqual(add.call_args.kwargs, {
            "start_at_stored_end": True, "end_at_stored_start": False,
        })

    def test_end_at_stored_start_flag_is_forwarded(self) -> None:
        with (
            patch("kpatch.cli.GitDb"),
            patch("kpatch.cli.add_to_db", return_value=self.outcome) as add,
        ):
            result = CliRunner().invoke(
                app, self.arguments + ["--start", "01-01-2026", "--end-at-stored-start"],
            )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(add.call_args.args[2:], (self.start, None))
        self.assertEqual(add.call_args.kwargs, {
            "start_at_stored_end": False, "end_at_stored_start": True,
        })

    def test_invalid_dates_fail_before_opening_database(self) -> None:
        for option in ("--start", "--end"):
            with (
                self.subTest(option=option),
                patch("kpatch.cli.GitDb") as database,
                patch("kpatch.cli.add_to_db") as add,
            ):
                result = CliRunner().invoke(app, self.arguments + [option, "not-a-date"])
                self.assertEqual(result.exit_code, 1)
                self.assertIn("Add failed", result.output)
                database.assert_not_called()
                add.assert_not_called()

    def test_validation_and_operational_failures_have_nonzero_exit(self) -> None:
        failures = [
            ValueError("A range bound is required"),
            RuntimeError("Invalid coverage metadata"),
            sqlite3.OperationalError("database is locked"),
            OSError("scratch disk is full"),
            subprocess.CalledProcessError(128, ["git", "log"]),
        ]
        for failure in failures:
            with (
                self.subTest(failure=failure),
                patch("kpatch.cli.GitDb"),
                patch("kpatch.cli.add_to_db", side_effect=failure),
            ):
                result = CliRunner().invoke(
                    app, self.arguments + ["--start", "01-01-2026"],
                )
                self.assertEqual(result.exit_code, 1)
                self.assertIn("Add failed", result.output)

    def test_creates_fresh_database_and_supports_repeat_and_backward_extension(self) -> None:
        repository = self.directory / "repository"
        repository.mkdir()
        environment = os.environ.copy()
        for args in (
            ["init", "-q", "-b", "main"],
            ["config", "user.name", "Test Author"],
            ["config", "user.email", "author@example.test"],
            ["config", "commit.gpgSign", "false"],
        ):
            subprocess.run(["git", "-C", str(repository), *args], check=True)
        for date in ("2026-01-01T00:00:00+00:00", "2026-01-02T00:00:00+00:00"):
            environment["GIT_AUTHOR_DATE"] = date
            environment["GIT_COMMITTER_DATE"] = date
            subprocess.run(
                ["git", "-C", str(repository), "commit", "--allow-empty", "-q", "-m", date],
                env=environment, check=True,
            )
        database = self.directory / "new.sqlite"
        arguments = ["add", "--repo", str(repository), "--db", str(database)]
        first = CliRunner().invoke(
            app, arguments + ["--start", "01-02-2026", "--end", "01-03-2026"],
        )
        self.assertEqual(first.exit_code, 0, first.output)
        self.assertTrue(database.is_file())
        self.assertIn("Added 1 commits; 1 total", first.output)
        repeated = CliRunner().invoke(
            app, arguments + ["--start", "01-02-2026", "--end", "01-03-2026"],
        )
        self.assertEqual(repeated.exit_code, 0, repeated.output)
        self.assertIn("Added 0 commits; 1 total", repeated.output)
        extended = CliRunner().invoke(app, arguments + ["--end-at-stored-start"])
        self.assertEqual(extended.exit_code, 0, extended.output)
        self.assertIn("Added 1 commits; 2 total", extended.output)
        self.assertEqual(len(GitDb(database).commits_between()), 2)

    def test_missing_repository_is_rejected(self) -> None:
        with patch("kpatch.cli.add_to_db") as add:
            result = CliRunner().invoke(app, [
                "add", "--repo", str(self.directory / "missing"),
                "--db", str(self.database_path), "--start", "01-01-2026",
            ])
        self.assertEqual(result.exit_code, 2)
        add.assert_not_called()


if __name__ == "__main__":
    unittest.main()
