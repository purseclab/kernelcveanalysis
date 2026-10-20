from datetime import UTC, datetime
from pathlib import Path
import sqlite3
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from typer.testing import CliRunner

from kpatch.cli import app
from kpatch.git import GitDb
from kpatch.update import UpdateResult


class UpdateCliTests(unittest.TestCase):
    def test_default_pulls_and_reports_only_raw_database_update(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database_path = root / "all_commits.sqlite"
            database_path.touch()
            database = Mock(spec=GitDb)
            outcome = UpdateResult(
                added_commits=7,
                total_commits=107,
                tip_commit="a" * 40,
                start_date=datetime(2026, 1, 1, tzinfo=UTC),
            )
            with (
                patch("kpatch.cli.GitDb", return_value=database) as open_database,
                patch("kpatch.cli.update_to_db", return_value=outcome) as update,
                patch("kpatch.cli.run_filter") as filter_commits,
            ):
                result = CliRunner().invoke(
                    app, ["update", "--repo", str(root), "--db", str(database_path)]
                )

            self.assertEqual(result.exit_code, 0, result.output)
            open_database.assert_called_once_with(database_path)
            update.assert_called_once()
            repository, passed_database, start = update.call_args.args
            self.assertEqual(repository.repo, root)
            self.assertIs(passed_database, database)
            self.assertIsNone(start)
            self.assertEqual(update.call_args.kwargs, {"pull": True})
            filter_commits.assert_not_called()
            self.assertIn("Added 7 commits; 107 total", result.output)
            self.assertIn("a" * 40, result.output)

    def test_bootstrap_date_and_no_pull_are_forwarded(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database_path = root / "all_commits.sqlite"
            database_path.touch()
            date = datetime(2026, 1, 1, tzinfo=UTC)
            outcome = UpdateResult(
                added_commits=0, total_commits=100, tip_commit="b" * 40, start_date=date
            )
            with (
                patch("kpatch.cli.GitDb") as database,
                patch("kpatch.cli.update_to_db", return_value=outcome) as update,
            ):
                result = CliRunner().invoke(
                    app,
                    [
                        "update", "--repo", str(root), "--db", str(database_path),
                        "--start", "01-01-2026", "--no-pull",
                    ],
                )

            self.assertEqual(result.exit_code, 0, result.output)
            self.assertEqual(update.call_args.args[2], date)
            self.assertIs(update.call_args.args[1], database.return_value)
            self.assertEqual(update.call_args.kwargs, {"pull": False})
            self.assertIn("Added 0 commits; 100 total", result.output)

    def test_invalid_date_fails_before_opening_database_or_pulling(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database_path = root / "all_commits.sqlite"
            database_path.touch()
            with (
                patch("kpatch.cli.GitDb") as database,
                patch("kpatch.cli.update_to_db") as update,
            ):
                result = CliRunner().invoke(
                    app,
                    [
                        "update", "--repo", str(root), "--db", str(database_path),
                        "--start", "not-a-date",
                    ],
                )

            self.assertEqual(result.exit_code, 1)
            self.assertIn("Update failed", result.output)
            database.assert_not_called()
            update.assert_not_called()

    def test_missing_database_is_not_silently_created(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database_path = root / "all_commits.sqlite"
            with patch("kpatch.cli.update_to_db") as update:
                result = CliRunner().invoke(
                    app, ["update", "--repo", str(root), "--db", str(database_path)]
                )

            self.assertEqual(result.exit_code, 2)
            self.assertFalse(database_path.exists())
            update.assert_not_called()

    def test_source_validation_and_git_failures_have_nonzero_exit(self) -> None:
        failures = [
            ValueError("Only complete unfiltered history can be updated"),
            RuntimeError("Update checkpoint is invalid"),
            sqlite3.OperationalError("database is locked"),
            OSError("scratch directory is full"),
            subprocess.CalledProcessError(1, ["git", "pull", "--ff-only"]),
        ]
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database_path = root / "all_commits.sqlite"
            database_path.touch()
            for failure in failures:
                with (
                    self.subTest(failure=failure),
                    patch("kpatch.cli.GitDb"),
                    patch("kpatch.cli.update_to_db", side_effect=failure),
                ):
                    result = CliRunner().invoke(
                        app,
                        ["update", "--repo", str(root), "--db", str(database_path)],
                    )

                    self.assertEqual(result.exit_code, 1)
                    self.assertIn("Update failed", result.output)


if __name__ == "__main__":
    unittest.main()
