from contextlib import closing
from datetime import UTC, datetime, timedelta, timezone
import os
from pathlib import Path
import sqlite3
import subprocess
from tempfile import TemporaryDirectory
from typing import Generator
import unittest
from unittest.mock import patch

from kpatch.add import add_to_db
from kpatch.git import GitDb, GitRepo, HistoryKind, extract_to_db


START = datetime(2026, 1, 1, tzinfo=UTC)


def day(offset: int) -> datetime:
    return START + timedelta(days=offset)


def git(repository: Path, *args: str, date: datetime | None = None) -> str:
    environment = os.environ.copy()
    if date is not None:
        environment["GIT_AUTHOR_DATE"] = date.isoformat()
        environment["GIT_COMMITTER_DATE"] = date.isoformat()
    return subprocess.run(
        ["git", "-C", str(repository), *args], check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment,
    ).stdout.strip()


class FailingRepo(GitRepo):
    def _iter_git_records(
        self, args: list[str], revisions_file: Path | None = None,
    ) -> Generator[bytes, None, None]:
        with closing(super()._iter_git_records(args, revisions_file)) as records:
            yield next(records)
            raise subprocess.CalledProcessError(128, ["git", *args])


class AddTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.repository = self.directory / "repository"
        self.repository.mkdir()
        git(self.repository, "init", "-q", "-b", "main")
        git(self.repository, "config", "user.name", "Test Author")
        git(self.repository, "config", "user.email", "author@example.test")
        git(self.repository, "config", "commit.gpgSign", "false")
        self.ids: list[str] = []
        for offset in range(6):
            self.ids.append(self.commit(f"commit {offset}", day(offset)))
        self.repo = GitRepo(self.repository)
        self.db = GitDb(self.directory / "commits.sqlite")

    def commit(self, message: str, date: datetime) -> str:
        path = self.repository / "file.txt"
        previous = path.read_text() if path.exists() else ""
        _ = path.write_text(previous + message + "\n")
        git(self.repository, "add", "file.txt")
        git(self.repository, "commit", "-q", "-m", message, date=date)
        return git(self.repository, "rev-parse", "HEAD")

    def stored_ids(self) -> set[str]:
        return {item.commit_id for item in self.db.commits_between(include_merges=True)}

    def snapshot(self) -> tuple[str, ...]:
        with closing(sqlite3.connect(self.db.db)) as connection:
            return tuple(connection.iterdump())

    def extract_middle(self) -> None:
        extract_to_db(self.repo, self.db, day(2), day(4))

    def test_new_database_uses_half_open_dates(self) -> None:
        result = add_to_db(self.repo, self.db, day(1), day(4))
        self.assertEqual(self.stored_ids(), set(self.ids[1:4]))
        self.assertEqual(result.added_commits, 3)
        self.assertEqual(result.total_commits, 3)
        self.assertEqual(result.start_date, day(1))
        self.assertEqual(result.end_date, day(4))
        self.assertEqual(self.db.history_kind, HistoryKind.COMPLETE)

    def test_missing_start_includes_all_prior_history(self) -> None:
        result = add_to_db(self.repo, self.db, end=day(3))
        self.assertEqual(self.stored_ids(), set(self.ids[:3]))
        self.assertEqual(result.added_commits, 3)
        self.assertIsNone(result.start_date)
        self.assertEqual(result.end_date, day(3))

    def test_missing_end_reaches_head_without_pulling(self) -> None:
        with patch.object(self.repo, "pull_ff_only") as pull:
            result = add_to_db(self.repo, self.db, start=day(3))
        pull.assert_not_called()
        self.assertEqual(self.stored_ids(), set(self.ids[3:]))
        self.assertEqual(result.added_commits, 3)
        self.assertIsNone(result.end_date)

    def test_bounds_are_required(self) -> None:
        before = self.snapshot()
        with self.assertRaises(ValueError):
            add_to_db(self.repo, self.db)
        self.assertEqual(self.snapshot(), before)

    def test_invalid_and_naive_dates_leave_database_unchanged(self) -> None:
        self.extract_middle()
        before = self.snapshot()
        for start, end in (
            (day(3), day(2)), (day(2), day(2)),
            (day(1).replace(tzinfo=None), day(5)),
            (day(1), day(5).replace(tzinfo=None)),
        ):
            with self.subTest(start=start, end=end), self.assertRaises(ValueError):
                add_to_db(self.repo, self.db, start, end)
            self.assertEqual(self.snapshot(), before)

    def test_offset_aware_dates_select_utc_instants(self) -> None:
        offset = timezone(timedelta(hours=5, minutes=30))
        result = add_to_db(
            self.repo, self.db, day(1).astimezone(offset), day(4).astimezone(offset),
        )
        self.assertEqual(self.stored_ids(), set(self.ids[1:4]))
        self.assertEqual(result.start_date, day(1))
        self.assertEqual(result.end_date, day(4))

    def test_touching_ranges_extend_both_sides(self) -> None:
        self.extract_middle()
        backward = add_to_db(self.repo, self.db, day(0), day(2))
        self.assertEqual(backward.added_commits, 2)
        self.assertEqual(backward.total_commits, 4)
        self.assertEqual(backward.start_date, day(0))
        self.assertEqual(backward.end_date, day(4))
        forward = add_to_db(self.repo, self.db, day(4), day(6))
        self.assertEqual(forward.added_commits, 2)
        self.assertEqual(forward.total_commits, 6)
        self.assertEqual(forward.start_date, day(0))
        self.assertEqual(forward.end_date, day(6))
        self.assertEqual(self.stored_ids(), set(self.ids))

    def test_overlapping_and_contained_ranges_only_add_missing_commits(self) -> None:
        self.extract_middle()
        result = add_to_db(self.repo, self.db, day(1), day(5))
        self.assertEqual(result.added_commits, 2)
        self.assertEqual(result.total_commits, 4)
        self.assertEqual(self.stored_ids(), set(self.ids[1:5]))
        before = self.snapshot()
        repeated = add_to_db(self.repo, self.db, day(2), day(4))
        self.assertEqual(repeated.added_commits, 0)
        self.assertEqual(repeated.total_commits, 4)
        self.assertEqual(repeated.start_date, day(1))
        self.assertEqual(repeated.end_date, day(5))
        self.assertEqual(self.snapshot(), before)

    def test_disjoint_ranges_are_rejected_without_changes(self) -> None:
        self.extract_middle()
        before = self.snapshot()
        for start, end in ((day(-1), day(1)), (day(5), day(7))):
            with self.subTest(start=start, end=end), self.assertRaises(ValueError):
                add_to_db(self.repo, self.db, start, end)
            self.assertEqual(self.snapshot(), before)

    def test_coverage_uses_extraction_bounds_not_commit_extrema(self) -> None:
        extract_to_db(self.repo, self.db, day(1), day(4) + timedelta(hours=12))
        result = add_to_db(self.repo, self.db, day(4) + timedelta(hours=12), day(6))
        self.assertEqual(result.added_commits, 1)
        self.assertEqual(self.stored_ids(), set(self.ids[1:]))

    def test_forward_flag_uses_stored_end_and_persists_union(self) -> None:
        self.extract_middle()
        result = add_to_db(self.repo, self.db, start_at_stored_end=True)
        self.assertEqual(result.added_commits, 2)
        self.assertEqual(result.start_date, day(2))
        self.assertIsNone(result.end_date)
        backward = add_to_db(self.repo, self.db, end_at_stored_start=True)
        self.assertEqual(backward.added_commits, 2)
        self.assertIsNone(backward.start_date)
        self.assertIsNone(backward.end_date)
        self.assertEqual(self.stored_ids(), set(self.ids))

    def test_backward_flag_uses_stored_start_and_explicit_start(self) -> None:
        self.extract_middle()
        result = add_to_db(self.repo, self.db, start=day(1), end_at_stored_start=True)
        self.assertEqual(result.added_commits, 1)
        self.assertEqual(result.start_date, day(1))
        self.assertEqual(result.end_date, day(4))
        self.assertEqual(self.stored_ids(), set(self.ids[1:4]))

    def test_forward_flag_accepts_explicit_end(self) -> None:
        self.extract_middle()
        result = add_to_db(self.repo, self.db, end=day(5), start_at_stored_end=True)
        self.assertEqual(result.added_commits, 1)
        self.assertEqual(result.end_date, day(5))
        self.assertEqual(self.stored_ids(), set(self.ids[2:5]))

    def test_flag_conflicts_are_rejected(self) -> None:
        self.extract_middle()
        before = self.snapshot()
        with self.assertRaises(ValueError):
            add_to_db(self.repo, self.db, start=day(1), start_at_stored_end=True)
        with self.assertRaises(ValueError):
            add_to_db(self.repo, self.db, end=day(5), end_at_stored_start=True)
        with self.assertRaises(ValueError):
            add_to_db(self.repo, self.db, start_at_stored_end=True, end_at_stored_start=True)
        self.assertEqual(self.snapshot(), before)

    def test_flags_require_nonempty_known_coverage(self) -> None:
        for forward in (False, True):
            with self.subTest(forward=forward), self.assertRaises(ValueError):
                add_to_db(
                    self.repo, self.db,
                    start_at_stored_end=forward, end_at_stored_start=not forward,
                )
        extract_to_db(self.repo, self.db, day(10), day(11))
        self.assertEqual(self.stored_ids(), set())
        with self.assertRaises(ValueError):
            add_to_db(self.repo, self.db, end_at_stored_start=True)

    def test_unknown_legacy_coverage_is_not_inferred_from_commit_dates(self) -> None:
        with closing(self.repo.iter_commits_between(day(2), day(4))) as commits:
            self.db.store_commits(commits, HistoryKind.COMPLETE)
        before = self.snapshot()
        with self.assertRaises(ValueError):
            add_to_db(self.repo, self.db, day(1), day(5))
        self.assertEqual(self.snapshot(), before)

    def test_sparse_and_unknown_history_are_rejected(self) -> None:
        for kind in (HistoryKind.SPARSE, HistoryKind.UNKNOWN):
            with self.subTest(kind=kind):
                db = GitDb(self.directory / f"{kind}.sqlite")
                with closing(self.repo.iter_commits_between(day(2), day(4))) as commits:
                    db.store_commits(commits, kind)
                with self.assertRaises(ValueError):
                    add_to_db(self.repo, db, day(1), day(5))

    def test_sync_state_supplies_coverage_for_backward_extension(self) -> None:
        extract_to_db(self.repo, self.db, day(2))
        result = add_to_db(self.repo, self.db, end_at_stored_start=True)
        self.assertEqual(result.added_commits, 2)
        self.assertIsNone(result.start_date)
        self.assertIsNone(result.end_date)
        self.assertEqual(self.stored_ids(), set(self.ids))

    def test_unbounded_end_forward_flag_includes_tied_and_new_tip_dates(self) -> None:
        extract_to_db(self.repo, self.db, day(2))
        tied = self.commit("tied with stored tip", day(5))
        later = self.commit("new tip", day(6))
        result = add_to_db(self.repo, self.db, start_at_stored_end=True)
        self.assertEqual(result.added_commits, 2)
        self.assertEqual(self.stored_ids(), set(self.ids[2:]) | {tied, later})
        self.assertEqual(result.start_date, day(2))
        self.assertIsNone(result.end_date)

    def test_unbounded_start_backward_flag_uses_existing_commit_boundary(self) -> None:
        extract_to_db(self.repo, self.db, end=day(4))
        result = add_to_db(self.repo, self.db, end_at_stored_start=True)
        self.assertEqual(result.added_commits, 0)
        self.assertEqual(self.stored_ids(), set(self.ids[:4]))
        self.assertIsNone(result.start_date)
        self.assertEqual(result.end_date, day(4))

    def test_existing_scores_ratings_and_patch_bytes_are_preserved(self) -> None:
        self.extract_middle()
        with closing(self.db._connect()) as connection, connection:
            connection.execute(
                "UPDATE commits SET score = ?, ratings_json = ? WHERE commit_id = ?",
                (0.9, '{ "retained" : 0.125 }', self.ids[2]),
            )
            connection.execute(
                "UPDATE commit_parents SET diff = ? WHERE commit_id = ?",
                ("retained patch\n\n", self.ids[2]),
            )
        original_rows = {
            line for line in self.snapshot()
            if line.startswith(('INSERT INTO "commits"', 'INSERT INTO "commit_parents"'))
        }
        result = add_to_db(self.repo, self.db, day(1), day(5))
        self.assertEqual(result.added_commits, 2)
        self.assertTrue(original_rows.issubset(set(self.snapshot())))

    def test_git_stream_failure_rolls_back_commits_and_coverage(self) -> None:
        self.extract_middle()
        before = self.snapshot()
        with self.assertRaises(subprocess.CalledProcessError):
            add_to_db(FailingRepo(self.repository), self.db, day(0), day(6))
        self.assertEqual(self.snapshot(), before)
        result = add_to_db(self.repo, self.db, start_at_stored_end=True)
        self.assertEqual(result.added_commits, 2)

    def test_write_failure_rolls_back_commits_and_metadata(self) -> None:
        self.extract_middle()
        with closing(self.db._connect()) as connection, connection:
            connection.execute(
                f"CREATE TRIGGER reject_second_new_commit BEFORE INSERT ON commits "
                f"WHEN NEW.commit_id = '{self.ids[0]}' BEGIN "
                "SELECT RAISE(ABORT, 'injected write failure'); END"
            )
        before = self.snapshot()
        with self.assertRaises(sqlite3.IntegrityError):
            add_to_db(self.repo, self.db, day(0), day(6))
        self.assertEqual(self.snapshot(), before)

    def test_late_merge_fills_previously_covered_dates_and_retains_merge_parents(self) -> None:
        self.extract_middle()
        git(self.repository, "checkout", "-q", "-b", "late", self.ids[0])
        _ = (self.repository / "late.txt").write_text("late historical change\n")
        git(self.repository, "add", "late.txt")
        git(self.repository, "commit", "-q", "-m", "late old commit", date=day(2))
        late = git(self.repository, "rev-parse", "HEAD")
        git(self.repository, "checkout", "-q", "main")
        git(self.repository, "merge", "--no-ff", "-m", "merge late", "late", date=day(7))
        tip = git(self.repository, "rev-parse", "HEAD")
        result = add_to_db(self.repo, self.db, day(4), day(8))
        self.assertEqual(result.added_commits, 4)
        self.assertEqual(result.total_commits, 6)
        self.assertEqual(self.stored_ids(), set(self.ids[2:]) | {late, tip})
        merged = next(item for item in self.db.commits_between(include_merges=True) if item.commit_id == tip)
        self.assertEqual(tuple(parent.commit_id for parent in merged.parents), (self.ids[5], late))
        self.assertIn("late historical change", merged.diff_str)

    def test_clock_skewed_parent_does_not_hide_in_range_child(self) -> None:
        future = self.commit("future parent", day(20))
        skewed = self.commit("earlier child", day(3))
        result = add_to_db(self.repo, self.db, day(2), day(4))
        self.assertEqual(result.added_commits, 3)
        self.assertEqual(self.stored_ids(), {self.ids[2], self.ids[3], skewed})
        self.assertNotIn(future, self.stored_ids())

    def test_dates_use_committer_time_not_author_time(self) -> None:
        author_date = day(1)
        committer_date = day(7)
        environment = os.environ.copy()
        environment["GIT_AUTHOR_DATE"] = author_date.isoformat()
        environment["GIT_COMMITTER_DATE"] = committer_date.isoformat()
        subprocess.run(
            ["git", "-C", str(self.repository), "commit", "--allow-empty", "-q", "-m", "different dates"],
            env=environment, check=True,
        )
        tip = git(self.repository, "rev-parse", "HEAD")
        add_to_db(self.repo, self.db, day(6), day(8))
        self.assertEqual(self.stored_ids(), {tip})


if __name__ == "__main__":
    unittest.main()
