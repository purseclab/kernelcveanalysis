from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import os
from pathlib import Path
import sqlite3
import subprocess
from tempfile import TemporaryDirectory
from threading import Event
from typing import BinaryIO, Generator, Literal
import unittest
from unittest.mock import patch

from kpatch.git import GitCommit, GitDb, GitRepo, HistoryKind, extract_to_db
from kpatch.update import update_to_db
from kpatch.update_state import (
    UPDATE_STATE_KEY,
    UpdateState,
    read_extraction_bounds,
    read_update_state,
)


START = datetime(2026, 1, 1, tzinfo=UTC)
ROOT_DATE = START - timedelta(days=1)
TIP_DATE = START + timedelta(days=9)


def git(repository: Path, *args: str, date: datetime | None = None) -> str:
    environment = os.environ.copy()
    if date is not None:
        environment["GIT_AUTHOR_DATE"] = date.isoformat()
        environment["GIT_COMMITTER_DATE"] = date.isoformat()
    return subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
    ).stdout.strip()


def configure(repository: Path) -> None:
    git(repository, "config", "user.name", "Test Author")
    git(repository, "config", "user.email", "author@example.test")
    git(repository, "config", "commit.gpgSign", "false")


def commit(repository: Path, message: str, date: datetime, filename: str) -> str:
    path = repository / filename
    previous = path.read_text() if path.exists() else ""
    _ = path.write_text(previous + message + "\n")
    git(repository, "add", filename)
    git(repository, "commit", "-q", "-m", message, date=date)
    return git(repository, "rev-parse", "HEAD")


class RecordingRepo(GitRepo):
    def __init__(self, repository: Path) -> None:
        super().__init__(repository)
        self.log_args: list[str] = []
        self.exclusions: list[str] = []
        self.revisions_path: Path | None = None
        self.streamed_ids: list[str] = []

    def _iter_git_records(
        self, args: list[str], revisions_file: Path | None = None,
    ) -> Generator[bytes, None, None]:
        self.log_args = args
        if revisions_file is not None:
            self.revisions_path = revisions_file
            self.exclusions = revisions_file.read_text().splitlines()
        yield from super()._iter_git_records(args, revisions_file)

    def iter_commits_from_revision(
        self, revision: str, start: datetime | None = None, *,
        revisions_file: Path | None = None,
    ) -> Generator[GitCommit, None, None]:
        with closing(super().iter_commits_from_revision(
            revision, start, revisions_file=revisions_file,
        )) as commits:
            for extracted in commits:
                self.streamed_ids.append(extracted.commit_id)
                yield extracted


class FailingRepo(GitRepo):
    def __init__(self, repository: Path, failure: Literal["parse", "git"]) -> None:
        super().__init__(repository)
        self.failure = failure

    def _iter_git_records(
        self, args: list[str], revisions_file: Path | None = None,
    ) -> Generator[bytes, None, None]:
        with closing(super()._iter_git_records(args, revisions_file)) as records:
            yield next(records)
            if self.failure == "parse":
                yield b"malformed second record"
            else:
                raise subprocess.CalledProcessError(128, ["git", *args])


class IncrementalUpdateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.repository = self.directory / "repository"
        self.repository.mkdir()
        git(self.repository, "init", "-q", "-b", "main")
        configure(self.repository)
        self.root = commit(self.repository, "root", ROOT_DATE, "root.txt")
        self.initial_tip = commit(self.repository, "main", TIP_DATE, "main.txt")
        self.repo = GitRepo(self.repository)
        self.db = GitDb(self.directory / "commits.sqlite")

    def legacy_extract(self) -> None:
        with closing(self.repo.iter_commits_between(START, include_merges=True)) as commits:
            self.db.store_commits(commits, HistoryKind.COMPLETE)

    def state(self) -> UpdateState | None:
        with closing(self.db._connect()) as connection:
            return read_update_state(connection)

    def snapshot(self) -> tuple[str, ...]:
        with closing(sqlite3.connect(self.db.db)) as connection:
            return tuple(connection.iterdump())

    def stored_lines(self) -> set[str]:
        return {
            line for line in self.snapshot()
            if line.startswith(('INSERT INTO "commits"', 'INSERT INTO "commit_parents"'))
        }

    def merge(self, branch: str, date: datetime = TIP_DATE) -> str:
        git(self.repository, "merge", "--no-ff", "-m", f"merge {branch}", branch, date=date)
        return self.repo.resolve_head()

    def remote_clone(self) -> Path:
        remote = self.directory / "remote.git"
        remote.mkdir()
        git(remote, "init", "--bare", "-q", "--initial-branch=main")
        git(self.repository, "remote", "add", "origin", str(remote))
        git(self.repository, "push", "-q", "-u", "origin", "main")
        clone = self.directory / "remote-clone"
        git(self.directory, "clone", "-q", str(remote), str(clone))
        configure(clone)
        return clone

    def test_legacy_bootstrap_requires_actual_start_and_complete_history(self) -> None:
        self.legacy_extract()
        before = self.snapshot()
        with (
            patch.object(self.repo, "pull_ff_only") as pull,
            self.assertRaisesRegex(ValueError, "provide --start"),
        ):
            update_to_db(self.repo, self.db)
        pull.assert_not_called()
        self.assertEqual(self.snapshot(), before)
        self.assertIsNone(self.state())

        for kind in (HistoryKind.UNKNOWN, HistoryKind.SPARSE):
            with self.subTest(kind=kind):
                db = GitDb(self.directory / f"{kind}.sqlite")
                db.store_commits([], kind)
                with (
                    patch.object(self.repo, "pull_ff_only") as pull,
                    self.assertRaisesRegex(ValueError, "COMPLETE"),
                ):
                    update_to_db(self.repo, db, START)
                pull.assert_not_called()

    def test_bootstrap_excludes_every_existing_id_and_preserves_bytes(self) -> None:
        git(self.repository, "checkout", "-q", "-b", "first-topic", self.root)
        commit(self.repository, "first topic", START + timedelta(days=2), "first.txt")
        git(self.repository, "checkout", "-q", "main")
        first_merge = self.merge("first-topic")
        self.legacy_extract()
        with closing(self.db._connect()) as connection, connection:
            connection.execute(
                "UPDATE commits SET score = ?, ratings_json = ? WHERE commit_id = ?",
                (0.9, '{ "kept" : 0.125 }', first_merge),
            )
            connection.execute(
                "UPDATE commit_parents SET diff = ? WHERE commit_id = ? AND parent_index = 0",
                ("retained first-parent patch\n\n", first_merge),
            )
        previous_lines = self.stored_lines()
        existing_ids = {item.commit_id for item in self.db.commits_between(include_merges=True)}

        git(self.repository, "checkout", "-q", "-b", "late", self.root)
        late = commit(self.repository, "late old commit", START + timedelta(days=1), "late.txt")
        git(self.repository, "checkout", "-q", "main")
        tip = self.merge("late")
        recorded = RecordingRepo(self.repository)
        result = update_to_db(recorded, self.db, START, pull=False)

        self.assertEqual(result.added_commits, 2)
        self.assertEqual(result.total_commits, len(existing_ids) + 2)
        self.assertEqual(result.tip_commit, tip)
        self.assertEqual(result.start_date, START)
        self.assertEqual(set(recorded.exclusions), {f"^{sha}" for sha in existing_ids})
        self.assertIn("--stdin", recorded.log_args)
        self.assertFalse(set(recorded.exclusions).intersection(recorded.log_args))
        self.assertEqual(set(recorded.streamed_ids), {late, tip})
        self.assertIsNotNone(recorded.revisions_path)
        assert recorded.revisions_path is not None
        self.assertFalse(recorded.revisions_path.exists())
        self.assertTrue(previous_lines.issubset(self.stored_lines()))
        extracted = {item.commit_id: item for item in self.db.commits_between(include_merges=True)}
        self.assertEqual(tuple(parent.commit_id for parent in extracted[tip].parents), (first_merge, late))
        self.assertIn("late old commit", extracted[tip].diff_str)
        self.assertEqual(extracted[tip].parents[1].diff_str, "")
        self.assertNotIn(self.root, extracted)
        state = self.state()
        assert state is not None
        self.assertEqual(state.tip_commit, tip)
        self.assertEqual(state.repo_path, str(self.repository.resolve()))

    def test_checkpoint_range_includes_late_old_and_tied_dates_but_respects_start(self) -> None:
        extract_to_db(self.repo, self.db, START)
        git(self.repository, "checkout", "-q", "-b", "late", self.root)
        too_old = commit(self.repository, "before start", ROOT_DATE, "late.txt")
        older = commit(self.repository, "older than old tip", START + timedelta(days=1), "late.txt")
        tied = commit(self.repository, "tied with old tip", TIP_DATE, "late.txt")
        git(self.repository, "checkout", "-q", "main")
        tip = self.merge("late", TIP_DATE + timedelta(days=1))
        recorded = RecordingRepo(self.repository)

        result = update_to_db(recorded, self.db, pull=False)

        self.assertEqual(result.added_commits, 3)
        self.assertEqual(result.total_commits, 4)
        self.assertIn(f"{self.initial_tip}..{tip}", recorded.log_args)
        self.assertNotIn("--stdin", recorded.log_args)
        self.assertEqual(set(recorded.streamed_ids), {older, tied, tip})
        self.assertNotIn(too_old, {item.commit_id for item in self.db.commits_between(include_merges=True)})
        before = self.snapshot()
        noop = update_to_db(self.repo, self.db, pull=False)
        self.assertEqual(noop.added_commits, 0)
        self.assertEqual(noop.total_commits, 4)
        self.assertEqual(self.snapshot(), before)

    def test_unbounded_extraction_persists_pinned_provenance(self) -> None:
        count = extract_to_db(self.repo, self.db, START)
        self.assertEqual(count, 1)
        state = self.state()
        assert state is not None
        self.assertEqual(state.start_date, START)
        self.assertEqual(state.tip_commit, self.initial_tip)
        tip = commit(self.repository, "next", TIP_DATE, "main.txt")
        result = update_to_db(self.repo, self.db, pull=False)
        self.assertEqual(result.added_commits, 1)
        self.assertEqual(result.tip_commit, tip)

    def test_all_history_extraction_keeps_none_start(self) -> None:
        extract_to_db(self.repo, self.db)
        result = update_to_db(self.repo, self.db, pull=False)
        self.assertIsNone(result.start_date)
        self.assertEqual(result.total_commits, 2)
        with self.assertRaisesRegex(ValueError, "cannot change"):
            update_to_db(self.repo, self.db, START, pull=False)

    def test_bounded_extraction_rejects_bootstrap_even_with_clock_skew(self) -> None:
        future_parent = commit(self.repository, "future parent", TIP_DATE + timedelta(days=10), "main.txt")
        earlier_child = commit(self.repository, "earlier child", TIP_DATE + timedelta(days=1), "main.txt")
        end = TIP_DATE + timedelta(days=5)
        extract_to_db(self.repo, self.db, START, end)
        self.assertIsNone(self.state())
        extracted_ids = {item.commit_id for item in self.db.commits_between()}
        self.assertIn(earlier_child, extracted_ids)
        self.assertNotIn(future_parent, extracted_ids)
        before = self.snapshot()
        for start in (None, START):
            with (
                self.subTest(start=start),
                patch.object(self.repo, "pull_ff_only") as pull,
                self.assertRaisesRegex(ValueError, "capped"),
            ):
                update_to_db(self.repo, self.db, start)
            pull.assert_not_called()
            self.assertEqual(self.snapshot(), before)

    def test_bounded_clock_skew_marker_survives_noop_store(self) -> None:
        future_parent = commit(self.repository, "future parent", TIP_DATE + timedelta(days=10), "main.txt")
        earlier_child = commit(self.repository, "earlier child", TIP_DATE + timedelta(days=1), "main.txt")
        extract_to_db(self.repo, self.db, START, TIP_DATE + timedelta(days=5))
        self.db.store_commits([])
        extracted_ids = {item.commit_id for item in self.db.commits_between()}
        self.assertIn(earlier_child, extracted_ids)
        self.assertNotIn(future_parent, extracted_ids)
        before = self.snapshot()
        with (
            patch.object(self.repo, "pull_ff_only") as pull,
            self.assertRaisesRegex(ValueError, "capped"),
        ):
            update_to_db(self.repo, self.db, START)
        pull.assert_not_called()
        self.assertEqual(self.snapshot(), before)

    def test_nonempty_extraction_preserves_known_bounds(self) -> None:
        extract_to_db(self.repo, self.db, START, TIP_DATE + timedelta(days=1))
        with closing(self.db._connect()) as connection:
            bounds = read_extraction_bounds(connection)
        extract_to_db(self.repo, self.db, START)
        self.assertIsNone(self.state())
        with closing(self.db._connect()) as connection:
            self.assertEqual(read_extraction_bounds(connection), bounds)
        with (
            patch.object(self.repo, "pull_ff_only") as pull,
            self.assertRaisesRegex(ValueError, "capped"),
        ):
            update_to_db(self.repo, self.db, START)
        pull.assert_not_called()

    def test_empty_unbounded_extraction_can_clear_previous_bounds(self) -> None:
        extract_to_db(self.repo, self.db, START, START + timedelta(days=1))
        self.assertEqual(self.db.commits_between(), [])
        with closing(self.db._connect()) as connection:
            self.assertIsNotNone(read_extraction_bounds(connection))
        extract_to_db(self.repo, self.db, START)
        with closing(self.db._connect()) as connection:
            self.assertIsNone(read_extraction_bounds(connection))
        self.assertIsNotNone(self.state())
        self.assertEqual(update_to_db(self.repo, self.db, pull=False).added_commits, 0)

    def test_extracting_into_nonempty_database_does_not_claim_new_provenance(self) -> None:
        extract_to_db(self.repo, self.db, START)
        self.assertIsNotNone(self.state())
        extract_to_db(self.repo, self.db, START + timedelta(days=1))
        self.assertIsNone(self.state())
        with self.assertRaisesRegex(ValueError, "provide --start"):
            update_to_db(self.repo, self.db, pull=False)

    def test_bounded_marker_and_invalidation_roll_back_with_failed_writes(self) -> None:
        for operation in ("store", "replace"):
            with self.subTest(operation=operation):
                extract_to_db(self.repo, self.db, START, TIP_DATE + timedelta(days=1))
                before = self.snapshot()
                with self.assertRaises(ValueError):
                    extract_to_db(self.repo, self.db, START.replace(tzinfo=None))
                self.assertEqual(self.snapshot(), before)
                original = self.db.commits_between()[0]
                invalid = replace(original, ratings={"invalid": float("nan")})
                write = self.db.store_commits if operation == "store" else self.db.replace_commits
                with self.assertRaises(ValueError):
                    write([invalid])
                self.assertEqual(self.snapshot(), before)
                write([original])
                with closing(self.db._connect()) as connection:
                    bounds = read_extraction_bounds(connection)
                if operation == "store":
                    self.assertIsNotNone(bounds)
                else:
                    self.assertIsNone(bounds)

    def test_start_cannot_silently_change_and_naive_dates_are_rejected(self) -> None:
        extract_to_db(self.repo, self.db, START)
        before = self.snapshot()
        for start in (START + timedelta(days=1), START.replace(tzinfo=None)):
            with (
                self.subTest(start=start),
                patch.object(self.repo, "pull_ff_only") as pull,
                self.assertRaises(ValueError),
            ):
                update_to_db(self.repo, self.db, start)
            pull.assert_not_called()
            self.assertEqual(self.snapshot(), before)
        self.assertEqual(update_to_db(self.repo, self.db, START, pull=False).added_commits, 0)

    def test_rewind_divergence_and_wrong_repository_are_rejected(self) -> None:
        extract_to_db(self.repo, self.db, START)
        before = self.snapshot()
        git(self.repository, "checkout", "-q", "--detach", self.root)
        with self.assertRaisesRegex(ValueError, "not a fast-forward"):
            update_to_db(self.repo, self.db, pull=False)
        self.assertEqual(self.snapshot(), before)
        commit(self.repository, "divergent", TIP_DATE, "different.txt")
        with self.assertRaisesRegex(ValueError, "not a fast-forward"):
            update_to_db(self.repo, self.db, pull=False)
        self.assertEqual(self.snapshot(), before)

        unrelated = self.directory / "unrelated"
        unrelated.mkdir()
        git(unrelated, "init", "-q", "-b", "main")
        configure(unrelated)
        commit(unrelated, "unrelated root", TIP_DATE, "unrelated.txt")
        with self.assertRaisesRegex(ValueError, "unavailable in this repository"):
            update_to_db(GitRepo(unrelated), self.db, pull=False)
        self.assertEqual(self.snapshot(), before)

    def test_default_pull_fast_forwards_from_local_remote_before_pinning(self) -> None:
        clone = self.remote_clone()
        extract_to_db(self.repo, self.db, START)
        tip = commit(clone, "remote addition", TIP_DATE, "remote.txt")
        git(clone, "push", "-q", "origin", "main")
        with patch.object(self.repo, "_run_git", wraps=self.repo._run_git) as run:
            result = update_to_db(self.repo, self.db)
        self.assertEqual(run.call_args_list[0].args[0], ["pull", "--ff-only", "--no-stat"])
        self.assertEqual(result.tip_commit, tip)
        self.assertEqual(self.repo.resolve_head(), tip)
        self.assertEqual(result.added_commits, 1)

    def test_failed_ff_only_pull_leaves_rows_and_checkpoint_untouched(self) -> None:
        clone = self.remote_clone()
        extract_to_db(self.repo, self.db, START)
        before = self.snapshot()
        commit(clone, "remote divergence", TIP_DATE, "remote.txt")
        git(clone, "push", "-q", "origin", "main")
        local_tip = commit(self.repository, "local divergence", TIP_DATE, "local.txt")
        with self.assertRaises(subprocess.CalledProcessError):
            update_to_db(self.repo, self.db)
        self.assertEqual(self.repo.resolve_head(), local_tip)
        self.assertEqual(self.snapshot(), before)

    def test_parse_and_git_stream_errors_roll_back_appends_and_state(self) -> None:
        self.legacy_extract()
        commit(self.repository, "one", TIP_DATE, "main.txt")
        commit(self.repository, "two", TIP_DATE, "main.txt")
        for checkpointed in (False, True):
            if checkpointed:
                update_to_db(self.repo, self.db, START, pull=False)
                commit(self.repository, "three", TIP_DATE, "main.txt")
                commit(self.repository, "four", TIP_DATE, "main.txt")
            for failure in ("parse", "git"):
                with self.subTest(checkpointed=checkpointed, failure=failure):
                    before = self.snapshot()
                    error_type = ValueError if failure == "parse" else subprocess.CalledProcessError
                    with self.assertRaises(error_type):
                        update_to_db(FailingRepo(self.repository, failure), self.db, START, pull=False)
                    self.assertEqual(self.snapshot(), before)

    def test_normal_store_and_replace_invalidate_state_atomically(self) -> None:
        for operation in ("store", "replace"):
            with self.subTest(operation=operation):
                extract_to_db(self.repo, self.db, START)
                update_to_db(self.repo, self.db, START, pull=False)
                self.assertIsNotNone(self.state())
                original = self.db.commits_between(include_merges=True)[0]
                before = self.snapshot()
                invalid = replace(original, ratings={"invalid": float("nan")})
                write = self.db.store_commits if operation == "store" else self.db.replace_commits
                with self.assertRaises(ValueError):
                    write([invalid])
                self.assertEqual(self.snapshot(), before)
                write([original])
                self.assertIsNone(self.state())
                with self.assertRaisesRegex(ValueError, "provide --start"):
                    update_to_db(self.repo, self.db, pull=False)

    def test_invalid_persisted_state_is_not_silently_bootstrapped(self) -> None:
        self.legacy_extract()
        with closing(self.db._connect()) as connection, connection:
            connection.execute(
                "INSERT INTO database_metadata (key, value) VALUES (?, ?)",
                (UPDATE_STATE_KEY, '{"version":2,"tip_commit":"invalid"}'),
            )
        before = self.snapshot()
        with (
            patch.object(self.repo, "pull_ff_only") as pull,
            self.assertRaises(ValueError),
        ):
            update_to_db(self.repo, self.db, START)
        pull.assert_not_called()
        self.assertEqual(self.snapshot(), before)

    def test_concurrent_updates_serialize_and_read_checkpoint_inside_transaction(self) -> None:
        extract_to_db(self.repo, self.db, START)
        tip = commit(self.repository, "concurrent addition", TIP_DATE, "main.txt")
        entered = Event()
        release = Event()
        second_pinned = Event()
        transaction_reads: list[bool] = []

        class BlockingRepo(GitRepo):
            def iter_commits_from_revision(
                self, revision: str, start: datetime | None = None, *,
                revisions_file: Path | None = None,
            ) -> Generator[GitCommit, None, None]:
                entered.set()
                if not release.wait(5):
                    raise RuntimeError("test did not release updater")
                yield from super().iter_commits_from_revision(
                    revision, start, revisions_file=revisions_file,
                )

        class SecondRepo(GitRepo):
            def resolve_head(self) -> str:
                resolved = super().resolve_head()
                second_pinned.set()
                return resolved

        def checked_state(connection: sqlite3.Connection) -> UpdateState | None:
            transaction_reads.append(connection.in_transaction)
            return read_update_state(connection)

        with (
            patch("kpatch.update.read_update_state", side_effect=checked_state),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            first = executor.submit(update_to_db, BlockingRepo(self.repository), self.db, pull=False)
            self.assertTrue(entered.wait(5))
            second = executor.submit(update_to_db, SecondRepo(self.repository), self.db, pull=False)
            try:
                self.assertTrue(second_pinned.wait(5))
            finally:
                release.set()
            results = [first.result(timeout=10), second.result(timeout=10)]
        self.assertEqual(transaction_reads.count(True), 2)
        self.assertEqual(transaction_reads.count(False), 2)
        self.assertEqual(sorted(result.added_commits for result in results), [0, 1])
        self.assertTrue(all(result.tip_commit == tip for result in results))
        self.assertTrue(all(result.total_commits == 2 for result in results))

    def test_cancelling_patch_stream_reaps_git_and_closes_revision_file(self) -> None:
        for number in range(3):
            _ = (self.repository / "large.txt").write_text(str(number) * 200_000 + "\n")
            git(self.repository, "add", "large.txt")
            git(self.repository, "commit", "-q", "-m", f"large {number}", date=TIP_DATE)
        tip = self.repo.resolve_head()
        revisions_file = self.directory / "exclusions"
        _ = revisions_file.write_text(f"^{self.root}\n")
        processes: list[subprocess.Popen[bytes]] = []
        inputs: list[BinaryIO] = []
        real_popen = subprocess.Popen

        def capture(
            command: list[str], *, stdin: BinaryIO | None, stdout: int, stderr: BinaryIO,
        ) -> subprocess.Popen[bytes]:
            process = real_popen(command, stdin=stdin, stdout=stdout, stderr=stderr)
            processes.append(process)
            assert stdin is not None
            inputs.append(stdin)
            return process

        with patch("kpatch.git.subprocess.Popen", side_effect=capture):
            commits = self.repo.iter_commits_from_revision(tip, revisions_file=revisions_file)
            next(commits)
            commits.close()
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].returncode)
        assert processes[0].stdout is not None
        self.assertTrue(processes[0].stdout.closed)
        self.assertTrue(inputs[0].closed)


if __name__ == "__main__":
    unittest.main()
