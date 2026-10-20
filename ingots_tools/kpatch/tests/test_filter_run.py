from contextlib import redirect_stdout
from datetime import UTC, datetime
from io import StringIO
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from kpatch.filter import (
    ConfigFilter,
    FilterContext,
    FilteredCommit,
    FilterPipeline,
    KernelConfig,
    MergeCommitFilter,
    RunFilterArgs,
    StreamingCommitFilter,
    run_filter,
)
from kpatch.git import CommitParent, GitCommit, GitDb, GitRepo, HistoryKind


class MemoryRepo(GitRepo):
    def __init__(self) -> None:
        pass

    def read_file(self, commit: str, path: str) -> bytes:
        raise FileNotFoundError(path)


def make_commit(commit_id: str) -> GitCommit:
    date = datetime(2026, 7, 1, tzinfo=UTC)
    patch_text = (
        "diff --git a/example.c b/example.c\n"
        "--- a/example.c\n+++ b/example.c\n"
        "@@ -1 +1 @@\n-old\n+new\n"
    )
    return GitCommit(commit_id, "", "", date, date, (CommitParent("outside", patch_text),), "")


class FailingFilter(StreamingCommitFilter):
    name = "Failure fixture"

    def filter_mutable_commit(
        self, commit: FilteredCommit, context: FilterContext
    ) -> FilteredCommit | None:
        if commit.original.commit_id == "second":
            raise RuntimeError("writer input failed")
        return commit


class StreamingFilterRunTests(unittest.TestCase):
    def test_run_uses_streaming_writer_and_preserves_input_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = GitDb(root / "source.sqlite")
            one, two, merge = (make_commit(name) for name in ("one", "two", "merge"))
            merge.parents += (CommitParent("topic", ""),)
            source.store_commits([one, two, merge], HistoryKind.COMPLETE)
            destination = root / "destination.sqlite"
            pipeline = FilterPipeline([MergeCommitFilter()])
            output = StringIO()

            with (
                patch("kpatch.filter._path_for_db_name", return_value=destination),
                patch("kpatch.git._path_for_db_name", return_value=destination),
                patch.object(pipeline, "filter_commits", side_effect=AssertionError("batch API")),
                redirect_stdout(output),
            ):
                run_filter(RunFilterArgs(MemoryRepo(), source, "destination"), pipeline, show_progress=False)

            self.assertEqual(
                {commit.commit_id for commit in GitDb(destination).commits_between()},
                {"one", "two"},
            )
            self.assertEqual(len(source.commits_between(include_merges=True)), 3)
            self.assertEqual(source.history_kind, HistoryKind.COMPLETE)
            self.assertIn("Filtered commit count: 2", output.getvalue())
            self.assertEqual(GitDb(destination).history_kind, HistoryKind.SPARSE)

    def test_destination_must_not_alias_source_even_before_loading(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = GitDb(Path(directory) / "source.sqlite")
            source.store_commits([make_commit("source")], HistoryKind.COMPLETE)
            with (
                patch("kpatch.filter._path_for_db_name", return_value=source.db),
                patch.object(source, "load_lazy_commits", side_effect=AssertionError("loaded")),
                self.assertRaisesRegex(ValueError, "destination different"),
            ):
                run_filter(
                    RunFilterArgs(MemoryRepo(), source, "alias"),
                    MergeCommitFilter(),
                    show_progress=False,
                )
            self.assertEqual(len(source.commits_between()), 1)

    def test_hardlinked_destination_is_rejected_before_loading(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = GitDb(root / "source.sqlite")
            source.store_commits([make_commit("source")], HistoryKind.COMPLETE)
            alias = root / "hardlink.sqlite"
            os.link(source.db, alias)
            self.assertNotEqual(source.db.resolve(), alias.resolve())
            with (
                patch("kpatch.filter._path_for_db_name", return_value=alias),
                patch.object(source, "load_lazy_commits", side_effect=AssertionError("loaded")),
                self.assertRaisesRegex(ValueError, "destination different"),
            ):
                run_filter(
                    RunFilterArgs(MemoryRepo(), source, "hardlink"),
                    MergeCommitFilter(),
                    show_progress=False,
                )
            self.assertEqual(len(source.commits_between()), 1)

    def test_invalid_history_does_not_create_or_clear_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = GitDb(root / "source.sqlite")
            source.store_commits([make_commit("c")], HistoryKind.SPARSE)
            destination = root / "destination.sqlite"
            with (
                patch("kpatch.filter._path_for_db_name", return_value=destination),
                patch("kpatch.filter.save_commits_to_db") as save,
                self.assertRaisesRegex(ValueError, "complete history"),
            ):
                run_filter(
                    RunFilterArgs(MemoryRepo(), source, "destination"),
                    ConfigFilter(KernelConfig("")),
                    show_progress=False,
                )
            save.assert_not_called()
            self.assertFalse(destination.exists())

    def test_streaming_failure_rolls_back_previous_destination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = GitDb(root / "source.sqlite")
            # Query order is descending insertion order when timestamps tie.
            source.store_commits(
                [make_commit("second"), make_commit("first")], HistoryKind.COMPLETE
            )
            destination = root / "destination.sqlite"
            output_db = GitDb(destination)
            stale = make_commit("stale")
            output_db.store_commits([stale], HistoryKind.SPARSE)
            output = StringIO()
            with (
                patch("kpatch.filter._path_for_db_name", return_value=destination),
                patch("kpatch.git._path_for_db_name", return_value=destination),
                redirect_stdout(output),
                self.assertRaisesRegex(RuntimeError, "writer input failed"),
            ):
                run_filter(
                    RunFilterArgs(MemoryRepo(), source, "destination"),
                    FilterPipeline([FailingFilter()]),
                    show_progress=False,
                )
            self.assertEqual(output_db.commits_between(), [stale])
            self.assertNotIn("Saved", output.getvalue())
            self.assertNotIn("Filtered commit count", output.getvalue())
            self.assertEqual(len(source.commits_between()), 2)


if __name__ == "__main__":
    unittest.main()
