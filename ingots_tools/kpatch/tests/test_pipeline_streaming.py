from collections.abc import Generator, Iterable
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from kpatch.diff import Diff
from kpatch.filter import (
    CommitFilter,
    ConfigFilter,
    CountFilter,
    FileFilter,
    FilterContext,
    FilteredCommit,
    FilterPipeline,
    IfdefFilter,
    KernelConfig,
    MergeCommitFilter,
    ScoreFilter,
    WhitespaceFilter,
)
from kpatch.filter.base import (
    StreamingCommitFilter,
    filter_progress,
    repository_file_reader,
)
from kpatch.filter.repository_file import RepositoryFileReader
from kpatch.git import CommitParent, GitCommit, GitRepo, StructuredCommits


def make_commit(commit_id: str, paths: tuple[str, ...] = ("drivers/keep.c",)) -> GitCommit:
    date = datetime(2024, 1, 1, tzinfo=UTC)
    diff = "\n".join(
        f"diff --git a/{path} b/{path}\n"
        f"--- a/{path}\n"
        f"+++ b/{path}\n"
        "@@ -1 +1 @@\n"
        "-int old_value;\n"
        "+int new_value;\n"
        for path in paths
    )
    return GitCommit(commit_id, "", "", date, date, (CommitParent("parent", diff),), "")


class TrackingFilter(StreamingCommitFilter):
    name = "Tracking commits"

    def __init__(self) -> None:
        self.seen: list[FilteredCommit] = []

    def filter_mutable_commit(
        self, commit: FilteredCommit, context: FilterContext
    ) -> FilteredCommit | None:
        self.seen.append(commit)
        return commit


class ReplaceFilter(StreamingCommitFilter):
    name = "Replacing commits"

    def filter_mutable_commit(
        self, commit: FilteredCommit, context: FilterContext
    ) -> FilteredCommit | None:
        if commit.original.commit_id == "reject":
            return None
        replacement = FilteredCommit.from_commit(commit.original)
        replacement.diff.files = replacement.diff.files[-1:]
        return replacement


class ReverseBatchFilter(CommitFilter):
    name = "Reversing collection"

    def __init__(self) -> None:
        self.batch_sizes: list[int] = []

    def filter_mutable_commits(
        self,
        commits: list[FilteredCommit],
        context: FilterContext,
        show_progress: bool = True,
    ) -> list[FilteredCommit]:
        self.batch_sizes.append(len(commits))
        return list(reversed(commits))


class ResourceFilter(StreamingCommitFilter):
    name = "Holding spool"

    def __init__(self, resources: list[Path]) -> None:
        self.resources = resources

    def iter_filter_mutable_commits(
        self,
        commits: Iterable[FilteredCommit],
        context: FilterContext,
        show_progress: bool = True,
        *,
        total: int | None = None,
    ) -> Generator[FilteredCommit, None, None]:
        with tempfile.TemporaryDirectory() as directory:
            self.resources.append(Path(directory))
            yield from super().iter_filter_mutable_commits(
                commits, context, show_progress=show_progress, total=total
            )


class FailingFilter(StreamingCommitFilter):
    name = "Failing filter"

    def filter_mutable_commit(
        self, commit: FilteredCommit, context: FilterContext
    ) -> FilteredCommit | None:
        raise RuntimeError("stage failed")


class MemoryGitRepo(GitRepo):
    def __init__(self) -> None:
        pass

    def read_file(self, commit: str, path: str) -> bytes:
        return b"int old_value;\n" if commit == "parent" else b"int new_value;\n"


class PipelineStreamingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = FilterContext(MemoryGitRepo())

    def test_first_yield_consumes_and_materializes_only_one_commit(self) -> None:
        pulled: list[str] = []
        first = TrackingFilter()
        second = TrackingFilter()

        def source() -> Generator[GitCommit, None, None]:
            for index in range(100):
                commit = make_commit(str(index))
                pulled.append(commit.commit_id)
                yield commit

        pipeline = FilterPipeline([first, FilterPipeline([second])])
        with (
            patch.object(Diff, "parse", wraps=Diff.parse) as parse,
            closing(pipeline.iter_filter_commits(source(), self.context, False)) as stream,
        ):
            self.assertEqual(pulled, [])
            result = next(stream)
            self.assertEqual(result.commit_id, "0")
            self.assertEqual(pulled, ["0"])
            self.assertEqual(parse.call_count, 1)
            self.assertIs(first.seen[0], second.seen[0])
            self.assertIsNot(result, first.seen[0].original)

    def test_rejections_replacements_and_original_diffs_are_preserved(self) -> None:
        rejected = make_commit("reject")
        kept = make_commit("keep", ("drivers/drop.c", "drivers/keep.c"))
        original_patch = kept.diff_str
        seen = TrackingFilter()
        pipeline = FilterPipeline([ReplaceFilter(), seen])

        results = list(pipeline.iter_filter_commits(iter([rejected, kept]), self.context, False))

        self.assertEqual([commit.commit_id for commit in results], ["keep"])
        self.assertEqual([file.file for file in results[0].diff.files], ["drivers/keep.c"])
        self.assertEqual([file.file for file in seen.seen[0].diff.files], ["drivers/keep.c"])
        self.assertEqual(kept.diff_str, original_patch)
        self.assertNotIn("diff", vars(kept.parents[0]))
        self.assertNotIn("diff", vars(rejected.parents[0]))

    def test_nested_count_and_custom_batch_barriers_preserve_list_semantics(self) -> None:
        commits = [make_commit(str(index)) for index in range(12)]
        for index, commit in enumerate(commits):
            commit.score = index / 12
        commits[4].parents += (CommitParent("topic", ""),)
        expected = commits
        for commit_filter in [MergeCommitFilter(), ScoreFilter(0.2), CountFilter(4, seed=13)]:
            expected = commit_filter.filter_commits(expected, self.context, False)
        expected = list(reversed(expected))

        tracking = TrackingFilter()
        batch = ReverseBatchFilter()
        pipeline = FilterPipeline(
            [
                MergeCommitFilter(),
                FilterPipeline([ScoreFilter(0.2), CountFilter(4, seed=13)]),
                batch,
                tracking,
            ]
        )
        with closing(pipeline.iter_filter_commits(iter(commits), self.context, False)) as stream:
            first = next(stream)
            self.assertEqual(batch.batch_sizes, [4])
            self.assertEqual(len(tracking.seen), 1)
            result = [first, *stream]

        self.assertEqual(result, expected)
        self.assertEqual(pipeline.filter_commits(commits, self.context, False), expected)

    def test_legacy_single_commit_filter_remains_a_collection_barrier(self) -> None:
        class LegacyFilter(CommitFilter):
            name = "Legacy single commit filter"

        pulled: list[int] = []

        def source() -> Generator[GitCommit, None, None]:
            for index in range(5):
                pulled.append(index)
                yield make_commit(str(index))

        with closing(LegacyFilter().iter_filter_commits(source(), self.context, False)) as stream:
            self.assertEqual(next(stream).commit_id, "0")
            self.assertEqual(pulled, list(range(5)))

    def test_empty_pipeline_and_unknown_progress_total(self) -> None:
        commits = [make_commit("one"), make_commit("two")]
        for show_progress in (False, True):
            self.assertEqual(
                list(FilterPipeline([]).iter_filter_commits(iter(commits), self.context, show_progress)),
                commits,
            )
            self.assertEqual(
                list(MergeCommitFilter().iter_filter_commits(iter(commits), self.context, show_progress)),
                commits,
            )
        with filter_progress("Unknown total", None, False) as progress:
            task = progress.add_task("Unknown total", total=None)
            progress.advance(task)

    def test_complete_history_is_validated_before_consuming_input(self) -> None:
        class CompleteHistoryFilter(StreamingCommitFilter):
            name = "Complete history filter"

            @property
            def requires_complete_history(self) -> bool:
                return True

        pulled: list[str] = []

        def source() -> Generator[GitCommit, None, None]:
            pulled.append("read")
            yield make_commit("one")

        pipeline = FilterPipeline([FilterPipeline([CompleteHistoryFilter()])])
        with self.assertRaisesRegex(ValueError, "complete history"):
            next(pipeline.iter_filter_commits(source(), self.context, False))
        self.assertEqual(pulled, [])

    def test_file_stats_reset_for_each_stream(self) -> None:
        file_filter = FileFilter(["drivers"], ["c"])
        commits = [make_commit("one"), make_commit("two")]
        with closing(file_filter.iter_filter_commits(iter(commits), self.context, False)) as stream:
            next(stream)
            self.assertEqual(file_filter.stats().paths, {"drivers": 1})
        self.assertEqual(file_filter.filter_commits([], self.context, False), [])
        self.assertEqual(file_filter.stats().paths, {"drivers": 0})
        file_filter.filter_mutable_commits([FilteredCommit.from_commit(commits[0])], self.context, False)
        self.assertEqual(file_filter.stats().paths, {"drivers": 1})

    def test_early_close_releases_all_nested_readers_and_spools(self) -> None:
        resources: list[Path] = []
        ifdef_filter = IfdefFilter(KernelConfig(""))
        whitespace_filter = WhitespaceFilter()
        pipeline = FilterPipeline(
            [ResourceFilter(resources), FilterPipeline([ifdef_filter, whitespace_filter])]
        )
        with patch.object(RepositoryFileReader, "close", autospec=True) as close_reader:
            stream = pipeline.iter_filter_commits(iter([make_commit("one"), make_commit("two")]), self.context, False)
            next(stream)
            self.assertEqual(close_reader.call_count, 0)
            self.assertTrue(resources[0].exists())
            self.assertIsNotNone(ifdef_filter._read_file)
            self.assertIsNotNone(whitespace_filter._read_file)
            self.assertEqual(ifdef_filter._read_file, whitespace_filter._read_file)
            stream.close()
            self.assertEqual(close_reader.call_count, 1)

        self.assertFalse(resources[0].exists())
        self.assertIsNone(ifdef_filter._read_file)
        self.assertIsNone(whitespace_filter._read_file)

    def test_stage_exception_releases_upstream_resources(self) -> None:
        resources: list[Path] = []
        ifdef_filter = IfdefFilter(KernelConfig(""))
        whitespace_filter = WhitespaceFilter()
        pipeline = FilterPipeline(
            [
                ResourceFilter(resources),
                FilterPipeline([ifdef_filter, whitespace_filter]),
                FailingFilter(),
            ]
        )
        with patch.object(RepositoryFileReader, "close", autospec=True) as close_reader:
            with self.assertRaisesRegex(RuntimeError, "stage failed"):
                list(pipeline.iter_filter_commits(iter([make_commit("one")]), self.context, False))
            self.assertEqual(close_reader.call_count, 1)

        self.assertFalse(resources[0].exists())
        self.assertIsNone(ifdef_filter._read_file)
        self.assertIsNone(whitespace_filter._read_file)

    def test_nested_and_batch_stages_share_one_reader_and_context_data(self) -> None:
        contexts: list[FilterContext] = []

        class CaptureFilter(StreamingCommitFilter):
            name = "Capturing stage context"

            def filter_mutable_commit(
                self, commit: FilteredCommit, context: FilterContext
            ) -> FilteredCommit | None:
                contexts.append(context)
                return commit

        class CaptureBatchFilter(CommitFilter):
            name = "Capturing batch context"

            def filter_mutable_commits(
                self,
                commits: list[FilteredCommit],
                context: FilterContext,
                show_progress: bool = True,
            ) -> list[FilteredCommit]:
                contexts.append(context)
                return commits

        pipeline = FilterPipeline(
            [
                CaptureFilter(),
                CaptureBatchFilter(),
                FilterPipeline(
                    [IfdefFilter(KernelConfig("")), WhitespaceFilter(), CaptureFilter()]
                ),
            ]
        )
        with patch("kpatch.filter.base.RepositoryFileReader", wraps=RepositoryFileReader) as create_reader:
            pipeline.filter_commits([make_commit("one")], self.context, False)
            create_reader.assert_called_once_with(self.context.repo)

        self.assertEqual(len(contexts), 3)
        self.assertIsNotNone(contexts[0].file_reader)
        for context in contexts:
            self.assertIs(context.repo, self.context.repo)
            self.assertIs(context.commits, self.context.commits)
            self.assertIs(context.structured_commits, self.context.structured_commits)
            self.assertIs(context.file_reader, contexts[0].file_reader)
        self.assertIsNone(self.context.file_reader)

    def test_config_preparation_and_streaming_filters_share_reader_until_close(self) -> None:
        class BuildRepo(MemoryGitRepo):
            def read_file(self, commit: str, path: str) -> bytes:
                if path == "drivers/Makefile":
                    return b"obj-y += keep.o\n"
                if path.endswith(".c"):
                    return super().read_file(commit, path)
                raise FileNotFoundError(path)

        commit = make_commit("one")
        context = FilterContext(BuildRepo(), StructuredCommits.from_commits([commit]), [commit])
        config_filter = ConfigFilter(KernelConfig(""))
        ifdef_filter = IfdefFilter(KernelConfig(""))
        whitespace_filter = WhitespaceFilter()
        pipeline = FilterPipeline(
            [config_filter, FilterPipeline([ifdef_filter, whitespace_filter])]
        )
        with (
            patch("kpatch.filter.base.RepositoryFileReader", wraps=RepositoryFileReader) as create_reader,
            patch.object(RepositoryFileReader, "close", autospec=True) as close_reader,
        ):
            stream = pipeline.iter_filter_commits([commit], context, False)
            self.assertEqual(next(stream).commit_id, "one")
            create_reader.assert_called_once_with(context.repo)
            close_reader.assert_not_called()
            store = config_filter._store
            assert store is not None
            spool_path = store.path
            self.assertTrue(spool_path.exists())
            self.assertEqual(ifdef_filter._read_file, whitespace_filter._read_file)
            stream.close()
            self.assertEqual(close_reader.call_count, 1)

        self.assertFalse(spool_path.parent.exists())
        self.assertIsNone(config_filter._store)
        self.assertIsNone(ifdef_filter._read_file)
        self.assertIsNone(whitespace_filter._read_file)

    def test_borrowed_reader_is_not_closed_on_success_or_error(self) -> None:
        with patch.object(RepositoryFileReader, "close", autospec=True) as close_reader:
            reader = RepositoryFileReader(self.context.repo)
            context = replace(self.context, file_reader=reader)
            with repository_file_reader(context) as borrowed:
                self.assertIs(borrowed, reader)
            with self.assertRaisesRegex(ValueError, "borrowed failure"):
                with repository_file_reader(context):
                    raise ValueError("borrowed failure")

            FilterPipeline([IfdefFilter(KernelConfig("")), WhitespaceFilter()]).filter_commits(
                [make_commit("one")], context, False
            )
            with self.assertRaisesRegex(RuntimeError, "stage failed"):
                FilterPipeline([FailingFilter()]).filter_commits([make_commit("one")], context, False)
            close_reader.assert_not_called()
            reader.close()
            close_reader.assert_called_once_with(reader)

    def test_stage_iterators_close_before_the_shared_reader(self) -> None:
        resources: list[Path] = []
        ifdef_filter = IfdefFilter(KernelConfig(""))
        whitespace_filter = WhitespaceFilter()
        pipeline = FilterPipeline(
            [ResourceFilter(resources), FilterPipeline([ifdef_filter, whitespace_filter])]
        )

        def close_reader(reader: RepositoryFileReader) -> None:
            self.assertFalse(resources[0].exists())
            self.assertIsNone(ifdef_filter._read_file)
            self.assertIsNone(whitespace_filter._read_file)

        with patch.object(RepositoryFileReader, "close", autospec=True, side_effect=close_reader) as close:
            with closing(pipeline.iter_filter_commits([make_commit("one")], self.context, False)) as stream:
                next(stream)
            self.assertEqual(close.call_count, 1)

    def test_read_failure_retains_commit_and_closes_shared_reader(self) -> None:
        commit = make_commit("one")
        commit.parents[0].diff_str = commit.diff_str.replace("+int new_value;", "+int  old_value;")
        ifdef_filter = IfdefFilter(KernelConfig(""))
        whitespace_filter = WhitespaceFilter()
        pipeline = FilterPipeline([ifdef_filter, whitespace_filter])
        with (
            patch.object(RepositoryFileReader, "read_file", side_effect=OSError("read failed")) as read_file,
            patch.object(RepositoryFileReader, "close", autospec=True) as close_reader,
        ):
            result = pipeline.filter_commits([commit], self.context, False)
            self.assertEqual(result, [commit])
            self.assertGreater(read_file.call_count, 1)
            self.assertEqual(close_reader.call_count, 1)
        self.assertIsNone(ifdef_filter._read_file)
        self.assertIsNone(whitespace_filter._read_file)

    def test_standalone_filters_own_their_reader(self) -> None:
        for commit_filter in (IfdefFilter(KernelConfig("")), WhitespaceFilter()):
            with (
                patch("kpatch.filter.base.RepositoryFileReader", wraps=RepositoryFileReader) as create_reader,
                patch.object(RepositoryFileReader, "close", autospec=True) as close_reader,
            ):
                commit_filter.filter_commits([make_commit("one")], self.context, False)
                create_reader.assert_called_once_with(self.context.repo)
                self.assertEqual(close_reader.call_count, 1)

    def test_materialization_exception_closes_pipeline_in_list_wrapper(self) -> None:
        resources: list[Path] = []
        pipeline = FilterPipeline([ResourceFilter(resources)])
        with patch.object(FilteredCommit, "materialize", side_effect=ValueError("bad patch")):
            with self.assertRaisesRegex(ValueError, "bad patch"):
                pipeline.filter_commits([make_commit("one"), make_commit("two")], self.context, False)
        self.assertFalse(resources[0].exists())

    def test_list_convenience_wrapper_closes_mutable_iterator(self) -> None:
        resources: list[Path] = []
        commit_filter = ResourceFilter(resources)
        result = commit_filter.filter_mutable_commits(
            [FilteredCommit.from_commit(make_commit("one"))], self.context, False
        )
        self.assertEqual(len(result), 1)
        self.assertFalse(resources[0].exists())


if __name__ == "__main__":
    unittest.main()
