import unittest
from datetime import UTC, datetime
from pathlib import Path
import tempfile

from kpatch.filter import (
    CommitFilter,
    ConfigFilter as CommitConfigFilter,
    ConfigValue,
    FileBuildModes,
    FileFilter,
    FilterContext,
    FilteredCommit,
    FilterPipeline,
    IfdefFilter,
    MergeCommitFilter,
    filter_commit_time_range,
)
from filter_helpers import filter_commits
from kpatch.filter.config_filter import KernelConfig
from kpatch.git import (
    CommitParent,
    GitCommit,
    GitDb,
    GitRepo,
    HistoryKind,
    StructuredCommits,
)


class FileFilterTests(unittest.TestCase):
    @staticmethod
    def make_commit(commit_id: str, paths: list[str]) -> GitCommit:
        patch = "\n".join(
            f"diff --git a/{path} b/{path}\n"
            f"index 1234567..89abcde 100644\n"
            f"--- a/{path}\n"
            f"+++ b/{path}\n"
            "@@ -1 +1 @@\n"
            "-old\n"
            "+new"
            for path in paths
        )
        date = datetime(2024, 1, 1, tzinfo=UTC)
        return GitCommit(
            commit_id,
            "",
            "",
            date,
            date,
            (CommitParent("", patch),),
            "",
        )

    def test_matches_path_prefix_and_exact_extensions(self) -> None:
        file_filter = FileFilter(["drivers", "fs"], ["c", ".h"])

        self.assertTrue(file_filter.matches_file("drivers/foo.c"))
        self.assertTrue(file_filter.matches_file("drivers/net/core/foo.h"))
        self.assertTrue(file_filter.matches_file("fs/name.c"))
        self.assertFalse(file_filter.matches_file("drivers2/foo.c"))
        self.assertFalse(file_filter.matches_file("kernel/foo.c"))
        self.assertFalse(file_filter.matches_file("drivers/foo.cpp"))
        self.assertFalse(file_filter.matches_file("drivers/foo.c.bak"))

    def test_escapes_prefix_and_extension(self) -> None:
        file_filter = FileFilter(["drivers/net+"], ["c++"])

        self.assertTrue(file_filter.matches_file("drivers/net+/socket.c++"))
        self.assertFalse(file_filter.matches_file("drivers/net/socket.c++"))
        self.assertFalse(file_filter.matches_file("drivers/net+/socket.cpp"))

    def test_empty_path_list_matches_nothing(self) -> None:
        self.assertFalse(FileFilter([], ["c"]).matches_file("foo.c"))

    def test_empty_extension_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            FileFilter(["drivers"], [""])

    def test_filter_stats_count_commits_per_rule(self) -> None:
        file_filter = FileFilter(["drivers", "fs"], [".c", ".h"])
        commits = [
            self.make_commit("one", ["drivers/a.c", "fs/b.h"]),
            self.make_commit("two", ["drivers/c.c", "drivers/d.c"]),
            self.make_commit("three", ["docs/e.c"]),
        ]

        included = file_filter.filter_commits(
            commits,
            FilterContext(GitRepo(Path("unused"))),
            show_progress=False,
        )

        self.assertEqual([commit.commit_id for commit in included], ["one", "two"])
        self.assertEqual(
            file_filter.stats().paths,
            {"drivers": 2, "fs": 1},
        )
        self.assertEqual(
            file_filter.stats().extensions,
            {".c": 2, ".h": 1},
        )
        self.assertEqual(
            file_filter.render_report(),
            "Filter report:\n"
            "Paths:\n"
            "  drivers: 2 commits\n"
            "  fs: 1 commits\n"
            "Extensions:\n"
            "  .c: 2 commits\n"
            "  .h: 1 commits",
        )


class MemoryGitRepo(GitRepo):
    def __init__(self, files: dict[str, str]):
        self.files = files

    def read_file(self, commit: str, path: str) -> bytes:
        key = f"{commit}:{path}"
        if key in self.files:
            return self.files[key].encode()
        if path in self.files:
            return self.files[path].encode()
        raise FileNotFoundError(f"{commit}:{path}")


class _KeepNamedFile(CommitFilter):
    name = "Keeping named file"

    def __init__(self, filename: str, seen: list[int] | None = None):
        self.filename = filename
        self.seen = seen

    def filter_mutable_commit(
        self,
        commit: FilteredCommit,
        context: FilterContext,
    ) -> FilteredCommit | None:
        if self.seen is not None:
            self.seen.append(id(commit))
        commit.diff.files = [
            diff_file
            for diff_file in commit.diff.files
            if diff_file.file == self.filename
        ]
        return commit if commit.diff.files else None


class _ReplaceView(CommitFilter):
    name = "Replacing mutable view"

    def filter_mutable_commit(
        self,
        commit: FilteredCommit,
        context: FilterContext,
    ) -> FilteredCommit | None:
        replacement = FilteredCommit.from_commit(commit.original)
        replacement.diff.files = commit.diff.files[-1:]
        return replacement


class FilterCommitsTests(unittest.TestCase):
    @staticmethod
    def make_commit(
        commit_id: str,
        parent_id: str | None,
        paths: list[str],
    ) -> GitCommit:
        patch = "\n".join(
            f"diff --git a/{path} b/{path}\n"
            f"index 1234567..89abcde 100644\n"
            f"--- a/{path}\n"
            f"+++ b/{path}\n"
            "@@ -1 +1 @@\n"
            "-old\n"
            "+new"
            for path in paths
        )
        date = datetime(2024, 1, 1, tzinfo=UTC)
        return GitCommit(
            commit_id,
            "",
            "",
            date,
            date,
            (CommitParent(parent_id or "", patch),),
            "",
        )

    def test_filter_commits_empty(self) -> None:
        repo = MemoryGitRepo({})
        config = KernelConfig("")
        result_with_progress = filter_commits(repo, config, [], show_progress=True)
        result_without_progress = filter_commits(repo, config, [], show_progress=False)
        self.assertEqual(result_with_progress, [])
        self.assertEqual(result_without_progress, [])

    def test_context_from_complete_db_range_builds_structured_history(self) -> None:
        start = datetime(2024, 1, 1, tzinfo=UTC)
        regular = self.make_commit("regular", "parent", ["drivers/foo.c"])
        regular.committer_date = start
        merge = GitCommit(
            "merge",
            "",
            "",
            start,
            datetime(2024, 1, 2, tzinfo=UTC),
            (
                CommitParent("regular", ""),
                CommitParent("topic", ""),
            ),
            "",
        )

        with tempfile.TemporaryDirectory() as directory:
            db = GitDb(Path(directory) / "commits.sqlite")
            db.store_commits([regular, merge], HistoryKind.COMPLETE)

            context = FilterContext.from_db_range(
                db,
                MemoryGitRepo({}),
                start,
                datetime(2024, 1, 3, tzinfo=UTC),
            )
            without_merges = FilterContext.from_db_range(
                db,
                MemoryGitRepo({}),
                start,
                datetime(2024, 1, 3, tzinfo=UTC),
                include_merges=False,
            )

        self.assertEqual(
            [commit.commit_id for commit in context.commits],
            ["merge", "regular"],
        )
        self.assertIsNotNone(context.structured_commits)
        self.assertEqual(
            [commit.commit_id for commit in without_merges.commits],
            ["regular"],
        )
        self.assertIsNone(without_merges.structured_commits)

    def test_context_from_sparse_db_does_not_build_structured_history(self) -> None:
        commit = self.make_commit("c1", "p0", ["drivers/foo.c"])
        with tempfile.TemporaryDirectory() as directory:
            db = GitDb(Path(directory) / "commits.sqlite")
            db.store_commits([commit], HistoryKind.SPARSE)

            context = FilterContext.from_db_range(
                db,
                MemoryGitRepo({}),
            )

        self.assertEqual([item.commit_id for item in context.commits], ["c1"])
        self.assertIsNone(context.structured_commits)

    def test_pipeline_computes_complete_history_requirement(self) -> None:
        regular_pipeline = FilterPipeline([MergeCommitFilter()])
        config_pipeline = FilterPipeline(
            [MergeCommitFilter(), CommitConfigFilter(KernelConfig(""))]
        )

        self.assertFalse(regular_pipeline.requires_complete_history)
        self.assertTrue(config_pipeline.requires_complete_history)
        nested_pipeline = FilterPipeline([config_pipeline])
        self.assertIsInstance(config_pipeline, CommitFilter)
        self.assertTrue(nested_pipeline.requires_complete_history)
        with self.assertRaisesRegex(ValueError, "complete history"):
            nested_pipeline.filter_commits(
                [],
                FilterContext(MemoryGitRepo({})),
                show_progress=False,
            )

    def test_merge_commit_filter_removes_only_merges(self) -> None:
        regular = self.make_commit("regular", "parent", ["drivers/foo.c"])
        merge = GitCommit(
            "merge",
            "",
            "",
            regular.author_date,
            regular.committer_date,
            (
                CommitParent("regular", regular.diff_str),
                CommitParent("topic", ""),
            ),
            "",
        )

        result = MergeCommitFilter().filter_commits(
            [regular, merge],
            FilterContext(MemoryGitRepo({})),
            show_progress=False,
        )

        self.assertEqual([commit.commit_id for commit in result], ["regular"])

    def test_filter_commits_with_progress(self) -> None:
        repo = MemoryGitRepo({"drivers/Makefile": "obj-y += foo.o\n"})
        config = KernelConfig("")
        c1 = self.make_commit("c1", None, ["drivers/foo.c"])
        c2 = self.make_commit("c2", "c1", ["drivers/bar.c"])
        c3 = self.make_commit("c3", "c2", ["drivers/foo.c"])

        # With progress bar
        res_progress = filter_commits(repo, config, [c1, c2, c3], show_progress=True)
        self.assertEqual([c.commit_id for c in res_progress], ["c1", "c3"])

        # Without progress bar
        res_no_progress = filter_commits(repo, config, [c1, c2, c3], show_progress=False)
        self.assertEqual([c.commit_id for c in res_no_progress], ["c1", "c3"])

    def test_pipeline_reuses_mutable_view_and_preserves_original(self) -> None:
        commit = self.make_commit(
            "c1",
            None,
            ["drivers/keep.c", "drivers/drop.c"],
        )
        self.assertIsNone(commit.score)
        commit.score = 0.75
        first_seen: list[int] = []
        second_seen: list[int] = []
        context = FilterContext(MemoryGitRepo({}))
        inner_pipeline = FilterPipeline(
            [_KeepNamedFile("drivers/keep.c", first_seen)]
        )
        self.assertIsInstance(inner_pipeline, CommitFilter)

        result = FilterPipeline(
            [
                inner_pipeline,
                _KeepNamedFile("drivers/keep.c", second_seen),
            ]
        ).filter_commits([commit], context, show_progress=False)

        self.assertEqual(first_seen, second_seen)
        self.assertEqual(result[0].score, 0.75)
        self.assertEqual(
            [diff_file.file for diff_file in result[0].diff.files],
            ["drivers/keep.c"],
        )
        self.assertEqual(
            [diff_file.file for diff_file in commit.diff.files],
            ["drivers/keep.c", "drivers/drop.c"],
        )

    def test_filter_uses_replacement_mutable_view_returned_by_filter(self) -> None:
        commit = self.make_commit(
            "c1",
            "p0",
            ["drivers/first.c", "drivers/second.c"],
        )

        result = FilterPipeline([_ReplaceView()]).filter_commits(
            [commit],
            FilterContext(MemoryGitRepo({})),
            show_progress=False,
        )

        self.assertEqual(
            [diff_file.file for diff_file in result[0].diff.files],
            ["drivers/second.c"],
        )

    def test_config_observes_removed_makefile_commit(self) -> None:
        makefile = self.make_commit(
            "c1",
            "p0",
            ["drivers/Makefile"],
        )
        source = self.make_commit(
            "c2",
            "c1",
            ["drivers/foo.c"],
        )
        repo = MemoryGitRepo(
            {
                "p0:drivers/Makefile": "obj-y += old.o\n",
                "c1:drivers/Makefile": "obj-y += foo.o\n",
                "c2:drivers/Makefile": "obj-y += foo.o\n",
            }
        )
        context = FilterContext(
            repo,
            StructuredCommits.from_commits([makefile, source]),
        )

        result = CommitConfigFilter(KernelConfig("")).filter_commits(
            [source],
            context,
            show_progress=False,
        )

        self.assertEqual([commit.commit_id for commit in result], ["c2"])

    def test_config_requires_structured_history(self) -> None:
        commit = self.make_commit("c1", None, ["drivers/foo.c"])
        with self.assertRaisesRegex(ValueError, "structured commit history"):
            CommitConfigFilter(KernelConfig("")).filter_commits(
                [commit],
                FilterContext(MemoryGitRepo({})),
                show_progress=False,
            )

    def test_config_time_range_rejects_sparse_database(self) -> None:
        date = datetime(2024, 1, 1, tzinfo=UTC)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db = GitDb(root / "commits.sqlite")
            db.store_commits([], HistoryKind.SPARSE)
            config_path = root / "kernel.config"
            config_path.write_text("")

            with self.assertRaisesRegex(ValueError, "complete history"):
                filter_commit_time_range(
                    MemoryGitRepo({}),
                    db,
                    "unused",
                    config_path,
                    date,
                    date,
                    show_progress=False,
                )

    def test_config_and_ifdef_correlate_on_the_same_file(self) -> None:
        date = datetime(2024, 1, 1, tzinfo=UTC)
        patch = (
            "diff --git a/drivers/built.c b/drivers/built.c\n"
            "--- a/drivers/built.c\n"
            "+++ b/drivers/built.c\n"
            "@@ -1,3 +1,3 @@\n"
            " #if 0\n"
            "-old\n"
            "+new\n"
            " #endif\n"
            "diff --git a/drivers/unbuilt.c b/drivers/unbuilt.c\n"
            "--- a/drivers/unbuilt.c\n"
            "+++ b/drivers/unbuilt.c\n"
            "@@ -1 +1 @@\n"
            "-old\n"
            "+new\n"
        )
        commit = GitCommit(
            "c1",
            "",
            "",
            date,
            date,
            (CommitParent("p0", patch),),
            "",
        )
        repo = MemoryGitRepo(
            {
                "drivers/Makefile": "obj-y += built.o\n",
                "p0:drivers/built.c": "#if 0\nold\n#endif\n",
                "c1:drivers/built.c": "#if 0\nnew\n#endif\n",
                "p0:drivers/unbuilt.c": "old\n",
                "c1:drivers/unbuilt.c": "new\n",
            }
        )
        context = FilterContext(
            repo,
            StructuredCommits.from_commits([commit]),
        )

        result = FilterPipeline(
            [
                CommitConfigFilter(KernelConfig("")),
                IfdefFilter(KernelConfig("")),
            ]
        ).filter_commits([commit], context, show_progress=False)

        self.assertEqual(result, [])

    def test_ifdef_materializes_only_active_changes(self) -> None:
        date = datetime(2024, 1, 1, tzinfo=UTC)
        patch = (
            "diff --git a/drivers/foo.c b/drivers/foo.c\n"
            "--- a/drivers/foo.c\n"
            "+++ b/drivers/foo.c\n"
            "@@ -1,4 +1,4 @@\n"
            " #if 0\n"
            "-old-disabled\n"
            "+new-disabled\n"
            " #endif\n"
            "-old-active\n"
            "+new-active\n"
        )
        commit = GitCommit(
            "c1",
            "",
            "",
            date,
            date,
            (CommitParent("p0", patch),),
            "",
        )
        repo = MemoryGitRepo(
            {
                "p0:drivers/foo.c": (
                    "#if 0\nold-disabled\n#endif\nold-active\n"
                ),
                "c1:drivers/foo.c": (
                    "#if 0\nnew-disabled\n#endif\nnew-active\n"
                ),
            }
        )

        result = IfdefFilter(KernelConfig("")).filter_commits(
            [commit],
            FilterContext(repo),
            show_progress=False,
        )

        self.assertEqual(len(result), 1)
        self.assertNotIn("+new-disabled", result[0].diff_str)
        self.assertNotIn("-old-disabled", result[0].diff_str)
        self.assertIn(" old-disabled", result[0].diff_str)
        self.assertIn("+new-active", result[0].diff_str)
        self.assertIn("-old-active", result[0].diff_str)
        self.assertIn("+new-disabled", commit.diff_str)

    def test_ifdef_uses_exact_build_mode_when_config_filter_annotates_it(self) -> None:
        date = datetime(2024, 1, 1, tzinfo=UTC)
        path = "drivers/foo.c"
        patch = (
            f"diff --git a/{path} b/{path}\n"
            f"--- a/{path}\n"
            f"+++ b/{path}\n"
            "@@ -1,3 +1,3 @@\n"
            " #ifdef MODULE\n"
            "-old\n"
            "+new\n"
            " #endif\n"
        )
        commit = GitCommit(
            "c1",
            "",
            "",
            date,
            date,
            (CommitParent("p0", patch),),
            "",
        )
        repo = MemoryGitRepo(
            {
                f"p0:{path}": "#ifdef MODULE\nold\n#endif\n",
                f"c1:{path}": "#ifdef MODULE\nnew\n#endif\n",
            }
        )
        context = FilterContext(repo)

        # Standalone use is conservative: the file may be built in either mode.
        standalone = IfdefFilter(KernelConfig("")).filter_commits(
            [commit],
            context,
            show_progress=False,
        )
        self.assertEqual([item.commit_id for item in standalone], ["c1"])

        builtin = FilteredCommit.from_commit(commit)
        builtin.build_modes[(None, path)] = FileBuildModes(
            old=ConfigValue.ENABLED,
            new=ConfigValue.ENABLED,
        )
        builtin_result = IfdefFilter(KernelConfig("")).filter_mutable_commits(
            [builtin],
            context,
            show_progress=False,
        )
        self.assertEqual(builtin_result, [])

        module = FilteredCommit.from_commit(commit)
        module.build_modes[(None, path)] = FileBuildModes(
            old=ConfigValue.MODULE,
            new=ConfigValue.MODULE,
        )
        module_result = IfdefFilter(KernelConfig("")).filter_mutable_commits(
            [module],
            context,
            show_progress=False,
        )
        self.assertEqual(len(module_result), 1)

    def test_default_filter_mutable_commit_is_identity(self) -> None:
        class _BatchOnlyFilter(CommitFilter):
            name = "Batch only filter"

        commit = self.make_commit("c1", None, ["drivers/foo.c"])
        mutable_commit = FilteredCommit.from_commit(commit)
        context = FilterContext(MemoryGitRepo({}))

        f = _BatchOnlyFilter()
        result = f.filter_mutable_commit(mutable_commit, context)
        self.assertIs(result, mutable_commit)


if __name__ == "__main__":
    unittest.main()
