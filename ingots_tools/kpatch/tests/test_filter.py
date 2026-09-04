import unittest
from datetime import UTC, datetime

from kpatch.filter import FileFilter, filter_commits
from kpatch.filter.config_filter import KernelConfig
from kpatch.git import CommitParent, GitCommit, GitRepo


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

        included = file_filter.filter_commits(commits)

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
        if path in self.files:
            return self.files[path].encode()
        raise FileNotFoundError(f"{commit}:{path}")


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


if __name__ == "__main__":
    unittest.main()

