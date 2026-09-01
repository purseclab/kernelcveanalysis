import unittest
from datetime import UTC, datetime

from kpatch.filter import FileFilter
from kpatch.git import GitCommit


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
        return GitCommit(commit_id, "", "", date, date, (), "", patch)

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


if __name__ == "__main__":
    unittest.main()
