from datetime import UTC, datetime
import math
from pathlib import Path
import unittest
from unittest.mock import patch

from kpatch.git import GitCommit
from kpatch.visualization import show_commit_sunburst
from kpatch.visualization.sunburst import (
    _ChartView,
    _MetricMode,
    _NodeKind,
    _TreeNode,
    _ViewNode,
    _build_chart_view,
    _build_commit_tree,
    _build_directory_views,
)


class CommitSunburstTests(unittest.TestCase):
    @staticmethod
    def make_commit(commit_id: str, paths: list[str]) -> GitCommit:
        patch_text = "\n".join(
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
        return GitCommit(commit_id, "", "", date, date, (), "", patch_text)

    @staticmethod
    def find_tree_node(root: _TreeNode, node_id: str) -> _TreeNode:
        if root.id == node_id:
            return root
        for child in root.children.values():
            try:
                return CommitSunburstTests.find_tree_node(child, node_id)
            except KeyError:
                pass
        raise KeyError(node_id)

    @staticmethod
    def view_nodes_by_id(view: _ChartView) -> dict[str, _ViewNode]:
        return {node.id: node for node in view.nodes}

    def test_tree_counts_unique_file_commit_touches(self) -> None:
        commits = [
            self.make_commit("one", ["drivers/net/a.c", "drivers/net/b.c"]),
            self.make_commit("two", ["drivers/net/a.c", "fs/x.c"]),
            self.make_commit("two", ["drivers/net/a.c", "fs/x.c"]),
        ]

        root = _build_commit_tree(commits)

        drivers = self.find_tree_node(root, "dir:drivers")
        file_a = self.find_tree_node(root, "file:drivers/net/a.c")
        self.assertEqual((root.file_touches, root.unique_commits), (4, 2))
        self.assertEqual((drivers.file_touches, drivers.unique_commits), (3, 2))
        self.assertEqual((file_a.file_touches, file_a.unique_commits), (2, 2))
        self.assertEqual(root.exclusive_commits, 2)
        self.assertEqual(drivers.exclusive_commits, 1)
        self.assertEqual(file_a.exclusive_commits, 0)

    def test_file_touch_geometry_is_additive(self) -> None:
        root = _build_commit_tree(
            [
                self.make_commit("one", ["drivers/net/a.c", "drivers/net/b.c"]),
                self.make_commit("two", ["drivers/net/a.c", "fs/x.c"]),
            ]
        )

        view = _build_chart_view(root, _MetricMode.FILE_TOUCHES, 0)
        nodes = self.view_nodes_by_id(view)

        self.assertTrue(math.isclose(nodes["dir:drivers"].value, 0.75))
        self.assertTrue(math.isclose(nodes["dir:fs"].value, 0.25))
        self.assertTrue(math.isclose(nodes["file:drivers/net/a.c"].value, 0.5))
        self.assertTrue(math.isclose(nodes["file:drivers/net/b.c"].value, 0.25))

    def test_unique_commit_geometry_uses_local_sibling_weights(self) -> None:
        root = _build_commit_tree(
            [
                self.make_commit("one", ["drivers/net/a.c", "drivers/net/b.c"]),
                self.make_commit("two", ["drivers/net/a.c", "fs/x.c"]),
            ]
        )

        view = _build_chart_view(root, _MetricMode.UNIQUE_COMMITS, 0)
        nodes = self.view_nodes_by_id(view)

        self.assertTrue(math.isclose(nodes["dir:drivers"].value, 2 / 3))
        self.assertTrue(math.isclose(nodes["dir:fs"].value, 1 / 3))
        self.assertTrue(math.isclose(nodes["file:drivers/net/a.c"].value, 4 / 9))
        self.assertTrue(math.isclose(nodes["file:drivers/net/b.c"].value, 2 / 9))
        self.assertEqual(nodes["dir:drivers"].unique_commits, 2)
        self.assertEqual(nodes["dir:fs"].unique_commits, 1)
        self.assertEqual(
            nodes["file:drivers/net/a.c"].sidebar_item_ids,
            ("dir:drivers",),
        )

    def test_exclusive_geometry_keeps_cross_child_commits_at_parent(self) -> None:
        root = _build_commit_tree(
            [
                self.make_commit("one", ["drivers/a.c"]),
                self.make_commit("two", ["drivers/a.c", "drivers/b.c"]),
                self.make_commit("three", ["drivers/a.c", "fs/x.c"]),
            ]
        )

        view = _build_chart_view(root, _MetricMode.EXCLUSIVE_COMMITS, 0)
        nodes = self.view_nodes_by_id(view)

        self.assertEqual(root.exclusive_commits, 3)
        self.assertTrue(math.isclose(nodes["dir:drivers"].value, 2 / 3))
        self.assertTrue(math.isclose(nodes["file:drivers/a.c"].value, 1 / 3))
        self.assertNotIn("dir:fs", nodes)
        self.assertNotIn("file:drivers/b.c", nodes)
        self.assertEqual(
            [
                (item.id, item.exclusive_commits)
                for item in view.sidebar_items
            ],
            [("dir:drivers", 2), ("dir:fs", 0)],
        )

    def test_threshold_grouping_is_recomputed_for_each_mode(self) -> None:
        commits = [
            self.make_commit(
                "bulk",
                [f"bulk/file-{index}.c" for index in range(100)],
            )
        ]
        commits.extend(
            self.make_commit(f"popular-{index}", ["popular/file.c"])
            for index in range(10)
        )
        root = _build_commit_tree(commits)

        file_chart = _build_chart_view(root, _MetricMode.FILE_TOUCHES, 0.1)
        file_view = self.view_nodes_by_id(file_chart)
        unique_view = self.view_nodes_by_id(
            _build_chart_view(root, _MetricMode.UNIQUE_COMMITS, 0.1)
        )

        self.assertIn("dir:bulk", file_view)
        self.assertNotIn("dir:popular", file_view)
        self.assertNotIn("dir:bulk", unique_view)
        self.assertIn("dir:popular", unique_view)
        self.assertEqual(
            [item.id for item in file_chart.sidebar_items],
            ["dir:bulk", "dir:popular"],
        )
        grouped = next(
            node
            for node in file_chart.nodes
            if node.parent_id == root.id and node.kind is _NodeKind.OTHER
        )
        self.assertEqual(grouped.sidebar_item_ids, ("dir:popular",))
        self.assertEqual(grouped.exclusive_commits, 10)

        all_views = _build_directory_views(root, 0.1)
        self.assertIn("dir:popular", all_views[_MetricMode.FILE_TOUCHES])

    def test_threshold_uses_full_circle_and_rerooting_reveals_children(self) -> None:
        commits = [
            self.make_commit(f"dominant-{index}", ["dominant/file.c"])
            for index in range(90)
        ]
        commits.extend(
            self.make_commit(
                f"parent-{index}",
                ["parent/a/file.c", "parent/b/file.c"],
            )
            for index in range(5)
        )
        root = _build_commit_tree(commits)

        root_view = _build_chart_view(root, _MetricMode.FILE_TOUCHES, 0.06)
        root_nodes = self.view_nodes_by_id(root_view)
        parent = root_nodes["dir:parent"]
        grouped = [
            node
            for node in root_view.nodes
            if node.parent_id == parent.id and node.kind is _NodeKind.OTHER
        ]
        self.assertNotIn("dir:parent/a", root_nodes)
        self.assertNotIn("dir:parent/b", root_nodes)
        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0].hidden_items, 2)
        self.assertEqual((grouped[0].file_touches, grouped[0].unique_commits), (10, 5))
        self.assertEqual(grouped[0].exclusive_commits, 0)
        self.assertTrue(math.isclose(grouped[0].value, 0.1))

        parent_tree = self.find_tree_node(root, "dir:parent")
        rerooted_view = _build_chart_view(
            parent_tree,
            _MetricMode.FILE_TOUCHES,
            0.06,
        )
        rerooted_nodes = self.view_nodes_by_id(rerooted_view)
        self.assertIn("dir:parent/a", rerooted_nodes)
        self.assertIn("dir:parent/b", rerooted_nodes)
        self.assertTrue(math.isclose(rerooted_nodes["dir:parent/a"].value, 0.5))
        self.assertTrue(math.isclose(rerooted_nodes["dir:parent/b"].value, 0.5))

    def test_rerooted_view_has_canonical_clickable_breadcrumbs(self) -> None:
        root = _build_commit_tree(
            [self.make_commit("one", ["net/sched/sch_api.c"])]
        )
        sched = self.find_tree_node(root, "dir:net/sched")

        view = _build_chart_view(sched, _MetricMode.FILE_TOUCHES, 0.01)

        self.assertEqual(
            [(breadcrumb.id, breadcrumb.label) for breadcrumb in view.breadcrumbs],
            [
                ("dir:.", "."),
                ("dir:net", "net"),
                ("dir:net/sched", "sched"),
            ],
        )

    def test_html_is_standalone_and_browser_open_is_optional(self) -> None:
        commit = self.make_commit("one", ["drivers/net/a.c"])
        original_paths = [file.file for file in commit.diff.files]
        output_path: Path | None = None
        try:
            with patch(
                "kpatch.visualization.sunburst.webbrowser.open"
            ) as browser_open:
                output_path = show_commit_sunburst([commit])

            self.assertTrue(output_path.exists())
            browser_open.assert_called_once_with(
                output_path.resolve().as_uri(),
                new=2,
            )
            rendered = output_path.read_text(encoding="utf-8")
            self.assertIn("File touches", rendered)
            self.assertIn("Unique commits", rendered)
            self.assertIn("Exclusive commits", rendered)
            self.assertIn("plotly_sunburstclick", rendered)
            self.assertIn("plotly_hover", rendered)
            self.assertIn("kpatch-sidebar", rendered)
            self.assertIn("Visible child layers", rendered)
            self.assertIn("let maxDepth = 3", rendered)
            self.assertIn('"maxdepth":4', rendered)
            self.assertIn("maxdepth: maxDepth + 1", rendered)
            self.assertIn('separator.textContent = "/"', rendered)
            self.assertNotIn("let history", rendered)
            self.assertIn("Plotly.newPlot", rendered)
            self.assertNotIn('src="https://cdn.plot.ly', rendered)
            self.assertEqual(
                [file.file for file in commit.diff.files],
                original_paths,
            )
        finally:
            if output_path is not None:
                output_path.unlink(missing_ok=True)

        output_path = show_commit_sunburst(
            [commit],
            max_depth=5,
            open_browser=False,
        )
        try:
            self.assertTrue(output_path.exists())
            self.assertIn(
                "let maxDepth = 5",
                output_path.read_text(encoding="utf-8"),
            )
        finally:
            output_path.unlink(missing_ok=True)

    def test_rejects_empty_data_and_invalid_thresholds(self) -> None:
        with self.assertRaisesRegex(ValueError, "changed files"):
            show_commit_sunburst([], open_browser=False)

        commit = self.make_commit("one", ["drivers/a.c"])
        for threshold in (-0.1, 1.0, math.inf, math.nan):
            with self.subTest(threshold=threshold):
                with self.assertRaisesRegex(ValueError, "min_sector_fraction"):
                    show_commit_sunburst(
                        [commit],
                        min_sector_fraction=threshold,
                        open_browser=False,
                    )

        for max_depth in (0, -1, True):
            with self.subTest(max_depth=max_depth):
                with self.assertRaisesRegex(ValueError, "max_depth"):
                    show_commit_sunburst(
                        [commit],
                        max_depth=max_depth,
                        open_browser=False,
                    )


if __name__ == "__main__":
    unittest.main()
