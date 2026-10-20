import gc
from datetime import UTC, datetime
from dataclasses import FrozenInstanceError
from pathlib import Path
import sqlite3
import tracemalloc
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import weakref

from kpatch.diff import Diff
from kpatch.filter import FilterContext, FilteredCommit
from kpatch.filter.config import ConfigFilter, _walk_history
from kpatch.filter.config.history import (
    ConfigHistoryReader,
    ConfigHistoryStore,
    DecisionShard,
    FileDecision,
    HistoryCommit,
    PrimaryHistory,
    parse_history_diff,
)
from kpatch.filter.config.traversal import walk_history
from kpatch.filter.config_filter import ConfigValue, KbuildState, KernelConfig
from kpatch.git import CommitParent, GitCommit, GitRepo, StructuredCommits


class MemoryRepo(GitRepo):
    def __init__(self) -> None:
        pass

    def read_file(self, commit: str, path: str) -> bytes:
        if path == "drivers/Makefile":
            return b"obj-y += example.o\n"
        raise FileNotFoundError(path)


def make_commit(commit_id: str, parent: str) -> GitCommit:
    date = datetime(2026, 7, 1, tzinfo=UTC)
    text = (
        "diff --git a/drivers/example.c b/drivers/example.c\n"
        "--- a/drivers/example.c\n"
        "+++ b/drivers/example.c\n"
        "@@ -1 +1 @@\n"
        '-#include "before.h"\n'
        '+#include "after.h"\n'
    )
    return GitCommit(commit_id, "", "", date, date, (CommitParent(parent, text),), "")


def reference_history_diff(text: str) -> Diff:
    diff = Diff.parse(text)
    diff.text = ""
    for diff_file in diff.files:
        diff_file.header_lines = []
        for chunk in diff_file.chunks:
            chunk.lines = [
                line for line in chunk.lines
                if line.startswith(("+", "-")) and line[1:].lstrip().startswith("#")
            ]
        diff_file.chunks = [chunk for chunk in diff_file.chunks if chunk.lines]
    return diff


class HistoryParserTests(unittest.TestCase):
    def test_projection_matches_full_parser_for_structural_and_binary_changes(self) -> None:
        ordinary = (
            "diff --git a/one.c b/one.c\n"
            "index 1234567..89abcde 100644\n"
            "--- a/one.c\n+++ b/one.c\n"
            "@@ -1,2 +1,2 @@ first\n-old\n+new\n context\n"
            "@@ -20,3 +20,3 @@ second\n--- removed body\n+++ added body\n"
            '- # include "old.h"\n+\t#include "new.h"\n'
            "\\ No newline at end of file\n"
        )
        structural = (
            "diff --git a/old.c b/new.c\n"
            "similarity index 100%\nrename from old.c\nrename to new.c\n"
            "diff --git a/old.c b/copied.c\n"
            "similarity index 100%\ncopy from old.c\ncopy to copied.c\n"
            "diff --git a/new.h b/new.h\nnew file mode 100644\n"
            "--- /dev/null\n+++ b/new.h\n@@ -0,0 +1 @@\n+#define NEW 1\n"
            "diff --git a/gone.h b/gone.h\ndeleted file mode 100644\n"
            "--- a/gone.h\n+++ /dev/null\n@@ -1 +0,0 @@\n-#define OLD 1\n"
            "diff --git a/mode.c b/mode.c\nold mode 100644\nnew mode 100755\n"
        )
        binary = (
            "diff --git a/image.bin b/image.bin\n"
            "index 1234567..89abcde 100644\nGIT binary patch\n"
            "literal 123\npayload\n\nliteral 321\nreverse-payload\n"
        )
        patches = ["", ordinary, structural, binary, ordinary + binary + structural]
        patches.append('--- a/raw.h\n+++ b/raw.h\n@@ -1 +1 @@\n-#define X 1\n+#define X 2\n')
        for text in patches:
            with self.subTest(text=text[:60]):
                self.assertEqual(parse_history_diff(text), reference_history_diff(text))

    def test_projection_preserves_splitlines_semantics(self) -> None:
        patch_text = make_commit("c", "parent").diff_str
        for separator in ("\n", "\r\n", "\r", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"):
            with self.subTest(separator=repr(separator)):
                text = patch_text.replace("\n", separator)
                self.assertEqual(parse_history_diff(text), reference_history_diff(text))

    def test_large_ordinary_hunk_is_not_materialized(self) -> None:
        body = "-old ordinary source line\n+new ordinary source line\n" * 40000
        text = (
            "diff --git a/large.c b/large.c\n"
            "--- a/large.c\n+++ b/large.c\n@@ -1,40000 +1,40000 @@\n"
            + body + '+#include "retained.h"\n'
        )
        tracemalloc.start()
        try:
            diff = parse_history_diff(text)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertEqual(diff.files[0].chunks[0].lines, ['+#include "retained.h"'])
        self.assertLess(peak, 512 * 1024)


class HistoryCommitTests(unittest.TestCase):
    def test_headers_copy_only_ordered_parent_ids(self) -> None:
        commit = make_commit("merge", "first")
        commit.parents += (CommitParent("second", "unused patch"),)
        header = HistoryCommit.from_commit(commit)
        self.assertEqual(header, HistoryCommit("merge", ("first", "second")))
        self.assertEqual(header.parent_id, "first")
        self.assertTrue(header.is_merge)
        with self.assertRaises(FrozenInstanceError):
            header.commit_id = "changed"

        commit.parents = ()
        root = HistoryCommit.from_commit(commit)
        self.assertIsNone(root.parent_id)
        self.assertFalse(root.is_merge)


class ConfigHistoryReaderTests(unittest.TestCase):
    def test_primary_root_graphs_preserve_insertion_and_sibling_order(self) -> None:
        headers = [
            HistoryCommit("leaf-z", ("fork",)),
            HistoryCommit("other", ("outside",)),
            HistoryCommit("fork", ("root",)),
            HistoryCommit("merge", ("fork", "other")),
            HistoryCommit("root", ()),
            HistoryCommit("sibling", ("root",)),
            HistoryCommit("side-merge", ("other", "root")),
        ]
        sizes = {"root": 5, "fork": 3, "other": 2}
        with ConfigHistoryStore() as store:
            for header in headers:
                store.add_history(header, Diff.parse(""), sizes.get(header.commit_id, 1))
            store.commit()
            with ConfigHistoryReader(store.path) as reader:
                graph = reader.load_root("root")
                self.assertEqual(list(graph.commits), ["leaf-z", "fork", "merge", "root", "sibling"])
                self.assertEqual(graph.root_commits, ("root",))
                self.assertEqual(graph.primary_children, {
                    "leaf-z": [], "fork": ["leaf-z", "merge"], "merge": [],
                    "root": ["fork", "sibling"], "sibling": [],
                })
                self.assertEqual(graph.subtree_sizes, {
                    "leaf-z": 1, "fork": 3, "merge": 1, "root": 5, "sibling": 1,
                })
                self.assertEqual(reader.load_root("other"), PrimaryHistory(
                    {"other": headers[1], "side-merge": headers[-1]},
                    {"other": ["side-merge"], "side-merge": []},
                    {"other": 2, "side-merge": 1},
                    ("other",),
                ))
                self.assertEqual(reader.load_root("fork").root_commits, ("fork",))
                for invalid_id in ("missing", "root' OR 1=1 --", ""):
                    with self.subTest(commit_id=invalid_id), self.assertRaises(KeyError):
                        reader.load_root(invalid_id)

    def test_deep_primary_chain_loads_without_python_recursion(self) -> None:
        count = 2500
        diff = Diff.parse("")
        with ConfigHistoryStore() as store:
            # Children deliberately precede their parents in persisted order.
            for index in reversed(range(count)):
                parent = f"node-{index - 1}" if index else "outside"
                store.add_history(HistoryCommit(f"node-{index}", (parent,)), diff, count - index)
            store.commit()
            with ConfigHistoryReader(store.path) as reader:
                graph = reader.load_root("node-0")

        self.assertEqual(len(graph.commits), count)
        self.assertEqual(next(iter(graph.commits)), f"node-{count - 1}")
        self.assertEqual(graph.root_commits, ("node-0",))
        self.assertEqual(graph.subtree_sizes["node-0"], count)
        self.assertEqual(graph.subtree_sizes[f"node-{count - 1}"], 1)
        self.assertEqual(graph.primary_children[f"node-{count - 1}"], [])
        for index in range(count - 1):
            self.assertEqual(graph.primary_children[f"node-{index}"], [f"node-{index + 1}"])
        base = KbuildState(MemoryRepo(), KernelConfig(""), "outside")
        self.assertEqual(
            [visit.commit_id for visit in walk_history(graph, lambda commit_id: base)],
            [f"node-{index}" for index in range(count)],
        )

    def test_reader_is_readonly_bounded_and_independent_from_result_writes(self) -> None:
        diff = parse_history_diff(make_commit("root", "outside").diff_str)
        with ConfigHistoryStore() as store:
            store.add_history(HistoryCommit("root", ("outside",)), diff, 1)
            store.commit()
            with ConfigHistoryReader(store.path) as reader:
                self.assertEqual(reader.get_history("root"), diff)
                with self.assertRaises(KeyError):
                    reader.get_history("missing")
                with self.assertRaises(sqlite3.OperationalError):
                    reader._connection.execute("DELETE FROM history")
                self.assertEqual(reader._connection.execute("PRAGMA cache_size").fetchone()[0], -4096)
                self.assertEqual(reader._connection.execute("PRAGMA mmap_size").fetchone()[0], 0)
                reader._connection.rollback()
                reader._connection.execute("BEGIN")
                reader._connection.execute("SELECT * FROM history").fetchone()
                store.add_decisions("root", {(None, "kept.c"): FileDecision(None, ConfigValue.ENABLED)})
                store.commit()
                self.assertEqual(reader.get_history("root"), diff)
            reader.close()
            self.assertTrue(store.path.exists())
            self.assertTrue(store.decisions_path.exists())
        self.assertFalse(store.path.parent.exists())

    def test_missing_database_does_not_create_a_file(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "missing.sqlite"
            with self.assertRaises(sqlite3.OperationalError):
                ConfigHistoryReader(path)
            self.assertFalse(path.exists())

    def test_reader_connection_is_closed_on_collection(self) -> None:
        with ConfigHistoryStore() as store:
            store.commit()
            reader = ConfigHistoryReader(store.path)
            connection = reader._connection
            reference = weakref.ref(reader)
            del reader
            gc.collect()
            self.assertIsNone(reference())
            with self.assertRaises(sqlite3.ProgrammingError):
                connection.execute("SELECT 1")


class ConfigHistoryStoreTests(unittest.TestCase):
    def test_history_roundtrip_and_insertion_order(self) -> None:
        first = parse_history_diff(make_commit("z", "parent").diff_str)
        second = Diff.parse("")
        with ConfigHistoryStore() as store:
            store.add_history(HistoryCommit("z", ("parent",)), first, 1)
            store.add_history(HistoryCommit("a", ()), second, 1)
            store.commit()

            self.assertEqual(list(store.iter_history()), [first, second])
            self.assertEqual(store.get_history("z"), first)
            self.assertEqual(store.get_history("a"), second)
            with self.assertRaises(KeyError):
                store.get_history("missing")
            path = store.path
        self.assertFalse(path.parent.exists())
        store.close()

    def test_nullable_path_keys_and_build_modes_roundtrip(self) -> None:
        decisions = {
            (None, "drivers/example.c"): FileDecision(ConfigValue.ENABLED, None),
            ("drivers/old.c", "drivers/new.c"): FileDecision(None, ConfigValue.MODULE),
        }
        with ConfigHistoryStore() as store:
            store.add_decisions("kept", decisions)
            store.add_decisions("rejected", {})
            store.commit()
            self.assertEqual(store.get_decisions("kept"), decisions)
            self.assertEqual(store.get_decisions("rejected"), {})
            self.assertEqual(store.get_decisions("missing"), {})
            self.assertIs(
                store.get_decisions("kept")[(None, "drivers/example.c")].old,
                ConfigValue.ENABLED,
            )
            self.assertEqual(
                store._connection.execute("PRAGMA cache_size").fetchone()[0], -4096
            )

    def test_worker_shards_merge_blobs_and_remove_only_successful_shards(self) -> None:
        decisions = {
            (None, "new.c"): FileDecision(None, ConfigValue.ENABLED),
            ("old.c", "renamed.c"): FileDecision(ConfigValue.MODULE, None),
        }
        with ConfigHistoryStore() as store:
            first = store.path.parent / "first.sqlite"
            second = store.path.parent / "second.sqlite"
            for shard_path, commit_id in ((first, "first"), (second, "second")):
                with DecisionShard(shard_path) as shard:
                    shard.add_decisions(commit_id, decisions)
                    shard.add_decisions("empty", {})
                    shard.commit()
                shard.close()
                with self.assertRaises(sqlite3.ProgrammingError):
                    shard._connection.execute("SELECT 1")

            # Blob merging must not deserialize each worker result in the parent.
            with patch("kpatch.filter.config.history._DECISIONS_ADAPTER") as adapter:
                store.merge_decisions(first)
                store.merge_decisions(second)
                adapter.validate_json.assert_not_called()
                adapter.dump_json.assert_not_called()
            store.commit()
            self.assertFalse(first.exists())
            self.assertFalse(second.exists())
            self.assertEqual(store.get_decisions("first"), decisions)
            self.assertEqual(store.get_decisions("second"), decisions)
            self.assertEqual(store.get_decisions("empty"), {})
            self.assertEqual(store._connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall(), [("history",)])
            self.assertEqual(store._decisions_connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall(), [("decisions",)])

            duplicate = store.path.parent / "duplicate.sqlite"
            with DecisionShard(duplicate) as shard:
                shard.add_decisions("first", decisions)
                shard.commit()
            with self.assertRaises(sqlite3.IntegrityError):
                store.merge_decisions(duplicate)
            self.assertTrue(duplicate.exists())
        self.assertFalse(duplicate.parent.exists())

    def test_second_connection_failure_closes_first_and_removes_scratch(self) -> None:
        connect = sqlite3.connect
        connections: list[sqlite3.Connection] = []
        paths: list[Path] = []

        def fail_second(path: Path, *, check_same_thread: bool) -> sqlite3.Connection:
            paths.append(path)
            if connections:
                raise sqlite3.OperationalError("second connection failed")
            connection = connect(path, check_same_thread=check_same_thread)
            connections.append(connection)
            return connection

        with patch("kpatch.filter.config.history.sqlite3.connect", side_effect=fail_second):
            with self.assertRaisesRegex(sqlite3.OperationalError, "second connection failed"):
                ConfigHistoryStore()
        self.assertFalse(paths[0].parent.exists())
        with self.assertRaises(sqlite3.ProgrammingError):
            connections[0].execute("SELECT 1")

    def test_history_size_must_be_positive(self) -> None:
        with ConfigHistoryStore() as store:
            with self.assertRaises(sqlite3.IntegrityError):
                store.add_history(HistoryCommit("invalid", ()), Diff.parse(""), 0)

    def test_connection_failure_removes_created_scratch_directory(self) -> None:
        paths: list[Path] = []

        def create_directory(*, prefix: str) -> TemporaryDirectory[str]:
            directory = TemporaryDirectory(prefix=prefix)
            paths.append(Path(directory.name))
            return directory

        with (
            patch("kpatch.filter.config.history.TemporaryDirectory", side_effect=create_directory),
            patch("kpatch.filter.config.history.sqlite3.connect", side_effect=sqlite3.OperationalError("full")),
            self.assertRaisesRegex(sqlite3.OperationalError, "full"),
        ):
            ConfigHistoryStore()
        self.assertEqual(len(paths), 1)
        self.assertFalse(paths[0].exists())

    def test_context_failure_and_collection_release_scratch_files(self) -> None:
        with self.assertRaises(sqlite3.IntegrityError):
            with ConfigHistoryStore() as store:
                path = store.path
                store.add_history(HistoryCommit("duplicate", ()), Diff.parse(""), 1)
                store.add_history(HistoryCommit("duplicate", ()), Diff.parse(""), 1)
        self.assertFalse(path.parent.exists())

        abandoned = ConfigHistoryStore()
        abandoned_path = abandoned.path
        history_connection = abandoned._connection
        decisions_connection = abandoned._decisions_connection
        reference = weakref.ref(abandoned)
        del abandoned
        gc.collect()
        self.assertIsNone(reference())
        self.assertFalse(abandoned_path.parent.exists())
        for connection in (history_connection, decisions_connection):
            with self.assertRaises(sqlite3.ProgrammingError):
                connection.execute("SELECT 1")

    def test_preparation_failure_and_success_close_stores(self) -> None:
        commit = make_commit("c", "outside")
        context = FilterContext(MemoryRepo(), StructuredCommits.from_commits([commit]))
        config_filter = ConfigFilter(KernelConfig(""))
        paths: list[Path] = []

        def create_store() -> ConfigHistoryStore:
            store = ConfigHistoryStore()
            paths.append(store.path)
            return store

        with patch("kpatch.filter.config.ConfigHistoryStore", side_effect=create_store):
            with patch.object(
                config_filter, "_populate_history", side_effect=RuntimeError("failed")
            ):
                with self.assertRaisesRegex(RuntimeError, "failed"):
                    config_filter.filter_commits([commit], context, show_progress=False)
            self.assertIsNone(config_filter._store)
            self.assertFalse(paths[-1].parent.exists())

            result = config_filter.filter_commits([commit], context, show_progress=False)
            self.assertEqual([item.commit_id for item in result], ["c"])
            self.assertIsNone(config_filter._store)
            self.assertTrue(all(not path.parent.exists() for path in paths))

    def test_individual_filter_calls_reuse_store_until_context_changes(self) -> None:
        commit = make_commit("c", "outside")
        context = FilterContext(MemoryRepo(), StructuredCommits.from_commits([commit]))
        config_filter = ConfigFilter(KernelConfig(""))
        self.assertIsNotNone(
            config_filter.filter_mutable_commit(FilteredCommit.from_commit(commit), context)
        )
        first_store = config_filter._store
        assert first_store is not None
        self.assertIsNotNone(
            config_filter.filter_mutable_commit(FilteredCommit.from_commit(commit), context)
        )
        self.assertIs(config_filter._store, first_store)

        empty_context = FilterContext(MemoryRepo(), StructuredCommits.from_commits([]))
        config_filter._prepare(empty_context, show_progress=False)
        self.assertFalse(first_store.path.parent.exists())
        self.assertIsNone(config_filter._store)


class HistoryTraversalTests(unittest.TestCase):
    def test_equal_size_siblings_keep_original_order_not_dates_or_ids(self) -> None:
        root = make_commit("root", "outside")
        children = [
            make_commit("z-older", "root"),
            make_commit("a-newer", "root"),
            make_commit("m-middle", "root"),
        ]
        for child, day in zip(children, (2, 4, 3), strict=True):
            child.committer_date = datetime(2026, 7, day, tzinfo=UTC)
        structured = StructuredCommits.from_commits([root, *children])
        config = KernelConfig("")

        def create_state(commit_id: str) -> KbuildState:
            return KbuildState(MemoryRepo(), config, "outside")

        original_order = [visit.commit_id for visit in _walk_history(structured, create_state)]
        with ConfigHistoryStore() as store:
            for commit in structured.commits.values():
                store.add_history(HistoryCommit.from_commit(commit), Diff.parse(""),
                                  4 if commit.commit_id == "root" else 1)
            store.commit()
            with ConfigHistoryReader(store.path) as reader:
                history = reader.load_root("root")
            self.assertEqual(history.primary_children["root"], ["z-older", "a-newer", "m-middle"])
            restored_order = [visit.commit_id for visit in walk_history(history, create_state)]
        self.assertEqual(original_order, ["root", "m-middle", "a-newer", "z-older"])
        self.assertEqual(restored_order, original_order)

    def test_wide_fork_copies_only_the_child_about_to_run(self) -> None:
        root = make_commit("root", "outside")
        children = [make_commit(f"child-{index}", "root") for index in range(200)]
        history = StructuredCommits.from_commits([root, *children])
        base = KbuildState(MemoryRepo(), KernelConfig(""), "outside")
        base.delegated.add("inherited")

        with patch.object(KbuildState, "copy", wraps=KbuildState.copy) as copy:
            walk = _walk_history(history, lambda commit_id: base)
            first = next(walk)
            self.assertEqual(first.commit_id, "root")
            copy.assert_not_called()
            first.state.base_commit = "root"
            second = next(walk)
            self.assertEqual(copy.call_count, 1)
            self.assertEqual(second.state.base_commit, "root")
            second.state.delegated.add("child-only")
            second.state.base_commit = second.commit_id
            self.assertNotIn("child-only", base.delegated)

            seen = {"root", second.commit_id}
            for visit in walk:
                self.assertEqual(visit.state.base_commit, "root")
                seen.add(visit.commit_id)
                visit.state.base_commit = visit.commit_id
            self.assertEqual(seen, set(history.commits))
            self.assertIs(visit.state, base)
            self.assertEqual(copy.call_count, len(children) - 1)

    def test_light_first_comb_keeps_live_snapshots_bounded(self) -> None:
        commits = [make_commit("root", "outside")]
        parent = "root"
        for index in range(100):
            heavy = f"heavy-{index}"
            # Deliberately put the heavy continuation first, as in the old walk.
            commits.extend([make_commit(heavy, parent), make_commit(f"leaf-{index}", parent)])
            parent = heavy
        history = StructuredCommits.from_commits(commits)
        config = KernelConfig("")
        live: weakref.WeakSet[KbuildState] = weakref.WeakSet()
        maximum = 0
        original_copy = KbuildState.copy

        def track_copy(state: KbuildState) -> KbuildState:
            nonlocal maximum
            copied = original_copy(state)
            live.add(copied)
            maximum = max(maximum, len(live))
            return copied

        def create_state(commit_id: str) -> KbuildState:
            state = KbuildState(MemoryRepo(), config, "outside")
            live.add(state)
            return state

        seen: set[str] = set()
        with patch.object(KbuildState, "copy", side_effect=track_copy):
            for visit in _walk_history(history, create_state):
                parent_edge = history.commits[visit.commit_id].parent
                assert parent_edge is not None
                self.assertEqual(visit.state.base_commit, parent_edge.commit_id)
                visit.state.base_commit = visit.commit_id
                seen.add(visit.commit_id)
        self.assertEqual(seen, set(history.commits))
        self.assertLessEqual(maximum, 4)

    def test_roots_are_created_lazily_and_secondary_edges_do_not_revisit(self) -> None:
        first = make_commit("first", "outside")
        second = make_commit("second", "another-outside")
        merge = make_commit("merge", "first")
        merge.parents += (CommitParent("second", ""),)
        history = StructuredCommits.from_commits([merge, first, second])
        created: list[str] = []

        def create_state(commit_id: str) -> KbuildState:
            created.append(commit_id)
            parent = history.commits[commit_id].parent
            assert parent is not None
            return KbuildState(MemoryRepo(), KernelConfig(""), parent.commit_id)

        walk = _walk_history(history, create_state)
        visit = next(walk)
        self.assertEqual(len(created), 1)
        seen = [visit.commit_id]
        visit.state.base_commit = visit.commit_id
        for visit in walk:
            seen.append(visit.commit_id)
            visit.state.base_commit = visit.commit_id
        self.assertEqual(set(seen), set(history.commits))
        self.assertEqual(len(seen), len(history.commits))
        self.assertEqual(len(created), 2)


if __name__ == "__main__":
    unittest.main()
