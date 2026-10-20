import gc
from datetime import UTC, datetime
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
from kpatch.filter.config.history import ConfigHistoryStore, FileDecision, parse_history_diff
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


class ConfigHistoryStoreTests(unittest.TestCase):
    def test_history_roundtrip_and_insertion_order(self) -> None:
        first = ConfigFilter._history_diff(make_commit("z", "parent"))
        second = Diff.parse("")
        with ConfigHistoryStore() as store:
            store.add_history("z", first)
            store.add_history("a", second)
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
                store.add_history("duplicate", Diff.parse(""))
                store.add_history("duplicate", Diff.parse(""))
        self.assertFalse(path.parent.exists())

        abandoned = ConfigHistoryStore()
        abandoned_path = abandoned.path
        reference = weakref.ref(abandoned)
        del abandoned
        gc.collect()
        self.assertIsNone(reference())
        self.assertFalse(abandoned_path.parent.exists())

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
