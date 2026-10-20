from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from pydantic import ValidationError

from kpatch.diff import Diff
from kpatch.filter.source_filter import (
    SourceIncludeIndex,
    _GLOBAL_TARGET_CACHE_SIZE,
    _iter_git_output,
)
from kpatch.git import GitRepo


@dataclass
class GitOutputProcess:
    stdout: BytesIO
    exit_code: int = 0
    running: bool = True
    killed: bool = False

    def wait(self) -> int:
        self.running = False
        return self.exit_code

    def poll(self) -> int | None:
        return None if self.running else self.exit_code

    def kill(self) -> None:
        self.killed = True


class GitOutputTests(unittest.TestCase):
    def test_records_cross_chunk_boundaries_and_keep_unterminated_tail(self) -> None:
        records = [b"a" * 65535, b"b" * 65537, b"tail"]
        process = GitOutputProcess(BytesIO(b"\0".join(records)))
        with patch("kpatch.filter.source_filter.subprocess.Popen", return_value=process):
            result = list(_iter_git_output(GitRepo(Path("unused")), [], b"\0", (0,)))

        self.assertEqual(result, records)
        self.assertTrue(process.stdout.closed)
        self.assertFalse(process.running)
        self.assertFalse(process.killed)

    def test_closing_iterator_terminates_and_reaps_the_process(self) -> None:
        process = GitOutputProcess(BytesIO(b"first\nsecond\n"))
        with patch("kpatch.filter.source_filter.subprocess.Popen", return_value=process):
            output = _iter_git_output(GitRepo(Path("unused")), [], b"\n", (0,))
            self.assertEqual(next(output), b"first")
            output.close()

        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.killed)
        self.assertFalse(process.running)

    def test_failed_command_is_not_mistaken_for_empty_output(self) -> None:
        process = GitOutputProcess(BytesIO(), exit_code=128)
        with patch("kpatch.filter.source_filter.subprocess.Popen", return_value=process):
            with self.assertRaises(subprocess.CalledProcessError) as raised:
                list(_iter_git_output(GitRepo(Path("unused")), [], b"\n", (0, 1)))

        self.assertEqual(raised.exception.returncode, 128)
        self.assertTrue(process.stdout.closed)
        self.assertFalse(process.running)


class SourceIncludeIndexTests(unittest.TestCase):
    def test_include_search_order_is_unchanged(self) -> None:
        paths = (
            "drivers/example/shared.h",
            "arch/arm64/include/shared.h",
            "include/shared.h",
            "arch/arm64/include/uapi/shared.h",
            "include/uapi/shared.h",
            "shared.h",
        )
        for offset, expected in enumerate(paths):
            with self.subTest(expected=expected):
                index = SourceIncludeIndex("arm64", paths[offset:])
                self.assertEqual(
                    index.target_from_line("drivers/example/wrapper.c", '#include "shared.h"'),
                    expected,
                )
                self.assertEqual(
                    index.target_from_line("drivers/example/wrapper.c", "#include <shared.h>"),
                    paths[max(1, offset)],
                )

    def test_quoted_local_resolution_is_not_shared_between_directories(self) -> None:
        index = SourceIncludeIndex("arm64", ("one/local.h", "two/local.h"))
        for folder in ("one", "two", "one"):
            self.assertEqual(
                index.target_from_line(f"{folder}/wrapper.c", '#include "local.h"'),
                f"{folder}/local.h",
            )

    def test_normalization_supported_extensions_and_nonliteral_includes(self) -> None:
        index = SourceIncludeIndex(
            "arm64",
            ("drivers/local.h", "drivers/impl.c", "drivers/entry.S", "drivers/data.inc"),
        )
        for requested in ("../local.h", "../impl.c", "../entry.S"):
            with self.subTest(requested=requested):
                self.assertEqual(
                    index.target_from_line("drivers/sub/wrapper.c", f'  # include "{requested}"'),
                    f"drivers/{Path(requested).name}",
                )
        for line in (
            '#include "../data.inc"',
            '#include "$(header).h"',
            "#include HEADER",
            "// #include <local.h>",
            '#include ""',
        ):
            with self.subTest(line=line):
                self.assertIsNone(index.target_from_line("drivers/sub/wrapper.c", line))

    def test_new_paths_invalidate_cached_misses_and_lower_priority_matches(self) -> None:
        index = SourceIncludeIndex("arm64", ("include/shared.h",))
        self.assertEqual(
            index.target_from_line("wrapper.c", "#include <shared.h>"),
            "include/shared.h",
        )
        self.assertIsNone(index.target_from_line("wrapper.c", "#include <new.h>"))

        index.add_paths(iter(("arch/arm64/include/shared.h", "include/new.h")))

        self.assertEqual(
            index.target_from_line("wrapper.c", "#include <shared.h>"),
            "arch/arm64/include/shared.h",
        )
        self.assertEqual(
            index.target_from_line("wrapper.c", "#include <new.h>"),
            "include/new.h",
        )

    def test_cached_resolution_uses_the_current_source_architecture(self) -> None:
        index = SourceIncludeIndex(
            "arm64", ("arch/arm64/include/asm/shared.h", "arch/x86/include/asm/shared.h")
        )
        self.assertEqual(
            index.target_from_line("wrapper.c", "#include <asm/shared.h>"),
            "arch/arm64/include/asm/shared.h",
        )
        index.srcarch = "x86"
        self.assertEqual(
            index.target_from_line("wrapper.c", "#include <asm/shared.h>"),
            "arch/x86/include/asm/shared.h",
        )

    def test_global_resolution_cache_is_bounded(self) -> None:
        index = SourceIncludeIndex("arm64")
        for number in range(_GLOBAL_TARGET_CACHE_SIZE * 2):
            index.target_from_line("wrapper.c", f"#include <missing_{number}.h>")

        self.assertLessEqual(len(index._global_targets), _GLOBAL_TARGET_CACHE_SIZE)

    def test_edges_share_canonical_path_strings(self) -> None:
        source = "drivers/" + "wrapper.c"
        target = "include/linux/" + "shared.h"
        index = SourceIncludeIndex("arm64", (source, target, "drivers/second.c"))
        index.add_line(source.encode().decode(), "#include <linux/shared.h>")
        index.add_line("drivers/second.c", "#include <linux/shared.h>")

        self.assertIs(index.includers(target)[1], source)
        self.assertIs(next(iter(index._targets[source])), target)
        self.assertIs(next(iter(index._targets["drivers/second.c"])), target)

    def test_sorted_includers_are_reused_and_invalidated_when_edges_change(self) -> None:
        index = SourceIncludeIndex("arm64", ("include/shared.h",))
        for source in ("z.h", "b.c", "a.S", "a.h"):
            index.add_line(source, "#include <shared.h>")
        first = index.includers("include/shared.h")
        self.assertEqual(first, ("a.S", "b.c", "a.h", "z.h"))
        self.assertIs(index.includers("include/shared.h"), first)

        index.add_line("b.c", "#include <shared.h>")
        self.assertIs(index.includers("include/shared.h"), first)
        index.add_line("c.c", "#include <shared.h>")
        self.assertEqual(
            index.includers("include/shared.h"),
            ("a.S", "b.c", "c.c", "a.h", "z.h"),
        )
        self.assertEqual(index.includers("missing.h"), ())

    def test_pure_rename_invalidates_sorted_includers_and_preserves_both_sources(self) -> None:
        index = SourceIncludeIndex("arm64", ("old.c", "shared.h"))
        index.add_line("old.c", '#include "shared.h"')
        self.assertEqual(index.includers("shared.h"), ("old.c",))
        index.add_diff(Diff.parse(
            "diff --git a/old.c b/new.c\n"
            "similarity index 100%\n"
            "rename from old.c\n"
            "rename to new.c\n"
        ))

        self.assertEqual(index.includers("shared.h"), ("new.c", "old.c"))
        self.assertEqual(index.dependent_targets(("new.c",)), frozenset(("shared.h",)))

    def test_added_and_removed_include_lines_remain_candidates(self) -> None:
        index = SourceIncludeIndex("arm64", ("before.h", "after.h"))
        index.add_diff(Diff.parse(
            "diff --git a/wrapper.c b/wrapper.c\n"
            "--- a/wrapper.c\n"
            "+++ b/wrapper.c\n"
            "@@ -1 +1 @@\n"
            '-#include "before.h"\n'
            '+#include "after.h"\n'
        ))

        self.assertEqual(index.includers("before.h"), ("wrapper.c",))
        self.assertEqual(index.includers("after.h"), ("wrapper.c",))
        self.assertEqual(
            index.dependent_targets(("wrapper.c",)),
            frozenset(("before.h", "after.h")),
        )

    def test_transitive_targets_handle_cycles_diamonds_and_duplicate_roots(self) -> None:
        paths = ("wrapper.c", "left.h", "right.h", "shared.h")
        index = SourceIncludeIndex("arm64", paths)
        for source, target in (
            ("wrapper.c", "left.h"),
            ("wrapper.c", "right.h"),
            ("left.h", "shared.h"),
            ("right.h", "shared.h"),
            ("shared.h", "left.h"),
        ):
            index.add_line(source, f'#include "{target}"')

        self.assertEqual(index.transitive_targets(iter(("wrapper.c",) * 3)), frozenset(paths))
        self.assertEqual(index.dependent_targets(("wrapper.c",)), frozenset(paths[1:]))
        self.assertEqual(index.transitive_targets(("unknown.c",)), frozenset(("unknown.c",)))
        self.assertEqual(index.transitive_targets(()), frozenset())


class SourceIncludeSnapshotTests(unittest.TestCase):
    def test_snapshot_preserves_resolution_aliases_edges_and_untracked_sources(self) -> None:
        index = SourceIncludeIndex("arm64", (
            "drivers/wrapper.c", "drivers/local.h", "drivers/entry.S",
            "arch/arm64/include/shared.h", "include/shared.h",
            "arch/x86/include/shared.h", "include/unused.h", "unused.c",
        ))
        index.add_line("drivers/wrapper.c", '#include "local.h"')
        index.add_line("drivers/local.h", "#include <shared.h>")
        index.add_line("drivers/entry.S", '#include "local.h"')
        index.add_line("untracked.inc", "#include <shared.h>")
        index.add_diff(Diff.parse(
            "diff --git a/drivers/wrapper.c b/drivers/renamed.c\n"
            "similarity index 100%\nrename from drivers/wrapper.c\nrename to drivers/renamed.c\n"
            "diff --git a/untracked.inc b/alias.inc\n"
            "similarity index 100%\nrename from untracked.inc\nrename to alias.inc\n"
        ))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "includes.json"
            index.write_snapshot(path)
            with patch("kpatch.filter.source_filter._iter_git_output", side_effect=AssertionError("Git must not run")):
                restored = SourceIncludeIndex.read_snapshot(path)

        self.assertEqual(restored.srcarch, index.srcarch)
        self.assertEqual(restored._tracked_paths, index._tracked_paths)
        self.assertNotIn("untracked.inc", restored._tracked_paths)
        self.assertNotIn("alias.inc", restored._tracked_paths)
        self.assertEqual(restored._targets, index._targets)
        for target in index._tracked_paths:
            self.assertEqual(restored.includers(target), index.includers(target))
        for source in (*index._tracked_paths, "untracked.inc", "alias.inc", "unknown.c"):
            self.assertEqual(restored.transitive_targets((source,)), index.transitive_targets((source,)))
            self.assertEqual(restored.dependent_targets((source,)), index.dependent_targets((source,)))
            for line in ('#include "local.h"', "#include <shared.h>", "#include <unused.h>"):
                self.assertEqual(restored.target_from_line(source, line), index.target_from_line(source, line))
        for candidate in (index, restored):
            candidate.srcarch = "x86"
        self.assertEqual(restored.target_from_line("unknown.c", "#include <shared.h>"),
                         index.target_from_line("unknown.c", "#include <shared.h>"))

    def test_restored_edges_share_vocabulary_strings(self) -> None:
        index = SourceIncludeIndex("arm64", ("include/shared.h", "one.c", "two.c"))
        for source in ("one.c", "two.c", "untracked.inc"):
            index.add_line(source, "#include <shared.h>")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "includes.json"
            index.write_snapshot(path)
            restored = SourceIncludeIndex.read_snapshot(path)

        target = restored._tracked_paths["include/shared.h"]
        for source, targets in restored._targets.items():
            self.assertIs(next(iter(targets)), target)
            includer = next(path for path in restored.includers(target) if path == source)
            self.assertIs(includer, source)
            if source in restored._tracked_paths:
                self.assertIs(source, restored._tracked_paths[source])

    def test_empty_edges_and_post_restore_path_additions_preserve_lookup(self) -> None:
        index = SourceIncludeIndex("arm64", ("include/shared.h", "unused.c"))
        index.target_from_line("unknown.c", "#include <shared.h>")
        index.target_from_line("unknown.c", "#include <missing.h>")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "includes.json"
            index.write_snapshot(path)
            restored = SourceIncludeIndex.read_snapshot(path)

        self.assertEqual(restored.includers("include/shared.h"), ())
        self.assertEqual(restored.target_from_line("unknown.c", "#include <shared.h>"), "include/shared.h")
        restored.add_paths(("arch/arm64/include/shared.h", "include/missing.h"))
        self.assertEqual(restored.target_from_line("unknown.c", "#include <shared.h>"),
                         "arch/arm64/include/shared.h")
        self.assertEqual(restored.target_from_line("unknown.c", "#include <missing.h>"), "include/missing.h")

    def test_empty_index_roundtrips(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.json"
            SourceIncludeIndex("arm64").write_snapshot(path)
            restored = SourceIncludeIndex.read_snapshot(path)
        self.assertEqual(restored.srcarch, "arm64")
        self.assertEqual(restored._tracked_paths, {})
        self.assertEqual(restored.transitive_targets(("unknown.c",)), frozenset(("unknown.c",)))

    def test_invalid_snapshot_ids_and_schema_are_rejected(self) -> None:
        valid = (
            '{"version":1,"srcarch":"arm64","paths":["include/shared.h","untracked.c"],'
            '"tracked_path_count":1,"adjacency":[[],[0]]}'
        )
        invalid = [
            valid.replace("[[],[0]]", "[[],[-1]]"),
            valid.replace("[[],[0]]", "[[],[1]]"),
            valid.replace("[[],[0]]", "[[],[2]]"),
            valid.replace("[[],[0]]", '[[],["0"]]'),
            valid.replace("[[],[0]]", "[[],[true]]"),
            valid.replace("[[],[0]]", "[[],[0,0]]"),
            valid.replace("[[],[0]]", "[[0]]"),
            valid.replace('"tracked_path_count":1', '"tracked_path_count":-1'),
            valid.replace('"tracked_path_count":1', '"tracked_path_count":3'),
            valid.replace('"tracked_path_count":1', '"tracked_path_count":true'),
            valid.replace('"untracked.c"', '"include/shared.h"'),
            valid.replace('"include/shared.h"', '"include/shared.inc"'),
            valid.replace('"version":1', '"version":2'),
            valid[:-1] + ',"unexpected":true}',
            "not JSON",
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            for payload in invalid:
                with self.subTest(payload=payload):
                    path.write_text(payload, encoding="utf-8")
                    with self.assertRaises(ValidationError):
                        SourceIncludeIndex.read_snapshot(path)


class RepositorySourceIncludeIndexTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = GitRepo(self.root)
        self.git("init", "-q")

    def git(self, *args: str) -> bytes:
        return subprocess.run(
            ["git", "-C", str(self.root), *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout

    def commit(self, files: dict[str, str]) -> str:
        for name, contents in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents)
        self.git("add", ".")
        self.git(
            "-c", "user.name=Test", "-c", "user.email=test@example.com",
            "commit", "-qm", "fixture",
        )
        return self.git("rev-parse", "HEAD").decode().strip()

    def test_repository_snapshot_includes_extra_paths_and_source_assembly(self) -> None:
        commit = self.commit({
            "drivers/wrapper.c": (
                '#include "local.h"\n'
                '#include "removed.c"\n'
                '#include "ignored.inc"\n'
                "#ifdef CONFIG_DISABLED\n#include <linux/shared.h>\n#endif\n"
            ),
            "drivers/local.h": "#include <linux/shared.h>\n",
            "drivers/entry.S": '# include "local.h"\n',
            "drivers/ignored.inc": '#include "local.h"\n',
            "include/linux/shared.h": "struct shared;\n",
        })
        (self.root / "drivers/wrapper.c").write_text("/* working tree differs */\n")
        index = SourceIncludeIndex.from_repository(
            self.repo, commit, "arm64", iter(("drivers/removed.c",))
        )

        self.assertEqual(
            index.includers("drivers/local.h"),
            ("drivers/entry.S", "drivers/wrapper.c"),
        )
        self.assertEqual(index.includers("drivers/removed.c"), ("drivers/wrapper.c",))
        self.assertEqual(index.includers("drivers/ignored.inc"), ())
        self.assertEqual(
            index.includers("include/linux/shared.h"),
            ("drivers/wrapper.c", "drivers/local.h"),
        )
        self.assertEqual(
            index.dependent_targets(("drivers/entry.S",)),
            frozenset(("drivers/local.h", "include/linux/shared.h")),
        )

    def test_no_include_matches_is_a_successful_empty_index(self) -> None:
        commit = self.commit({
            "drivers/plain.c": "int plain;\n",
            "include/plain.h": "struct plain;\n",
        })
        index = SourceIncludeIndex.from_repository(self.repo, commit, "arm64")

        self.assertEqual(index.includers("include/plain.h"), ())
        self.assertEqual(
            index.target_from_line("drivers/plain.c", "#include <plain.h>"),
            "include/plain.h",
        )

    def test_invalid_snapshot_raises_instead_of_returning_empty_index(self) -> None:
        self.commit({"plain.c": "int plain;\n"})
        with self.assertRaises(subprocess.CalledProcessError):
            SourceIncludeIndex.from_repository(self.repo, "missing-commit", "arm64")


if __name__ == "__main__":
    unittest.main()
