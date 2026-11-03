from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest

from kpatch.filter import FilteredCommit, LineRange, MaskReason, SourceSide, SourceVersions
from kpatch.git import CommitParent, GitCommit


class MaskingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Test")

    def git(self, *arguments: str, patch: str | None = None) -> str:
        result = subprocess.run(["git", "-C", str(self.path), *arguments], input=patch,
                                text=True, capture_output=True, check=True)
        return result.stdout

    def view(self, old: str, new: str) -> FilteredCommit:
        self.sources = SourceVersions(old.encode(), new.encode())
        source = self.path / "unit.c"
        source.write_bytes(self.sources.old)
        self.git("add", ".")
        self.git("commit", "-qm", "parent", "--allow-empty")
        parent = self.git("rev-parse", "HEAD").strip()
        source.write_bytes(self.sources.new)
        self.git("add", ".")
        self.git("commit", "-qm", "child", "--allow-empty")
        child = self.git("rev-parse", "HEAD").strip()
        diff = self.git("diff", parent, child)
        date = datetime(2025, 10, 16, tzinfo=UTC)
        return FilteredCommit(GitCommit(child, "", "", date, date, (CommitParent(parent, diff),), ""))

    def test_edit_projection_keeps_parent_text_and_original_coordinates(self) -> None:
        view = self.view("int value = 1;\nint other = 3;\n", "int value = 2;\nint extra = 9;\nint other = 4;\n")
        snapshot = view.original_diff
        file = view.diff.files[0]
        view.mask_edits(file, (LineRange(1, 2),), (LineRange(1, 3),), MaskReason.FILE_SELECTION)
        expected = b"int value = 1;\nint other = 4;\n"
        self.assertEqual(view.effective_sources(file, self.sources).new, expected)
        self.assertEqual(view.active_sources(file, self.sources).new, expected)
        self.assertEqual(view.changed_lines(file, SourceSide.NEW), frozenset({3}))
        self.assertIs(view.original_diff, snapshot)
        self.assertEqual(snapshot.text, view.original.diff_str)
        (self.path / "unit.c").write_bytes(self.sources.old)
        patch = view.remaining_diff().text
        self.git("apply", "--check", patch=patch)
        self.git("apply", patch=patch)
        self.assertEqual((self.path / "unit.c").read_bytes(), expected)

    def test_original_snapshot_is_deeply_immutable(self) -> None:
        view = self.view("int value = 1;\n", "int value = 2;\n")
        file = view.original_diff.files[0]
        with self.assertRaises(FrozenInstanceError):
            file.file = "different.c"  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            file.chunks[0].lines += ("+unexpected",)  # type: ignore[misc]

    def test_code_masks_preserve_file_metadata_while_file_edit_masks_remove_it(self) -> None:
        patch = "diff --git a/unit.c b/unit.c\nold mode 100644\nnew mode 100755\n"
        date = datetime(2025, 10, 16, tzinfo=UTC)
        view = FilteredCommit(GitCommit("child", "", "", date, date, (CommitParent("parent", patch),), ""))
        file = view.diff.files[0]
        for side in SourceSide:
            view.mask_code(file, side, (), MaskReason.IFDEF, whole_file=True)
        self.assertTrue(view.remaining_diff().files[0].mode_changed)
        view.mask_file(file, MaskReason.FILE_SELECTION)
        self.assertEqual(view.remaining_diff().files, [])

    def test_code_masks_blank_unchanged_code_without_resurrecting_old_lines(self) -> None:
        old = "#if 0\nint old_name = 1;\nint unchanged = old_name;\n#endif\nint active = 1;\n"
        new = old.replace("old_name = 1", "new_name = 2").replace("active = 1", "active = 2")
        view = self.view(old, new)
        file = view.diff.files[0]
        for side in SourceSide:
            view.mask_code(file, side, (LineRange(2, 4),), MaskReason.IFDEF)
        active = view.active_sources(file, self.sources)
        self.assertNotIn(b"old_name", active.old + active.new)
        self.assertNotIn(b"unchanged", active.old + active.new)
        self.assertEqual(len(active.old), len(self.sources.old))
        self.assertEqual(len(active.new), len(self.sources.new))
        self.assertEqual(active.new.count(b"\n"), new.count("\n"))
        effective = view.effective_sources(file, self.sources)
        self.assertIn(b"int old_name = 1;", effective.new)
        self.assertNotIn(b"new_name", effective.new)
        self.assertIn(b"int active = 2;", effective.new)

    def test_no_newline_markers_survive_masked_deletion(self) -> None:
        view = self.view("int a;\nint b;", "int a;\nint c;\nint d;")
        file = view.diff.files[0]
        view.mask_edits(file, (LineRange(2, 3),), (LineRange(2, 4),), MaskReason.FILE_SELECTION)
        self.assertEqual(view.effective_sources(file, self.sources).new, self.sources.old)
        self.assertEqual(view.remaining_diff().files, [])

    def test_ambiguous_partial_eof_selection_retains_a_valid_original_patch(self) -> None:
        view = self.view("int a;", "int b;\nint c;")
        file = view.diff.files[0]
        view.mask_edits(file, (LineRange(1, 2),), (), MaskReason.FILE_SELECTION)
        self.assertEqual(view.effective_sources(file, self.sources).new, self.sources.new)
        self.assertEqual(view.active_sources(file, self.sources).new, self.sources.new)
        (self.path / "unit.c").write_bytes(self.sources.old)
        self.git("apply", "--check", patch=view.remaining_diff().text)
        self.git("apply", patch=view.remaining_diff().text)
        self.assertEqual((self.path / "unit.c").read_bytes(), self.sources.new)

    def test_sources_must_match_the_exact_parent_and_child(self) -> None:
        view = self.view("int value = 1;\n", "int value = 2;\n")
        file = view.diff.files[0]
        with self.assertRaisesRegex(ValueError, "mismatch"):
            view.effective_sources(file, SourceVersions(b"int other;\n", self.sources.new))

    def test_multiple_hunks_keep_original_side_masks_after_offset_changes(self) -> None:
        old = "int a;\n" + "/* gap */\n" * 20 + "int b = 1;\n"
        new = "int inserted;\nint a;\n" + "/* gap */\n" * 20 + "int b = 2;\n"
        view = self.view(old, new)
        file = view.diff.files[0]
        view.mask_edits(file, (), (LineRange(1, 2),), MaskReason.FILE_SELECTION)
        expected = old.replace("b = 1", "b = 2").encode()
        self.assertEqual(view.effective_sources(file, self.sources).new, expected)
        (self.path / "unit.c").write_bytes(self.sources.old)
        self.git("apply", "--check", patch=view.remaining_diff().text)
        self.git("apply", patch=view.remaining_diff().text)
        self.assertEqual((self.path / "unit.c").read_bytes(), expected)


if __name__ == "__main__":
    unittest.main()
