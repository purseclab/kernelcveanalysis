import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from kpatch.diff import Diff, DiffFile, DiffFileType
from kpatch.filter.source_modes import regular_source_change
from kpatch.git import GitRepo


def file_change(old_mode: str | None, new_mode: str | None,
                change_type: DiffFileType = DiffFileType.DEFAULT, *,
                path: str = "unit.c", old_path: str | None = None) -> DiffFile:
    return DiffFile(path, old_path, old_mode, new_mode, change_type, False, [], [])


class SourceModeGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = GitRepo(Path("unused-mode-fixture"))

    def test_complete_regular_metadata_never_queries_git(self) -> None:
        for mode in ("100644", "100755"):
            with self.subTest(mode=mode), patch.object(self.repo, "read_file_mode") as read:
                self.assertTrue(regular_source_change(file_change(mode, mode), self.repo, "old", "new"))
                read.assert_not_called()

    def test_mode_change_role_is_separate_from_permission_equivalence(self) -> None:
        file = file_change("100644", "100755")
        self.assertTrue(file.mode_changed)
        with patch.object(self.repo, "read_file_mode") as read:
            self.assertTrue(regular_source_change(file, self.repo, "old", "new"))
            read.assert_not_called()

    def test_any_known_nonregular_mode_rejects_before_missing_mode_lookup(self) -> None:
        for mode in ("120000", "160000", "040000", "100664", ""):
            for old, new in ((mode, None), (None, mode), (mode, mode)):
                with self.subTest(old=old, new=new), patch.object(self.repo, "read_file_mode") as read:
                    self.assertFalse(regular_source_change(file_change(old, new), self.repo, "old", "new"))
                    read.assert_not_called()

    def test_unknown_modes_query_exact_revision_and_each_side_path(self) -> None:
        file = file_change(None, None, path="new name.c", old_path="old\nname.c")
        with patch.object(self.repo, "read_file_mode", side_effect=("100644", "100755")) as read:
            self.assertTrue(regular_source_change(file, self.repo, "parent", "child"))
        self.assertEqual([call.args for call in read.call_args_list], [("parent", "old\nname.c"), ("child", "new name.c")])

    def test_only_missing_mode_is_queried(self) -> None:
        with patch.object(self.repo, "read_file_mode", return_value="100644") as read:
            self.assertTrue(regular_source_change(file_change("100644", None), self.repo, "parent", "child"))
        read.assert_called_once_with("child", "unit.c")

    def test_new_and_deleted_files_query_only_existing_sides(self) -> None:
        for file, parent, expected in (
            (file_change(None, None, DiffFileType.NEW), None, ("child", "unit.c")),
            (file_change(None, None, DiffFileType.DELETE), "parent", ("parent", "unit.c")),
        ):
            with self.subTest(kind=file.change_type), patch.object(self.repo, "read_file_mode", return_value="100644") as read:
                self.assertTrue(regular_source_change(file, self.repo, parent, "child"))
                read.assert_called_once_with(*expected)

    def test_new_and_deleted_known_regular_metadata_avoid_queries(self) -> None:
        for file, parent in ((file_change(None, "100755", DiffFileType.NEW), None),
                             (file_change("100644", None, DiffFileType.DELETE), "parent")):
            with self.subTest(kind=file.change_type), patch.object(self.repo, "read_file_mode") as read:
                self.assertTrue(regular_source_change(file, self.repo, parent, "child"))
                read.assert_not_called()

    def test_missing_parent_cannot_authorize_an_existing_old_side(self) -> None:
        with patch.object(self.repo, "read_file_mode") as read:
            self.assertFalse(regular_source_change(file_change("100644", "100644"), self.repo, None, "child"))
            read.assert_not_called()

    def test_missing_nonregular_and_failed_lookup_remain_unknown(self) -> None:
        for mode in (None, "120000", "160000", "unexpected"):
            with self.subTest(mode=mode), patch.object(self.repo, "read_file_mode", return_value=mode):
                self.assertFalse(regular_source_change(file_change(None, "100644"), self.repo, "parent", "child"))
        for error in (OSError("unreadable"), ValueError("malformed"), subprocess.CalledProcessError(128, ["git"])):
            with self.subTest(error=error), patch.object(self.repo, "read_file_mode", side_effect=error):
                self.assertFalse(regular_source_change(file_change(None, None), self.repo, "parent", "child"))


class HistoricalGitModeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = GitRepo(self.root)
        self.git("init", "-q")
        self.git("config", "user.name", "Mode fixture")
        self.git("config", "user.email", "mode@example.invalid")
        self.paths = ("unit.c", "path with spaces.c", "colon:name.c", "odd\nfilename.c",
                      "literal[ab]*?.c", ":(exclude)*.c", "tab\tname.c", "sub dir/nested.c")
        for name in self.paths:
            file = self.root / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text("int value;\n")
        (self.root / "executable.c").write_text("int value;\n")
        (self.root / "executable.c").chmod(0o755)
        for name in ("one", "two"):
            directory = self.root / f"*{name}*"
            directory.mkdir()
            (directory / "header.h").write_text("#define VALUE 1\n")
        (self.root / "api.h").symlink_to("./*one*/header.h")
        self.git("add", ".")
        self.git("-c", "commit.gpgsign=false", "commit", "-qm", "parent")
        self.parent = self.git("rev-parse", "HEAD")

    def git(self, *arguments: str) -> str:
        return subprocess.check_output(["git", "-C", str(self.root), *arguments], stderr=subprocess.PIPE).decode().strip()

    def test_literal_paths_are_nul_framed_and_exact(self) -> None:
        for name in self.paths:
            with self.subTest(name=name):
                self.assertEqual(self.repo.read_file_mode(self.parent, name), "100644")
        self.assertEqual(self.repo.read_file_mode(self.parent, "executable.c"), "100755")
        self.assertIsNone(self.repo.read_file_mode(self.parent, "literal*.c"))
        self.assertIsNone(self.repo.read_file_mode(self.parent, "sub dir"))

    def test_symlink_witness_is_nonregular_with_and_without_index_modes(self) -> None:
        link = self.root / "api.h"
        link.unlink()
        link.symlink_to("./*two*/header.h")
        self.git("add", ".")
        self.git("-c", "commit.gpgsign=false", "commit", "-qm", "link target change")
        child = self.git("rev-parse", "HEAD")
        file = Diff.parse(self.git("diff", "--full-index", self.parent, child)).files[0]
        self.assertEqual((file.old_mode, file.new_mode), ("120000", "120000"))
        self.assertFalse(regular_source_change(file, self.repo, self.parent, child))
        self.assertEqual(self.repo.read_file_mode(self.parent, "api.h"), "120000")
        file.old_mode = file.new_mode = None
        self.assertFalse(regular_source_change(file, self.repo, self.parent, child))

    def test_unknown_regular_modes_are_authoritatively_resolved(self) -> None:
        self.assertTrue(regular_source_change(file_change(None, None), self.repo, self.parent, self.parent))
        self.assertFalse(regular_source_change(file_change(None, None, path="missing.c"), self.repo, self.parent, self.parent))
        self.assertFalse(regular_source_change(file_change(None, None), self.repo, "missing-revision", self.parent))

    def test_historical_mode_is_independent_of_current_worktree_and_head(self) -> None:
        file = self.root / "unit.c"
        file.unlink()
        file.symlink_to("executable.c")
        self.git("add", ".")
        self.git("-c", "commit.gpgsign=false", "commit", "-qm", "change role")
        child = self.git("rev-parse", "HEAD")
        self.assertEqual(self.repo.read_file_mode(self.parent, "unit.c"), "100644")
        self.assertEqual(self.repo.read_file_mode(child, "unit.c"), "120000")
        self.assertFalse(regular_source_change(file_change(None, None), self.repo, self.parent, child))

    def test_git_environment_cannot_expand_literal_path_to_other_rows(self) -> None:
        for values in ({"GIT_GLOB_PATHSPECS": "1"}, {"GIT_NOGLOB_PATHSPECS": "1"},
                       {"GIT_LITERAL_PATHSPECS": "0"}, {"GIT_ICASE_PATHSPECS": "1"}):
            with self.subTest(values=values), patch.dict(os.environ, values):
                try:
                    mode = self.repo.read_file_mode(self.parent, "literal[ab]*?.c")
                except subprocess.CalledProcessError:
                    continue
                self.assertEqual(mode, "100644")


class GitModeProtocolTests(unittest.TestCase):
    def test_only_one_exact_blob_row_establishes_a_mode(self) -> None:
        repo = GitRepo(Path("unused-mode-fixture"))
        oid = b"1" * 40
        valid = b"100644 blob " + oid + b"\tunit.c\0"
        malformed = (b"", valid[:-1], valid + valid, valid.replace(b"unit.c", b"different.c"),
                     valid.replace(b"blob", b"tree"), valid.replace(b"100644", b"040000"),
                     valid.replace(oid, b"not-an-object"), valid + b"tail", valid.replace(b"\t", b" "))
        for output in malformed:
            with self.subTest(output=output), patch.object(repo, "_run_git", return_value=output):
                self.assertIsNone(repo.read_file_mode("revision", "unit.c"))
        for width in (40, 64):
            output = b"100755 blob " + b"a" * width + b"\tunit.c\0"
            with self.subTest(width=width), patch.object(repo, "_run_git", return_value=output):
                self.assertEqual(repo.read_file_mode("revision", "unit.c"), "100755")


if __name__ == "__main__":
    unittest.main()
