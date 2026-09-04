import unittest
from datetime import UTC, datetime

from kpatch.diff import Diff, DiffChunk, DiffFile, DiffFileType
from kpatch.filter import filter_commits
from kpatch.filter.config_filter import ConfigFilter, ConfigValue, KernelConfig
from kpatch.filter.ifdef_filter import (
    diff_file_touches_active_code,
    evaluate_condition,
    evaluate_ifdef,
    evaluate_ifndef,
    get_active_lines,
    is_c_source_file,
)
from kpatch.git import CommitParent, GitCommit, GitRepo


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


class IfdefFilterUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = KernelConfig(
            """
            CONFIG_ENABLED=y
            CONFIG_MODULE=m
            # CONFIG_DISABLED is not set
            CONFIG_CPUS=64
            CONFIG_NAME="test"
            """
        )

    def test_is_c_source_file(self) -> None:
        self.assertTrue(is_c_source_file("kernel/fork.c"))
        self.assertTrue(is_c_source_file("include/linux/sched.h"))
        self.assertTrue(is_c_source_file("arch/x86/entry/entry_64.S"))
        self.assertFalse(is_c_source_file("drivers/Makefile"))
        self.assertFalse(is_c_source_file("Kconfig"))
        self.assertFalse(is_c_source_file("Documentation/index.rst"))

    def test_evaluate_ifdef_and_ifndef(self) -> None:
        # CONFIG_ENABLED=y
        self.assertTrue(evaluate_ifdef("CONFIG_ENABLED", self.config))
        self.assertFalse(evaluate_ifndef("CONFIG_ENABLED", self.config))

        # CONFIG_MODULE=m (in autoconf, CONFIG_MODULE is not defined, CONFIG_MODULE_MODULE is)
        self.assertFalse(evaluate_ifdef("CONFIG_MODULE", self.config))
        self.assertTrue(evaluate_ifndef("CONFIG_MODULE", self.config))
        self.assertTrue(evaluate_ifdef("CONFIG_MODULE_MODULE", self.config))
        self.assertFalse(evaluate_ifndef("CONFIG_MODULE_MODULE", self.config))

        # CONFIG_DISABLED is not set
        self.assertFalse(evaluate_ifdef("CONFIG_DISABLED", self.config))
        self.assertTrue(evaluate_ifndef("CONFIG_DISABLED", self.config))

        # Integer config
        self.assertTrue(evaluate_ifdef("CONFIG_CPUS", self.config))
        self.assertFalse(evaluate_ifndef("CONFIG_CPUS", self.config))

        # Standard non-config symbols
        self.assertTrue(evaluate_ifdef("__KERNEL__", self.config))
        self.assertFalse(evaluate_ifndef("__KERNEL__", self.config))
        self.assertFalse(evaluate_ifdef("__cplusplus", self.config))
        self.assertTrue(evaluate_ifndef("__cplusplus", self.config))

        # MODULE symbol
        self.assertTrue(evaluate_ifdef("MODULE", self.config, is_module=True))
        self.assertFalse(evaluate_ifdef("MODULE", self.config, is_module=False))

        # Unknown non-config symbols: conservative handling (both evaluate to True)
        self.assertTrue(evaluate_ifdef("DEBUG", self.config))
        self.assertTrue(evaluate_ifndef("_LINUX_FOO_H", self.config))

    def test_evaluate_condition(self) -> None:
        # IS_ENABLED: y or m
        self.assertTrue(evaluate_condition("IS_ENABLED(CONFIG_ENABLED)", self.config))
        self.assertTrue(evaluate_condition("IS_ENABLED(CONFIG_MODULE)", self.config))
        self.assertFalse(evaluate_condition("IS_ENABLED(CONFIG_DISABLED)", self.config))

        # IS_BUILTIN: only y
        self.assertTrue(evaluate_condition("IS_BUILTIN(CONFIG_ENABLED)", self.config))
        self.assertFalse(evaluate_condition("IS_BUILTIN(CONFIG_MODULE)", self.config))
        self.assertFalse(evaluate_condition("IS_BUILTIN(CONFIG_DISABLED)", self.config))

        # IS_MODULE: only m
        self.assertFalse(evaluate_condition("IS_MODULE(CONFIG_ENABLED)", self.config))
        self.assertTrue(evaluate_condition("IS_MODULE(CONFIG_MODULE)", self.config))
        self.assertFalse(evaluate_condition("IS_MODULE(CONFIG_DISABLED)", self.config))

        # IS_REACHABLE
        self.assertTrue(evaluate_condition("IS_REACHABLE(CONFIG_ENABLED)", self.config, is_module=False))
        self.assertFalse(evaluate_condition("IS_REACHABLE(CONFIG_MODULE)", self.config, is_module=False))
        self.assertTrue(evaluate_condition("IS_REACHABLE(CONFIG_MODULE)", self.config, is_module=True))

        # defined(...)
        self.assertTrue(evaluate_condition("defined(CONFIG_ENABLED)", self.config))
        self.assertFalse(evaluate_condition("defined(CONFIG_MODULE)", self.config))
        self.assertTrue(evaluate_condition("defined(CONFIG_MODULE_MODULE)", self.config))
        self.assertFalse(evaluate_condition("defined(CONFIG_DISABLED)", self.config))

        # Boolean logic
        self.assertTrue(
            evaluate_condition(
                "IS_ENABLED(CONFIG_ENABLED) && !IS_ENABLED(CONFIG_DISABLED)",
                self.config,
            )
        )
        self.assertFalse(
            evaluate_condition(
                "IS_ENABLED(CONFIG_ENABLED) && IS_ENABLED(CONFIG_DISABLED)",
                self.config,
            )
        )
        self.assertTrue(
            evaluate_condition(
                "IS_ENABLED(CONFIG_DISABLED) || IS_ENABLED(CONFIG_MODULE)",
                self.config,
            )
        )

        # Comparisons and arithmetic
        self.assertTrue(evaluate_condition("CONFIG_CPUS > 32", self.config))
        self.assertFalse(evaluate_condition("CONFIG_CPUS > 128", self.config))
        self.assertTrue(evaluate_condition("CONFIG_CPUS == 64", self.config))
        self.assertTrue(evaluate_condition("CONFIG_CPUS != 0", self.config))

        # Comments
        self.assertTrue(
            evaluate_condition(
                "/* check */ IS_ENABLED(CONFIG_ENABLED) // enabled",
                self.config,
            )
        )

        # Literals
        self.assertTrue(evaluate_condition("1", self.config))
        self.assertFalse(evaluate_condition("0", self.config))

    def test_get_active_lines_no_config(self) -> None:
        code = "int a = 1;\nint b = 2;\nint c = 3;\n"
        active = get_active_lines(code, self.config)
        self.assertEqual(active, {1, 2, 3})

    def test_get_active_lines_simple_ifdef(self) -> None:
        code = (
            "int a = 1;\n"           # 1 (active)
            "#ifdef CONFIG_DISABLED\n" # 2 (active directive)
            "int b = 2;\n"           # 3 (inactive)
            "#else\n"                 # 4 (active directive)
            "int c = 3;\n"           # 5 (active)
            "#endif\n"                # 6 (active directive)
            "int d = 4;\n"           # 7 (active)
        )
        active = get_active_lines(code, self.config)
        self.assertIn(1, active)
        self.assertIn(2, active)
        self.assertNotIn(3, active)
        self.assertIn(4, active)
        self.assertIn(5, active)
        self.assertIn(6, active)
        self.assertIn(7, active)

    def test_get_active_lines_nested_ifdef(self) -> None:
        code = (
            "#ifdef CONFIG_DISABLED\n"  # 1 (active directive)
            "  #ifdef CONFIG_ENABLED\n"  # 2 (inactive directive inside disabled block)
            "  int x = 1;\n"             # 3 (inactive)
            "  #endif\n"                 # 4 (inactive directive)
            "#else\n"                   # 5 (active directive)
            "  #ifdef CONFIG_ENABLED\n"  # 6 (active directive)
            "  int y = 2;\n"             # 7 (active)
            "  #endif\n"                 # 8 (active directive)
            "#endif\n"                  # 9 (active directive)
        )
        active = get_active_lines(code, self.config)
        self.assertIn(1, active)
        self.assertNotIn(2, active)
        self.assertNotIn(3, active)
        self.assertNotIn(4, active)
        self.assertIn(5, active)
        self.assertIn(6, active)
        self.assertIn(7, active)
        self.assertIn(8, active)
        self.assertIn(9, active)

    def test_get_active_lines_elif(self) -> None:
        code = (
            "#if IS_ENABLED(CONFIG_DISABLED)\n"  # 1 (active directive)
            "int branch_1 = 1;\n"                # 2 (inactive)
            "#elif IS_ENABLED(CONFIG_MODULE)\n"   # 3 (active directive)
            "int branch_2 = 2;\n"                # 4 (active)
            "#else\n"                            # 5 (active directive)
            "int branch_3 = 3;\n"                # 6 (inactive)
            "#endif\n"                           # 7 (active directive)
        )
        active = get_active_lines(code, self.config)
        self.assertNotIn(2, active)
        self.assertIn(4, active)
        self.assertNotIn(6, active)

    def test_get_active_lines_multiline_continuation(self) -> None:
        code = (
            "#if defined(CONFIG_DISABLED) || \\\n"  # 1
            "    defined(CONFIG_ENABLED)\n"         # 2
            "int ok = 1;\n"                         # 3 (active)
            "#endif\n"                              # 4
        )
        active = get_active_lines(code, self.config)
        self.assertIn(1, active)
        self.assertIn(2, active)
        self.assertIn(3, active)
        self.assertIn(4, active)


class DiffTouchesActiveCodeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = KernelConfig(
            """
            CONFIG_ENABLED=y
            CONFIG_MODULE=m
            # CONFIG_DISABLED is not set
            """
        )

    def test_touches_active_code_in_file(self) -> None:
        old_code = (
            "int common = 1;\n"
            "#ifdef CONFIG_DISABLED\n"
            "int disabled_val = 10;\n"
            "#endif\n"
            "int active_val = 20;\n"
        )
        new_code = (
            "int common = 1;\n"
            "#ifdef CONFIG_DISABLED\n"
            "int disabled_val = 99;\n"
            "#endif\n"
            "int active_val = 20;\n"
        )

        repo = MemoryGitRepo({
            "c0:drivers/foo.c": old_code,
            "c1:drivers/foo.c": new_code,
        })

        # Diff modifying disabled_val on line 3
        diff_file_disabled = DiffFile(
            file="drivers/foo.c",
            old_file="drivers/foo.c",
            old_mode=None,
            new_mode=None,
            change_type=DiffFileType.DEFAULT,
            binary=False,
            header_lines=[],
            chunks=[
                DiffChunk(
                    header="@@ -3,1 +3,1 @@",
                    lines=["-int disabled_val = 10;", "+int disabled_val = 99;"],
                    old_start=3,
                    old_count=1,
                    new_start=3,
                    new_count=1,
                    section=None,
                )
            ],
        )

        # Modifying only disabled code should return False
        self.assertFalse(
            diff_file_touches_active_code(
                repo=repo,
                parent_commit="c0",
                current_commit="c1",
                diff_file=diff_file_disabled,
                config=self.config,
            )
        )

        # Diff modifying active_val on line 5
        diff_file_active = DiffFile(
            file="drivers/foo.c",
            old_file="drivers/foo.c",
            old_mode=None,
            new_mode=None,
            change_type=DiffFileType.DEFAULT,
            binary=False,
            header_lines=[],
            chunks=[
                DiffChunk(
                    header="@@ -5,1 +5,1 @@",
                    lines=["-int active_val = 20;", "+int active_val = 25;"],
                    old_start=5,
                    old_count=1,
                    new_start=5,
                    new_count=1,
                    section=None,
                )
            ],
        )

        # Modifying active code should return True
        self.assertTrue(
            diff_file_touches_active_code(
                repo=repo,
                parent_commit="c0",
                current_commit="c1",
                diff_file=diff_file_active,
                config=self.config,
            )
        )

    def test_filter_commits_excludes_disabled_ifdef_commit(self) -> None:
        makefile = "obj-y += foo.o\n"
        old_foo = (
            "int a = 1;\n"
            "#ifdef CONFIG_DISABLED\n"
            "int dead = 2;\n"
            "#endif\n"
        )
        new_foo = (
            "int a = 1;\n"
            "#ifdef CONFIG_DISABLED\n"
            "int dead = 3;\n"
            "#endif\n"
        )

        repo = MemoryGitRepo({
            "drivers/Makefile": makefile,
            "c0:drivers/foo.c": old_foo,
            "c1:drivers/foo.c": new_foo,
        })

        patch_disabled = (
            "diff --git a/drivers/foo.c b/drivers/foo.c\n"
            "--- a/drivers/foo.c\n"
            "+++ b/drivers/foo.c\n"
            "@@ -3,1 +3,1 @@\n"
            "-int dead = 2;\n"
            "+int dead = 3;\n"
        )
        date = datetime(2024, 1, 1, tzinfo=UTC)
        c0 = GitCommit("c0", "", "", date, date, (), "")
        c1 = GitCommit(
            "c1",
            "",
            "",
            date,
            date,
            (CommitParent("c0", patch_disabled),),
            "",
        )

        # c1 only modifies dead code inside #ifdef CONFIG_DISABLED
        # It should be filtered out!
        res = filter_commits(repo, self.config, [c0, c1], show_progress=False)
        self.assertEqual([c.commit_id for c in res], [])

        # Now let commit c2 modify line 1 ("int a = 1;") which is active
        patch_active = (
            "diff --git a/drivers/foo.c b/drivers/foo.c\n"
            "--- a/drivers/foo.c\n"
            "+++ b/drivers/foo.c\n"
            "@@ -1,1 +1,1 @@\n"
            "-int a = 1;\n"
            "+int a = 10;\n"
        )
        c2 = GitCommit(
            "c2",
            "",
            "",
            date,
            date,
            (CommitParent("c0", patch_active),),
            "",
        )
        repo.files["c2:drivers/foo.c"] = new_foo

        res2 = filter_commits(repo, self.config, [c0, c2], show_progress=False)
        self.assertEqual([c.commit_id for c in res2], ["c2"])


if __name__ == "__main__":
    unittest.main()
