from pathlib import Path
import unittest

from kpatch.diff import Diff, DiffChunk, DiffFile, DiffFileType
from kpatch.filter.base import FilterContext, FilteredCommit
from kpatch.filter.jev.extended_diff import (
    build_input_state,
    generate_extended_file_diff,
    is_c_source,
)
from kpatch.filter.repository_file import RepositoryFileReader
from kpatch.git import GitDb, GitRepo


class TestJevExtendedDiff(unittest.TestCase):
    def test_is_c_source(self) -> None:
        self.assertTrue(is_c_source("foo.c"))
        self.assertTrue(is_c_source("include/linux/foo.h"))
        self.assertTrue(is_c_source("bar.cpp"))
        self.assertFalse(is_c_source("script.py"))
        self.assertFalse(is_c_source("Makefile"))
        self.assertFalse(is_c_source("README.md"))

    def test_modified_function_expansion(self) -> None:
        old_content = """/*
 * Doc comment.
 */
static int calculate(int x)
{
    int y = x + 1;
    return y * 2;
}

int other(void)
{
    return 0;
}
"""
        new_content = """/*
 * Doc comment.
 */
static int calculate(int x)
{
    int y = x + 2;
    return y * 2;
}

int other(void)
{
    return 0;
}
"""
        # A 1-line change at line 7
        diff_file = DiffFile(
            file="math.c",
            old_file="math.c",
            old_mode=None,
            new_mode=None,
            change_type=DiffFileType.DEFAULT,
            binary=False,
            header_lines=[],
            chunks=[
                DiffChunk(
                    header="@@ -7,3 +7,3 @@",
                    lines=["-    int y = x + 1;", "+    int y = x + 2;", "     return y * 2;"],
                    old_start=7,
                    old_count=3,
                    new_start=7,
                    new_count=3,
                    section="calculate",
                )
            ],
        )

        diff_text, expanded = generate_extended_file_diff(diff_file, old_content, new_content)
        self.assertEqual(len(expanded), 1)
        self.assertEqual(expanded[0].name, "calculate")
        # Ensure the entire function body and doc comment are rendered in the diff
        self.assertIn("/*", diff_text)
        self.assertIn("Doc comment.", diff_text)
        self.assertIn("static int calculate(int x)", diff_text)
        self.assertIn("-    int y = x + 1;", diff_text)
        self.assertIn("+    int y = x + 2;", diff_text)
        self.assertIn("return y * 2;", diff_text)
        # Ensure other(void) is NOT included in the diff
        self.assertNotIn("other(void)", diff_text)

    def test_added_function(self) -> None:
        old_content = "int main(void) { return 0; }\n"
        new_content = """/*
 * New helper.
 */
int helper(int a)
{
    return a + 1;
}

int main(void) { return 0; }
"""
        diff_file = DiffFile(
            file="app.c",
            old_file="app.c",
            old_mode=None,
            new_mode=None,
            change_type=DiffFileType.DEFAULT,
            binary=False,
            header_lines=[],
            chunks=[
                DiffChunk(
                    header="@@ -1,0 +1,9 @@",
                    lines=[
                        "+/*",
                        "+ * New helper.",
                        "+ */",
                        "+int helper(int a)",
                        "+{",
                        "+    return a + 1;",
                        "+}",
                        "+",
                    ],
                    old_start=1,
                    old_count=0,
                    new_start=1,
                    new_count=8,
                    section="",
                )
            ],
        )

        diff_text, expanded = generate_extended_file_diff(diff_file, old_content, new_content)
        self.assertEqual(len(expanded), 1)
        self.assertEqual(expanded[0].name, "helper")
        self.assertIn("+int helper(int a)", diff_text)
        self.assertIn("+    return a + 1;", diff_text)

    def test_deleted_function(self) -> None:
        old_content = """/*
 * Old helper.
 */
int helper(int a)
{
    return a + 1;
}

int main(void) { return 0; }
"""
        new_content = "int main(void) { return 0; }\n"
        diff_file = DiffFile(
            file="app.c",
            old_file="app.c",
            old_mode=None,
            new_mode=None,
            change_type=DiffFileType.DEFAULT,
            binary=False,
            header_lines=[],
            chunks=[
                DiffChunk(
                    header="@@ -1,8 +1,0 @@",
                    lines=[
                        "-/*",
                        "- * Old helper.",
                        "- */",
                        "-int helper(int a)",
                        "-{",
                        "-    return a + 1;",
                        "-}",
                        "-",
                    ],
                    old_start=1,
                    old_count=8,
                    new_start=1,
                    new_count=0,
                    section="",
                )
            ],
        )

        diff_text, expanded = generate_extended_file_diff(diff_file, old_content, new_content)
        self.assertEqual(len(expanded), 0)
        self.assertIn("-int helper(int a)", diff_text)
        self.assertIn("-    return a + 1;", diff_text)

    def test_non_c_file_fallback(self) -> None:
        old_content = "def foo():\n    return 1\n"
        new_content = "def foo():\n    return 2\n"
        diff_file = DiffFile(
            file="script.py",
            old_file="script.py",
            old_mode=None,
            new_mode=None,
            change_type=DiffFileType.DEFAULT,
            binary=False,
            header_lines=[],
            chunks=[
                DiffChunk(
                    header="@@ -2,1 +2,1 @@",
                    lines=["-    return 1", "+    return 2"],
                    old_start=2,
                    old_count=1,
                    new_start=2,
                    new_count=1,
                    section="",
                )
            ],
        )

        diff_text, expanded = generate_extended_file_diff(diff_file, old_content, new_content)
        self.assertEqual(len(expanded), 0)
        self.assertIn("-    return 1", diff_text)
        self.assertIn("+    return 2", diff_text)

    def test_build_input_state_real_commit(self) -> None:
        db = GitDb(Path("db/filtered.sqlite"))
        repo = GitRepo(Path("linux"))
        commit = [c for c in db.commits_between() if c.commit_id.startswith("360941242f09")][0]
        ctx = FilterContext(repo=repo)
        filt_commit = FilteredCommit.from_commit(commit)

        input_state = build_input_state(filt_commit, ctx)

        self.assertIn("io_uring/uring_cmd.c", input_state.patched_files)
        ext_diff = input_state.patched_files["io_uring/uring_cmd.c"]
        # Entire function body is present
        self.assertIn("int io_uring_cmd(struct io_kiocb *req, unsigned int issue_flags)", ext_diff)
        self.assertIn("return IOU_COMPLETE;", ext_diff)
        self.assertIn("-	if (ioucmd->flags & IORING_URING_CMD_MULTISHOT)", ext_diff)

        # Context functions are populated
        self.assertGreater(len(input_state.context_functions), 0)
        self.assertTrue(any("security_uring_cmd" in f for f in input_state.context_functions))


if __name__ == "__main__":
    unittest.main()
