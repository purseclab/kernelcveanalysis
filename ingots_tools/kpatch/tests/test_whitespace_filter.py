from datetime import UTC, datetime
from pathlib import Path
import unittest

from kpatch.diff import DiffFileType
from kpatch.filter import (
    CTokenKind,
    FilterContext,
    FilteredCommit,
    FilterPipeline,
    WhitespaceFilter,
    tokenize_c_source,
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


class CLexerTests(unittest.TestCase):
    def test_comments_between_identifiers(self) -> None:
        tokens = tokenize_c_source("int/*comment*/x;\n")
        self.assertIsNotNone(tokens)
        assert tokens is not None
        self.assertEqual(
            [(t.kind, t.value) for t in tokens],
            [
                (CTokenKind.IDENTIFIER, "int"),
                (CTokenKind.IDENTIFIER, "x"),
                (CTokenKind.PUNCTUATOR, ";"),
            ],
        )

    def test_line_and_block_comments_stripped(self) -> None:
        source = """
        // line comment
        int a = 10;
        /* multi
           line
           comment */
        return a;
        """
        tokens = tokenize_c_source(source)
        self.assertIsNotNone(tokens)
        assert tokens is not None
        values = [t.value for t in tokens]
        self.assertEqual(values, ["int", "a", "=", "10", ";", "return", "a", ";"])

    def test_string_literals_containing_comment_markers(self) -> None:
        source = 'const char *s = "/* not a comment */ // also not";\n'
        tokens = tokenize_c_source(source)
        self.assertIsNotNone(tokens)
        assert tokens is not None
        string_tokens = [t for t in tokens if t.kind is CTokenKind.STRING_LITERAL]
        self.assertEqual(len(string_tokens), 1)
        self.assertEqual(
            string_tokens[0].value,
            '"/* not a comment */ // also not"',
        )

    def test_character_constants_with_escapes(self) -> None:
        source = "char c = '\\'';\n"
        tokens = tokenize_c_source(source)
        self.assertIsNotNone(tokens)
        assert tokens is not None
        char_tokens = [t for t in tokens if t.kind is CTokenKind.CHAR_CONSTANT]
        self.assertEqual(len(char_tokens), 1)
        self.assertEqual(char_tokens[0].value, "'\\''")

    def test_escaped_newlines_spliced(self) -> None:
        macro1 = "#define FOO(x) \\\n    ((x) + 1)\n"
        macro2 = "#define FOO(x) ((x) + 1)\n"
        self.assertEqual(tokenize_c_source(macro1), tokenize_c_source(macro2))

    def test_macro_function_like_vs_object_like(self) -> None:
        func_like = "#define FOO(x) (x + 1)\n"
        obj_like = "#define FOO (x) (x + 1)\n"
        self.assertNotEqual(
            tokenize_c_source(func_like),
            tokenize_c_source(obj_like),
        )

    def test_header_name_in_include(self) -> None:
        include1 = "#include <linux/kernel.h>\n"
        include2 = "#include /* comment */ <linux/kernel.h>\n"
        self.assertEqual(tokenize_c_source(include1), tokenize_c_source(include2))

    def test_token_pasting_and_stringification(self) -> None:
        macro = "#define CONCAT(a, b) a ## b\n#define STR(x) #x\n"
        tokens = tokenize_c_source(macro)
        self.assertIsNotNone(tokens)
        assert tokens is not None
        punct_values = [t.value for t in tokens if t.kind is CTokenKind.PUNCTUATOR]
        self.assertIn("##", punct_values)
        self.assertIn("#", punct_values)

    def test_unterminated_tokens_return_none(self) -> None:
        self.assertIsNone(tokenize_c_source('const char *s = "unterminated;'))
        self.assertIsNone(tokenize_c_source("char c = 'unterminated;"))

    def test_trailing_block_comment_without_closing_delimiter(self) -> None:
        # Diff context lines frequently end with an opened /* that closes outside the hunk
        tokens = tokenize_c_source("int x = 1;\n/* trailing comment without close")
        self.assertIsNotNone(tokens)
        assert tokens is not None
        self.assertEqual([t.value for t in tokens], ["int", "x", "=", "1", ";"])

    def test_newline_policy(self) -> None:
        code1 = "int a;\n\nint b;\n"
        code2 = "int a;\nint b;\n"
        # Strict mode: newlines are retained
        self.assertNotEqual(
            tokenize_c_source(code1, ignore_non_directive_newlines=False),
            tokenize_c_source(code2, ignore_non_directive_newlines=False),
        )
        # Lenient mode: non-directive newlines are ignored
        self.assertEqual(
            tokenize_c_source(code1, ignore_non_directive_newlines=True),
            tokenize_c_source(code2, ignore_non_directive_newlines=True),
        )


class WhitespaceFilterTests(unittest.TestCase):
    @staticmethod
    def make_commit(
        commit_id: str,
        parent_id: str,
        diff_text: str,
    ) -> GitCommit:
        date = datetime(2024, 1, 1, tzinfo=UTC)
        return GitCommit(
            commit_id,
            "",
            "",
            date,
            date,
            (CommitParent(parent_id, diff_text),),
            "",
        )

    def test_eliminates_comment_only_commit(self) -> None:
        patch = (
            "diff --git a/drivers/foo.c b/drivers/foo.c\n"
            "--- a/drivers/foo.c\n"
            "+++ b/drivers/foo.c\n"
            "@@ -1,3 +1,3 @@\n"
            " int a;\n"
            "-/* old comment */\n"
            "+/* new comment */\n"
            " int b;\n"
        )
        commit = self.make_commit("c1", "p0", patch)
        repo = MemoryGitRepo(
            {
                "p0:drivers/foo.c": "int a;\n/* old comment */\nint b;\n",
                "c1:drivers/foo.c": "int a;\n/* new comment */\nint b;\n",
            }
        )
        context = FilterContext(repo)
        result = WhitespaceFilter().filter_commits([commit], context, show_progress=False)
        self.assertEqual(result, [])

    def test_eliminates_whitespace_formatting_commit(self) -> None:
        patch = (
            "diff --git a/drivers/foo.c b/drivers/foo.c\n"
            "--- a/drivers/foo.c\n"
            "+++ b/drivers/foo.c\n"
            "@@ -1,3 +1,3 @@\n"
            " int a;\n"
            "-\tint b;\n"
            "+\t\tint b;\n"
            " int c;\n"
        )
        commit = self.make_commit("c1", "p0", patch)
        repo = MemoryGitRepo(
            {
                "p0:drivers/foo.c": "int a;\n\tint b;\nint c;\n",
                "c1:drivers/foo.c": "int a;\n\t\tint b;\nint c;\n",
            }
        )
        context = FilterContext(repo)
        result = WhitespaceFilter().filter_commits([commit], context, show_progress=False)
        self.assertEqual(result, [])

    def test_preserves_meaningful_code_changes(self) -> None:
        patch = (
            "diff --git a/drivers/foo.c b/drivers/foo.c\n"
            "--- a/drivers/foo.c\n"
            "+++ b/drivers/foo.c\n"
            "@@ -1,3 +1,3 @@\n"
            " int a;\n"
            "-b = 1;\n"
            "+b = 2;\n"
            " int c;\n"
        )
        commit = self.make_commit("c1", "p0", patch)
        repo = MemoryGitRepo(
            {
                "p0:drivers/foo.c": "int a;\nb = 1;\nint c;\n",
                "c1:drivers/foo.c": "int a;\nb = 2;\nint c;\n",
            }
        )
        context = FilterContext(repo)
        result = WhitespaceFilter().filter_commits([commit], context, show_progress=False)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].commit_id, "c1")

    def test_mixed_commit_prunes_noop_file_and_retains_code_file(self) -> None:
        patch = (
            "diff --git a/drivers/comment.c b/drivers/comment.c\n"
            "--- a/drivers/comment.c\n"
            "+++ b/drivers/comment.c\n"
            "@@ -1,2 +1,2 @@\n"
            "-// old\n"
            "+// new\n"
            " int x;\n"
            "diff --git a/drivers/code.c b/drivers/code.c\n"
            "--- a/drivers/code.c\n"
            "+++ b/drivers/code.c\n"
            "@@ -1,2 +1,2 @@\n"
            "-int y = 1;\n"
            "+int y = 2;\n"
            " int z;\n"
        )
        commit = self.make_commit("c1", "p0", patch)
        repo = MemoryGitRepo(
            {
                "p0:drivers/comment.c": "// old\nint x;\n",
                "c1:drivers/comment.c": "// new\nint x;\n",
                "p0:drivers/code.c": "int y = 1;\nint z;\n",
                "c1:drivers/code.c": "int y = 2;\nint z;\n",
            }
        )
        context = FilterContext(repo)
        filter_inst = WhitespaceFilter()
        result = filter_inst.filter_commits([commit], context, show_progress=False)

        self.assertEqual(len(result), 1)
        # comment.c should be pruned; only code.c retained
        retained_files = [f.file for f in result[0].diff.files]
        self.assertEqual(retained_files, ["drivers/code.c"])
        self.assertNotIn("comment.c", result[0].diff_str)
        self.assertIn("code.c", result[0].diff_str)

        stats = filter_inst.stats()
        self.assertEqual(stats.processed_commits, 1)
        self.assertEqual(stats.eliminated_commits, 0)
        self.assertEqual(stats.pruned_files, 1)

    def test_conservatively_retains_assembly_files(self) -> None:
        patch = (
            "diff --git a/arch/arm/entry.S b/arch/arm/entry.S\n"
            "--- a/arch/arm/entry.S\n"
            "+++ b/arch/arm/entry.S\n"
            "@@ -1,2 +1,2 @@\n"
            "-/* old */\n"
            "+/* new */\n"
            " nop\n"
        )
        commit = self.make_commit("c1", "p0", patch)
        repo = MemoryGitRepo(
            {
                "p0:arch/arm/entry.S": "/* old */\nnop\n",
                "c1:arch/arm/entry.S": "/* new */\nnop\n",
            }
        )
        context = FilterContext(repo)
        result = WhitespaceFilter().filter_commits([commit], context, show_progress=False)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].commit_id, "c1")

    def test_conservatively_retains_non_c_files(self) -> None:
        patch = (
            "diff --git a/Documentation/foo.rst b/Documentation/foo.rst\n"
            "--- a/Documentation/foo.rst\n"
            "+++ b/Documentation/foo.rst\n"
            "@@ -1,2 +1,2 @@\n"
            "-old\n"
            "+new\n"
        )
        commit = self.make_commit("c1", "p0", patch)
        repo = MemoryGitRepo(
            {
                "p0:Documentation/foo.rst": "old\n",
                "c1:Documentation/foo.rst": "new\n",
            }
        )
        context = FilterContext(repo)
        result = WhitespaceFilter().filter_commits([commit], context, show_progress=False)
        self.assertEqual(len(result), 1)

    def test_conservatively_retains_binary_and_structural_changes(self) -> None:
        # Binary change
        commit_binary = self.make_commit(
            "c1",
            "p0",
            (
                "diff --git a/drivers/foo.c b/drivers/foo.c\n"
                "Binary files a/drivers/foo.c and b/drivers/foo.c differ\n"
            ),
        )
        # New file change
        commit_new = self.make_commit(
            "c2",
            "p0",
            (
                "diff --git a/drivers/new.c b/drivers/new.c\n"
                "new file mode 100644\n"
                "--- /dev/null\n"
                "+++ b/drivers/new.c\n"
                "@@ -0,0 +1 @@\n"
                "+/* only comments */\n"
            ),
        )
        repo = MemoryGitRepo(
            {
                "p0:drivers/foo.c": "a",
                "c1:drivers/foo.c": "b",
                "c2:drivers/new.c": "/* only comments */\n",
            }
        )
        context = FilterContext(repo)
        res = WhitespaceFilter().filter_commits(
            [commit_binary, commit_new],
            context,
            show_progress=False,
        )
        self.assertEqual(len(res), 2)

    def test_conservatively_retains_unreadable_file(self) -> None:
        patch = (
            "diff --git a/drivers/missing.c b/drivers/missing.c\n"
            "--- a/drivers/missing.c\n"
            "+++ b/drivers/missing.c\n"
            "@@ -1,2 +1,2 @@\n"
            "-/* old */\n"
            "+/* new */\n"
        )
        commit = self.make_commit("c1", "p0", patch)
        # Repo does not have the files; read_file will raise FileNotFoundError
        repo = MemoryGitRepo({})
        context = FilterContext(repo)
        result = WhitespaceFilter().filter_commits([commit], context, show_progress=False)
        self.assertEqual(len(result), 1)


if __name__ == "__main__":
    unittest.main()
