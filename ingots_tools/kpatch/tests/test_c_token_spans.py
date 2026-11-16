from dataclasses import FrozenInstanceError
from random import Random
import re
import unittest
from unittest.mock import patch

from kpatch.filter.whitespace.c_lexer import (
    CToken,
    CTokenKind,
    CTokenSpan,
    CTokenizationError,
    iter_c_token_spans,
    preprocessor_directive_text,
    replace_c_comments,
    tokenize_c_source,
)


class CTokenSpanTests(unittest.TestCase):
    def assert_valid_spans(self, source: str, spans: list[CTokenSpan]) -> None:
        normalized = re.sub(r"\\(?:\r\n|\n)", "", source)
        end = 0
        for span in spans:
            self.assertLessEqual(end, span.start)
            self.assertLessEqual(span.start, span.end)
            self.assertLessEqual(span.end, len(normalized))
            spelling = normalized[span.start:span.end]
            if span.token.kind in {CTokenKind.NEWLINE, CTokenKind.DIRECTIVE_NEWLINE}:
                self.assertIn(spelling, {"", "\n", "\r\n"})
                self.assertEqual(span.token.value, "\n")
            else:
                self.assertEqual(spelling, span.token.value)
            end = span.end

    def test_exact_offsets_and_comment_gap(self) -> None:
        source = "int/* gap */x=1;"
        self.assertEqual(list(iter_c_token_spans(source)), [
            CTokenSpan(CToken(CTokenKind.IDENTIFIER, "int"), 0, 3, False),
            CTokenSpan(CToken(CTokenKind.IDENTIFIER, "x"), 12, 13, True),
            CTokenSpan(CToken(CTokenKind.PUNCTUATOR, "="), 13, 14, False),
            CTokenSpan(CToken(CTokenKind.PP_NUMBER, "1"), 14, 15, False),
            CTokenSpan(CToken(CTokenKind.PUNCTUATOR, ";"), 15, 16, False),
        ])

    def test_leading_trivia_and_ignored_newlines_are_logical_gaps(self) -> None:
        spans = list(iter_c_token_spans(" /*x*/\na\n\n b/**/+c"))
        self.assertEqual([(span.token.value, span.whitespace_before) for span in spans],
                         [("a", True), ("b", True), ("+", True), ("c", False)])

    def test_phase_two_splices_do_not_create_whitespace(self) -> None:
        for source in ("ab\\\ncd+e", "ab\\\r\ncd+e"):
            with self.subTest(source=source):
                spans = list(iter_c_token_spans(source))
                self.assertEqual([(span.token.value, span.start, span.end, span.whitespace_before) for span in spans],
                                 [("abcd", 0, 4, False), ("+", 4, 5, False), ("e", 5, 6, False)])

    def test_splices_before_trivia_or_after_tokens_keep_correct_ends(self) -> None:
        for source in ("one\\\n +two", "one \\\n+two", "one\\\n/**/+two"):
            with self.subTest(source=source):
                spans = list(iter_c_token_spans(source))
                self.assertEqual(spans[0].end, 3)
                self.assertTrue(spans[1].whitespace_before)
                self.assert_valid_spans(source, spans)

    def test_macro_function_lparen_preserves_adjacency(self) -> None:
        for source, function_like in (("#define F(x) x\n", True),
                                      ("#define F\\\n(x) x\n", True),
                                      ("#define F (x) x\n", False),
                                      ("#define F/**/(x) x\n", False)):
            with self.subTest(source=source):
                spans = list(iter_c_token_spans(source))
                first_lparen = next(span for span in spans if span.token.value == "(")
                self.assertEqual(first_lparen.token.kind is CTokenKind.MACRO_FUNCTION_LPAREN, function_like)
                self.assertEqual(first_lparen.whitespace_before, not function_like)
                self.assert_valid_spans(source, spans)

    def test_explicit_and_synthetic_directive_newline(self) -> None:
        for suffix, width in (("", 0), ("\n", 1), ("\r\n", 2)):
            with self.subTest(suffix=suffix):
                source = "#define X 1" + suffix
                spans = list(iter_c_token_spans(source))
                endings = [span for span in spans if span.token.kind is CTokenKind.DIRECTIVE_NEWLINE]
                self.assertEqual(len(endings), 1)
                self.assertEqual(endings[0].end - endings[0].start, width)
                self.assert_valid_spans(source, spans)

    def test_emitted_newlines_consume_their_span_and_gap(self) -> None:
        source = "a \nb"
        spans = list(iter_c_token_spans(source, ignore_non_directive_newlines=False))
        self.assertEqual([(span.token.value, span.whitespace_before) for span in spans],
                         [("a", False), ("\n", True), ("b", False)])
        self.assert_valid_spans(source, spans)

    def test_trailing_trivia_belongs_to_synthetic_directive_newline(self) -> None:
        spans = list(iter_c_token_spans("#define X 1 /* note */"))
        self.assertEqual(spans[-1].token.kind, CTokenKind.DIRECTIVE_NEWLINE)
        self.assertTrue(spans[-1].whitespace_before)
        self.assertEqual(spans[-1].start, spans[-1].end)

    def test_atomic_header_has_exact_bytes_and_no_duplicate_interior_tokens(self) -> None:
        # Intentionally differs from the old lexer, which emitted header bytes
        # again as ordinary tokens after also producing HEADER_NAME.
        for header in ("<linux/kernel.h>", "<a b\tc/d.h>", "<foo/*x*/bar.h>", "<foo//bar.h>", '<foo"bar.h>'):
            with self.subTest(header=header):
                source = "#include " + header + "\nint after;"
                spans = list(iter_c_token_spans(source))
                self.assertEqual([span.token.value for span in spans], ["#", "include", header, "\n", "int", "after", ";"])
                self.assertEqual(spans[2].token.kind, CTokenKind.HEADER_NAME)
                self.assertTrue(spans[2].whitespace_before)
                self.assert_valid_spans(source, spans)

    def test_header_comment_match_cannot_swallow_following_source(self) -> None:
        source = "#include <foo/*bar.h>\nint important;\n/* later */ int tail;"
        spans = list(iter_c_token_spans(source))
        self.assertEqual([span.token.value for span in spans],
                         ["#", "include", "<foo/*bar.h>", "\n", "int", "important", ";", "int", "tail", ";"])
        self.assert_valid_spans(source, spans)

    def test_include_next_import_and_digraph_headers(self) -> None:
        for directive in ("#include_next", "#import", "%:include", "#/**/include"):
            with self.subTest(directive=directive):
                spans = list(iter_c_token_spans(directive + " <dir/import.h>\n"))
                self.assertEqual(sum(span.token.kind is CTokenKind.HEADER_NAME for span in spans), 1)
                self.assert_valid_spans(directive + " <dir/import.h>\n", spans)

    def test_unmodeled_header_operators_and_embed_fail_closed(self) -> None:
        for source in ('#if __has_include(<foo/*x*/bar.h>)\n#endif\n',
                       '#if __has_include_next(<foo.h>)\n#endif\n',
                       '#if __has_embed(<file.bin>)\n#endif\n',
                       '#embed <file.bin>\n', '%:embed <file.bin>\n',
                       '#include <unfinished'):
            with self.subTest(source=source):
                with self.assertRaises(CTokenizationError):
                    list(iter_c_token_spans(source))
                self.assertIsNone(tokenize_c_source(source))

    def test_budget_is_enforced_before_yielding_the_excess_token(self) -> None:
        output = iter_c_token_spans("one two three", token_limit=1)
        self.assertEqual(next(output).token.value, "one")
        with self.assertRaisesRegex(CTokenizationError, "token limit"):
            next(output)

    def test_budget_counts_directive_newlines_including_eof(self) -> None:
        for source in ("#define X 1", "#define X 1\n"):
            with self.subTest(source=source):
                self.assertEqual(len(list(iter_c_token_spans(source, token_limit=5))), 5)
                with self.assertRaises(CTokenizationError):
                    list(iter_c_token_spans(source, token_limit=4))
        self.assertEqual(list(iter_c_token_spans(" /*comment*/ ", token_limit=0)), [])
        with self.assertRaises(CTokenizationError):
            list(iter_c_token_spans("x", token_limit=0))
        with self.assertRaises(CTokenizationError):
            list(iter_c_token_spans("", token_limit=-1))

    def test_raw_literals_rejected_by_all_shared_entry_points_after_splicing(self) -> None:
        for prefix in ("R", "u8R", "uR", "UR", "LR", "u8\\\nR", "R\\\r\n"):
            source = prefix + '"tag(raw /*text*/ )tag"'
            with self.subTest(prefix=prefix):
                with self.assertRaises(CTokenizationError):
                    list(iter_c_token_spans(source))
                self.assertIsNone(tokenize_c_source(source))
                self.assertIsNone(replace_c_comments(source))
                self.assertIsNone(preprocessor_directive_text(source))
        self.assertIsNone(tokenize_c_source('/* R"(unmodeled even in comment)" */ int x;'))

    def test_raw_prefix_word_boundary_does_not_reject_ordinary_identifier(self) -> None:
        source = 'int userR; const char *s = "ordinary";'
        self.assertIsNotNone(tokenize_c_source(source))

    def test_non_ascii_whitespace_is_not_silently_discarded(self) -> None:
        for gap in ("\u00a0", "\u0085", "\u2003", "\u2028", "\u2029"):
            with self.subTest(gap=gap):
                with self.assertRaises(CTokenizationError):
                    list(iter_c_token_spans("int" + gap + "x;"))
                self.assertIsNone(tokenize_c_source("int" + gap + "x;"))
        self.assertIsNotNone(tokenize_c_source('/* \u00a0 */ const char *s="\u2003";'))

    def test_named_error_retains_partial_iterator_failure_and_wrapper_unknown(self) -> None:
        output = iter_c_token_spans('int value; "unfinished')
        self.assertEqual(next(output).token.value, "int")
        self.assertEqual(next(output).token.value, "value")
        self.assertEqual(next(output).token.value, ";")
        with self.assertRaises(CTokenizationError):
            next(output)
        for source in ('"unfinished\nnext', "'unfinished\nnext", "import <file>;", "??=define X 1", "\ufeffint x;", "int x;\r"):
            with self.subTest(source=source):
                self.assertIsNone(tokenize_c_source(source))

    def test_partial_hunk_unterminated_comment_tolerance_is_preserved(self) -> None:
        self.assertEqual([span.token.value for span in iter_c_token_spans("int x; /* open")], ["int", "x", ";"])
        self.assertIsNone(preprocessor_directive_text("int x; /* open", strict_multiline=True))

    def test_ordinary_tokens_and_wrapper_match_the_stream(self) -> None:
        samples = ("int x=0x10 + .5e+2;", '#define STR(x) #x\n#define CAT(a,b) a##b\n',
                   'u8"a\\n/*b*/" L\'x\' // end\n', "x->field++ != a <<= 2;", "/* prefix */ %:define X 1\n")
        for source in samples:
            with self.subTest(source=source):
                spans = list(iter_c_token_spans(source))
                self.assertEqual(tuple(span.token for span in spans), tokenize_c_source(source))
                self.assert_valid_spans(source, spans)

    def test_token_only_wrapper_does_not_construct_discarded_spans(self) -> None:
        samples = ("int x=1; /* comment */\n", "#define F(x) x\n",
                   "#include <foo/*bar.h>\nint after;", "#define EOF 1")
        for source in samples:
            for ignore_newlines in (False, True):
                with self.subTest(source=source, ignore_newlines=ignore_newlines):
                    expected = tuple(span.token for span in iter_c_token_spans(source, ignore_newlines))
                    with patch("kpatch.filter.whitespace.c_lexer.CTokenSpan",
                               side_effect=AssertionError("token-only scan constructed a span")):
                        self.assertEqual(tokenize_c_source(source, ignore_newlines), expected)

    def test_randomized_wrappers_share_tokens_and_unknown_results(self) -> None:
        random = Random(20261107)
        fragments = ("word", "0x10", ".5e+2", "u8\"text\"", "L'x'", "+=", "##",
                     " ", "\t", "\n", "\r\n", "/* note */", "// line\n", "\\\n",
                     "#define F(x) x\n", "#include <dir/file.h>\n",
                     "#include <foo/*bar.h>\nint after;", "#define EOF 1",
                     "\u00a0", "??=", "import <file>;", 'R"(raw)"', '"unfinished')
        for case in range(200):
            source = "".join(random.choices(fragments, k=random.randrange(1, 20)))
            for ignore_newlines in (False, True):
                with self.subTest(case=case, ignore_newlines=ignore_newlines):
                    try:
                        spans = list(iter_c_token_spans(source, ignore_newlines))
                    except CTokenizationError:
                        self.assertIsNone(tokenize_c_source(source, ignore_newlines))
                    else:
                        self.assertEqual(tokenize_c_source(source, ignore_newlines),
                                         tuple(span.token for span in spans))
                        self.assert_valid_spans(source, spans)

    def test_span_records_are_immutable(self) -> None:
        span = next(iter_c_token_spans("x"))
        with self.assertRaises(FrozenInstanceError):
            setattr(span, "start", 99)


if __name__ == "__main__":
    unittest.main()
