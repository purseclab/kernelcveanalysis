from dataclasses import FrozenInstanceError
from random import Random
import unittest
from unittest.mock import patch

import kpatch.filter.constant_conditionals as scanner_module
from kpatch.filter.constant_conditionals import (
    ConstantBranchCandidates,
    ConstantConditionalScanner,
    may_have_numeric_condition,
)
from kpatch.filter.masking import LineRange


class ConstantConditionalTests(unittest.TestCase):
    def assert_ranges(self, source: bytes, expected: tuple[LineRange, ...]) -> None:
        self.assertEqual(ConstantConditionalScanner().scan(source), ConstantBranchCandidates(expected))
        if expected:
            self.assertTrue(may_have_numeric_condition(source))

    def project(self, source: bytes) -> bytes:
        result = ConstantConditionalScanner().scan(source)
        self.assertIsNotNone(result)
        assert result is not None
        lines = source.splitlines(keepends=True)
        for span in result.inactive:
            for index in range(span.start - 1, span.end - 1):
                lines[index] = bytes(value if value in {10, 13} else 32 for value in lines[index])
        return b"".join(lines)

    def test_no_controls_empty_and_comment_only_sources(self) -> None:
        for source in (b"", b"int x;\n", b"/* #if 0 */\n", b'const char*s="#if 0";\n'):
            with self.subTest(source=source):
                self.assert_ranges(source, ())

    def test_false_and_true_groups_keep_only_the_selected_body(self) -> None:
        self.assert_ranges(b"#if 0\ndead\n#endif\n", (LineRange(1, 4),))
        self.assert_ranges(b"#if 1\nlive\n#endif\n", (LineRange(1, 2), LineRange(3, 4)))
        self.assert_ranges(b"#if 0\ndead\n#else\nlive\n#endif\n",
                           (LineRange(1, 4), LineRange(5, 6)))

    def test_numeric_chain_and_all_false_without_else(self) -> None:
        source = b"#if 0\na\n#elif (2 - 2)\nb\n#elif 0xffUL == 255\nc\n#else\nd\n#endif\n"
        self.assert_ranges(source, (LineRange(1, 6), LineRange(7, 10)))
        self.assert_ranges(b"#if 0\na\n#elif !1\nb\n#endif\n", (LineRange(1, 6),))

    def test_unknown_preceding_arm_prevents_later_true_selection(self) -> None:
        for prefix in (b"#if UNKNOWN", b"#if 0\na\n#elif UNKNOWN", b"#ifdef NAME", b"#ifndef NAME"):
            with self.subTest(prefix=prefix):
                self.assert_ranges(prefix + b"\na\n#elif 1\nb\n#else\nc\n#endif\n", ())

    def test_known_true_prevents_evaluation_of_later_unknown_arms(self) -> None:
        source = b"#if 1\nlive\n#elif UNKNOWN\ndead\n#else\nalso_dead\n#endif\n"
        self.assert_ranges(source, (LineRange(1, 2), LineRange(3, 8)))

    def test_unknown_groups_recurse_all_child_groups_only(self) -> None:
        source = (b"#if NAME\n#if 0\ndead\n#endif\n#else\n"
                  b"#if 1\nlive\n#endif\n#endif\n")
        self.assert_ranges(source, (LineRange(2, 5), LineRange(6, 7), LineRange(8, 9)))

    def test_known_groups_recurse_only_selected_children(self) -> None:
        source = (b"#if 0\n#ifdef NAME\nanything\n#endif\n#else\n"
                  b"#if 0\ndead\n#else\nlive\n#endif\n#endif\n")
        self.assert_ranges(source, (LineRange(1, 9), LineRange(10, 12)))

    def test_selected_directive_effects_and_counters_remain_in_order(self) -> None:
        selected = (b'#define VALUE __COUNTER__\n#undef PREVIOUS\n#include "active.h"\n'
                    b'#line 40 "active"\n#pragma message("active")\nint value=VALUE+__LINE__;\n')
        source = b"#if 0\n__COUNTER__ dead;\n#else\n" + selected + b"#endif\n"
        projected = self.project(source)
        self.assertIn(selected, projected)
        self.assertNotIn(b"__COUNTER__ dead", projected)
        self.assertEqual(projected.count(b"\n"), source.count(b"\n"))

    def test_directive_splices_preserve_whole_physical_spans(self) -> None:
        source = b"#i\\\nf 1 && \\\n1\nlive\n#en\\\ndif\n"
        self.assert_ranges(source, (LineRange(1, 4), LineRange(5, 7)))
        self.assert_ranges(b"%:if 0\r\ndead\r\n%:endif\r\n", (LineRange(1, 4),))

    def test_comments_before_and_inside_controls(self) -> None:
        self.assert_ranges(b"/* prefix */ #if 1 /* note */\nlive\n#endif /* end */\n",
                           (LineRange(1, 2), LineRange(3, 4)))
        self.assert_ranges(b"#if (0 /* note */ + 0)\ndead\n#endif\n", (LineRange(1, 4),))

    def test_identifiers_overflow_and_unsupported_expressions_stay_unknown(self) -> None:
        for expression in (b"0 && NAME", b"1 || NAME", b"defined(NAME)", b"NAME(0)",
                           b"1 / 0", b"1 << 64", b"9223372036854775807 + 1", b"'x'", b"1 +"):
            with self.subTest(expression=expression):
                self.assert_ranges(b"#if " + expression + b"\nlive\n#else\nalso_live\n#endif\n", ())

    def test_newer_and_malformed_controls_reject_whole_source(self) -> None:
        sources = (b"#if 0\nx\n#elifdef NAME\ny\n#endif\n",
                   b"#if 0\nx\n#elifndef NAME\ny\n#endif\n",
                   b"#if 0\n#if 0\n#elifdef NAME\n#endif\n#endif\n",
                   b"#if\nx\n#endif\n", b"#ifdef\nx\n#endif\n",
                   b"#ifdef NAME extra\nx\n#endif\n", b"#if 0\nx\n",
                   b"#else\n", b"#elif 1\n", b"#endif\n",
                   b"#if 1\n#else\n#else\n#endif\n",
                   b"#if 1\n#else\n#elif 1\n#endif\n",
                   b"#if 1\n#else extra\n#endif\n", b"#if 0\n#endif extra\n",
                   b"#if 1\n#elif\n#endif\n", b"#if 0\n#elsewhere\n#endif\n")
        for source in sources:
            with self.subTest(source=source):
                self.assertIsNone(ConstantConditionalScanner().scan(source))

    def test_original_logical_context_and_ascii_directives_are_required(self) -> None:
        sources = (b"#if 0\n\xff\n#endif\n", b"#if 0\n/* unfinished\n#endif\n",
                   b"??=if 0\nx\n??=endif\n",
                   b"#if 0\nx\n#endif\n\\\n", b"#if 0\nx\n#endif\r",
                   b"#if 0\0\nx\n#endif\n", b"#if 0\nR\"(raw)\"\n#endif\n",
                   b"#if 1 /* multiline\n comment */\nx\n#endif\n",
                   b"#if 0\\ \nx\n#endif\n", '\u00a0#if 0\nx\n\u00a0#endif\n'.encode(),
                   '#\u00a0if 0\nx\n#endif\n'.encode(), '#if 0\nx\n#endif\u00a0\n'.encode())
        for source in sources:
            with self.subTest(source=source):
                self.assertIsNone(ConstantConditionalScanner().scan(source))

    def test_candidate_result_does_not_replace_original_lexer_validation(self) -> None:
        from kpatch.filter.whitespace.c_lexer import tokenize_c_source

        source = b'#if 0\n"unfinished\n#endif\n'
        self.assertIsNotNone(ConstantConditionalScanner().scan(source))
        self.assertIsNone(tokenize_c_source(source.decode()))

    def test_full_structure_is_checked_after_earlier_candidates(self) -> None:
        valid = b"#if 0\ndead\n#endif\n"
        for suffix in (b"#endif\n", b"#if 1\n", b"#if 0\n#else\n#else\n#endif\n"):
            with self.subTest(suffix=suffix):
                self.assertIsNone(ConstantConditionalScanner().scan(valid + suffix))

    def test_adjacent_ranges_merge_without_erasing_intervening_live_lines(self) -> None:
        group = b"#if 0\ndead\n#endif\n"
        self.assert_ranges(group + group, (LineRange(1, 7),))
        self.assert_ranges(group + b"live\n" + group, (LineRange(1, 4), LineRange(5, 8)))

    def test_byte_and_physical_lf_bounds(self) -> None:
        source = b"#if 0\nx\n#endif\n"
        with patch.object(scanner_module, "_MAX_SOURCE_BYTES", len(source) - 1):
            scanner = ConstantConditionalScanner()
            self.assertIsNone(scanner.scan(source))
            self.assertEqual(scanner.stats.cache_entries, 0)
        with patch.object(scanner_module, "_MAX_PHYSICAL_LF", 3):
            self.assertIsNotNone(ConstantConditionalScanner().scan(source))
            self.assertIsNone(ConstantConditionalScanner().scan(source + b"\n"))

    def test_group_and_nesting_bounds_include_inactive_children(self) -> None:
        group = b"#if 0\nx\n#endif\n"
        with patch.object(scanner_module, "_MAX_GROUPS", 2):
            self.assertIsNotNone(ConstantConditionalScanner().scan(group * 2))
            self.assertIsNone(ConstantConditionalScanner().scan(group * 3))
        with patch.object(scanner_module, "_MAX_NESTING", 2):
            self.assertIsNotNone(ConstantConditionalScanner().scan(b"#if 0\n" * 2 + b"#endif\n" * 2))
            self.assertIsNone(ConstantConditionalScanner().scan(b"#if 0\n" * 3 + b"#endif\n" * 3))

    def test_cache_reuses_complete_candidates_and_unknowns_with_bounds(self) -> None:
        scanner = ConstantConditionalScanner()
        source = b"#if 0\nx\n#endif\n"
        first = scanner.scan(source)
        self.assertIs(scanner.scan(source), first)
        self.assertEqual(scanner.stats.scans, 1)
        self.assertEqual(scanner.stats.cache_hits, 1)
        self.assertIsNone(scanner.scan(b"#endif\n"))
        self.assertIsNone(scanner.scan(b"#endif\n"))
        self.assertEqual(scanner.stats.unsupported_scans, 1)
        with patch.object(scanner_module, "_CACHE_ENTRIES", 2), patch.object(scanner_module, "_CACHE_INPUT_BYTES", 24):
            for number in range(6):
                self.assertIsNotNone(scanner.scan(f"int x{number};\n".encode()))
                self.assertLessEqual(scanner.stats.cache_entries, 2)
                self.assertLessEqual(scanner.stats.cache_input_bytes, 24)

    def test_candidate_and_stats_records_are_immutable(self) -> None:
        scanner = ConstantConditionalScanner()
        result = scanner.scan(b"#if 0\nx\n#endif\n")
        self.assertIsNotNone(result)
        with self.assertRaises(FrozenInstanceError):
            setattr(result, "inactive", ())
        with self.assertRaises(FrozenInstanceError):
            setattr(scanner.stats, "scans", 0)

    def test_numeric_hint_covers_comments_parentheses_digraphs_and_splices(self) -> None:
        sources = (b"#if 0", b"#if(0)", b"#if +1", b"#if -1", b"#if !1", b"#if ~0",
                   b"#/**/if 0", b"#/**/if0", b"#if/**/0", b"#if /*a*/ /*b*/ (0)",
                   b"/* before */ #if 0", b"%:if 0", b"%:/**/if(0)",
                   b"#i\\\nf 0", b"#if \\\n0", b"%\\\r\n:if(0)", b"#i\\\nf\\\n(0)")
        for source in sources:
            with self.subTest(source=source):
                self.assertTrue(may_have_numeric_condition(source))

    def test_numeric_hint_skips_body_only_and_configuration_only_sources(self) -> None:
        body = b"static int work(int x) { return x + 1; }\n"
        config = b"#ifndef GUARD\n#define GUARD\n#if CONFIG_FOO\nint x;\n#else\nint y;\n#endif\n#endif\n"
        for source in (body, config, b"#ifdef NAME\n#elif 0\n#endif\n", config * 10000):
            with self.subTest(bytes=len(source)):
                self.assertFalse(may_have_numeric_condition(source))

    def test_numeric_hint_unknown_spellings_request_full_scan(self) -> None:
        for source in (b"??=if 0", b"#if \\ \n0", b"#if\0 0", b"\xef\xbb\xbf#if 0",
                       b"#\\u0069f 0", '#\u00a0if 0'.encode(), '#if\u00a00'.encode()):
            with self.subTest(source=source):
                self.assertTrue(may_have_numeric_condition(source))

    def test_numeric_hint_never_misses_supported_random_comment_splice_variants(self) -> None:
        random = Random(20261107)
        scanner = ConstantConditionalScanner()
        separators = (b" ", b"\t", b"/**/", b" /*note*/ ")
        expressions = (b"0", b"1", b"(0)", b"!1", b"~0", b"+1", b"-1", b"0xffUL == 255")
        for case in range(400):
            introducer = random.choice((b"#", b"%:"))
            source = (random.choice((b"", b"/* leading */ ")) + introducer
                      + random.choice(separators) + b"if" + random.choice(separators)
                      + random.choice(expressions) + b"\nx\n#else\ny\n#endif\n")
            if random.randrange(2):
                position = random.randrange(len(source))
                source = source[:position] + random.choice((b"\\\n", b"\\\r\n")) + source[position:]
            with self.subTest(case=case):
                result = scanner.scan(source)
                if result is not None and result.inactive:
                    self.assertTrue(may_have_numeric_condition(source))


if __name__ == "__main__":
    unittest.main()
