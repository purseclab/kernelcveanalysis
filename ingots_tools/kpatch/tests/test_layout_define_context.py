from dataclasses import FrozenInstanceError
import re
import unittest
from unittest.mock import patch

from kpatch.filter.whitespace import c_lexer as lex
from kpatch.filter.whitespace import layout


class DefineContextTests(unittest.TestCase):
    def supported(self, source: str, *, ignore_newlines: bool = True, limit: int = 512) -> bool:
        return lex.layout_comment_context_supported(
            source, ignore_non_directive_newlines=ignore_newlines, token_limit=limit,
        )

    def test_intervals_use_logical_character_offsets_and_are_immutable(self) -> None:
        source = '/* é */\n#define A (1 << 0) /* first */\n%:define B 2 /* second */'
        intervals = lex._define_intervals(source, True, 512)
        first, second = source.index('#define'), source.index('%:define')
        self.assertEqual(intervals, (lex._DefineInterval(first, source.index('\n', first)),
                                     lex._DefineInterval(second, len(source))))
        self.assertNotEqual(first, len(source[:first].encode()))
        with self.assertRaises(FrozenInstanceError):
            setattr(intervals[0], 'start', 0)

    def test_only_real_leading_define_directives_get_intervals(self) -> None:
        source = ('const char*s="#define FAKE";\n'
                  '/* #define ALSO_FAKE */\n'
                  'int x; #define NOT_DIRECTIVE 1\n'
                  '#if FLAG\n#endif\n'
                  '#pragma something\n'
                  '/* prefix */ #/**/define GOOD (1 << 0) /* doc */\n')
        intervals = lex._define_intervals(source, True, 512)
        start = source.index('#/**/define')
        self.assertEqual(intervals, (lex._DefineInterval(start, source.index('\n', start)),))

    def test_comments_do_not_split_a_definition_or_create_directive_starts(self) -> None:
        source = '#define A (1 << 0) /* multi\n line */ + 1\n'
        self.assertEqual(lex._define_intervals(source, True, 512),
                         (lex._DefineInterval(0, len(source) - 1),))
        self.assertTrue(self.supported(source))
        self.assertEqual(lex._define_intervals('int x; /* multi\n */ #define BAD 1\n', True, 512), ())

    def test_standard_splices_are_applied_exactly_once_to_original_source(self) -> None:
        # Removing the second backslash and first LF exposes a new splice in
        # the comment. It must remain in the once-normalized logical view.
        prefix = '/* ' + '\\\\' + '\n\n */\n'
        source = prefix + '#de\\\nfine A (1 << 0) /* doc */\n'
        once = re.sub(r'\\(?:\r\n|\n)', '', source)
        twice = re.sub(r'\\(?:\r\n|\n)', '', once)
        self.assertNotEqual(once, twice)
        expected = lex._DefineInterval(once.index('#define'), len(once) - 1)
        self.assertEqual(lex._define_intervals(source, True, 512), (expected,))
        context = lex._DefineCommentContext(source, True, 512)
        self.assertTrue(context.allows(once.index('/* doc */')))
        self.assertEqual(context.source, source)
        self.assertTrue(self.supported(source))

    def test_spliced_digraph_keyword_and_eof_offsets_match_the_normalizer(self) -> None:
        source = '%\\\r\n:de\\\nfine FLAG (1 << 0) /* doc */'
        once = re.sub(r'\\(?:\r\n|\n)', '', source)
        self.assertEqual(lex._define_intervals(source, True, 512),
                         (lex._DefineInterval(0, len(once)),))
        self.assertTrue(self.supported(source))

    def test_typical_numeric_shift_definition_is_layout_supported_only(self) -> None:
        source = '#define FLAG (1 << 0) /* doc */\n'
        self.assertIsNone(lex.preprocessor_directive_text(source))
        self.assertIsNone(lex.preprocessor_directive_text(source, strict_multiline=True))
        self.assertTrue(self.supported(source))
        self.assertIn('/* doc */', lex.replace_c_comments(source) or '')
        self.assertTrue(layout.LayoutComparer().equivalent(source.encode(), source.replace('doc', 'new').encode()))

    def test_non_definition_angle_contexts_remain_unsupported(self) -> None:
        sources = ('#if HAS(<foo/*x*/bar.h>)\n#endif\n',
                   '#elif HAS(<foo/*x*/bar.h>)\n',
                   '#include <foo/*x*/bar.h>\n',
                   '#include_next <foo/*x*/bar.h>\n',
                   '#import <foo/*x*/bar.h>\n',
                   '#pragma vendor <foo/*x*/bar.h>\n')
        for source in sources:
            with self.subTest(source=source):
                self.assertFalse(self.supported(source))

    def test_mixed_definition_and_header_ambiguities_do_not_grant_whole_source(self) -> None:
        definition = '#define FLAG (1 << 0) /* doc */\n'
        header = '#if HAS(<foo/*x*/bar.h>)\n#endif\n'
        for source in (definition + header, header + definition):
            with self.subTest(source=source):
                with patch.object(lex, '_define_intervals', wraps=lex._define_intervals) as discovery:
                    self.assertFalse(self.supported(source))
                self.assertEqual(discovery.call_count, 1)

    def test_no_ambiguity_does_not_discover_definitions(self) -> None:
        with patch.object(lex, '_define_intervals', side_effect=AssertionError('unnecessary full lex')):
            for source in ('int x; /* ordinary */\n', '#define X 1\n', '#if FLAG\n#endif\n'):
                with self.subTest(source=source):
                    self.assertTrue(self.supported(source))

    def test_multiple_ambiguities_discover_definitions_once(self) -> None:
        source = '#define A (1 << 0) /* first */ + 1 /* second */\n#define B (1 << 1) /* third */\n'
        with patch.object(lex, '_define_intervals', wraps=lex._define_intervals) as discovery:
            self.assertTrue(self.supported(source))
        self.assertEqual(discovery.call_count, 1)

    def test_empty_interval_result_is_cached_for_all_ambiguities(self) -> None:
        source = '#if HAS(<foo/*x*/bar.h>)\n#endif\n#if OTHER(<foo/*y*/bar.h>)\n#endif\n'
        with patch.object(lex, '_define_intervals', wraps=lex._define_intervals) as discovery:
            self.assertFalse(self.supported(source))
        self.assertEqual(discovery.call_count, 1)

    def test_discovery_failure_cannot_grant_an_earlier_prefix(self) -> None:
        prefix = '#define FLAG (1 << 0) /* doc */\n'
        for suffix in ('import <header>;', '#if __has_include(<file>)\n#endif\n', '"unfinished\n'):
            with self.subTest(suffix=suffix):
                self.assertFalse(self.supported(prefix + suffix))
                self.assertFalse(layout.LayoutComparer().equivalent((prefix + suffix).encode(), (prefix + suffix).encode()))

    def test_final_hard_normalizer_failure_is_not_waived_by_definition_proof(self) -> None:
        source = '#define FLAG (1 << 0) /* doc */\n/* unclosed'
        self.assertFalse(self.supported(source))
        self.assertFalse(layout.LayoutComparer().equivalent(source.encode(), source.encode()))

    def test_failed_layout_fact_is_cached_without_repeating_discovery(self) -> None:
        source = b'#define FLAG (1 << 0) /* doc */\n'
        comparer = layout.LayoutComparer()
        with patch.object(lex, '_define_intervals', side_effect=lex.CTokenizationError('incomplete proof')) as discovery:
            self.assertFalse(comparer.equivalent(source, source))
            self.assertFalse(comparer.equivalent_ignoring_line_numbers(source, source))
        self.assertEqual(discovery.call_count, 1)
        self.assertEqual(comparer.stats.unsupported_scans, 1)

    def test_semantic_and_traversal_limits_match_both_newline_modes(self) -> None:
        source = '\n\n#define FLAG (1 << 0) /* doc */\n\nint x;\n'
        for ignore_newlines in (True, False):
            tokens = lex.tokenize_c_source(source, ignore_newlines)
            assert tokens is not None
            semantic_limit = len(tokens)
            expected_traversal = semantic_limit + (source.count('\n') if ignore_newlines else 0)
            with self.subTest(ignore_newlines=ignore_newlines):
                with patch.object(lex, 'iter_c_token_spans', wraps=lex.iter_c_token_spans) as stream:
                    self.assertTrue(self.supported(source, ignore_newlines=ignore_newlines, limit=semantic_limit))
                self.assertEqual(stream.call_args.args, (source, False, expected_traversal))
                self.assertFalse(self.supported(source, ignore_newlines=ignore_newlines, limit=semantic_limit - 1))
                with patch.object(layout, '_MAX_TOKENS', semantic_limit):
                    self.assertTrue(layout.LayoutComparer(ignore_non_directive_newlines=ignore_newlines)
                                    .equivalent(source.encode(), source.encode()))
                with patch.object(layout, '_MAX_TOKENS', semantic_limit - 1):
                    self.assertFalse(layout.LayoutComparer(ignore_non_directive_newlines=ignore_newlines)
                                     .equivalent(source.encode(), source.encode()))

    def test_eof_directive_newline_counts_toward_semantic_budget(self) -> None:
        for ending in ('', '\n'):
            source = '#define FLAG (1 << 0) /* doc */' + ending
            tokens = lex.tokenize_c_source(source)
            assert tokens is not None
            with self.subTest(ending=ending):
                self.assertTrue(self.supported(source, limit=len(tokens)))
                self.assertFalse(self.supported(source, limit=len(tokens) - 1))

    def test_public_normalizer_never_uses_the_layout_admission(self) -> None:
        with patch.object(lex, '_define_intervals', side_effect=AssertionError('public behavior changed')):
            self.assertEqual(lex.preprocessor_directive_text('#define X 1 /* note */\n'), '#define X 1  \n')
            self.assertIsNone(lex.preprocessor_directive_text('#define X (1 << 0) /* note */\n'))
            self.assertEqual(lex.preprocessor_directive_text('#define X 1 /* a\nb */\n'), '#define X 1  \n\n')
            self.assertIsNone(lex.preprocessor_directive_text('#define X 1 /* a\nb */\n', strict_multiline=True))

    def test_existing_raw_header_operator_and_trigraph_guards_remain(self) -> None:
        for source in ('#define X (1 << 0) /* doc */\nR"(raw)"',
                       '#define X (1 << 0) /* doc */\n??=if 0\n',
                       '#define X __has_include(<foo/*x*/bar.h>)\n',
                       '#define X __has_include_next(<file>)\n',
                       '#define X __has_embed(<file>)\n', '#embed <file>\n'):
            with self.subTest(source=source):
                # A context-only fast path need not lex unambiguous input.
                # Force lazy discovery to verify a later refusal cannot be
                # concealed by an already recognized definition interval.
                prefix = '#define FLAG (1 << 0) /* doc */\n'
                self.assertFalse(self.supported(prefix + source))
                self.assertFalse(layout.LayoutComparer().equivalent(source.encode(), source.encode()))


if __name__ == '__main__':
    unittest.main()
