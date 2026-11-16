from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import kpatch.filter.whitespace.layout as layout_module
from kpatch.filter.whitespace.layout import LayoutComparer, _PhysicalCursor, _SpliceMap


class LayoutComparerTests(unittest.TestCase):
    def test_multiline_directive_comments_preserve_logical_boundaries(self) -> None:
        pairs = (
            (b'#define X a/* old\n*/b\n', b'#define X a/* new\n*/b\n'),
            (b'#if 1 /* old\n*/ && 0\nint x;\n#endif\n',
             b'#if 1 /* new\n*/ && 0\nint x;\n#endif\n'),
            (b'#define X 1 /* old\n*/\n', b'#define X 1 /* a longer note\n*/\n'),
        )
        for old, new in pairs:
            with self.subTest(old=old):
                comparer = LayoutComparer()
                self.assertTrue(comparer.equivalent(old, new))
                self.assertTrue(comparer.equivalent_ignoring_line_numbers(old, new))

    def test_directive_end_lines_remain_observable_after_comments_and_splices(self) -> None:
        pairs = (
            (b'#line 100 /* old */\n\nint value=__LINE__;\n',
             b'#line 100 /* old\n*/\nint value=__LINE__;\n'),
            (b'#line 100\n\nint value=__LINE__;\n',
             b'#line 100\\\n\nint value=__LINE__;\n'),
            (b'#line __LINE__\n\nint value=__LINE__;\n',
             b'#line __LINE__\\\n\nint value=__LINE__;\n'),
            (b'#define X 1 /* old */', b'#define X 1 /* old\n*/'),
        )
        for old, new in pairs:
            with self.subTest(old=old):
                comparer = LayoutComparer()
                self.assertFalse(comparer.equivalent(old, new))
                self.assertTrue(comparer.equivalent_ignoring_line_numbers(old, new))

    def test_multiline_comment_keeps_function_macro_spacing_significant(self) -> None:
        old = b'#define F/* old\n*/(x) x\n'
        new = b'#define F(x) x\n'
        self.assertFalse(LayoutComparer().equivalent(old, new))
        self.assertFalse(LayoutComparer().equivalent_ignoring_line_numbers(old, new))

    def test_trivia_after_explicit_directive_newline_is_redundant(self) -> None:
        old = b'#include "observer.h"\n\nint value = LOCATION;\n'
        new = b'#include "observer.h"\nint value = LOCATION;\n'
        comparer = LayoutComparer()
        self.assertFalse(comparer.equivalent(old, new))
        self.assertTrue(comparer.equivalent_ignoring_line_numbers(old, new))

    def test_directive_in_macro_argument_keeps_newline_separation(self) -> None:
        prefix = b'#define S(x) #x\nconst char*s=S(a\n#define UNUSED 1\n'
        old, new = prefix + b'\n+b);\n', prefix + b'+b);\n'
        self.assertTrue(LayoutComparer().equivalent_ignoring_line_numbers(old, new))
        self.assertFalse(LayoutComparer().equivalent(old, new))

    def test_comment_wording_and_own_line_lengths_preserve_real_token_positions(self) -> None:
        old = b'/* short */\nint value = 1; /* tail */\n'
        new = b'/* a longer explanation */\nint value = 1; /* another longer tail */\n'
        self.assertTrue(LayoutComparer().equivalent(old, new))

    def test_relaxed_comparison_ignores_only_physical_line_numbers(self) -> None:
        pairs = ((b'/* one */\nint value = 1;\n', b'/* one\n two */\nint value = 1;\n'),
                 (b'int x;\nint y;\n', b'int x;\n\nint y;\n'),
                 (b'ab\\\ncd;', b'ab\\\n\\\ncd;'))
        for old, new in pairs:
            with self.subTest(old=old):
                comparer = LayoutComparer()
                self.assertFalse(comparer.equivalent(old, new))
                self.assertTrue(comparer.equivalent_ignoring_line_numbers(old, new))

    def test_relaxed_comparison_keeps_columns_token_values_and_gaps(self) -> None:
        pairs = ((b'int n = /*a*/1;\n', b'int n = /*longer*/1;\n'),
                 (b'int n = 1/*a*/;\n', b'int n = 1/*longer*/;\n'),
                 (b'int n = 1;\n', b'int n = 2;\n'),
                 (b'const char*s=S(1+ 2);\n', b'const char*s=S(1 +2);\n'),
                 (b'const char*s=S(a\\\n+b);\n', b'const char*s=S(a \n+b);\n'))
        for old, new in pairs:
            with self.subTest(old=old):
                comparer = LayoutComparer()
                self.assertFalse(comparer.equivalent(old, new))
                self.assertFalse(comparer.equivalent_ignoring_line_numbers(old, new))

    def test_relaxed_comparison_keeps_directive_and_requested_newline_tokens(self) -> None:
        pairs = ((b'#define X 1\n+2\n', b'#define X 1+2\n'),
                 (b'#define F(x) x\n', b'#define F (x) x\n'),
                 (b'#define X a/*\n*/b\n', b'#define X a  \n  b\n'))
        for old, new in pairs:
            with self.subTest(old=old):
                self.assertFalse(LayoutComparer().equivalent_ignoring_line_numbers(old, new))
        self.assertFalse(LayoutComparer(ignore_non_directive_newlines=False)
                         .equivalent_ignoring_line_numbers(b'int x;\n', b'int x;\n\n'))

    def test_relaxed_comparison_does_not_ignore_header_spellings(self) -> None:
        pairs = ((b'#include <path/*x*/file>\n', b'#include <path/*y*/file>\n'),
                 (b'#include <head x.h>\n', b'#include <head\tx.h>\n'),
                 (b'#include "old.h"\n', b'#include "new.h"\n'))
        for old, new in pairs:
            with self.subTest(old=old):
                self.assertFalse(LayoutComparer().equivalent_ignoring_line_numbers(old, new))

    def test_inline_comment_length_cannot_move_numbers_or_punctuation(self) -> None:
        pairs = ((b'int n = /*a*/1;\n', b'int n = /*longer*/1;\n'),
                 (b'int n = 1/*a*/;\n', b'int n = 1/*longer*/;\n'))
        for old, new in pairs:
            with self.subTest(old=old):
                self.assertFalse(LayoutComparer().equivalent(old, new))

    def test_macro_argument_whitespace_survives_phase_two_normalization(self) -> None:
        old = b'#define S(x) #x\nconst char *value = S(a\\\n+b);\n'
        new = b'#define S(x) #x\nconst char *value = S(a \n+b);\n'
        # Every real token has the same physical start/end; the removed
        # backslash is the difference between no gap and a stringified gap.
        self.assertFalse(LayoutComparer().equivalent(old, new))

    def test_unrelated_standard_splices_do_not_block_comment_changes(self) -> None:
        for newline in (b'\n', b'\r\n'):
            prefix = b'#define SUM(x) \\' + newline + b' ((x) + 1)' + newline
            old = prefix + b'/* old */' + newline + b'int run(void) { return SUM(2); }' + newline
            new = prefix + b'/* a longer explanation */' + newline + b'int run(void) { return SUM(2); }' + newline
            with self.subTest(newline=newline):
                self.assertTrue(LayoutComparer().equivalent(old, new))

    def test_splice_mapper_keeps_token_ends_left_and_next_starts_right(self) -> None:
        source = 'name\\\n\\\r\n;'
        mapper, cursor = _SpliceMap(source), _PhysicalCursor(source)
        cursor.advance(mapper.physical(0, right_bias=True))
        self.assertEqual((cursor.line, cursor.column), (1, 1))
        cursor.advance(mapper.physical(4, right_bias=False))
        self.assertEqual((cursor.line, cursor.column), (1, 5))
        cursor.advance(mapper.physical(4, right_bias=True))
        self.assertEqual((cursor.line, cursor.column), (3, 1))
        cursor.advance(mapper.physical(5, right_bias=False))
        self.assertEqual((cursor.line, cursor.column), (3, 2))

    def test_comment_only_changes_at_eof_have_no_surviving_observer(self) -> None:
        pairs = ((b'int x;\n/* short */', b'int x;\n/* longer\ncomment */'),
                 (b'/* short */', b'/* longer\ncomment */'),
                 (b'int x; // short', b'int x; // longer comment'))
        for old, new in pairs:
            with self.subTest(old=old):
                self.assertTrue(LayoutComparer().equivalent(old, new))

    def test_directive_trailing_comments_and_synthetic_eof_do_not_move_real_tokens(self) -> None:
        for old, new in ((b'#define X 1\n', b'#define X 1 /* description */\n'),
                         (b'#define X 1', b'#define X 1 /* description */'),
                         (b'#define X 1', b'#define X 1\n')):
            with self.subTest(old=old, new=new):
                self.assertTrue(LayoutComparer().equivalent(old, new))

    def test_directive_boundaries_and_function_macro_adjacency_remain_significant(self) -> None:
        pairs = ((b'#define F(x) x\n', b'#define F (x) x\n'),
                 (b'#define X 1\n+2\n', b'#define X 1+2\n'),
                 (b'#define X a/*\n*/b\n', b'#define X a  \n  b\n'))
        for old, new in pairs:
            with self.subTest(old=old):
                self.assertFalse(LayoutComparer().equivalent(old, new))

    def test_non_directive_newline_option_is_forwarded(self) -> None:
        old, new = b'int x;\n', b'int x;\n\n'
        self.assertTrue(LayoutComparer().equivalent(old, new))
        self.assertFalse(LayoutComparer(ignore_non_directive_newlines=False).equivalent(old, new))

    def test_utf8_columns_use_bytes_and_tabs_use_their_physical_byte_extent(self) -> None:
        comparer = LayoutComparer()
        self.assertFalse(comparer.equivalent(b'/*a*/ int x;\n', '/*é*/ int x;\n'.encode()))
        self.assertTrue(comparer.equivalent(b'/*ab*/ int x;\n', '/*é*/ int x;\n'.encode()))
        self.assertTrue(comparer.equivalent(b'/*\tab*/ int x;\n', b'/*ab\t*/ int x;\n'))

    def test_unsupported_inputs_never_compare_positive_even_when_identical(self) -> None:
        sources = (b'int x;\0', b'??=define X 1\n', b'\xef\xbb\xbfint x;', b'int x;\r',
                   b'int x;\xff', b'#define X \\  \n1\n', b'/* unterminated', b'"unterminated',
                   b'int x; import header;', b'int x = `y`;',
                   'int\u00a0x;'.encode(), 'int\u0085x;'.encode(), '\u2028'.encode())
        for source in sources:
            with self.subTest(source=source):
                self.assertFalse(LayoutComparer().equivalent(source, source))
                self.assertFalse(LayoutComparer().equivalent_ignoring_line_numbers(source, source))

    def test_raw_strings_include_phase_two_split_introducers(self) -> None:
        for prefix in (b'R', b'u8R', b'uR', b'UR', b'LR', b'R\\\n'):
            source = b'const char *s = ' + prefix + b'"tag(/* raw */)tag";\n'
            with self.subTest(prefix=prefix):
                self.assertFalse(LayoutComparer().equivalent(source, source))
                self.assertFalse(LayoutComparer().equivalent_ignoring_line_numbers(source, source))
        self.assertTrue(LayoutComparer().equivalent(b'void run(void){log(KERN_ERR"message");}',
                                                    b'void run(void){log(KERN_ERR"message");}'))

    def test_header_feature_operators_are_unsupported_without_special_header_lexing(self) -> None:
        for name in (b'__has_include', b'__has_include_next', b'__has_embed'):
            source = b'#if ' + name + b'(<path/*part*/file>)\nint x;\n#endif\n'
            with self.subTest(name=name):
                self.assertFalse(LayoutComparer().equivalent(source, source))
                self.assertFalse(LayoutComparer().equivalent_ignoring_line_numbers(source, source))
        self.assertFalse(LayoutComparer().equivalent(b'#embed "bytes"\n', b'#embed "bytes"\n'))
        self.assertTrue(LayoutComparer().equivalent(b'int embed;\n', b'int embed;\n'))

    def test_source_and_token_budget_failures_do_not_cache_partial_success(self) -> None:
        source = b'int x;'
        with patch.object(layout_module, '_MAX_SOURCE_BYTES', len(source) - 1):
            comparer = LayoutComparer()
            self.assertFalse(comparer.equivalent(source, source))
            self.assertFalse(comparer.equivalent_ignoring_line_numbers(source, source))
            self.assertEqual(comparer.stats.cache_entries, 0)
        with patch.object(layout_module, '_MAX_TOKENS', 2):
            comparer = LayoutComparer()
            self.assertFalse(comparer.equivalent(source, source))
            self.assertFalse(comparer.equivalent_ignoring_line_numbers(source, source))
            self.assertEqual(comparer.stats.unsupported_scans, 1)
            self.assertEqual(comparer.stats.cache_hits, 3)

    def test_strict_and_relaxed_methods_reuse_the_same_complete_scan(self) -> None:
        comparer = LayoutComparer()
        old, new = b'/* note */\nint x;\n', b'/* note\n more */\nint x;\n'
        self.assertFalse(comparer.equivalent(old, new))
        self.assertEqual(comparer.stats.scans, 2)
        self.assertTrue(comparer.equivalent_ignoring_line_numbers(old, new))
        self.assertFalse(comparer.equivalent(old, new))
        self.assertEqual(comparer.stats.scans, 2)
        self.assertEqual(comparer.stats.cache_hits, 4)

    def test_content_cache_reuses_complete_facts_and_has_input_and_entry_limits(self) -> None:
        comparer = LayoutComparer()
        source = b'int x;\n'
        self.assertTrue(comparer.equivalent(source, source))
        self.assertEqual(comparer.stats.scans, 1)
        self.assertEqual(comparer.stats.cache_hits, 1)
        self.assertFalse(comparer.equivalent(source, b'int y;\n'))
        with patch.object(layout_module, '_CACHE_ENTRIES', 2), patch.object(layout_module, '_CACHE_INPUT_BYTES', 14):
            for number in range(5):
                value = f'int n{number};\n'.encode()
                self.assertTrue(comparer.equivalent(value, value))
                self.assertTrue(comparer.equivalent_ignoring_line_numbers(value, value))
                self.assertLessEqual(comparer.stats.cache_entries, 2)
                self.assertLessEqual(comparer.stats.cache_input_bytes, 14)


class CompiledLayoutTests(unittest.TestCase):
    def test_line_alias_runtime_change_is_accepted_only_by_explicit_relaxed_method(self) -> None:
        old = b'#include "observer.h"\n/* note */\nint main(void){return LOC;}\n'
        new = b'#include "observer.h"\n/* note\n more */\nint main(void){return LOC;}\n'
        comparer = LayoutComparer()
        self.assertFalse(comparer.equivalent(old, new))
        self.assertTrue(comparer.equivalent_ignoring_line_numbers(old, new))
        compiled = 0
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'observer.h').write_text('#define LOC __LINE__\n')
            for name in ('gcc', 'clang'):
                compiler = shutil.which(name)
                if compiler is None:
                    continue
                with self.subTest(compiler=name):
                    exits = []
                    for version, source in (('old', old), ('new', new)):
                        path, binary = root / (version + '.c'), root / (name + '-' + version)
                        path.write_bytes(source)
                        result = subprocess.run([compiler, '-std=gnu11', '-I', directory, str(path), '-o', str(binary)],
                                                capture_output=True, text=True)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        exits.append(subprocess.run([str(binary)]).returncode)
                    self.assertEqual(exits, [3, 4])
                    compiled += 1
        if not compiled:
            self.skipTest('GCC/Clang is unavailable')

    def test_included_alias_and_stringification_runtime_changes_are_rejected(self) -> None:
        cases = (
            ('line', '#define LOC __LINE__\n',
             '#include "observer.h"\n/*a*/int main(void){return LOC;}\n',
             '#include "observer.h"\n/*a\nb*/int main(void){return LOC;}\n', False),
            ('column', '#define LOC __builtin_COLUMN()\n',
             '#include "observer.h"\nint main(void){return /*a*/ LOC;}\n',
             '#include "observer.h"\nint main(void){return /*longer*/ LOC;}\n', False),
            ('splice_gap', '#define S(x) #x\n',
             '#include "observer.h"\nint main(void){return S(a\\\n+b)[1];}\n',
             '#include "observer.h"\nint main(void){return S(a \n+b)[1];}\n', False),
            ('utf8_byte_columns', '#define LOC __builtin_COLUMN()\n',
             '#include "observer.h"\nint main(void){return /*ab*/ LOC;}\n',
             '#include "observer.h"\nint main(void){return /*é*/ LOC;}\n', True),
            ('tab_byte_columns', '#define LOC __builtin_COLUMN()\n',
             '#include "observer.h"\nint main(void){return /*\tab*/ LOC;}\n',
             '#include "observer.h"\nint main(void){return /*ab\t*/ LOC;}\n', True),
        )
        compiled = 0
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for name, header, old, new, equal in cases:
                self.assertEqual(LayoutComparer().equivalent(old.encode(), new.encode()), equal)
                self.assertEqual(LayoutComparer().equivalent_ignoring_line_numbers(old.encode(), new.encode()), equal)
                (root / 'observer.h').write_text(header)
                for compiler_name in ('gcc', 'clang'):
                    compiler = shutil.which(compiler_name)
                    if compiler is None or compiler_name == 'gcc' and '__builtin_COLUMN' in header:
                        continue
                    with self.subTest(case=name, compiler=compiler_name):
                        exits = []
                        for version, source in (('old', old), ('new', new)):
                            path = root / (version + '.c')
                            path.write_text(source)
                            binary = root / (compiler_name + '-' + version)
                            result = subprocess.run([compiler, '-std=gnu11', '-I', directory, str(path), '-o', str(binary)],
                                                    capture_output=True, text=True)
                            self.assertEqual(result.returncode, 0, result.stderr)
                            exits.append(subprocess.run([str(binary)]).returncode)
                        self.assertEqual(exits[0] == exits[1], equal)
                        compiled += 1
        if not compiled:
            self.skipTest('GCC/Clang is unavailable')


if __name__ == '__main__':
    unittest.main()
