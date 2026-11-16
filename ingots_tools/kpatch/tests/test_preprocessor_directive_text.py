from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
from typing import ClassVar
import unittest

from kpatch.filter.whitespace.c_lexer import preprocessor_directive_text, replace_c_comments, tokenize_c_source


class PreprocessorDirectiveTextTests(unittest.TestCase):
    def test_comment_prefix_is_whitespace_before_a_directive(self) -> None:
        self.assertEqual(preprocessor_directive_text('/* prefix */ #include "api.h"\n'),
                         '  #include "api.h"\n')

    def test_newlines_inside_comments_stay_in_the_directive_inventory(self) -> None:
        source = 'int unrelated; /* first\nsecond */ #include "api.h"\n'
        self.assertEqual(preprocessor_directive_text(source),
                         'int unrelated;  \n #include "api.h"\n')

    def test_splicing_happens_before_comment_recognition(self) -> None:
        source = '/\\\n* prefix */ #inc\\\nlude "api.h"\n'
        self.assertEqual(preprocessor_directive_text(source), '  #include "api.h"\n')

    def test_string_comment_markers_stay_opaque(self) -> None:
        source = 'const char *url="https://example/ /* string */";\n'
        self.assertEqual(preprocessor_directive_text(source), source)

    def test_unmodeled_header_spellings_and_trigraphs_are_unknown(self) -> None:
        for source in ('#include <foo/*part*/bar.h>\n', '??=include "api.h"\n', '/* unfinished'):
            with self.subTest(source=source):
                self.assertIsNone(preprocessor_directive_text(source))

    def test_strict_include_analysis_does_not_truncate_multiline_conditions(self) -> None:
        for source in ('#include /* first\nsecond */ "api.h"\n',
                       '#if /* first\nsecond */ 0\n#else\n#include "api.h"\n#endif\n'):
            with self.subTest(source=source):
                self.assertIsNone(preprocessor_directive_text(source, strict_multiline=True))

    def test_comparisons_and_shifts_in_code_do_not_open_header_names(self) -> None:
        for prefix in ('enum { FLAG = 1U << 0, ', 'pcic |= (1 << 23); ',
                       'if (left < right) ', 'value <<= 1; '):
            with self.subTest(prefix=prefix):
                source = '#include "api.h"\n' + prefix + '/* note */\n'
                expected = '#include "api.h"\n' + prefix + ' \n'
                self.assertEqual(preprocessor_directive_text(source, strict_multiline=True), expected)
                self.assertEqual(replace_c_comments(source), expected)

    def test_hash_and_angle_markers_in_literals_or_comments_do_not_start_directives(self) -> None:
        source = 'puts("#include <"); /* first\nsecond */\nint bits = 1 << 0; /* # < */\n'
        self.assertEqual(preprocessor_directive_text(source, strict_multiline=True),
                         'puts("#include <");  \n\nint bits = 1 << 0;  \n')
        self.assertEqual(replace_c_comments(source), 'puts("#include <");  \nint bits = 1 << 0;  \n')

    def test_header_opacity_survives_comment_prefixes_splices_and_digraphs(self) -> None:
        for prefix in ('#include', '#/**/include', '#/* first\nsecond */include',
                       '/* first\nsecond */ %:inc\\\nlude', '%:include_next', '#import'):
            source = prefix + ' <foo/*old*/bar.h>\n'
            with self.subTest(prefix=prefix):
                self.assertIsNone(preprocessor_directive_text(source))
                self.assertIsNone(preprocessor_directive_text(source, strict_multiline=True))
                self.assertNotEqual(replace_c_comments(source), replace_c_comments(source.replace('old', 'new')))

    def test_unclassified_directive_angle_contexts_stay_conservative(self) -> None:
        for source in ('#if __has_include(<foo/*part*/bar.h>)\n#endif\n',
                       '#if ALIAS(<foo/*part*/bar.h>)\n#endif\n',
                       '#define HEADER <foo/*part*/bar.h>\n'):
            with self.subTest(source=source):
                self.assertIsNone(preprocessor_directive_text(source))

    def test_unsupported_phase_one_context_cannot_use_token_fallback(self) -> None:
        for source in ('??=include <foo/*part*/bar.h>\n',
                       '\ufeff#include <foo/*part*/bar.h>\n',
                       'int prefix;\r#include <foo/*part*/bar.h>\r'):
            with self.subTest(source=source):
                self.assertIsNone(preprocessor_directive_text(source))
                self.assertIsNone(replace_c_comments(source))
                self.assertIsNone(tokenize_c_source(source))

    def test_header_unit_imports_are_not_reinterpreted_as_comparisons(self) -> None:
        for source in ('import <foo/*part*/bar.h>;\n',
                       'export module example; import <foo/*part*/bar.h>;\n',
                       'import\n<foo/*part*/bar.h>;\n'):
            with self.subTest(source=source):
                self.assertIsNone(preprocessor_directive_text(source))
                self.assertIsNone(replace_c_comments(source))
                self.assertIsNone(tokenize_c_source(source))

    def test_preprocessor_import_and_header_path_import_word_remain_distinct(self) -> None:
        for source in ('#include <linux/import.h>\n', '#import "api.h"\n', '%:include <linux/import.h>\n'):
            with self.subTest(source=source):
                self.assertEqual(preprocessor_directive_text(source), source)
                self.assertIsNotNone(tokenize_c_source(source))

    def test_preprocessor_header_directive_variants_keep_complete_header_names(self) -> None:
        for directive in ('#include', '#include_next', '#import', '%:include', '%:include_next', '%:import'):
            old = directive + ' <foo/*old*/bar.h>\n'
            new = directive + ' <foo/*new*/bar.h>\n'
            with self.subTest(directive=directive):
                self.assertNotEqual(tokenize_c_source(old), tokenize_c_source(new))

    def test_many_comments_on_one_long_line_preserve_directive_context(self) -> None:
        source = '#define LONG ' + 'value/**/ ' * 10000 + '\n'
        self.assertEqual(preprocessor_directive_text(source, strict_multiline=True),
                         '#define LONG ' + 'value  ' * 10000 + '\n')
        self.assertEqual(replace_c_comments(source), '#define LONG ' + 'value  ' * 10000 + '\n')


class PreprocessorCompilerOracleTests(unittest.TestCase):
    compilers: ClassVar[tuple[str, ...]]

    @classmethod
    def setUpClass(cls) -> None:
        cls.compilers = tuple(path for name in ('gcc', 'clang') if (path := shutil.which(name)) is not None)
        if not cls.compilers:
            raise unittest.SkipTest('GCC or Clang is required for the independent compiler oracle')

    def setUp(self) -> None:
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.headers = Path(directory.name)
        (self.headers / 'regular.h').write_text('#define HEADER_VALUE 31\n')
        for name, value in (('old', 31), ('new', 47)):
            for path in (self.headers / f'foo/*{name}*/bar.h', self.headers / f'foo/{name}.h'):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f'#define HEADER_VALUE {value}\n')
        present = self.headers / 'presence/*present*/only.h'
        present.parent.mkdir(parents=True, exist_ok=True)
        present.write_text('/* present header */\n')

    def compile(self, compiler: str, source: str) -> str:
        result = subprocess.run([compiler, '-S', '-O2', '-g0', '-std=c11', '-nostdinc',
                                 '-DCONFIG_TEST=1', '-I', str(self.headers), '-x', 'c', '-o', '-', '-'],
                                input=source, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_normalized_shift_comment_sources_compile_identically(self) -> None:
        sources = (
            '#include "regular.h"\nint main(void) {unsigned x=1U << 0; /* retprobe */ return HEADER_VALUE+x;}\n',
            '/* prefix */#include "regular.h"\nenum {F=1U << 0, /* note */};\nint main(void) {return HEADER_VALUE+F;}\n',
            '#if CONFIG_TEST /* conditional */\n#include "regular.h"\n#else\n#error wrong branch\n#endif\n'
            'int main(void) {int x=1; if (x < 3) /* comparison */ return HEADER_VALUE; return 0;}\n',
            '#inc\\\nlude "regular.h"\nint main(void) {const char *s="#include <"; /* first\nsecond */ return HEADER_VALUE+s[0];}\n',
        )
        for compiler in self.compilers:
            for source in sources:
                with self.subTest(compiler=compiler, source=source):
                    normalized = preprocessor_directive_text(source, strict_multiline=True)
                    self.assertIsNotNone(normalized)
                    assert normalized is not None
                    self.assertEqual(self.compile(compiler, source), self.compile(compiler, normalized))

    def test_opaque_header_spellings_are_real_behavior_changing_inputs(self) -> None:
        prefixes = ('#include <foo/*NAME*/bar.h>', '#include_next <foo/*NAME*/bar.h>',
                    '#import <foo/*NAME*/bar.h>', '%:include_next <foo/*NAME*/bar.h>',
                    '%:import <foo/*NAME*/bar.h>', '#/**/include <foo/*NAME*/bar.h>',
                    '#/* first\nsecond */include <foo/*NAME*/bar.h>',
                    '/* prefix\n */ %:inc\\\nlude <foo/*NAME*/bar.h>',
                    '#include <foo//NAME.h>', '??=include <foo/*NAME*/bar.h>',
                    '\ufeff#include <foo/*NAME*/bar.h>', 'int prefix;\r#include <foo/*NAME*/bar.h>\r')
        for compiler in self.compilers:
            for prefix in prefixes:
                with self.subTest(compiler=compiler, prefix=prefix):
                    old = prefix.replace('NAME', 'old') + '\nint main(void) {return HEADER_VALUE;}\n'
                    new = prefix.replace('NAME', 'new') + '\nint main(void) {return HEADER_VALUE;}\n'
                    self.assertIsNone(preprocessor_directive_text(old, strict_multiline=True))
                    self.assertNotEqual(self.compile(compiler, old), self.compile(compiler, new))

    def test_header_name_comments_change_has_include_conditionals(self) -> None:
        source = ('#if __has_include(<presence/*NAME*/only.h>)\n#define HEADER_VALUE 31\n'
                  '#else\n#define HEADER_VALUE 47\n#endif\nint main(void) {return HEADER_VALUE;}\n')
        for compiler in self.compilers:
            with self.subTest(compiler=compiler):
                present = source.replace('NAME', 'present')
                missing = source.replace('NAME', 'missing')
                self.assertIsNone(preprocessor_directive_text(present, strict_multiline=True))
                self.assertNotEqual(self.compile(compiler, present), self.compile(compiler, missing))


if __name__ == '__main__':
    unittest.main()
