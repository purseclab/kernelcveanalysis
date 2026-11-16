from collections.abc import Iterator
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import kpatch.filter.macro_lookup as lookup_module
from kpatch.filter.git_output import GitGrepProtocolError, GitGrepRow
from kpatch.filter.macro_lookup import MacroDefinition, MacroLookup, MacroObservation, MacroOrigin
from kpatch.filter.reference_index import ReferenceSite
from kpatch.git import GitRepo


def row(path: str, text: bytes, *, revision: str = 'r', line: int = 1) -> GitGrepRow:
    return GitGrepRow((revision + ':' + path).encode(), line, text)


def rows(values: tuple[GitGrepRow, ...]) -> Iterator[GitGrepRow]:
    yield from values


class MacroLookupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name)
        self.repo = GitRepo(self.path)
        subprocess.run(['git', '-C', str(self.path), 'init', '-q'], check=True)
        subprocess.run(['git', '-C', str(self.path), 'config', 'core.autocrlf', 'false'], check=True)

    def tree(self, files: dict[str, bytes]) -> str:
        subprocess.run(['git', '-C', str(self.path), 'rm', '--cached', '-r', '--ignore-unmatch', '.'],
                       check=True, capture_output=True)
        for name, contents in files.items():
            target = self.path / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(contents)
            subprocess.run(['git', '-C', str(self.path), 'add', name], check=True)
        return subprocess.check_output(['git', '-C', str(self.path), 'write-tree']).decode().strip()

    def provider(self, sources: dict[str, bytes]) -> MacroLookup:
        return MacroLookup(self.repo, lambda revision, path: sources[path], lambda revision, site: True)

    def test_complete_numeric_function_and_gnu_variadic_definitions(self) -> None:
        tree = self.tree({'values.h': b'#define VALUE (1 << 4)\n#define APPLY(x) helper(x)\n'
                          b'#define LOG(fmt, args...) helper(fmt, ##args)\n#define VA(...) helper(__VA_ARGS__)\n'})
        provider = MacroLookup(self.repo, self.repo.read_file, lambda revision, site: True)
        observed = provider.lookup(tree, frozenset({'VALUE', 'APPLY', 'LOG', 'VA', 'absent'}))
        self.assertEqual(observed['VALUE'].definitions, (MacroDefinition(False, b'(1 << 4)'),))
        self.assertEqual(observed['APPLY'].definitions[0].parameters, frozenset({'x'}))
        self.assertEqual(observed['LOG'].definitions[0].parameters, frozenset({'fmt', 'args'}))
        self.assertEqual(observed['VA'].definitions[0].parameters, frozenset({'__VA_ARGS__'}))
        self.assertTrue(observed['LOG'].definitions[0].function_like)
        self.assertEqual(observed['absent'], MacroObservation())
        self.assertEqual(provider.repository_scans, 1)
        provider.lookup(tree, frozenset({'VALUE'}))
        self.assertEqual(provider.repository_scans, 1)

    def test_later_known_binding_survives_unrelated_source_opacity(self) -> None:
        sources = {'opaque.h': b'\0# /* unknown */\n', 'values.h': b'#define watched other\n'}
        provider = self.provider(sources)
        with patch.object(lookup_module, 'iter_git_grep_rows', return_value=rows((
                row('opaque.h', sources['opaque.h']), row('values.h', sources['values.h'])))):
            observed = provider.lookup('r', frozenset({'watched'}))['watched']
        self.assertIn(MacroDefinition(False, b'other'), observed.definitions)
        self.assertIn('nul_source', observed.uncertainties)
        self.assertTrue(observed.assumable)

    def test_later_known_binding_survives_read_failure_and_remains_nonassumable(self) -> None:
        def read(revision: str, path: str) -> bytes:
            if path == 'missing.h':
                raise OSError('fixture unreadable')
            return b'#define watched 3\n'
        provider = MacroLookup(self.repo, read, lambda revision, site: True, allow_unknown=True)
        with patch.object(lookup_module, 'iter_git_grep_rows', return_value=rows((
                row('missing.h', b'# /* unobserved */'), row('values.h', b'#define watched 3')))):
            observed = provider.lookup('r', frozenset({'watched'}))['watched']
        self.assertIn(MacroDefinition(False, b'3'), observed.definitions)
        self.assertIn('source_read_failure', observed.uncertainties)
        self.assertFalse(observed.assumable)

    def test_unreadable_literal_target_is_preserved_as_opaque_source(self) -> None:
        def read(revision: str, path: str) -> bytes:
            raise OSError('fixture unreadable')
        provider = MacroLookup(self.repo, read, lambda revision, site: True)
        with patch.object(lookup_module, 'iter_git_grep_rows', return_value=rows((row('missing.h', b'#define watched(x) capture(x)'),))):
            observed = provider.lookup('r', frozenset({'watched'}))['watched']
        self.assertIn(MacroDefinition(True, None), observed.definitions)
        self.assertFalse(observed.assumable)

    def test_positive_variants_preserve_opaque_lhs_under_all_modes(self) -> None:
        definitions = (
            b'??=define VALUE __LINE__\n', b'\0#define VALUE __LINE__\n',
            b'#define VA\\   \nLUE __LINE__\n', b'#define VA\\\rLUE __LINE__\r',
            b'\xef\xbb\xbf#/**/define VALUE __LINE__\n',
            b'#define/**/VA\\ \nLUE __LINE__\n', b'#/**/de\\ \nfine VALUE __LINE__\n',
            b'#define \\u0056ALUE __LINE__\n',
            b'#define\0VALUE __LINE__\n', b'#define VALUE\0OTHER __LINE__\n',
            b'#\0define VALUE __LINE__\n', b'#def\0ine VALUE __LINE__\n',
            b'#define\xef\xbb\xbfVALUE __LINE__\n', b'#define VALUE\xef\xbb\xbfOTHER __LINE__\n',
        )
        for source in definitions:
            for allow_unknown in (False, True):
                with self.subTest(source=source, allow_unknown=allow_unknown):
                    tree = self.tree({'values.h': source})
                    provider = MacroLookup(self.repo, self.repo.read_file, lambda revision, site: True,
                                           allow_unknown=allow_unknown)
                    observed = provider.lookup(tree, frozenset({'VALUE'}))['VALUE']
                    self.assertTrue(any(item.origin is MacroOrigin.SOURCE and item.replacement is None
                                        for item in observed.definitions), observed)
                    self.assertTrue(observed.uncertainties)

    def test_supported_comment_and_standard_splice_forms_are_exact(self) -> None:
        definitions = (b'/* start\ncontinued */ #define VALUE __LINE__\n',
                       b'/* start\ncontinued */ %:define VALUE __LINE__\n',
                       b'#def\\\nine VALUE __LINE__\n', b'#define VA\\\nLUE __LINE__\n',
                       b'#/**/define/**/VALUE __LINE__\n')
        for source in definitions:
            with self.subTest(source=source):
                tree = self.tree({'values.h': source})
                provider = MacroLookup(self.repo, self.repo.read_file, lambda revision, site: True)
                observed = provider.lookup(tree, frozenset({'VALUE'}))['VALUE']
                self.assertIn(MacroDefinition(False, b'__LINE__'), observed.definitions)

    def test_tracked_compiler_and_unclassified_options_keep_distinct_origins(self) -> None:
        tree = self.tree({'Makefile': b'KBUILD_CFLAGS += -Dwatched=1\n',
                          'notes.txt': b'Example flag -Ddocumented=1\n'})
        provider = MacroLookup(self.repo, self.repo.read_file, lambda revision, site: True)
        observed = provider.lookup(tree, frozenset({'watched', 'documented'}))
        self.assertTrue(any(item.origin is MacroOrigin.COMPILER for item in observed['watched'].definitions))
        self.assertTrue(any(item.origin is MacroOrigin.UNCLASSIFIED for item in observed['documented'].definitions))
        self.assertIn('unclassified_compiler_option', observed['documented'].uncertainties)

    def test_spliced_compiler_options_remain_known_compiler_bindings(self) -> None:
        flags = (b'KBUILD_CFLAGS += -DVA\\\nLUE=1\n', b'KBUILD_CFLAGS += -\\\nDVALUE=1\n',
                 b'KBUILD_CFLAGS += -DVA\\  \nLUE=1\n', b'KBUILD_CFLAGS += -DVALUE=1\0\n',
                 b'KBUILD_CFLAGS += -DVALUE=1\r\n')
        for source in flags:
            with self.subTest(source=source):
                tree = self.tree({'Makefile': source})
                observed = MacroLookup(self.repo, self.repo.read_file, lambda revision, site: True,
                                       allow_unknown=True).lookup(tree, frozenset({'VALUE'}))['VALUE']
                self.assertTrue(any(item.origin is MacroOrigin.COMPILER for item in observed.definitions), observed)

    def test_shell_compiler_variables_and_versioned_or_cpp_programs_keep_flags(self) -> None:
        for prefix in (b'gcc-12 ', b'clang++ ', b'"$CC" ', b'${CC:-clang} ', b'$(HOSTCXX) '):
            with self.subTest(prefix=prefix):
                tree = self.tree({'build.sh': prefix + b'-DVALUE=1 input.c\n'})
                observed = MacroLookup(self.repo, self.repo.read_file, lambda revision, site: True).lookup(
                    tree, frozenset({'VALUE'}))['VALUE']
                self.assertTrue(any(item.origin is MacroOrigin.COMPILER for item in observed.definitions), observed)

    def test_file_budget_keeps_scanning_raw_later_lhs_without_reading_more_files(self) -> None:
        sources = {'first.h': b'# /* unrelated */\n', 'later.h': b'#define watched __LINE__\n'}
        reads: list[str] = []
        def read(revision: str, path: str) -> bytes:
            reads.append(path)
            return sources[path]
        provider = MacroLookup(self.repo, read, lambda revision, site: True)
        provider._budget = lookup_module._Budget(20, 1, 1024)
        with patch.object(lookup_module, '_POSITIVE_READ_FILES', 0), patch.object(
                lookup_module, 'iter_git_grep_rows', return_value=rows((
                    row('first.h', sources['first.h']), row('later.h', sources['later.h'])))):
            observed = provider.lookup('r', frozenset({'watched'}))['watched']
        self.assertEqual(reads, ['first.h'])
        self.assertIn(MacroDefinition(False, None), observed.definitions)
        self.assertIn('file_budget', observed.uncertainties)
        self.assertTrue(observed.assumable)

    def test_byte_budget_keeps_raw_positive_facts(self) -> None:
        provider = self.provider({'values.h': b'#define watched __LINE__\n'})
        provider._budget = lookup_module._Budget(20, 20, 4)
        with patch.object(lookup_module, 'iter_git_grep_rows', return_value=rows((row('values.h', b'#define watched __LINE__'),))):
            observed = provider.lookup('r', frozenset({'watched'}))['watched']
        self.assertIn(MacroDefinition(False, None), observed.definitions)
        self.assertIn('byte_budget', observed.uncertainties)

    def test_definition_budget_preserves_the_current_discovery_rows_target(self) -> None:
        source = b'#define OTHER 0\n#define watched capture\n'
        provider = self.provider({'values.h': source})
        with patch.object(lookup_module, '_FILE_DEFINITIONS', 1), patch.object(
                lookup_module, 'iter_git_grep_rows', return_value=rows((row('values.h', b'#define watched capture'),))):
            observed = provider.lookup('r', frozenset({'watched'}))['watched']
        self.assertIn(MacroDefinition(False, None), observed.definitions)
        self.assertIn('definition_budget', observed.uncertainties)

    def test_row_budget_keeps_boundary_positive_without_reading_another_source(self) -> None:
        sources = {'first.h': b'# /* context */\n', 'later.h': b'#define watched 1\n'}
        reads: list[str] = []
        def read(revision: str, path: str) -> bytes:
            reads.append(path)
            return sources[path]
        provider = MacroLookup(self.repo, read, lambda revision, site: True)
        provider._budget = lookup_module._Budget(1, 20, 1024)
        with patch.object(lookup_module, 'iter_git_grep_rows', return_value=rows((
                row('first.h', sources['first.h']), row('later.h', sources['later.h'])))):
            observed = provider.lookup('r', frozenset({'watched'}))['watched']
        self.assertEqual(reads, ['first.h'])
        self.assertIn(MacroDefinition(False, None), observed.definitions)
        self.assertIn('row_budget', observed.uncertainties)

    def test_malformed_rows_do_not_erase_later_known_bindings_or_allow_assumption(self) -> None:
        provider = self.provider({'values.h': b'#define watched 1\n'})
        with patch.object(lookup_module, 'iter_git_grep_rows', return_value=rows((
                row('bad.h', b'/* unknown */', revision='wrong'), row('values.h', b'#define watched 1')))):
            observed = provider.lookup('r', frozenset({'watched'}))['watched']
        self.assertIn(MacroDefinition(False, b'1'), observed.definitions)
        self.assertFalse(observed.assumable)

    def test_git_failure_preserves_earlier_known_binding(self) -> None:
        provider = self.provider({'values.h': b'#define watched 1\n'})
        def failing() -> Iterator[GitGrepRow]:
            yield row('values.h', b'#define watched 1')
            raise subprocess.CalledProcessError(2, ['git', 'grep'])
        with patch.object(lookup_module, 'iter_git_grep_rows', return_value=failing()):
            observed = provider.lookup('r', frozenset({'watched'}))['watched']
        self.assertIn(MacroDefinition(False, b'1'), observed.definitions)
        self.assertFalse(observed.assumable)

    def test_protocol_failure_preserves_earlier_known_binding_without_allowing_assumption(self) -> None:
        provider = self.provider({'values.h': b'#define watched 1\n'})
        def failing() -> Iterator[GitGrepRow]:
            yield row('values.h', b'#define watched 1')
            raise GitGrepProtocolError('truncated row')
        with patch.object(lookup_module, 'iter_git_grep_rows', return_value=failing()):
            observed = provider.lookup('r', frozenset({'watched'}))['watched']
        self.assertIn(MacroDefinition(False, b'1'), observed.definitions)
        self.assertFalse(observed.assumable)

    def test_color_and_unusual_filename_cannot_hide_a_macro_binding(self) -> None:
        self.repo._run_git(['config', 'color.grep', 'always'])
        for filename in ('odd\nfilename.h', 'colon:name.h', 'escape\x1b[31m.h', 'café.h'):
            with self.subTest(filename=filename):
                tree = self.tree({filename: b'#define watched __LINE__\n'})
                observed = MacroLookup(self.repo, self.repo.read_file, lambda revision, site: True).lookup(
                    tree, frozenset({'watched'}))['watched']
                self.assertIn(MacroDefinition(False, b'__LINE__'), observed.definitions)

    def test_missing_pcre_cannot_fallback_to_an_incompatible_negative_query(self) -> None:
        provider = self.provider({})
        def failing() -> Iterator[GitGrepRow]:
            raise subprocess.CalledProcessError(128, ['git', 'grep', '-P'])
            yield row('unreachable', b'')
        with patch.object(lookup_module, 'iter_git_grep_rows', return_value=failing()) as query:
            observed = provider.lookup('r', frozenset({'watched'}))['watched']
        self.assertEqual(query.call_count, 1)
        self.assertIn('repository_scan_failure', observed.uncertainties)
        self.assertFalse(observed.assumable)

    def test_full_file_content_cache_reuses_all_names_and_invalidates_on_content(self) -> None:
        provider = MacroLookup(self.repo, self.repo.read_file, lambda revision, site: True)
        source = b'#define ALPHA 1\n#define BETA 2\n'
        first = self.tree({'values.h': source, 'other.txt': b'first'})
        provider.lookup(first, frozenset({'ALPHA'}))
        second = self.tree({'values.h': source, 'other.txt': b'second'})
        observed = provider.lookup(second, frozenset({'BETA'}))['BETA']
        self.assertIn(MacroDefinition(False, b'2'), observed.definitions)
        self.assertEqual(provider.file_parses, 1)
        self.assertEqual(provider.file_cache_hits, 1)
        third = self.tree({'values.h': b'#define GAMMA 3\n'})
        observed = provider.lookup(third, frozenset({'GAMMA'}))['GAMMA']
        self.assertIn(MacroDefinition(False, b'3'), observed.definitions)
        self.assertEqual(provider.file_parses, 2)

    def test_file_cache_input_and_count_limits_evict_without_changing_facts(self) -> None:
        provider = self.provider({})
        sources = (b'#define A 1\n', b'#define B 2\n', b'#define C 3\n')
        with patch.object(lookup_module, '_FILE_CACHE_BYTES', 24), patch.object(lookup_module, '_FILE_CACHE_COUNT', 2):
            for source in sources:
                provider._file_facts(source)
                self.assertLessEqual(provider.file_cache_input_bytes, 24)
                self.assertLessEqual(len(provider._files), 2)
            result = provider._file_facts(sources[0])
        self.assertEqual(provider.file_parses, 4)
        self.assertEqual(result.definitions[0].name, 'A')
        self.assertEqual(result.definitions[0].definition.replacement, b'1')

    def test_inactive_source_is_not_reused_as_a_context_free_positive(self) -> None:
        source = b'#define watched 1\n'
        tree = self.tree({'values.h': source})
        active = True
        def site(revision: str, reference: ReferenceSite) -> bool:
            return active
        provider = MacroLookup(self.repo, self.repo.read_file, site)
        provider.lookup(tree, frozenset({'watched'}))
        active = False
        second = self.tree({'values.h': source, 'other.txt': b'changed'})
        self.assertEqual(provider.lookup(second, frozenset({'watched'}))['watched'].definitions, ())

    def test_empty_and_invalid_queries_do_not_scan(self) -> None:
        provider = self.provider({})
        self.assertEqual(provider.lookup('r', frozenset()), {})
        self.assertFalse(provider.lookup('r', frozenset({'not-an-identifier'}))['not-an-identifier'].assumable)
        self.assertEqual(provider.repository_scans, 0)
        self.assertFalse(MacroObservation(uncertainties=frozenset({'new_unknown_failure'})).assumable)


if __name__ == '__main__':
    unittest.main()
