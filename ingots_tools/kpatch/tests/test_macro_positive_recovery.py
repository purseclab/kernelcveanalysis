from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import kpatch.filter.macro_lookup as lookup_module
from kpatch.filter.macro_lookup import MacroDefinition, MacroLookup
from kpatch.git import GitRepo


class MacroPositiveRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name)
        self.repo = GitRepo(self.path)
        self.repo._run_git(['init', '-q'])
        self.reads: list[str] = []

    def tree(self, files: dict[str, bytes]) -> str:
        self.repo._run_git(['rm', '--cached', '-r', '--ignore-unmatch', '.'])
        for filename, source in files.items():
            target = self.path / filename
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source)
            self.repo._run_git(['add', '--', filename])
        return self.repo._run_git(['write-tree']).decode().strip()

    def read(self, revision: str, filename: str) -> bytes:
        self.reads.append(filename)
        return self.repo.read_file(revision, filename)

    def provider(self) -> MacroLookup:
        provider = MacroLookup(self.repo, self.read, lambda revision, site: True, allow_unknown=True)
        provider._budget = lookup_module._Budget(100, 0, 1024)
        return provider

    def test_complete_file_recovers_numeric_body_without_another_grep(self) -> None:
        revision = self.tree({'z.h': b'#define VALUE 0\n'})
        provider = self.provider()
        with patch.object(lookup_module, 'iter_git_grep_rows', wraps=lookup_module.iter_git_grep_rows) as query:
            observed = provider.lookup(revision, frozenset({'VALUE'}))['VALUE']
        self.assertEqual(observed.definitions, (MacroDefinition(False, b'0'),))
        self.assertIn('file_budget', observed.uncertainties)
        self.assertTrue(observed.assumable)
        self.assertEqual(self.reads, ['z.h'])
        self.assertEqual(query.call_count, 1)

    def test_extra_evidence_preserves_original_budget_counters_and_flags(self) -> None:
        source = b'#define VALUE 0\n'
        revision = self.tree({'z.h': source})
        provider = self.provider()
        discovery = lookup_module._Discovery.for_names(frozenset({'VALUE'}))
        provider._source(revision, 'z.h', source.rstrip(b'\n'), discovery)
        self.assertEqual(discovery.files, 0)
        self.assertEqual(discovery.input_bytes, 0)
        self.assertTrue(discovery.read_budget_hit)
        self.assertEqual(discovery.processed, {'z.h'})
        self.assertEqual(discovery.fallback, {'z.h'})
        self.assertEqual(discovery.observations()['VALUE'].definitions, (MacroDefinition(False, b'0'),))

    def test_full_comment_context_rejects_a_clean_looking_row(self) -> None:
        revision = self.tree({'z.h': b'/*\n#define VALUE 0\n*/\n#define VALUE __LINE__\n'})
        observed = self.provider().lookup(revision, frozenset({'VALUE'}))['VALUE']
        self.assertEqual(observed.definitions, (MacroDefinition(False, b'__LINE__'),))
        self.assertEqual(self.reads, ['z.h'])

    def test_continued_definition_keeps_its_location_dependency(self) -> None:
        revision = self.tree({'z.h': b'#define VALUE \\\n__LINE__\n'})
        observed = self.provider().lookup(revision, frozenset({'VALUE'}))['VALUE']
        self.assertTrue(any(item.replacement is not None and b'__LINE__' in item.replacement
                            for item in observed.definitions))
        self.assertNotIn(MacroDefinition(False, b'0'), observed.definitions)

    def test_a_row_inside_another_continued_directive_is_not_a_definition(self) -> None:
        revision = self.tree({'z.h': b'#define OTHER \\\n#define VALUE 0\n'})
        observed = self.provider().lookup(revision, frozenset({'VALUE'}))['VALUE']
        self.assertEqual(observed.definitions, ())
        self.assertIn('file_budget', observed.uncertainties)

    def test_conditional_and_repeated_definitions_all_survive_recovery(self) -> None:
        source = b'#if FLAG\n#define VALUE 0\n#else\n#define VALUE __LINE__\n#endif\n#define VALUE 1\n'
        revision = self.tree({'z.h': source})
        observed = self.provider().lookup(revision, frozenset({'VALUE'}))['VALUE']
        self.assertEqual(set(observed.definitions), {MacroDefinition(False, b'0'),
                                                   MacroDefinition(False, b'__LINE__'),
                                                   MacroDefinition(False, b'1')})
        self.assertEqual(self.reads, ['z.h'])

    def test_opaque_facts_from_other_files_survive_before_and_after_recovery(self) -> None:
        opaque = b'\0#define VALUE __LINE__\n'
        complete = b'#define VALUE 0\n#define VALUE 1\n'
        for before in (True, False):
            with self.subTest(opaque_first=before):
                self.reads.clear()
                revision = self.tree({'a.h': opaque if before else complete,
                                      'z.h': complete if before else opaque})
                observed = self.provider().lookup(revision, frozenset({'VALUE'}))['VALUE']
                self.assertIn(MacroDefinition(False, None), observed.definitions)
                self.assertIn(MacroDefinition(False, b'0'), observed.definitions)
                self.assertIn(MacroDefinition(False, b'1'), observed.definitions)

    def test_uncertain_complete_file_keeps_its_opaque_placeholder(self) -> None:
        revision = self.tree({'z.h': b'#define VALUE 0\n\0#define OTHER 1\n'})
        observed = self.provider().lookup(revision, frozenset({'VALUE'}))['VALUE']
        self.assertIn(MacroDefinition(False, None), observed.definitions)
        self.assertIn('nul_source', observed.uncertainties)
        self.assertNotIn(MacroDefinition(False, b'0'), observed.definitions)

    def test_inactive_rows_do_not_consume_the_positive_read_budget(self) -> None:
        revision = self.tree({'z.h': b'#define VALUE 0\n'})
        provider = MacroLookup(self.repo, self.read, lambda rev, site: False, allow_unknown=True)
        provider._budget = lookup_module._Budget(100, 0, 1024)
        observed = provider.lookup(revision, frozenset({'VALUE'}))['VALUE']
        self.assertEqual(observed.definitions, ())
        self.assertEqual(self.reads, [])
        self.assertEqual(provider.positive_file_reads, 0)

    def test_already_processed_fallback_is_not_speculatively_expanded(self) -> None:
        revision = self.tree({'z.h': b'#/* unrelated */\n#define VALUE 0\n'})
        observed = self.provider().lookup(revision, frozenset({'VALUE'}))['VALUE']
        self.assertEqual(observed.definitions, (MacroDefinition(False, None),))
        self.assertEqual(self.reads, [])

    def test_first_baseline_byte_overflow_remains_opaque_but_later_file_can_recover(self) -> None:
        revision = self.tree({'a.h': b'#/* unrelated */\n', 'z.h': b'#define VALUE 0\n'})
        provider = self.provider()
        provider._budget = lookup_module._Budget(100, 10, 1)
        observed = provider.lookup(revision, frozenset({'VALUE'}))['VALUE']
        self.assertEqual(observed.definitions, (MacroDefinition(False, b'0'),))
        self.assertIn('byte_budget', observed.uncertainties)
        self.assertEqual(self.reads, ['a.h', 'z.h'])
        self.assertEqual(provider.positive_file_reads, 1)

    def test_first_overflowing_target_file_is_not_read_a_second_time(self) -> None:
        revision = self.tree({'z.h': b'#define VALUE 0\n'})
        provider = self.provider()
        provider._budget = lookup_module._Budget(100, 10, 1)
        observed = provider.lookup(revision, frozenset({'VALUE'}))['VALUE']
        self.assertEqual(observed.definitions, (MacroDefinition(False, None),))
        self.assertEqual(self.reads, ['z.h'])
        self.assertEqual(provider.positive_file_reads, 0)

    def test_file_and_cumulative_byte_caps_keep_later_opaque_facts(self) -> None:
        first = b'#define VALUE 0\n'
        revision = self.tree({'a.h': first, 'z.h': b'#define VALUE __LINE__\n'})
        for name, limit in (('_POSITIVE_READ_FILES', 1), ('_POSITIVE_READ_BYTES', len(first))):
            with self.subTest(limit=name), patch.object(lookup_module, name, limit):
                self.reads.clear()
                observed = self.provider().lookup(revision, frozenset({'VALUE'}))['VALUE']
                self.assertIn(MacroDefinition(False, b'0'), observed.definitions)
                self.assertIn(MacroDefinition(False, None), observed.definitions)
                self.assertEqual(self.reads, ['a.h'])

    def test_size_probes_are_bounded_even_when_every_file_is_too_large(self) -> None:
        revision = self.tree({name: b'#define VALUE 0\n' for name in ('a.h', 'b.h', 'c.h')})
        original = self.repo._run_git
        with patch.object(lookup_module, '_POSITIVE_READ_FILES', 1), patch.object(
                lookup_module, '_POSITIVE_READ_BYTES', 1), patch.object(self.repo, '_run_git', wraps=original) as query:
            observed = self.provider().lookup(revision, frozenset({'VALUE'}))['VALUE']
        probes = [call for call in query.call_args_list if call.args[0][:2] == ['cat-file', '-s']]
        self.assertEqual(len(probes), 1)
        self.assertEqual(self.reads, [])
        self.assertEqual(observed.definitions, (MacroDefinition(False, None),))

    def test_failed_or_malformed_size_query_remains_nonassumable(self) -> None:
        revision = self.tree({'z.h': b'#define VALUE 0\n'})
        original = self.repo._run_git
        for malformed in (False, True):
            def query(arguments: list[str]) -> bytes:
                if arguments[:2] == ['cat-file', '-s']:
                    if malformed:
                        return b'invalid size\n'
                    raise subprocess.CalledProcessError(128, arguments)
                return original(arguments)
            with self.subTest(malformed=malformed), patch.object(self.repo, '_run_git', side_effect=query):
                observed = self.provider().lookup(revision, frozenset({'VALUE'}))['VALUE']
                self.assertFalse(observed.assumable)
                self.assertIn(MacroDefinition(False, None), observed.definitions)
                self.assertEqual(self.reads, [])

    def test_read_failure_and_size_mismatch_remain_nonassumable(self) -> None:
        revision = self.tree({'z.h': b'#define VALUE 0\n'})
        for mismatch in (False, True):
            def read(rev: str, filename: str) -> bytes:
                if mismatch:
                    return self.repo.read_file(rev, filename) + b'extra'
                raise OSError('fixture read failure')
            with self.subTest(mismatch=mismatch):
                provider = MacroLookup(self.repo, read, lambda rev, site: True, allow_unknown=True)
                provider._budget = lookup_module._Budget(100, 0, 1024)
                observed = provider.lookup(revision, frozenset({'VALUE'}))['VALUE']
                self.assertFalse(observed.assumable)
                self.assertIn(MacroDefinition(False, None), observed.definitions)

    def test_row_boundary_stays_opaque_even_after_complete_file_recovery(self) -> None:
        revision = self.tree({'z.h': b'#define VALUE 0\n#define VALUE __LINE__\n'})
        for rows in (0, 1):
            with self.subTest(rows=rows):
                self.reads.clear()
                provider = self.provider()
                provider._budget = lookup_module._Budget(rows, 0, 1024)
                observed = provider.lookup(revision, frozenset({'VALUE'}))['VALUE']
                self.assertIn(MacroDefinition(False, None), observed.definitions)
                self.assertIn('row_budget', observed.uncertainties)
                self.assertEqual(len(self.reads), rows)


if __name__ == '__main__':
    unittest.main()
