from collections.abc import Iterator
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import kpatch.filter.input_roles as roles
from kpatch.filter.input_roles import RawInputIndex, RawInputKind
from kpatch.filter.input_role_models import (InputInventoryState, RawInputFailure, RawInputFailureKind,
                                            RawInputObservation, RawInputUnknown, RawInputUnknownKind)
from kpatch.git import GitRepo


def issues(observed: RawInputObservation) -> tuple[RawInputUnknown | RawInputFailure, ...]:
    return (*observed.unknowns, *observed.failures)


def unknown_kinds(observed: RawInputObservation) -> set[RawInputUnknownKind]:
    return {note.kind for note in observed.unknowns}


def failure_kinds(observed: RawInputObservation) -> set[RawInputFailureKind]:
    return {failure.kind for failure in observed.failures}

class RawInputIndexTests(unittest.TestCase):

    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name)
        self.repo = GitRepo(self.path)
        self.git('init', '-q')
        self.reads: list[tuple[str, str]] = []
        self.index = RawInputIndex(self.repo, self.read)

    def git(self, *arguments: str) -> bytes:
        return subprocess.check_output(['git', '-C', str(self.path), *arguments], stderr=subprocess.PIPE)

    def tree(self, files: dict[str, str]) -> str:
        self.git('rm', '--cached', '-r', '--ignore-unmatch', '.')
        for name, source in files.items():
            path = self.path / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source)
            self.git('--literal-pathspecs', 'add', '--', name)
        return self.git('write-tree').decode().strip()

    def read(self, revision: str, path: str) -> bytes:
        self.reads.append((revision, path))
        return self.repo.read_file(revision, path)

    def alias_tree(self, files: dict[str, str], links: dict[str, str]) -> str:
        self.tree(files)
        for name, target in links.items():
            path = self.path / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.is_symlink():
                path.unlink()
            path.symlink_to(target)
            self.git('--literal-pathspecs', 'add', '--', name)
        return self.git('write-tree').decode().strip()

    def test_inventory_states_and_local_unknown_provenance_are_typed(self) -> None:
        with self.assertRaises(TypeError):
            RawInputObservation()  # type: ignore[call-arg]
        source = 'generated.c: $(INPUT)\n\tperl gen.pl $< $@\n'
        revision = self.tree({'Makefile': source})
        observed = self.index.lookup(revision, 'api.h')
        self.assertEqual(observed.state, InputInventoryState.FULL)
        self.assertFalse(observed.failures)
        note, = observed.unknowns
        self.assertEqual((note.consumer_path, note.line, note.kind, note.operand),
                         ('Makefile', 1, RawInputUnknownKind.MAKE_OPERAND, '$(INPUT)'))
        from hashlib import sha256
        self.assertEqual(note.source_sha256, sha256(source.encode()).hexdigest())
        self.assertEqual(self.index.veto_observation(revision, 'api.h').state, InputInventoryState.RETENTION_WITNESS)
        self.assertEqual(self.index.lookup('HEAD', 'api.h').state, InputInventoryState.INCOMPLETE)

    def test_expansion_unknown_preserves_literal_rules_all_literal_values_and_asm(self) -> None:
        values = ' '.join(f'input{number}.h' for number in range(129))
        source = ('out.c: watched.h\n\tperl gen.pl $< $@\n'
                  f'INPUTS := {values}\nother.c: $(INPUTS)\n\tperl gen.pl $^ $@\n'
                  'after.c: later.h\n\tperl gen.pl $< $@\n'
                  'cmd_raw = .incbin "asm.h"\n')
        revision = self.tree({'Makefile': source})
        for name in ('watched.h', 'input0.h', 'input128.h', 'later.h', 'asm.h'):
            with self.subTest(name=name):
                observed = self.index.lookup(revision, name)
                self.assertEqual(observed.state, InputInventoryState.FULL)
                self.assertTrue(observed.consumers)
                self.assertFalse(observed.failures)
                self.assertIn(RawInputUnknownKind.MAKE_EXPANSION, unknown_kinds(observed))

    def test_generic_in_tree_assembly_alias_reads_regular_target(self) -> None:
        revision = self.alias_tree({'common/source.data': '.incbin "api.h"\n', 'api.h': '/* 7 */\n'},
                                   {'drivers/raw.S': '../common/source.data'})
        observed = self.index.lookup(revision, 'api.h')
        self.assertEqual(observed.state, InputInventoryState.FULL)
        self.assertEqual(observed.consumers[0].path, 'drivers/raw.S')
        self.assertFalse(issues(observed))

    def test_consumer_alias_target_and_link_deltas_never_leave_stale_facts(self) -> None:
        links = {'drivers/raw.S': '../common/first.data'}
        first = self.alias_tree({'common/first.data': '.incbin "api.h"\n'}, links)
        self.assertTrue(self.index.lookup(first, 'api.h').consumers)
        second = self.alias_tree({'common/first.data': '.incbin "other.h"\n'}, links)
        self.assertFalse(self.index.lookup(second, 'api.h').consumers)
        self.assertTrue(self.index.lookup(second, 'other.h').consumers)
        third = self.alias_tree({'common/first.data': '.incbin "other.h"\n', 'common/second.data': '.incbin "third.h"\n'},
                                {'drivers/raw.S': '../common/second.data'})
        self.assertFalse(self.index.lookup(third, 'other.h').consumers)
        self.assertTrue(self.index.lookup(third, 'third.h').consumers)
        missing = self.alias_tree({}, {'drivers/raw.S': '../common/second.data'})
        observed = self.index.lookup(missing, 'third.h')
        self.assertFalse(observed.consumers)
        self.assertEqual(observed.state, InputInventoryState.FULL)
        self.assertIn(RawInputFailureKind.INPUT_ALIAS, failure_kinds(observed))
        self.assertEqual(self.index.stats().repository_scans, 1)

    def test_alias_semantic_unknown_is_not_a_regular_file_retention_witness(self) -> None:
        source = 'generated.c: $(INPUT)\n\tperl gen.pl $< $@\n'
        first = self.alias_tree({'common/rules.data': source}, {'Makefile': 'common/rules.data'})
        observed = self.index.veto_observation(first, 'api.h')
        self.assertEqual(observed.state, InputInventoryState.FULL)
        self.assertIn(RawInputUnknownKind.MAKE_OPERAND, unknown_kinds(observed))
        self.assertEqual(observed.unknowns[0].consumer_path, 'common/rules.data')
        from hashlib import sha256
        self.assertEqual(observed.unknowns[0].source_sha256,
                         sha256(self.repo.read_file(first, 'common/rules.data')).hexdigest())
        self.assertIsNone(self.index._witness)
        self.assertFalse(self.index._veto_cache)
        second = self.alias_tree({'common/rules.data': source, 'unrelated.txt': 'changed'}, {'Makefile': 'common/rules.data'})
        self.assertEqual(self.index.veto_observation(second, 'api.h').state, InputInventoryState.FULL)
        self.assertEqual(self.index.stats().witness_hits, 0)

    def test_consumer_alias_cycles_outside_paths_and_budgets_remain_hard(self) -> None:
        for links in ({'first.S': 'second.S', 'second.S': 'first.S'}, {'first.S': '/outside/source.S'}):
            with self.subTest(links=links):
                revision = self.alias_tree({}, links)
                fresh = RawInputIndex(self.repo, self.read)
                observed = fresh.lookup(revision, 'api.h')
                self.assertEqual(observed.state, InputInventoryState.FULL)
                self.assertIn(RawInputFailureKind.INPUT_ALIAS, failure_kinds(observed))
                self.assertFalse(observed.unknowns)
        revision = self.alias_tree({'source.data': '.incbin "api.h"\n'}, {'raw.S': 'source.data'})
        fresh = RawInputIndex(self.repo, self.read)
        with patch.object(roles, '_MAX_FILES', 1):
            observed = fresh.lookup(revision, 'api.h')
        self.assertEqual(observed.state, InputInventoryState.INCOMPLETE)
        self.assertIn(RawInputFailureKind.FILE_BUDGET, failure_kinds(observed))

    def test_constructor_is_lazy_and_queries_share_one_inventory(self) -> None:
        with patch.object(roles, 'iter_git_records', side_effect=AssertionError('native work')):
            RawInputIndex(self.repo, self.read)
        revision = self.tree({'blob.S': '.incbin "api.h"\n', 'api.h': '/* 7 */\n'})
        first = self.index.lookup(revision, 'api.h')
        count = len(self.reads)
        self.assertEqual(len(first.consumers), 1)
        self.assertEqual(issues(first), ())
        self.assertEqual(self.index.lookup(revision, './api.h'), first)
        self.assertEqual(self.index.lookup(revision, 'unrelated.h').consumers, ())
        self.assertEqual(len(self.reads), count)
        self.assertEqual(self.index.stats().repository_scans, 1)
        self.assertEqual(self.index.stats().revision_cache_hits, 2)

    def test_c_inline_incbin_and_assembler_include_remain_raw_roles(self) -> None:
        revision = self.tree({'main.c': 'asm(".incbin \\"drivers/api.h\\"\\n");\n', 'blob.S': '.include "drivers/api.h"\n', 'drivers/api.h': '/* 7 */\n'})
        observed = self.index.lookup(revision, 'drivers/api.h')
        self.assertEqual({row.kind for row in observed.consumers}, {RawInputKind.ASSEMBLER_INCBIN, RawInputKind.ASSEMBLER_INCLUDE})
        self.assertEqual(issues(observed), ())

    def test_actual_oid_generator_make_rule_is_a_raw_input(self) -> None:
        make = '$(obj)/oid_registry_data.c: $(srctree)/include/linux/oid_registry.h \\\n\t\t$(src)/build_OID_registry\n\t$(call cmd,build_OID_registry)\ncmd_build_OID_registry = perl $(src)/build_OID_registry $< $@\n'
        revision = self.tree({'lib/Makefile': make, 'include/linux/oid_registry.h': '/* 1.2 */\n'})
        observed = self.index.lookup(revision, 'include/linux/oid_registry.h')
        self.assertEqual(len(observed.consumers), 1)
        consumer, = observed.consumers
        self.assertEqual((consumer.path, consumer.line, consumer.kind, consumer.target), ('lib/Makefile', 1, RawInputKind.MAKE_GENERATOR, '$(obj)/oid_registry_data.c'))
        self.assertFalse(issues(observed))

    def test_ordinary_compilation_and_cpp_includes_are_not_raw_roles(self) -> None:
        revision = self.tree({'Makefile': 'main.o: main.c api.h\n\t$(CC) -c main.c -o main.o\n', 'main.c': '#include "api.h"\nint run(void) { return 1; }\n', 'api.h': '/* comment */\n'})
        observed = self.index.lookup(revision, 'api.h')
        self.assertEqual(observed.consumers, ())
        self.assertEqual(issues(observed), ())
        self.assertEqual(type(observed).__dataclass_fields__.keys(), {'state', 'consumers', 'unknowns', 'failures'})

    def test_all_make_conditional_branches_and_inline_recipes_are_possible(self) -> None:
        make = 'ifeq ($(CONFIG_OTHER),y)\ngenerated.c: api.h ; python gen.py api.h\nelse\ndata.bin: api.h\n\tcat api.h > data.bin\nendif\n'
        revision = self.tree({'Makefile': make, 'api.h': '/* 7 */\n'})
        observed = self.index.lookup(revision, 'api.h')
        self.assertEqual({row.target for row in observed.consumers}, {'generated.c', 'data.bin'})

    def test_normal_kbuild_compile_wrappers_are_not_raw_generators(self) -> None:
        for wrapper in ('if_changed', 'if_changed_dep', 'if_changed_rule', 'cmd'):
            with self.subTest(wrapper=wrapper):
                revision = self.tree({'Makefile': f'main.o: main.c api.h\n\t$(call {wrapper},cc_o_c)\n', 'main.c': '#include "api.h"\n', 'api.h': '/* comment */\n'})
                observed = self.index.lookup(revision, 'api.h')
                self.assertFalse(observed.consumers)
                self.assertFalse(issues(observed))

    def test_make_cross_product_and_parse_cache_are_bounded(self) -> None:
        revision = self.tree({'Makefile': 'one.c two.c: api.h other.h\n\tpython generate.py\n'})
        with patch.object(roles, '_MAX_REFERENCES', 3):
            self.assertIn(RawInputFailureKind.REFERENCE_BUDGET, failure_kinds(self.index.lookup(revision, 'api.h')))
        revision = self.tree({'left/Makefile': 'one.c: api.h\n\tpython one.py\n', 'right/Makefile': 'two.c: api.h\n\tpython two.py\n'})
        fresh = RawInputIndex(self.repo, self.read)
        with patch.object(roles, '_MAX_FILE_CACHE_BYTES', 40):
            self.assertTrue(fresh.lookup(revision, 'api.h').consumers)
            self.assertLessEqual(fresh._file_cache_bytes, 40)

    def test_unresolved_prefix_with_literal_basename_vetoes_conservatively(self) -> None:
        revision = self.tree({'Makefile': 'generated.c: $(unknown)/api.h\n\tpython generate.py $< >$@\n', 'drivers/blob.S': '.incbin "other/root/data.h"\n'})
        self.assertTrue(self.index.lookup(revision, 'include/api.h').consumers)
        self.assertTrue(self.index.lookup(revision, 'unrelated/prefix/data.h').consumers)

    def test_source_prefixes_and_physical_make_coordinates(self) -> None:
        revision = self.tree({'lib/Kbuild': '# comment\n$(obj)/out.c: $(src)/api.h\n\tperl generate.pl $< $@\n', 'lib/api.h': '/* 7 */\n'})
        observed = self.index.lookup(revision, 'lib/api.h')
        self.assertEqual(observed.consumers[0].line, 2)

    def test_standard_phase_two_splice_in_input_path(self) -> None:
        revision = self.tree({'blob.S': '.incbin "drivers/\\\napi.h"\n', 'drivers/api.h': '/* 7 */\n'})
        observed = self.index.lookup(revision, 'drivers/api.h')
        self.assertTrue(observed.consumers)
        self.assertFalse(issues(observed))

    def test_phase_two_marker_splices_are_discovered_cold_and_in_deltas(self) -> None:
        for directive in ('.inc\\\nbin', '.i\\\nnc\\\nbin', '.\\\ninclude'):
            with self.subTest(directive=directive):
                first = self.tree({'api.h': '/* 7 */\n'})
                second = self.tree({'api.h': '/* 7 */\n', 'blob.S': directive + ' "api.h"\n'})
                fresh = RawInputIndex(self.repo, self.read)
                self.assertTrue(fresh.lookup(second, 'api.h').consumers)
                delta = RawInputIndex(self.repo, self.read)
                delta.lookup(first, 'api.h')
                self.assertTrue(delta.lookup(second, 'api.h').consumers)
                self.assertEqual(delta.stats().repository_scans, 1)

    def test_literal_glob_and_colon_consumer_delta_does_not_hide_inputs(self) -> None:
        first = self.tree({'api.h': '/* 7 */\n'})
        second = self.tree({'api.h': '/* 7 */\n', ':(exclude)*.S': '.incbin "api.h"\n'})
        self.index.lookup(first, 'api.h')
        observed = self.index.lookup(second, 'api.h')
        self.assertEqual(observed.consumers[0].path, ':(exclude)*.S')
        self.assertFalse(issues(observed))

    def test_make_literal_variables_are_resolved_and_unknown_raw_inputs_retain(self) -> None:
        known = self.tree({'Makefile': 'INPUT := api.h\ngenerated.c: $(INPUT)\n\tpython gen.py $< $@\n'})
        self.assertTrue(self.index.lookup(known, 'api.h').consumers)
        self.assertFalse(issues(self.index.lookup(known, 'api.h')))
        unknown = self.tree({'Makefile': 'generated.c: $(INPUT)\n\tpython gen.py $< $@\n'})
        self.assertIn(RawInputUnknownKind.MAKE_OPERAND, unknown_kinds(self.index.lookup(unknown, 'api.h')))

    def test_known_generator_wrappers_shell_assignments_and_wildcards_retain_unknown(self) -> None:
        for prefix, operand in (('', '$(INPUT)'), ("INPUT != printf 'api.%s' h\n", '$(INPUT)'), ('', 'include/api*.h'), ('', 'include/%.h')):
            with self.subTest(prefix=prefix, operand=operand):
                make = prefix + f'generated.c: {operand}\n\t$(call cmd,generate)\ncmd_generate = perl gen.pl $< $@\n'
                revision = self.tree({'Makefile': make})
                self.assertIn(RawInputUnknownKind.MAKE_OPERAND, unknown_kinds(self.index.lookup(revision, 'include/api.h')))

    def test_recognized_uncertainty_reuses_inventory_and_deleted_fact_clears_it(self) -> None:
        make = 'generated.c: $(INPUT)\n\tperl gen.pl $< $@\n'
        first = self.tree({'Makefile': make, 'api.h': '/* 7 */\n'})
        self.assertTrue(issues(self.index.lookup(first, 'api.h')))
        second = self.tree({'Makefile': make, 'api.h': '/* 8 */\n'})
        self.assertTrue(issues(self.index.lookup(second, 'api.h')))
        third = self.tree({'api.h': '/* 8 */\n'})
        self.assertFalse(issues(self.index.lookup(third, 'api.h')))
        self.assertEqual(self.index.stats().repository_scans, 1)
        self.assertEqual(self.index.stats().incremental_updates, 2)

    def test_local_parse_budget_is_cached_and_inventory_continues_through_deltas(self) -> None:
        expanded = ' '.join((f'input{number}.h' for number in range(129)))
        oversized = f'INPUTS := {expanded}\nlarge.c: $(INPUTS)\n\tperl gen.pl $^ $@\n'
        known = 'output.c: api.h\n\tperl gen.pl $< $@\n'
        first = self.tree({'Makefile': oversized, 'other/Makefile': known, 'api.h': '/* 7 */\n'})
        observed = self.index.lookup(first, 'api.h')
        self.assertIn(RawInputUnknownKind.MAKE_EXPANSION, unknown_kinds(observed))
        self.assertEqual(observed.consumers[0].path, 'other/Makefile')
        self.assertTrue(self.index._snapshots[first].inventory_complete)
        previous_reads = len(self.reads)
        second = self.tree({'Makefile': oversized, 'other/Makefile': known, 'api.h': '/* 8 */\n'})
        self.assertIn(RawInputUnknownKind.MAKE_EXPANSION, unknown_kinds(self.index.lookup(second, 'api.h')))
        self.assertEqual(len(self.reads), previous_reads)
        third = self.tree({'other/Makefile': known, 'api.h': '/* 8 */\n'})
        self.assertFalse(issues(self.index.lookup(third, 'api.h')))
        fourth = self.tree({'moved/Makefile': oversized, 'other/Makefile': known, 'api.h': '/* 8 */\n'})
        self.assertIn(RawInputUnknownKind.MAKE_EXPANSION, unknown_kinds(self.index.lookup(fourth, 'api.h')))
        self.assertEqual(self.index.stats().file_parses, 2)
        self.assertEqual(self.index.stats().file_cache_hits, 1)
        self.assertEqual(self.index.stats().repository_scans, 1)
        self.assertEqual(self.index.stats().incremental_updates, 3)

    def test_native_marker_batches_are_bounded_and_never_global(self) -> None:
        revision = self.tree({name + '.S': '.incbin "api.h"\n' for name in ('first', 'second', 'third')})
        with patch.object(roles, '_MARKER_BATCH_PATHS', 1):
            self.assertEqual(len(self.index.lookup(revision, 'api.h').consumers), 3)
        self.assertEqual(self.index.stats().repository_scans, 1)
        self.assertEqual(self.index.stats().marker_queries, 3)

    def test_assembler_macro_quoted_operand_and_symlink_cycles_are_unknown(self) -> None:
        revision = self.tree({'blob.S': '.macro embed file\n.incbin "\\file"\n.endm\nembed api.h\n'})
        self.assertIn(RawInputUnknownKind.ASM_OPERAND, unknown_kinds(self.index.lookup(revision, 'api.h')))
        self.tree({'blob.S': '.incbin "first"\n'})
        (self.path / 'first').symlink_to('second')
        (self.path / 'second').symlink_to('first')
        self.git('add', '--', 'first', 'second')
        revision = self.git('write-tree').decode().strip()
        self.assertIn(RawInputFailureKind.INPUT_ALIAS, failure_kinds(self.index.lookup(revision, 'api.h')))

    def test_unresolved_asm_operands_after_labels_and_semicolons_are_unknown(self) -> None:
        for source in ('raw_blob: .incbin INPUT_MACRO\n', '.section .rodata; .incbin INPUT_MACRO\n'):
            with self.subTest(source=source):
                revision = self.tree({'blob.S': source})
                self.assertIn(RawInputUnknownKind.ASM_OPERAND, unknown_kinds(self.index.lookup(revision, 'api.h')))

    def test_historical_deltas_add_change_and_remove_consumers(self) -> None:
        first = self.tree({'api.h': '/* 7 */\n'})
        second = self.tree({'api.h': '/* 8 */\n', 'blob.S': '.incbin "api.h"\n'})
        third = self.tree({'api.h': '/* 8 */\n', 'blob.S': '.incbin "other.h"\n'})
        fourth = self.tree({'api.h': '/* 8 */\n'})
        self.assertFalse(self.index.lookup(first, 'api.h').consumers)
        self.assertTrue(self.index.lookup(second, 'api.h').consumers)
        self.assertFalse(self.index.lookup(third, 'api.h').consumers)
        self.assertFalse(self.index.lookup(fourth, 'api.h').consumers)
        self.assertTrue(self.index.lookup(second, 'api.h').consumers)
        self.assertEqual(self.index.stats().repository_scans, 1)
        self.assertEqual(self.index.stats().incremental_updates, 3)

    def test_unchanged_consumers_and_content_facts_are_reused(self) -> None:
        make = '$(obj)/out.c: $(src)/api.h\n\tperl gen.pl $< $@\n'
        first = self.tree({'left/Makefile': make, 'right/Makefile': make, 'api.h': '/* 7 */\n'})
        self.assertTrue(self.index.lookup(first, 'api.h').consumers)
        self.assertEqual(self.index.stats().file_parses, 1)
        self.assertEqual(self.index.stats().file_cache_hits, 1)
        previous_reads = len(self.reads)
        second = self.tree({'left/Makefile': make, 'right/Makefile': make, 'api.h': '/* 8 */\n'})
        self.assertTrue(self.index.lookup(second, 'api.h').consumers)
        self.assertEqual(len(self.reads), previous_reads)
        self.assertEqual(self.index.stats().repository_scans, 1)

    def test_literal_consumer_filenames_preserve_lf_colon_and_color_config(self) -> None:
        self.git('config', 'color.grep', 'always')
        revision = self.tree({'odd\ncolon:name.S': '.incbin "api.h"\n', 'api.h': '/* 7 */\n'})
        observed = self.index.lookup(revision, 'api.h')
        self.assertEqual(observed.consumers[0].path, 'odd\ncolon:name.S')
        self.assertFalse(issues(observed))

    def test_symlink_input_alias_is_resolved_without_poisoning_unrelated_links(self) -> None:
        revision = self.tree({'blob.S': '.incbin "alias.data"\n', 'api.h': '/* 7 */\n'})
        (self.path / 'alias.data').symlink_to('api.h')
        (self.path / 'unrelated-link').symlink_to('outside-documentation')
        self.git('add', '--', 'alias.data', 'unrelated-link')
        revision = self.git('write-tree').decode().strip()
        observed = self.index.lookup(revision, 'api.h')
        self.assertTrue(observed.consumers)
        self.assertFalse(issues(observed))

    def test_nonregular_make_or_assembly_consumer_is_unknown(self) -> None:
        self.tree({'api.h': '/* 7 */\n'})
        (self.path / 'blob.S').symlink_to('external.S')
        self.git('add', '--', 'blob.S')
        revision = self.git('write-tree').decode().strip()
        self.assertIn(RawInputFailureKind.INPUT_ALIAS, failure_kinds(self.index.lookup(revision, 'api.h')))

    def test_limits_and_failures_are_unknown_and_never_cached_as_absence(self) -> None:
        revision = self.tree({'blob.S': '.incbin "api.h"\n', 'api.h': '/* 7 */\n'})
        with patch.object(roles, '_MAX_BYTES', 1):
            observed = self.index.lookup(revision, 'api.h')
        self.assertIn(RawInputFailureKind.INPUT_BUDGET, failure_kinds(observed))
        self.assertEqual(self.index.lookup(revision, 'api.h'), observed)
        failing = RawInputIndex(self.repo, self.read)
        with patch.object(roles, 'iter_git_records', side_effect=subprocess.CalledProcessError(2, ['git'])):
            self.assertIn(RawInputFailureKind.NATIVE_SCAN, failure_kinds(failing.lookup(revision, 'api.h')))

    def test_missing_files_and_unresolved_recognized_asm_are_unknown(self) -> None:
        revision = self.tree({'blob.S': '.incbin INPUT_MACRO\n'})
        self.assertIn(RawInputUnknownKind.ASM_OPERAND, unknown_kinds(self.index.lookup(revision, 'api.h')))
        broken = RawInputIndex(self.repo, lambda revision, path: (_ for _ in ()).throw(FileNotFoundError(path)))
        self.assertIn(RawInputFailureKind.CONSUMER_READ, failure_kinds(broken.lookup(revision, 'api.h')))

    def test_delta_budget_is_unknown_and_stops_without_a_new_global_scan(self) -> None:
        first = self.tree({'api.h': '/* 7 */\n'})
        self.index.lookup(first, 'api.h')
        second = self.tree({'api.h': '/* 8 */\n', 'blob.S': '.incbin "api.h"\n'})
        with patch.object(roles, '_MAX_DELTA_ROWS', 1):
            observed = self.index.lookup(second, 'api.h')
        self.assertIn(RawInputFailureKind.DELTA_ROW_BUDGET, failure_kinds(observed))
        self.assertEqual(self.index.stats().repository_scans, 1)

    def test_partial_record_inventory_closes_native_stream(self) -> None:
        closed: list[bool] = []
        revision = 'a' * 40

        def records(repo: GitRepo, arguments: list[str], delimiter: bytes, success_codes: tuple[int, ...]) -> Iterator[bytes]:
            try:
                if arguments[0] == 'ls-tree':
                    yield (b'100644 blob ' + revision.encode() + b'\tone.S')
                    yield (b'100644 blob ' + revision.encode() + b'\ttwo.S')
                else:
                    yield (revision + ':one.S').encode()
                    yield (revision + ':two.S').encode()
            finally:
                closed.append(True)
        with patch.object(roles, '_MAX_FILES', 1), patch.object(roles, 'iter_git_records', side_effect=records):
            observed = self.index.lookup(revision, 'api.h')
        self.assertIn(RawInputFailureKind.FILE_BUDGET, failure_kinds(observed))
        self.assertEqual(closed, [True, True])

    def test_unsupported_symbolic_or_escaping_coordinates_retain(self) -> None:
        for revision, path in [('HEAD', 'api.h'), ('a' * 40, '../api.h'), ('a' * 40, '/api.h')]:
            self.assertTrue(issues(self.index.lookup(revision, path)))
        self.assertEqual(self.index.stats().repository_scans, 0)

    def test_veto_witness_skips_inventory_for_new_revision_and_preserves_full_lookup(self) -> None:
        uncertain = 'generated.c: $(INPUT)\n\tperl gen.pl $< $@\n'
        known = 'generated.c: api.h\n\tperl gen.pl $< $@\n'
        first = self.tree({'Makefile': uncertain, 'other/Makefile': known, 'api.h': '/* 7 */\n'})
        self.assertTrue(issues(self.index.veto_observation(first, 'api.h')))
        second = self.tree({'Makefile': uncertain, 'other/Makefile': known, 'api.h': '/* 8 */\n'})
        reads = len(self.reads)
        with patch.object(roles, 'iter_git_records', side_effect=AssertionError('unexpected tree/grep/delta')):
            observed = self.index.veto_observation(second, 'api.h')
            self.assertIn(RawInputUnknownKind.MAKE_OPERAND, unknown_kinds(observed))
            self.assertEqual(len(self.reads), reads + 1)
            self.assertEqual(self.index.veto_observation(second, 'another.h'), observed)
            self.assertEqual(len(self.reads), reads + 1)
        self.assertNotIn(second, self.index._snapshots)
        full = self.index.lookup(second, 'api.h')
        self.assertTrue(full.consumers)
        self.assertIn(RawInputUnknownKind.MAKE_OPERAND, unknown_kinds(full))
        self.assertEqual(self.index.stats().repository_scans, 1)
        self.assertEqual(self.index.stats().incremental_updates, 1)
        self.assertEqual(self.index.stats().witness_reads, 1)
        self.assertEqual(self.index.stats().witness_hits, 1)

    def test_changed_or_deleted_witness_recovers_without_stale_uncertainty(self) -> None:
        uncertain = 'generated.c: $(INPUT)\n\tperl gen.pl $< $@\n'
        first = self.tree({'Makefile': uncertain, 'api.h': '/* 7 */\n'})
        self.assertTrue(issues(self.index.veto_observation(first, 'api.h')))
        second = self.tree({'Makefile': 'main.o: main.c api.h\n\t$(CC) -c main.c\n', 'api.h': '/* 7 */\n'})
        self.assertFalse(issues(self.index.veto_observation(second, 'api.h')))
        self.assertNotIn(second, self.index._veto_cache)
        self.assertIsNone(self.index._witness)
        separate = RawInputIndex(self.repo, self.read)
        self.assertTrue(issues(separate.veto_observation(first, 'api.h')))
        deleted = self.tree({'api.h': '/* 7 */\n'})
        self.assertFalse(issues(separate.veto_observation(deleted, 'api.h')))
        self.assertNotIn(deleted, separate._veto_cache)
        self.assertIsNone(separate._witness)

    def test_veto_cache_is_bounded_and_only_file_local_uncertainty_is_authority(self) -> None:
        make = 'generated.c: $(INPUT)\n\tperl gen.pl $< $@\n'
        with patch.object(roles, '_MAX_VETO_REVISIONS', 2):
            for number in range(4):
                revision = self.tree({'Makefile': make, 'api.h': f'/* {number} */\n'})
                self.assertTrue(issues(self.index.veto_observation(revision, 'api.h')))
            self.assertEqual(len(self.index._veto_cache), 2)
        empty = RawInputIndex(self.repo, self.read)
        revision = self.tree({'api.h': '/* 7 */\n'})
        self.assertFalse(issues(empty.veto_observation(revision, 'api.h')))
        self.assertFalse(empty._veto_cache)
        self.assertIsNone(empty._witness)
        failed = RawInputIndex(self.repo, self.read)
        with patch.object(roles, 'iter_git_records', side_effect=subprocess.CalledProcessError(2, ['git'])):
            self.assertTrue(issues(failed.veto_observation(revision, 'api.h')))
        self.assertFalse(failed._veto_cache)
        self.assertIsNone(failed._witness)

    def test_veto_witness_coordinate_validation_precedes_cache_and_nonregular_is_not_witness(self) -> None:
        make = 'generated.c: $(INPUT)\n\tperl gen.pl $< $@\n'
        revision = self.tree({'Makefile': make})
        self.index.veto_observation(revision, 'api.h')
        reads = len(self.reads)
        self.assertIn(RawInputFailureKind.UNSUPPORTED_COORDINATE, failure_kinds(self.index.veto_observation(revision, '../api.h')))
        self.assertIn(RawInputFailureKind.UNSUPPORTED_COORDINATE, failure_kinds(self.index.veto_observation('HEAD', 'api.h')))
        self.assertEqual(len(self.reads), reads)
        self.tree({'api.h': '/* 7 */\n'})
        (self.path / 'blob.S').symlink_to('external.S')
        self.git('add', '--', 'blob.S')
        revision = self.git('write-tree').decode().strip()
        fresh = RawInputIndex(self.repo, self.read)
        self.assertIn(RawInputFailureKind.INPUT_ALIAS, failure_kinds(fresh.veto_observation(revision, 'api.h')))
        self.assertIsNone(fresh._witness)
        self.assertFalse(fresh._veto_cache)
if __name__ == '__main__':
    unittest.main()
