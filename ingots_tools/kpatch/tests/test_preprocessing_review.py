"""Actual compiler controls for hidden and generated preprocessing consumers."""

import hashlib
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from kpatch.filter import FilterContext
from kpatch.filter.input_role_models import RawInputObservation
from kpatch.filter.policy_context import PolicyBuildContext
from kpatch.filter.policy_clang import CompileCommand
from kpatch.filter.repository_file import RepositoryFileReader
from kpatch.git import GitCommit
import test_target_preprocessing as helpers


class PreprocessingReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        helpers.TargetPreprocessingTests.setUpClass()

    def setUp(self) -> None:
        self.case = helpers.TargetPreprocessingTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)

    def test_spliced_and_stringified_header_consumers_are_compared(self) -> None:
        for include in ('#in\\\nclude "api.h"\n',
                        '#define STR_INNER(x) #x\n#define STR(x) STR_INNER(x)\n#include STR(api.h)\n'):
            with self.subTest(include=include):
                case = self.case
                files = {'api.h': '#define VALUE 1\n',
                         'unit.c': '#include "api.h"\nint first(void){return 3;}\n',
                         'other.c': include + 'int second(void){return VALUE;}\n',
                         'Makefile': 'obj-y += unit.o other.o\n'}
                commit, build = case.change(files, {'api.h': '#define VALUE 2\n'})
                result, _ = case.run_stage(commit, build)
                self.assertEqual(len(result), 1)
                self.assertEqual(result[0].edit_masks, ())
                self.assertEqual(case.records[-1].reason, 'expanded_inputs_changed')
                self.assertIn('other.c', [item.path for item in case.records[-1].units])
                # A fresh fixture is needed because its genuine parent checkout
                # is intentionally retained after each independent history.
                if include.startswith('#in'):
                    self.case = helpers.TargetPreprocessingTests()
                    self.case.setUp()
                    self.addCleanup(self.case.doCleanups)

    def test_c_source_can_be_a_stringified_preprocessor_input(self) -> None:
        case = self.case
        files = {'unit.c': '#define VALUE 1\nint first(void){return 3;}\n',
                 'other.c': '#define STR_INNER(x) #x\n#define STR(x) STR_INNER(x)\n'
                            '#include STR(unit.c)\nint second(void){return VALUE;}\n',
                 'Makefile': 'obj-y += unit.o other.o\n'}
        commit, build = case.change(files, {'unit.c': files['unit.c'].replace('VALUE 1', 'VALUE 2')})
        result, _ = case.run_stage(commit, build)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].edit_masks, ())
        self.assertEqual(case.records[-1].reason, 'expanded_inputs_changed')

    def test_missing_configured_macro_consumer_is_unknown(self) -> None:
        case = self.case
        files = {'api.h': '#define VALUE 1\n', 'unit.c': '#include "api.h"\nint first;\n',
                 'other.c': '#define STR_INNER(x) #x\n#define STR(x) STR_INNER(x)\n'
                            '#include STR(api.h)\nint second=VALUE;\n',
                 'Makefile': 'obj-y += unit.o other.o\n'}
        commit, build = case.change(files, {'api.h': '#define VALUE 2\n'}, missing_command='other.c')
        result, _ = case.run_stage(commit, build)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].edit_masks, ())
        self.assertIn('missing_consumer_compilation_command', case.records[-1].reason)

    def generated_context(self, *, live_value: bool = True) -> tuple[GitCommit, PolicyBuildContext, Path]:
        case = self.case
        files = {'api.h': '#define VALUE 1\n', 'unit.c': '#include "api.h"\nint first;\n',
                 'Makefile': 'obj-y += unit.o\n'}
        commit, _ = case.change(files, {'api.h': '#define VALUE 2\n'})
        generated = case.build / 'generated.c'
        generated.write_text('#include "api.h"\nint generated=' + ('VALUE' if live_value else '3') + ';\n')
        database = case.build / 'compile_commands.json'
        commands = json.loads(database.read_text())
        commands.append({'directory': str(case.build), 'file': str(generated),
                         'arguments': [case.clang, '-std=gnu11', '-nostdinc', '-I', str(case.source),
                                       '-c', str(generated)]})
        database.write_text(json.dumps(commands))
        build = PolicyBuildContext.capture(case.source, case.build, database, case.build / '.config')
        return commit, build, generated

    def test_generated_compiled_consumer_retains_a_live_header_change(self) -> None:
        commit, build, generated = self.generated_context()
        self.assertIn(generated, {item.path for item in build.generated_inputs})
        result, _ = self.case.run_stage(commit, build)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].edit_masks, ())
        self.assertEqual(self.case.records[-1].units[0].path, '@build/generated.c')
        self.assertEqual(self.case.records[-1].reason, 'expanded_inputs_changed')

    def test_generated_assembly_consumer_is_pinned_and_compared(self) -> None:
        commit, build, generated = self.generated_context()
        assembly = generated.with_suffix('.S')
        assembly.write_text('#include "api.h"\n.byte VALUE\n')
        generated.unlink()
        database = self.case.build / 'compile_commands.json'
        commands = json.loads(database.read_text())
        commands[-1]['file'] = str(assembly)
        commands[-1]['arguments'][-1] = str(assembly)
        database.write_text(json.dumps(commands))
        build = PolicyBuildContext.capture(self.case.source, self.case.build, database, build.config_file)
        self.assertIn(assembly, {item.path for item in build.generated_inputs})
        result, _ = self.case.run_stage(commit, build)
        self.assertEqual(len(result), 1)
        self.assertEqual(self.case.records[-1].units[0].path, '@build/generated.S')
        self.assertEqual(self.case.records[-1].reason, 'expanded_inputs_changed')

    def test_missing_plain_c_forced_include_consumer_is_unknown(self) -> None:
        case = self.case
        files = {'api.h': '#define VALUE 1\n', 'unit.c': '#include "api.h"\nint first;\n',
                 'other.c': 'int second(void){return VALUE;}\n',
                 'Makefile': 'obj-y += unit.o other.o\nccflags-y += -include api.h\n'}
        commit, build = case.change(files, {'api.h': '#define VALUE 2\n'}, missing_command='other.c')
        result, _ = case.run_stage(commit, build)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].edit_masks, ())
        self.assertIn('missing_consumer_compilation_command', case.records[-1].reason)

    def test_unchanged_generated_consumer_is_cached_and_does_not_veto(self) -> None:
        commit, build, generated = self.generated_context(live_value=False)
        cache = self.case.root / 'cache.sqlite'
        result, _ = self.case.run_stage(commit, build, cache=cache)
        self.assertEqual(result, [])
        result, stage = self.case.run_stage(commit, build, cache=cache)
        self.assertEqual(result, [])
        self.assertEqual(stage.compiler.stats.preprocessing_extractions, 0)
        self.assertEqual(stage.compiler.stats.preprocessing_cache_hits, 4)
        self.assertEqual(hashlib.sha256(generated.read_bytes()).hexdigest(),
                         next(item.sha256 for item in build.generated_inputs if item.path == generated))

    def test_mutated_or_unpinned_generated_source_is_unknown(self) -> None:
        commit, build, generated = self.generated_context(live_value=False)
        legacy = build.model_copy(update={'generated_inputs': tuple(item for item in build.generated_inputs
                                                                  if item.path != generated)})
        result, _ = self.case.run_stage(commit, legacy)
        self.assertEqual(len(result), 1)
        self.assertIn('generated_compilation_source_not_pinned', self.case.records[-1].reason)
        generated.write_text(generated.read_text() + '\nint modified;\n')
        result, _ = self.case.run_stage(commit, build)
        self.assertEqual(len(result), 1)
        self.assertIn('generated_build_input_changed', self.case.records[-1].reason)

    def test_external_compilation_sources_are_not_silently_ignored(self) -> None:
        commit, build, _ = self.generated_context(live_value=False)
        external = self.case.root / 'outside.c'
        external.write_text('int outside;\n')
        database = self.case.build / 'compile_commands.json'
        commands = json.loads(database.read_text())
        commands.append({'directory': str(self.case.build), 'file': str(external),
                         'arguments': [self.case.clang, '-nostdinc', '-c', str(external)]})
        database.write_text(json.dumps(commands))
        with self.assertRaisesRegex(ValueError, 'outside pinned'):
            PolicyBuildContext.capture(self.case.source, self.case.build, database, build.config_file)

    def pragma_control(self, separator: str, flags: tuple[str, ...] = ()) -> None:
        case = self.case
        old = ('#pragma pack ' + separator + '(1)\nstruct state {char c;int n;};\n'
               'int main(void){return sizeof(struct state);}\n')
        new = old.replace('(1)', '(2)')
        sizes = []
        for label, contents in (('old', old), ('new', new)):
            source, binary = case.root / (label + '.c'), case.root / (label + '.bin')
            source.write_bytes(contents.encode())
            subprocess.run([case.clang, '-std=gnu11', *flags, str(source), '-o', str(binary)],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            sizes.append(subprocess.run([str(binary)], check=False).returncode)
        self.assertEqual(sizes, [5, 6])
        commit, build = case.change({'unit.c': old}, {'unit.c': new})
        if flags:
            database = case.build / 'compile_commands.json'
            commands = json.loads(database.read_text())
            for command in commands:
                command['arguments'][1:1] = flags
            database.write_text(json.dumps(commands))
            build = PolicyBuildContext.capture(case.source, case.build, database, build.config_file)
        result, _ = case.run_stage(commit, build)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].edit_masks, ())
        self.assertEqual(case.records[-1].reason, 'expanded_inputs_changed')

    def test_gnu_whitespace_spliced_pragma_preserves_actual_pack_effect(self) -> None:
        self.pragma_control('\\ \n')

    def test_crlf_spliced_pragma_preserves_actual_pack_effect(self) -> None:
        self.pragma_control('\\\r\n')

    def test_trigraph_spliced_pragma_preserves_actual_pack_effect(self) -> None:
        self.pragma_control('??/\n', ('-trigraphs',))

    def test_multiline_comment_pragma_preserves_actual_pack_effect(self) -> None:
        self.pragma_control('/* comment\n */ ')

    def test_affected_consumer_budget_retains_after_complete_baseline(self) -> None:
        case = self.case
        files = {'api.h': '#define UNUSED 1\n',
                 **{f'unit{index}.c': '#include "api.h"\nint value;\n' for index in range(129)}}
        commit, build = case.change(files, {'api.h': '#define UNUSED 2\n'})
        result, stage = case.run_stage(commit, build)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].edit_masks, ())
        self.assertEqual(case.records[-1].reason, 'translation_unit_budget')
        self.assertEqual(stage.stats.baseline_units, 129)
        self.assertEqual(stage.stats.dirty_units, 0)

    def test_standalone_batch_shares_owned_reader_with_actual_role_provider(self) -> None:
        from kpatch.filter.preprocessing import TargetPreprocessorFilter

        case = self.case
        commit, build = case.change({'unit.c': '#define UNUSED 1\nint value;\n'},
                                    {'unit.c': '#define UNUSED 2\nint value;\n'})
        context = FilterContext(case.repo)
        actual_provider = context.input_roles
        seen = []
        stage = TargetPreprocessorFilter(build, analyzer=case.analyzer)

        class ReaderCheckingProvider:
            def lookup(provider, incoming: FilterContext, revision: str, path: str) -> RawInputObservation:
                self.assertIsNotNone(incoming.file_reader)
                self.assertIs(incoming.file_reader, stage.compiler.reader)
                seen.append(incoming.file_reader)
                return actual_provider.lookup(incoming, revision, path)

        from dataclasses import replace

        result = stage.filter_commits([commit], replace(context, input_roles=ReaderCheckingProvider()), False)
        self.assertEqual(result, [])
        self.assertEqual(len(seen), 2)
        self.assertIs(seen[0], seen[1])

    def test_volatile_builtins_are_not_cached_as_content_only_inputs(self) -> None:
        source = self.case.source / 'clock.c'
        command = CompileCommand.for_source(source)
        for builtin in ('__TIME__', '__DATE__', '__TIMESTAMP__'):
            with self.subTest(builtin=builtin):
                source.write_text('const char *value=' + builtin + ';\n')
                result = self.case.analyzer.preprocess(command)
                self.assertFalse(result.complete)
                self.assertIsNone(result.digest)
                self.assertIn('volatile_preprocessor_builtin_not_pinned:' + builtin, result.diagnostics)
        source.write_text('#undef __TIME__\n#define __TIME__ "fixed"\nconst char *value=__TIME__;\n')
        self.assertTrue(self.case.analyzer.preprocess(command).complete)

    def test_build_model_read_failure_retains_before_preprocessing(self) -> None:
        case = self.case
        commit, build = case.change({'api.h': '#define UNUSED 1\n',
                                     'unit.c': '#include "api.h"\nint value;\n',
                                     'Makefile': 'obj-y += unit.o\n'},
                                    {'api.h': '#define UNUSED 2\n'})
        original = RepositoryFileReader.read_file

        def failing_read(reader: RepositoryFileReader, revision: str, path: str) -> bytes:
            if path == 'Makefile':
                raise OSError('injected native Makefile failure')
            return original(reader, revision, path)

        with patch.object(RepositoryFileReader, 'read_file', new=failing_read), \
                patch.object(case.analyzer, 'preprocess', side_effect=AssertionError('read failure must precede PP')):
            result, _ = case.run_stage(commit, build)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].edit_masks, ())
        self.assertEqual(case.records[-1].reason, 'consumer_input_failure')


if __name__ == '__main__':
    unittest.main()
