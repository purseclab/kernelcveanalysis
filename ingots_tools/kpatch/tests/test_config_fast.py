"""Configured-model restoration and positive-input publication controls."""
from datetime import UTC, datetime
import subprocess
import shutil
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from kpatch.diff import DiffFileType
from kpatch.filter import ConfigFilter, FilterContext, FilteredCommit, FilterPipeline, IfdefFilter
from kpatch.filter.config_filter import BuildInputClosure, ConfigValue, KbuildMakefile, KbuildState, KernelConfig, SourceAnalysisCache
from kpatch.filter.input_role_models import (
    InputInventoryState, RawInputConsumer, RawInputFailure, RawInputFailureKind,
    RawInputKind, RawInputObservation, RawInputUnknown, RawInputUnknownKind,
)
from kpatch.filter.masking import MaskReason
from kpatch.filter.source_filter import SourceIncludeIndex
from kpatch.git import CommitParent, GitCommit, StructuredCommits
from tests.test_config_filter import MemoryGitRepo, make_diff


def original(path: str = 'drivers/unit.c', *, line: int = 1) -> GitCommit:
    patch = (f'diff --git a/{path} b/{path}\nindex 1234567..89abcde 100644\n'
             f'--- a/{path}\n+++ b/{path}\n@@ -{line} +{line} @@\n-int value = 1;\n+int value = 2;\n')
    date = datetime(2026, 1, 1, tzinfo=UTC)
    return GitCommit('child', '', '', date, date, (CommitParent('parent', patch),), '')


class Observations:
    def __init__(self, values: dict[str, RawInputObservation] | None = None) -> None:
        self.values = values or {}
        self.calls: list[tuple[str, str, bool, bool]] = []

    def lookup(self, context: FilterContext, revision: str, path: str) -> RawInputObservation:
        self.calls.append((revision, path, context.full_input_inventory, context.file_reader is not None))
        return self.values.get(revision, RawInputObservation(InputInventoryState.FULL))


class ConfigRestorationTests(unittest.TestCase):
    def context(self, makefile: str, source: str = 'int value = 1;\n', *, line: int = 1,
                roles: Observations | None = None) -> tuple[FilteredCommit, FilterContext]:
        commit = original(line=line)
        before = {'drivers/Makefile': makefile, 'drivers/unit.c': source}
        after = {**before, 'drivers/unit.c': source.replace('value = 1', 'value = 2')}
        repo = MemoryGitRepo({'parent': before, 'child': after})
        return FilteredCommit(commit), FilterContext(repo, StructuredCommits.from_commits([commit]),
                                                      input_roles=roles or Observations())

    def test_default_restores_disabled_file_mask_and_requires_history(self) -> None:
        view, context = self.context('obj-$(CONFIG_OFF) += unit.o\n')
        stage = ConfigFilter(KernelConfig(''))
        self.assertTrue(stage.requires_complete_history)
        result = stage.filter_mutable_commits([view], context, False)
        self.assertEqual(result, [])
        self.assertTrue(view.edit_masks)
        self.assertTrue(all(mask.reason is MaskReason.CONFIG for mask in view.edit_masks))

    def test_enabled_and_module_modes_are_complete(self) -> None:
        for goal, expected in [('obj-y', ConfigValue.ENABLED), ('obj-m', ConfigValue.MODULE)]:
            with self.subTest(goal=goal):
                view, context = self.context(goal + ' += unit.o\n')
                retained = ConfigFilter(KernelConfig('')).filter_mutable_commits([view], context, False)
                self.assertEqual(retained, [view])
                modes = view.build_modes[(None, 'drivers/unit.c')]
                self.assertEqual((modes.old, modes.new, modes.complete), (expected, expected, True))

    def test_observation_option_retains_disabled_file_without_config_mask(self) -> None:
        view, context = self.context('obj-$(CONFIG_OFF) += unit.o\n')
        retained = ConfigFilter(KernelConfig(''), collect_observations=True).filter_mutable_commits([view], context, False)
        self.assertEqual(retained, [view])
        self.assertFalse(view.edit_masks)

    def test_restored_modes_enable_actual_inactive_hunk_pruning(self) -> None:
        view, context = self.context('obj-y += unit.o\n', '#if CONFIG_OFF\nint value = 1;\n#endif\n', line=2)
        result = FilterPipeline([ConfigFilter(KernelConfig('')), IfdefFilter(KernelConfig(''))]).filter_mutable_commits([view], context, False)
        self.assertEqual(result, [])
        self.assertTrue(view.code_masks)

    def test_local_module_or_config_redefinition_remains_active(self) -> None:
        for prefix, condition in [('#undef MODULE', 'defined(MODULE)'),
                                  ('#define CONFIG_OFF 1', 'CONFIG_OFF')]:
            with self.subTest(prefix=prefix):
                view, context = self.context('obj-m += unit.o\n', prefix + '\n#if ' + condition + '\nint value = 1;\n#endif\n', line=3)
                result = FilterPipeline([ConfigFilter(KernelConfig('')), IfdefFilter(KernelConfig(''))]).filter_mutable_commits([view], context, False)
                self.assertEqual(result, [view])
                self.assertFalse(view.code_masks)

    def test_positive_old_side_and_operational_failure_retain(self) -> None:
        observations = [RawInputObservation(InputInventoryState.FULL,
                                            consumers=(RawInputConsumer('consumer.S', 1, RawInputKind.ASSEMBLER_INCBIN),)),
                        RawInputObservation(InputInventoryState.INCOMPLETE),
                        RawInputObservation(InputInventoryState.FULL,
                                            failures=(RawInputFailure(RawInputFailureKind.NATIVE_SCAN),))]
        for observation in observations:
            with self.subTest(observation=observation):
                roles = Observations({'parent': observation})
                view, context = self.context('obj-$(CONFIG_OFF) += unit.o\n', roles=roles)
                result = ConfigFilter(KernelConfig('')).filter_mutable_commits([view], context, False)
                self.assertEqual(result, [view])
                self.assertFalse(view.edit_masks)
                self.assertTrue(all(full and shared for _, _, full, shared in roles.calls))

    def test_local_operand_unknown_alone_does_not_block_configured_absence(self) -> None:
        unknown = RawInputUnknown('Makefile', 2, RawInputUnknownKind.MAKE_OPERAND, '$(INPUT)', '0' * 64)
        roles = Observations({'parent': RawInputObservation(InputInventoryState.FULL, unknowns=(unknown,)),
                              'child': RawInputObservation(InputInventoryState.FULL, unknowns=(unknown,))})
        view, context = self.context('obj-$(CONFIG_OFF) += unit.o\n', roles=roles)
        self.assertEqual(ConfigFilter(KernelConfig('')).filter_mutable_commits([view], context, False), [])
        self.assertEqual([revision for revision, _, _, _ in roles.calls], ['parent', 'child'])

    def test_per_file_positive_guard_runs_even_when_all_decisions_absent(self) -> None:
        roles = Observations({'child': RawInputObservation(InputInventoryState.FULL,
                                      consumers=(RawInputConsumer('Makefile', 1, RawInputKind.MAKE_GENERATOR),))})
        view, context = self.context('')
        context = FilterContext(context.repo, context.structured_commits, input_roles=roles)
        self.assertEqual(ConfigFilter(KernelConfig('')).filter_mutable_commits([view], context, False), [view])
        self.assertEqual(len(roles.calls), 2)

    def test_stale_modes_clear_and_merges_reject_without_patch_parse(self) -> None:
        view, context = self.context('obj-y += unit.o\n')
        view.original.parents += (CommitParent('other', 'unparsed'),)
        self.assertIsNone(ConfigFilter(KernelConfig('')).filter_mutable_commit(view, context))
        self.assertIsNone(view._diff)
        self.assertFalse(view.build_modes)


class ConfigModeContextTests(unittest.TestCase):
    def state(self, files: dict[str, str]) -> KbuildState:
        index = SourceIncludeIndex('', files)
        for path, contents in files.items():
            for line in contents.splitlines(): index.add_line(path, line)
        return KbuildState(MemoryGitRepo({'base': files}), KernelConfig(''), 'base', index)

    def test_shared_builtin_module_header_is_not_exclusive(self) -> None:
        state = self.state({'drivers/Makefile': 'obj-y += builtin.o\nobj-m += module.o\n',
                            'drivers/builtin.c': '#include "api.h"\n', 'drivers/module.c': '#include "api.h"\n',
                            'drivers/api.h': 'int api;\n'})
        self.assertEqual(state.get('drivers/api.h'), ConfigValue.ENABLED)
        self.assertFalse(state.cpp_context_complete('drivers/api.h'))
        self.assertTrue(state.cpp_context_complete('drivers/builtin.c'))
        self.assertTrue(state.cpp_context_complete('drivers/module.c'))
        self.assertIs(state.build_input_closure, BuildInputClosure.UNKNOWN)

    def test_disabled_includer_does_not_promote_unrelated_input(self) -> None:
        state = self.state({'drivers/Makefile': 'obj-$(CONFIG_OFF) += disabled.o\nobj-y += enabled.o\n',
                            'drivers/disabled.c': '#include "api.h"\n', 'drivers/enabled.c': '#define LOCAL 1\n',
                            'drivers/api.h': 'int api;\n'})
        self.assertIsNone(state.get('drivers/api.h'))
        self.assertIsNone(state.get('drivers/unlisted.c'))

    def test_uncertain_known_include_remains_enabled_but_not_exclusive(self) -> None:
        state = self.state({'drivers/Makefile': 'obj-m += module.o\n',
                            'drivers/module.c': '#define LOCAL 1\n#include "api.h"\n',
                            'drivers/api.h': 'int api;\n'})
        self.assertEqual(state.get('drivers/api.h'), ConfigValue.ENABLED)
        self.assertFalse(state.cpp_context_complete('drivers/api.h'))

    def test_make_read_error_is_retention_not_missing_rules(self) -> None:
        class Unreadable(MemoryGitRepo):
            def read_file(self, commit: str, path: str) -> bytes:
                if path == 'drivers/Makefile': raise PermissionError(path)
                return super().read_file(commit, path)
        state = KbuildState(Unreadable({'base': {}}), KernelConfig(''), 'base')
        self.assertEqual(state.get('drivers/unit.c'), ConfigValue.ENABLED)
        self.assertFalse(state.cpp_context_complete('drivers/unit.c'))

    def test_patsubst_preserves_unmatched_make_words(self) -> None:
        rules = KbuildMakefile('obj-y += $(patsubst %.S,%.o,one.S two.o)\n', KernelConfig(''), 'drivers')
        self.assertEqual(rules.get('drivers/one.S'), ConfigValue.ENABLED)
        self.assertEqual(rules.get('drivers/two.c'), ConfigValue.ENABLED)

    def test_additional_inputs_propagate_and_preserve_mode_conflicts(self) -> None:
        files = {'drivers/Makefile': 'obj-y += builtin.o\n',
                 'drivers/builtin.c': '#include "api.h"\n',
                 'drivers/vendor.c': '#include "api.h"\n', 'drivers/api.h': 'int api;\n'}
        index = SourceIncludeIndex('', files)
        for path, contents in files.items():
            for line in contents.splitlines(): index.add_line(path, line)
        config = KernelConfig('', additional_inputs={'drivers/vendor.c': ConfigValue.MODULE,
                                                    'drivers/builtin.c': ConfigValue.MODULE})
        state = KbuildState(MemoryGitRepo({'base': files}), config, 'base', index)
        self.assertEqual(state.get('drivers/vendor.c'), ConfigValue.MODULE)
        self.assertFalse(state.cpp_context_complete('drivers/vendor.c'))
        self.assertEqual(state.get('drivers/builtin.c'), ConfigValue.ENABLED)
        self.assertFalse(state.cpp_context_complete('drivers/builtin.c'))
        self.assertEqual(state.get('drivers/api.h'), ConfigValue.ENABLED)
        self.assertFalse(state.cpp_context_complete('drivers/api.h'))

    def test_literal_macro_include_and_forced_header_are_positive(self) -> None:
        for source, flags in [('#define HEADER "api.h"\n#include HEADER\n', ''),
                              ('int unit;\n', 'ccflags-y += -include $(src)/api.h\n')]:
            with self.subTest(flags=flags):
                state = self.state({'drivers/Makefile': 'obj-y += main.o\n' + flags,
                                    'drivers/main.c': source, 'drivers/api.h': 'int api;\n'})
                state.source_includes.add_diff(make_diff('drivers/main.c', DiffFileType.DEFAULT))
                self.assertEqual(state.get('drivers/api.h'), ConfigValue.ENABLED)
                self.assertFalse(state.cpp_context_complete('drivers/api.h'))

    def test_additional_only_vendor_config_does_not_authorize_cpp_absence(self) -> None:
        view, context = ConfigRestorationTests().context('', '#if CONFIG_VENDOR\nint value = 1;\n#endif\n', line=2)
        config = KernelConfig('', additional_inputs={'drivers/unit.c': ConfigValue.MODULE})
        output = FilterPipeline([ConfigFilter(config), IfdefFilter(config)]).filter_mutable_commits([view], context, False)
        self.assertEqual(output, [view])
        self.assertFalse(view.build_modes[(None, 'drivers/unit.c')].complete)
        self.assertFalse(view.code_masks)
        files = {'drivers/Makefile': '', 'drivers/vendor.c': '#if CONFIG_VENDOR\n#include "api.h"\n#endif\n',
                 'drivers/api.h': '#if CONFIG_VENDOR\n#include "nested.h"\n#endif\n', 'drivers/nested.h': 'int value;\n'}
        index = SourceIncludeIndex('', files)
        for path, contents in files.items():
            for line in contents.splitlines():
                index.add_line(path, line)
        config = KernelConfig('', additional_inputs={'drivers/vendor.c': ConfigValue.MODULE})
        state = KbuildState(MemoryGitRepo({'base': files}), config, 'base', index)
        self.assertEqual(state.get('drivers/api.h'), ConfigValue.ENABLED)
        self.assertEqual(state.get('drivers/nested.h'), ConfigValue.ENABLED)
        self.assertFalse(state.cpp_context_complete('drivers/api.h'))
        self.assertFalse(state.cpp_context_complete('drivers/nested.h'))

    def test_cyclic_diamond_context_has_bounded_queries_and_both_modes(self) -> None:
        levels = 22
        files = {'drivers/Makefile': 'obj-y += builtin.o\nobj-m += module.o\n',
                 'drivers/builtin.c': '#include "a0.h"\n', 'drivers/module.c': '#include "b0.h"\n'}
        for level in range(levels):
            next_level = (level + 1) % levels
            for branch in ('a', 'b'):
                files[f'drivers/{branch}{level}.h'] = f'#include "a{next_level}.h"\n#include "b{next_level}.h"\n'
        state = self.state(files)
        original_get = state._get_kbuild
        queries = 0
        def bounded_get(path: str) -> ConfigValue | None:
            nonlocal queries
            queries += 1
            self.assertLessEqual(queries, 3 * len(files), 'Cyclic closure enumerated paths instead of finite node states')
            return original_get(path)
        with patch.object(state, '_get_kbuild', side_effect=bounded_get):
            self.assertEqual(state.modeled_inclusion('drivers/a21.h'), ConfigValue.ENABLED)
            for level in range(levels):
                for branch in ('a', 'b'):
                    context = state._include_context_cache[f'drivers/{branch}{level}.h']
                    self.assertEqual(context.modes, frozenset((ConfigValue.ENABLED, ConfigValue.MODULE)))
                    self.assertFalse(state.cpp_context_complete(f'drivers/{branch}{level}.h'))

    def test_conditional_cycle_keeps_distinct_exclusive_modes(self) -> None:
        state = self.state({'drivers/Makefile': 'obj-y += builtin.o\nobj-m += module.o\n',
                            'drivers/builtin.c': '#include "a.h"\n', 'drivers/module.c': '#include "b.h"\n',
                            'drivers/a.h': '#ifdef MODULE\n#include "b.h"\n#endif\n',
                            'drivers/b.h': '#ifndef MODULE\n#include "a.h"\n#endif\n'})
        self.assertEqual(state.modeled_inclusion('drivers/a.h'), ConfigValue.ENABLED)
        self.assertEqual(state.get('drivers/b.h'), ConfigValue.MODULE)
        self.assertTrue(state.cpp_context_complete('drivers/a.h'))
        self.assertTrue(state.cpp_context_complete('drivers/b.h'))

    def test_interrupted_positive_discovery_stays_failed_until_build_refresh(self) -> None:
        class Interrupted(MemoryGitRepo):
            def read_file(self, commit: str, path: str) -> bytes:
                if commit == 'base' and path == 'drivers/main.c':
                    raise PermissionError(path)
                return super().read_file(commit, path)
        files = {'drivers/Makefile': 'obj-y += main.o\n',
                 'drivers/main.c': '#include "api.\\\nh"\n', 'drivers/api.h': 'int api;\n'}
        index = SourceIncludeIndex('', files)
        index.add_line('drivers/main.c', '#include "api.\\')
        state = KbuildState(Interrupted({'base': files, 'next': files}), KernelConfig(''), 'base', index)
        self.assertEqual(state.get('drivers/unlisted.c'), ConfigValue.ENABLED)
        self.assertTrue(state.has_input_failures)
        self.assertIn('drivers/main.c', state._pending_include_sources)
        state.update_filter_state(make_diff('drivers/api.h', DiffFileType.DEFAULT), 'next')
        self.assertEqual(state.get('drivers/unlisted.c'), ConfigValue.ENABLED)
        self.assertFalse(state.cpp_context_complete('drivers/main.c'))
        state.update_filter_state(make_diff('drivers/Makefile', DiffFileType.DEFAULT), 'next')
        self.assertEqual(state.get('drivers/api.h'), ConfigValue.ENABLED)
        self.assertIsNone(state.get('drivers/unlisted.c'))
        self.assertFalse(state.has_input_failures)

    def test_additional_input_validation(self) -> None:
        for path in ('', '/abs.c', '../escape.c', 'a/../unit.c', 'unit.c\n'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                KernelConfig('', additional_inputs={path: ConfigValue.ENABLED})
        with self.assertRaises(ValueError):
            KernelConfig('', additional_inputs={'unit.c': ConfigValue.DISABLED})

    def test_normalized_hidden_include_positive_is_discovered(self) -> None:
        files = {'drivers/Makefile': 'obj-y += main.o\n',
                 'drivers/main.c': '#inc\\\nlude "api.h"\n', 'drivers/api.h': 'int api;\n'}
        state = self.state(files)
        state.source_includes.add_diff(make_diff('drivers/main.c', DiffFileType.DEFAULT))
        self.assertEqual(state.get('drivers/api.h'), ConfigValue.ENABLED)
        self.assertTrue(state.cpp_context_complete('drivers/api.h'))

    def test_compiler_overrides_are_scoped_and_matching_defaults_stay_complete(self) -> None:
        for flags, unit_complete, other_complete in [
            ('ccflags-y += -UCONFIG_FEATURE', False, False),
            ('CFLAGS_unit.o += -UCONFIG_FEATURE', False, True),
            ('ccflags-y += -D__KERNEL__', True, True),
            ('ccflags-y += -DCONFIG_FEATURE=1 -UCONFIG_OFF', True, True),
        ]:
            with self.subTest(flags=flags):
                files = {'Kbuild': 'obj-y += drivers/ separate/\n',
                         'drivers/Makefile': 'obj-y += unit.o other.o\n' + flags + '\n',
                         'separate/Makefile': 'obj-y += outside.o\n',
                         'drivers/unit.c': 'int unit;\n', 'drivers/other.c': 'int other;\n',
                         'separate/outside.c': 'int outside;\n'}
                index = SourceIncludeIndex('', files)
                state = KbuildState(MemoryGitRepo({'base': files}), KernelConfig('CONFIG_FEATURE=y'), 'base', index)
                self.assertEqual(state.get('drivers/unit.c'), ConfigValue.ENABLED)
                self.assertEqual(state.cpp_context_complete('drivers/unit.c'), unit_complete)
                self.assertEqual(state.cpp_context_complete('drivers/other.c'), other_complete)
                self.assertTrue(state.cpp_context_complete('separate/outside.c'))
                self.assertFalse(state.has_input_failures)

    def test_inherited_override_reaches_descendants(self) -> None:
        files = {'Kbuild': 'obj-y += drivers/\n',
                 'drivers/Makefile': 'obj-y += child/\nsubdir-ccflags-y += -UCONFIG_FEATURE\n',
                 'drivers/child/Makefile': 'obj-y += unit.o\n', 'drivers/child/unit.c': 'int unit;\n'}
        index = SourceIncludeIndex('', files)
        state = KbuildState(MemoryGitRepo({'base': files}), KernelConfig('CONFIG_FEATURE=y'), 'base', index)
        self.assertEqual(state.get('drivers/child/unit.c'), ConfigValue.ENABLED)
        self.assertFalse(state.cpp_context_complete('drivers/child/unit.c'))

    def test_root_makefile_flags_observed_alongside_root_kbuild(self) -> None:
        for flags, complete in [('-UCONFIG_FEATURE', False), ('-D__KERNEL__', True)]:
            with self.subTest(flags=flags):
                files = {'Kbuild': 'obj-y += unit.o\n',
                         'Makefile': 'KBUILD_CPPFLAGS += ' + flags + '\n',
                         'unit.c': 'int unit;\n'}
                state = KbuildState(MemoryGitRepo({'base': files}), KernelConfig('CONFIG_FEATURE=y'),
                                    'base', SourceIncludeIndex('', files))
                self.assertEqual(state.get('unit.c'), ConfigValue.ENABLED)
                self.assertEqual(state.cpp_context_complete('unit.c'), complete)

    def test_modeled_sources_enumerates_selected_roots_and_forced_plain_source(self) -> None:
        files = {'Makefile': 'obj-y += live/\nobj-$(CONFIG_OFF) += disabled/\n',
                 'live/Makefile': 'obj-y += unit.o plain.o\nccflags-y += -include $(src)/api.h\n',
                 'live/unit.c': '#include "api.h"\n', 'live/plain.c': 'int plain;\n', 'live/api.h': 'int api;\n',
                 'disabled/Makefile': 'obj-y += unused.o\n', 'disabled/unused.c': '#include "api.h"\n',
                 'vendor/Makefile': '', 'vendor/extra.c': 'int vendor;\n'}
        index = SourceIncludeIndex('', files)
        repo = MemoryGitRepo({'base': files})
        config = KernelConfig('', additional_inputs={'vendor/extra.c': ConfigValue.MODULE})
        state = KbuildState(repo, config, 'base', index)
        with patch.object(repo, 'read_file', wraps=repo.read_file) as reads:
            self.assertEqual(state.modeled_sources(), frozenset(('live/unit.c', 'live/plain.c', 'vendor/extra.c')))
            self.assertFalse(any(call.args[1].startswith('disabled/') for call in reads.call_args_list))
        self.assertEqual(state.get('live/api.h'), ConfigValue.ENABLED)

    def test_comment_hint_scan_does_not_backtrack_over_comment_chains(self) -> None:
        text = '#define EMPTY_GUARD\n' + '/* closing */\n' * 100 + '#define HEADER "api.h"\n#include HEADER\n'
        program = ('import sys; from kpatch.filter.include_hints import literal_include_hints; '
                   'result=literal_include_hints(sys.stdin.read()); '
                   'assert chr(35)+"include "+chr(34)+"api.h"+chr(34) in result; print("ok")')
        completed = subprocess.run([sys.executable, '-c', program], input=text, text=True,
                                   capture_output=True, timeout=3)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), 'ok')

    def test_positive_edges_preserve_source_facts_but_path_changes_invalidate(self) -> None:
        index = SourceIncludeIndex('', ('unit.c', 'api.h'))
        cache = SourceAnalysisCache(KernelConfig(''), index)
        contents = b'#include "api.h"\n'
        epoch = index.resolution_epoch
        generation = index.generation
        with patch.object(index, 'analyze_source', wraps=index.analyze_source) as analyze:
            first = cache.analyze_facts('unit.c', ConfigValue.ENABLED, contents)
            index.observe_targets('unit.c', ('api.h',))
            self.assertGreater(index.generation, generation)
            self.assertEqual(index.resolution_epoch, epoch)
            self.assertIs(cache.analyze_facts('unit.c', ConfigValue.ENABLED, contents), first)
            self.assertEqual(analyze.call_count, 1)
            index.add_paths(('other.h',))
            self.assertGreater(index.resolution_epoch, epoch)
            cache.analyze_facts('unit.c', ConfigValue.ENABLED, contents)
            self.assertEqual(analyze.call_count, 2)

    def test_sibling_state_keeps_exact_facts_after_positive_edge_addition(self) -> None:
        files = {'Kbuild': 'obj-y += unit.o\n', 'unit.c': '#include "api.h"\n',
                 'api.h': 'int api;\n', 'other.h': 'int other;\n'}
        state = self.state(files)
        self.assertEqual(state.get('api.h'), ConfigValue.ENABLED)
        sibling = KbuildState.copy(state)
        with patch.object(sibling, '_read_file', wraps=sibling._read_file) as read:
            state.source_includes.observe_targets('unit.c', ('other.h',))
            self.assertEqual(sibling.get('api.h'), ConfigValue.ENABLED)
            self.assertFalse(any(call.args[1] == 'unit.c' for call in read.call_args_list))
            # The new possible reverse edge is rechecked against the actual bytes.
            self.assertIsNone(sibling.get('other.h'))
        old_epoch = state.source_includes.resolution_epoch
        state.source_includes.add_paths(('new.h',))
        self.assertGreater(state.source_includes.resolution_epoch, old_epoch)
        with patch.object(sibling, '_read_file', wraps=sibling._read_file) as read:
            self.assertEqual(sibling.get('api.h'), ConfigValue.ENABLED)
            self.assertTrue(any(call.args[1] == 'unit.c' for call in read.call_args_list))

    def test_nonregular_opacity_and_nonfile_membership_change_resolution_epoch(self) -> None:
        index = SourceIncludeIndex('', ('unit.c',))
        epoch = index.resolution_epoch
        diff = make_diff('unit.c', DiffFileType.DEFAULT)
        diff.files[0].old_mode = diff.files[0].new_mode = '160000'
        index.add_diff(diff)
        self.assertGreater(index.resolution_epoch, epoch)
        self.assertFalse(index.has_path('unit.c'))
        epoch = index.resolution_epoch
        diff.files[0].old_mode = diff.files[0].new_mode = '100644'
        index.add_diff(diff)
        self.assertGreater(index.resolution_epoch, epoch)
        self.assertTrue(index.has_path('unit.c'))

    def test_architecture_change_invalidates_exact_include_resolution(self) -> None:
        index = SourceIncludeIndex('x86', ('unit.c', 'arch/x86/include/asm/api.h', 'arch/arm64/include/asm/api.h'))
        cache = SourceAnalysisCache(KernelConfig(''), index)
        contents = b'#include <asm/api.h>\n'
        self.assertEqual(cache.analyze('unit.c', ConfigValue.ENABLED, contents), frozenset(('arch/x86/include/asm/api.h',)))
        epoch = index.resolution_epoch
        index.srcarch = 'arm64'
        self.assertGreater(index.resolution_epoch, epoch)
        self.assertEqual(cache.analyze('unit.c', ConfigValue.ENABLED, contents), frozenset(('arch/arm64/include/asm/api.h',)))

    def test_many_cold_roots_read_relevant_consumer_not_configured_frontier(self) -> None:
        sources = [f'unit{number}.c' for number in range(1024)]
        files = {'Makefile': 'obj-y += ' + ' '.join(path[:-2] + '.o' for path in sources),
                 **{path: 'int plain;\n' for path in sources}, 'api.h': '#define VALUE 1\n'}
        files['unit0.c'] = '#define STR_(x) #x\n#define STR(x) STR_(x)\n#include STR(api.h)\n'
        files['unit1.c'] = '#define LABEL(x) \\\n    "value: " #x \\\n    "!"\nint plain;\n'
        roots = 40
        repo = MemoryGitRepo({f'root{number}': files for number in range(roots)})
        index = SourceIncludeIndex('', files)
        for path, contents in files.items():
            for line in contents.splitlines():
                index.add_line(path, line)
        config = KernelConfig('')
        self.assertFalse(index.normalization_sources)
        cache = SourceAnalysisCache(config, index)
        source_reads = 0
        def read(revision: str, path: str) -> bytes:
            nonlocal source_reads
            source_reads += path.endswith('.c')
            return repo.read_file(revision, path)
        for number in range(roots):
            state = KbuildState(repo, config, f'root{number}', index, read, source_analysis_cache=cache)
            self.assertEqual(state.get('unit1.c'), ConfigValue.ENABLED)
            self.assertEqual(state.get('api.h'), ConfigValue.ENABLED)
        self.assertEqual(source_reads, roots)

    def test_split_filename_normalization_candidates_survive_worker_snapshot(self) -> None:
        index = SourceIncludeIndex('', ('unit.c', 'api.h'))
        index.add_line('unit.c', '#include "api.\\')
        self.assertEqual(index.normalization_sources, frozenset(('unit.c',)))
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / 'snapshot.json'
            index.write_snapshot(path)
            restored = SourceIncludeIndex.read_snapshot(path)
        self.assertEqual(restored.normalization_sources, index.normalization_sources)
        self.assertEqual(restored.uncertain_sources, index.uncertain_sources)

    def test_normalization_does_not_eagerly_read_ordinary_header_closure(self) -> None:
        files = {'Kbuild': 'obj-y += unit.o\n', 'unit.c': '#include "api.\\\nh"\n',
                 'api.h': '#include "nested.h"\n', 'nested.h': 'int value;\n'}
        index = SourceIncludeIndex('', files)
        for path, contents in files.items():
            for line in contents.splitlines():
                index.add_line(path, line)
        self.assertEqual(index.normalization_sources, frozenset(('unit.c',)))
        repo = MemoryGitRepo({'base': files})
        reads: list[str] = []
        def read(revision: str, path: str) -> bytes:
            reads.append(path)
            return repo.read_file(revision, path)
        state = KbuildState(repo, KernelConfig(''), 'base', index, read)
        self.assertIsNone(state.get('unrelated.c'))
        self.assertIn('unit.c', reads)
        self.assertNotIn('api.h', reads)
        self.assertNotIn('nested.h', reads)
        self.assertEqual(state.get('nested.h'), ConfigValue.ENABLED)
        self.assertIn('api.h', reads)

    def test_actual_computed_include_positives_preserve_native_header_change(self) -> None:
        compiler = shutil.which('clang')
        if compiler is None:
            self.skipTest('Clang native control unavailable')
        expressions = (
            ('#define STR_(x) #x\n#define STR(x) STR_(x)\n#include STR(api.h)\n', 'api.h'),
            ('#define HEADER(x) "api.h"\n#include HEADER(ignored)\n', 'api.h'),
            ('#include "regi\\\nstry.h"\n', 'registry.h'),
        )
        for expression, header in expressions:
            with self.subTest(expression=expression), TemporaryDirectory() as temporary:
                root = Path(temporary)
                repo_path = root / 'repo'
                repo_path.mkdir()
                def git(*args: str) -> str:
                    return subprocess.check_output(['git', '-C', str(repo_path), *args], stderr=subprocess.PIPE).decode().strip()
                git('init', '-q'); git('config', 'user.name', 'Config test'); git('config', 'user.email', 'config@example.invalid')
                (repo_path / 'Makefile').write_text('obj-y += unit.o\n')
                (repo_path / 'unit.c').write_text(expression + 'int main(void) { return VALUE; }\n')
                for value in (1, 2):
                    (repo_path / header).write_text(f'#define VALUE {value}\n')
                    git('add', '.'); git('commit', '-qm', str(value))
                    output = root / f'native-{value}'
                    compiled = subprocess.run([compiler, str(repo_path / 'unit.c'), '-o', str(output)], capture_output=True)
                    self.assertEqual(compiled.returncode, 0, compiled.stderr)
                    self.assertEqual(subprocess.run([str(output)]).returncode, value)
                from kpatch.git import GitRepo
                repo = GitRepo(repo_path)
                commit = next(repo.iter_commits_from_revision('HEAD^!'))
                for prefer_pcre in (False, True):
                    index = SourceIncludeIndex.from_repository(repo, commit.commit_id, '', prefer_pcre=prefer_pcre)
                    if header == 'registry.h':
                        self.assertIn('unit.c', index.normalization_sources)
                    else:
                        self.assertEqual(index.includers(header), ('unit.c',))
                view = FilteredCommit(commit)
                context = FilterContext(repo, StructuredCommits.from_commits([commit]), input_roles=Observations())
                config = KernelConfig('')
                output = FilterPipeline([ConfigFilter(config), IfdefFilter(config)]).filter_mutable_commits([view], context, False)
                self.assertEqual(output, [view])
                self.assertFalse(view.edit_masks)
                self.assertFalse(view.code_masks)
                self.assertEqual(view.build_modes[(None, header)].complete, header == 'registry.h')

    def test_actual_config_ifdef_preserves_native_uconfig_runtime_change(self) -> None:
        self._assert_native_override_retained(root_flags=False)

    def test_bare_custom_suffix_alias_keeps_nested_header_consumer_live(self) -> None:
        compiler = shutil.which('clang')
        if compiler is None:
            self.skipTest('Clang native control unavailable')
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo_path = root / 'repo'
            repo_path.mkdir()
            def git(*args: str) -> str:
                return subprocess.check_output(['git', '-C', str(repo_path), *args], stderr=subprocess.PIPE).decode().strip()
            git('init', '-q'); git('config', 'user.name', 'Config test'); git('config', 'user.email', 'config@example.invalid')
            (repo_path / 'Makefile').write_text('obj-y += unit.o\n')
            (repo_path / 'unit.c').write_text('#define STR_(x) #x\n#define STR(x) STR_(x)\n'
                                             '#define HEADER foo.custom\n#include STR(HEADER)\n'
                                             'int main(void) { return VALUE; }\n')
            (repo_path / 'foo.custom').write_text('#include "api.h"\n')
            for value in (1, 2):
                (repo_path / 'api.h').write_text(f'#define VALUE {value}\n')
                git('add', '.'); git('commit', '-qm', str(value))
                output = root / f'native-{value}'
                compiled = subprocess.run([compiler, str(repo_path / 'unit.c'), '-o', str(output)], capture_output=True)
                self.assertEqual(compiled.returncode, 0, compiled.stderr)
                self.assertEqual(subprocess.run([str(output)]).returncode, value)
            from kpatch.git import GitRepo
            repo = GitRepo(repo_path)
            commit = next(repo.iter_commits_from_revision('HEAD^!'))
            for prefer_pcre in (False, True):
                index = SourceIncludeIndex.from_repository(repo, commit.commit_id, '', prefer_pcre=prefer_pcre)
                self.assertEqual(index.includers('foo.custom'), ('unit.c',))
            view = FilteredCommit(commit)
            context = FilterContext(repo, StructuredCommits.from_commits([commit]))
            config = KernelConfig('')
            output = FilterPipeline([ConfigFilter(config), IfdefFilter(config)]).filter_mutable_commits([view], context, False)
            self.assertEqual(output, [view])
            self.assertFalse(view.edit_masks)
            self.assertFalse(view.code_masks)

    def test_actual_config_ifdef_preserves_native_root_flag_runtime_change(self) -> None:
        self._assert_native_override_retained(root_flags=True)

    def _assert_native_override_retained(self, *, root_flags: bool) -> None:
        compiler = shutil.which('clang')
        if compiler is None:
            self.skipTest('Clang native control unavailable')
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo_path = root / 'repo'
            repo_path.mkdir()
            def git(*args: str) -> str:
                return subprocess.check_output(['git', '-C', str(repo_path), *args], stderr=subprocess.PIPE).decode().strip()
            git('init', '-q'); git('config', 'user.name', 'Config test'); git('config', 'user.email', 'config@example.invalid')
            (repo_path / 'drivers').mkdir()
            (repo_path / 'Makefile').write_text('KBUILD_CPPFLAGS += -UCONFIG_FEATURE\n' if root_flags else 'obj-y += main.o drivers/\n')
            if root_flags:
                (repo_path / 'Kbuild').write_text('obj-y += main.o drivers/\n')
            (repo_path / 'drivers/Makefile').write_text('obj-y += unit.o\n' + ('' if root_flags else 'ccflags-y += -UCONFIG_FEATURE\n'))
            (repo_path / 'main.c').write_text('int value(void); int main(void) { return value(); }\n')
            revisions = []
            for value in (7, 8):
                (repo_path / 'drivers/unit.c').write_text(f'#ifndef CONFIG_FEATURE\nint value(void) {{ return {value}; }}\n#endif\n')
                git('add', '.'); git('commit', '-qm', str(value)); revisions.append(git('rev-parse', 'HEAD'))
                output = root / f'native-{value}'
                compiled = subprocess.run([compiler, '-DCONFIG_FEATURE=1', '-UCONFIG_FEATURE',
                                           str(repo_path / 'main.c'), str(repo_path / 'drivers/unit.c'), '-o', str(output)], capture_output=True)
                self.assertEqual(compiled.returncode, 0, compiled.stderr)
                self.assertEqual(subprocess.run([str(output)]).returncode, value)
            from kpatch.git import GitRepo
            repo = GitRepo(repo_path)
            commit = next(repo.iter_commits_from_revision(revisions[1] + '^!'))
            context = FilterContext(repo, StructuredCommits.from_commits([commit]), input_roles=Observations())
            view = FilteredCommit(commit)
            self.assertEqual(len(view.diff.files), 1)
            config = KernelConfig('CONFIG_FEATURE=y')
            output = FilterPipeline([ConfigFilter(config), IfdefFilter(config)]).filter_mutable_commits([view], context, False)
            self.assertEqual(output, [view])
            self.assertFalse(view.build_modes[(None, 'drivers/unit.c')].complete)
            self.assertFalse(view.edit_masks)
            self.assertFalse(view.code_masks)

    def test_root_object_keeps_root_header_consumer_live(self) -> None:
        state = self.state({'Makefile': 'obj-y += unit.o other.o\n',
                            'unit.c': '#include "api.h"\n', 'other.c': '#include "api.h"\n',
                            'api.h': 'int api;\n'})
        self.assertEqual(state.get('other.c'), ConfigValue.ENABLED)
        self.assertEqual(state.get('api.h'), ConfigValue.ENABLED)
        self.assertTrue(state.cpp_context_complete('api.h'))

    def test_root_and_lowercase_assembly_object_relations_are_positive(self) -> None:
        state = self.state({'Kbuild': 'obj-y += root.o drivers/\n',
                            'drivers/Makefile': 'obj-y += assembly.o\n'})
        self.assertEqual(state.get('root.c'), ConfigValue.ENABLED)
        self.assertEqual(state.get('drivers/assembly.s'), ConfigValue.ENABLED)


if __name__ == '__main__': unittest.main()
