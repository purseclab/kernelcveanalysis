"""Configured runtime uses, expanded standalone definitions and known hazards."""
from datetime import UTC, datetime
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest

from kpatch.filter import DeadCodeFilter, FilterContext, FilteredCommit, FilterPipeline, KernelConfig
from kpatch.filter.pruning_decision import PruningDecision
from kpatch.git import CommitParent, GitCommit, GitRepo
from kpatch.filter.syntax import parse_source, unused_definitions


class ConfiguredUnusedTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name)
        self.repo = GitRepo(self.path)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Test')
        self.git('config', 'user.email', 'test@example.invalid')

    def git(self, *args: str) -> str:
        return subprocess.check_output(['git', '-C', str(self.path), *args], stderr=subprocess.PIPE).decode().strip()

    def change(self, before: dict[str, str], after: dict[str, str]) -> GitCommit:
        def save(files: dict[str, str]) -> str:
            for name, text in files.items():
                path = self.path / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            self.git('add', '.')
            self.git('commit', '-qm', 'test', '--allow-empty')
            return self.git('rev-parse', 'HEAD')
        parent, child = save(before), save(after)
        date = datetime(2025, 10, 16, tzinfo=UTC)
        return GitCommit(child, 'Test', 'test@example.invalid', date, date,
                         (CommitParent(parent, self.git('diff', parent, child)),), 'test')

    def run_stage(self, commit: GitCommit, *, config: KernelConfig | None = None) -> list[GitCommit]:
        return FilterPipeline([DeadCodeFilter(config)]).filter_commits([commit], FilterContext(self.repo), show_progress=False)

    def test_new_definition_shapes(self) -> None:
        for old, new in (
            ('extern int isolated_widget(void);\n', ''),
            ('typedef int isolated_type;\n', 'typedef long isolated_type;\n'),
            ('union isolated_type { int value; };\n', 'union isolated_type { long value; };\n'),
            ('enum isolated_type { UNUSED_A=1, UNUSED_B=2 };\n', 'enum isolated_type { UNUSED_A=3, UNUSED_B=4 };\n'),
        ):
            with self.subTest(old=old):
                commit = self.change({'api.h': old}, {'api.h': new})
                self.assertEqual(self.run_stage(commit), [])

    def test_enum_tracks_every_enumerator(self) -> None:
        source = b'enum unused_tag { FIRST=1, LIVE=2 };\n'
        item = next(d for d in unused_definitions(source, parse_source(source)) if d.kind == 'enum_specifier')
        self.assertEqual(item.names, {'unused_tag', 'FIRST', 'LIVE'})
        commit = self.change({'api.h': source.decode(), 'unit.c': '#include "api.h"\nint run(void) { return LIVE; }\n'},
                             {'api.h': source.decode().replace('FIRST=1', 'FIRST=9')})
        self.assertEqual(len(self.run_stage(commit)), 1)

    def test_global_definition_ignores_prototype_but_preserves_callbacks_and_exports(self) -> None:
        old = '#include "api.h"\nint isolated_widget(void) { return 1; }\n'
        for reference, removed in (('', True), ('int (*callback)(void) = isolated_widget;\n', False),
                                   ('EXPORT_SYMBOL(isolated_widget);\n', False)):
            with self.subTest(reference=reference):
                commit = self.change({'Makefile': 'obj-y += unit.o\n',
                                      'api.h': 'int isolated_widget(void);\n', 'unit.c': old + reference},
                                     {'unit.c': (old + reference).replace('return 1', 'return 2')})
                self.assertEqual(not self.run_stage(commit, config=KernelConfig('')), removed)

    def test_configured_out_consumer_no_longer_retains_header(self) -> None:
        old = 'static inline int isolated_widget(void) { return 1; }\n'
        for enabled in (False, True):
            with self.subTest(enabled=enabled):
                commit = self.change({'Makefile': 'obj-y += drivers/\n',
                                      'drivers/Makefile': 'obj-y += enabled.o\nobj-$(CONFIG_FEATURE) += disabled.o\n',
                                      'drivers/api.h': old, 'drivers/enabled.c': '#include "api.h"\n',
                                      'drivers/disabled.c': '#include "api.h"\nint run(void) { return isolated_widget(); }\n'},
                                     {'drivers/api.h': old.replace('return 1', 'return 2')})
                config = KernelConfig('CONFIG_FEATURE=y\n' if enabled else '# CONFIG_FEATURE is not set\n')
                self.assertEqual(not self.run_stage(commit, config=config), not enabled)

    def test_lossy_discovery_keeps_known_multisplice_use(self) -> None:
        consumer = '#include "api.h"\n#if H\\\nZ_\\\nPER_\\\nGHZ\nint run(void) { return 1; }\n#endif\n'
        commit = self.change({'api.h': '', 'unit.c': consumer}, {'api.h': '#define HZ_PER_GHZ 1\n'})
        decisions: list[PruningDecision] = []
        result = FilterPipeline([DeadCodeFilter(on_pruned=decisions.append, lossy=True)]).filter_commits(
            [commit], FilterContext(self.repo), show_progress=False)
        self.assertEqual(len(result), 1)
        self.assertEqual(decisions, [])

    def test_line_assumption_is_separate_and_audited(self) -> None:
        old = '#include "observer.h"\nstatic inline int alive(void) { return LOC; }\n'
        new = old.replace('static inline', 'static int isolated_widget(void) { return 1; }\nstatic inline')
        commit = self.change({'api.h': old, 'observer.h': '#define LOC __LINE__\n',
                              'unit.c': '#include "api.h"\nint run(void) { return alive(); }\n'}, {'api.h': new})
        self.assertEqual(len(self.run_stage(commit)), 1)
        decisions: list[PruningDecision] = []
        stage = DeadCodeFilter(line_numbers_lossy=True, on_line_numbers_assumed=decisions.append)
        result = FilterPipeline([stage]).filter_commits([commit], FilterContext(self.repo), show_progress=False)
        self.assertEqual(result, [])
        self.assertEqual(len(decisions), 1)
        self.assertTrue(decisions[0].lossy)
        self.assertEqual(decisions[0].rule, 'unreferenced_definition_line_numbers_lossy')
        self.assertIn('source_line_number_observations_may_change_runtime_behavior', decisions[0].risk_reasons)
        with self.assertRaises(ValueError):
            DeadCodeFilter(line_numbers_lossy=True)

    def test_line_assumption_does_not_waive_known_columns(self) -> None:
        old = '#include "observer.h"\nstatic inline int alive(void) { return LOC; }\n'
        new = ('#include "observer.h"\nstatic int isolated_widget(void) { return 1; }\n'
               'static inline int alive(void) { return     LOC; }\n')
        commit = self.change({'api.h': old, 'observer.h': '#define LOC __builtin_COLUMN()\n',
                              'unit.c': '#include "api.h"\nint run(void) { return alive(); }\n'}, {'api.h': new})
        decisions: list[PruningDecision] = []
        stage = DeadCodeFilter(line_numbers_lossy=True, on_line_numbers_assumed=decisions.append)
        result = FilterPipeline([stage]).filter_commits([commit], FilterContext(self.repo), show_progress=False)
        self.assertEqual(len(result), 1)
        self.assertEqual(decisions, [])

    def test_unused_audit_failure_precedes_masks(self) -> None:
        commit = self.change({'unit.c': 'static int isolated_widget(void) { return 1; }\n'},
                             {'unit.c': 'static int isolated_widget(void) { return 2; }\n'})
        view = FilteredCommit(commit)
        def fail(decision: PruningDecision) -> None:
            raise RuntimeError('audit failed')
        with self.assertRaisesRegex(RuntimeError, 'audit failed'):
            DeadCodeFilter(on_pruned=fail).filter_mutable_commits([view], FilterContext(self.repo), False)
        self.assertEqual(view.code_masks, ())
        self.assertEqual(view.edit_masks, ())

    def test_balanced_signature_macro_cannot_emit_a_live_definition(self) -> None:
        macros = '#define OLD_TYPE int live_value=1; int\n#define NEW_TYPE int live_value=2; int\n'
        old = '#include "types.h"\nOLD_TYPE isolated_widget(void) { return 0; }\n'
        commit = self.change({'types.h': macros, 'unit.c': old,
                              'consumer.c': 'extern int live_value;\nint run(void) { return live_value; }\n'},
                             {'unit.c': old.replace('OLD_TYPE', 'NEW_TYPE')})
        decisions: list[PruningDecision] = []
        result = FilterPipeline([DeadCodeFilter(on_pruned=decisions.append, lossy=True)]).filter_commits(
            [commit], FilterContext(self.repo), show_progress=False)
        self.assertEqual(len(result), 1)
        self.assertEqual(decisions, [])

    def test_plain_documentation_is_not_a_configured_runtime_use(self) -> None:
        old = 'static inline int isolated_widget(void) { return 1; }\n'
        commit = self.change({'Makefile': 'obj-y += unit.o\n', 'api.h': old,
                              'unit.c': '#include "api.h"\n',
                              'Documentation/example.rst': 'The isolated_widget function is described here.\n'},
                             {'api.h': old.replace('return 1', 'return 2')})
        self.assertEqual(self.run_stage(commit, config=KernelConfig('')), [])

    def test_asm_named_prototype_is_an_observable_binding(self) -> None:
        old = ('int isolated_widget(void) asm("active_alias");\n'
               'int isolated_widget(void) { return 1; }\n')
        commit = self.change({'Makefile': 'obj-y += unit.o consumer.o\n', 'unit.c': old,
                              'consumer.c': 'int active_alias(void);\nint run(void) { return active_alias(); }\n'},
                             {'unit.c': old.replace('return 1', 'return 2')})
        self.assertEqual(len(self.run_stage(commit, config=KernelConfig(''))), 1)

    def test_enabling_a_consumer_in_child_does_not_reuse_parent_absence(self) -> None:
        old = 'static inline int isolated_widget(void) { return 1; }\n'
        commit = self.change({'Makefile': 'obj-y += drivers/\n', 'drivers/Makefile': 'obj-y += empty.o\n',
                              'drivers/empty.c': '', 'drivers/api.h': old,
                              'drivers/consumer.c': '#include "api.h"\nint run(void) { return isolated_widget(); }\n'},
                             {'drivers/Makefile': 'obj-y += empty.o consumer.o\n',
                              'drivers/api.h': old.replace('return 1', 'return 2')})
        result = self.run_stage(commit, config=KernelConfig(''))
        self.assertEqual(len(result), 1)
        self.assertIn('drivers/api.h', [f.file for f in result[0].diff.files])

    def test_configured_inactive_branch_is_not_a_runtime_consumer(self) -> None:
        old = 'static inline int isolated_widget(void) { return 1; }\n'
        commit = self.change({'Makefile': 'obj-y += unit.o\n', 'api.h': old,
                              'unit.c': '#include "api.h"\n#ifdef CONFIG_FEATURE\nint run(void) { return isolated_widget(); }\n#endif\n'},
                             {'api.h': old.replace('return 1', 'return 2')})
        self.assertEqual(self.run_stage(commit, config=KernelConfig('# CONFIG_FEATURE is not set\n')), [])

    def test_unused_alias_or_signature_cannot_erase_an_escaping_tag(self) -> None:
        observer = ('int callback(struct introduced *);\nint main(void) {\n'
                    ' return __builtin_types_compatible_p(__typeof__(&callback), int (*)(struct introduced *));\n}\n')
        for declaration in ('typedef struct introduced unused_alias;\n',
                            'struct introduced *isolated_widget(void);\n',
                            'struct introduced *isolated_widget(void) { return 0; }\n',
                            'static struct introduced *isolated_widget(void) { return 0; }\n',
                            'struct unused_outer { struct introduced *member; };\n'):
            with self.subTest(declaration=declaration):
                source = (declaration + observer).encode()
                candidate = next(item for item in unused_definitions(source, parse_source(source))
                                 if item.name in {'unused_alias', 'isolated_widget', 'unused_outer'})
                self.assertIn('introduced', candidate.names)
                commit = self.change({'unit.c': source.decode()}, {'unit.c': observer})
                self.assertEqual(len(self.run_stage(commit)), 1)

    def test_clear_prior_page_declaration_is_not_a_new_dependency(self) -> None:
        old = ('#ifndef API_H\n#define API_H\nstruct page;\n'
               'static inline struct page *isolated_widget(void) { return 0; }\n#endif\n')
        candidate = next(item for item in unused_definitions(old.encode(), parse_source(old.encode()))
                         if item.name == 'isolated_widget')
        self.assertNotIn('page', candidate.names)
        commit = self.change({'api.h': old}, {'api.h': old.replace('static inline struct page *isolated_widget(void) { return 0; }\n', '')})
        self.assertEqual(self.run_stage(commit), [])

    def test_tag_in_opposite_preprocessor_branch_is_not_prior_evidence(self) -> None:
        source = b'#ifdef OTHER\nstruct introduced;\n#else\ntypedef struct introduced unused_alias;\n#endif\n'
        candidate = next(item for item in unused_definitions(source, parse_source(source)) if item.name == 'unused_alias')
        self.assertIn('introduced', candidate.names)

    def test_global_function_requires_a_configured_caller_scope(self) -> None:
        old = 'int isolated_widget(void) { return 1; }\n'
        commit = self.change({'Makefile': 'obj-y += unit.o\n', 'unit.c': old},
                             {'unit.c': old.replace('return 1', 'return 2')})
        self.assertEqual(len(self.run_stage(commit)), 1)
        self.assertEqual(self.run_stage(commit, config=KernelConfig('')), [])

    def test_known_type_introducing_macro_is_not_metadata(self) -> None:
        observer = ('int callback(struct introduced *);\nint main(void) {\n'
                    ' return __builtin_types_compatible_p(__typeof__(&callback), int (*)(struct introduced *));\n}\n')
        for prefix, declaration in (
            ('#define RET struct introduced\n', 'RET *isolated_widget(void);\n'),
            ('struct old_tag;\n#define old_tag introduced\n', 'typedef struct old_tag unused_alias;\n'),
        ):
            with self.subTest(prefix=prefix):
                commit = self.change({'unit.c': prefix + declaration + observer}, {'unit.c': prefix + observer})
                decisions: list[PruningDecision] = []
                result = FilterPipeline([DeadCodeFilter(on_pruned=decisions.append, lossy=True)]).filter_commits(
                    [commit], FilterContext(self.repo), show_progress=False)
                self.assertEqual(len(result), 1)
                self.assertEqual(decisions, [])

    def test_body_local_type_macro_does_not_escape_an_unused_function(self) -> None:
        macros = '#define CAST(value) ((struct local_type *)(value))\n'
        old = '#include "types.h"\nstatic int isolated_widget(void) { return CAST(0) != 0; }\n'
        commit = self.change({'types.h': macros, 'unit.c': old}, {'unit.c': old.replace('CAST(0)', 'CAST(1)')})
        self.assertEqual(self.run_stage(commit), [])

    def test_scoped_guard_constructor_is_a_known_generated_callback(self) -> None:
        old = 'static inline int class_widget_constructor(void) { return 1; }\n'
        consumer = ('#include "api.h"\n#define USE_GUARD(name) class_##name##_constructor()\n'
                    'int run(void) { return USE_GUARD(widget); }\n')
        commit = self.change({'api.h': old, 'unit.c': consumer}, {'api.h': old.replace('return 1', 'return 2')})
        decisions: list[PruningDecision] = []
        output = FilterPipeline([DeadCodeFilter(on_pruned=decisions.append, lossy=True)]).filter_commits(
            [commit], FilterContext(self.repo), show_progress=False)
        self.assertEqual(len(output), 1)
        self.assertEqual(decisions, [])

    def test_linker_wrapper_spellings_are_runtime_consumers(self) -> None:
        old = 'int isolated_widget(void) { return 1; }\n'
        for reference in ('__real_isolated_widget', '__wrap_isolated_widget'):
            with self.subTest(reference=reference):
                commit = self.change({'Makefile': 'obj-y += unit.o consumer.o\n', 'unit.c': old,
                                      'consumer.c': f'int {reference}(void);\nint run(void) {{ return {reference}(); }}\n'},
                                     {'unit.c': old.replace('return 1', 'return 2')})
                self.assertEqual(len(self.run_stage(commit, config=KernelConfig(''))), 1)

    def test_literal_linker_build_glue_is_a_runtime_consumer(self) -> None:
        old = 'int isolated_widget(void) { return 1; }\n'
        commit = self.change({'Makefile': 'obj-y += unit.o\nKBUILD_LDFLAGS += --wrap=isolated_widget\n', 'unit.c': old},
                             {'unit.c': old.replace('return 1', 'return 2')})
        self.assertEqual(len(self.run_stage(commit, config=KernelConfig(''))), 1)

    def test_underscored_constructor_macro_is_a_runtime_callback(self) -> None:
        old = ('#define RET int __attribute__((__constructor__))\nint live_value;\n'
               'static RET startup_hook(void) { live_value=1; return 0; }\n')
        commit = self.change({'unit.c': old}, {'unit.c': old.replace('live_value=1', 'live_value=2')})
        self.assertEqual(len(self.run_stage(commit)), 1)
