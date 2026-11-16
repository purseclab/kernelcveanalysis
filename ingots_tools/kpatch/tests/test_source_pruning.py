from collections.abc import Iterator
from datetime import UTC, datetime
from dataclasses import asdict
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from kpatch.filter import DeadCodeFilter, FilterContext, FilteredCommit, FilterPipeline, IfdefFilter, KernelConfig, LineRange, MaskReason, RenameFilter, WhitespaceFilter
from kpatch.filter.base import FileBuildModes
from kpatch.filter.reference_index import ReferenceIndex, ReferenceSite, spelling_guards
from kpatch.filter.repository_file import RepositoryFileReader
from kpatch.filter.reordering import hunk_reorder_candidate
from kpatch.filter.source_pruning import PruningDecision, source_pruning_tail
from kpatch.filter.source_filter import SourceIncludeIndex, _iter_git_grep
from kpatch.filter.git_output import GitGrepRow
from kpatch.git import CommitParent, GitCommit, GitRepo
from kpatch.diff import Diff
from benchmarks.ast_pruning.verify import Decision, Verifier


class SourcePruningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name)
        self.repo = GitRepo(self.path)
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Test")

    def git(self, *args: str) -> str:
        return subprocess.check_output(["git", "-C", str(self.path), *args], stderr=subprocess.PIPE).decode().strip()

    def commit(self, files: dict[str, str]) -> str:
        for path, text in files.items():
            target = self.path / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        self.git("add", ".")
        self.git("commit", "-qm", "test", "--allow-empty")
        return self.git("rev-parse", "HEAD")

    def change(self, before: dict[str, str], after: dict[str, str]) -> GitCommit:
        parent = self.commit(before)
        child = self.commit(after)
        date = datetime(2025, 10, 16, tzinfo=UTC)
        return GitCommit(child, "Test", "test@example.invalid", date, date,
                         (CommitParent(parent, self.git("diff", parent, child)),), "test")

    def run_stage(self, commit: GitCommit, *, rename: bool = False, config: KernelConfig | None = None) -> list[GitCommit]:
        self.decisions: list[PruningDecision] = []
        # Exercise rename safety guards in the explicitly lossy candidate mode;
        # default metadata retention has its own regression test below.
        stage = RenameFilter(config, self.decisions.append, lossy=True) if rename else DeadCodeFilter(config, self.decisions.append)
        return FilterPipeline([stage]).filter_commits([commit], FilterContext(self.repo), show_progress=False)

    @staticmethod
    def complete_cpp_view(commit: GitCommit) -> FilteredCommit:
        """These fixtures explicitly model each changed file as a sole CPP input."""
        return FilteredCommit(commit, build_modes={
            (file.old_file, file.file): FileBuildModes('y', 'y', complete=True) for file in commit.diff.files
        })

    def test_static_function_rename_and_all_calls(self) -> None:
        a = "static int old_helper(int n) { return n + 1; }\nint run(void) { return old_helper(2); }\n"
        commit = self.change({"unit.c": a}, {"unit.c": a.replace("old_helper", "new_helper")})
        self.assertEqual(self.run_stage(commit, rename=True), [])
        self.assertEqual(self.decisions[0].rule, "consistent_rename")
        self.assertFalse(self.decisions[0].lossy)
        self.assertIn('symbol_type_and_member_names_may_be_observable_through_btf_or_kallsyms', self.decisions[0].risk_reasons)

    def test_default_ignores_metadata_only_identifier_names(self) -> None:
        for old in (
            'static int primary(void) { return 1; }\nint run(void) { return primary(); }\n',
            'struct primary { int value; };\nstruct primary instance;\n',
            'union primary { int value; };\nunion primary instance;\n',
            'enum primary { VALUE = 1 };\nenum primary instance;\n',
            'enum kind { primary = 1 };\nint run(void) { return primary; }\n',
            'struct kind { int primary; };\nint run(struct kind *p) { return p->primary; }\n',
            'typedef int primary;\nprimary instance;\n',
        ):
            with self.subTest(source=old):
                commit = self.change({'unit.c': old}, {'unit.c': old.replace('primary', 'renamed')})
                decisions: list[PruningDecision] = []
                stage = RenameFilter(on_pruned=decisions.append)
                self.assertEqual(stage.filter_commits([commit], FilterContext(self.repo), False), [])
                self.assertTrue(decisions)
                self.assertFalse(decisions[0].lossy)
                self.assertEqual(self.run_stage(commit, rename=True), [])
                self.assertFalse(self.decisions[0].lossy)

    def test_unused_header_is_not_blocked_by_asm_include_or_comment(self) -> None:
        old = ('#include <asm/memory.h>\n/* asm __func__ ## are words in a comment. */\n'
               'static inline int isolated_widget(void) { return 1; }\n')
        c = self.change({"api.h": old, "asm/memory.h": "/* tracked include */\n"},
                        {"api.h": old.replace("return 1", "return 2")})
        self.assertEqual(self.run_stage(c), [])
        self.assertEqual(self.decisions[0].symbols, ("isolated_widget",))

    def test_unused_literal_macro_is_not_blocked_by_opaque_words_in_string(self) -> None:
        c = self.change({"api.h": '#define ISOLATED_WIDGET "asm ## __func__"\n'},
                        {"api.h": '#define ISOLATED_WIDGET "__asm__ #text"\n'})
        self.assertEqual(self.run_stage(c), [])

    def test_unused_macro_at_end_preserves_a_live_header_location_alias(self) -> None:
        base = '#include "observer.h"\nstatic inline int value(void) { return LOC; }\n'
        added = base + '#define ISOLATED_WIDGET 1\n'
        for old, new in ((base, added), (added, base)):
            with self.subTest(adding=len(new) > len(old)):
                commit = self.change({'api.h': old, 'observer.h': '#define LOC __LINE__\n',
                                      'unit.c': '#include "api.h"\nint run(void) { return value(); }\n'},
                                     {'api.h': new})
                self.assertEqual(self.run_stage(commit), [])
                self.assertEqual(self.decisions[0].symbols, ('ISOLATED_WIDGET',))

    def test_unused_macro_cannot_shift_a_live_header_line_alias(self) -> None:
        base = '#include "observer.h"\nstatic inline int value(void) { return LOC; }\n'
        added = '#define ISOLATED_WIDGET 1\n' + base
        for old, new in ((base, added), (added, base)):
            with self.subTest(adding=len(new) > len(old)):
                commit = self.change({'api.h': old, 'observer.h': '#define LOC __LINE__\n',
                                      'unit.c': '#include "api.h"\nint run(void) { return value(); }\n'},
                                     {'api.h': new})
                self.assertEqual(len(self.run_stage(commit)), 1)
                self.assertEqual(self.decisions, [])

    def test_line_only_movement_does_not_change_a_column_alias(self) -> None:
        base = '#include "observer.h"\nstatic inline int value(void) { return LOC; }\n'
        commit = self.change({'api.h': base, 'observer.h': '#define LOC __builtin_COLUMN()\n',
                              'unit.c': '#include "api.h"\nint run(void) { return value(); }\n'},
                             {'api.h': '#define ISOLATED_WIDGET 1\n' + base})
        self.assertEqual(self.run_stage(commit), [])

    def test_unused_function_addition_or_removal_cannot_shift_a_live_line_alias(self) -> None:
        base = '#include "observer.h"\nstatic inline int value(void) { return LOC; }\n'
        added = '#include "observer.h"\nstatic int isolated_helper(void) { return 1; }\n' + base.split('\n', 1)[1]
        for old, new in ((base, added), (added, base)):
            with self.subTest(adding=len(new) > len(old)):
                commit = self.change({'api.h': old, 'observer.h': '#define LOC __LINE__\n',
                                      'unit.c': '#include "api.h"\nint run(void) { return value(); }\n'},
                                     {'api.h': new})
                self.assertEqual(len(self.run_stage(commit)), 1)
                self.assertEqual(self.decisions, [])

    def test_unused_macro_and_function_group_cannot_hide_live_line_movement(self) -> None:
        base = '#include "observer.h"\nstatic inline int value(void) { return LOC; }\n'
        added = ('#define ISOLATED_WIDGET 1\nstatic int isolated_helper(void) { return 1; }\n' + base)
        for old, new in ((base, added), (added, base)):
            with self.subTest(adding=len(new) > len(old)):
                commit = self.change({'api.h': old, 'observer.h': '#define LOC __LINE__\n',
                                      'unit.c': '#include "api.h"\nint run(void) { return value(); }\n'},
                                     {'api.h': new})
                self.assertEqual(len(self.run_stage(commit)), 1)
                self.assertEqual(self.decisions, [])

    def test_partial_unused_function_mask_preserves_other_changed_location_observers(self) -> None:
        old = ('#include "observer.h"\nstatic int isolated_helper(void) { return 1; }\n'
               'static inline int value(void) { return LOC; }\n')
        for observer, new_body in (
            ('__LINE__', 'static inline int value(void) {\n return LOC + 1;\n}\n'),
            ('__builtin_COLUMN()', 'static inline int value(void) { return     LOC + 1; }\n'),
        ):
            with self.subTest(observer=observer):
                new = ('#include "observer.h"\nstatic int isolated_helper(void) { return 2; }\n' + new_body)
                commit = self.change({'api.h': old, 'observer.h': '#define LOC ' + observer + '\n',
                                      'unit.c': '#include "api.h"\nint run(void) { return value(); }\n'},
                                     {'api.h': new})
                decisions: list[PruningDecision] = []
                output = DeadCodeFilter(on_pruned=decisions.append).filter_mutable_commits(
                    [FilteredCommit(commit)], FilterContext(self.repo), False,
                )
                self.assertEqual(len(output), 1)
                self.assertEqual(output[0].code_masks, ())
                self.assertEqual(output[0].edit_masks, ())
                self.assertEqual(decisions, [])

    def test_phase_two_spliced_consumer_references_cannot_look_unused(self) -> None:
        for newline, splice in (('\n', '\\\n'), ('\r\n', '\\\r\n'), ('\n', '\\  \n')):
            consumer = newline.join(('#include "api.h"', '#if ' + splice.join(('H', 'Z_', 'PER_', 'GHZ')),
                                     'int run(void) { return 1; }', '#else',
                                     'int run(void) { return 0; }', '#endif', ''))
            for old, new in (('', '#define HZ_PER_GHZ 1\n'), ('#define HZ_PER_GHZ 1\n', '')):
                with self.subTest(newline=repr(newline), splice=repr(splice), adding=bool(new)):
                    commit = self.change({'api.h': old, 'unit.c': consumer}, {'api.h': new})
                    self.assertEqual(len(self.run_stage(commit)), 1)
                    self.assertEqual(self.decisions, [])

    def test_unused_guard_preserves_real_asm_and_macro_effects(self) -> None:
        prefixes = ['void run(void) { asm("nop"); }\n', 'void run(void) { __asm__("nop"); }\n',
                    '#define NAME(x) prefix ## x\n', '#define TEXT(x) #x\n']
        for prefix in prefixes:
            with self.subTest(prefix=prefix):
                old = prefix + 'static int isolated_widget(void) { return 1; }\n'
                self.assertEqual(len(self.run_stage(self.change({"unit.c": old}, {"unit.c": old.replace('return 1', 'return 2')}))), 1)

    def test_independent_static_helpers_reorder_is_pruned(self) -> None:
        a = 'static int first(int n) { return n + 1; }\n'
        b = 'static int second(int n) { return n - 1; }\n'
        c = self.change({"unit.c": a + b}, {"unit.c": b + a})
        self.assertEqual(self.run_stage(c, rename=True), [])
        self.assertEqual(self.decisions[0].rule, "independent_definition_reorder")
        self.assertEqual(self.decisions[0].symbols, ("first", "second"))
        self.assertTrue(self.decisions[0].lossy)
        with RepositoryFileReader(self.repo) as reader:
            Verifier(self.repo, reader, KernelConfig("")).verify(Decision.model_validate(asdict(self.decisions[0])))

    def test_adjacent_switch_returns_are_pruned_with_separate_reason(self) -> None:
        prefix = '#include "values.h"\nint run(int n) { switch(n) {\n'
        a, b = 'case FIRST: return 10;\n', 'case SECOND: return 20;\n'
        tail = 'default: warn(); return -1;\n}}\n'
        commit = self.change({'unit.c': prefix+a+b+tail, 'values.h': '#define FIRST 1\n#define SECOND 2\n'},
                             {'unit.c': prefix+b+a+tail})
        self.assertEqual(self.run_stage(commit, rename=True), [])
        self.assertEqual(self.decisions[0].rule, 'independent_return_case_reorder')
        self.assertTrue(self.decisions[0].lossy)

    def assert_reorder_requires_audited_assumption(self, commit: GitCommit, reason: str) -> None:
        for lossy, audited in ((False, True), (True, False), (True, True)):
            with self.subTest(lossy=lossy, audited=audited):
                decisions: list[PruningDecision] = []
                stage = RenameFilter(on_pruned=decisions.append if audited else None, lossy=lossy)
                view = FilteredCommit(commit)
                output = FilterPipeline([stage]).filter_mutable_commits([view], FilterContext(self.repo), False)
                self.assertEqual(view.code_masks, ())
                if not lossy or not audited:
                    self.assertEqual(output, [view])
                    self.assertEqual(view.edit_masks, ())
                    self.assertEqual(decisions, [])
                    continue
                self.assertEqual(output, [])
                self.assertEqual(len(view.edit_masks), 1)
                self.assertTrue(view.edit_masks[0].whole_file)
                self.assertEqual(len(decisions), 1)
                self.assertEqual(decisions[0].rule, reason)
                self.assertTrue(decisions[0].lossy)
                self.assertIn('function_and_callsite_addresses_may_change_runtime_behavior', decisions[0].risk_reasons)
                self.assertIn('compiler_generated_layout_and_instrumentation_not_proven_equivalent', decisions[0].risk_reasons)

    def test_function_address_observer_reorder_requires_audited_assumption(self) -> None:
        prefix = 'typedef unsigned long word;\n'
        left = 'static int left(void) { return 1; }\n'
        right = 'static int right(void) { return 2; }\n'
        observer = 'int main(void) { word a=(word)left, b=(word)right; return a<b?1:2; }\n'
        commit = self.change({'unit.c': prefix+left+right+observer}, {'unit.c': prefix+right+left+observer})
        self.assert_reorder_requires_audited_assumption(commit, 'independent_definition_reorder')

    def test_return_callsite_observer_reorder_requires_audited_assumption(self) -> None:
        prefix = ('typedef unsigned long word;\n'
                  '__attribute__((noinline)) word observe(int ignored) { (void)ignored; '
                  'return (word)__builtin_return_address(0); }\n'
                  '__attribute__((noinline)) word run(int n) { switch(n) {\n')
        first, second = 'case 1: return observe(1);\n', 'case 2: return observe(2);\n'
        suffix = '} return 0; }\nint main(void) { word a=run(1), b=run(2); return a<b?1:2; }\n'
        commit = self.change({'unit.c': prefix+first+second+suffix}, {'unit.c': prefix+second+first+suffix})
        self.assert_reorder_requires_audited_assumption(commit, 'independent_return_case_reorder')

    def test_return_case_macros_cannot_observe_a_reorder(self) -> None:
        prefix = '#include "values.h"\nint run(int n) { switch(n) {\n'
        a, b = 'case 1: return VALUE;\n', 'case 2: return 20;\n'
        tail = 'default: return -1;\n}}\n'
        commit = self.change({'unit.c': prefix+a+b+tail, 'values.h': '#define VALUE __LINE__\n'},
                             {'unit.c': prefix+b+a+tail})
        self.assertEqual(len(self.run_stage(commit, rename=True)), 1)

    def test_preceding_fallthrough_blocks_a_return_case_reorder(self) -> None:
        prefix = 'int run(int n) { switch(n) {case 0:n++;\n'
        a, b = 'case 1:return 10;\n', 'case 2:return 20;\n'
        tail = '}return 0;}\n'
        commit = self.change({'unit.c': prefix+a+b+tail}, {'unit.c': prefix+b+a+tail})
        self.assertEqual(len(self.run_stage(commit, rename=True)), 1)
        self.assertEqual(self.decisions, [])

    def test_reorder_after_masking_a_new_unused_helper(self) -> None:
        a = 'static int first(int n) { return n + 1; }\n'
        b = 'static int second(int n) { return n - 1; }\n'
        unused = 'static int isolated_widget(void) { return 777; }\n'
        caller = 'int run(void) { return first(1) + second(2); }\n'
        c = self.change({"unit.c": a + b + caller}, {"unit.c": b + a + unused + caller})
        decisions: list[PruningDecision] = []
        pipeline = FilterPipeline(list(source_pruning_tail(on_pruned=decisions.append, lossy=True)))
        self.assertEqual(pipeline.filter_commits([c], FilterContext(self.repo), False), [])
        self.assertEqual([d.rule for d in decisions], ["unreferenced_definition", "independent_definition_reorder"])
        with RepositoryFileReader(self.repo) as reader:
            verifier = Verifier(self.repo, reader, KernelConfig(""))
            for decision in decisions:
                verifier.verify(Decision.model_validate(asdict(decision)))

    def test_masked_reorder_uses_complete_sources_when_reduced_hunk_is_incomplete(self) -> None:
        a = 'static inline int first(int n)\n{\n\treturn n & 1;\n}\n\n'
        b = 'static inline int second(int n)\n{\n\treturn n & 2;\n}\n\n'
        unused = 'static inline int isolated_widget(int n)\n{\n\treturn n & 4;\n}\n\n'
        caller = 'int run(void) { return first(1) + second(2); }\n'
        c = self.change({"unit.c": a + b + caller}, {"unit.c": b + a + unused + caller})
        views = FilterPipeline([DeadCodeFilter()]).filter_mutable_commits([FilteredCommit(c)], FilterContext(self.repo), False)
        self.assertEqual(len(views), 1)
        self.assertFalse(hunk_reorder_candidate(views[0].diff.files[0]))
        decisions: list[PruningDecision] = []
        self.assertEqual(FilterPipeline([RenameFilter(on_pruned=decisions.append, lossy=True)]).filter_mutable_commits(
            views, FilterContext(self.repo), False), [])
        self.assertTrue(decisions[0].lossy)

    def test_reorder_allows_literal_numeric_macros(self) -> None:
        a = 'static inline int first(const struct card *c) { return c->quirks & FLAG_A; }\n'
        b = 'static inline int second(const struct card *c) { return c->quirks & FLAG_B; }\n'
        c = self.change({"api.h": '#define FLAG_A (1<<4)\n#define FLAG_B (1<<5)\n', "unit.c": a + b},
                        {"unit.c": b + a})
        self.assertEqual(self.run_stage(c, rename=True), [])

    def test_reorder_macro_discovery_normalizes_complete_comment_and_splice_context(self) -> None:
        prefix = '#include "values.h"\n'
        a = 'static int first(void) { return VALUE; }\n'
        b = 'static int second(void) { return 2; }\n'
        definitions = [
            '/* start\n continued */ #define VALUE __LINE__\n',
            '/* start\n continued */ %:define VALUE __LINE__\n',
            '/* start\n continued */ #def' + chr(92) + '\nine VALUE __LINE__\n',
            '/* start\n continued */ #define VAL' + chr(92) + '\nUE __LINE__\n',
            '??=define VALUE __LINE__\n',
            '\0#define VALUE __LINE__\n',
            '#define VA' + chr(92) + '   \nLUE __LINE__\n',
            '#define VA' + chr(92) + '\rLUE __LINE__\r',
        ]
        for definition in definitions:
            with self.subTest(definition=definition):
                commit = self.change({'unit.c': prefix+a+b, 'values.h': definition}, {'unit.c': prefix+b+a})
                self.assertEqual(len(self.run_stage(commit, rename=True)), 1)
                self.assertEqual(self.decisions, [])

    def test_switch_macro_discovery_preserves_hidden_location_binding(self) -> None:
        prefix = '#include "values.h"\nint run(int n) {switch(n){\n'
        a, b, tail = 'case 1:return VALUE;\n', 'case 2:return 2;\n', '}}\n'
        commit = self.change({'unit.c': prefix+a+b+tail, 'values.h': '/* start\n continued */ #define VALUE __LINE__\n'},
                             {'unit.c': prefix+b+a+tail})
        self.assertEqual(len(self.run_stage(commit, rename=True)), 1)
        self.assertEqual(self.decisions, [])

    def test_reorder_retains_external_position_and_unknown_macros(self) -> None:
        a = 'static int first(void) { return VALUE; }\n'
        b = 'static int second(void) { return VALUE + 1; }\n'
        for macros in ('#define VALUE __COUNTER__\n', '#define VALUE __LINE__\n',
                       '#define VALUE OTHER_VALUE\n', '#define VALUE compute()\n',
                       '#define \\\nVALUE __COUNTER__\n', '#define VA\\\nLUE __COUNTER__\n',
                       '#\\\ndefine VALUE __COUNTER__\n', '#/**/define VALUE __COUNTER__\n',
                       '#define/**/VALUE __COUNTER__\n', '#define VALUE/**/__COUNTER__\n',
                       '%:define VALUE __COUNTER__\n', '/* prefix */ #define VALUE __COUNTER__\n'):
            with self.subTest(macros=macros):
                c = self.change({"api.h": macros, "unit.c": a + b}, {"unit.c": b + a})
                self.assertEqual(len(self.run_stage(c, rename=True)), 1)
                self.assertEqual(self.decisions, [])

    def test_reorder_retains_macro_capture_of_parameter_or_field(self) -> None:
        a = 'static int first(int n) { return n + 1; }\n'
        b = 'static int second(int n) { return n - 1; }\n'
        c = self.change({"api.h": '#define n __COUNTER__\n', "unit.c": a + b}, {"unit.c": b + a})
        self.assertEqual(len(self.run_stage(c, rename=True)), 1)

    def test_reorder_ignores_unrelated_continued_macro_definitions(self) -> None:
        a = 'static int first(int n) { return n + 1; }\n'
        b = 'static int second(int n) { return n - 1; }\n'
        macros = '#define OTHER\\\n 1\n#define \\\n UNRELATED 2\n'
        c = self.change({"api.h": macros, "unit.c": a + b}, {"unit.c": b + a})
        self.assertEqual(self.run_stage(c, rename=True), [])

    def test_reorder_ignores_configured_out_translation_unit_macros(self) -> None:
        a = 'static int first(int n) { return n + 1; }\n'
        b = 'static int second(int n) { return n - 1; }\n'
        c = self.change({"Makefile": 'obj-y += unit.o drivers/\n',
                         "drivers/Makefile": 'obj-$(CONFIG_OTHER) += capture.o\n',
                         "drivers/capture.c": '#define n __COUNTER__\n', "unit.c": a + b},
                        {"unit.c": b + a})
        self.assertEqual(len(self.run_stage(c, rename=True)), 1)
        self.assertEqual(self.run_stage(c, rename=True, config=KernelConfig('# CONFIG_OTHER is not set\n')), [])
        self.assertEqual(len(self.run_stage(c, rename=True, config=KernelConfig('CONFIG_OTHER=y\n'))), 1)

    def test_reorder_rejects_behavior_changes_and_file_moves(self) -> None:
        a = 'static int first(void) { return 1; }\n'
        b = 'static int second(void) { return 2; }\n'
        c = self.change({"unit.c": a + b}, {"unit.c": b + a.replace('return 1', 'return 3')})
        self.assertEqual(len(self.run_stage(c, rename=True)), 1)
        c = self.change({"unit.c": a + b, "other.c": ''}, {"unit.c": a, "other.c": b})
        self.assertEqual(len(self.run_stage(c, rename=True)), 1)

    def test_reorder_failure_does_not_publish_preview_masks(self) -> None:
        a = 'static int first(void) { return VALUE; }\n'
        b = 'static int second(void) { return VALUE + 1; }\n'
        inactive = '#if 0\nint dead = 1;\n#endif\n'
        c = self.change({"Makefile": 'obj-y += unit.o\n', "api.h": '#define VALUE __COUNTER__\n',
                         "unit.c": '#include "api.h"\n' + inactive + a + b},
                        {"unit.c": '#include "api.h"\n' + inactive + b + a})
        view = FilteredCommit(c)
        decisions: list[PruningDecision] = []
        self.assertEqual(len(RenameFilter(KernelConfig(''), decisions.append, lossy=True).filter_mutable_commits(
            [view], FilterContext(self.repo), False)), 1)
        self.assertEqual(view.code_masks, ())
        self.assertEqual(view.edit_masks, ())
        self.assertEqual(decisions, [])

    def test_rename_ignores_pruned_logic_and_unchanged_references_in_inactive_code(self) -> None:
        old = ("static int old_helper(void) { return 1; }\n"
               "#ifdef CONFIG_DISABLED\nstatic int unused(void) { return old_helper() + 10; }\n#endif\n"
               "int run(void) { return old_helper(); }\n")
        new = old.replace("static int old_helper", "static int new_helper").replace("return old_helper();", "return new_helper();").replace("+ 10", "+ 20")
        c = self.change({"unit.c": old}, {"unit.c": new})
        config = KernelConfig("# CONFIG_DISABLED is not set\n")
        pipeline = FilterPipeline([IfdefFilter(config), DeadCodeFilter(config), RenameFilter(config, lossy=True)])
        self.assertEqual(pipeline.filter_mutable_commits([self.complete_cpp_view(c)], FilterContext(self.repo), False), [])

    def test_whitespace_confirmation_uses_the_remaining_patch_source(self) -> None:
        old = "#if 0\nint inactive = 1;\n#endif\n/* before */\nint run(void) { return 1; }\n"
        new = old.replace("inactive = 1", "inactive = 2").replace("/* before */", "/* after */")
        c = self.change({"unit.c": old}, {"unit.c": new})
        config = KernelConfig("")
        output = FilterPipeline([IfdefFilter(config), WhitespaceFilter()]).filter_mutable_commits(
            [self.complete_cpp_view(c)], FilterContext(self.repo), False,
        )
        self.assertEqual(output, [])

    def test_dead_definition_mask_exposes_remaining_rename_in_the_same_file(self) -> None:
        old = ("static int old_helper(void) { return 1; }\n"
               "static int isolated_helper(void) { return 777; }\n"
               "int run(void) { return old_helper(); }\n")
        new = old.replace("old_helper", "new_helper").replace("777", "888")
        c = self.change({"unit.c": old}, {"unit.c": new})
        decisions: list[PruningDecision] = []
        self.assertEqual(len(self.run_stage(c, rename=True)), 1)
        pipeline = FilterPipeline([DeadCodeFilter(on_pruned=decisions.append), RenameFilter(on_pruned=decisions.append, lossy=True)])
        self.assertEqual(pipeline.filter_commits([c], FilterContext(self.repo), False), [])
        self.assertEqual([item.rule for item in decisions], ["unreferenced_definition", "consistent_rename"])
        self.assertEqual(decisions[0].symbols, ("isolated_helper",))
        with RepositoryFileReader(self.repo) as reader:
            verifier = Verifier(self.repo, reader, KernelConfig(""))
            for decision in decisions:
                verifier.verify(Decision.model_validate(asdict(decision)))

    def test_unused_definition_documentation_retains_moved_active_tokens(self) -> None:
        old = "int run(void) { return 0; }\n"
        new = "/** New unused helper. */\nstatic int isolated_helper(void) { return 1; }\n" + old
        c = self.change({"unit.c": old}, {"unit.c": new})
        output = FilterPipeline(list(source_pruning_tail())).filter_commits([c], FilterContext(self.repo), False)
        self.assertEqual(len(output), 1)
        self.assertIn("+/** New unused helper. */", output[0].diff_str)
        self.assertNotIn("isolated_helper(void)", output[0].diff_str)

    def test_unused_addition_cannot_hide_an_observable_line_macro(self) -> None:
        old = "int run(void) { return __LINE__; }\n"
        new = "static int isolated_helper(void) { return 1; }\n" + old
        c = self.change({"unit.c": old}, {"unit.c": new})
        output = FilterPipeline(list(source_pruning_tail())).filter_commits([c], FilterContext(self.repo), False)
        self.assertEqual(len(output), 1)

    def test_partial_dead_mask_does_not_hide_active_value_change(self) -> None:
        old = ("static int old_helper(int n) { return n; }\n"
               "static int isolated_helper(void) { return 777; }\n"
               "int run(void) { return old_helper(1); }\n")
        new = old.replace("old_helper", "new_helper").replace("777", "888").replace("new_helper(1)", "new_helper(2)")
        c = self.change({"unit.c": old}, {"unit.c": new})
        output = FilterPipeline([DeadCodeFilter(), RenameFilter(lossy=True)]).filter_commits([c], FilterContext(self.repo), False)
        self.assertEqual(len(output), 1)
        self.assertNotIn("888", output[0].diff_str)
        self.assertIn("return new_helper(2)", output[0].diff_str)

    def test_masked_unused_caller_does_not_block_cross_file_rename(self) -> None:
        old = {"api.h": "static inline int old_helper(void) { return 1; }\n",
               "live.c": '#include "api.h"\nint run(void) { return old_helper(); }\n',
               "unused.c": '#include "api.h"\nstatic int isolated_caller(void) { return old_helper() + 777; }\n'}
        new = {path: text.replace("old_helper", "new_helper").replace("777", "888") for path, text in old.items()}
        c = self.change(old, new)
        output = FilterPipeline([DeadCodeFilter(), RenameFilter(lossy=True)]).filter_commits([c], FilterContext(self.repo), False)
        self.assertEqual(output, [])

    def test_edit_mask_does_not_hide_a_new_live_foreign_reference(self) -> None:
        c = self.change({"api.h": "enum kind { OLD_KIND = 1 };\n", "caller.c": ""},
                        {"api.h": "enum kind { NEW_KIND = 1 };\n", "caller.c": "int value = NEW_KIND;\n"})
        view = FilteredCommit(c)
        caller = next(file for file in view.diff.files if file.file == "caller.c")
        view.mask_file(caller, MaskReason.FILE_SELECTION)
        output = RenameFilter(lossy=True).filter_mutable_commits([view], FilterContext(self.repo), False)
        self.assertEqual(output, [view])

    def test_edit_mask_restores_a_declaration_instead_of_deleting_it(self) -> None:
        old = "typedef int number;\nstatic number old_helper(void) { return 1; }\nint run(void) { return old_helper(); }\n"
        new = old.replace("typedef int number;", "typedef int  number;").replace("old_helper", "new_helper")
        c = self.change({"unit.c": old}, {"unit.c": new})
        view = FilteredCommit(c)
        file = view.diff.files[0]
        view.mask_edits(file, (LineRange(1, 2),), (LineRange(1, 2),), MaskReason.WHITESPACE)
        decisions: list[PruningDecision] = []
        self.assertEqual(RenameFilter(on_pruned=decisions.append, lossy=True).filter_mutable_commits([view], FilterContext(self.repo), False), [])
        with RepositoryFileReader(self.repo) as reader:
            Verifier(self.repo, reader, KernelConfig("")).verify(Decision.model_validate(asdict(decisions[0])))

    def test_failed_source_projection_does_not_publish_new_masks(self) -> None:
        old = "#if 0\nint inactive;\n#endif\nstatic int old_helper(void) { return 1; }\nint run(void) { return old_helper(); }\n"
        c = self.change({"unit.c": old}, {"unit.c": old.replace("old_helper", "new_helper")})
        assert c.parent is not None
        c.parents = (CommitParent(c.parent.commit_id, c.diff_str.replace("-static int old_helper", "-static int wrong_helper")),)
        view = FilteredCommit(c)
        output = RenameFilter(KernelConfig(""), lossy=True).filter_mutable_commits([view], FilterContext(self.repo), False)
        self.assertEqual(output, [view])
        self.assertEqual(view.code_masks, ())

    def test_dead_code_requires_an_exact_original_source_patch(self) -> None:
        old = "static int isolated_helper(void) { return 1; }\n"
        c = self.change({"unit.c": old}, {"unit.c": old.replace("return 1", "return 2")})
        assert c.parent is not None
        c.parents = (CommitParent(c.parent.commit_id, c.diff_str.replace("-static int isolated_helper(void) { return 1; }", "-static int isolated_helper(void) { return 9; }")),)
        view = FilteredCommit(c)
        self.assertEqual(DeadCodeFilter().filter_mutable_commits([view], FilterContext(self.repo), False), [view])
        self.assertEqual(view.code_masks, ())

    def test_dead_code_mask_cannot_erase_an_active_same_line_neighbor(self) -> None:
        old = "static int isolated_helper(void) { return 777; } int run(void) { return 1; }\n"
        c = self.change({"unit.c": old}, {"unit.c": old.replace("777", "888")})
        self.assertEqual(len(self.run_stage(c)), 1)

    def test_unused_function_cannot_hide_global_preprocessor_effects(self) -> None:
        old = "static int isolated_helper(void) {\n#define POLICY_VALUE 1\nreturn 0;\n}\nint run(void) { return POLICY_VALUE; }\n"
        c = self.change({"unit.c": old}, {"unit.c": old.replace("POLICY_VALUE 1", "POLICY_VALUE 2")})
        self.assertEqual(len(self.run_stage(c)), 1)

    def test_unused_structure_cannot_hide_pragma_effects(self) -> None:
        old = "struct isolated_type {\n#pragma pack(1)\nchar a;\n};\nstruct live_type { char a; int b; };\nint run(void) { return sizeof(struct live_type); }\n"
        c = self.change({"api.h": old}, {"api.h": old.replace("pack(1)", "pack(2)")})
        self.assertEqual(len(self.run_stage(c)), 1)

    def test_inactive_line_insertion_cannot_hide_observable_line_number_change(self) -> None:
        old = "#if 0\nint ignored;\n#endif\nstatic int old_helper(void) { return __LINE__; }\nint run(void) { return old_helper(); }\n"
        new = old.replace("int ignored;", "int ignored;\nint another;").replace("old_helper", "new_helper")
        c = self.change({"unit.c": old}, {"unit.c": new})
        config = KernelConfig("")
        output = FilterPipeline([IfdefFilter(config), RenameFilter(config, lossy=True)]).filter_commits([c], FilterContext(self.repo), False)
        self.assertEqual(len(output), 1)

    def test_whitespace_masking_cannot_hide_a_shifted_line_macro(self) -> None:
        old = "#if 0\nint ignored;\n#endif\nint run(void) { return __LINE__; }\n"
        new = old.replace("int ignored;", "int ignored;\nint another;")
        c = self.change({"unit.c": old}, {"unit.c": new})
        output = FilterPipeline([IfdefFilter(KernelConfig("")), WhitespaceFilter()]).filter_commits([c], FilterContext(self.repo), False)
        self.assertEqual(len(output), 1)

    def test_parameter_rename(self) -> None:
        a = "int run(int old_arg) { return old_arg + 1; }\n"
        commit = self.change({"unit.c": a}, {"unit.c": a.replace("old_arg", "new_arg")})
        self.assertEqual(self.run_stage(commit, rename=True), [])

    def test_external_function_rename_cannot_hide_macro_generated_callers(self) -> None:
        old = 'int primary(void) { return 1; }\n'
        fallback = '#define CAT(a,b,c) a ## b ## c\n__attribute__((weak)) int CAT(pri,ma,ry)(void) { return 2; }\n'
        caller = ('#define CAT(a,b,c) a ## b ## c\nint CAT(pri,ma,ry)(void);\n'
                  'int main(void) { return CAT(pri,ma,ry)(); }\n')
        commit = self.change({'unit.c': old, 'fallback.c': fallback, 'caller.c': caller},
                             {'unit.c': old.replace('primary', 'renamed')})
        self.assertEqual(len(self.run_stage(commit, rename=True)), 1)
        self.assertEqual(self.decisions, [])

    def hidden_splice_rename(self, prefix: str, splice: str) -> GitCommit:
        old = prefix + 'static inline int old_helper(void) { return 1; }\n'
        hidden_name = splice.join(('old', '_hel', 'per'))
        consumer = ('#include "api.h"\nextern int ' + hidden_name + '(void);\n'
                    'int main(void) { return ' + hidden_name + '(); }\n')
        fallback = ('int fallback_binding(void) __asm__("old" "_he" "lper");\n'
                    'int fallback_binding(void) { return 2; }\n')
        external = (consumer + fallback).encode()
        names = frozenset({'old_helper', 'new_helper'})
        guards = frozenset(guard for name in names for guard in spelling_guards(name))
        self.assertFalse(any(re.search(rb'\b' + re.escape(guard.encode()) + rb'\b', external)
                             for guard in guards))
        return self.change({'api.h': old, 'consumer.c': consumer, 'fallback.c': fallback},
                           {'api.h': old.replace('old_helper', 'new_helper')})

    def test_lossy_inline_rename_retains_phase_two_hidden_callers(self) -> None:
        for splice in ('\\\n', '\\\r\n'):
            with self.subTest(splice=repr(splice)):
                commit = self.hidden_splice_rename('', splice)
                self.assertEqual(len(self.run_stage(commit, rename=True)), 1)
                self.assertEqual(self.decisions, [])

    def test_lossy_inline_rename_retains_early_unresolved_include_before_hidden_caller(self) -> None:
        commit = self.hidden_splice_rename('#include "unresolved.h"\n', '\\\n')
        self.assertEqual(len(self.run_stage(commit, rename=True)), 1)
        self.assertEqual(self.decisions, [])

    def test_external_object_rename_cannot_hide_macro_generated_callers(self) -> None:
        old = 'int primary = 1;\n'
        fallback = '#define CAT(a,b,c) a ## b ## c\n__attribute__((weak)) int CAT(pri,ma,ry) = 2;\n'
        caller = ('#define CAT(a,b,c) a ## b ## c\nextern int CAT(pri,ma,ry);\n'
                  'int main(void) { return CAT(pri,ma,ry); }\n')
        commit = self.change({'unit.c': old, 'fallback.c': fallback, 'caller.c': caller},
                             {'unit.c': old.replace('primary', 'renamed')})
        self.assertEqual(len(self.run_stage(commit, rename=True)), 1)
        self.assertEqual(self.decisions, [])

    def test_parenthesized_external_declarators_are_not_anchored_by_local_bindings(self) -> None:
        for declaration in ('int (primary) = 1;\n', 'int (*primary)(void);\n', 'int (*primary[2])(void);\n'):
            with self.subTest(declaration=declaration):
                old = declaration + ('static int helper(int primary) { return primary; }\n'
                                     'int observe(void) { return helper(7); }\n')
                commit = self.change({'unit.c': old}, {'unit.c': old.replace('primary', 'renamed')})
                self.assertEqual(len(self.run_stage(commit, rename=True)), 1)
                self.assertEqual(self.decisions, [])

    def test_block_extern_rename_requires_linkage_proof(self) -> None:
        old = 'int run(void) { extern int primary; return primary; }\n'
        commit = self.change({'unit.c': old}, {'unit.c': old.replace('primary', 'renamed')})
        self.assertEqual(len(self.run_stage(commit, rename=True)), 1)

    def test_private_static_object_rename_remains_eligible(self) -> None:
        old = 'static int primary = 1;\nint run(void) { return primary; }\n'
        commit = self.change({'unit.c': old}, {'unit.c': old.replace('primary', 'renamed')})
        self.assertEqual(self.run_stage(commit, rename=True), [])

    def test_keyword_macro_can_change_static_linkage(self) -> None:
        old = '#define static\nstatic int primary(void) { return 1; }\n'
        commit = self.change({'unit.c': old}, {'unit.c': old.replace('primary', 'renamed')})
        self.assertEqual(len(self.run_stage(commit, rename=True)), 1)

    def test_declaration_macro_can_emit_an_external_symbol(self) -> None:
        old = '#include "types.h"\nstatic RETURN_TYPE primary(void) { return 1; }\n'
        commit = self.change({'unit.c': old, 'types.h': '#define RETURN_TYPE int unused_data; int\n'},
                             {'unit.c': old.replace('primary', 'renamed')})
        self.assertEqual(len(self.run_stage(commit, rename=True)), 1)

    def test_included_macro_can_observe_a_renamed_function_name(self) -> None:
        old = ('#include "names.h"\nstatic int alpha(void) { return READ_NAME(); }\n'
               'int main(void) { return alpha(); }\n')
        commit = self.change({'unit.c': old, 'names.h': '#define READ_NAME() __func__[0]\n'},
                             {'unit.c': old.replace('alpha', 'beta')})
        self.assertEqual(len(self.run_stage(commit, rename=True)), 1)

    def test_macro_body_can_emit_code_outside_an_apparently_unused_function(self) -> None:
        old = '#include "bridge.h"\nstatic int isolated_helper(void) { BRIDGE(); return 1; }\n'
        commit = self.change({'unit.c': old, 'bridge.h': '#define BRIDGE() return 0; } int primary(void) {\n'},
                             {'unit.c': old.replace('return 1', 'return 2')})
        self.assertEqual(len(self.run_stage(commit)), 1)

    def test_unrelated_macro_does_not_block_a_private_rename(self) -> None:
        old = ('#include "values.h"\nstatic int alpha(void) { return 1; }\n'
               'int main(void) { return alpha(); }\n')
        commit = self.change({'unit.c': old, 'values.h': '#define UNRELATED_VALUE 4\n'},
                             {'unit.c': old.replace('alpha', 'beta')})
        self.assertEqual(self.run_stage(commit, rename=True), [])

    def test_type_and_field_renames(self) -> None:
        for a, old, new in (
            ("typedef int old_type;\nold_type run(void) { return 1; }\n", "old_type", "new_type"),
            ("struct old_type { int value; };\nstruct old_type instance;\n", "old_type", "new_type"),
            ("struct data { int old_field; };\nint run(struct data *p) { return p->old_field; }\n", "old_field", "new_field"),
        ):
            with self.subTest(source=a):
                c = self.change({"unit.c": a}, {"unit.c": a.replace(old, new)})
                self.assertEqual(self.run_stage(c, rename=True), [])

    def test_rename_does_not_hide_type_or_layout_change(self) -> None:
        c = self.change({"unit.c": "typedef int old_type;\n"}, {"unit.c": "typedef long new_type;\n"})
        self.assertEqual(len(self.run_stage(c, rename=True)), 1)

    def test_macro_error_before_function_requires_expansion_proof(self) -> None:
        a = "#define DECLARE_DATA(x) int x;\nDECLARE_DATA(counter)\nstatic int old_helper(void) { return 1; }\nint run(void) { return old_helper(); }\n"
        c = self.change({"unit.c": a}, {"unit.c": a.replace("old_helper", "new_helper")})
        self.assertEqual(len(self.run_stage(c, rename=True)), 1)

    def test_keyword_macros_can_change_standalone_tag_linkage(self) -> None:
        for keyword in ("struct", "union", "enum"):
            with self.subTest(keyword=keyword):
                old = f'#include "keywords.h"\n{keyword} primary;\n'
                commit = self.change({'unit.c': old, 'keywords.h': f'#define {keyword} int\n'},
                                     {'unit.c': old.replace('primary', 'renamed')})
                self.assertEqual(len(self.run_stage(commit, rename=True)), 1)

    def test_foreign_macro_can_export_or_stringify_renamed_symbol(self) -> None:
        a = '#include "api.h"\nstatic int old_helper(void) { return 1; }\nREGISTER(old_helper);\n'
        c = self.change({"unit.c": a, "api.h": "#define REGISTER(x) EXPORT_SYMBOL(x)\n"},
                        {"unit.c": a.replace("old_helper", "new_helper")})
        self.assertEqual(len(self.run_stage(c, rename=True)), 1)

    def test_implicit_name_in_other_function_does_not_block_rename(self) -> None:
        a = 'static int old_helper(void) { return 1; }\nint run(void) { puts(__func__); return old_helper(); }\n'
        c = self.change({"unit.c": a}, {"unit.c": a.replace("old_helper", "new_helper")})
        self.assertEqual(self.run_stage(c, rename=True), [])

    def test_call_target_change_is_not_rename(self) -> None:
        commit = self.change({"unit.c": "int run(void) { return old_target(); }\n"},
                             {"unit.c": "int run(void) { return new_target(); }\n"})
        self.assertEqual(len(self.run_stage(commit, rename=True)), 1)

    def test_rename_plus_behavior_change_is_retained(self) -> None:
        a = "static int old_helper(void) { return 1; }\n"
        b = "static int new_helper(void) { return 2; }\n"
        self.assertEqual(len(self.run_stage(self.change({"unit.c": a}, {"unit.c": b}), rename=True)), 1)

    def test_primitive_type_change_is_not_rename(self) -> None:
        c = self.change({"unit.c": "int run(int n) { return n; }\n"},
                        {"unit.c": "long run(long n) { return n; }\n"})
        self.assertEqual(len(self.run_stage(c, rename=True)), 1)

    def test_renamed_export_is_retained(self) -> None:
        a = "int old_helper(void) { return 1; }\nEXPORT_SYMBOL(old_helper);\n"
        c = self.change({"unit.c": a}, {"unit.c": a.replace("old_helper", "new_helper")})
        self.assertEqual(len(self.run_stage(c, rename=True)), 1)

    def test_implicit_function_name_is_retained(self) -> None:
        a = 'static int old_helper(void) { puts(__func__); return 1; }\n'
        c = self.change({"unit.c": a}, {"unit.c": a.replace("old_helper", "new_helper")})
        self.assertEqual(len(self.run_stage(c, rename=True)), 1)

    def test_literal_change_is_retained(self) -> None:
        a = 'static int old_helper(void) { puts("old_helper"); return 1; }\n'
        c = self.change({"unit.c": a}, {"unit.c": a.replace("old_helper", "new_helper")})
        self.assertEqual(len(self.run_stage(c, rename=True)), 1)

    def test_diagnostic_wording_only_is_pruned_and_audited(self) -> None:
        old = 'void run(void) { pr_err("allocation failed: %d\\n", err); }\n'
        c = self.change({"unit.c": old}, {"unit.c": old.replace("allocation failed", "allocation failure")})
        self.assertEqual(self.run_stage(c, rename=True), [])
        self.assertEqual(self.decisions[0].rule, "diagnostic_wording")
        self.assertEqual(self.decisions[0].symbols, ())
        with RepositoryFileReader(self.repo) as reader:
            Verifier(self.repo, reader, KernelConfig("")).verify(Decision.model_validate(asdict(self.decisions[0])))

    def test_rename_and_diagnostic_name_update_are_pruned(self) -> None:
        old = ('static int old_helper(void) { pr_info("old_helper: done\\n"); return 1; }\n'
               'int run(void) { return old_helper(); }\n')
        c = self.change({"unit.c": old}, {"unit.c": old.replace("old_helper", "new_helper")})
        self.assertEqual(self.run_stage(c, rename=True), [])
        self.assertEqual(self.decisions[0].rule, "consistent_rename_and_diagnostics")
        with RepositoryFileReader(self.repo) as reader:
            Verifier(self.repo, reader, KernelConfig("")).verify(Decision.model_validate(asdict(self.decisions[0])))

    def test_diagnostic_change_cannot_hide_behavior_or_foreign_reference(self) -> None:
        old = 'static int old_helper(void) { pr_err("old\\n"); return 1; }\nint run(void) { return old_helper(); }\n'
        for new in (old.replace('"old', '"new').replace('return 1', 'return 2'),
                    old.replace('old_helper', 'new_helper').replace('"old', '"new')):
            with self.subTest(new=new):
                c = self.change({"unit.c": old, "outside.c": 'int other(void) { return old_helper(); }\n'}, {"unit.c": new})
                self.assertEqual(len(self.run_stage(c, rename=True)), 1)
                self.assertEqual(self.decisions, [])

    def test_diagnostics_respect_masks_and_keep_other_files(self) -> None:
        old = '#if 0\nint inactive = 1;\n#endif\nvoid run(void) { pr_err("old\\n"); }\n'
        new = old.replace('inactive = 1', 'inactive = 2').replace('"old', '"new')
        c = self.change({"unit.c": old}, {"unit.c": new})
        stages = [IfdefFilter(KernelConfig("")), RenameFilter(lossy=True)]
        self.assertEqual(FilterPipeline(stages).filter_mutable_commits([self.complete_cpp_view(c)], FilterContext(self.repo), False), [])
        c = self.change({"unit.c": old, "other.c": 'int n = 1;\n'}, {"unit.c": new, "other.c": 'int n = 2;\n'})
        self.assertEqual(len(self.run_stage(c, rename=True)), 1)

    def test_logging_control_and_line_counter_changes_are_retained(self) -> None:
        for old, new in [
            ('void run(void) { pr_err("%p", ptr); }\n', 'void run(void) { pr_err("%px", ptr); }\n'),
            ('void run(void) { pr_err("old"); }\n', 'void run(void) { pr_err("new\\n"); }\n'),
            ('void run(void) { pr_err("old"); }\nint line = __LINE__;\n', 'void run(void) {\n pr_err("new"); }\nint line = __LINE__;\n'),
            ('void run(void) { pr_err("old"); }\nint n = __COUNTER__;\n', 'void run(void) { pr_err("new"); }\nint n = __COUNTER__;\n'),
        ]:
            with self.subTest(old=old):
                self.assertEqual(len(self.run_stage(self.change({"unit.c": old}, {"unit.c": new}), rename=True)), 1)

    def test_inconsistent_or_colliding_rename_is_retained(self) -> None:
        a = "static int old_helper(void) { return 1; }\nint run(void) { return old_helper(); }\n"
        b = a.replace("int old_helper", "int new_helper")
        self.assertEqual(len(self.run_stage(self.change({"unit.c": a}, {"unit.c": b}), rename=True)), 1)

    def test_cross_file_enum_rename(self) -> None:
        a = {"api.h": "enum kind { OLD_KIND = 1 };\n", "unit.c": '#include "api.h"\nint run(void) { return OLD_KIND; }\n'}
        b = {path: source.replace("OLD_KIND", "NEW_KIND") for path, source in a.items()}
        self.assertEqual(self.run_stage(self.change(a, b), rename=True), [])

    def test_reference_outside_patch_prevents_rename(self) -> None:
        a = {"api.h": "enum kind { OLD_KIND = 1 };\n", "unit.c": "int run(void) { return OLD_KIND; }\n"}
        c = self.change(a, {"api.h": "enum kind { NEW_KIND = 1 };\n"})
        self.assertEqual(len(self.run_stage(c, rename=True)), 1)

    def test_local_shadow_cannot_hide_external_reference(self) -> None:
        old = "static int old_helper(void) { return 1; }\nint other(void) { int old_helper = 2; return old_helper; }\n"
        c = self.change({"api.h": old, "caller.c": '#include "api.h"\nint run(void) { return old_helper(); }\n'},
                        {"api.h": old.replace("old_helper", "new_helper")})
        self.assertEqual(len(self.run_stage(c, rename=True)), 1)

    def test_local_shadow_in_another_changed_file_cannot_hide_reference(self) -> None:
        a = {"api.h": "static int old_helper(void) { return 1; }\n",
             "other.c": "int other(void) { int old_helper = 2; return old_helper; }\n",
             "caller.c": '#include "api.h"\nint run(void) { return old_helper(); }\n'}
        b = {path: source.replace("old_helper", "new_helper") for path, source in a.items() if path != "caller.c"}
        self.assertEqual(len(self.run_stage(self.change(a, b), rename=True)), 1)

    def test_unused_static_function(self) -> None:
        a = "static int isolated_helper(void) { return 1; }\nint run(void) { return 0; }\n"
        c = self.change({"unit.c": a}, {"unit.c": a.replace("return 1", "return 2")})
        self.assertEqual(self.run_stage(c), [])

    def test_unused_header_inline_and_documentation(self) -> None:
        a = "/* isolated_helper returns a number. */\nstatic inline int isolated_helper(void) { return 1; }\n"
        c = self.change({"api.h": a, "unit.c": '#include "api.h"\n'}, {"api.h": a.replace("return 1", "return 2")})
        self.assertEqual(self.run_stage(c), [])

    def test_unused_macro_and_type(self) -> None:
        for path, a, b in (
            ("macro.h", "#define ISOLATED_LIMIT 1\n", "#define ISOLATED_LIMIT 2\n"),
            ("type.h", "struct isolated_type { int value; };\n", "struct isolated_type { long value; };\n"),
        ):
            with self.subTest(path=path):
                c = self.change({path: a}, {path: b})
                self.assertEqual(self.run_stage(c), [])

    def test_live_call_and_address_taken_are_retained(self) -> None:
        for reference in ("int run(void) { return isolated_helper(); }", "int (*callback)(void) = isolated_helper;"):
            with self.subTest(reference=reference):
                a = "static int isolated_helper(void) { return 1; }\n" + reference + "\n"
                c = self.change({"unit.c": a}, {"unit.c": a.replace("return 1", "return 2")})
                self.assertEqual(len(self.run_stage(c)), 1)

    def test_header_macro_can_reference_source_local_function(self) -> None:
        a = '#include "api.h"\nstatic int isolated_helper(void) { return 1; }\nint run(void) { return CALL_HELPER(); }\n'
        c = self.change({"unit.c": a, "api.h": "#define CALL_HELPER() isolated_helper()\n"},
                        {"unit.c": a.replace("return 1", "return 2")})
        self.assertEqual(len(self.run_stage(c)), 1)

    def test_live_header_consumer_is_found_without_a_repository_scan(self) -> None:
        old = "static inline int isolated_helper(void) { return 1; }\n"
        c = self.change({"api.h": old, "wrapper.h": '#include "api.h"\nstatic inline int wrapper(void) { return isolated_helper(); }\n',
                         "unit.c": '#include "wrapper.h"\nint run(void) { return wrapper(); }\n'},
                        {"api.h": old.replace("return 1", "return 2")})
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            index.bind_includes(SourceIncludeIndex.from_repository(self.repo, c.commit_id, "x86"), c.commit_id)
            context = FilterContext(self.repo, file_reader=reader, reference_index=index)
            self.assertEqual(len(DeadCodeFilter().filter_commits([c], context, False)), 1)
            self.assertEqual(index.stats().repository_scans, 0)

    def test_disabled_consumer_is_excluded_by_configured_build(self) -> None:
        a = "static inline int isolated_helper(void) { return 1; }\n"
        c = self.change({
            "drivers/Makefile": "obj-y += enabled.o\nobj-$(CONFIG_FEATURE) += disabled.o\n",
            "drivers/api.h": a,
            "drivers/enabled.c": '#include "api.h"\n',
            "drivers/disabled.c": '#include "api.h"\nint run(void) { return isolated_helper(); }\n',
        }, {"drivers/api.h": a.replace("return 1", "return 2")})
        self.assertEqual(self.run_stage(c, config=KernelConfig("# CONFIG_FEATURE is not set\n")), [])
        self.assertEqual(len(self.run_stage(c, config=KernelConfig("CONFIG_FEATURE=y\n"))), 1)

    def test_layout_use_prevents_struct_pruning(self) -> None:
        a = "struct isolated_type { int value; };\n"
        c = self.change({"api.h": a, "unit.c": 'int run(void) { return sizeof(struct isolated_type); }\n'},
                        {"api.h": a.replace("int", "long")})
        self.assertEqual(len(self.run_stage(c)), 1)

    def test_nested_tags_and_enumerators_can_escape_outer_structure(self) -> None:
        for nested in ("enum { LIVE_VALUE = 1 } member;", "struct live_type { int value; } member;"):
            with self.subTest(nested=nested):
                a = "struct isolated_type { " + nested + " };\n"
                c = self.change({"api.h": a}, {"api.h": a.replace("1", "2").replace("int value", "long value")})
                self.assertEqual(len(self.run_stage(c)), 1)

    def test_init_registration_and_pasting_are_retained(self) -> None:
        for a in (
            "static int __init isolated_helper(void) { return 1; }\n",
            "static int isolated_helper(void) { return 1; }\n#define JOIN(a,b) a##b\n",
        ):
            with self.subTest(source=a):
                c = self.change({"unit.c": a}, {"unit.c": a.replace("return 1", "return 2")})
                self.assertEqual(len(self.run_stage(c)), 1)

    def test_only_unused_files_removed_from_mixed_commit(self) -> None:
        a = "static inline int isolated_helper(void) { return 1; }\n"
        c = self.change({"api.h": a, "unit.c": "int run(void) { return 1; }\n"},
                        {"api.h": a.replace("return 1", "return 2"), "unit.c": "int run(void) { return 2; }\n"})
        output = self.run_stage(c)
        self.assertEqual(len(output), 1)
        self.assertNotIn("api.h", output[0].diff_str)
        self.assertIn("unit.c", output[0].diff_str)

    def test_use_added_in_same_commit_is_retained(self) -> None:
        a = "static inline int isolated_helper(void) { return 1; }\n"
        c = self.change({"api.h": a, "unit.c": "int run(void) { return 0; }\n"},
                        {"api.h": a.replace("return 1", "return 2"), "unit.c": "int run(void) { return isolated_helper(); }\n"})
        self.assertIn("api.h", self.run_stage(c)[0].diff_str)

    def test_parent_use_removed_in_same_commit_is_retained(self) -> None:
        a = "static inline int isolated_helper(void) { return 1; }\n"
        c = self.change({"api.h": a, "unit.c": "int run(void) { return isolated_helper(); }\n"},
                        {"api.h": a.replace("return 1", "return 2"), "unit.c": "int run(void) { return 0; }\n"})
        self.assertIn("api.h", self.run_stage(c)[0].diff_str)

    def test_inactive_caller_requires_closed_preprocessor_context(self) -> None:
        a = "static int isolated_helper(void) { return 1; }\n#ifdef CONFIG_FEATURE\nint run(void) { return isolated_helper(); }\n#endif\n"
        c = self.change({"drivers/Makefile": "obj-y += unit.o\n", "drivers/unit.c": a},
                        {"drivers/unit.c": a.replace("return 1", "return 2")})
        self.assertEqual(len(self.run_stage(c, config=KernelConfig("# CONFIG_FEATURE is not set\n"))), 1)
        self.assertEqual(len(self.run_stage(c, config=KernelConfig("CONFIG_FEATURE=y\n"))), 1)

    def test_rename_projection_requires_explicit_complete_build_modes(self) -> None:
        old = ('#if CONFIG_FEATURE\nint feature_value = 1;\n#endif\n'
               'static int alpha(void) { return 10; }\nint run(void) { return alpha(); }\n')
        commit = self.change({'unit.c': old}, {'unit.c': old.replace('= 1;', '= 2;').replace('alpha', 'beta')})
        for complete in (False, True):
            with self.subTest(complete=complete):
                view = FilteredCommit(commit, build_modes={(None, 'unit.c'): FileBuildModes('y', 'y', complete=complete)})
                config = KernelConfig('')
                output = FilterPipeline([IfdefFilter(config), RenameFilter(config, lossy=True)]).filter_mutable_commits(
                    [view], FilterContext(self.repo), False,
                )
                self.assertEqual(len(output), 0 if complete else 1)
        self.assertEqual(len(self.run_stage(commit, rename=True, config=KernelConfig(''))), 1)

    def test_local_config_override_prevents_rename_projection(self) -> None:
        old = ('#define CONFIG_FEATURE 1\n#if CONFIG_FEATURE\nint feature_value = 1;\n#endif\n'
               'static int alpha(void) { return 10; }\nint run(void) { return alpha(); }\n')
        commit = self.change({'unit.c': old}, {'unit.c': old.replace('feature_value = 1', 'feature_value = 2').replace('alpha', 'beta')})
        view = FilteredCommit(commit, build_modes={(None, 'unit.c'): FileBuildModes('y', 'y', complete=True)})
        output = RenameFilter(KernelConfig(''), lossy=True).filter_mutable_commits([view], FilterContext(self.repo), False)
        self.assertEqual(output, [view])
        self.assertEqual(view.code_masks, ())

    def test_foreign_reference_after_bare_carriage_return(self) -> None:
        a = "static inline int isolated_helper(void) { return 1; }\n"
        c = self.change({"api.h": a, "unit.c": "int x;\rint run(void) { return isolated_helper(); }\n"},
                        {"api.h": a.replace("return 1", "return 2")})
        self.assertEqual(len(self.run_stage(c)), 1)

    def test_live_probe_does_not_cache_incomplete_absence(self) -> None:
        revision = self.commit({"one.c": "int a = ISOLATED_LIMIT;\n", "two.c": "int b = ISOLATED_LIMIT;\n"})
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            names = frozenset({"ISOLATED_LIMIT"})
            self.assertIsNone(index.lookup(revision, names, is_live=lambda name, site: True)["ISOLATED_LIMIT"])
            sites = index.lookup(revision, names)["ISOLATED_LIMIT"]
            self.assertEqual({site.path for site in sites or ()}, {"one.c", "two.c"})
            self.assertEqual(index.stats().repository_scans, 2)

    def test_unrelated_prefetch_symbol_cannot_abort_the_requested_search(self) -> None:
        old = "static inline int existing_helper(void) { return 1; }\n"
        c = self.change({"api.h": old}, {"api.h": old.replace("existing_helper", "different_helper")})
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            index.plan_diffs([Diff.parse(c.diff_str)])
            calls: list[str] = []
            def live(name: str, site: ReferenceSite) -> bool:
                calls.append(name)
                return True
            result = index.lookup(c.commit_id, frozenset({"absent_helper"}), is_live=live)
            self.assertEqual(result["absent_helper"], ())
            self.assertEqual(calls, [])

    def test_shared_include_scan_seeds_exact_revision_reference_facts(self) -> None:
        old = "static inline int old_helper(void) { return 1; }\n"
        c = self.change({"api.h": old, "unit.c": '\n  #include "api.h"\nint run(void) { return old_helper(); }\n'},
                        {"api.h": old.replace("old_helper", "new_helper"), "unit.c": '\n  #include "api.h"\nint run(void) { return new_helper(); }\n'})
        ordinary = SourceIncludeIndex.from_repository(self.repo, c.commit_id, "x86")
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            index.observe_patch(c.diff_str)
            names = index.begin_bootstrap(c.commit_id)
            shared = SourceIncludeIndex.from_repository(self.repo, c.commit_id, "x86", reference_names=names, reference_hit=index.bootstrap_hit, prefer_pcre=True)
            index.finish_bootstrap()
            self.assertEqual(ordinary._snapshot(), shared._snapshot())
            self.assertEqual(len(index.lookup(c.commit_id, frozenset({"new_helper"}))["new_helper"] or ()), 2)
            self.assertEqual(index.stats().repository_scans, 0)
            assert c.parent is not None
            parent_sites = index.lookup(c.parent.commit_id, frozenset({"old_helper"}))["old_helper"]
            self.assertEqual({site.path for site in parent_sites or ()}, {"api.h", "unit.c"})

    def test_reference_index_updates_and_keeps_branches_separate(self) -> None:
        parent = self.commit({"api.h": "#define ISOLATED_LIMIT 1\n", "unit.c": "int x = ISOLATED_LIMIT;\n"})
        child = self.commit({"unit.c": "int x = 0;\n"})
        with RepositoryFileReader(self.repo) as reader:
            index = ReferenceIndex(self.repo, reader.read_file)
            names = frozenset({"ISOLATED_LIMIT"})
            a = index.lookup(parent, names)["ISOLATED_LIMIT"]
            b = index.lookup(child, names, parent=parent, changed_paths=frozenset({"unit.c"}))["ISOLATED_LIMIT"]
            self.assertEqual(len(a or ()), 2)
            self.assertEqual(len(b or ()), 1)
            self.assertEqual(index.lookup(parent, names)["ISOLATED_LIMIT"], a)
            self.assertEqual(index.stats().repository_scans, 1)
            self.assertEqual(index.stats().incremental_updates, 1)
            index.close()

    def test_persistent_reference_facts_avoid_second_scan(self) -> None:
        revision = self.commit({"unit.c": "int x = ISOLATED_LIMIT;\n"})
        names = frozenset({"ISOLATED_LIMIT"})
        with RepositoryFileReader(self.repo) as reader:
            with ReferenceIndex(self.repo, reader.read_file) as first:
                expected = first.lookup(revision, names)
                self.assertEqual(first.stats().repository_scans, 1)
            with ReferenceIndex(self.repo, reader.read_file) as second:
                self.assertEqual(second.lookup(revision, names), expected)
                self.assertEqual(second.stats().repository_scans, 0)

    def test_over_budget_query_retains_unknown_without_caching_absence(self) -> None:
        revision = self.commit({"unit.c": "int x = isolated_helper;\n"})
        names = frozenset({"isolated_helper"} | {f"other_{i}" for i in range(256)})
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            self.assertTrue(all(sites is None for sites in index.lookup(revision, names).values()))
            self.assertEqual(index.stats().repository_scans, 0)
            self.assertEqual(len(index.lookup(revision, frozenset({"isolated_helper"}))["isolated_helper"] or ()), 1)

    def test_shared_scan_seeds_new_header_helpers_and_paste_guards(self) -> None:
        c = self.change({"include/linux/api.h": "", "unit.c": '#include "include/linux/api.h"\n'},
                        {"include/linux/api.h": "static inline int isolated_helper(void) { return 1; }\n"})
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            index.observe_patch(c.diff_str)
            names = index.begin_bootstrap(c.commit_id)
            self.assertTrue(spelling_guards("isolated_helper") <= names)
            SourceIncludeIndex.from_repository(self.repo, c.commit_id, "x86", reference_names=names, reference_hit=index.bootstrap_hit, prefer_pcre=True)
            index.finish_bootstrap()
            facts = index.lookup(c.commit_id, names)
            self.assertEqual(len(facts["isolated_helper"] or ()), 1)
            self.assertEqual(index.stats().repository_scans, 0)

    def test_identifier_prefix_cannot_hide_longer_whole_word(self) -> None:
        revision = self.commit({"unit.c": "int value = isolated_helper;\n"})
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            sites = index.lookup(revision, frozenset({"isolated", "isolated_helper"}))
            self.assertEqual(sites["isolated"], ())
            self.assertEqual(len(sites["isolated_helper"] or ()), 1)

    def test_scope_recovers_includes_removed_after_parent_revision(self) -> None:
        old = self.commit({"api.h": "#define ISOLATED_LIMIT 1\n", "unit.c": '#include "api.h"\nint x = ISOLATED_LIMIT;\n'})
        new = self.commit({"unit.c": "int x = 0;\n"})
        includes = SourceIncludeIndex.from_repository(self.repo, new, "x86")
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            index.bind_includes(includes, new)
            scope = index.scope_for(("api.h",), old)
            self.assertIsNotNone(scope)
            self.assertIn("unit.c", scope or ())
            sites = index.lookup(old, frozenset({"ISOLATED_LIMIT"}), scope=scope)["ISOLATED_LIMIT"]
            self.assertIn("unit.c", [site.path for site in sites or ()])

    def test_empty_include_scope_cannot_establish_reference_absence(self) -> None:
        revision = self.commit({"unit.c": "int x = ISOLATED_LIMIT;\n"})
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            sites = index.lookup(revision, frozenset({"ISOLATED_LIMIT"}), scope=frozenset())
            self.assertEqual({site.path for site in sites["ISOLATED_LIMIT"] or ()}, {"unit.c"})
            self.assertEqual(index.stats().repository_scans, 1)

    def test_pcre_search_falls_back_when_unavailable(self) -> None:
        found = GitGrepRow(b'HEAD:unit.c', 1, b'found')
        def output(repo: GitRepo, arguments: list[str]) -> Iterator[GitGrepRow]:
            if "-P" in arguments:
                raise subprocess.CalledProcessError(128, arguments)
            self.assertIn("-E", arguments)
            yield found

        with patch("kpatch.filter.source_filter.iter_git_grep_rows", side_effect=output):
            self.assertEqual(list(_iter_git_grep(self.repo, ["grep", "-P", "-e", "name"])), [found])

    def test_scoped_negative_cache_cannot_hide_reference_in_wider_scope(self) -> None:
        revision = self.commit({"one.c": "int a;\n", "two.c": "int b = ISOLATED_LIMIT;\n"})
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            names = frozenset({"ISOLATED_LIMIT"})
            scoped = index.lookup(revision, names, scope=frozenset({"one.c"}))["ISOLATED_LIMIT"]
            self.assertEqual({site.path for site in scoped or ()}, {"two.c"})
            self.assertEqual(len(index.lookup(revision, names)["ISOLATED_LIMIT"] or ()), 1)


    def test_foreign_macro_cannot_capture_a_renamed_parameter(self) -> None:
        old = '#include "aliases.h"\nint GLOBAL_VALUE = 10;\nint run(int n) { return n + GET_GLOBAL(); }\n'
        aliases = "#define value GLOBAL_VALUE\n#define GET_GLOBAL() GLOBAL_VALUE\n"
        c = self.change({"unit.c": old, "aliases.h": aliases},
                        {"unit.c": old.replace("int n", "int value").replace("return n", "return value")})
        self.assertEqual(len(self.run_stage(c, rename=True)), 1)

    def test_reduced_input_cannot_hide_new_references_in_build_fragments(self) -> None:
        c = self.change({"api.h": "enum kind { OLD_KIND = 1 };\n", "extra.mk": ""},
                        {"api.h": "enum kind { NEW_KIND = 1 };\n", "extra.mk": "REFERENCE = NEW_KIND\n"})
        assert c.parent is not None
        reduced = Diff.parse(c.diff_str)
        reduced.files = [file for file in reduced.files if file.file == "api.h"]
        c.parents = (CommitParent(c.parent.commit_id, reduced.render()),)
        self.assertEqual(len(self.run_stage(c, rename=True)), 1)

    def test_linker_preprocessor_references_are_not_disabled_translation_units(self) -> None:
        c = self.change({"api.h": "#define ISOLATED_LIMIT 1\n", "vmlinux.lds.S": "SECTIONS { . = ISOLATED_LIMIT; }\n"},
                        {"api.h": "#define ISOLATED_LIMIT 2\n"})
        self.assertEqual(len(self.run_stage(c, config=KernelConfig(""))), 1)

    def test_config_observations_preserve_unchanged_build_references(self) -> None:
        from unittest.mock import Mock
        from kpatch.filter import ConfigFilter, ConfigValue, SourceSide
        from kpatch.filter.config.history import ConfigHistoryStore, FileDecision
        c = self.change({"unit.c": "int value = 1;\n", "extra.mk": "REFERENCE = OLD_KIND\n"},
                        {"unit.c": "int value = 2;\n", "extra.mk": "REFERENCE = NEW_KIND\n"})
        assert c.parent is not None
        copied = "diff --git a/foo.c b/bar.c\nsimilarity index 100%\ncopy from foo.c\ncopy to bar.c\n"
        c.parents = (CommitParent(c.parent.commit_id, c.diff_str + copied),)
        view = FilteredCommit(c)
        stage = ConfigFilter(KernelConfig(""), collect_observations=True)
        store = Mock(spec=ConfigHistoryStore)
        store.get_decisions.return_value = {(None, "unit.c"): FileDecision(ConfigValue.ENABLED, ConfigValue.ENABLED)}
        stage._store = store
        with patch.object(stage, "_prepare"):
            self.assertIs(stage.filter_mutable_commit(view, FilterContext(self.repo)), view)
        self.assertEqual([file.file for file in view.diff.files], ["extra.mk", "unit.c"])
        self.assertFalse(any(mask.file.path == "extra.mk" for mask in view.code_masks))
        live_source = b"int still_live;\n"
        self.assertEqual(view.code_source("foo.c", SourceSide.OLD, live_source), live_source)


if __name__ == "__main__":
    unittest.main()
