from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
from tempfile import TemporaryDirectory
from typing import ClassVar
import unittest
from unittest.mock import patch

from kpatch.filter import FilterContext, FilteredCommit, FilterPipeline
from kpatch.filter.masking import LineRange, MaskReason
from kpatch.filter.policy_analysis import PolicyCommitDecision, PolicyFilter
from kpatch.filter.policy_clang import ClangAnalyzer, ClangToolchain, ClangUnavailable
from kpatch.filter.policy_context import PolicyBuildContext
from kpatch.filter.policy_profile import (
    AnalysisScope, PolicyTargetProfile, SeccompDenial, SeccompProfile, SELinuxPolicyEvaluator,
)
from kpatch.filter.policy_seccomp import ALLOW, ERRNO, JMP_JEQ_K, LD_W_ABS, RET_K
from kpatch.git import CommitParent, GitCommit, GitRepo


_NATIVE = 0xC00000B7
_COMPAT = 0x40000028
_WRAPPER_HEADER = "arch/arm64/include/asm/syscall_wrapper.h"
_NATIVE_TABLE = "arch/arm64/kernel/sys.c"
_COMPAT_TABLE = "arch/arm64/kernel/sys32.c"
_WRAPPERS = """#ifndef FIXTURE_SYSCALL_WRAPPER_H
#define FIXTURE_SYSCALL_WRAPPER_H
struct pt_regs { unsigned long regs[6]; };
typedef long (*syscall_fn_t)(const struct pt_regs *);
#define SYSCALL_DEFINE0(name) long __arm64_sys_##name(const struct pt_regs *unused)
#define SYSCALL_DEFINE1(name, type, arg) \\
 static inline long __do_sys_##name(type arg); \\
 static long __se_sys_##name(long arg); \\
 long __arm64_sys_##name(const struct pt_regs *regs) { return __se_sys_##name((long)regs->regs[0]); } \\
 static long __se_sys_##name(long arg) { return __do_sys_##name((type)arg); } \\
 static inline long __do_sys_##name(type arg)
#endif
"""
_UNIT = '#include <asm/syscall_wrapper.h>\nSYSCALL_DEFINE1(test, int, value)\n{\n return 7;\n}\n'


def _table(name: str, number: int, *, extra_alias: int | None = None) -> str:
    aliases = f', [{extra_alias}] = __arm64_sys_test' if extra_alias is not None else ''
    return ('#include <asm/syscall_wrapper.h>\n'
            'long __arm64_sys_ni_syscall(const struct pt_regs *);\n'
            'long __arm64_sys_test(const struct pt_regs *);\n'
            f'const syscall_fn_t {name}[4] = {{ [0 ... 3] = __arm64_sys_ni_syscall, '
            f'[{number}] = __arm64_sys_test{aliases} }};\n')


def _filter(denials: tuple[tuple[int, int], ...]) -> bytes:
    instructions: list[tuple[int, int, int, int]] = []
    for architecture, number in denials:
        instructions.extend(((LD_W_ABS, 0, 0, 4), (JMP_JEQ_K, 0, 3, architecture),
                             (LD_W_ABS, 0, 0, 0), (JMP_JEQ_K, 0, 1, number),
                             (RET_K, 0, 0, ERRNO | 13)))
    instructions.append((RET_K, 0, 0, ALLOW))
    return b''.join(struct.pack('<HBBI', *instruction) for instruction in instructions)


class SeccompEntryIntegrationTests(unittest.TestCase):
    binary: ClassVar[Path]
    compiler: ClassVar[str]

    @classmethod
    def setUpClass(cls) -> None:
        compiler = shutil.which('clang')
        if compiler is None:
            raise unittest.SkipTest('Clang is required')
        cls.compiler = compiler
        try:
            cls.binary = ClangToolchain.discover().build()
        except ClangUnavailable as error:
            raise unittest.SkipTest(str(error)) from error

    def setUp(self) -> None:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / 'source'
        self.output = self.root / 'build'
        self.source.mkdir()
        self.output.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.name', 'Seccomp Test')
        self.git('config', 'user.email', 'seccomp@example.invalid')
        self.config = self.output / '.config'
        self.config.write_text('CONFIG_ARM64=y\nCONFIG_COMPAT=y\nCONFIG_SECCOMP=y\nCONFIG_SECCOMP_FILTER=y\n')
        self.policy_file = self.root / 'sepolicy'
        self.policy_file.write_bytes(b'seccomp-entry-integration-no-selinux-claims')
        self.filter_file = self.root / 'filter.bpf'
        program = _filter(((_NATIVE, 1), (_COMPAT, 2)))
        self.filter_file.write_bytes(program)
        self.profile = PolicyTargetProfile(
            name='direct-seccomp-fixture', policy_file=self.policy_file,
            policy_sha256=hashlib.sha256(self.policy_file.read_bytes()).hexdigest(),
            subject_context='u:r:untrusted_app:s0', architecture='aarch64',
            scope=AnalysisScope.DIRECT_APP,
            seccomp=SeccompProfile(mode=2, architecture='aarch64', filter_file=self.filter_file,
                                  filter_sha256=hashlib.sha256(program).hexdigest()))
        self.evaluator = SELinuxPolicyEvaluator(self.policy_file, enforcing=None)
        self.analyzer = ClangAnalyzer(self.binary)
        self.addCleanup(self.analyzer.close)
        self.decisions: list[PolicyCommitDecision] = []

    def git(self, *arguments: str) -> str:
        return subprocess.check_output(['git', '-C', str(self.source), *arguments], stderr=subprocess.PIPE).decode().strip()

    def change(self, old: str = _UNIT, new: str | None = None, *,
               before: dict[str, str] | None = None, after: dict[str, str] | None = None,
               compile_tables: tuple[str, ...] = (_NATIVE_TABLE, _COMPAT_TABLE)) -> tuple[GitCommit, PolicyBuildContext]:
        files = {_WRAPPER_HEADER: _WRAPPERS, _NATIVE_TABLE: _table('sys_call_table', 1),
                 _COMPAT_TABLE: _table('compat_sys_call_table', 2), 'unit.c': old, **(before or {})}
        for name, contents in files.items():
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents)
        self.git('add', '.')
        self.git('commit', '-qm', 'parent')
        parent = self.git('rev-parse', 'HEAD')
        for name, contents in {'unit.c': new if new is not None else old.replace('return 7', 'return 8'),
                               **(after or {})}.items():
            (self.source / name).write_text(contents)
        self.git('add', '.')
        self.git('commit', '-qm', 'child')
        child = self.git('rev-parse', 'HEAD')
        patch = self.git('diff', '--no-ext-diff', '--no-renames', '--full-index', parent, child)
        self.git('checkout', '--detach', '-q', parent)
        paths = ('unit.c', *compile_tables, *(name for name in files if name.endswith('.c')
                                             and name not in {'unit.c', _NATIVE_TABLE, _COMPAT_TABLE}))
        commands = [{'directory': str(self.output), 'file': str(self.source / path),
                     'arguments': [self.compiler, '--target=aarch64-linux-gnu', '-std=gnu11', '-nostdinc',
                                   '-I', str(self.source / 'arch/arm64/include'), '-I', str(self.source),
                                   '-c', str(self.source / path)]} for path in paths]
        compdb = self.output / 'compile_commands.json'
        compdb.write_text(json.dumps(commands))
        context = PolicyBuildContext.capture(self.source, self.output, compdb, self.config)
        date = datetime(2026, 11, 7, tzinfo=UTC)
        commit = GitCommit(child, 'Seccomp Test', 'seccomp@example.invalid', date, date,
                           (CommitParent(parent, patch),), 'full original seccomp fixture')
        self.assertEqual(self.git('status', '--porcelain'), '')
        return commit, context

    def run_stage(self, commit: GitCommit, build: PolicyBuildContext, *,
                  profile: PolicyTargetProfile | None = None,
                  view: FilteredCommit | None = None) -> tuple[list[FilteredCommit], FilteredCommit]:
        self.decisions.clear()
        stage = PolicyFilter(profile or self.profile, build, self.evaluator, analyzer=self.analyzer,
                             on_decision=self.decisions.append)
        filtered = view if view is not None else FilteredCommit(commit)
        output = FilterPipeline([stage]).filter_mutable_commits([filtered], FilterContext(GitRepo(self.source)), False)
        self.assertEqual(self.git('rev-parse', 'HEAD'), build.base_revision)
        self.assertEqual(self.git('status', '--porcelain'), '')
        return output, filtered

    def assert_retained(self, commit: GitCommit, build: PolicyBuildContext, *,
                        profile: PolicyTargetProfile | None = None) -> None:
        output, view = self.run_stage(commit, build, profile=profile)
        self.assertEqual(len(output), 1, self.decisions)
        self.assertEqual(view.edit_masks, ())
        self.assertEqual(view.code_masks, ())
        self.assertNotEqual(self.decisions[0].status, 'excluded')

    def test_zero_argument_real_entry_is_excluded_from_full_original_diff(self) -> None:
        old = '#include <asm/syscall_wrapper.h>\nSYSCALL_DEFINE0(test)\n{\n return 7;\n}\n'
        commit, context = self.change(old)
        output, view = self.run_stage(commit, context)
        self.assertEqual(output, [], self.decisions)
        self.assertEqual(self.decisions[0].status, 'excluded')
        self.assertEqual({mask.reason for mask in view.edit_masks}, {MaskReason.POLICY})
        self.assertEqual(view.code_masks, ())
        self.assertEqual(view.original_diff.text, commit.diff_str)

    def test_one_argument_wrapper_chain_and_runtime_cleanup_writes_are_excluded(self) -> None:
        old = ('#include <asm/syscall_wrapper.h>\nstatic void clean(int *p) { *p=0; }\n'
               'SYSCALL_DEFINE1(test, int, value)\n{\n'
               ' int local __attribute__((cleanup(clean)))=7;\n int array[2];\n'
               ' array[0]=local;\n return array[0];\n}\n')
        commit, context = self.change(old, old.replace('return array[0]', 'return !array[0]'))
        output, _ = self.run_stage(commit, context)
        self.assertEqual(output, [], self.decisions)
        self.assertTrue(all(span.gate == 'seccomp' for span in self.decisions[0].files[0].old_exclusions))

    def test_services_scope_reports_candidate_and_publishes_no_masks(self) -> None:
        commit, context = self.change()
        profile = self.profile.model_copy(update={'scope': AnalysisScope.APP_WITH_SERVICES})
        output, view = self.run_stage(commit, context, profile=profile)
        self.assertEqual(len(output), 1)
        self.assertEqual(self.decisions[0].status, 'direct_app_candidate', self.decisions)
        self.assertEqual(view.edit_masks, ())
        self.assertEqual(view.code_masks, ())

    def test_same_domain_declared_complete_services_still_does_not_prove_app_entry_scope(self) -> None:
        commit, context = self.change()
        profile = self.profile.model_copy(update={
            'scope': AnalysisScope.APP_WITH_SERVICES, 'mediation_complete': True,
            'modeled_subject_types': ('untrusted_app',)})
        output, view = self.run_stage(commit, context, profile=profile)
        self.assertEqual(len(output), 1)
        self.assertEqual(self.decisions[0].status, 'direct_app_candidate', self.decisions)
        self.assertEqual(view.edit_masks, ())
        self.assertEqual(view.code_masks, ())

    def test_any_allowed_native_alias_retains(self) -> None:
        commit, context = self.change(before={_NATIVE_TABLE: _table('sys_call_table', 1, extra_alias=3)})
        self.assert_retained(commit, context)

    def test_allowed_compat_alias_retains_even_when_native_is_denied(self) -> None:
        program = _filter(((_NATIVE, 1),))
        self.filter_file.write_bytes(program)
        profile = self.profile.model_copy(update={'seccomp': self.profile.seccomp.model_copy(
            update={'filter_sha256': hashlib.sha256(program).hexdigest()})})
        commit, context = self.change()
        self.assert_retained(commit, context, profile=profile)

    def test_missing_recorded_table_command_retains(self) -> None:
        commit, context = self.change(compile_tables=(_NATIVE_TABLE,))
        self.assert_retained(commit, context)

    def test_incomplete_semantic_table_with_null_gaps_retains(self) -> None:
        table = _table('compat_sys_call_table', 2).replace('[0 ... 3] = __arm64_sys_ni_syscall, ', '')
        commit, context = self.change(before={_COMPAT_TABLE: table})
        self.assert_retained(commit, context)

    def test_local_unguarded_caller_retains(self) -> None:
        old = _UNIT + 'long local_entry(void) { return __do_sys_test(0); }\n'
        commit, context = self.change(old)
        self.assert_retained(commit, context)

    def test_untracked_header_caller_retains(self) -> None:
        old = _UNIT + '#include "entry.h"\n'
        commit, context = self.change(old, before={'entry.h': 'long header_entry(void) { return __do_sys_test(0); }\n'})
        self.assert_retained(commit, context)

    def test_implementation_or_wrapper_address_escape_retains(self) -> None:
        for escape in ('long (*saved)(int)=__do_sys_test;',
                       'syscall_fn_t saved=__arm64_sys_test;'):
            with self.subTest(escape=escape):
                commit, context = self.change(_UNIT + escape + '\n')
                self.assert_retained(commit, context)

    def test_translation_related_body_declarations_retain(self) -> None:
        for declaration in ('static int saved=7;', 'extern int external;',
                            'register long reg __asm__("x12")=7;',
                            'int aligned __attribute__((aligned(32)));',
                            'int prototype(void);', '__asm__("nop");'):
            with self.subTest(declaration=declaration):
                old = _UNIT.replace(' return 7;', ' ' + declaration + '\n return 7;')
                commit, context = self.change(old)
                self.assert_retained(commit, context)

    def test_mismatched_abi_and_multiple_subjects_retain(self) -> None:
        commit, context = self.change()
        profiles = (self.profile.model_copy(update={'architecture': 'x86_64'}),
                    self.profile.model_copy(update={'seccomp': self.profile.seccomp.model_copy(update={'architecture': 'arm'})}),
                    self.profile.model_copy(update={'modeled_subject_types': ('untrusted_app', 'system_server'),
                                                    'mediation_complete': True}))
        for profile in profiles:
            with self.subTest(profile=profile.name, architecture=profile.architecture, subjects=profile.modeled_subject_types):
                self.assert_retained(commit, context, profile=profile)

    def test_disabled_seccomp_configuration_retains(self) -> None:
        self.config.write_text(self.config.read_text().replace('CONFIG_SECCOMP_FILTER=y', '# CONFIG_SECCOMP_FILTER is not set'))
        commit, context = self.change()
        self.assert_retained(commit, context)

    def test_opaque_assembly_in_another_main_function_retains(self) -> None:
        old = _UNIT + 'void reachable_entry(void) { __asm__("bl __arm64_sys_test"); }\n'
        commit, context = self.change(old)
        self.assert_retained(commit, context)

    def test_opaque_assembly_in_an_untracked_header_function_retains(self) -> None:
        old = _UNIT + '#include "opaque.h"\nvoid reachable_entry(void) { hidden(); }\n'
        commit, context = self.change(old, before={
            'opaque.h': 'static inline void hidden(void) { __asm__("bl __arm64_sys_test"); }\n'})
        self.assert_retained(commit, context)

    def test_indirect_table_dispatch_in_another_main_function_retains(self) -> None:
        old = (_UNIT + 'extern const syscall_fn_t sys_call_table[4];\n'
               'long reachable_entry(const struct pt_regs *regs) {return sys_call_table[1](regs);}\n')
        commit, context = self.change(old)
        self.assert_retained(commit, context)

    def test_indirect_table_dispatch_in_an_untracked_header_retains(self) -> None:
        old = _UNIT + '#include "dispatch.h"\nlong reachable_entry(const struct pt_regs *regs) {return hidden(regs);}\n'
        commit, context = self.change(old, before={'dispatch.h':
            'extern const syscall_fn_t sys_call_table[4];\n'
            'static inline long hidden(const struct pt_regs *regs) {return sys_call_table[1](regs);}\n'})
        self.assert_retained(commit, context)

    def test_implicit_cleanup_caller_in_an_untracked_header_retains(self) -> None:
        old = _UNIT + '#include "cleanup.h"\nlong reachable_entry(void) {return hidden();}\n'
        commit, context = self.change(old, before={'cleanup.h':
            'static inline long hidden(void) {struct pt_regs regs '
            '__attribute__((cleanup(__arm64_sys_test)))={0}; return 0;}\n'})
        self.assert_retained(commit, context)

    def test_changed_automatic_variable_type_inside_denied_entry_is_ignored(self) -> None:
        old = ('#include <asm/syscall_wrapper.h>\n'
               'struct old_type {int field;}; struct new_type {int field;};\n'
               'SYSCALL_DEFINE1(test, int, value)\n{\n struct old_type local={0};\n return local.field;\n}\n')
        new = old.replace('struct old_type local', 'struct new_type local')
        commit, context = self.change(old, new)
        output, _ = self.run_stage(commit, context)
        self.assertEqual(output, [], self.decisions)

    def test_changed_label_name_inside_denied_entry_is_ignored(self) -> None:
        old = _UNIT.replace(' return 7;', ' if(value) goto original;\n return 3;\noriginal: return 7;')
        commit, context = self.change(old, old.replace('original', 'renamed'))
        output, _ = self.run_stage(commit, context)
        self.assertEqual(output, [], self.decisions)

    def test_btf_configuration_does_not_veto_denied_runtime_body(self) -> None:
        self.config.write_text(self.config.read_text() + 'CONFIG_DEBUG_INFO_BTF=y\n')
        selecting = ('#include <asm/syscall_wrapper.h>\n'
                     'struct first {int a;}; struct second {long b;};\n'
                     'SYSCALL_DEFINE1(test, int, value)\n{\n'
                     ' if(0) {struct first local={0}; return local.a;}\n'
                     ' else {struct second local={0}; return local.b;}\n}\n')
        for old, new in ((_UNIT, _UNIT.replace('return 7', 'return 8')),
                         (selecting, selecting.replace('if(0)', 'if(1)'))):
            with self.subTest(old=old):
                commit, context = self.change(old, new)
                output, _ = self.run_stage(commit, context)
                self.assertEqual(output, [], self.decisions)
                self.assertIn('btf_and_debug_metadata', self.decisions[0].ignored_differences)

    def test_empty_memory_barrier_in_a_header_does_not_hide_an_entry_caller(self) -> None:
        old = _UNIT + '#include "barrier.h"\nvoid independent(void) { barrier(); }\n'
        commit, context = self.change(old, before={
            'barrier.h': 'static inline void barrier(void) { __asm__ volatile("" : : : "memory"); }\n'})
        output, _ = self.run_stage(commit, context)
        self.assertEqual(output, [], self.decisions)

    def test_macro_events_inside_denied_body_still_retain(self) -> None:
        old = _UNIT.replace(' return 7;', '#define BODY_VALUE 7\n return BODY_VALUE;')
        commit, context = self.change(old, old.replace('BODY_VALUE 7', 'BODY_VALUE 8'))
        self.assert_retained(commit, context)

    def test_reachable_second_file_change_publishes_no_partial_policy_masks(self) -> None:
        commit, context = self.change(before={'other.c': 'int reachable(void) {return 7;}\n'},
                                      after={'other.c': 'int reachable(void) {return 8;}\n'})
        self.assert_retained(commit, context)
        self.assertTrue(any(file.equivalent_outside_exclusions for file in self.decisions[0].files), self.decisions)

    def test_manual_denials_without_raw_filter_do_not_authorize_removal(self) -> None:
        commit, context = self.change()
        seccomp = self.profile.seccomp.model_copy(update={'filter_file': None, 'denials': (
            SeccompDenial(architecture='aarch64', syscall_number=1, syscall_name='test',
                          filter_sha256=self.profile.seccomp.filter_sha256 or '', all_arguments=True),)})
        self.assert_retained(commit, context, profile=self.profile.model_copy(update={'seccomp': seccomp}))

    def test_prior_edit_masks_do_not_reconstruct_a_synthetic_compiler_input(self) -> None:
        old = 'int observable=7;\n' + _UNIT
        new = old.replace('observable=7', 'observable=8').replace('return 7', 'return 8')
        commit, context = self.change(old, new)
        view = FilteredCommit(commit)
        view.mask_edits(view.diff.files[0], (LineRange(1, 2),), (LineRange(1, 2),), MaskReason.WHITESPACE)
        prior_masks = view.edit_masks
        original = view.original_diff
        output, result = self.run_stage(commit, context, view=view)
        self.assertEqual(len(output), 1, self.decisions)
        self.assertEqual(result.edit_masks, prior_masks)
        self.assertEqual(result.code_masks, ())
        self.assertEqual(result.original_diff, original)


if __name__ == '__main__':
    unittest.main()
