from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
from typing import ClassVar
import unittest
from unittest.mock import patch

from kpatch.filter import FilterContext, FilteredCommit, FilterPipeline
from kpatch.filter.masking import MaskReason
from kpatch.filter.policy_analysis import PolicyCommitDecision, PolicyFilter
from kpatch.filter.policy_clang import ClangAnalyzer, ClangToolchain, ClangUnavailable, TranslationUnitFacts
from kpatch.filter.policy_context import PolicyBuildContext
from kpatch.filter.policy_profile import (
    AnalysisScope, PolicyTargetProfile, SELinuxDecision, SELinuxPermissionQuery,
    SELinuxPolicyEvaluator, SELinuxResult, SEToolsRuntime,
)
from kpatch.git import CommitParent, GitCommit, GitRepo


class DeniedFixturePolicy(SELinuxPolicyEvaluator):
    """Exact denial evidence for rule integration; no real binary is inferred."""

    def query(self, query: SELinuxPermissionQuery) -> SELinuxResult:
        return SELinuxResult(SELinuxDecision.DENIED, "permission denial fixture", self.policy_sha256)

    def capability_enabled(self, name: str) -> bool | None:
        return False if name == "bpf_token_perms" else None


class PolicyAnalysisTests(unittest.TestCase):
    binary: ClassVar[Path]
    compiler: ClassVar[str]

    @classmethod
    def setUpClass(cls) -> None:
        try:
            cls.binary = ClangToolchain.discover().build()
        except ClangUnavailable as error:
            raise unittest.SkipTest(str(error)) from error
        compiler = shutil.which("clang")
        if compiler is None:
            raise unittest.SkipTest("Clang is required")
        cls.compiler = compiler

    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.output = self.root / "build"
        self.source.mkdir()
        self.output.mkdir()
        self.repo = GitRepo(self.source)
        self.git("init", "-q")
        self.git("config", "user.name", "Policy Test")
        self.git("config", "user.email", "policy@example.invalid")
        self.config = self.output / ".config"
        self.config.write_text('CONFIG_MULTIUSER=y\nCONFIG_SECURITY=y\nCONFIG_SECURITY_SELINUX=y\nCONFIG_LSM="selinux,bpf"\n')
        self.prelude = self.output / "syscalls.h"
        self.prelude.write_text(
            '#define SYSCALL_DEFINE0(name) static long __do_sys_##name(void)\n'
            '#define SYSCALL_DEFINE1(name, type, arg) static long __do_sys_##name(type arg)\n'
            'int capable(int); int ns_capable(void *, int);\n'
            'int security_bpf(int, void *, unsigned int, int);\n'
            'int security_perf_event_open(void *, int);\n'
            'int owner(void); void unknown_effect(void); void override_creds(void);\n'
            'void *unknown_attributes(void);\n'
        )
        self.policy_file = self.root / "policy"
        self.policy_file.write_bytes(b"policy-analysis-fixture")
        self.profile = PolicyTargetProfile(name="direct-app-fixture", policy_file=self.policy_file,
                                           policy_sha256=hashlib.sha256(self.policy_file.read_bytes()).hexdigest(),
                                           subject_context="u:r:app:s0", selinux_enforcing=True,
                                           cap_effective=0, cap_permitted=0, cap_bounding=0,
                                           user_namespaces_enabled=False, scope=AnalysisScope.DIRECT_APP)
        self.evaluator = DeniedFixturePolicy(self.policy_file, enforcing=True)
        self.analyzer = ClangAnalyzer(self.binary)
        self.addCleanup(self.analyzer.close)
        self.decisions: list[PolicyCommitDecision] = []

    def git(self, *arguments: str) -> str:
        return subprocess.check_output(["git", "-C", str(self.source), *arguments], stderr=subprocess.PIPE).decode().strip()

    def change(self, old: str, new: str, *, before: dict[str, str] | None = None,
               after: dict[str, str] | None = None) -> tuple[GitCommit, PolicyBuildContext]:
        files = {"unit.c": old, **(before or {})}
        for relative, text in files.items():
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        self.git("add", ".")
        self.git("commit", "-qm", "before")
        parent = self.git("rev-parse", "HEAD")
        for relative, text in {"unit.c": new, **(after or {})}.items():
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        self.git("add", ".")
        self.git("commit", "-qm", "after")
        child = self.git("rev-parse", "HEAD")
        patch_text = self.git("diff", "--no-ext-diff", "--no-renames", parent, child)
        self.git("checkout", "--detach", "-q", parent)
        commands = [{"directory": str(self.output), "file": str(path),
                     "arguments": [self.compiler, "-std=gnu11", "-nostdinc", "-I", str(self.source),
                                   "-include", str(self.prelude), "-c", str(path)]}
                    for path in sorted(self.source.rglob("*.c"))]
        compdb = self.output / "compile_commands.json"
        compdb.write_text(json.dumps(commands))
        build = PolicyBuildContext.capture(self.source, self.output, compdb, self.config)
        date = datetime(2026, 11, 6, tzinfo=UTC)
        commit = GitCommit(child, "Policy Test", "policy@example.invalid", date, date,
                           (CommitParent(parent, patch_text),), "test")
        return commit, build

    def run_stage(self, commit: GitCommit, build: PolicyBuildContext,
                  *, profile: PolicyTargetProfile | None = None,
                  evaluator: SELinuxPolicyEvaluator | None = None) -> tuple[list[FilteredCommit], FilteredCommit]:
        self.decisions.clear()
        stage = PolicyFilter(profile or self.profile, build, evaluator or self.evaluator,
                             analyzer=self.analyzer, on_decision=self.decisions.append,
                             cache_path=self.root / "facts.sqlite")
        view = FilteredCommit(commit)
        output = FilterPipeline([stage]).filter_mutable_commits([view], FilterContext(self.repo), False)
        return output, view

    def assert_retained(self, commit: GitCommit, build: PolicyBuildContext, *, unknown: bool = False) -> None:
        output, view = self.run_stage(commit, build)
        self.assertEqual(len(output), 1, self.decisions)
        self.assertEqual(view.edit_masks, ())
        self.assertEqual(view.code_masks, ())
        if unknown:
            self.assertEqual(self.decisions[0].status, "unknown")
        else:
            self.assertIn(self.decisions[0].status, {"retained", "unknown"})

    def test_capability_guarded_body_change_is_excluded_in_explicit_direct_scope(self) -> None:
        old = 'SYSCALL_DEFINE0(test) { if (!capable(21)) return -1; return 7; }\n'
        commit, build = self.change(old, old.replace("return 7", "return 8"))
        output, view = self.run_stage(commit, build)
        self.assertEqual(output, [], self.decisions)
        self.assertEqual(self.decisions[0].status, "excluded")
        self.assertEqual({mask.reason for mask in view.edit_masks}, {MaskReason.POLICY})
        self.assertEqual(view.code_masks, ())

    def test_default_scope_records_candidate_and_retains_every_edit(self) -> None:
        old = 'SYSCALL_DEFINE0(test) { if (!capable(21)) return -1; return 7; }\n'
        commit, build = self.change(old, old.replace("return 7", "return 8"))
        profile = self.profile.model_copy(update={"scope": AnalysisScope.APP_WITH_SERVICES})
        output, view = self.run_stage(commit, build, profile=profile)
        self.assertEqual(len(output), 1)
        self.assertEqual(self.decisions[0].status, "direct_app_candidate", self.decisions)
        self.assertEqual(view.edit_masks, ())
        self.assertEqual(view.code_masks, ())

    def test_btf_configuration_permits_unreachable_local_type_selection(self) -> None:
        self.config.write_text(self.config.read_text() + "CONFIG_DEBUG_INFO_BTF=y\n")
        old = ('struct old_type {long member;}; struct new_type {char member;};\n'
               'void consume(void *);\n'
               'SYSCALL_DEFINE0(test) { if (!capable(21)) return -1;\n'
               'if (0) {struct old_type local; consume(&local);}\n'
               'else {struct new_type local; consume(&local);} return 7; }\n')
        commit, build = self.change(old, old.replace('if (0)', 'if (1)'))
        output, view = self.run_stage(commit, build)
        self.assertEqual(output, [], self.decisions)
        self.assertNotIn("emitted_btf_equivalence_unproved", self.decisions[0].files[0].reasons)
        self.assertIn("btf_and_debug_metadata", self.decisions[0].ignored_differences)
        self.assertTrue(view.edit_masks)
        self.assertEqual(view.code_masks, ())

    def test_existing_type_reference_in_guarded_return_is_unreachable(self) -> None:
        old = ('struct first {long member;}; struct second {char member;};\n'
               'SYSCALL_DEFINE0(test) { if (!capable(21)) return -1; return sizeof(struct first); }\n')
        commit, build = self.change(old, old.replace('sizeof(struct first)', 'sizeof(struct second)'))
        output, _ = self.run_stage(commit, build)
        self.assertEqual(output, [], self.decisions)

    def test_closed_static_helper_called_only_after_gate_can_be_excluded(self) -> None:
        old = ('static int helper(void) { return 7; }\n'
               'SYSCALL_DEFINE0(test) { if (!capable(21)) return -1; return helper(); }\n')
        commit, build = self.change(old, old.replace("return 7", "return 8"))
        output, _ = self.run_stage(commit, build)
        self.assertEqual(output, [], self.decisions)

    def test_static_helper_with_unguarded_second_caller_is_retained(self) -> None:
        old = ('static int helper(void) { return 7; }\n'
               'SYSCALL_DEFINE0(test) { if (!capable(21)) return -1; return helper(); }\n'
               'SYSCALL_DEFINE0(other) { return helper(); }\n')
        commit, build = self.change(old, old.replace("return 7", "return 8"))
        self.assert_retained(commit, build)

    def test_header_function_calling_static_helper_prevents_main_file_closure(self) -> None:
        old = ('static int helper(void) { return 7; }\n'
               '#include "entry.h"\n'
               'SYSCALL_DEFINE0(test) { if (!capable(21)) return -1; return helper(); }\n')
        commit, build = self.change(old, old.replace("return 7", "return 8"),
                                   before={"entry.h": "int public_header_entry(void) { return helper(); }\n"})
        self.assert_retained(commit, build)

    def test_header_assembly_call_to_static_helper_prevents_caller_closure(self) -> None:
        old = ('static int helper(void) { return 7; }\n'
               '#include "entry.h"\n'
               'SYSCALL_DEFINE0(test) { if (!capable(21)) return -1; return helper(); }\n')
        commit, build = self.change(old, old.replace('return 7', 'return 8'), before={
            'entry.h': 'void public_header_entry(void) { __asm__("call helper"); }\n'})
        self.assert_retained(commit, build)

    def test_owner_or_capability_alternative_retains(self) -> None:
        old = 'SYSCALL_DEFINE0(test) { if (owner() || capable(21)) return 7; return 0; }\n'
        commit, build = self.change(old, old.replace("return 7", "return 8"))
        self.assert_retained(commit, build)

    def test_failure_side_change_retains(self) -> None:
        old = 'SYSCALL_DEFINE0(test) { if (!capable(21)) return 7; return 0; }\n'
        commit, build = self.change(old, old.replace("return 7", "return 8"))
        self.assert_retained(commit, build)

    def test_precheck_change_retains(self) -> None:
        old = 'SYSCALL_DEFINE0(test) { int n = 7; if (!capable(21)) return -1; return n; }\n'
        commit, build = self.change(old, old.replace("n = 7", "n = 8"))
        self.assert_retained(commit, build)

    def test_changed_gate_itself_retains(self) -> None:
        old = 'SYSCALL_DEFINE0(test) { if (!capable(21)) return -1; return 7; }\n'
        commit, build = self.change(old, old.replace("capable(21)", "capable(12)"))
        self.assert_retained(commit, build)

    def test_guard_added_only_in_child_does_not_exclude_old_reachable_code(self) -> None:
        old = 'SYSCALL_DEFINE0(test) { return 7; }\n'
        new = 'SYSCALL_DEFINE0(test) { if (!capable(21)) return -1; return 8; }\n'
        commit, build = self.change(old, new)
        self.assert_retained(commit, build)

    def test_global_change_outside_guarded_body_retains(self) -> None:
        old = 'int observable = 7;\nSYSCALL_DEFINE0(test) { if (!capable(21)) return -1; return 7; }\n'
        new = old.replace("observable = 7", "observable = 8").replace("return 7", "return 8")
        commit, build = self.change(old, new)
        self.assert_retained(commit, build)

    def test_counter_in_excluded_statement_can_affect_reachable_initializer(self) -> None:
        old = ('SYSCALL_DEFINE0(test) { if (!capable(21)) return -1; return 7; }\n'
               'int externally_visible = __COUNTER__;\n')
        commit, build = self.change(old, old.replace("return 7", "return __COUNTER__"))
        self.assert_retained(commit, build)

    def test_line_shift_in_excluded_statement_can_affect_reachable_initializer(self) -> None:
        old = ('SYSCALL_DEFINE0(test) { if (!capable(21)) return -1; return 7; }\n'
               'int externally_visible = __LINE__;\n')
        commit, build = self.change(old, old.replace("return 7", "return\n8"))
        self.assert_retained(commit, build)

    def test_header_layout_or_definition_change_retains(self) -> None:
        old = '#include "api.h"\nSYSCALL_DEFINE0(test) { if (!capable(21)) return -1; return 7; }\n'
        commit, build = self.change(old, old, before={"api.h": "struct object { int field; };\n"},
                                   after={"api.h": "struct object { long field; };\n"})
        self.assert_retained(commit, build, unknown=True)

    def test_credential_change_before_gate_retains(self) -> None:
        old = 'SYSCALL_DEFINE0(test) { override_creds(); if (!capable(21)) return -1; return 7; }\n'
        commit, build = self.change(old, old.replace("return 7", "return 8"))
        self.assert_retained(commit, build)

    def test_unknown_callee_before_gate_retains(self) -> None:
        old = 'SYSCALL_DEFINE0(test) { unknown_effect(); if (!capable(21)) return -1; return 7; }\n'
        commit, build = self.change(old, old.replace("return 7", "return 8"))
        self.assert_retained(commit, build)

    def test_same_named_static_preserving_api_is_not_a_credential_contract(self) -> None:
        old = ('static void copy_from_user(void) { override_creds(); }\n'
               'SYSCALL_DEFINE0(test) { copy_from_user(); if (!capable(21)) return -1; return 7; }\n')
        commit, build = self.change(old, old.replace("return 7", "return 8"))
        self.assert_retained(commit, build)

    def test_main_file_capable_definition_cannot_inherit_external_api_contract(self) -> None:
        old = ('int capable(int capability) { return 1; }\n'
               'SYSCALL_DEFINE0(test) { if (!capable(21)) return -1; return 7; }\n')
        commit, build = self.change(old, old.replace("return 7", "return 8"))
        self.assert_retained(commit, build)

    def test_global_initial_namespace_capability_gate_can_exclude(self) -> None:
        old = ('extern int init_user_ns;\n'
               'SYSCALL_DEFINE0(test) { if (!ns_capable(&init_user_ns, 21)) return -1; return 7; }\n')
        commit, build = self.change(old, old.replace("return 7", "return 8"))
        output, _ = self.run_stage(commit, build)
        self.assertEqual(output, [], self.decisions)

    def test_shadow_local_initial_namespace_name_does_not_prove_denial(self) -> None:
        old = ('SYSCALL_DEFINE0(test) { int init_user_ns = 0; '
               'if (!ns_capable(&init_user_ns, 21)) return -1; return 7; }\n')
        commit, build = self.change(old, old.replace("return 7", "return 8"))
        self.assert_retained(commit, build)

    def test_later_textual_credential_mutation_can_execute_before_gate_on_backedge(self) -> None:
        old = ('SYSCALL_DEFINE0(test) { int n = 0; do { if (n) { '
               'if (!capable(21)) return -1; return 7; } override_creds(); n = 1; } while (1); }\n')
        commit, build = self.change(old, old.replace("return 7", "return 8"))
        self.assert_retained(commit, build)

    def test_unknown_callee_inside_guard_arguments_retains(self) -> None:
        old = 'SYSCALL_DEFINE0(test) { if (security_bpf(5, unknown_attributes(), 0, 0)) return -1; return 7; }\n'
        commit, build = self.change(old, old.replace("return 7", "return 8"))
        self.assert_retained(commit, build)

    def test_mixed_reachable_file_publishes_no_partial_masks(self) -> None:
        old = 'SYSCALL_DEFINE0(test) { if (!capable(21)) return -1; return 7; }\n'
        before = {"other.c": "SYSCALL_DEFINE0(other) { return 7; }\n"}
        after = {"other.c": "SYSCALL_DEFINE0(other) { return 8; }\n"}
        commit, build = self.change(old, old.replace("return 7", "return 8"), before=before, after=after)
        self.assert_retained(commit, build)
        self.assertTrue(any(file.old_exclusions for file in self.decisions[0].files))

    def test_failed_compiler_facts_retain_without_masks(self) -> None:
        old = 'SYSCALL_DEFINE0(test) { if (!capable(21)) return -1; return 7; }\n'
        commit, build = self.change(old, old.replace("return 7", "return 8"))
        with patch.object(self.analyzer, "analyze", return_value=TranslationUnitFacts.failure("fixture_failure")):
            self.assert_retained(commit, build, unknown=True)

    def test_changed_build_context_retains_without_masks(self) -> None:
        old = 'SYSCALL_DEFINE0(test) { if (!capable(21)) return -1; return 7; }\n'
        commit, build = self.change(old, old.replace("return 7", "return 8"))
        self.config.write_text("CONFIG_MULTIUSER=n\n")
        self.assert_retained(commit, build, unknown=True)

    def test_arbitrary_sys_named_function_is_not_a_trusted_entry(self) -> None:
        old = 'int sys_test(void) { if (!capable(21)) return -1; return 7; }\n'
        commit, build = self.change(old, old.replace("return 7", "return 8"))
        self.assert_retained(commit, build)

    def test_syscall_macro_name_in_comment_does_not_create_entry_evidence(self) -> None:
        old = 'int sys_test(void) /* SYSCALL_DEFINE0(test) */ { if (!capable(21)) return -1; return 7; }\n'
        commit, build = self.change(old, old.replace("return 7", "return 8"))
        self.assert_retained(commit, build)

    def test_address_taken_syscall_body_has_unknown_callback_credential_context(self) -> None:
        old = ('SYSCALL_DEFINE0(test) { if (!capable(21)) return -1; return 7; }\n'
               'long (*callback)(void) = __do_sys_test;\n')
        commit, build = self.change(old, old.replace("return 7", "return 8"))
        self.assert_retained(commit, build)

    def test_explicit_internal_caller_prevents_treating_syscall_body_as_direct_root(self) -> None:
        old = ('SYSCALL_DEFINE0(test) { if (!capable(21)) return -1; return 7; }\n'
               'long internal_caller(void) { override_creds(); return __do_sys_test(); }\n')
        commit, build = self.change(old, old.replace("return 7", "return 8"))
        self.assert_retained(commit, build)

    def test_builtin_memory_write_before_gate_retains(self) -> None:
        old = ('extern void *credential_storage;\n'
               'SYSCALL_DEFINE0(test) { __builtin_memset(credential_storage, 0, 64); '
               'if (!capable(21)) return -1; return 7; }\n')
        commit, build = self.change(old, old.replace("return 7", "return 8"))
        self.assert_retained(commit, build)

    def test_pointer_write_before_gate_retains(self) -> None:
        old = ('extern unsigned long *credential_storage;\n'
               'SYSCALL_DEFINE0(test) { *credential_storage = 1; '
               'if (!capable(21)) return -1; return 7; }\n')
        commit, build = self.change(old, old.replace("return 7", "return 8"))
        self.assert_retained(commit, build)

    def test_pointer_write_after_same_success_gate_does_not_poison_prefix(self) -> None:
        old = ('extern unsigned long *credential_storage;\n'
               'SYSCALL_DEFINE0(test) { if (!capable(21)) return -1; '
               '*credential_storage = 1; return 7; }\n')
        commit, build = self.change(old, old.replace('return 7', 'return 8'))
        output, _ = self.run_stage(commit, build)
        self.assertEqual(output, [], self.decisions)

    def test_changed_write_after_same_success_gate_can_be_excluded(self) -> None:
        old = ('extern unsigned long *credential_storage;\n'
               'SYSCALL_DEFINE0(test) { if (!capable(21)) return -1; '
               '*credential_storage = 1; return 7; }\n')
        commit, build = self.change(old, old.replace('*credential_storage = 1', '*credential_storage = 2'))
        output, _ = self.run_stage(commit, build)
        self.assertEqual(output, [], self.decisions)

    def test_macro_post_gate_write_does_not_poison_prefix(self) -> None:
        self.prelude.write_text(self.prelude.read_text() + '#define WRITE(p) (*(p)=1)\n')
        old = ('extern unsigned long *credential_storage;\n'
               'SYSCALL_DEFINE0(test) { if (!capable(21)) return -1; '
               'WRITE(credential_storage); return 7; }\n')
        commit, build = self.change(old, old.replace('return 7', 'return 8'))
        output, _ = self.run_stage(commit, build)
        self.assertEqual(output, [], self.decisions)

    def test_later_write_can_precede_first_gate_via_loop(self) -> None:
        old = ('extern unsigned long *credential_storage;\n'
               'SYSCALL_DEFINE0(test) { int n=0; do { if(n) { '
               'if(!capable(21)) return -1; return 7; } '
               '*credential_storage=1; n=1; } while(1); }\n')
        commit, build = self.change(old, old.replace('return 7', 'return 8'))
        self.assert_retained(commit, build)

    def test_later_write_can_precede_first_gate_via_goto(self) -> None:
        old = ('extern unsigned long *credential_storage;\n'
               'SYSCALL_DEFINE0(test) { goto mutate; check: '
               'if(!capable(21)) return -1; return 7; '
               'mutate: *credential_storage=1; goto check; }\n')
        commit, build = self.change(old, old.replace('return 7', 'return 8'))
        self.assert_retained(commit, build)

    def test_nested_gate_argument_memory_write_retains(self) -> None:
        old = ('extern unsigned long *credential_storage;\n'
               'SYSCALL_DEFINE0(test) { if(security_bpf(5, (*credential_storage=1,(void*)0), 0, 0)) '
               'return -1; return 7; }\n')
        commit, build = self.change(old, old.replace('return 7', 'return 8'))
        self.assert_retained(commit, build)

    def test_helper_write_before_gate_still_retains(self) -> None:
        old = ('extern unsigned long *credential_storage;\n'
               'static void helper(void) { *credential_storage=1; }\n'
               'SYSCALL_DEFINE0(test) { helper(); if(!capable(21)) return -1; return 7; }\n')
        commit, build = self.change(old, old.replace('return 7', 'return 8'))
        self.assert_retained(commit, build)

    def test_unaccounted_atomic_write_retains(self) -> None:
        old = ('extern unsigned long *credential_storage;\n'
               'SYSCALL_DEFINE0(test) { (void)sizeof(__atomic_fetch_add(credential_storage,1,0)); '
               'if(!capable(21)) return -1; return 7; }\n')
        commit, build = self.change(old, old.replace('return 7', 'return 8'))
        self.assert_retained(commit, build)

    def test_unaccounted_macro_write_retains(self) -> None:
        self.prelude.write_text(self.prelude.read_text() + '#define HIDDEN_WRITE(p) sizeof((*(p)=1))\n')
        old = ('extern unsigned long *credential_storage;\n'
               'SYSCALL_DEFINE0(test) { (void)HIDDEN_WRITE(credential_storage); '
               'if(!capable(21)) return -1; return 7; }\n')
        commit, build = self.change(old, old.replace('return 7', 'return 8'))
        self.assert_retained(commit, build)

    def test_va_arg_implicit_pointer_write_before_gate_retains(self) -> None:
        old = ('extern __builtin_va_list *shared;\n'
               'SYSCALL_DEFINE0(test) { (void)__builtin_va_arg(*shared,int); '
               'if(!capable(21)) return -1; return 7; }\n')
        commit, build = self.change(old, old.replace('return 7', 'return 8'))
        self.assert_retained(commit, build)

    def test_incomplete_write_coverage_retains_even_without_global_unknown(self) -> None:
        old = 'SYSCALL_DEFINE0(test) { if(!capable(21))return -1; return 7; }\n'
        commit, build = self.change(old, old.replace('return 7', 'return 8'))
        analyze = self.analyzer.analyze

        def incomplete(*args, **kwargs):
            facts = analyze(*args, **kwargs)
            return facts.model_copy(update={'functions': tuple(
                function.model_copy(update={'write_coverage_complete': False}) for function in facts.functions
            )})

        with patch.object(self.analyzer, 'analyze', side_effect=incomplete):
            self.assert_retained(commit, build)

    def test_missing_cfg_metadata_retains_even_for_same_success_gate_write(self) -> None:
        old = ('extern unsigned long *credential_storage;\n'
               'SYSCALL_DEFINE0(test) { if(!capable(21))return -1; '
               '*credential_storage=1; return 7; }\n')
        commit, build = self.change(old, old.replace('return 7', 'return 8'))
        analyze = self.analyzer.analyze

        def missing_graph(*args, **kwargs):
            facts = analyze(*args, **kwargs)
            return facts.model_copy(update={'functions': tuple(
                function.model_copy(update={'cfg_blocks': ()}) for function in facts.functions
            )})

        with patch.object(self.analyzer, 'analyze', side_effect=missing_graph):
            self.assert_retained(commit, build)

    def test_nested_macro_gate_occurrences_do_not_share_success_proof(self) -> None:
        self.prelude.write_text(self.prelude.read_text()
                               + '#define GATE(n) capable(n)\n'
                               '#define CHECKS(p) do { if(GATE(1)) *(p)=1; if(!GATE(21)) return -1; } while(0)\n')
        self.profile = self.profile.model_copy(update={'cap_effective': 1 << 1})
        old = ('extern unsigned long *credential_storage;\n'
               'SYSCALL_DEFINE0(test) { CHECKS(credential_storage); return 7; }\n')
        commit, build = self.change(old, old.replace('return 7', 'return 8'))
        self.assert_retained(commit, build)

    def test_macro_loop_can_reenter_after_credential_mutation(self) -> None:
        self.prelude.write_text(self.prelude.read_text() + '#define REPEAT do\n#define FOREVER while (1)\n')
        old = ('SYSCALL_DEFINE0(test) { int n = 0; REPEAT { if (n) { '
               'if (!capable(21)) return -1; return 7; } override_creds(); n = 1; } FOREVER; }\n')
        commit, build = self.change(old, old.replace("return 7", "return 8"))
        self.assert_retained(commit, build)

    def test_bpf_literal_command_success_branch_is_excluded(self) -> None:
        old = 'SYSCALL_DEFINE0(test) { if (security_bpf(5, 0, 0, 0)) return -1; return 7; }\n'
        commit, build = self.change(old, old.replace("return 7", "return 8"))
        output, _ = self.run_stage(commit, build)
        self.assertEqual(output, [], self.decisions)

    @unittest.skipUnless(os.environ.get("KPATCH_TEST_SEPOLICY"), "Set KPATCH_TEST_SEPOLICY for real policy integration")
    def test_fresh_android_binary_denial_drives_actual_cfg_exclusion(self) -> None:
        old = 'SYSCALL_DEFINE0(test) { if (security_bpf(5, 0, 0, 0)) return -1; return 7; }\n'
        commit, build = self.change(old, old.replace("return 7", "return 8"))
        binary = Path(os.environ["KPATCH_TEST_SEPOLICY"])
        runtime = SEToolsRuntime(Path(os.environ["KPATCH_TEST_SETOOLS_PYTHON"]),
                                tuple(Path(item) for item in os.environ.get("KPATCH_TEST_SETOOLS_PATH", "").split(os.pathsep) if item))
        evaluator = SELinuxPolicyEvaluator(binary, enforcing=True, runtime=runtime)
        profile = self.profile.model_copy(update={"policy_file": binary, "policy_sha256": evaluator.policy_sha256,
                                                  "subject_context": "u:r:untrusted_app:s0", "scope": AnalysisScope.DIRECT_APP})
        output, _ = self.run_stage(commit, build, profile=profile, evaluator=evaluator)
        self.assertEqual(output, [], self.decisions)


if __name__ == "__main__":
    unittest.main()
