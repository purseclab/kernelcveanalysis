"""Compiler-backed caller scope and accepted metadata differences."""

import unittest

from kpatch.filter.policy_clang import TranslationUnitFacts
from kpatch.filter.policy_source import _noncalling_arm64_assembly

import test_policy_analysis as analysis_helpers
import test_policy_entry_review as entry_helpers
import test_policy_seccomp_entry as seccomp_helpers


class ScopedPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        analysis_helpers.PolicyAnalysisTests.setUpClass()
        entry_helpers.PolicyEntryReviewTests.setUpClass()
        seccomp_helpers.SeccompEntryIntegrationTests.setUpClass()

    def entries(self) -> entry_helpers.PolicyEntryReviewTests:
        case = entry_helpers.PolicyEntryReviewTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        return case

    def analysis(self) -> analysis_helpers.PolicyAnalysisTests:
        case = analysis_helpers.PolicyAnalysisTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        return case

    def test_unrelated_header_callback_and_arm64_atomics_do_not_block_entry(self) -> None:
        case = self.entries()
        header = case.root / 'independent.h'
        header.write_text('static inline void callback(void (*fn)(void *), void *p) {fn(p);}\n'
                          'static inline void barrier(void) {asm volatile("dmb ish");}\n')
        facts = case.analyze('#include "independent.h"\n'
                             'void another(void (*fn)(void *), void *p) {callback(fn,p);barrier();}\n')
        self.assertTrue(facts.indirect_target_coverage_complete)
        self.assertEqual(case.excluded(facts), ('__do_sys_test',))

    def test_compatible_header_callback_remains_a_barrier(self) -> None:
        case = self.entries()
        header = case.root / 'compatible.h'
        header.write_text('static inline long callback(long (*fn)(const struct pt_regs *), '
                          'const struct pt_regs *p) {return fn(p);}\n')
        facts = case.analyze('#include "compatible.h"\n')
        self.assertIn('c:@F@__arm64_sys_test', facts.indirect_call_targets)
        self.assertEqual(case.excluded(facts), ())

    def test_raw_encoded_calls_and_unrecognized_assembly_remain_barriers(self) -> None:
        case = self.entries()
        for assembly in ('.inst 0xd63f0000', '.word 0x94000000', 'blr x0', 'bl another',
                         '.include "generated.S"', '.macro hidden; bl another; .endm; hidden',
                         '.inst (0xd503201f & 0) | 0xd63f0000'):
            with self.subTest(assembly=assembly):
                text = assembly.replace('"', '\\"')
                facts = case.analyze('void another(void) {asm volatile("' + text + '");}\n')
                self.assertEqual(case.excluded(facts), ())

    def test_local_branch_data_records_and_system_encoding_are_noncalling(self) -> None:
        case = self.entries()
        assembly = ('1: ldxr %0, [%1]; cbnz %0, 1b; .inst 0xd503227f; '
                    '.pushsection __ex_table,"a"; .long 1b - .; .popsection')
        escaped = assembly.replace('"', '\\"')
        facts = case.analyze('void another(long *p) {long value; asm volatile("' + escaped
                             + '" : "=&r"(value) : "r"(p));}\n')
        self.assertEqual(case.excluded(facts), ('__do_sys_test',))

    def test_legacy_facts_cannot_supply_scoped_indirect_coverage(self) -> None:
        case = self.entries()
        facts = case.analyze()
        legacy = facts.model_dump()
        legacy.pop('indirect_target_coverage_complete')
        legacy.pop('indirect_call_targets')
        self.assertEqual(case.excluded(TranslationUnitFacts.model_validate(legacy)), ())

    def test_indirect_type_comparison_budget_fails_closed(self) -> None:
        case = self.entries()
        unrelated = ''.join('int leaf_' + str(index) + '(void *p) {return 0;}\n' for index in range(401))
        callbacks = ''.join('struct tag_' + str(index) + ';\nvoid callback_' + str(index)
                            + '(void (*fn)(struct tag_' + str(index) + ' *), struct tag_'
                            + str(index) + ' *p) {fn(p);}\n' for index in range(251))
        facts = case.analyze(unrelated + callbacks)
        self.assertTrue(facts.complete)
        self.assertTrue(facts.indirect_call_coverage_complete)
        self.assertFalse(facts.indirect_target_coverage_complete)
        self.assertEqual(case.excluded(facts), ())

    def test_static_helper_closure_is_per_translation_unit_not_repository(self) -> None:
        case = self.analysis()
        old = ('static int helper(void) {int value=7; return value;}\n'
               'SYSCALL_DEFINE0(test) {if(!capable(21)) return -1; return helper();}\n')
        commit, build = case.change(old, old.replace('value=7', 'value=8'),
                                    before={'unrelated.c': 'int unrelated(void) {return 9;}\n'})
        output, _ = case.run_stage(commit, build)
        self.assertEqual(output, [], case.decisions)

    def test_static_helper_compatible_indirect_call_retains(self) -> None:
        case = self.analysis()
        old = ('static int helper(void) {return 7;}\n'
               'int callback(int (*fn)(void)) {return fn();}\n'
               'SYSCALL_DEFINE0(test) {if(!capable(21)) return -1; return helper();}\n')
        commit, build = case.change(old, old.replace('return 7', 'return 8'))
        case.assert_retained(commit, build)

    def test_capability_root_with_hidden_assembly_caller_retains(self) -> None:
        case = self.analysis()
        old = ('SYSCALL_DEFINE0(test) {if(!capable(21)) return -1; return 7;}\n'
               'void outside(void) {asm volatile("call __do_sys_test");}\n')
        commit, build = case.change(old, old.replace('return 7', 'return 8'))
        case.assert_retained(commit, build)

    def test_seccomp_denied_entry_closes_private_helper_chain(self) -> None:
        case = seccomp_helpers.SeccompEntryIntegrationTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        old = ('#include <asm/syscall_wrapper.h>\n'
               'static int leaf(void) {int result=7; return result;}\n'
               'static int helper(void) {return leaf();}\n'
               'SYSCALL_DEFINE1(test, int, value) {return helper();}\n')
        commit, build = case.change(old, old.replace('result=7', 'result=8'))
        output, _ = case.run_stage(commit, build)
        self.assertEqual(output, [], case.decisions)

    def test_seccomp_private_helper_with_second_entry_remains_reachable(self) -> None:
        case = seccomp_helpers.SeccompEntryIntegrationTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        old = ('#include <asm/syscall_wrapper.h>\n'
               'static int helper(void) {return 7;}\n'
               'SYSCALL_DEFINE1(test, int, value) {return helper();}\n'
               'int other(void) {return helper();}\n')
        commit, build = case.change(old, old.replace('return 7', 'return 8'))
        case.assert_retained(commit, build)

    def test_btf_enabled_capability_proof_records_ignored_metadata(self) -> None:
        case = self.analysis()
        case.config.write_text(case.config.read_text() + 'CONFIG_DEBUG_INFO_BTF=y\n')
        old = 'SYSCALL_DEFINE0(test) {if(!capable(21)) return -1; return 7;}\n'
        commit, build = case.change(old, old.replace('return 7', 'return 8'))
        output, _ = case.run_stage(commit, build)
        self.assertEqual(output, [], case.decisions)
        self.assertIn('btf_and_debug_metadata', case.decisions[0].ignored_differences)
        self.assertEqual(case.decisions[0].reachability_model,
                         'ordinary_linux_entries_and_type_compatible_c_calls')


class AssemblyClassifierTests(unittest.TestCase):
    def test_comment_strings_and_raw_code_cannot_hide_a_transfer(self) -> None:
        for text in ('nop; bl target', 'nop /*;*/; blr x1', 'nop // comment\n blr x1',
                     '.pushsection .text,"ax"; .word 0xd63f0000; .popsection',
                     '.pushsection .text,"a"; .word 0xd63f0000; .popsection',
                     '.pushsection .init.text,"a"; .word 0xd63f0000; .popsection',
                     '.pushsection .altinstr_replacement,"a"; .word 0xd63f0000; .popsection',
                     '.pushsection unknown_section,"a"; .word 0xd63f0000; .popsection',
                     '.inst (0xd503201f | (0)) & 0; blr x0', '.byte 0, 0, 0x3f, 0xd6',
                     'cbnz x0, elsewhere', 'b .+4', '.org .+4,0x14', 'nop /* unterminated',
                     '.section .rodata,"a"; .section .text; .subsection 1; .previous; .word 0x94000000',
                     '.if 0; .section .rodata,"a"; .endif; .word 0x94000000',
                     '.macro mrs_s; .section .rodata,"a"; .endm; .word 0x94000000'):
            with self.subTest(text=text):
                self.assertFalse(_noncalling_arm64_assembly(text))

    def test_scoped_numeric_labels_and_data_strings_are_not_calls(self) -> None:
        for text in ('nop', '1: add x0,x0,1; cbnz x0,1b', 'cbnz x0,.',
                     '.inst (0xd5000000 | ((3)<<16) | (4))',
                     '.pushsection .rodata,"a"; .string "bl fake; x"; .popsection'):
            with self.subTest(text=text):
                self.assertTrue(_noncalling_arm64_assembly(text))


if __name__ == '__main__':
    unittest.main()
