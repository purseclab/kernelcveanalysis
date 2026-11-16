"""Functional registration effects must survive runtime-only policy masking."""

import unittest

from kpatch.filter.policy_source import emission_sensitive_functions
import test_policy_seccomp_entry as helpers


_ASSEMBLY = ('661: nop\\n662:\\n.pushsection .altinstructions,\\"a\\"\\n'
             '.long 661b - .\\n.long boot_callback - .\\n.hword 32768\\n'
             '.byte 662b-661b\\n.byte 0\\n.popsection\\n')
_HEADER = 'static inline void register_site(void){asm volatile("' + _ASSEMBLY + '");}\n'
_PREFIX = ('#include <asm/syscall_wrapper.h>\nint boot_state;\n'
           'void boot_callback(void*a,void*b,void*c,int n){boot_state=1;}\n'
           '#include "registration.h"\n')


class PolicyEmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        helpers.SeccompEntryIntegrationTests.setUpClass()

    def setUp(self) -> None:
        self.case = helpers.SeccompEntryIntegrationTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)

    def assert_registration_retained(self, before_body: str, after_body: str, *, header: str = _HEADER) -> None:
        case = self.case
        old = _PREFIX + 'SYSCALL_DEFINE1(test,int,value){' + before_body + '}\n'
        new = _PREFIX + 'SYSCALL_DEFINE1(test,int,value){' + after_body + '}\n'
        commit, build = case.change(old, new, before={'registration.h': header})
        output, view = case.run_stage(commit, build)
        self.assertEqual(len(output), 1, case.decisions)
        self.assertEqual(view.edit_masks, ())
        self.assertEqual(view.code_masks, ())

    def test_new_call_cannot_hide_a_header_alternative_callback_registration(self) -> None:
        self.assert_registration_retained('return 7;', 'register_site();return 7;')

    def test_unchanged_call_under_changed_constant_condition_is_retained(self) -> None:
        self.assert_registration_retained('if(0)register_site();return 7;', 'if(1)register_site();return 7;')

    def test_unchanged_call_under_changed_local_constant_is_retained(self) -> None:
        self.assert_registration_retained('int enabled=0;if(enabled)register_site();return 7;',
                                          'int enabled=1;if(enabled)register_site();return 7;')

    def test_sectioned_header_storage_is_a_functional_effect(self) -> None:
        header = ('void boot_ctor(void);\nstatic inline void register_site(void){'
                  'static void(*entry)(void) __attribute__((section(".init_array")))=boot_ctor;'
                  'asm volatile(""::"r"(&entry));}\n')
        self.assert_registration_retained('int enabled=0;if(enabled)register_site();return 7;',
                                          'int enabled=1;if(enabled)register_site();return 7;', header=header)

    def test_transitive_header_registration_is_retained(self) -> None:
        header = _HEADER + 'static inline void middle(void){register_site();}\n'
        self.assert_registration_retained('if(0)middle();return 7;', 'if(1)middle();return 7;', header=header)

    def test_unrelated_registered_helper_does_not_block_pure_denied_body(self) -> None:
        case = self.case
        old = _PREFIX + 'void independent(void){register_site();}\nSYSCALL_DEFINE1(test,int,value){return 7;}\n'
        commit, build = case.change(old, old.replace('return 7', 'return 8'), before={'registration.h': _HEADER})
        output, _ = case.run_stage(commit, build)
        self.assertEqual(output, [], case.decisions)

    def test_known_local_alternative_patch_metadata_does_not_block_denied_body(self) -> None:
        header = _HEADER.replace('boot_callback', 'alt_cb_patch_nops')
        self.assert_registration_pure_metadata(header)

    def assert_registration_pure_metadata(self, header: str) -> None:
        case = self.case
        old = _PREFIX + 'SYSCALL_DEFINE1(test,int,value){register_site();return 7;}\n'
        commit, build = case.change(old, old.replace('return 7', 'return 8'), before={'registration.h': header})
        output, _ = case.run_stage(commit, build)
        self.assertEqual(output, [], case.decisions)


if __name__ == '__main__':
    unittest.main()
