import unittest

from kpatch.filter.switch_reordering import independent_switch_reorder


class SwitchReorderingTests(unittest.TestCase):
    def reorder(self, prefix: bytes = b'', tail: bytes = b''):
        a = b'case FIRST: return LEFT;\n'
        b = b'case SECOND: return RIGHT;\n'
        start = prefix + b'int run(int n) {switch(n) {\n'
        end = tail + b'}}\n'
        return independent_switch_reorder(start + a + b + end, start + b + a + end)

    def test_adjacent_terminal_returns_preserve_function_and_dependencies(self) -> None:
        proof = self.reorder()
        self.assertIsNotNone(proof)
        assert proof is not None
        self.assertEqual(proof.symbols, ('run',))
        self.assertEqual(proof.numeric_names, frozenset({'FIRST', 'SECOND', 'LEFT', 'RIGHT'}))
        self.assertIn('case', proof.identifiers)
        self.assertNotIn('case', proof.numeric_names)

    def test_unchanged_complex_default_is_a_barrier(self) -> None:
        self.assertIsNotNone(self.reorder(tail=b'default: warn(); return -1;\n'))

    def test_fallthrough_and_nonreturn_arms_do_not_move(self) -> None:
        prefix = b'int run(int n) {switch(n) {'
        end = b'}}'
        for a in (b'case FIRST: n++;', b'case FIRST: break;', b'case FIRST:', b'case FIRST: goto elsewhere;'):
            b = b'case SECOND: return 2;'
            with self.subTest(a=a):
                self.assertIsNone(independent_switch_reorder(prefix+a+b+end, prefix+b+a+end))

    def test_declarations_and_directives_are_barriers(self) -> None:
        a = b'case FIRST: return 1;\n'
        b = b'case SECOND: return 2;\n'
        start, end = b'int run(int n) {switch(n) {\n', b'}}\n'
        for barrier in (b'int value;\n', b'#define VALUE 1\n', b'#if ON\n#endif\n', b'#include "state.h"\n'):
            with self.subTest(barrier=barrier):
                self.assertIsNone(independent_switch_reorder(start+a+barrier+b+end, start+b+barrier+a+end))

    def test_complex_arms_cannot_be_crossed_by_a_return_run(self) -> None:
        a, b = b'case A:return 1;', b'case B:return 2;'
        barrier = b'case C: warn(); return 3;'
        start, end = b'int f(int n){switch(n){', b'}}'
        self.assertIsNone(independent_switch_reorder(start+a+b+barrier+end, start+barrier+b+a+end))

    def test_a_preceding_arm_can_fall_through_to_the_first_return(self) -> None:
        a, b = b'case 1:return 10;', b'case 2:return 20;'
        start, end = b'int f(int n){switch(n){', b'}return 0;}'
        for predecessor in (b'case 0:n++;', b'case 0:if(n<0)return 3;', b'default:n++;'):
            with self.subTest(predecessor=predecessor):
                self.assertIsNone(independent_switch_reorder(start+predecessor+a+b+end, start+predecessor+b+a+end))

    def test_unsupported_terminal_predecessors_still_retain(self) -> None:
        a, b = b'case 1:return 10;', b'case 2:return 20;'
        start, end = b'int f(int n){switch(n){case 0:warn();return 3;', b'}return 0;}'
        self.assertIsNone(independent_switch_reorder(start+a+b+end, start+b+a+end))

    def test_case_ranges_stacked_labels_and_local_statement_expressions_retain(self) -> None:
        for a in (b'case 1 ... 3: return 1;', b'case 1: case 2: return 1;', b'case 1: return ({int x=1;x;});'):
            b = b'case 4: return 2;'
            start, end = b'int f(int n){switch(n){', b'}}'
            with self.subTest(a=a):
                self.assertIsNone(independent_switch_reorder(start+a+b+end, start+b+a+end))

    def test_changed_condition_return_expression_and_other_code_retain(self) -> None:
        start = b'int f(int n){switch(n){'
        a, b, end = b'case 1:return 1;', b'case 2:return 2;', b'}}'
        old, new = start+a+b+end, start+b+a+end
        for changed in (new.replace(b'switch(n)', b'switch(n+1)'), new.replace(b'return 2', b'return 3'), b'int added;'+new):
            with self.subTest(changed=changed):
                self.assertIsNone(independent_switch_reorder(old, changed))

    def test_return_types_cannot_introduce_names_for_later_arms(self) -> None:
        prefix, suffix = b'enum {E=2}; int f(int n){switch(n){', b'}return 0;}'
        a, b = b'case 1:return sizeof(enum{E=1});', b'case 2:return E;'
        self.assertIsNone(independent_switch_reorder(prefix+a+b+suffix, prefix+b+a+suffix))
        for definition in (b'struct T{int x;}', b'union T{int x;}'):
            with self.subTest(definition=definition):
                a = b'case 1:return sizeof(' + definition + b');'
                self.assertIsNone(independent_switch_reorder(prefix+a+b+suffix, prefix+b+a+suffix))

    def test_location_macros_pragmas_and_asm_are_not_erased(self) -> None:
        for prefix in (b'int line=__LINE__;\n', b'int counter=__COUNTER__;\n', b'_Pragma("pack(1)")\n'):
            with self.subTest(prefix=prefix):
                self.assertIsNone(self.reorder(prefix=prefix))
        start, end = b'int f(int n){switch(n){', b'}}'
        a, b = b'case 1:return ({asm("nop");1;});', b'case 2:return 2;'
        self.assertIsNone(independent_switch_reorder(start+a+b+end, start+b+a+end))

    def test_unchanged_order_and_duplicate_case_spellings_retain(self) -> None:
        text = b'int f(int n){switch(n){case A:return 1;case B:return 2;}}'
        self.assertIsNone(independent_switch_reorder(text, text))
        self.assertIsNone(independent_switch_reorder(text.replace(b'case B', b'case A'), text.replace(b'case B', b'case A')))
