import unittest

from kpatch.filter.binding_renames import BindingKind, compare_bindings, function_value_references


class BindingRenameTests(unittest.TestCase):
    def test_leaf_function_values_resolve_parameters_and_locals(self) -> None:
        for source in (b'int leaf(void) { return 7; }',
                       b'int leaf(int x) { int y=x+1; { int x=y; y+=x; } return y+x; }',
                       b'int *leaf(int *x) { int *value=x; return value; }',
                       b'int leaf(int n, int a[n]) { return a[0]; }',
                       b'int leaf(int n) { { int n[n]; } return n; }'):
            with self.subTest(source=source):
                facts = function_value_references(source)
                self.assertIsNotNone(facts)
                assert facts is not None
                self.assertEqual(facts.unbound_names, frozenset())
                self.assertFalse(facts.has_calls)

    def test_function_calls_and_uncalled_helper_values_remain_visible(self) -> None:
        for body, called in ((b'return helper();', True), (b'return (void *)helper;', False)):
            with self.subTest(body=body):
                facts = function_value_references(b'void *leaf(void) { ' + body + b' }')
                self.assertIsNotNone(facts)
                assert facts is not None
                self.assertEqual(facts.unbound_names, {'helper'})
                self.assertEqual(facts.has_calls, called)

    def test_later_shadow_cannot_capture_an_earlier_nonlocal_value(self) -> None:
        for source in (b'int *leaf(void) { int *p=helper; int helper=0; return p; }',
                       b'int leaf(int a[extent], int extent) { return 0; }',
                       b'int leaf(void) { int a[extent]; int extent=1; return 0; }'):
            with self.subTest(source=source):
                facts = function_value_references(source)
                self.assertIsNotNone(facts)
                assert facts is not None
                self.assertTrue(facts.unbound_names)

    def test_unsupported_function_bindings_do_not_certify_a_leaf(self) -> None:
        for source in (b'int leaf(int x, int x) { return x; }',
                       b'int leaf(int (*fn)(void)) { return fn(); }',
                       b'int (*orphan(void))(int register_site){return (int(*)(int))register_site;}',
                       b'int leaf(void) { asm(""); return 0; }',
                       b'int leaf(void) { int nested(void) { return 0; } return 0; }'):
            with self.subTest(source=source):
                self.assertIsNone(function_value_references(source))

    def test_prototype_names_have_distinct_nested_scopes(self) -> None:
        old = b'int run(struct device *dev, int (*fn)(struct device *dev));\n'
        new = b'int run(struct device *parent, int (*fn)(struct device *dev));\n'
        proof = compare_bindings(old, new)
        self.assertIsNotNone(proof)
        assert proof is not None
        self.assertFalse(proof.lossy)
        self.assertEqual(proof.names, frozenset({'dev', 'parent'}))

    def test_unrelated_global_spelling_does_not_bind_prototype_name(self) -> None:
        old = b'int dev; int run(int dev); int other(void) { return dev; }\n'
        new = old.replace(b'run(int dev)', b'run(int parent)')
        self.assertIsNotNone(compare_bindings(old, new))

    def test_prototype_types_bounds_and_attributes_stay_observable(self) -> None:
        pairs = [(b'int run(int old);', b'int run(long renamed);'),
                 (b'int run(int n, int a[n]);', b'int run(int m, int a[n]);'),
                 (b'int run(int n, int a[4]);', b'int run(int n, int a[8]);'),
                 (b'int run(int old) __attribute__((annotate("a")));',
                  b'int run(int renamed) __attribute__((annotate("a")));')]
        for old, new in pairs:
            with self.subTest(old=old):
                self.assertIsNone(compare_bindings(old, new))

    def test_function_parameter_needs_explicit_body_mode(self) -> None:
        old = b'int run(int old) { return old; }'
        new = b'int run(int renamed) { return renamed; }'
        self.assertIsNone(compare_bindings(old, new))
        proof = compare_bindings(old, new, bodies=True)
        self.assertIsNotNone(proof)
        assert proof is not None
        self.assertTrue(proof.lossy)
        self.assertEqual(proof.renames[0].kind, BindingKind.PARAMETER)

    def test_local_shadowing_and_sibling_names_resolve_separately(self) -> None:
        old = b'int run(int x) { int n=x; { int x=2; n+=x; } return n+x; }'
        new = b'int run(int input) { int sum=input; { int x=2; sum+=x; } return sum+input; }'
        self.assertIsNotNone(compare_bindings(old, new, bodies=True))
        self.assertIsNone(compare_bindings(old, new.replace(b'sum+=x', b'sum+=input'), bodies=True))

    def test_binding_capture_is_not_an_equivalent_rename(self) -> None:
        pairs = [(b'int run(int x) { int y=2; return x+y; }',
                  b'int run(int y) { int y=2; return y+y; }'),
                 (b'int global; int run(void) { int old=2; return old+global; }',
                  b'int global; int run(void) { int global=2; return global+global; }'),
                 (b'int run(int x) { { int y=2; } return x; }',
                  b'int run(int input) { { int input=2; } return input; }')]
        for old, new in pairs[:2]:
            with self.subTest(old=old):
                self.assertIsNone(compare_bindings(old, new, bodies=True))
        # A name in a nested block is out of scope at the final return.
        self.assertIsNotNone(compare_bindings(*pairs[2], bodies=True))

    def test_for_initializer_has_its_own_scope(self) -> None:
        old = b'int i; int run(void) { int sum=0; for(int i=0;i<2;i++) sum+=i; return sum+i; }'
        new = b'int i; int run(void) { int total=0; for(int j=0;j<2;j++) total+=j; return total+i; }'
        self.assertIsNotNone(compare_bindings(old, new, bodies=True))
        self.assertIsNone(compare_bindings(old, new.replace(b'total+i', b'total+j'), bodies=True))

    def test_initializers_resolve_after_the_declarator(self) -> None:
        old = b'int run(int x) { int n=x, next=n+1; return next; }'
        new = b'int run(int input) { int value=input, result=value+1; return result; }'
        self.assertIsNotNone(compare_bindings(old, new, bodies=True))

    def test_member_and_global_changes_are_not_local_renames(self) -> None:
        pairs = [(b'int run(int x) { return obj.x+x; }', b'int run(int y) { return obj.y+y; }'),
                 (b'int run(int x) { return first(x); }', b'int run(int y) { return second(y); }'),
                 (b'int run(int x) { return x+1; }', b'int run(int y) { return y+2; }')]
        for old, new in pairs:
            with self.subTest(old=old):
                self.assertIsNone(compare_bindings(old, new, bodies=True))

    def test_extern_symbol_changes_are_not_local_renames(self) -> None:
        self.assertIsNone(compare_bindings(b'int f(void){extern int a;return a;}',
                                           b'int f(void){extern int b;return b;}', bodies=True))

    def test_typedef_capture_is_retained(self) -> None:
        pairs = [(b'typedef int T; int f(int x, T y);', b'typedef int T; int f(int T, T y);'),
                 (b'typedef int T; int f(char x){return sizeof(T);}',
                  b'typedef int T; int f(char T){return sizeof(T);}')]
        for old, new in pairs:
            with self.subTest(old=old):
                self.assertIsNone(compare_bindings(old, new, bodies=True))

    def test_renames_cannot_create_duplicate_declarations(self) -> None:
        pairs = [(b'int f(int x, int y);', b'int f(int y, int y);'),
                 (b'int f(int x) { int y=2; return y; }', b'int f(int y) { int y=2; return y; }'),
                 (b'int f(void) { int x=1, y=2; return x; }', b'int f(void) { int y=1, y=2; return y; }')]
        for old, new in pairs:
            with self.subTest(old=old):
                self.assertIsNone(compare_bindings(old, new, bodies=True))

    def test_unsupported_body_forms_stay_unnormalized(self) -> None:
        pairs = [(b'int run(int x) { asm(""); return x; }', b'int run(int y) { asm(""); return y; }'),
                 (b'int run(int x) {\n#ifdef ON\nreturn x;\n#endif\n}',
                  b'int run(int y) {\n#ifdef ON\nreturn y;\n#endif\n}'),
                 (b'int run(int x) { int nested(void) { return x; } return nested(); }',
                  b'int run(int y) { int nested(void) { return y; } return nested(); }')]
        for old, new in pairs:
            with self.subTest(old=old):
                self.assertIsNone(compare_bindings(old, new, bodies=True))

    def test_btf_debug_names_are_only_the_declared_policy_exemption(self) -> None:
        old = b'int run(int old); const char *name="old";'
        new = b'int run(int renamed); const char *name="renamed";'
        self.assertIsNone(compare_bindings(old, new))

    def test_reserved_btf_parameter_annotations_are_not_erased(self) -> None:
        self.assertIsNone(compare_bindings(b'int kfunc(void *buf, int size);',
                                           b'int kfunc(void *buf, int size__sz);'))


if __name__ == '__main__':
    unittest.main()
