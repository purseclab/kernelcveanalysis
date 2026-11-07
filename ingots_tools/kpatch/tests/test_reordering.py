import unittest

from kpatch.filter.reordering import independent_reorder
from kpatch.filter.syntax import has_opaque_tokens, parse_source


class ReorderingTests(unittest.TestCase):
    def test_adjacent_independent_helpers(self) -> None:
        a = b"static int first(int n) { return n + 1; }\n"
        b = b"static int second(int n) { return n - 1; }\n"
        proof = independent_reorder(a + b, b + a)
        self.assertIsNotNone(proof)
        assert proof is not None
        self.assertEqual(proof.symbols, ("first", "second"))
        self.assertNotIn("n", proof.numeric_names)

    def test_static_inline_struct_helpers_under_same_guard(self) -> None:
        a = b"static inline int first(const struct card *c) { return c->quirks & FLAG_A; }\n"
        b = b"static inline int second(const struct card *c) { return c->quirks & FLAG_B; }\n"
        proof = independent_reorder(b"#ifndef API_H\n#define API_H\n" + a + b + b"#endif\n",
                                    b"#ifndef API_H\n#define API_H\n" + b + a + b"#endif\n")
        self.assertIsNotNone(proof)
        assert proof is not None
        self.assertEqual(proof.numeric_names, frozenset({"FLAG_A", "FLAG_B"}))

    def test_dependencies_include_address_references_and_crossed_middle(self) -> None:
        a = b"static int first(void) { return 1; }\n"
        b = b"static int (*middle(void))(void) { return first; }\n"
        c = b"static int last(void) { return 3; }\n"
        self.assertIsNone(independent_reorder(a + b + c, c + b + a))

    def test_calls_and_recursive_helpers_are_retained(self) -> None:
        a = b"static int first(void) { return external(); }\n"
        b = b"static int second(void) { return 2; }\n"
        self.assertIsNone(independent_reorder(a + b, b + a))

    def test_declarations_directives_and_registration_are_barriers(self) -> None:
        a = b"static int first(void) { return 1; }\n"
        b = b"static int second(void) { return 2; }\n"
        for barrier in (b"int value;\n", b"#define VALUE 1\n", b"#include <other.h>\n",
                        b"REGISTER(first);\n", b"#if ENABLED\n#endif\n"):
            with self.subTest(barrier=barrier):
                self.assertIsNone(independent_reorder(a + barrier + b, b + barrier + a))

    def test_body_value_type_and_statement_order_changes_are_retained(self) -> None:
        a = b"static int first(void) { return 1; }\n"
        b = b"static int second(void) { return 2; }\n"
        for new in (b + a.replace(b"return 1", b"return 3"), b + a.replace(b"int first", b"long first")):
            with self.subTest(new=new):
                self.assertIsNone(independent_reorder(a + b, new))
        self.assertIsNone(independent_reorder(b"void run(void) { a(); b(); }", b"void run(void) { b(); a(); }"))

    def test_position_macros_asm_and_attributes_are_retained(self) -> None:
        b = b"static int second(void) { return 2; }\n"
        for a in (b"static int first(void) { return __LINE__; }\n",
                  b"static int first(void) { return __COUNTER__; }\n",
                  b"static int first(void) { asm(\"nop\"); return 1; }\n",
                  b"static int __init first(void) { return 1; }\n",
                  b"static int first(void) { return __func__[0]; }\n"):
            with self.subTest(a=a):
                self.assertIsNone(independent_reorder(a + b, b + a))

    def test_nonstatic_function_moves_are_retained(self) -> None:
        a = b"int first(void) { return 1; }\n"
        b = b"int second(void) { return 2; }\n"
        self.assertIsNone(independent_reorder(a + b, b + a))

    def test_helpers_introducing_type_definitions_are_retained(self) -> None:
        a = b"static struct item { int value; } *first(void) { return 0; }\n"
        b = b"static int second(struct item *p) { return p->value; }\n"
        self.assertIsNone(independent_reorder(a + b, b + a))

    def test_unchanged_source_is_not_a_reorder(self) -> None:
        text = b"static int first(void) { return 1; }\nstatic int second(void) { return 2; }\n"
        self.assertIsNone(independent_reorder(text, text))

    def test_local_keyword_macro_override_is_retained(self) -> None:
        prefix = b"#define inline SPECIAL\n"
        a = b"static inline int first(void) { return 1; }\n"
        b = b"static inline int second(void) { return 2; }\n"
        self.assertIsNone(independent_reorder(prefix + a + b, prefix + b + a))


class OpaqueTokenTests(unittest.TestCase):
    def test_comments_strings_and_headers_are_not_asm_or_pasting(self) -> None:
        for text in (b"#include <asm/memory.h>\n", b'\n#include "asm/api.h"\n',
                     b'/* asm __func__ ## #x */\nint x;\n', b'char *s = "asm __func__ ##";\n'):
            with self.subTest(text=text):
                self.assertFalse(has_opaque_tokens(parse_source(text)))

    def test_real_asm_implicit_names_and_macro_operators_are_opaque(self) -> None:
        for text in (b'void run(void) { asm("nop"); }', b'void run(void) { __asm__("nop"); }',
                     b'void run(void) { __asm("nop"); }', b'char *run(void) { return __func__; }',
                     b'#define NAME(x) prefix ## x\n', b'#define TEXT(x) #x\n'):
            with self.subTest(text=text):
                self.assertTrue(has_opaque_tokens(parse_source(text)))


if __name__ == "__main__":
    unittest.main()
