import random
import shutil
import subprocess
import unittest

from kpatch.filter.config_filter import KernelConfig
from kpatch.filter.cpp_expression import CInteger, evaluate_cpp_expression, parse_cpp_integer
from kpatch.filter.ifdef_filter import _evaluate_condition, get_active_lines


class CppExpressionTests(unittest.TestCase):
    def test_c_precedence_and_comparison_associativity(self) -> None:
        cases = {"!1 == 2": 0, "1 & 2 == 0": 0, "2 < 1 < 1": 1,
                 "1 == 2 == 0": 1, "1 | 2 == 2": 1, "1 << 2 + 1": 8,
                 "3 ^ 1 & 2": 3, "1 + 2 * 3": 7}
        for expression, value in cases.items():
            with self.subTest(expression=expression):
                self.assertEqual(evaluate_cpp_expression(expression), CInteger(value))

    def test_preprocessor_integer_width_and_unsigned_conversions(self) -> None:
        cases = {"0xffffffff > -1": CInteger(1), "2147483647 + 1": CInteger(2147483648),
                 "-1 < 1U": CInteger(0), "1U - 2": CInteger((1 << 64) - 1, True),
                 "~0U": CInteger((1 << 64) - 1, True), "~0U == 0xffffffff": CInteger(0),
                 "0xffffffffffffffff + 1": CInteger(0, True),
                 "-0x8000000000000000 < 0": CInteger(0),
                 "1 << 1U": CInteger(2), "1U << 63": CInteger(1 << 63, True),
                 "0x8000000000000000 >> 63": CInteger(1, True)}
        for expression, value in cases.items():
            with self.subTest(expression=expression):
                self.assertEqual(evaluate_cpp_expression(expression), value)

    def test_negative_division_and_remainder_truncate_toward_zero(self) -> None:
        for expression, value in {"-7 / 3": -2, "7 / -3": -2, "-7 / -3": 2,
                                  "-7 % 3": -1, "7 % -3": 1, "-7 % -3": -1}.items():
            with self.subTest(expression=expression):
                self.assertEqual(evaluate_cpp_expression(expression), CInteger(value))

    def test_literal_spelling_and_suffixes(self) -> None:
        for expression in ("1", "+1", "01", "0x1", "0b1", "1L", "1ll", "1LL"):
            self.assertEqual(parse_cpp_integer(expression), CInteger(1))
        for expression in ("1U", "1u", "1UL", "1llu", "1uLL", "1LLU"):
            self.assertEqual(parse_cpp_integer(expression), CInteger(1, True))
        for expression in ("09", "1lL", "1UU", "1ULU", "1.0", "1e3", "1wb", "1'000"):
            self.assertIsNone(parse_cpp_integer(expression))

    def test_unsupported_or_undefined_expressions_stay_unknown(self) -> None:
        for expression in ("", "UNKNOWN", "0 && UNKNOWN", "1 || UNKNOWN", "'a'", '"a"',
                           "1.0", "(int) 1", "sizeof(int)", "1 ? 2 : 3", "call()", "1, 2",
                           "1 / 0", "1 % 0", "1 << -1", "1 << 64", "-1 << 1", "-2 >> 1",
                           "1 << 63", "9223372036854775807 + 1", "-(-9223372036854775807 - 1)",
                           "(-9223372036854775807 - 1) / -1", "18446744073709551616U",
                           "9223372036854775808", "1); return (0", "1\0"):
            with self.subTest(expression=expression):
                self.assertIsNone(evaluate_cpp_expression(expression))

    def test_logical_short_circuit_does_not_evaluate_invalid_arithmetic(self) -> None:
        self.assertEqual(evaluate_cpp_expression("0 && (1 / 0)"), CInteger(0))
        self.assertEqual(evaluate_cpp_expression("1 || (1 << -1)"), CInteger(1))
        self.assertIsNone(evaluate_cpp_expression("0 && (int)1"))

    def test_input_node_and_depth_budgets(self) -> None:
        self.assertIsNone(parse_cpp_integer("1" * 5000))
        for expression in ("1" * 5000, "+".join("1" for _ in range(300)), "(" * 100 + "1" + ")" * 100):
            self.assertIsNone(evaluate_cpp_expression(expression))

    def test_known_configuration_values_keep_integer_spelling(self) -> None:
        config = KernelConfig('CONFIG_ON=y\nCONFIG_FEATURE=m\nCONFIG_CPUS=64\n'
                              'CONFIG_MASK=0xffffffffffffffffULL\nCONFIG_NEG=-3\nCONFIG_NAME="example"\n')
        for expression in ("CONFIG_CPUS == 64", "CONFIG_MASK + 1 == 0", "-CONFIG_NEG == 3",
                           "CONFIG_FEATURE_MODULE", "defined(CONFIG_CPUS)",
                           "IS_ENABLED(CONFIG_FEATURE)", "IS_BUILTIN(CONFIG_FEATURE_MODULE)",
                           "/* comment */ CONFIG_ON // comment"):
            self.assertIs(_evaluate_condition(expression, config), True, expression)
        for expression in ("CONFIG_FEATURE", "IS_BUILTIN(CONFIG_FEATURE)", "CONFIG_MISSING"):
            self.assertIs(_evaluate_condition(expression, config), False, expression)
        for expression in ("CONFIG_NAME == 0", "IS_ENABLED(CONFIG_CPUS)", "0 && UNKNOWN",
                           "defined(CONFIG_ON)U", "IS_ENABLED(CONFIG_ON)LL"):
            self.assertIsNone(_evaluate_condition(expression, config), expression)

    def test_c_expression_results_control_the_correct_ifdef_branch(self) -> None:
        config = KernelConfig("")
        for condition, selected in (("!1 == 2", 4), ("1 & 2 == 0", 4), ("-7 % 3 == -1", 2), ("-1 < 1U", 4)):
            source = f"#if {condition}\nfirst();\n#else\nsecond();\n#endif\n"
            active = get_active_lines(source, config)
            self.assertIn(selected, active)
            self.assertNotIn(6 - selected, active)


def _differential_cases() -> tuple[tuple[str, CInteger], ...]:
    expressions = ["!1 == 2", "1 & 2 == 0", "2 < 1 < 1", "-7 / 3", "-7 % 3", "-1 < 1U",
                   "0xffffffff > -1", "~0U == 0xffffffff", "1U << 63", "0xffffffffffffffff + 1",
                   "0 && (1 / 0)", "1 || (1 << -1)", "(-9223372036854775807 - 1)"]
    randomizer = random.Random(20261107)
    constants = ("0", "1", "2", "3", "7", "31", "63", "-1", "-3", "1U", "3UL", "017", "0b11",
                 "0xffffffff", "0x8000000000000000", "0xffffffffffffffffULL")
    operators = ("+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>", "==", "!=", "<", "<=", ">", ">=", "&&", "||")

    def expression(depth: int) -> str:
        if depth == 0 or randomizer.randrange(4) == 0:
            return randomizer.choice(constants)
        if randomizer.randrange(4) == 0:
            return randomizer.choice(("+", "-", "!", "~")) + "(" + expression(depth - 1) + ")"
        return "(" + expression(depth - 1) + ") " + randomizer.choice(operators) + " (" + expression(depth - 1) + ")"

    expressions.extend(expression(3) for _ in range(700))
    return tuple((text, value) for text in expressions if (value := evaluate_cpp_expression(text)) is not None)


class CompilerDifferentialTests(unittest.TestCase):
    def compare_compiler(self, compiler: str) -> None:
        cases = _differential_cases()
        self.assertGreater(len(cases), 300)
        source: list[str] = []
        expected: set[str] = set()
        for number, (expression, value) in enumerate(cases):
            literal = "(-9223372036854775807LL - 1LL)" if value.value == -(1 << 63) else str(value.value) + ("ULL" if value.unsigned else "LL")
            for label, condition in (("TRUTH", expression), ("VALUE", f"({expression}) == ({literal})"),
                                     ("SIGNED", f"(({expression}) - ({expression}) - 1) < 0")):
                true = value.value != 0 if label == "TRUTH" else not value.unsigned if label == "SIGNED" else True
                marker = f"{label}_{number}_{int(true)}"
                expected.add(marker)
                source.append(f"#if {condition}\n{label}_{number}_1\n#else\n{label}_{number}_0\n#endif\n")
        result = subprocess.run([compiler, "-std=gnu11", "-E", "-P", "-x", "c", "-"],
                                input="".join(source), capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr[:6000])
        self.assertEqual(set(result.stdout.split()), expected)

    @unittest.skipUnless(shutil.which("gcc"), "GCC not available")
    def test_gcc_preprocessing_truth_value_and_signedness(self) -> None:
        self.compare_compiler("gcc")

    @unittest.skipUnless(shutil.which("clang"), "Clang not available")
    def test_clang_preprocessing_truth_value_and_signedness(self) -> None:
        self.compare_compiler("clang")
