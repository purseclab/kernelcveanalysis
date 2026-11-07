import unittest

from kpatch.filter.diagnostic_strings import normalize_diagnostic_strings
from kpatch.filter.whitespace.c_lexer import tokenize_c_source


class DiagnosticStringTests(unittest.TestCase):
    def equivalent(self, old: str, new: str) -> bool:
        a = normalize_diagnostic_strings(old.encode())
        b = normalize_diagnostic_strings(new.encode())
        return tokenize_c_source(a.contents.decode()) == tokenize_c_source(b.contents.decode())

    def test_standard_logging_wording_and_prefixes(self) -> None:
        for call in ('pr_err("old: %d\\n", err)', 'dev_warn_ratelimited(dev, "old: %d\\n", err)',
                     'printk(KERN_ERR "old: " "%d\\n", err)'):
            old = f"void run(void) {{ {call}; }}\n"
            with self.subTest(call=call):
                self.assertTrue(self.equivalent(old, old.replace('old:', 'new wording:')))
        old = '#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt\nvoid run(void) { pr_info("old\\n"); }\n'
        self.assertTrue(self.equivalent(old, old.replace('"old', '"new')))

    def test_formats_controls_and_arguments_remain_observable(self) -> None:
        changes = [('%p', '%px'), ('%pOFn', '%pOFP'), ('%d', '%u'), ('%s', '%.3s'),
                   ('%*ph', '%*phC'), ('%lu', '%llu'), ('%%', '%d'), ('%s', '%p'),
                   ('hello', 'hello\\n'), ('hello\\n', 'hello\\n\\n'), ('hello\\t', 'hello'),
                   ('%s\\n%d', '%s%d\\n'), ('%2d', '%3d'), ('%s', '%.*s')]
        for before, after in changes:
            with self.subTest(before=before, after=after):
                self.assertFalse(self.equivalent(f'void run(void) {{ pr_err("{before}", x, y); }}',
                                                f'void run(void) {{ pr_err("{after}", x, y); }}'))
        self.assertFalse(self.equivalent('void run(void) { pr_err("old %d", x); }',
                                        'void run(void) { pr_err("new %d", y); }'))

    def test_unrecognized_or_consumed_strings_remain_observable(self) -> None:
        calls = ['pr_debug("old")', 'dev_dbg(dev, "old")', 'trace_printk("old")',
                 'seq_printf(seq, "old")', 'sysfs_emit(buf, "old")', 'snprintf(buf, n, "old")',
                 'panic("old")', 'WARN(1, "old")', 'strcmp(value, "old")',
                 'wrapper("old")', 'return printk("old")', 'count = printk("old")',
                 'count = ({ printk("old"); })', '(void) printk("old")',
                 'pr_err("%s", "old")', 'pr_err(flag ? "old" : "other")']
        for call in calls:
            old = f'int run(void) {{ {call}; }}'
            with self.subTest(call=call):
                self.assertFalse(self.equivalent(old, old.replace('"old"', '"new"')))

    def test_macro_overrides_and_shadowing_block_exemption(self) -> None:
        prefixes = ['#define pr_err(fmt) consume(fmt)\n', '#undef pr_err\n',
                    '#define pr_fmt(fmt) sizeof(fmt)\n', '#define pr_fmt(fmt) "%" fmt\n',
                    '#define pr_fmt(fmt) "%s" fmt, __func__\n',
                    '#define KBUILD_MODNAME "%"\n#define pr_fmt(fmt) KBUILD_MODNAME fmt\n',
                    'static void pr_err(char *msg) { consume(msg); }\n']
        for prefix in prefixes:
            old = prefix + 'void run(void) { pr_err("old"); }'
            with self.subTest(prefix=prefix):
                self.assertFalse(self.equivalent(old, old.replace('"old"', '"new"')))

    def test_unsupported_literals_and_macro_arguments_are_retained(self) -> None:
        formats = ['L"old"', '"old\\x01"', '"old\\001"', '"old\\0"',
                   '"old\\\n text"', '"old %q"', '"old %n"', 'FMT "old"']
        for value in formats:
            old = f'void run(void) {{ pr_err({value}); }}'
            with self.subTest(value=value):
                self.assertFalse(self.equivalent(old, old.replace('old', 'new')))
        old = '#define LOG() pr_err("old")\nvoid run(void) { LOG(); }'
        self.assertFalse(self.equivalent(old, old.replace('"old"', '"new"')))

    def test_log_level_prefix_is_preserved_and_local_override_blocks_exemption(self) -> None:
        old = 'void run(void) { printk(KERN_ERR "old"); }'
        self.assertFalse(self.equivalent(old, old.replace('KERN_ERR "old"', 'KERN_INFO "new"')))
        old = '#define KERN_ERR "%"\nvoid run(void) { printk(KERN_ERR "s", ptr); }'
        self.assertFalse(self.equivalent(old, old.replace('"s"', '"p"')))

    def test_untouched_code_and_physical_lines_survive_normalization(self) -> None:
        source = b'void run(void) {\n pr_err("old "\n "%d\\n", err);\n do_work();\n}\n'
        result = normalize_diagnostic_strings(source)
        self.assertEqual(result.contents.count(b'\n'), source.count(b'\n'))
        self.assertIn(b'do_work();', result.contents)
        self.assertEqual(len(result.literals), 1)


if __name__ == "__main__":
    unittest.main()
