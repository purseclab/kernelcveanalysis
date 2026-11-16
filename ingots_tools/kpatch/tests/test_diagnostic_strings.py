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

    def test_internal_logger_overrides_block_dependent_calls(self) -> None:
        cases = [
            ('__printk_index_emit', 'pr_info("old")'),
            ('printk_index_wrap', 'pr_info("old")'),
            ('printk', 'pr_info("old")'),
            ('dev_printk_index_emit', 'dev_err(dev, "old")'),
            ('printk_index_subsys_emit', 'dev_err(dev, "old")'),
            ('_dev_err', 'dev_err_once(dev, "old")'),
            ('dev_err', 'dev_err_ratelimited(dev, "old")'),
            ('unlikely', 'pr_info_once("old")'),
            ('__ONCE_LITE_IF', 'pr_info_once("old")'),
            ('___ratelimit', 'pr_info_ratelimited("old")'),
            ('DEFAULT_RATELIMIT_BURST', 'dev_warn_ratelimited(dev, "old")'),
        ]
        for name, call in cases:
            old = f'#define {name}(...) observe(__VA_ARGS__)\nvoid run(void) {{ {call}; }}'
            with self.subTest(name=name, call=call):
                self.assertFalse(self.equivalent(old, old.replace('"old"', '"new"')))

    def test_comments_splices_and_digraphs_cannot_hide_helper_overrides(self) -> None:
        directives = [
            '#/**/define __printk_index_emit(...) observe(__VA_ARGS__)\n',
            '#define/**/__printk_index_emit(...) observe(__VA_ARGS__)\n',
            '%:define __printk_index_emit(...) observe(__VA_ARGS__)\n',
            '#de\\\nfine __printk_index_emit(...) observe(__VA_ARGS__)\n',
            '#define __printk_index_\\\nemit(...) observe(__VA_ARGS__)\n',
            '#undef __printk_index_emit\n',
        ]
        for directive in directives:
            old = directive + 'void run(void) { pr_info("old"); }'
            with self.subTest(directive=directive):
                self.assertFalse(self.equivalent(old, old.replace('"old"', '"new"')))

    def test_backend_c_shadowing_is_distinct_from_ordinary_local_names(self) -> None:
        old = 'void run(int (*_printk)(char *)) { pr_info("old"); }'
        self.assertFalse(self.equivalent(old, old.replace('"old"', '"new"')))
        old = 'typedef int (*logger)(char *); void run(void) { logger first, _printk; pr_info("old"); }'
        self.assertFalse(self.equivalent(old, old.replace('"old"', '"new"')))
        old = 'void run(int file, int line, char *fmt) { pr_info("old"); }'
        self.assertTrue(self.equivalent(old, old.replace('"old"', '"new"')))
        old = '#include "api.h"\nvoid run(void) { int size=sizeof(&_printk); pr_info("old"); }'
        self.assertTrue(self.equivalent(old, old.replace('"old"', '"new"')))

    def test_macro_generated_backend_bindings_are_not_standard_logging(self) -> None:
        sources = [
            '#define CB(name) int (*name)(char *) = custom\nvoid run(void) { CB(_printk); pr_info("old"); }',
            '#define CB(name) int (*name)(char *)\nvoid run(CB(_printk)) { pr_info("old"); }',
            '#define CB int (*_printk)(char *) = custom\nvoid run(void) { CB; pr_info("old"); }',
            '#define BACKEND _printk\nvoid run(void) { int (*BACKEND)(char *)=custom; pr_info("old"); }',
            '#define CB(a,b) int (*a##b)(char *)=custom\nvoid run(void) { CB(_print,k); pr_info("old"); }',
        ]
        for old in sources:
            with self.subTest(source=old):
                self.assertFalse(self.equivalent(old, old.replace('"old"', '"new"')))

    def test_macro_formals_and_literal_operator_text_do_not_create_bindings(self) -> None:
        old = '#define ID(_printk) (_printk)\nvoid run(void) { pr_info("old"); }'
        self.assertTrue(self.equivalent(old, old.replace('"old"', '"new"')))
        old = '#define TEXT "# ## %:"\nvoid run(void) { pr_info("old"); }'
        self.assertTrue(self.equivalent(old, old.replace('"old"', '"new"')))

    def test_plain_pr_override_does_not_override_once_forwarding(self) -> None:
        old = '#define pr_info(...) consume(__VA_ARGS__)\nvoid run(void) { pr_info_once("old"); }'
        self.assertTrue(self.equivalent(old, old.replace('"old"', '"new"')))
        old = '#define unlikely(x) (x)\nvoid run(void) { pr_info("old"); }'
        self.assertTrue(self.equivalent(old, old.replace('"old"', '"new"')))

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
