from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from kpatch.filter.policy_clang import (
    ClangAnalyzer, ClangByteExclusion, ClangCall, ClangMetadataSpan, ClangToolchain, ClangUnavailable, CompileCommand,
    SourceOverlay, TranslationUnitFacts,
)


class PolicyClangTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            cls.binary = ClangToolchain.discover().build()
        except ClangUnavailable as error:
            raise unittest.SkipTest(str(error)) from error

    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "unit.c"
        self.analyzer = ClangAnalyzer(self.binary)
        self.addCleanup(self.analyzer.close)

    def analyze(self, body: str) -> TranslationUnitFacts:
        self.source.write_text('int capable(int); int security_bpf(int); int owner(void); void target(void);\n' + body)
        result = self.analyzer.analyze(CompileCommand.for_source(self.source))
        self.assertTrue(result.complete, result.diagnostics)
        return result

    def call(self, result: TranslationUnitFacts, name: str = "target", *, function: str = "run") -> ClangCall:
        f = next(f for f in result.functions if f.name == function)
        return next(call for call in f.calls if call.callee == name)

    def analyze_syscall_table(self, body: str, *, compat: bool = False,
                              target: str = "aarch64-linux-gnu") -> TranslationUnitFacts:
        source = self.root / 'arch' / 'arm64' / 'kernel' / ('sys32.c' if compat else 'sys.c')
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text('struct pt_regs { long value; };\n'
                          'typedef long (*syscall_fn_t)(const struct pt_regs *);\n'
                          'long ni(const struct pt_regs *); long native(const struct pt_regs *);\n'
                          'long compat(const struct pt_regs *); long final(const struct pt_regs *);\n' + body)
        return self.analyzer.analyze(CompileCommand.for_source(source, flags=('--target=' + target,)))

    def test_native_syscall_table_resolves_designators_fillers_and_macro_aliases(self) -> None:
        result = self.analyze_syscall_table(
            '#define __arm64_sys_personality __arm64_sys_arm64_personality\n'
            'long __arm64_sys_arm64_personality(const struct pt_regs *);\n'
            '#define __SYSCALL(nr, sym) [nr] = __arm64_##sym,\n'
            '#define __SYSCALL_WITH_COMPAT(nr, sym, compat) __SYSCALL(nr, sym)\n'
            'const syscall_fn_t sys_call_table[6] = { [0 ... 5] = ni,\n'
            ' __SYSCALL_WITH_COMPAT(1, sys_personality, compat_sys_personality)\n'
            ' [2] = native, [2] = final, [4] = &native };\n')
        self.assertTrue(result.complete, result)
        table, = result.syscall_tables
        self.assertTrue(table.complete, table)
        self.assertEqual(table.status_reason, 'complete')
        self.assertEqual(table.audit_arch, 0xC00000B7)
        self.assertEqual(table.source_path.name, 'sys.c')
        self.assertEqual([binding.number for binding in table.bindings], list(range(6)))
        self.assertEqual([binding.callee_name for binding in table.bindings],
                         ['ni', '__arm64_sys_arm64_personality', 'final', 'ni', 'native', 'ni'])
        self.assertEqual(table.bindings[0].callee_usr, table.bindings[5].callee_usr)
        for binding in table.bindings:
            self.assertTrue(binding.callee_usr)
            self.assertIn(binding.callee_usr, {reference.usr for reference in result.address_taken})

    def test_compat_syscall_table_selects_compiler_resolved_compat_macro(self) -> None:
        result = self.analyze_syscall_table(
            '#define __SYSCALL(nr, sym) [nr] = sym,\n'
            '#define __SYSCALL_WITH_COMPAT(nr, sym, compat) __SYSCALL(nr, compat)\n'
            'const syscall_fn_t compat_sys_call_table[4] = { [0 ... 3] = ni,\n'
            ' __SYSCALL_WITH_COMPAT(2, native, compat) };\n', compat=True)
        self.assertTrue(result.complete, result)
        table, = result.syscall_tables
        self.assertTrue(table.complete, table)
        self.assertEqual(table.audit_arch, 0x40000028)
        self.assertEqual(table.name, 'compat_sys_call_table')
        self.assertEqual([binding.callee_name for binding in table.bindings], ['ni', 'ni', 'compat', 'ni'])

    def test_syscall_table_rejects_mutability_casts_indirection_and_null_slots(self) -> None:
        fixtures = (
            'syscall_fn_t sys_call_table[2] = {ni, native};',
            'static const syscall_fn_t sys_call_table[2] = {ni, native};',
            'const syscall_fn_t sys_call_table[2] = {ni, (syscall_fn_t)native};',
            'const syscall_fn_t saved = native; const syscall_fn_t sys_call_table[2] = {ni, saved};',
            'const syscall_fn_t sys_call_table[3] = {[2] = native};',
            'const syscall_fn_t sys_call_table[2] = {ni, 0};',
            'const syscall_fn_t sys_call_table[2] = {ni, 1 ? native : final};',
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                result = self.analyze_syscall_table(fixture)
                table, = result.syscall_tables
                self.assertFalse(table.complete, table)
                self.assertFalse(result.complete)
                self.assertIn('syscall_table_not_modeled', result.unknowns)

    def test_syscall_table_rejects_symbol_and_table_aliases_on_any_redeclaration(self) -> None:
        fixtures = (
            'long native(const struct pt_regs *) __asm__("different");',
            'long native(const struct pt_regs *) __attribute__((weak));',
            'long native(const struct pt_regs *) __attribute__((alias("final"))); '
            'long final(const struct pt_regs *p) {return 0;}',
            'extern const syscall_fn_t sys_call_table[2] __asm__("other_table");',
            'extern const syscall_fn_t sys_call_table[2] __attribute__((weak));',
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                result = self.analyze_syscall_table(fixture + '\nconst syscall_fn_t sys_call_table[2] = {ni,native};')
                table, = result.syscall_tables
                self.assertFalse(table.complete, table)
                self.assertFalse(result.complete)

    def test_syscall_table_budget_and_missing_symbol_stay_unknown(self) -> None:
        maximum = self.analyze_syscall_table('const syscall_fn_t sys_call_table[2048] = {[0 ... 2047] = ni};')
        self.assertTrue(maximum.complete, maximum)
        self.assertEqual(len(maximum.syscall_tables[0].bindings), 2048)
        oversized = self.analyze_syscall_table('const syscall_fn_t sys_call_table[2049] = {[0 ... 2048] = ni};')
        self.assertFalse(oversized.syscall_tables[0].complete)
        self.assertEqual(oversized.syscall_tables[0].status_reason, 'syscall_slot_budget')
        invalid = self.analyze_syscall_table('const syscall_fn_t sys_call_table[1] = {unknown_symbol};')
        self.assertFalse(invalid.complete)
        self.assertEqual(invalid.syscall_tables, ())

    def test_syscall_tables_are_limited_to_requested_native_little_endian_arm64_tu(self) -> None:
        body = 'const syscall_fn_t sys_call_table[2] = {ni,native};'
        for target in ('x86_64-linux-gnu', 'aarch64_be-linux-gnu', 'arm-linux-gnueabi',
                       'arm64_32-apple-watchos', 'aarch64-apple-darwin'):
            with self.subTest(target=target):
                result = self.analyze_syscall_table(body, target=target)
                self.assertEqual(result.syscall_tables, ())
        other = self.analyze(body.replace('syscall_fn_t', 'void *').replace('{ni,native}', '{0,0}'))
        self.assertEqual(other.syscall_tables, ())
        source = self.root / 'arch' / 'arm64' / 'kernel' / 'sys.c'
        self.source.write_text('#include "arch/arm64/kernel/sys.c"\n')
        included = self.analyzer.analyze(CompileCommand.for_source(self.source, flags=('--target=aarch64-linux-gnu',)),
                                         tracked_paths=(source,))
        self.assertEqual(included.syscall_tables, ())
        actual_command = CompileCommand.for_source(source, flags=('--target=aarch64-linux-gnu',))
        mismatched = CompileCommand(actual_command.directory, source, (
            'clang', '--target=aarch64-linux-gnu', '-std=gnu11', '-fsyntax-only', str(self.source)))
        self.assertEqual(self.analyzer.analyze(mismatched).syscall_tables, ())

    def test_syscall_table_does_not_inherit_old_or_warm_table_facts(self) -> None:
        legacy = TranslationUnitFacts.model_validate({'complete': True, 'functions': []})
        self.assertEqual(legacy.syscall_tables, ())
        first = self.analyze_syscall_table('const syscall_fn_t sys_call_table[2] = {ni,native};')
        self.assertTrue(first.syscall_tables[0].complete)
        second = self.analyze_syscall_table('int unrelated;')
        self.assertFalse(second.syscall_tables[0].complete)
        self.assertEqual(second.syscall_tables[0].bindings, ())

    def test_body_translation_inventory_allows_automatic_runtime_declarations(self) -> None:
        result = self.analyze('void clean(int *);\n'
                              'int run(int n) { int automatic=1; register int reg=2; '
                              'int unused __attribute__((unused)); '
                              'int value __attribute__((cleanup(clean)))=3; '
                              'int array[n]; array[0]=value; return automatic+reg+array[0]; }\n')
        function = next(function for function in result.functions if function.name == 'run')
        self.assertTrue(function.declaration_coverage_complete)
        self.assertEqual(function.body_translation_effects, ())
        self.assertIn('cleanup_attribute', function.unknowns)
        self.assertTrue(function.write_effects)

    def test_body_translation_inventory_retains_static_extern_tls_and_asm_variables(self) -> None:
        for declaration in ('static int saved=1;', 'extern int elsewhere;',
                            'static __thread int local_tls;',
                            'register long reg __asm__("r12")=7;',
                            'int aligned __attribute__((aligned(32)));'):
            with self.subTest(declaration=declaration):
                result = self.analyze('int run(void) {' + declaration + 'return 0;}\n')
                function = result.functions[0]
                self.assertTrue(function.declaration_coverage_complete)
                self.assertTrue(function.body_translation_effects)

    def test_body_translation_inventory_retains_local_types_prototypes_and_assembly(self) -> None:
        for declaration in ('int declared(void);', 'typedef int local_type;',
                            'struct local { int member; };', 'union local { int member; };',
                            'enum local { VALUE };', 'struct forward;', '__asm__("nop");'):
            with self.subTest(declaration=declaration):
                result = self.analyze('int run(void) {' + declaration + 'return 0;}\n')
                self.assertTrue(result.functions[0].declaration_coverage_complete)
                self.assertTrue(result.functions[0].body_translation_effects)

    def test_body_translation_inventory_sees_macro_generated_declarations(self) -> None:
        result = self.analyze('#define DECLARE static int generated=7\n'
                              'int run(void) { DECLARE; return generated; }\n')
        self.assertIn('nonautomatic_body_variable', result.functions[0].body_translation_effects)

    def test_body_translation_inventory_sees_tags_introduced_in_type_expressions(self) -> None:
        for expression in ('sizeof(struct visible { int member; })',
                           '_Alignof(struct visible { int member; })',
                           '((struct visible { int member; }){7}).member',
                           '((union visible { int member; }){.member=7}).member',
                           '(long)(struct visible { int member; } *)0',
                           '_Generic(0, struct visible {int member;}: 1, default: 2)',
                           'sizeof(enum visible { VALUE })', '_Alignof(enum visible { VALUE })'):
            with self.subTest(expression=expression):
                result = self.analyze('int run(void) { return ' + expression + '; }\n')
                self.assertTrue(result.functions[0].declaration_coverage_complete)
                self.assertIn('body_tag_declaration', result.functions[0].body_translation_effects)
        global_type = self.analyze('struct global {int member;};\n'
                                   'int run(void) { struct global value={7}; return value.member; }\n')
        self.assertEqual(global_type.functions[0].body_translation_effects, ())

    def test_body_translation_inventory_defaults_and_cxx_remain_unknown(self) -> None:
        result = self.analyze('int run(void) { return 7; }\n')
        serialized = result.model_dump()
        serialized['functions'][0].pop('declaration_coverage_complete')
        serialized['functions'][0].pop('body_translation_effects')
        legacy = TranslationUnitFacts.model_validate(serialized)
        self.assertFalse(legacy.functions[0].declaration_coverage_complete)
        self.source.write_text('int run() { int value=7; return value; }\n')
        command = CompileCommand.for_source(self.source, flags=('-x', 'c++'))
        # for_source defaults to gnu11; use a coherent C++ command explicitly.
        command = CompileCommand(command.directory, command.file,
                                 ('clang', '-x', 'c++', '-std=c++20', '-fsyntax-only', str(self.source)))
        cpp = self.analyzer.analyze(command)
        self.assertFalse(cpp.complete)
        self.assertFalse(cpp.functions[0].declaration_coverage_complete)

    def test_entry_closure_audit_includes_untracked_headers_and_ignores_function_filters(self) -> None:
        header = self.root / 'opaque.h'
        header.write_text('static inline void hidden(void) { __asm__("nop"); }\n')
        self.source.write_text('#include "opaque.h"\n'
                               'int run(void) { __asm__ volatile("" : : : "memory"); return 7; }\n')
        result = self.analyzer.analyze(CompileCommand.for_source(self.source), function_names=('absent',))
        self.assertTrue(result.complete, result)
        self.assertEqual(result.functions, ())
        self.assertTrue(result.inline_assembly_coverage_complete)
        self.assertTrue(result.indirect_call_coverage_complete)
        self.assertEqual({record.span.start.path for record in result.inline_assembly}, {header, self.source})
        self.assertEqual({record.kind for record in result.inline_assembly}, {'opaque', 'empty_barrier'})
        self.assertEqual(result.indirect_calls, ())

    def test_entry_closure_empty_barrier_requires_exact_empty_template_and_no_operands(self) -> None:
        fixtures = (
            ('__asm__("");', 'empty_barrier'),
            ('__asm__ volatile("" : : : "memory");', 'empty_barrier'),
            ('__asm__(" ");', 'opaque'),
            (r'__asm__("\0nop");', 'opaque'),
            ('__asm__("" : : "r"(7));', 'opaque'),
            ('int output; __asm__("" : "=r"(output));', 'opaque'),
            ('__asm__("" : : : "cc");', 'opaque'),
            ('__asm__ goto("" : : : : destination); destination: ;', 'opaque'),
        )
        for statement, expected in fixtures:
            with self.subTest(statement=statement):
                result = self.analyze('int run(void) {' + statement + 'return 0;}\n')
                self.assertTrue(result.inline_assembly_coverage_complete)
                self.assertEqual(len(result.inline_assembly), 1)
                self.assertEqual(result.inline_assembly[0].kind, expected)
                if 'goto' not in statement:
                    self.assertIn('assembly', result.functions[0].unknowns)

    def test_entry_closure_inventory_includes_header_and_unevaluated_indirect_calls(self) -> None:
        header = self.root / 'indirect.h'
        header.write_text('static inline int hidden(int (*callback)(void)) {return callback();}\n')
        self.source.write_text('#include "indirect.h"\n'
                               'int run(int (*callback)(void)) { '
                               '(void)sizeof(({ __asm__("nop"); callback(); 0; })); '
                               'typeof(({ __asm__("nop"); callback(); 0; })) local=0; '
                               'return callback()+local; }\n')
        result = self.analyzer.analyze(CompileCommand.for_source(self.source), function_names=('absent',))
        self.assertTrue(result.complete, result)
        self.assertTrue(result.inline_assembly_coverage_complete)
        self.assertTrue(result.indirect_call_coverage_complete)
        self.assertEqual(len(result.inline_assembly), 2)
        self.assertEqual(len(result.indirect_calls), 4)
        self.assertEqual({call.start.path for call in result.indirect_calls}, {header, self.source})

    def test_entry_closure_budget_marks_both_inventories_incomplete(self) -> None:
        for statements in ('__asm__("nop");' * 4097,
                           '__asm__("' + 'nop;' * 4097 + '");'):
            with self.subTest(length=len(statements)):
                result = self.analyze('int run(void) {' + statements + 'return 0;}\n')
                self.assertFalse(result.inline_assembly_coverage_complete)
                self.assertFalse(result.indirect_call_coverage_complete)
                self.assertLessEqual(len(result.inline_assembly), 4096)

    def test_entry_closure_legacy_and_unsupported_language_stay_unknown(self) -> None:
        legacy = TranslationUnitFacts.model_validate({'complete': True})
        self.assertFalse(legacy.inline_assembly_coverage_complete)
        self.assertFalse(legacy.indirect_call_coverage_complete)
        self.assertEqual(legacy.inline_assembly, ())
        self.assertEqual(legacy.indirect_calls, ())
        self.source.write_text('int run(void) { int (^block)(void)=^{return 7;}; return 0; }\n')
        blocks = self.analyzer.analyze(CompileCommand.for_source(self.source, flags=('-fblocks',)))
        self.assertTrue(blocks.complete, blocks)
        self.assertFalse(blocks.inline_assembly_coverage_complete)
        self.assertFalse(blocks.indirect_call_coverage_complete)
        self.source.write_text('int run(void) { __asm nop; return 0; }\n')
        microsoft = self.analyzer.analyze(CompileCommand.for_source(self.source, flags=('-fasm-blocks',)))
        self.assertFalse(microsoft.inline_assembly_coverage_complete)
        self.assertFalse(microsoft.indirect_call_coverage_complete)
        if microsoft.complete:
            self.assertEqual(microsoft.inline_assembly[0].kind, 'opaque')
        else:
            self.assertTrue(any('MS-style inline assembly' in reason for reason in microsoft.diagnostics), microsoft)
        computed = self.analyze('int run(void) { void *label=&&destination; goto *label; destination: return 0; }\n')
        self.assertFalse(computed.indirect_call_coverage_complete)

    def test_body_metadata_inventory_protects_declarations_types_refs_members_and_func(self) -> None:
        result = self.analyze('struct global_type {int member;}; extern int global_value;\n'
                              'int run(void) { struct global_type local={0}; int value=global_value; '
                              'return local.member+value+__func__[0]; }\n')
        function = result.functions[0]
        self.assertTrue(function.body_metadata_coverage_complete)
        source = self.source.read_bytes()
        pieces = [source[item.start:item.end].decode() for item in function.body_metadata_spans]
        self.assertTrue(any('struct global_type local' in piece for piece in pieces), pieces)
        for expected in ('struct global_type', 'global_value', 'local.member', '__func__'):
            self.assertTrue(any(expected in piece for piece in pieces), (expected, pieces))

    def test_body_metadata_budget_and_legacy_fields_do_not_certify_absence(self) -> None:
        result = self.analyze('extern int value; int run(void) {' + 'value;' * 4097 + 'return 0;}\n')
        function = result.functions[0]
        self.assertFalse(function.body_metadata_coverage_complete)
        self.assertLessEqual(len(function.body_metadata_spans), 4096)
        serialized = result.model_dump()
        serialized['functions'][0].pop('body_metadata_coverage_complete')
        serialized['functions'][0].pop('body_metadata_spans')
        legacy = TranslationUnitFacts.model_validate(serialized)
        self.assertFalse(legacy.functions[0].body_metadata_coverage_complete)
        self.assertEqual(legacy.functions[0].body_metadata_spans, ())

    def test_body_metadata_byte_intervals_preserve_macro_sites_and_validate_coordinates(self) -> None:
        result = self.analyze('#define FETCH(value) ((value).member)\nstruct item {int member;};\n'
                              'int run(void) {struct item local={7}; return FETCH(local);}\n')
        function = result.functions[0]
        self.assertTrue(function.body_metadata_coverage_complete)
        spans = function.body_metadata_spans
        self.assertTrue(all(item.path == self.source and function.body_span.start.offset <= item.start < item.end
                            <= function.body_span.end.offset for item in spans))
        self.assertTrue(all(first.end < second.start for first, second in zip(spans, spans[1:])))
        pieces = [self.source.read_bytes()[item.start:item.end].decode() for item in spans]
        self.assertTrue(any('struct item local' in piece for piece in pieces), pieces)
        self.assertTrue(any('FETCH' in piece for piece in pieces), pieces)
        for start, end in ((-1, 2), (2, 1), (1, 1), (True, 2), ('1', 2), (1, 2.0)):
            with self.subTest(start=start, end=end), self.assertRaises(ValueError):
                ClangMetadataSpan.model_validate({'path': self.source, 'start': start, 'end': end})

    def test_header_cleanup_attribute_records_implicit_unknown_caller(self) -> None:
        header = self.root / 'cleanup.h'
        header.write_text('static inline void hidden(void) {'
                          'struct value local __attribute__((cleanup(cleanup)))={0};}\n')
        self.source.write_text('struct value {int member;}; void cleanup(struct value *p) {}\n'
                               '#include "cleanup.h"\nint run(void) {hidden(); return 0;}\n')
        result = self.analyzer.analyze(CompileCommand.for_source(self.source), function_names=('absent',))
        self.assertTrue(result.complete, result)
        self.assertTrue(any(reference.usr == 'c:@F@cleanup' and reference.span.start.path == header
                            for reference in result.address_taken))

    def test_early_capability_return_controls_later_call_but_not_check(self) -> None:
        result = self.analyze('int run(void) { if (!capable(21)) return -1; target(); return 0; }\n')
        guard, = self.call(result).guards
        self.assertEqual((guard.callee, guard.outcome, guard.arguments[0].integer), ("capable", "nonzero", 21))
        self.assertEqual(self.call(result, "capable").guards, ())

    def test_error_side_is_reachable_under_denial(self) -> None:
        result = self.analyze('int run(void) { if (!capable(21)) { target(); return -1; } return 0; }\n')
        self.assertEqual(self.call(result).guards[0].outcome, "zero")

    def test_statements_before_the_check_have_no_obligation(self) -> None:
        result = self.analyze('int run(void) { target(); if (!capable(21)) return -1; return 0; }\n')
        self.assertEqual(self.call(result).guards, ())

    def test_assigned_errno_result_with_later_reassignment(self) -> None:
        result = self.analyze('int run(int cmd) { int ret; ret = security_bpf(cmd); if (ret < 0) return ret; target(); ret=5; return ret; }\n')
        guard, = self.call(result).guards
        self.assertEqual((guard.callee, guard.outcome, guard.arguments[0].parameter), ("security_bpf", "nonnegative", 0))

    def test_reassigned_or_escaped_result_does_not_keep_stale_guard(self) -> None:
        for middle in ('ret = 0;', 'int *p = &ret; *p = 0;'):
            with self.subTest(middle=middle):
                result = self.analyze('int run(int cmd) { int ret=security_bpf(cmd); ' + middle + ' if(ret<0)return ret; target(); return 0; }\n')
                self.assertEqual(self.call(result).guards, ())

    def test_multiple_reaching_definitions_are_unknown(self) -> None:
        result = self.analyze('int run(int cmd, int x) { int ret; if(x) ret=security_bpf(cmd); else ret=0; if(ret<0)return ret; target(); return 0; }\n')
        self.assertEqual(self.call(result).guards, ())

    def test_goto_can_bypass_a_check(self) -> None:
        result = self.analyze('int run(int x) { if(x) goto allowed; if(!capable(21))return -1; allowed: target(); return 0; }\n')
        self.assertEqual(self.call(result).guards, ())

    def test_goto_cleanup_does_not_bypass_guarded_body(self) -> None:
        result = self.analyze('int run(void) { if(!capable(21))goto out; target(); out:return 0; }\n')
        self.assertEqual(self.call(result).guards[0].outcome, "nonzero")

    def test_owner_alternative_does_not_require_capability(self) -> None:
        result = self.analyze('int run(void) { if(owner() || capable(21)) target(); return 0; }\n')
        self.assertFalse(any(g.callee == "capable" for g in self.call(result).guards))

    def test_conjunction_requires_the_capability(self) -> None:
        result = self.analyze('int run(void) { if(owner() && capable(21)) target(); return 0; }\n')
        self.assertTrue(any(g.callee == "capable" and g.outcome == "nonzero" for g in self.call(result).guards))

    def test_nested_negation_comparison_preserves_outcome(self) -> None:
        result = self.analyze('int run(void) { if((!capable(21))==0) target(); return 0; }\n')
        self.assertEqual(self.call(result).guards[0].outcome, "nonzero")

    def test_boolean_and_unsigned_sign_comparisons_are_not_errno_guards(self) -> None:
        for condition in ('!!security_bpf(5) < 0', '(unsigned)security_bpf(5) < 0'):
            with self.subTest(condition=condition):
                result = self.analyze('int run(void) { if(' + condition + ')return -1; target(); return 0; }\n')
                self.assertFalse(any(g.callee == "security_bpf" for g in self.call(result).guards))

    def test_narrowed_or_unsigned_local_does_not_model_original_errno(self) -> None:
        for declaration in ('short ret', 'unsigned ret', 'volatile int ret'):
            with self.subTest(declaration=declaration):
                result = self.analyze('int run(void) { ' + declaration + '=security_bpf(5); if(ret<0)return -1; target(); return 0; }\n')
                self.assertFalse(any(g.callee == "security_bpf" for g in self.call(result).guards))

    def test_switch_case_constraint_and_modified_parameter(self) -> None:
        result = self.analyze('int run(int cmd) { switch(cmd) { case 5: target(); break; default: break; } return 0; }\n')
        constraint, = self.call(result).constraints
        self.assertEqual((constraint.parameter, constraint.integer), (0, 5))
        result = self.analyze('int run(int cmd) { cmd &= 7; switch(cmd) { case 5: target(); break; default: break; } return 0; }\n')
        self.assertEqual(self.call(result).constraints, ())
        self.assertEqual(result.functions[0].modified_parameters, (0,))

    def test_case_fallthrough_keeps_alternative_value(self) -> None:
        result = self.analyze('int run(int cmd) { switch(cmd) { case 3: ; case 5: target(); break; } return 0; }\n')
        self.assertEqual(self.call(result).constraints, ())

    def test_address_taken_and_indirect_calls_are_recorded(self) -> None:
        result = self.analyze('static void local(void) {}\nvoid (*saved)(void)=local;\nint run(void) { saved(); return 0; }\n')
        self.assertIn("local", [r.name for r in result.address_taken])
        function = next(f for f in result.functions if f.name == "run")
        self.assertIn("indirect_call", function.unknowns)
        self.assertTrue(any(c.callee is None for c in function.calls))

    def test_argument_declaration_identity_distinguishes_shadowed_namespace(self) -> None:
        result = self.analyze('struct user_namespace { int value; };\n'
                              'extern struct user_namespace init_user_ns;\n'
                              'int ns_capable(struct user_namespace *, int); void consume(int);\n'
                              'int run(int value) { if(!ns_capable(&init_user_ns, 21))return -1; consume(value); return 0; }\n'
                              'int shadow(void) { struct user_namespace init_user_ns; '
                              'if(!ns_capable(&init_user_ns, 21))return -1; return 0; }\n')
        global_argument = self.call(result, 'ns_capable').arguments[0]
        shadow_argument = self.call(result, 'ns_capable', function='shadow').arguments[0]
        parameter_argument = self.call(result, 'consume').arguments[0]
        self.assertEqual(global_argument.expression, shadow_argument.expression)
        self.assertEqual(global_argument.declaration_usr, 'c:@init_user_ns')
        self.assertIsNotNone(shadow_argument.declaration_usr)
        self.assertNotEqual(global_argument.declaration_usr, shadow_argument.declaration_usr)
        self.assertIsNotNone(parameter_argument.declaration_usr)
        self.assertEqual(parameter_argument.parameter, 0)

    def test_untracked_header_direct_caller_prevents_closed_static_closure(self) -> None:
        header = self.root / 'consumer.h'
        header.write_text('int public_entry(void) { return helper(); }\n')
        result = self.analyze('static int helper(void) { return 7; }\n'
                              '#include "consumer.h"\n'
                              'int run(void) { if(!capable(21))return -1; return helper(); }\n')
        helper = next(function for function in result.functions if function.name == 'helper')
        references = [reference for reference in result.address_taken if reference.usr == helper.usr]
        self.assertEqual(len(references), 1)
        self.assertEqual(references[0].span.start.path, header)
        self.assertNotIn('public_entry', [function.name for function in result.functions])

    def test_main_file_syscall_macro_wrapper_keeps_direct_call_tracking(self) -> None:
        header = self.root / 'syscalls.h'
        header.write_text('#define SYSCALL_DEFINE0(name) '
                          'static long __do_sys_##name(void); '
                          'static long __se_sys_##name(void) { return __do_sys_##name(); } '
                          'static long __do_sys_##name(void)\n')
        result = self.analyze('#include "syscalls.h"\n'
                              'SYSCALL_DEFINE0(test) { if(!capable(21))return -1; return 7; }\n')
        implementation = next(function for function in result.functions if function.name == '__do_sys_test')
        wrapper = next(function for function in result.functions if function.name == '__se_sys_test')
        self.assertTrue(any(call.callee_usr == implementation.usr for call in wrapper.calls))
        self.assertFalse(any(reference.usr == implementation.usr for reference in result.address_taken))

    def test_source_overlay_reuses_tu_and_refreshes_facts(self) -> None:
        self.source.write_text('int capable(int); void target(void); int run(void) { if(!capable(21))return 0; target(); return 1; }\n')
        command = CompileCommand.for_source(self.source)
        first = self.analyzer.analyze(command)
        changed = self.source.read_text().replace('if(!capable(21))return 0;', '')
        second = self.analyzer.analyze(command, overlays=(SourceOverlay(self.source, changed),))
        self.assertTrue(first.complete and second.complete, second.diagnostics)
        self.assertFalse(first.reused_tu)
        self.assertTrue(second.reused_tu)
        self.assertTrue(set(first.dependencies) <= set(second.dependencies))
        self.assertTrue(self.call(first).guards)
        self.assertEqual(self.call(second).guards, ())
        self.assertIn('if(!capable', self.source.read_text())

    def test_header_overlay_invalidates_preamble(self) -> None:
        header = self.root / "api.h"
        header.write_text('#define CAP 21\nint capable(int); void target(void);\n')
        self.source.write_text('#include "api.h"\nint run(void) { if(!capable(CAP))return 0; target(); return 1; }\n')
        command = CompileCommand.for_source(self.source)
        first = self.analyzer.analyze(command)
        second = self.analyzer.analyze(command, overlays=(SourceOverlay(header, header.read_text().replace('21', '12')),))
        self.assertTrue(first.complete and second.complete, second.diagnostics)
        self.assertIn(header, second.dependencies)
        self.assertEqual(self.call(first).guards[0].arguments[0].integer, 21)
        self.assertEqual(self.call(second).guards[0].arguments[0].integer, 12)

    def test_macro_only_preamble_dependencies_survive_warm_reparse(self) -> None:
        leaf = self.root / 'leaf.h'
        leaf.write_text('#define CHECK_CAP 21\n')
        wrapper = self.root / 'wrapper.h'
        wrapper.write_text('#include "leaf.h"\nint capable(int); void target(void);\n')
        self.source.write_text('#include "wrapper.h"\nint run(void) { if(!capable(CHECK_CAP))return 0; target(); return 1; }\n')
        command = CompileCommand.for_source(self.source)
        first = self.analyzer.analyze(command)
        second = self.analyzer.analyze(command)
        self.assertTrue(first.complete and second.complete, second.diagnostics)
        self.assertTrue({leaf, wrapper, self.source} <= set(first.dependencies))
        self.assertTrue(set(first.dependencies) <= set(second.dependencies))

    def test_counter_generated_error_attributes_keep_distinct_header_body_declarations(self) -> None:
        header = self.root / 'assertions.h'
        header.write_text('#define ASSERT_IMPL(n, message) '
                          'extern void assertion_##n(void) __attribute__((error(message)))\n'
                          '#define ASSERT_EXPAND(n, message) ASSERT_IMPL(n, message)\n'
                          '#define ASSERT(message) ASSERT_EXPAND(__COUNTER__, message)\n'
                          'static inline void first(void) { ASSERT("header first"); }\n'
                          'static inline void second(void) { ASSERT("header second"); }\n')
        self.source.write_text('#include "assertions.h"\n'
                               'int run(void) { ASSERT("source body"); return 0; }\n')
        command = CompileCommand.for_source(self.source)
        first = self.analyzer.analyze(command)
        second = self.analyzer.analyze(command)
        self.assertTrue(first.complete, first.diagnostics)
        self.assertTrue(second.complete, second.diagnostics)
        self.assertIn(header, first.dependencies)
        self.assertIn(header, second.dependencies)

    def test_syntax_errors_and_unsupported_flags_are_incomplete(self) -> None:
        self.source.write_text('int run(void) { no_such( }\n')
        self.assertFalse(self.analyzer.analyze(CompileCommand.for_source(self.source)).complete)
        self.source.write_text('int run(void) { return 0; }\n')
        self.assertTrue(self.analyzer.analyze(CompileCommand.for_source(self.source)).complete)
        command = CompileCommand.for_source(self.source, flags=('-fconserve-stack',))
        self.assertFalse(self.analyzer.analyze(command).complete)

    def test_credential_changes_and_assembly_are_unknown(self) -> None:
        result = self.analyze('void override_creds(void); int run(void) { override_creds(); if(!capable(21))return -1; asm("nop"); target(); return 0; }\n')
        function, = result.functions
        self.assertIn("credential_context_change", function.unknowns)
        self.assertIn("assembly", function.unknowns)

    def export_header(self, replacement: str | None = None) -> Path:
        header = self.root / 'include/linux/export.h'
        header.parent.mkdir(parents=True, exist_ok=True)
        definition = (r'#define __EXPORT_SYMBOL(sym) asm(".section \".export_symbol\",\"a\"; __export_symbol_" #sym '
                      r'":; .asciz \"GPL\"; .ascii \"\" \"\\0\"; .balign 8; .quad " #sym "; .previous")')
        header.write_text((replacement or definition) + '\n#define EXPORT_SYMBOL_GPL(sym) __EXPORT_SYMBOL(sym)\n')
        return header

    def test_exact_readonly_export_metadata_records_an_unknown_caller(self) -> None:
        self.export_header()
        result = self.analyze('#include "include/linux/export.h"\n'
                              'static int exported(void) { return 7; }\nEXPORT_SYMBOL_GPL(exported);\n')
        function, = result.functions
        self.assertTrue(any(reference.usr == function.usr for reference in result.address_taken))
        metadata, = result.file_scope_assembly
        self.assertEqual(metadata.kind, 'readonly_export')
        self.assertEqual(metadata.symbols, ('exported',))

    def test_export_metadata_rejects_executable_sections_and_extra_directives(self) -> None:
        for old, new in ((r'\"a\"', r'\"ax\"'), ('.previous', '.previous; .text; .byte 0'),
                         ('.quad ', '.quad 1+')):
            with self.subTest(new=new):
                header = self.export_header()
                header.write_text(header.read_text().replace(old, new))
                self.source.write_text('#include "include/linux/export.h"\nint exported(void) { return 7; }\nEXPORT_SYMBOL_GPL(exported);\n')
                result = self.analyzer.analyze(CompileCommand.for_source(self.source))
                self.assertFalse(result.complete)
                self.assertIn('file_scope_assembly', result.unknowns)

    def test_export_metadata_requires_trusted_macro_and_resolved_symbol(self) -> None:
        header = self.export_header()
        for declaration, include in (('', '#include "include/linux/export.h"\n'),
                                     ('int exported(void) { return 7; }\n', header.read_text() + '\n')):
            with self.subTest(declaration=declaration):
                self.source.write_text(include + declaration + 'EXPORT_SYMBOL_GPL(exported);\n')
                result = self.analyzer.analyze(CompileCommand.for_source(self.source))
                self.assertFalse(result.complete)
                self.assertIn('file_scope_assembly', result.unknowns)

    def test_export_targets_with_assembler_names_are_not_guessed(self) -> None:
        self.export_header()
        self.source.write_text('#include "include/linux/export.h"\n'
                               'int exported(void) asm("other");\n'
                               'int exported(void) { return 7; }\nEXPORT_SYMBOL_GPL(exported);\n')
        result = self.analyzer.analyze(CompileCommand.for_source(self.source))
        self.assertFalse(result.complete)
        self.assertIn('file_scope_assembly', result.unknowns)

    def initcall_header(self) -> Path:
        header = self.root / 'include/linux/init.h'
        header.parent.mkdir(parents=True, exist_ok=True)
        header.write_text(r'#define ____define_initcall(fn) asm(".section \".initcall7.init\", \"a\"; '
                          r'__initcall__fixture_" #fn "7:; .long " #fn " - .; .previous")'
                          + '\n#define INITCALL(fn) ____define_initcall(fn)\n')
        return header

    def test_exact_readonly_initcall_records_the_registered_function(self) -> None:
        self.initcall_header()
        result = self.analyze('#include "include/linux/init.h"\n'
                              'static int registered(void) { return 7; }\nINITCALL(registered);\n')
        function, = result.functions
        self.assertTrue(any(reference.usr == function.usr for reference in result.address_taken))
        metadata, = result.file_scope_assembly
        self.assertEqual((metadata.kind, metadata.symbols), ('readonly_initcall', ('registered',)))

    def test_initcall_rejects_executable_or_unresolved_entries(self) -> None:
        for old, new in ((r'\"a\"', r'\"ax\"'), ('.previous', '.previous; .text; nop'),
                         ('.long ', '.long 1+'), ('.initcall7.init', '.arbitrary')):
            with self.subTest(new=new):
                header = self.initcall_header()
                header.write_text(header.read_text().replace(old, new))
                self.source.write_text('#include "include/linux/init.h"\n'
                                       'static int registered(void) { return 7; }\nINITCALL(registered);\n')
                result = self.analyzer.analyze(CompileCommand.for_source(self.source))
                self.assertFalse(result.complete)
                self.assertIn('file_scope_assembly', result.unknowns)
        self.initcall_header()
        for declaration in ('', 'int registered;',
                            'int registered(void) asm("other"); int registered(void) { return 7; }'):
            with self.subTest(declaration=declaration):
                self.source.write_text('#include "include/linux/init.h"\n' + declaration + '\nINITCALL(registered);\n')
                result = self.analyzer.analyze(CompileCommand.for_source(self.source))
                self.assertFalse(result.complete)
                self.assertIn('file_scope_assembly', result.unknowns)

    def test_initcall_requires_the_trusted_header_macro(self) -> None:
        header = self.initcall_header()
        self.source.write_text(header.read_text() + '\nstatic int registered(void) { return 7; }\nINITCALL(registered);\n')
        result = self.analyzer.analyze(CompileCommand.for_source(self.source))
        self.assertFalse(result.complete)
        self.assertIn('file_scope_assembly', result.unknowns)

    def tracepoint_header(self) -> Path:
        header = self.root / 'include/linux/tracepoint.h'
        header.parent.mkdir(parents=True, exist_ok=True)
        header.write_text(
            r'#define __TRACEPOINT_ENTRY(name) asm("\t.section \"__tracepoints_ptrs\", \"a\"\n" '
            r'"\t.balign 4\n" "\t.long __tracepoint_" #name " - .\n" "\t.previous\n")'
            '\n#define __DEFINE_TRACE_EXT(name) '
            'static const char __tpstrtab_##name[] = #name; '
            'struct tracepoint __tracepoint_##name __attribute__((used,section("__tracepoints"))) = {0}; '
            '__TRACEPOINT_ENTRY(name)\n'
            '#define DEFINE_TRACE(name) __DEFINE_TRACE_EXT(name)\n')
        return header

    def test_exact_readonly_tracepoint_records_the_object_and_keeps_callback_references(self) -> None:
        self.tracepoint_header()
        result = self.analyze('#include "include/linux/tracepoint.h"\n'
                              'struct tracepoint {void (*callback)(void);};\n'
                              'static void probe(void) {}\n'
                              'struct tracepoint __tracepoint_sample={probe};\n'
                              '__TRACEPOINT_ENTRY(sample);\n')
        metadata, = result.file_scope_assembly
        self.assertEqual((metadata.kind, metadata.symbols), ('readonly_tracepoint', ('__tracepoint_sample',)))
        references = {reference.usr for reference in result.address_taken}
        self.assertIn('c:@__tracepoint_sample', references)
        self.assertIn(result.functions[0].usr, references)

    def test_tracepoint_metadata_accepts_the_nested_header_expansion_stack(self) -> None:
        self.tracepoint_header()
        event_header = self.root / 'include/trace/events/fixture.h'
        event_header.parent.mkdir(parents=True)
        event_header.write_text('#define TRACE_EVENT(name) DEFINE_TRACE(name)\nTRACE_EVENT(nested);\n')
        result = self.analyze('#include "include/linux/tracepoint.h"\n'
                              'struct tracepoint {void (*callback)(void);};\n'
                              '#include "include/trace/events/fixture.h"\n')
        metadata, = result.file_scope_assembly
        self.assertEqual((metadata.kind, metadata.symbols), ('readonly_tracepoint', ('__tracepoint_nested',)))
        self.assertIn('c:@__tracepoint_nested', {reference.usr for reference in result.address_taken})

    def test_tracepoint_metadata_rejects_nonexact_sections_widths_and_relocations(self) -> None:
        for old, new in ((r'\"a\"', r'\"ax\"'), (r'\"a\"', r'\"aw\"'),
                         ('__tracepoints_ptrs', '__tracepoints_ ptrs'),
                         ('.balign 4', '.balign 8'), ('.balign 4', '.balign4'),
                         ('.long ', '.quad '), ('.long ', '.long'),
                         ('.long __tracepoint_', '.long 1+__tracepoint_'),
                         (' - .', ' - . + 0'), (' - .', ' + .'),
                         ('.previous', '.previous; .text; nop'),
                         ('.previous', '.previous; .set alias, __tracepoint_sample')):
            with self.subTest(new=new):
                header = self.tracepoint_header()
                header.write_text(header.read_text().replace(old, new))
                self.source.write_text('#include "include/linux/tracepoint.h"\n'
                                       'int __tracepoint_sample;\n__TRACEPOINT_ENTRY(sample);\n')
                result = self.analyzer.analyze(CompileCommand.for_source(self.source))
                self.assertFalse(result.complete, result)
                self.assertIn('file_scope_assembly', result.unknowns)

    def test_tracepoint_metadata_rejects_wrong_origin_missing_nonobject_and_alias_symbols(self) -> None:
        for declaration in ('', 'int __tracepoint_sample(void);',
                            'int __tracepoint_sample asm("other");',
                            'extern int __tracepoint_sample asm("other"); int __tracepoint_sample;',
                            'int __tracepoint_sample __attribute__((weak));',
                            'int actual; extern int __tracepoint_sample __attribute__((alias("actual")));',
                            '__thread int __tracepoint_sample;'):
            with self.subTest(declaration=declaration):
                self.tracepoint_header()
                self.source.write_text('#include "include/linux/tracepoint.h"\n' + declaration + '\n__TRACEPOINT_ENTRY(sample);\n')
                result = self.analyzer.analyze(CompileCommand.for_source(self.source))
                self.assertFalse(result.complete, result)
                self.assertIn('file_scope_assembly', result.unknowns)
        header = self.tracepoint_header()
        self.source.write_text(header.read_text() + '\nint __tracepoint_sample;\n__TRACEPOINT_ENTRY(sample);\n')
        result = self.analyzer.analyze(CompileCommand.for_source(self.source))
        self.assertFalse(result.complete)
        self.assertIn('file_scope_assembly', result.unknowns)

    def test_tracepoint_metadata_rejects_mixed_macro_origins_and_oversized_names(self) -> None:
        header = self.tracepoint_header()
        definition = header.read_text().splitlines()[0]
        header.write_text('#define TRUSTED_PREFIX asm\n')
        self.source.write_text('#include "include/linux/tracepoint.h"\n' +
                               definition.replace('asm(', 'TRUSTED_PREFIX(') +
                               '\nint __tracepoint_sample;\n__TRACEPOINT_ENTRY(sample);\n')
        result = self.analyzer.analyze(CompileCommand.for_source(self.source))
        self.assertFalse(result.complete)
        self.assertIn('file_scope_assembly', result.unknowns)
        self.tracepoint_header()
        name = 'x' * 256
        self.source.write_text('#include "include/linux/tracepoint.h"\nint __tracepoint_' + name +
                               ';\n__TRACEPOINT_ENTRY(' + name + ');\n')
        result = self.analyzer.analyze(CompileCommand.for_source(self.source))
        self.assertFalse(result.complete)
        self.assertIn('file_scope_assembly', result.unknowns)

    def test_tracepoint_symbol_redeclarations_require_a_unique_valid_object(self) -> None:
        self.tracepoint_header()
        result = self.analyze('#include "include/linux/tracepoint.h"\n'
                              'extern int __tracepoint_sample; int __tracepoint_sample;\n'
                              '__TRACEPOINT_ENTRY(sample);\n')
        self.assertEqual(result.file_scope_assembly[0].kind, 'readonly_tracepoint')
        self.source.write_text('#include "include/linux/tracepoint.h"\n'
                               'int __tracepoint_sample; long __tracepoint_sample;\n'
                               '__TRACEPOINT_ENTRY(sample);\n')
        invalid = self.analyzer.analyze(CompileCommand.for_source(self.source))
        self.assertFalse(invalid.complete)
        self.assertFalse(any(record.kind == 'readonly_tracepoint' for record in invalid.file_scope_assembly))

    def btf_header(self) -> Path:
        header = self.root / 'include/linux/btf_ids.h'
        header.parent.mkdir(parents=True, exist_ok=True)
        header.write_text(
            r'#define __BTF_ID_LIST(name) asm(".pushsection .BTF_ids,\"a\"; .globl " #name "; " #name ":; .popsection")'
            '\n'
            r'#define ____BTF_ID(symbol) asm(".pushsection .BTF_ids,\"a\"; .local " #symbol "; .type " #symbol ", STT_OBJECT; .size " #symbol ", 4; " #symbol ":; .zero 4; .popsection")'
            '\n#define BTF_SINGLE(list, fn) extern unsigned list[]; __BTF_ID_LIST(list); '
            '____BTF_ID(__BTF_ID__func__##fn##__123)\n'
            '#define BTF_ID_LIST_GLOBAL(list, n) __BTF_ID_LIST(list)\n'
            '#define BTF_ID_LIST_GLOBAL_SINGLE(list, prefix, fn) BTF_ID_LIST_GLOBAL(list, 1); '
            '____BTF_ID(__BTF_ID__func__##fn##__123)\n')
        return header

    def test_exact_readonly_btf_function_id_records_unknown_callers(self) -> None:
        self.btf_header()
        result = self.analyze('#include "include/linux/btf_ids.h"\n'
                              'static int registered(void) { return 7; }\nBTF_SINGLE(ids, registered);\n')
        function, = result.functions
        self.assertTrue(any(reference.usr == function.usr for reference in result.address_taken))
        self.assertEqual([item.kind for item in result.file_scope_assembly], ['readonly_btf', 'readonly_btf'])
        self.assertEqual([item.symbols for item in result.file_scope_assembly], [('ids',), ('registered',)])

    def test_nested_btf_list_wrappers_preserve_trusted_header_origin(self) -> None:
        self.btf_header()
        result = self.analyze('#include "include/linux/btf_ids.h"\n'
                              'extern unsigned ids[]; static int registered(void) { return 7; }\n'
                              'BTF_ID_LIST_GLOBAL_SINGLE(ids, func, registered);\n')
        self.assertEqual([item.kind for item in result.file_scope_assembly], ['readonly_btf', 'readonly_btf'])
        self.assertTrue(any(reference.name == 'registered' for reference in result.address_taken))

    def test_btf_metadata_rejects_extra_directives_and_unsupported_layouts(self) -> None:
        for old, new in ((r'\"a\"', r'\"ax\"'), ('.popsection', '.popsection; .text; nop'),
                         ('STT_OBJECT', 'STT_FUNC'), ('.zero 4', '.zero 8'),
                         ('__BTF_ID__func__', '__BTF_ID__struct__'), ('##__123', '##__suffix')):
            with self.subTest(new=new):
                header = self.btf_header()
                header.write_text(header.read_text().replace(old, new))
                self.source.write_text('#include "include/linux/btf_ids.h"\n'
                                       'static int registered(void) { return 7; }\nBTF_SINGLE(ids, registered);\n')
                result = self.analyzer.analyze(CompileCommand.for_source(self.source))
                self.assertFalse(result.complete)
                self.assertIn('file_scope_assembly', result.unknowns)

    def test_btf_metadata_requires_trusted_resolved_function_references(self) -> None:
        header = self.btf_header()
        for declaration, include in (('', '#include "include/linux/btf_ids.h"\n'),
                                     ('int registered;', '#include "include/linux/btf_ids.h"\n'),
                                     ('int registered(void) asm("other"); int registered(void) { return 7; }', '#include "include/linux/btf_ids.h"\n'),
                                     ('int registered(void) { return 7; }', header.read_text() + '\n')):
            with self.subTest(declaration=declaration):
                self.source.write_text(include + declaration + '\nBTF_SINGLE(ids, registered);\n')
                result = self.analyzer.analyze(CompileCommand.for_source(self.source))
                self.assertFalse(result.complete)
                self.assertIn('file_scope_assembly', result.unknowns)

    def test_btf_list_requires_a_resolved_object_without_assembler_alias(self) -> None:
        self.btf_header()
        for declaration in ('', 'int ids(void);', 'extern unsigned ids[] asm("elsewhere");'):
            with self.subTest(declaration=declaration):
                self.source.write_text('#include "include/linux/btf_ids.h"\n' + declaration + '\n__BTF_ID_LIST(ids);\n')
                result = self.analyzer.analyze(CompileCommand.for_source(self.source))
                self.assertFalse(result.complete)
                self.assertIn('file_scope_assembly', result.unknowns)

    def test_bodyless_aliases_are_explicitly_unknown(self) -> None:
        self.source.write_text('static int target(void) { return 7; }\n'
                               'int alias(void) __attribute__((alias("target")));\n')
        result = self.analyzer.analyze(CompileCommand.for_source(self.source))
        self.assertFalse(result.complete)
        self.assertIn('alias_not_modeled', result.unknowns)

    def test_assembler_named_callers_record_the_tracked_target(self) -> None:
        result = self.analyze('static int local(void) { return 7; }\n'
                              'int bridge(void) asm("local");\n'
                              'int run(void) { return bridge(); }\n')
        local = next(function for function in result.functions if function.name == 'local')
        self.assertTrue(any(reference.usr == local.usr for reference in result.address_taken))

    def test_assembler_named_object_reference_cannot_hide_a_function_address(self) -> None:
        result = self.analyze('static int local(void) { return 7; }\n'
                              'extern char bridge asm("local");\n'
                              'int run(void) { return ((int (*)(void))(void *)&bridge)(); }\n')
        local = next(function for function in result.functions if function.name == 'local')
        self.assertTrue(any(reference.usr == local.usr for reference in result.address_taken))

    def test_cleanup_and_registration_attributes_are_unknown(self) -> None:
        result = self.analyze('void cleanup(int *); static int run(void) __attribute__((used));\nstatic int run(void) { int n __attribute__((cleanup(cleanup)))=0; if(!capable(21))return -1; target(); return n; }\n')
        function, = result.functions
        self.assertIn("cleanup_attribute", function.unknowns)
        self.assertIn("special_function_attribute", function.unknowns)

    def test_nonlocal_memory_assignments_and_increments_have_complete_effects(self) -> None:
        for write in ('*p = 1;', 'p[0] += 1;', 's->value++;', 'local.value = 1;',
                      'global_value = 1;', '++*p;', '__atomic_store_n(p, 1, 0);'):
            with self.subTest(write=write):
                result = self.analyze('struct item { int value; }; int global_value;\n'
                                      'int run(int *p, struct item *s) { struct item local; '
                                      + write + ' if(!capable(21))return -1; target(); return 0; }\n')
                function, = result.functions
                self.assertTrue(function.write_coverage_complete)
                self.assertNotIn("memory_write", function.unknowns)
                self.assertEqual(len(function.write_effects), 1)
                self.assertIn(function.write_effects[0].block, {block.block for block in function.cfg_blocks})

    def test_post_gate_effect_records_exact_guard_call_occurrence(self) -> None:
        result = self.analyze('int run(int *p) { if(!capable(21))return -1; *p=1; target(); return 0; }\n')
        function, = result.functions
        effect, = function.write_effects
        guard, = effect.guards
        call = self.call(result, 'capable')
        self.assertEqual((guard.call_block, guard.call_order), (call.block, call.order))
        self.assertIsNotNone(call.block)
        self.assertIsNotNone(call.order)

    def test_nested_gate_argument_write_has_prior_cfg_order(self) -> None:
        result = self.analyze('int run(int *p) { if(!capable((*p=1,21)))return -1; target(); return 0; }\n')
        function, = result.functions
        effect, = function.write_effects
        call = self.call(result, 'capable')
        self.assertTrue(function.write_coverage_complete)
        self.assertEqual(effect.block, call.block)
        self.assertLess(effect.order, call.order)
        self.assertEqual(effect.guards, ())

    def test_unmapped_atomic_and_macro_ast_writes_preserve_global_unknown(self) -> None:
        for expression in ('sizeof((*p=1))', 'sizeof(__atomic_fetch_add(p,1,0))', 'HIDDEN_WRITE(p)'):
            with self.subTest(expression=expression):
                result = self.analyze('#define HIDDEN_WRITE(p) sizeof((*(p)=1))\n'
                                      'int run(int *p) { (void)' + expression + '; '
                                      'if(!capable(21))return -1; target(); return 0; }\n')
                function, = result.functions
                self.assertFalse(function.write_coverage_complete)
                self.assertIn('memory_write', function.unknowns)

    def test_nested_macro_guards_have_distinct_cfg_call_occurrences(self) -> None:
        result = self.analyze('#define GATE(n) capable(n)\n'
                              '#define CHECKS(p) do { if(GATE(1)) *(p)=1; if(!GATE(21)) return -1; } while(0)\n'
                              'int run(int *p) { CHECKS(p); target(); return 0; }\n')
        function, = result.functions
        first, = function.write_effects[0].guards
        second = next(guard for guard in self.call(result).guards if guard.arguments[0].integer == 21)
        self.assertEqual(first.span, second.span)
        self.assertNotEqual((first.call_block, first.call_order), (second.call_block, second.call_order))
        self.assertIsNotNone(first.span.spelling_start)
        self.assertIsNotNone(first.span.spelling_end)

    def test_file_spans_omit_only_redundant_spelling_coordinates(self) -> None:
        result = self.analyze('int run(void) { if(!capable(21))return -1; target(); return 0; }\n')
        call = self.call(result)
        self.assertFalse(call.span.macro)
        self.assertIsNone(call.span.spelling_start)
        self.assertIsNone(call.span.spelling_end)
        source = self.source.read_bytes()
        start = source.index(b'target()')
        for point, offset in ((call.span.start, start), (call.span.end, start + len(b'target()'))):
            self.assertEqual(point.path, self.source)
            self.assertEqual(point.offset, offset)
            self.assertEqual(point.line, source[:offset].count(b'\n') + 1)
            self.assertEqual(point.column, offset - source.rfind(b'\n', 0, offset))

    def test_partial_macro_ranges_keep_both_spelling_points(self) -> None:
        result = self.analyze('#define VALUE 7\n'
                              'int run(void) { if(!capable(21))return -1; return VALUE; }\n')
        function, = result.functions
        statement = next(statement for statement in function.statements
                         if statement.kind == 'ReturnStmt' and statement.span.macro)
        self.assertIsNotNone(statement.span.spelling_start)
        self.assertIsNotNone(statement.span.spelling_end)
        self.assertEqual(statement.span.start, statement.span.spelling_start)
        self.assertNotEqual(statement.span.end, statement.span.spelling_end)

    def test_va_arg_implicit_storage_write_remains_unmodeled(self) -> None:
        result = self.analyze('extern __builtin_va_list *shared;\n'
                              'int run(void) { (void)__builtin_va_arg(*shared,int); '
                              'if(!capable(21))return -1; target(); return 0; }\n')
        function, = result.functions
        self.assertFalse(function.write_coverage_complete)
        self.assertIn('memory_write', function.unknowns)

    def test_asm_labeled_initializers_do_not_claim_complete_local_effects(self) -> None:
        for storage in ('', 'register '):
            with self.subTest(storage=storage):
                self.source.write_text('int capable(int); void target(void);\nint run(void) { '
                                       + storage + 'unsigned long slot asm("r12")=1; '
                                       'if(!capable(21))return -1; target(); return 0; }\n')
                result = self.analyzer.analyze(CompileCommand.for_source(
                    self.source, flags=('--target=x86_64-linux-gnu',)))
                self.assertTrue(result.complete, result.diagnostics)
                function, = result.functions
                self.assertFalse(function.write_coverage_complete)
                self.assertIn('memory_write', function.unknowns)

    def test_older_function_payload_defaults_to_incomplete_write_coverage(self) -> None:
        result = self.analyze('int run(void) { if(!capable(21))return -1; target(); return 0; }\n')
        payload = result.model_dump()
        for function in payload['functions']:
            for key in ('write_effects', 'write_coverage_complete', 'cfg_blocks', 'cfg_entry'):
                function.pop(key)
        legacy = TranslationUnitFacts.model_validate(payload)
        self.assertFalse(legacy.functions[0].write_coverage_complete)
        self.assertEqual(legacy.functions[0].write_effects, ())

    def test_plain_local_scalar_and_parameter_assignments_remain_modeled(self) -> None:
        result = self.analyze('int run(int n) { int local = 0; int *p = &local; '
                              'local = n; local++; n += 1; p = 0; '
                              'if(!capable(21))return -1; target(); return local; }\n')
        function, = result.functions
        self.assertNotIn("memory_write", function.unknowns)
        self.assertNotIn("static_storage_declaration", function.unknowns)

    def test_static_storage_in_function_body_is_unknown(self) -> None:
        for declaration in ('static int stored;',
                            'static int stored __attribute__((used, section(".custom"))) = 1;',
                            'static _Thread_local int stored;'):
            with self.subTest(declaration=declaration):
                result = self.analyze('int run(void) { ' + declaration
                                      + ' if(!capable(21))return -1; target(); return 0; }\n')
                function, = result.functions
                self.assertIn("static_storage_declaration", function.unknowns)

    def test_compile_command_does_not_write_object_or_dependency_outputs(self) -> None:
        self.source.write_text('int run(void) { return 0; }\n')
        output, dep = self.root / 'unit.o', self.root / 'unit.d'
        command = CompileCommand(self.root, self.source, ('clang', '-c', str(self.source), '-o', str(output), '-MMD', '-MF', str(dep)))
        self.assertTrue(self.analyzer.analyze(command).complete)
        self.assertFalse(output.exists())
        self.assertFalse(dep.exists())

    def fingerprint_pair(self, old: str, new: str, old_excluded: str, new_excluded: str) -> tuple[str | None, str | None]:
        self.source.write_text(old)
        command = CompileCommand.for_source(self.source)
        def exclusions(text: str, part: str) -> tuple[ClangByteExclusion, ...]:
            start = text.encode().index(part.encode())
            return (ClangByteExclusion(self.source, start, start + len(part.encode())),)
        before = self.analyzer.fingerprint(command, excluded_spans=exclusions(old, old_excluded))
        after = self.analyzer.fingerprint(command, overlays=(SourceOverlay(self.source, new),), excluded_spans=exclusions(new, new_excluded))
        self.assertTrue(before.complete and after.complete, (before.diagnostics, after.diagnostics))
        self.assertGreater(before.tokens, 0)
        return before.digest, after.digest

    def test_fingerprint_ignores_only_excluded_c_tokens(self) -> None:
        old = 'int run(void) { return 1; }\nint outside=7;\n'
        before, after = self.fingerprint_pair(old, old.replace('return 1', 'return 2'), 'return 1;', 'return 2;')
        self.assertEqual(before, after)
        before, after = self.fingerprint_pair(old, old.replace('outside=7', 'outside=8'), 'return 1;', 'return 1;')
        self.assertNotEqual(before, after)

    def test_fingerprint_preserves_counter_and_line_effects(self) -> None:
        old = '#define POS __COUNTER__\nint run(void) { return 1; }\nint outside=POS;\n'
        new = old.replace('return 1;', 'return POS;')
        before, after = self.fingerprint_pair(old, new, 'return 1;', 'return POS;')
        self.assertNotEqual(before, after)
        old = '#define POS __LINE__\nint run(void) { return 1; }\nint outside=POS;\n'
        new = old.replace('return 1;', 'return\n1;')
        before, after = self.fingerprint_pair(old, new, 'return 1;', 'return\n1;')
        self.assertNotEqual(before, after)

    def test_fingerprint_preserves_compiler_evaluated_location_builtins(self) -> None:
        for builtin in ('__builtin_LINE', '__builtin_COLUMN', '__builtin_FILE', '__builtin_FILE_NAME',
                        '__builtin_FUNCTION', '__builtin_FUNCSIG', '__builtin_source_location'):
            with self.subTest(builtin=builtin):
                old = 'int run(void) { return 1; }\nint value(void) { return ' + builtin + '(); }\n'
                new = old.replace('return 1;', 'return\n1;')
                before, after = self.fingerprint_pair(old, new, 'return 1;', 'return\n1;')
                self.assertNotEqual(before, after)
        old = '#define POSITION __builtin_LINE()\nint value(void) { return POSITION; }\n'
        self.source.write_text(old)
        before = self.analyzer.fingerprint(CompileCommand.for_source(self.source))
        after = self.analyzer.fingerprint(CompileCommand.for_source(self.source),
                                          overlays=(SourceOverlay(self.source, old.replace('int value', '\nint value')),))
        self.assertTrue(before.complete and after.complete, (before.diagnostics, after.diagnostics))
        self.assertNotEqual(before.digest, after.digest)

    def test_fingerprint_rejects_cpp_caller_dependent_source_locations(self) -> None:
        self.source.write_text('int value(int line = __builtin_LINE()) { return line; }\nint run() { return value(); }\n')
        command = CompileCommand(self.root, self.source, ('clang', '-std=gnu++20', '-x', 'c++', str(self.source)))
        result = self.analyzer.fingerprint(command)
        self.assertFalse(result.complete)
        self.assertIn('cpp_source_location_context_not_modeled', result.diagnostics)

    def test_fingerprint_keeps_ident_directives(self) -> None:
        old = '#ident "before"\nint value;\n'
        before, after = self.fingerprint_pair(old, old.replace('"before"', '"after"'), '#ident "before"', '#ident "after"')
        self.assertNotEqual(before, after)

    def test_fingerprint_rejects_macro_dependent_pragma_state(self) -> None:
        self.source.write_text('#define ALIGNMENT 1\n#pragma pack(ALIGNMENT)\nstruct value { char a; int b; };\n')
        result = self.analyzer.fingerprint(CompileCommand.for_source(self.source))
        self.assertFalse(result.complete)
        self.assertTrue(any(reason.startswith('macro_dependent_pragma_not_modeled') for reason in result.diagnostics))

    def test_fingerprint_keeps_macro_definitions_and_pragmas_inside_exclusions(self) -> None:
        for old, new in (('#define UNUSED 1\nint outside;\n', '#define UNUSED 2\nint outside;\n'),
                         ('#pragma pack(1)\nstruct object { char a; int b; };\n', '#pragma pack(2)\nstruct object { char a; int b; };\n')):
            with self.subTest(old=old):
                before, after = self.fingerprint_pair(old, new, old.splitlines()[0], new.splitlines()[0])
                self.assertNotEqual(before, after)

    def test_fingerprint_keeps_macro_argument_pragma_effects(self) -> None:
        old = '#define P(x) _Pragma(#x)\nP(pack(1))\nstruct object { char a; int b; };\n'
        new = old.replace('P(pack(1))', 'P(pack(2))')
        self.source.write_text(old)
        before = self.analyzer.fingerprint(CompileCommand.for_source(self.source))
        after = self.analyzer.fingerprint(CompileCommand.for_source(self.source), overlays=(SourceOverlay(self.source, new),))
        self.assertFalse(before.complete and after.complete and before.digest == after.digest)

    def test_fingerprint_is_fresh_after_cached_ast_and_tracks_headers(self) -> None:
        header = self.root / 'api.h'; header.write_text('#define VALUE 7\n')
        self.source.write_text('#include "api.h"\nint run(void) { return VALUE; }\n')
        command = CompileCommand.for_source(self.source)
        self.assertTrue(self.analyzer.analyze(command).complete)
        before = self.analyzer.fingerprint(command)
        after = self.analyzer.fingerprint(command, overlays=(SourceOverlay(header, '#define VALUE 8\n'),))
        self.assertTrue(before.complete and after.complete, (before.diagnostics, after.diagnostics))
        self.assertIn(header, after.dependencies)
        self.assertNotEqual(before.digest, after.digest)

    def test_fingerprint_rejects_precompiled_inputs_and_errors(self) -> None:
        self.source.write_text('int run(void) { return 0; }\n')
        self.assertFalse(self.analyzer.fingerprint(CompileCommand.for_source(self.source, flags=('-fmodules',))).complete)
        self.source.write_text('#include "missing.h"\n')
        self.assertFalse(self.analyzer.fingerprint(CompileCommand.for_source(self.source)).complete)


if __name__ == "__main__":
    unittest.main()
