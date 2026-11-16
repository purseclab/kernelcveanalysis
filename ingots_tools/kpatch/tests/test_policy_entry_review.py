"""Independent compiler witnesses for syscall-entry proof boundaries."""

from pathlib import Path
import struct
from tempfile import TemporaryDirectory
from typing import ClassVar
import unittest

from kpatch.filter.policy_clang import (
    ClangAnalyzer, ClangByteExclusion, ClangSyscallTable, ClangToolchain, ClangUnavailable, CompileCommand,
    TranslationUnitFacts,
)
from kpatch.filter.policy_entry import Arm64SeccompEntries
from kpatch.filter.policy_seccomp import PinnedSeccompFilter


_WRAPPERS = """struct pt_regs { long regs[6]; };
#define SYSCALL_DEFINE1(name, type, arg) \
static long __do_sys_##name(type arg); \
static long __se_sys_##name(long arg) { return __do_sys_##name((type)arg); } \
long __arm64_sys_##name(const struct pt_regs *regs) { return __se_sys_##name(regs->regs[0]); } \
static long __do_sys_##name(type arg)
"""


def _instruction(code: int, k: int, jt: int = 0, jf: int = 0) -> bytes:
    return struct.pack("<HBBI", code, jt, jf, k)


class PolicyEntryReviewTests(unittest.TestCase):
    binary: ClassVar[Path]

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
        self.header = self.root / "arch/arm64/include/asm/syscall_wrapper.h"
        self.header.parent.mkdir(parents=True)
        self.header.write_text(_WRAPPERS)
        self.source = self.root / "unit.c"
        self.analyzer = ClangAnalyzer(self.binary)
        self.addCleanup(self.analyzer.close)
        self.filter = PinnedSeccompFilter(_instruction(0x20, 0) + _instruction(0x15, 0, jf=1)
                                          + _instruction(0x06, 0x00050001) + _instruction(0x06, 0x7FFF0000))

    def analyze(self, suffix: str = "", *, body: str = "return value + 1;") -> TranslationUnitFacts:
        self.source.write_text('#include "arch/arm64/include/asm/syscall_wrapper.h"\n'
                               + "SYSCALL_DEFINE1(test, int, value) {" + body + "}\n" + suffix)
        return self.analyze_file(self.source)

    def analyze_file(self, path: Path) -> TranslationUnitFacts:
        command = CompileCommand.for_source(path, flags=("--target=aarch64-linux-gnu",))
        facts = self.analyzer.analyze(command)
        self.assertEqual(facts.diagnostics, ())
        return facts

    def table(self, *, compat: bool = False, aliases: bool = False) -> ClangSyscallTable:
        table_path = self.root / "arch/arm64/kernel" / ("sys32.c" if compat else "sys.c")
        table_path.parent.mkdir(parents=True, exist_ok=True)
        name = "compat_sys_call_table" if compat else "sys_call_table"
        table_path.write_text('struct pt_regs;\n'
                              'long __arm64_sys_test(const struct pt_regs *);\n'
                              'long allowed(const struct pt_regs *);\n'
                              'typedef long (*syscall_fn_t)(const struct pt_regs *);\n'
                              'const syscall_fn_t ' + name + '[2] = {__arm64_sys_test, '
                              + ('__arm64_sys_test' if aliases else 'allowed') + '};\n')
        table, = self.analyze_file(table_path).syscall_tables
        self.assertTrue(table.complete, table.status_reason)
        return table

    def excluded(self, facts: TranslationUnitFacts, *, tables: tuple[ClangSyscallTable, ...] = ()) -> tuple[str, ...]:
        entries = Arm64SeccompEntries(self.filter, self.root, tables or (self.table(),))
        return tuple(item.function.name for item in entries.exclusions(self.source.read_bytes(), self.source, facts))

    def test_standard_wrapper_body_is_excluded_when_every_alias_denies(self) -> None:
        facts = self.analyze()
        self.assertTrue(facts.complete)
        self.assertEqual(self.excluded(facts), ("__do_sys_test",))

    def test_allowed_native_alias_retains_the_body(self) -> None:
        facts = self.analyze()
        self.assertEqual(self.excluded(facts, tables=(self.table(aliases=True),)), ())

    def test_allowed_compat_alias_retains_the_body(self) -> None:
        facts = self.analyze()
        self.assertEqual(self.excluded(facts, tables=(self.table(), self.table(compat=True, aliases=True))), ())

    def test_main_file_direct_body_and_wrapper_calls_retain(self) -> None:
        for callee, argument in (("__do_sys_test", "7"), ("__arm64_sys_test", "regs")):
            with self.subTest(callee=callee):
                facts = self.analyze("long allowed(const struct pt_regs *regs) { return " + callee + "(" + argument + "); }\n")
                self.assertEqual(self.excluded(facts), ())

    def test_header_defined_direct_caller_and_pointer_escape_retain(self) -> None:
        consumer = self.root / "consumer.h"
        for contents in ('long header_call(const struct pt_regs *r) {return __arm64_sys_test(r);}\n',
                         'long (*saved)(const struct pt_regs *) = __arm64_sys_test;\n'):
            with self.subTest(contents=contents):
                consumer.write_text(contents)
                facts = self.analyze('#include "consumer.h"\n')
                self.assertEqual(self.excluded(facts), ())

    def test_local_inline_assembly_can_call_a_denied_wrapper_from_an_allowed_entry(self) -> None:
        facts = self.analyze('long allowed(const struct pt_regs *regs) { '
                             'asm volatile("bl __arm64_sys_test"); return 0; }\n')
        # Clang cannot expose a CallExpr or DeclRefExpr for this literal branch.
        # The allowed entry at slot1 remains an actual route to the changed body.
        self.assertEqual(self.excluded(facts), ())

    def test_header_inline_assembly_can_call_a_denied_wrapper_from_an_allowed_entry(self) -> None:
        consumer = self.root / "consumer.h"
        consumer.write_text('static inline long header_call(void) { '
                             'asm volatile("bl __arm64_sys_test"); return 0; }\n')
        facts = self.analyze('#include "consumer.h"\n'
                             'long allowed(const struct pt_regs *regs) { return header_call(); }\n')
        self.assertEqual(self.excluded(facts), ())

    def test_empty_main_and_header_memory_barriers_preserve_a_valid_entry_proof(self) -> None:
        consumer = self.root / "consumer.h"
        consumer.write_text('static inline void header_barrier(void) {asm volatile("" ::: "memory");}\n')
        facts = self.analyze('#include "consumer.h"\n'
                             'long allowed(const struct pt_regs *regs) { '
                             'header_barrier(); asm volatile("" ::: "memory"); return 0; }\n')
        self.assertEqual(self.excluded(facts), ("__do_sys_test",))

    def test_main_and_header_cleanup_targets_retain_the_denied_wrapper(self) -> None:
        cleanup_body = ('struct pt_regs local __attribute__((cleanup(__arm64_sys_test))) = *regs; '
                        'return 0;')
        facts = self.analyze('long allowed(const struct pt_regs *regs) {' + cleanup_body + '}\n')
        self.assertEqual(self.excluded(facts), ())
        consumer = self.root / "consumer.h"
        consumer.write_text('static inline long header_cleanup(const struct pt_regs *regs) {' + cleanup_body + '}\n')
        facts = self.analyze('#include "consumer.h"\n'
                             'long allowed(const struct pt_regs *regs) {return header_cleanup(regs);}\n')
        self.assertEqual(self.excluded(facts), ())

    def test_header_indirect_dispatch_through_the_table_retains(self) -> None:
        consumer = self.root / "consumer.h"
        consumer.write_text('typedef long (*entry_t)(const struct pt_regs *);\n'
                             'extern const entry_t sys_call_table[2];\n'
                             'static inline long header_dispatch(const struct pt_regs *regs) {'
                             'return sys_call_table[0](regs);}\n')
        facts = self.analyze('#include "consumer.h"\n'
                             'long allowed(const struct pt_regs *regs) {return header_dispatch(regs);}\n')
        self.assertEqual(self.excluded(facts), ())

    def test_static_storage_retains_but_local_type_metadata_does_not(self) -> None:
        self.assertEqual(self.excluded(self.analyze(body="static int stored; return ++stored;")), ())
        for body in ("typedef long hidden; hidden local=value; return local;", "return sizeof(struct hidden { int member; });"):
            with self.subTest(body=body):
                self.assertEqual(self.excluded(self.analyze(body=body)), ("__do_sys_test",))

    def test_legacy_declaration_inventory_does_not_certify_runtime_only_body(self) -> None:
        facts = self.analyze()
        functions = tuple(function.model_copy(update={"declaration_coverage_complete": False})
                          if function.name == "__do_sys_test" else function for function in facts.functions)
        self.assertEqual(self.excluded(facts.model_copy(update={"functions": functions})), ())

    def test_missing_whole_translation_unit_escape_coverage_retains(self) -> None:
        facts = self.analyze()
        for field in ("inline_assembly_coverage_complete", "indirect_call_coverage_complete", "indirect_target_coverage_complete"):
            with self.subTest(field=field):
                self.assertEqual(self.excluded(facts.model_copy(update={field: False})), ())

    def test_outside_location_builtin_fingerprint_detects_denied_body_layout_changes(self) -> None:
        for builtin, old_body, new_body, separator in (
            ("__builtin_LINE", "{return 7;}", "{\nreturn 8;}", "\n"),
            ("__builtin_COLUMN", "{return 7;}", "{return 888;}", " "),
        ):
            digests: list[str | None] = []
            for body in (old_body, new_body):
                with self.subTest(builtin=builtin, body=body):
                    self.source.write_text('#include "arch/arm64/include/asm/syscall_wrapper.h"\n'
                                           'SYSCALL_DEFINE1(test, int, value) ' + body + separator
                                           + 'long allowed(void) {return ' + builtin + '();}\n')
                    facts = self.analyze_file(self.source)
                    function = next(item for item in facts.functions if item.name == "__do_sys_test")
                    span = function.body_span
                    fingerprint = self.analyzer.fingerprint(
                        CompileCommand.for_source(self.source, flags=("--target=aarch64-linux-gnu",)),
                        excluded_spans=(ClangByteExclusion(self.source, span.start.offset, span.end.offset),))
                    self.assertTrue(fingerprint.complete, fingerprint.diagnostics)
                    digests.append(fingerprint.digest)
            self.assertNotEqual(digests[0], digests[1])


if __name__ == "__main__":
    unittest.main()
