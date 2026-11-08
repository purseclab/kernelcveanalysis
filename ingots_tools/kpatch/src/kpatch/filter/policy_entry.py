"""Seccomp exclusions under the standard ARM64 Linux syscall-entry contract.

Compiler-resolved dispatch slots supply syscall numbers. This models ordinary
syscall dispatch, not arbitrary kernel code invoking exported wrappers, injected
kernel instrumentation, or privileged brokers. The caller must keep those scope
limitations explicit and compare preprocessing outside every proposed body mask.
"""

from dataclasses import dataclass
from pathlib import Path
import re

from .config_filter import ConfigValue, KernelConfig
from .policy_clang import ClangByteExclusion, ClangFunction, ClangSyscallTable, TranslationUnitFacts
from .policy_context import RevisionCompiler
from .policy_profile import PolicyTargetProfile
from .policy_rules import GateExclusion
from .policy_seccomp import Disposition, PinnedSeccompFilter, SyscallTarget
from .policy_source import caller_closure_complete, emission_sensitive_functions, execution_spans
from .whitespace.c_lexer import tokenize_c_source


_AUDIT_AARCH64 = 0xC00000B7
_AUDIT_ARM = 0x40000028
# These describe execution of an unreachable body. New/translation-related
# unknowns remain barriers; inline assembly and static storage are not allowed.
_RUNTIME_UNKNOWNS = frozenset({"macro_function_definition", "cleanup_attribute",
                               "credential_context_change", "nonlocal_control_flow", "memory_write"})


@dataclass(frozen=True, slots=True)
class _TableRole:
    path: str
    name: str
    audit_arch: int


_NATIVE = _TableRole("arch/arm64/kernel/sys.c", "sys_call_table", _AUDIT_AARCH64)
_COMPAT = _TableRole("arch/arm64/kernel/sys32.c", "compat_sys_call_table", _AUDIT_ARM)


@dataclass(frozen=True, slots=True)
class SeccompBodyExclusion:
    function: ClangFunction
    gate: GateExclusion
    spans: tuple[ClangByteExclusion, ...]


@dataclass(frozen=True, slots=True)
class Arm64SeccompEntries:
    filter: PinnedSeccompFilter
    source_root: Path
    tables: tuple[ClangSyscallTable, ...]

    @classmethod
    def for_revision(cls, compiler: RevisionCompiler, revision: str, config: KernelConfig,
                     profile: PolicyTargetProfile, pinned_filter: PinnedSeccompFilter) -> "Arm64SeccompEntries | None":
        if (profile.architecture != "aarch64" or profile.seccomp.architecture != "aarch64"
                or profile.seccomp.mode != 2 or profile.seccomp.filter_sha256 != pinned_filter.digest
                or any(config.get(symbol) is not ConfigValue.ENABLED
                       for symbol in ("CONFIG_ARM64", "CONFIG_SECCOMP", "CONFIG_SECCOMP_FILTER"))):
            return None
        # A captured app filter cannot certify another process's syscall entry.
        if profile.mediation_complete and any(subject != profile.subject_type for subject in profile.modeled_subject_types):
            return None
        roles = (_NATIVE, _COMPAT) if config.get("CONFIG_COMPAT") is ConfigValue.ENABLED else (_NATIVE,)
        tables: list[ClangSyscallTable] = []
        for role in roles:
            facts = compiler.facts(revision, role.path)
            matches = [table for table in facts.syscall_tables if table.name == role.name
                       and table.source_path == compiler.build.source_root / role.path
                       and table.audit_arch == role.audit_arch]
            if not facts.complete or len(matches) != 1 or not matches[0].complete:
                return None
            table = matches[0]
            if (not table.bindings or len({binding.number for binding in table.bindings}) != len(table.bindings)
                    or any(not 0 <= binding.number < 2048 for binding in table.bindings)):
                return None
            tables.append(table)
        return cls(pinned_filter, compiler.build.source_root, tuple(tables))

    def _denial(self, wrapper: ClangFunction) -> GateExclusion | None:
        targets = tuple(SyscallTarget(table.audit_arch, binding.number) for table in self.tables
                        for binding in table.bindings if binding.callee_usr == wrapper.usr)
        if not targets or any(self.filter.evaluate(target).disposition is not Disposition.DENIED for target in targets):
            return None
        bindings = ", ".join(f"{target.audit_arch:#x}:{target.number}" for target in targets)
        return GateExclusion("seccomp", "Pinned filter universally denies every configured syscall alias (" + bindings + ")")

    def exclusions(self, source: bytes, path: Path, facts: TranslationUnitFacts) -> tuple[SeccompBodyExclusion, ...]:
        functions = {function.usr: function for function in facts.functions}
        sensitive = emission_sensitive_functions(facts)
        if sensitive is None:
            return ()
        known = frozenset(function.usr for function in facts.emission_functions)
        denied: dict[str, GateExclusion] = {}
        for function in functions.values():
            if function.usr in sensitive or not _runtime_body(function, path):
                continue
            wrapper = _syscall_wrapper(source, path, function, facts, self.source_root)
            if wrapper is None:
                continue
            chain = tuple(candidate for candidate in functions.values()
                          if candidate.span.start.path == path
                          and candidate.span.start.offset == function.span.start.offset)
            if not caller_closure_complete(facts, chain):
                continue
            gate = self._denial(wrapper)
            if gate is not None:
                denied[function.usr] = gate
        # A private helper cannot gain an independent entry merely because the
        # compilation database also contains unrelated translation units. All
        # compiler-resolved callers must already be denied, with no escape or
        # compatible opaque call site (including sites in included headers).
        incoming: dict[str, list[ClangFunction]] = {usr: [] for usr in functions}
        for caller in functions.values():
            for call in caller.calls:
                if call.callee_usr in incoming:
                    incoming[call.callee_usr].append(caller)
        helpers = tuple(function for function in functions.values()
                        if function.usr not in denied and function.usr not in sensitive
                        and function.is_static and _runtime_body(function, path)
                        and incoming[function.usr]
                        and not any(reference.usr == function.usr for reference in facts.address_taken)
                        and caller_closure_complete(facts, (function,)))
        for _ in range(min(len(functions), 64)):
            additions = {function.usr: denied[incoming[function.usr][0].usr] for function in helpers
                         if function.usr not in denied and all(caller.usr in denied for caller in incoming[function.usr])}
            if not additions:
                break
            denied.update(additions)
        return tuple(SeccompBodyExclusion(functions[usr], gate, spans) for usr, gate in denied.items()
                     if (spans := execution_spans(functions[usr], functions[usr].body_span, path, known_functions=known)))


def _runtime_body(function: ClangFunction, path: Path) -> bool:
    body = function.body_span
    return (not body.macro and body.start.path == path and body.end.path == path
            and function.declaration_coverage_complete
            and not set(function.body_translation_effects).difference({"body_typedef", "body_tag_declaration"})
            and not set(function.unknowns).difference(_RUNTIME_UNKNOWNS))


def _syscall_wrapper(source: bytes, path: Path, body: ClangFunction, facts: TranslationUnitFacts,
                     root: Path) -> ClangFunction | None:
    prefix = source[body.span.start.offset:body.body_span.start.offset]
    tokens = tokenize_c_source(prefix.decode())
    if tokens is None or len(tokens) < 4 or tokens[1].value != "(" or tokens[-1].value != ")":
        return None
    macro = re.fullmatch(r"SYSCALL_DEFINE([0-6])", tokens[0].value)
    name = tokens[2].value
    if macro is None or re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", name) is None:
        return None
    wrapper_name = "__arm64_sys_" + name
    names = ((wrapper_name,) if macro[1] == "0" else
             ("__do_sys_" + name, "__se_sys_" + name, wrapper_name))
    if (body.name != names[0] or not body.span.macro or body.span.spelling_start is None
            or body.span.spelling_start.path != root / "arch/arm64/include/asm/syscall_wrapper.h"):
        return None
    chain: list[ClangFunction] = []
    for index, expected in enumerate(names):
        matches = [function for function in facts.functions if function.name == expected]
        if len(matches) != 1:
            return None
        function = matches[0]
        if (function.span.start.path != path or function.span.start.offset != body.span.start.offset
                or function.is_static != (index < len(names) - 1)
                or any(reference.usr == function.usr for reference in facts.address_taken)):
            return None
        if index and not _trusted_wrapper_body(function, root):
            return None
        chain.append(function)
    if chain[-1].usr != "c:@F@" + wrapper_name:
        return None
    for index, target in enumerate(chain):
        incoming = [(caller, call) for caller in facts.functions for call in caller.calls if call.callee_usr == target.usr]
        if index == len(chain) - 1:
            if incoming:
                return None
            continue
        if (len(incoming) != 1 or incoming[0][0].usr != chain[index + 1].usr
                or not incoming[0][1].span.macro
                or incoming[0][1].span.start.offset != body.span.start.offset):
            return None
    return chain[-1]


def _trusted_wrapper_body(function: ClangFunction, root: Path) -> bool:
    span = function.body_span
    header = root / "arch/arm64/include/asm/syscall_wrapper.h"
    return (span.macro and span.spelling_start is not None and span.spelling_end is not None
            and span.spelling_start.path == header and span.spelling_end.path == header
            and not set(function.unknowns).difference({"macro_function_definition"}))
