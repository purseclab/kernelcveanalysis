"""Compiler source and caller facts used by runtime policy masks."""

from pathlib import Path
from functools import lru_cache
from collections import defaultdict, deque
import re

from .policy_clang import ClangByteExclusion, ClangFunction, ClangSpan, TranslationUnitFacts


_ARM64_NONCALLING = frozenset("""
    nop cmp ccmp cmn tst sbc add adds sub subs and ands bic bics orr orn eor eon
    mov movk movn movz lsl lsr asr ror sxtb sxth sxtw uxtb uxth
    ldr ldrb ldrh ldrsw ldur ldurb ldurh ldtr ldtrb ldtrh ldp ldnp str strb strh stur sturb sturh stp stnp
    ldar ldarb ldarh stlr stlrb stlrh ldxr ldxrb ldxrh ldaxr ldaxrb ldaxrh
    stxr stxrb stxrh stlxr stlxrb stlxrh ldxp ldaxp stxp stlxp
    prfm dmb dsb isb mrs msr tlbi dc ic sys sysl hint wfe wfi sevl sev yield
    brk hvc smc ldg stg stzg irg
""".split())
_ATOMIC_INSTRUCTION = re.compile(r"(?:cas|casp|swp|ldadd|ldclr|ldeor|ldset|ldsmax|ldsmin|ldumax|ldumin)(?:a|l|al)?[bh]?|st(?:add|clr|eor|set|smax|smin|umax|umin)[bh]?")
_LOCAL_BRANCH = re.compile(r"(?:\.|[0-9]+[bf]|%l(?:\[[A-Za-z_][A-Za-z_0-9]*\]|[0-9]+))")
_DATA_SECTION = re.compile(r"(?:\.rodata(?:\.[A-Za-z_0-9.$]+)?|\.altinstructions|__bug_table|__ex_table|__jump_table)")


def _assembly_statements(text: str) -> tuple[str, ...] | None:
    """Split assembler separators without interpreting strings as instructions."""
    result: list[str] = []
    current: list[str] = []
    quoted = escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        if quoted:
            current.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif text.startswith("//", index):
            end = text.find("\n", index)
            index = len(text) if end < 0 else end
            continue
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end < 0:
                return None
            current.append(" ")
            index = end + 2
            continue
        elif char == '"':
            quoted = True
            current.append(char)
        elif char in ";\n":
            result.append("".join(current).strip())
            current.clear()
        else:
            current.append(char)
        index += 1
    if quoted:
        return None
    result.append("".join(current).strip())
    return tuple(result)


def _nonbranch_encoding(expression: str) -> bool:
    # ARM64 system instructions and GCS stores cannot become branch opcodes
    # through OR operands. Never admit arbitrary .inst/.word encodings.
    expression = expression.strip()
    while expression.startswith("("):
        depth = 0
        for index, char in enumerate(expression):
            depth += (char == "(") - (char == ")")
            if depth == 0:
                break
        if depth or index != len(expression) - 1:
            break
        expression = expression[1:-1].strip()
    reduced = re.sub(r"\([^()]*\)", "X", expression)
    while reduced != expression:
        expression = reduced
        reduced = re.sub(r"\([^()]*\)", "X", expression)
    if re.fullmatch(r"\s*0x[dD][59][0-9a-fA-F]{6}\s*(?:\|\s*X\s*)*", reduced) is None:
        return False
    return True


@lru_cache(maxsize=4096)
def _noncalling_arm64_assembly(text: str) -> bool:
    statements = _assembly_statements(text)
    if statements is None:
        return False
    data = False
    stack: list[bool] = []
    macros: set[str] = set()
    defining_macro: str | None = None
    for statement in statements:
        statement = re.sub(r"^(?:[0-9]+|\.[A-Za-z_.$][A-Za-z_0-9.$]*)\s*:\s*", "", statement).strip()
        if not statement:
            continue
        parts = statement.split(None, 1)
        mnemonic, operands = parts[0].lower(), parts[1] if len(parts) > 1 else ""
        if defining_macro is not None:
            if mnemonic == ".endm":
                macros.add(defining_macro)
                defining_macro = None
            elif mnemonic != ".inst" or not _nonbranch_encoding(operands):
                return False
            continue
        if mnemonic in {".pushsection", ".section"}:
            if mnemonic == ".pushsection":
                stack.append(data)
            flags = re.search(r',\s*"([^\"]*)"', operands)
            name = operands.split(",", 1)[0].strip().strip('"')
            # GNU assemblers can ignore changed flags on an existing section.
            # Flags alone never turn .text or an unknown section into data.
            data = (_DATA_SECTION.fullmatch(name) is not None and flags is not None
                    and "x" not in flags[1] and "a" in flags[1])
        elif mnemonic == ".popsection":
            if not stack:
                return False
            data = stack.pop()
        elif mnemonic in {".previous", ".subsection", ".else", ".endif", ".endr"}:
            # Returning sections and conditional/repeated assembler blocks can
            # select different subsection histories. Treat the result as code;
            # never let uncertain section state authorize raw instruction data.
            data = False
        elif mnemonic in {".word", ".long", ".quad", ".hword", ".short", ".byte", ".string", ".asciz"}:
            if not data:
                return False
        elif mnemonic == ".inst":
            if not _nonbranch_encoding(operands):
                return False
        elif mnemonic in {".align", ".balign", ".p2align", ".org"}:
            if "," in operands:
                return False
        elif mnemonic in {".if", ".arch", ".arch_extension", ".irp", ".rept", ".equ"}:
            continue
        elif mnemonic == ".macro":
            if not operands or operands.split(",", 1)[0].split()[0] not in {"mrs_s", "msr_s"}:
                return False
            defining_macro = operands.split(",", 1)[0].split()[0]
        elif mnemonic == ".purgem":
            macros.discard(operands)
        elif mnemonic in {"mrs_s", "msr_s"}:
            if mnemonic not in macros:
                return False
        elif mnemonic == "b" or mnemonic.startswith("b.") or mnemonic in {"cbz", "cbnz", "tbz", "tbnz"}:
            if _LOCAL_BRANCH.fullmatch(operands.rsplit(",", 1)[-1].strip()) is None:
                return False
        elif mnemonic not in _ARM64_NONCALLING and _ATOMIC_INSTRUCTION.fullmatch(mnemonic) is None:
            return False
    return not stack and defining_macro is None


def caller_closure_complete(facts: TranslationUnitFacts, targets: tuple[ClangFunction, ...]) -> bool:
    """Exclude unrelated callbacks/atomics from a target's ordinary C callers.

    No arbitrary function-pointer type punning, runtime text injection or custom
    syscall-wrapper dispatch is modeled. Explicit references, compatible opaque
    calls and unsupported assembly remain barriers, including header sites.
    """
    if (not facts.complete or not facts.inline_assembly_coverage_complete
            or not facts.indirect_call_coverage_complete or not facts.indirect_target_coverage_complete
            or any(target.usr in facts.indirect_call_targets for target in targets)):
        return False
    for assembly in facts.inline_assembly:
        if assembly.kind == "empty_barrier":
            continue
        if any(re.search(r"\b" + re.escape(target.name) + r"\b", assembly.text) for target in targets):
            return False
        if facts.target_architecture != "aarch64" or not _noncalling_arm64_assembly(assembly.text):
            return False
    return True


def _registration_assembly(text: str) -> bool:
    statements = _assembly_statements(text)
    if statements is None:
        return True
    alternatives = False
    for statement in statements:
        if re.match(r"\.(?:pushsection|section)\s+", statement):
            name = statement.split(None, 1)[1].split(",", 1)[0].strip().strip('"')
            if _DATA_SECTION.fullmatch(name) is None:
                return True
            alternatives |= name == ".altinstructions"
    if alternatives:
        for statement in statements:
            if match := re.match(r"\.(?:word|long)\s+(.+)", statement):
                operand = re.sub(r"\s+", "", match[1])
                if re.fullmatch(r"(?:[0-9]+[bf]|alt_cb_patch_nops)-\.", operand) is None:
                    return True
    return False


def emission_sensitive_functions(facts: TranslationUnitFacts) -> frozenset[str] | None:
    """Positive linker/registration effects, including unused header bodies.

    Runtime unreachability cannot erase their controlling source: an inlined
    callback registration can execute at boot even if its syscall never runs.
    Ordinary local alternative patch records and private data placement do not
    supply independent runtime callbacks.
    """
    if not facts.emission_coverage_complete:
        return None
    functions = {function.usr: function for function in facts.emission_functions}
    if (len(functions) != len(facts.emission_functions)
            or any(function.usr not in functions for function in facts.functions)):
        return None
    reverse: dict[str, set[str]] = defaultdict(set)
    sensitive: set[str] = set()
    nop_definitions = {item.usr for item in functions.values() if item.name == "alt_cb_patch_nops"}
    for function in functions.values():
        effects = tuple(effect for effect in function.effects
                        if re.fullmatch(r"sectioned_storage:\.(?:data|bss|rodata)(?:\.[A-Za-z_0-9.$-]+)?", effect) is None)
        if effects or function.usr in nop_definitions or any(_registration_assembly(code) for code in function.assembly):
            sensitive.add(function.usr)
        for callee in function.callees:
            reverse[callee].add(function.usr)
        if any(re.search(r"\balt_cb_patch_nops\b", code) for code in function.assembly):
            for callee in nop_definitions:
                reverse[callee].add(function.usr)
    pending = deque(sensitive)
    while pending:
        for caller in reverse.get(pending.popleft(), ()):
            if caller not in sensitive:
                sensitive.add(caller)
                pending.append(caller)
    return frozenset(sensitive)


def execution_spans(function: ClangFunction, span: ClangSpan, path: Path, *,
                    known_functions: frozenset[str] = frozenset()) -> tuple[ClangByteExclusion, ...]:
    """Ignore runtime and local debug/type metadata inside unreachable code.

    Nonlocal declarations, storage, attributes and assembler effects remain
    barriers. Outgoing call spellings/arguments are functional inputs rather
    than debug provenance. Preprocessor events outside ranges compare separately.
    """
    body = function.body_span
    if (not function.declaration_coverage_complete or span.macro
            or span.start.path != path or span.end.path != path
            or not body.start.offset <= span.start.offset <= span.end.offset <= body.end.offset
            or set(function.body_translation_effects).difference({"body_typedef", "body_tag_declaration"})):
        return ()
    protected = sorted((call.span for call in function.calls if call.callee_usr not in known_functions),
                       key=lambda item: (item.start.offset, item.end.offset))
    if any(item.start.path != path or item.end.path != path
           or not body.start.offset <= item.start.offset <= item.end.offset <= body.end.offset for item in protected):
        return ()
    cursor = span.start.offset
    result: list[ClangByteExclusion] = []
    for item in protected:
        if item.end.offset <= cursor or item.start.offset >= span.end.offset:
            continue
        if item.start.offset > cursor:
            result.append(ClangByteExclusion(path, cursor, item.start.offset))
        cursor = max(cursor, item.end.offset)
        if cursor >= span.end.offset:
            return tuple(result)
    if cursor < span.end.offset:
        result.append(ClangByteExclusion(path, cursor, span.end.offset))
    return tuple(result)
