"""Compiler source and caller facts used by runtime policy masks."""

from pathlib import Path

from .policy_clang import ClangByteExclusion, ClangFunction, ClangSpan, TranslationUnitFacts


def caller_closure_complete(facts: TranslationUnitFacts) -> bool:
    """Opaque sibling/header transfers cannot certify a closed caller set."""
    return (facts.complete and facts.inline_assembly_coverage_complete
            and all(assembly.kind == "empty_barrier" for assembly in facts.inline_assembly)
            and facts.indirect_call_coverage_complete and not facts.indirect_calls
            and not any("indirect_call" in function.unknowns for function in facts.functions))


def execution_spans(function: ClangFunction, span: ClangSpan, path: Path) -> tuple[ClangByteExclusion, ...]:
    """Subtract declaration/type/reference spans from an unreachable code range.

    Existing tag uses can select emitted BTF/DWARF even without introducing a
    declaration. Source tokens and preprocessing events at those sites must
    still match on both real revisions. Missing inventory retains the range.
    """
    body = function.body_span
    if (not function.body_metadata_coverage_complete or span.macro
            or span.start.path != path or span.end.path != path
            or not body.start.offset <= span.start.offset <= span.end.offset <= body.end.offset):
        return ()
    protected = sorted(function.body_metadata_spans, key=lambda item: (item.start, item.end))
    if any(item.path != path or not body.start.offset <= item.start <= item.end <= body.end.offset for item in protected):
        return ()
    cursor = span.start.offset
    result: list[ClangByteExclusion] = []
    for item in protected:
        if item.end <= cursor or item.start >= span.end.offset:
            continue
        if item.start > cursor:
            result.append(ClangByteExclusion(path, cursor, item.start))
        if item.end >= span.end.offset:
            return tuple(result)
        cursor = item.end
    if cursor < span.end.offset:
        result.append(ClangByteExclusion(path, cursor, span.end.offset))
    return tuple(result)
