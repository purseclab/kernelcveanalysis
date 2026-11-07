"""Recognize diagnostic wording under the standard kernel logging API contract.

This is an explicit policy exemption for log text, not C program equivalence.
Unknown calls, debug selectors, format changes and consumed return values stay
observable. Included/generated macro overrides need compiler-aware analysis.
"""

from dataclasses import dataclass
import re

from tree_sitter import Node

from .syntax import call_expressions, declaration_names, node_text, parse_source
from .whitespace.c_lexer import CTokenKind, tokenize_c_source


_LEVELS = ("emerg", "alert", "crit", "err", "warn", "notice", "info")
_LOG_ARGUMENTS = {
    f"{family}_{level}{suffix}".encode(): position
    for family, position in (("pr", 0), ("dev", 1))
    for level in _LEVELS for suffix in ("", "_once", "_ratelimited")
} | {b"printk": 0}
_KERN_PREFIXES = frozenset({
    b"KERN_EMERG", b"KERN_ALERT", b"KERN_CRIT", b"KERN_ERR", b"KERN_WARNING",
    b"KERN_NOTICE", b"KERN_INFO", b"KERN_DEBUG", b"KERN_DEFAULT", b"KERN_CONT",
})
_LOG_CALL = re.compile(rb"\b(?:(?:pr|dev)_(?:emerg|alert|crit|err|warn|notice|info)(?:_once|_ratelimited)?|printk)\s*\(")
_DEFINE = re.compile(rb"(?m)^[ \t]*#[ \t]*(define|undef)[ \t]+([A-Za-z_]\w*)([^\n]*)")
_FORMAT = re.compile(rb"%(?:%|[-+ #0]*(?:\*|[0-9]+)?(?:\.(?:\*|[0-9]*))?(?:hh|ll|[hlztj])?[diuoxXcsp])")
_ESCAPES = dict(zip(b"abfnrtv\\\"'?", (7, 8, 12, 10, 13, 9, 11, 92, 34, 39, 63)))
_STATEMENT_ANCESTORS = frozenset({
    "compound_statement", "if_statement", "else_clause", "for_statement",
    "while_statement", "do_statement", "switch_statement", "case_statement",
    "labeled_statement", "preproc_if", "preproc_ifdef", "preproc_else", "preproc_elif",
})


@dataclass(frozen=True, slots=True)
class DiagnosticSource:
    contents: bytes
    literals: tuple[bytes, ...]


def _decode_literal(value: bytes) -> bytes | None:
    # Retain prefixed, numeric-escape and physically spliced literals initially.
    if not value.startswith(b'"') or not value.endswith(b'"'):
        return None
    result = bytearray()
    position = 1
    while position < len(value) - 1:
        char = value[position]
        position += 1
        if char == 92:
            if position >= len(value) - 1 or value[position] not in _ESCAPES:
                return None
            char = _ESCAPES[value[position]]
            position += 1
        if char == 0 or char == 1:
            return None
        result.append(char)
    return bytes(result)


def _signature(value: bytes) -> bytes | None:
    """Keep every conversion, kernel %p suffix and ordered control byte."""
    parts: list[bytes] = []
    position = 0
    while position < len(value):
        char = value[position]
        if char == 37:
            match = _FORMAT.match(value, position)
            if match is None:
                return None
            end = match.end()
            if match.group().endswith(b"p"):
                while end < len(value) and (65 <= value[end] <= 90 or 97 <= value[end] <= 122 or 48 <= value[end] <= 57):
                    end += 1
            parts.append(b"format:" + value[position:end])
            position = end
            continue
        if char < 32 or char == 127:
            parts.append(b"control:" + bytes((char,)))
        position += 1
    return b"\0".join(parts)


def _standard_prefix(body: bytes) -> bool:
    match = re.fullmatch(rb"\(\s*([A-Za-z_]\w*)\s*\)\s*(.*)", body)
    if match is None:
        return False
    parameter, expansion = match.groups()
    tokens = tokenize_c_source(expansion.decode())
    if not tokens or tokens[-1].value.encode() != parameter:
        return False
    for token in tokens[:-1]:
        if token.kind is CTokenKind.IDENTIFIER and token.value in {"KBUILD_MODNAME", "KBUILD_BASENAME"}:
            continue
        if token.kind is not CTokenKind.STRING_LITERAL:
            return False
        value = _decode_literal(token.value.encode())
        if value is None or b"%" in value:
            return False
    return True


def _blocked_names(source: bytes) -> set[bytes]:
    blocked: set[bytes] = set()
    # Join directives for inspection only; the literal decoder still rejects
    # physical splices rather than silently changing source coordinates.
    for directive in _DEFINE.finditer(source.replace(b"\\\n", b"")):
        operation, name, body = directive.groups()
        if name in {b"KBUILD_MODNAME", b"KBUILD_BASENAME"} or name in _KERN_PREFIXES:
            blocked.update(_LOG_ARGUMENTS)
        if name in _LOG_ARGUMENTS:
            blocked.add(name)
        if name in {b"pr_fmt", b"dev_fmt"} and (operation != b"define" or not _standard_prefix(body)):
            family = name.split(b"_", 1)[0] + b"_"
            blocked.update(name for name in _LOG_ARGUMENTS if name.startswith(family))
    return blocked


def _standalone_call(call: Node) -> bool:
    statement = call.parent
    if statement is None or statement.type != "expression_statement":
        return False
    parent = statement.parent
    while parent is not None:
        if parent.type == "function_definition":
            return True
        if parent.type not in _STATEMENT_ANCESTORS:
            return False
        parent = parent.parent
    return False


def _format_argument(call: Node, blocked: set[bytes]) -> Node | None:
    function = call.child_by_field_name("function")
    arguments = call.child_by_field_name("arguments")
    if function is None or function.type != "identifier" or arguments is None or call.has_error:
        return None
    name = node_text(function)
    position = _LOG_ARGUMENTS.get(name)
    if position is None or name in blocked or not _standalone_call(call):
        return None
    values = [child for child in arguments.named_children if child.type != "comment"]
    if len(values) <= position or values[position].type not in {"string_literal", "concatenated_string"}:
        return None
    return values[position]


def _normalized_format(argument: Node) -> bytes | None:
    if b"\\\n" in node_text(argument) or b"\\\r\n" in node_text(argument):
        return None
    tokens = tokenize_c_source(node_text(argument).decode())
    if not tokens:
        return None
    prefix = b""
    if tokens[0].kind is CTokenKind.IDENTIFIER and tokens[0].value.encode() in _KERN_PREFIXES:
        prefix = tokens[0].value.encode() + b" "
        tokens = tokens[1:]
    values: list[bytes] = []
    for token in tokens:
        if token.kind is not CTokenKind.STRING_LITERAL:
            return None
        value = _decode_literal(token.value.encode())
        if value is None:
            return None
        values.append(value)
    signature = _signature(b"".join(values)) if values else None
    if signature is None:
        return None
    # A constant independent of wording, with all formatting semantics encoded.
    return prefix + b'"' + signature.hex().encode() + b'"' + b"\n" * node_text(argument).count(b"\n")


def normalize_diagnostic_strings(source: bytes) -> DiagnosticSource:
    if _LOG_CALL.search(source) is None:
        return DiagnosticSource(source, ())
    tree = parse_source(source)
    blocked = _blocked_names(source) | (set(declaration_names(tree)) & _LOG_ARGUMENTS.keys())
    replacements: list[tuple[Node, bytes]] = []
    for call in call_expressions(tree):
        argument = _format_argument(call, blocked)
        if argument is not None and (normalized := _normalized_format(argument)) is not None:
            replacements.append((argument, normalized))
    replacements.sort(key=lambda item: item[0].start_byte)
    contents: list[bytes] = []
    position = 0
    for argument, normalized in replacements:
        contents.extend((source[position:argument.start_byte], normalized))
        position = argument.end_byte
    contents.append(source[position:])
    return DiagnosticSource(b"".join(contents), tuple(node_text(argument) for argument, _ in replacements))
