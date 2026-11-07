"""Recognize diagnostic wording under the standard kernel logging API contract.

This is an explicit policy exemption for log text, not C program equivalence.
Unknown calls, debug selectors, format changes and consumed return values stay
observable. Included/generated macro overrides need compiler-aware analysis.
"""

from dataclasses import dataclass
import re

from tree_sitter import Node, Tree

from .syntax import call_expressions, declaration_names, macro_parameter_names, node_text, nodes, parse_source
from .whitespace.c_lexer import CTokenKind, preprocessor_directive_text, tokenize_c_source


_LEVELS = ("emerg", "alert", "crit", "err", "warn", "notice", "info")
_LOG_ARGUMENTS = {
    f"{family}_{level}{suffix}".encode(): position
    for family, position in (("pr", 0), ("dev", 1))
    for level in _LEVELS for suffix in ("", "_once", "_ratelimited")
} | {b"printk": 0}
_PRINTK_DEPENDENCIES = frozenset({b"printk", b"printk_index_wrap", b"__printk_index_emit", b"_printk"})
_ONCE_DEPENDENCIES = frozenset({b"printk_once", b"DO_ONCE_LITE", b"DO_ONCE_LITE_IF", b"__ONCE_LITE_IF", b"no_printk"})
_RATE_DEPENDENCIES = frozenset({b"DEFINE_RATELIMIT_STATE", b"RATELIMIT_STATE_INIT", b"RATELIMIT_STATE_INIT_FLAGS",
                               b"DEFAULT_RATELIMIT_INTERVAL", b"DEFAULT_RATELIMIT_BURST", b"__ratelimit", b"___ratelimit"})
_DEV_DEPENDENCIES = frozenset({b"dev_printk_index_wrap", b"dev_printk_index_emit",
                              b"printk_index_subsys_emit", b"__printk_index_emit"})
_KERN_PREFIXES = frozenset({
    b"KERN_EMERG", b"KERN_ALERT", b"KERN_CRIT", b"KERN_ERR", b"KERN_WARNING",
    b"KERN_NOTICE", b"KERN_INFO", b"KERN_DEBUG", b"KERN_DEFAULT", b"KERN_CONT",
})
_MACRO_INPUTS = frozenset(b"NULL __FILE__ __LINE__ __builtin_constant_p __func__ __section __used "
                         b"_entry _entry_ptr const do file fmt func if level line pi_entry static struct "
                         b"subsys_fmt_prefix while".split())
_PR_ONCE_INPUTS = frozenset(b"__already_done __ret_cond __ret_do_once __ret_once bool false true unlikely".split())
_DEV_ONCE_INPUTS = frozenset(b"__print_once __read_mostly bool true".split())
_RATE_INPUTS = frozenset(b"HZ __RAW_SPIN_LOCK_UNLOCKED _rs burst flags interval lock ratelimit_state".split())
_LOG_CALL = re.compile(rb"\b(?:(?:pr|dev)_(?:emerg|alert|crit|err|warn|notice|info)(?:_once|_ratelimited)?|printk)\s*\(")
_DEFINE = re.compile(rb"(?m)^[ \t\f\v]*(?:#|%:)[ \t\f\v]*(define|undef)[ \t\f\v]+([A-Za-z_]\w*)([^\n]*)")
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
    logger_offsets: frozenset[int] = frozenset()


@dataclass(frozen=True, slots=True)
class _DirectiveFacts:
    names: frozenset[bytes]
    possible_bindings: frozenset[bytes]
    blocked: frozenset[bytes]


def _logger_dependencies(name: bytes) -> frozenset[bytes]:
    """Macro forwarding and external C backends in the logging API contract.

    Checked prefix hooks are handled separately. Stop at the C backend: local
    functions do not rewrite a separately compiled backend's implementation.
    """
    if name == b"printk":
        return _PRINTK_DEPENDENCIES
    once, rate = name.endswith(b"_once"), name.endswith(b"_ratelimited")
    if name.startswith(b"pr_"):
        dependencies = _PRINTK_DEPENDENCIES | {name}
        if once:
            return dependencies | _ONCE_DEPENDENCIES
        if rate:
            return dependencies | _RATE_DEPENDENCIES | {b"printk_ratelimited", b"no_printk"}
        return dependencies
    base = name.removesuffix(b"_once").removesuffix(b"_ratelimited")
    dependencies = _DEV_DEPENDENCIES | {name, base, b"_" + base}
    if once:
        return dependencies | {b"dev_level_once"}
    return dependencies | _RATE_DEPENDENCIES | {b"dev_level_ratelimited"} if rate else dependencies


_LOG_DEPENDENCIES = {name: _logger_dependencies(name) for name in _LOG_ARGUMENTS}
_BINDING_NAMES = frozenset(name for dependencies in _LOG_DEPENDENCIES.values() for name in dependencies)
_DECLARATIONS = frozenset({"declaration", "parameter_declaration", "function_definition", "field_declaration", "type_definition"})


def _logger_macro_inputs(name: bytes) -> frozenset[bytes]:
    # A caller macro can replace keywords, fields and internal variable names
    # in a header macro body. Ordinary C declarations cannot do that.
    inputs = _LOG_DEPENDENCIES[name] | _MACRO_INPUTS
    if name != b"printk":
        inputs |= _KERN_PREFIXES
    if name.endswith(b"_once"):
        inputs |= _PR_ONCE_INPUTS if name.startswith(b"pr_") else _DEV_ONCE_INPUTS
    if name.endswith(b"_ratelimited"):
        inputs |= _RATE_INPUTS
    return inputs


_LOG_MACRO_INPUTS = {name: _logger_macro_inputs(name) for name in _LOG_ARGUMENTS}


def _possible_declaration(node: Node) -> bool:
    current = node
    for _ in range(64):
        parent = current.parent
        if parent is None:
            return False
        if parent.type in _DECLARATIONS:
            return current in parent.children_by_field_name("declarator")
        if parent.is_error:
            return True
        if parent.type != "parenthesized_declarator" and parent.child_by_field_name("declarator") != current:
            return False
        current = parent
    return True  # An over-deep possible binding cannot certify the API contract.


def _possible_macro_argument(node: Node) -> bool:
    current = node.parent
    for _ in range(64):
        if current is None or current.type in _DECLARATIONS | {"expression_statement", "compound_statement", "translation_unit"}:
            return False
        if current.type == "argument_list":
            return True
        current = current.parent
    return True


def _local_logger_bindings(tree: Tree) -> frozenset[bytes]:
    # Parenthesized function pointers and later comma declarators also shadow
    # the backend. Follow declarator edges, excluding initializer/bound uses.
    found = set(declaration_names(tree))
    found.update(node_text(node) for node in nodes(tree.root_node)
                 if node.type in {"identifier", "field_identifier", "type_identifier"} and node_text(node) in _BINDING_NAMES
                 and (node.type == "type_identifier" or _possible_declaration(node) or _possible_macro_argument(node)))
    return frozenset(found)


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


def _replacement_bindings(body: bytes) -> frozenset[bytes] | None:
    parameters: set[bytes] = set()
    if body.startswith(b"("):
        end = body.find(b")")
        if end < 0:
            return None
        names = macro_parameter_names(body[:end + 1])
        if names is None:
            return None
        parameters.update(name.encode() for name in names)
        body = body[end + 1:]
    tokens = tokenize_c_source(body.decode())
    if tokens is None or any(token.value in {"#", "##", "%:", "%:%:"} for token in tokens):
        return None
    watched = _BINDING_NAMES - parameters
    return frozenset(token.value.encode() for token in tokens
                     if token.kind is CTokenKind.IDENTIFIER and token.value.encode() in watched)


def _directive_blocks(text: bytes) -> _DirectiveFacts:
    blocked: set[bytes] = set()
    observed: set[bytes] = set()
    possible_bindings: set[bytes] = set()
    for directive in _DEFINE.finditer(text):
        operation, name, body = directive.groups()
        observed.add(name)
        if operation == b"define":
            bindings = _replacement_bindings(body)
            if bindings is None:
                # Pasting/stringification can construct a backend declaration
                # without spelling its name in the caller's raw syntax tree.
                blocked.update(_LOG_ARGUMENTS)
            else:
                possible_bindings.update(bindings)
        if name in {b"KBUILD_MODNAME", b"KBUILD_BASENAME"} or name in _KERN_PREFIXES:
            blocked.update(_LOG_ARGUMENTS)
        if name in _LOG_ARGUMENTS:
            blocked.add(name)
        if name in {b"pr_fmt", b"dev_fmt"} and (operation != b"define" or not _standard_prefix(body)):
            family = name.split(b"_", 1)[0] + b"_"
            blocked.update(name for name in _LOG_ARGUMENTS if name.startswith(family))
    return _DirectiveFacts(frozenset(observed), frozenset(possible_bindings), frozenset(blocked))


def _blocked_names(source: bytes, declarations: frozenset[bytes]) -> set[bytes]:
    text = preprocessor_directive_text(source.decode(), strict_multiline=True)
    if text is None:
        return set(_LOG_ARGUMENTS)
    # Keep the existing conservative prefix checks as well as normalized
    # negative observations. Comments, splices and digraphs cannot hide a
    # local override, and normalization does not waive an old prefix barrier.
    raw, normalized = (_directive_blocks(value) for value in (source.replace(b"\\\n", b""), text.encode()))
    observed = raw.names | normalized.names
    possible = declarations | raw.possible_bindings | normalized.possible_bindings
    blocked = set(raw.blocked | normalized.blocked)
    blocked.update(name for name, dependencies in _LOG_DEPENDENCIES.items()
                   if possible & dependencies or observed & _LOG_MACRO_INPUTS[name])
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
    blocked = _blocked_names(source, _local_logger_bindings(tree))
    replacements: list[tuple[Node, bytes]] = []
    logger_offsets: set[int] = set()
    for call in call_expressions(tree):
        argument = _format_argument(call, blocked)
        if argument is not None and (normalized := _normalized_format(argument)) is not None:
            replacements.append((argument, normalized))
            function = call.child_by_field_name("function")
            assert function is not None
            logger_offsets.add(function.start_byte)
    replacements.sort(key=lambda item: item[0].start_byte)
    contents: list[bytes] = []
    position = 0
    for argument, normalized in replacements:
        contents.extend((source[position:argument.start_byte], normalized))
        position = argument.end_byte
    contents.append(source[position:])
    return DiagnosticSource(b"".join(contents), tuple(node_text(argument) for argument, _ in replacements),
                            frozenset(logger_offsets))
