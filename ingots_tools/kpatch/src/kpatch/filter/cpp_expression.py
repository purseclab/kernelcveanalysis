"""Bounded integer-only C preprocessing expressions, parsed by Tree-sitter.

The Linux GCC/Clang model uses 64-bit intmax_t/uintmax_t and two's complement.
Unknown macro names are rejected before evaluation: expansion can change the
expression's structure even inside an apparently short-circuited operand.
Signed overflow, invalid shifts/division and unsupported constructs stay unknown.
"""

from dataclasses import dataclass
from functools import lru_cache
import re

from tree_sitter import Node

from .syntax import node_text, nodes, parse_source


_BITS = 64
_UNSIGNED_MAX = (1 << _BITS) - 1
_SIGNED_MAX = (1 << (_BITS - 1)) - 1
_SIGNED_MIN = -(1 << (_BITS - 1))
_MAX_BYTES = 4096
_MAX_NODES = 512
_MAX_DEPTH = 64
_PREFIX = b"long __kpatch_cpp(void) { return ("
_SUFFIX = b"); }\n"
_LITERAL = re.compile(
    rb"(?P<sign>[+-]?)(?P<number>0[xX][0-9a-fA-F]+|0[bB][01]+|0[0-7]*|[1-9][0-9]*)"
    rb"(?P<suffix>[uU](?:[lL]|ll|LL)?|(?:[lL]|ll|LL)[uU]?)?"
)
_BINARY = frozenset({"+", "-", "*", "/", "%", "<<", ">>", "&", "|", "^", "==", "!=", "<", "<=", ">", ">=", "&&", "||"})


@dataclass(frozen=True, slots=True)
class CInteger:
    value: int
    unsigned: bool = False


def _integer(value: int, unsigned: bool = False) -> CInteger | None:
    if unsigned:
        return CInteger(value & _UNSIGNED_MAX, True)
    return CInteger(value) if _SIGNED_MIN <= value <= _SIGNED_MAX else None


def _unary(operation: str, argument: CInteger) -> CInteger | None:
    if operation == "+":
        return argument
    if operation == "-":
        return _integer(-argument.value, argument.unsigned)
    if operation == "~":
        return _integer(~argument.value, argument.unsigned)
    return CInteger(int(argument.value == 0)) if operation == "!" else None


def parse_cpp_integer(text: str) -> CInteger | None:
    """Parse one C integer literal; diagnostic/extended literal types retain."""
    if not text or len(text) > _MAX_BYTES:
        return None
    try:
        return _literal(text.encode("ascii"))
    except UnicodeEncodeError:
        return None


def _literal(text: bytes) -> CInteger | None:
    match = _LITERAL.fullmatch(text)
    if match is None:
        return None
    number, suffix = match["number"], match["suffix"] or b""
    base = 16 if number.lower().startswith(b"0x") else 2 if number.lower().startswith(b"0b") else 8 if number.startswith(b"0") else 10
    try:
        value = int(number, base)
    except ValueError:
        return None
    unsigned = b"u" in suffix.lower() or base != 10 and value > _SIGNED_MAX
    if value > _UNSIGNED_MAX or not unsigned and value > _SIGNED_MAX:
        return None
    result = CInteger(value, unsigned)
    return _unary("-", result) if match["sign"] == b"-" else result


def _children(node: Node) -> list[Node]:
    return [child for child in node.named_children if child.type != "comment"]


def _expression(source: bytes) -> Node | None:
    tree = parse_source(_PREFIX + source + _SUFFIX)
    if tree.root_node.has_error or len(tree.root_node.named_children) != 1:
        return None
    body = tree.root_node.named_children[0].child_by_field_name("body")
    if body is None or len(_children(body)) != 1:
        return None
    statement = _children(body)[0]
    values = _children(statement)
    if statement.type != "return_statement" or len(values) != 1:
        return None
    expression = values[0]
    if (expression.type != "parenthesized_expression" or expression.start_byte != len(_PREFIX) - 1
            or expression.end_byte != len(_PREFIX) + len(source) + 1):
        return None
    return expression


def _supported(expression: Node) -> bool:
    for count, node in enumerate(nodes(expression), 1):
        if count > _MAX_NODES:
            return False
        if not node.is_named or node.type == "comment":
            continue
        if node.type == "number_literal":
            if _literal(node_text(node)) is None:
                return False
        elif node.type in {"binary_expression", "unary_expression"}:
            operator = node.child_by_field_name("operator")
            valid = _BINARY if node.type == "binary_expression" else {"+", "-", "!", "~"}
            if operator is None or operator.type not in valid:
                return False
        elif node.type != "parenthesized_expression":
            return False
    return True


def _shift(operation: str, left: CInteger, right: CInteger) -> CInteger | None:
    if not 0 <= right.value < _BITS:
        return None
    if operation == ">>":
        # Negative signed right shifts are implementation-defined in C.
        return None if left.value < 0 else _integer(left.value >> right.value, left.unsigned)
    if left.value < 0:
        return None
    return _integer(left.value << right.value, left.unsigned)


def _arithmetic(operation: str, left: CInteger, right: CInteger) -> CInteger | None:
    unsigned = left.unsigned or right.unsigned
    a, b = (left.value & _UNSIGNED_MAX, right.value & _UNSIGNED_MAX) if unsigned else (left.value, right.value)
    if operation in {"/", "%"}:
        if b == 0 or not unsigned and a == _SIGNED_MIN and b == -1:
            return None
        quotient = abs(a) // abs(b)
        quotient = -quotient if (a < 0) != (b < 0) else quotient
        return _integer(quotient if operation == "/" else a - quotient * b, unsigned)
    match operation:
        case "+": value = a + b
        case "-": value = a - b
        case "*": value = a * b
        case "&": value = a & b
        case "|": value = a | b
        case "^": value = a ^ b
        case "==": return CInteger(int(a == b))
        case "!=": return CInteger(int(a != b))
        case "<": return CInteger(int(a < b))
        case "<=": return CInteger(int(a <= b))
        case ">": return CInteger(int(a > b))
        case ">=": return CInteger(int(a >= b))
        case _: return None
    return _integer(value, unsigned)


def _evaluate(node: Node, depth: int = 0) -> CInteger | None:
    if depth > _MAX_DEPTH:
        return None
    if node.type == "number_literal":
        return _literal(node_text(node))
    if node.type == "parenthesized_expression":
        children = _children(node)
        return _evaluate(children[0], depth + 1) if len(children) == 1 else None
    operator = node.child_by_field_name("operator")
    if operator is None:
        return None
    if node.type == "unary_expression":
        argument = node.child_by_field_name("argument")
        value = _evaluate(argument, depth + 1) if argument is not None else None
        return _unary(operator.type, value) if value is not None else None
    left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
    a = _evaluate(left, depth + 1) if left is not None else None
    if a is None:
        return None
    if operator.type == "&&" and a.value == 0:
        return CInteger(0)
    if operator.type == "||" and a.value != 0:
        return CInteger(1)
    b = _evaluate(right, depth + 1) if right is not None else None
    if b is None:
        return None
    if operator.type in {"&&", "||"}:
        return CInteger(int(b.value != 0))
    return _shift(operator.type, a, b) if operator.type in {"<<", ">>"} else _arithmetic(operator.type, a, b)


@lru_cache(maxsize=4096)
def evaluate_cpp_expression(expression: str) -> CInteger | None:
    """Evaluate a bounded, already substituted integer preprocessing expression."""
    if not expression or len(expression) > _MAX_BYTES or "\0" in expression:
        return None
    try:
        source = expression.encode("ascii")
    except UnicodeEncodeError:
        return None
    node = _expression(source)
    return _evaluate(node) if node is not None and _supported(node) else None
