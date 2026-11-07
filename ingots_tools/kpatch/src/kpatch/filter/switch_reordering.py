"""Permutations of switch arms which each immediately return.

No fallthrough, declarations or directives may cross another arm. Complete
source tokens must otherwise match; the caller also checks macro bindings.
Function/callsite addresses can still change. Filtering requires the caller's
explicit audited assumption about those observations.
"""

from dataclasses import dataclass
import re

from tree_sitter import Node

from .reordering import ReorderProof
from .syntax import declarator_name, node_text, nodes, parse_source
from .whitespace.c_lexer import CToken, CTokenKind, tokenize_c_source


@dataclass(frozen=True, slots=True)
class _Arm:
    key: str
    source: bytes
    tokens: tuple[CToken, ...]
    identifiers: frozenset[str]
    numeric_names: frozenset[str]


@dataclass(frozen=True, slots=True)
class _CaseRun:
    start: int
    end: int
    function: str
    arms: tuple[_Arm, ...]


def _arm(node: Node) -> _Arm | None:
    children = [child for child in node.named_children if child.type != 'comment']
    label = node.child_by_field_name('value')
    statements = children[1:] if label is not None else children
    if (node.type != 'case_statement' or len(statements) != 1 or statements[0].type != 'return_statement'
            or label is not None and label.type not in {'identifier', 'number_literal', 'char_literal'}):
        return None
    descendants = tuple(nodes(node))
    if any(child.type.startswith('preproc_') or child.type == 'compound_statement' for child in descendants):
        return None
    # Even inside sizeof/casts, a tag or enumerator definition can bind names
    # in the enclosing block and change what a later case expression means.
    if any(child.type in {'struct_specifier', 'union_specifier', 'enum_specifier'}
           and child.child_by_field_name('body') is not None for child in descendants):
        return None
    tokens = tokenize_c_source(node_text(node).decode())
    if tokens is None:
        return None
    identifiers = frozenset(token.value for token in tokens if token.kind is CTokenKind.IDENTIFIER)
    if any(re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', name) is None for name in identifiers):
        return None
    if identifiers & {'asm', '__asm', '__asm__', '_Pragma', '__pragma', '__func__', '__FUNCTION__', '__PRETTY_FUNCTION__'}:
        return None
    names = frozenset(node_text(child).decode() for child in descendants
                      if child.type in {'identifier', 'type_identifier', 'field_identifier'})
    return _Arm(node_text(label).decode() if label is not None else 'default', node_text(node), tokens, identifiers, names)


def _switches(source: bytes) -> tuple[_CaseRun, ...]:
    found: list[_CaseRun] = []
    tree = parse_source(source)
    for node in nodes(tree.root_node):
        if node.type != 'switch_statement' or node.has_error:
            continue
        body = node.child_by_field_name('body')
        if body is None or body.type != 'compound_statement':
            continue
        parent = node.parent
        while parent is not None and parent.type != 'function_definition':
            parent = parent.parent
        declarator = parent.child_by_field_name('declarator') if parent is not None else None
        name = declarator_name(declarator) if declarator is not None else None
        if name is None:
            continue
        run: list[_Arm] = []
        start = end = 0
        for child in body.named_children:
            if child.type == 'comment':
                continue
            arm = _arm(child)
            if arm is None:
                # A preceding complex arm may fall through into this run's
                # first return. Only the initial run has no such predecessor.
                break
            start = child.start_byte if not run else start
            end = child.end_byte
            run.append(arm)
        if 2 <= len(run) <= 128 and len({item.key for item in run}) == len(run):
            found.append(_CaseRun(start, end, node_text(name).decode(), tuple(run)))
    ordered = tuple(sorted(found, key=lambda switch: switch.start))
    if any(first.end > second.start for first, second in zip(ordered, ordered[1:])):
        return ()
    return ordered


def _canonical(source: bytes, switches: tuple[_CaseRun, ...]) -> bytes:
    parts: list[bytes] = []
    position = 0
    for switch in switches:
        parts.append(source[position:switch.start])
        parts.append(b'\n'.join(arm.source for arm in sorted(switch.arms, key=lambda arm: arm.key)))
        position = switch.end
    parts.append(source[position:])
    return b''.join(parts)


def independent_switch_reorder(old: bytes, new: bytes) -> ReorderProof | None:
    if max(len(old), len(new)) > 512 * 1024 or re.search(rb'\b(?:__LINE__|__COUNTER__|_Pragma|__pragma)\b', old + new):
        return None
    first, second = _switches(old), _switches(new)
    if not first or len(first) != len(second):
        return None
    moved: list[_Arm] = []
    functions: set[str] = set()
    for before, after in zip(first, second, strict=True):
        a, b = {arm.key: arm for arm in before.arms}, {arm.key: arm for arm in after.arms}
        if before.function != after.function or a.keys() != b.keys() or any(a[key].tokens != b[key].tokens for key in a):
            return None
        if tuple(arm.key for arm in before.arms) != tuple(arm.key for arm in after.arms):
            moved.extend(before.arms)
            functions.add(before.function)
    if not moved or tokenize_c_source(_canonical(old, first).decode()) != tokenize_c_source(_canonical(new, second).decode()):
        return None
    identifiers = frozenset(name for arm in moved for name in arm.identifiers)
    protected = frozenset(name for arm in moved for name in arm.identifiers - arm.numeric_names)
    return ReorderProof(tuple(sorted(functions)), identifiers, identifiers - protected)
