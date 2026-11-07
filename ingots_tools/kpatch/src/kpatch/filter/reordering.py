"""Bounded, same-file permutations of adjacent independent static helpers.

Declarations and preprocessing directives are barriers. Function bodies and
signatures must match exactly, and references between crossed functions are
rejected. A separate repository macro check covers ordinary identifier macros.
These source facts do not establish code-address or emitted-layout equivalence;
the filtering caller must require an explicit audited assumption.
As with the other raw-source analyses, compiler keyword macros, generated and
forced includes/flags require the standard kernel compilation model.
"""

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
import re

from tree_sitter import Node

from .macro_lookup import MacroLookup, MacroObservation, MacroOrigin
from .reference_index import ReferenceSite
from .syntax import (
    call_expressions, declaration_names, definitions, has_opaque_tokens,
    macro_definitions, node_text, nodes, parse_source,
)
from .whitespace.c_lexer import CToken, CTokenKind, tokenize_c_source
from ..diff import DiffFile
from ..git import GitRepo


_KEYWORDS = frozenset("auto break case char const continue default do double else enum extern float for goto if inline int long register restrict return short signed sizeof static struct switch typedef union unsigned void volatile while _Alignas _Alignof _Atomic _Bool _Complex _Generic _Imaginary _Noreturn _Static_assert _Thread_local".split())
_TOP_LEVEL = frozenset({"preproc_if", "preproc_ifdef", "preproc_else", "preproc_elif"})
_NUMERIC_OPERATORS = frozenset("( ) + - * / % << >> & | ^ ~ ! && || == != < > <= >= ? :".split())
LINE_BUILTINS = frozenset({"__LINE__", "__builtin_LINE", "__builtin_source_location"})
COLUMN_BUILTINS = frozenset({"__builtin_COLUMN", "__builtin_source_location"})


@dataclass(frozen=True, slots=True)
class ReorderProof:
    """Source-permutation facts, not an emitted-code equivalence certificate."""

    symbols: tuple[str, ...]
    identifiers: frozenset[str]
    numeric_names: frozenset[str]


@dataclass(frozen=True, slots=True)
class _Function:
    name: str
    start: int
    end: int
    tokens: tuple[CToken, ...]
    identifiers: frozenset[str]
    protected_names: frozenset[str]


def hunk_reorder_candidate(file: DiffFile) -> bool:
    versions = ["\n".join(line[1:] for chunk in file.chunks for line in chunk.lines if line.startswith(prefix))
                for prefix in ("-", "+")]
    if max(map(len, versions)) > 256 * 1024:
        return False
    a, b = (tokenize_c_source(text) for text in versions)
    return a is not None and b is not None and bool(a) and Counter(a) == Counter(b)


def _top_level(node: Node) -> bool:
    parent = node.parent
    while parent is not None and parent.type in _TOP_LEVEL:
        parent = parent.parent
    return parent is not None and parent.type == "translation_unit"


def _functions(source: bytes) -> list[_Function]:
    tree = parse_source(source)
    eligible = {item.start: item for item in definitions(source, tree) if item.kind == "function_definition"}
    found: list[_Function] = []
    for node in nodes(tree.root_node):
        item = eligible.get(node.start_byte) if node.type == "function_definition" else None
        if item is None or not _top_level(node) or node.end_byte - node.start_byte > 16 * 1024:
            continue
        text = node_text(node)
        parsed = parse_source(text)
        if parsed.root_node.has_error or call_expressions(parsed) or any(
            child.type == "function_definition" and child != parsed.root_node.named_children[0]
            for child in nodes(parsed.root_node)
        ):
            continue
        # A tag/enumerator introduced by a return type can escape the helper
        # and make its position a declaration-order dependency.
        if any(child.type in {"struct_specifier", "union_specifier", "enum_specifier"}
               and child.child_by_field_name("body") is not None for child in nodes(parsed.root_node)):
            continue
        tokens = tokenize_c_source(text.decode())
        if tokens is None:
            continue
        identifiers = frozenset(t.value for t in tokens if t.kind is CTokenKind.IDENTIFIER and t.value not in _KEYWORDS)
        protected = set(name.decode() for name in declaration_names(parsed))
        protected.update(node_text(n).decode() for n in nodes(parsed.root_node)
                         if n.type in {"type_identifier", "field_identifier"})
        found.append(_Function(item.name, item.start, item.end, tokens, identifiers, frozenset(protected)))
    return sorted(found, key=lambda item: item.start)


def _runs(source: bytes) -> list[list[_Function]]:
    groups: list[list[_Function]] = []
    for function in _functions(source):
        if groups and tokenize_c_source(source[groups[-1][-1].end:function.start].decode()) == ():
            groups[-1].append(function)
        else:
            groups.append([function])
    return [group for group in groups if len(group) > 1]


def _canonical(source: bytes, runs: list[list[_Function]]) -> bytes:
    result: list[bytes] = []
    position = 0
    for run in runs:
        result.append(source[position:run[0].start])
        result.extend(source[function.start:function.end] + b"\n" for function in sorted(run, key=lambda item: item.name))
        position = run[-1].end
    result.append(source[position:])
    return b"".join(result)


def independent_reorder(old: bytes, new: bytes) -> ReorderProof | None:
    if max(len(old), len(new)) > 512 * 1024:
        return None
    old_tokens, new_tokens = tokenize_c_source(old.decode()), tokenize_c_source(new.decode())
    if old_tokens is None or new_tokens is None or Counter(old_tokens) != Counter(new_tokens):
        return None
    if re.search(rb"\b(?:__LINE__|__COUNTER__|_Pragma|__pragma)\b", old + new):
        return None
    if has_opaque_tokens(parse_source(old)) or has_opaque_tokens(parse_source(new)):
        return None
    for source in (old, new):
        if any((name := macro.child_by_field_name("name")) is not None and node_text(name).decode() in _KEYWORDS
               for macro in macro_definitions(parse_source(source))):
            return None
    a, b = _runs(old), _runs(new)
    if not a or len(a) != len(b) or sum(map(len, a)) > 128:
        return None
    changed: dict[str, _Function] = {}
    for first, second in zip(a, b, strict=True):
        left = {item.name: item for item in first}
        right = {item.name: item for item in second}
        if len(left) != len(first) or left.keys() != right.keys():
            return None
        if any(item.tokens != right[name].tokens for name, item in left.items()):
            return None
        order = {item.name: position for position, item in enumerate(second)}
        for i, earlier in enumerate(first):
            for later in first[i + 1:]:
                if order[earlier.name] <= order[later.name]:
                    continue
                if earlier.name in later.identifiers or later.name in earlier.identifiers:
                    return None
                changed.update({earlier.name: earlier, later.name: later})
    if not changed:
        return None
    if tokenize_c_source(_canonical(old, a).decode()) != tokenize_c_source(_canonical(new, b).decode()):
        return None
    identifiers = frozenset(name for item in changed.values() for name in item.identifiers)
    protected = frozenset(name for item in changed.values() for name in item.protected_names)
    return ReorderProof(tuple(sorted(changed)), identifiers, identifiers - protected)


class ReorderMacroGuard:
    """Keep observed bindings separate from incomplete discovery.

    Normal mode retains unknown observations. Explicit lossy source analysis
    can assume the missing context while still checking every observed binding.
    Discovery itself never turns an incomplete result into an absence proof.
    """

    def __init__(self, repo: GitRepo, read_file: Callable[[str, str], bytes],
                 active_site: Callable[[str, ReferenceSite], bool], *, allow_unknown: bool = False) -> None:
        self.allow_unknown = allow_unknown
        self._discovery = MacroLookup(repo, read_file, active_site, allow_unknown=allow_unknown)
        self._assumptions: set[str] = set()

    @property
    def repository_scans(self) -> int:
        return self._discovery.repository_scans

    @property
    def assumed_uncertainties(self) -> frozenset[str]:
        return frozenset(self._assumptions)

    def reset_assumptions(self) -> None:
        self._assumptions.clear()

    def _lookup(self, revision: str, names: frozenset[str]) -> dict[str, MacroObservation]:
        return self._discovery.lookup(revision, names)

    def _usable(self, observation: MacroObservation) -> bool:
        if not observation.uncertainties:
            return True
        if not self.allow_unknown or not observation.assumable:
            return False
        self._assumptions.update(observation.uncertainties)
        return True

    def allows(self, revision: str, proof: ReorderProof) -> bool:
        if len(proof.identifiers) > 64:
            return False
        for name, observation in self._lookup(revision, proof.identifiers).items():
            if not self._usable(observation):
                return False
            if observation.definitions and name not in proof.numeric_names:
                return False
            for macro in observation.definitions:
                if macro.function_like or macro.replacement is None:
                    return False
                tokens = tokenize_c_source(macro.replacement.decode())
                if not tokens or not all(
                    token.kind is CTokenKind.PP_NUMBER
                    or token.kind is CTokenKind.PUNCTUATOR and token.value in _NUMERIC_OPERATORS
                    for token in tokens
                ):
                    return False
        return True

    def binding_names_safe(self, revision: str, names: frozenset[str]) -> bool:
        # CALL(parameter) can invoke a raw function-like macro binding even
        # without a literal parameter(...) occurrence in the original source.
        if len(names) > 64:
            return False
        for observation in self._lookup(revision, names).values():
            if (not self._usable(observation)
                    or any(macro.origin is not MacroOrigin.UNCLASSIFIED for macro in observation.definitions)):
                return False
        return True

    def compiler_names_safe(self, revision: str, names: frozenset[str]) -> bool:
        return all(self._usable(observation)
                   and all(macro.origin is MacroOrigin.SOURCE for macro in observation.definitions)
                   for observation in self._lookup(revision, names).values())

    def source_names_unbound(self, revision: str, names: frozenset[str]) -> bool:
        """An unclosed include walk cannot discard already observed macros."""
        return all(self._usable(observation)
                   and not any(macro.origin is MacroOrigin.SOURCE for macro in observation.definitions)
                   for observation in self._lookup(revision, names).values())

    def location_independent(self, revision: str, names: frozenset[str], builtins: frozenset[str]) -> bool:
        """Follow observed replacements, preserving known physical locations."""
        pending = set(names)
        visited: set[str] = set()
        for _ in range(8):
            pending.difference_update(visited)
            if not pending:
                return True
            if pending & builtins or len(visited | pending) > 256:
                return False
            batch = frozenset(pending)
            pending.clear()
            for observation in self._lookup(revision, batch).values():
                if not self._usable(observation):
                    return False
                for macro in observation.definitions:
                    if macro.origin is MacroOrigin.UNCLASSIFIED:
                        continue
                    if macro.replacement is None:
                        return False
                    tokens = tokenize_c_source(macro.replacement.decode())
                    if tokens is None or any(token.value in {"#", "##", "%:", "%:%:", "_Pragma", "__pragma"}
                                             for token in tokens):
                        return False
                    pending.update({token.value for token in tokens if token.kind is CTokenKind.IDENTIFIER}
                                   - macro.parameters)
            visited.update(batch)
        return False

    def preserves_bindings(self, revision: str, identifiers: frozenset[str], renamed: frozenset[str]) -> bool:
        pending = set(identifiers)
        visited: set[str] = set()
        for _ in range(8):
            pending.difference_update(visited)
            if not pending:
                return True
            if len(visited | pending) > 128:
                return False
            batch = frozenset(pending)
            pending.clear()
            for observation in self._lookup(revision, batch).values():
                if not self._usable(observation):
                    return False
                for macro in observation.definitions:
                    if macro.origin is MacroOrigin.UNCLASSIFIED:
                        continue
                    if macro.origin is MacroOrigin.COMPILER or macro.replacement is None:
                        return False
                    tokens = tokenize_c_source(macro.replacement.decode())
                    if tokens is None or any(token.value in {"#", "##", "%:", "%:%:"} for token in tokens):
                        return False
                    names = {token.value for token in tokens if token.kind is CTokenKind.IDENTIFIER} - macro.parameters
                    if names & renamed:
                        return False
                    pending.update(names)
            visited.update(batch)
        return False
