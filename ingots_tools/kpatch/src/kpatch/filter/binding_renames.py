"""C parameter erasure and lexical alpha-equivalence, with explicit risk scope.

Prototype parameter names do not affect the runtime C type. Function bodies
need preprocessing bindings as well as lexical bindings; their normalization is
therefore available only to the separately labeled lossy source mode.
"""

from dataclasses import dataclass
from bisect import bisect_right
from enum import StrEnum
import re

from tree_sitter import Node

from .syntax import declarator_name, node_text, nodes, parse_source
from .whitespace.c_lexer import tokenize_c_source


class BindingKind(StrEnum):
    PROTOTYPE_PARAMETER = "prototype_parameter"
    PARAMETER = "function_parameter"
    LOCAL = "local_variable"


@dataclass(frozen=True, slots=True)
class BindingRename:
    kind: BindingKind
    old: str
    new: str


@dataclass(frozen=True, slots=True)
class BindingComparison:
    renames: tuple[BindingRename, ...]
    macro_identifiers: frozenset[str] = frozenset()
    invoked_names: frozenset[str] = frozenset()

    @property
    def names(self) -> frozenset[str]:
        return frozenset(name for item in self.renames for name in (item.old, item.new))

    @property
    def lossy(self) -> bool:
        return any(item.kind is not BindingKind.PROTOTYPE_PARAMETER for item in self.renames)


@dataclass(frozen=True, slots=True)
class _Binding:
    kind: BindingKind
    name: bytes
    environment: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class _View:
    source: bytes
    bindings: tuple[_Binding, ...]
    invoked: frozenset[int]


class _Normalizer:
    def __init__(self, source: bytes, bodies: bool) -> None:
        self.source = source
        self.bodies = bodies
        self.bindings: list[_Binding] = []
        self.replacements: dict[int, tuple[int, int]] = {}
        self.scopes: list[dict[bytes, int | None]] = []
        self.type_names: set[bytes] = set()
        self.environment: frozenset[str] = frozenset()
        self.invoked: set[int] = set()
        self.invalid = False
        splices = tuple(re.finditer(rb"\\(?:\r\n|\n)", source))
        self.splice_ends = tuple(match.end() for match in splices)
        removed = [0]
        for match in splices:
            removed.append(removed[-1] + match.end() - match.start())
        self.splice_removed = tuple(removed)
        self.spliced = re.sub(rb"\\(?:\r\n|\n)", b"", source)

    def _occurrence(self, leaf: Node, identity: int) -> None:
        self.replacements[leaf.start_byte] = (leaf.end_byte, identity)
        position = leaf.end_byte - self.splice_removed[bisect_right(self.splice_ends, leaf.end_byte)]
        while position < len(self.spliced):
            if self.spliced[position:position + 1].isspace():
                position += 1
            elif self.spliced[position:position + 2] == b'/*':
                end = self.spliced.find(b'*/', position + 2)
                if end < 0:
                    return
                position = end + 2
            elif self.spliced[position:position + 2] == b'//':
                end = self.spliced.find(b'\n', position + 2)
                if end < 0:
                    return
                position = end + 1
            else:
                if self.spliced[position:position + 1] == b'(':
                    self.invoked.add(identity)
                return

    def _declare(self, leaf: Node, kind: BindingKind) -> int:
        identity = len(self.bindings)
        self.bindings.append(_Binding(kind, node_text(leaf), self.environment))
        self._occurrence(leaf, identity)
        return identity

    def _prototype(self, declaration: Node) -> None:
        # Reparse a complete declaration, not an error-recovered parameter leaf.
        if declaration.has_error or parse_source(node_text(declaration)).root_node.has_error:
            return
        if re.search(rb"\b(?:__attribute__|__attribute|_Pragma|__pragma|asm|__asm__)\b", node_text(declaration)):
            return
        leaves: list[Node] = []
        parameters: list[Node] = []
        for node in nodes(declaration):
            if node.type != "parameter_declaration":
                continue
            declarator = node.child_by_field_name("declarator")
            leaf = declarator_name(declarator) if declarator is not None else None
            if leaf is not None and leaf.type == "identifier":
                leaves.append(leaf)
                parameters.append(node)
        declared = {leaf.start_byte for leaf in leaves}
        scopes: dict[int, set[bytes]] = {}
        for leaf, parameter in zip(leaves, parameters, strict=True):
            assert parameter.parent is not None
            names = scopes.setdefault(parameter.parent.start_byte, set())
            if node_text(leaf) in names:
                return
            names.add(node_text(leaf))
        # Dependent bounds, typeof and attribute operands are kept verbatim.
        referenced = {node_text(node) for node in nodes(declaration)
                      if node.type in {"identifier", "type_identifier"} and node.start_byte not in declared}
        for leaf, parameter in zip(leaves, parameters, strict=True):
            # The implementation-reserved namespace includes Linux's BTF
            # kfunc argument annotations (for example buffer__sz). Preserve
            # these names instead of treating them as cosmetic C declarations.
            if (node_text(leaf) in referenced or parameter.has_error or b"__" in node_text(leaf)
                    or re.fullmatch(rb"[A-Za-z_][A-Za-z_0-9]*", node_text(leaf)) is None):
                continue
            self._declare(leaf, BindingKind.PROTOTYPE_PARAMETER)

    def _lookup(self, name: bytes) -> int | None:
        for scope in reversed(self.scopes):
            if name in scope:
                return scope[name]
        return None

    def _local_declaration(self, node: Node) -> None:
        # C puts a variable into scope immediately after its declarator, before
        # its initializer. Sibling declarators are visited in source order.
        for child in node.named_children:
            if child.type == "init_declarator":
                declarator = child.child_by_field_name("declarator")
                value = child.child_by_field_name("value")
            elif child in node.children_by_field_name("declarator"):
                declarator, value = child, None
            else:
                self._walk(child)
                continue
            leaf = declarator_name(declarator) if declarator is not None else None
            if leaf is not None and leaf.type == "identifier":
                assert declarator is not None
                if node_text(leaf) in self.scopes[-1]:
                    self.invalid = True
                # Function declarations have prototype scope, not a local
                # variable binding. Function-pointer declarators stay opaque.
                complex_type = any(item.type == "function_declarator" for item in nodes(declarator))
                external = any(child.type == "storage_class_specifier" and node_text(child) == b"extern"
                               for child in node.named_children)
                if (not complex_type and node.type != "type_definition" and not external
                        and node_text(leaf) not in self.type_names
                        and re.fullmatch(rb"[A-Za-z_][A-Za-z_0-9]*", node_text(leaf)) is not None):
                    self._walk_declarator(declarator, leaf)
                    identity = self._declare(leaf, BindingKind.LOCAL)
                    self.scopes[-1][node_text(leaf)] = identity
                else:
                    self.scopes[-1][node_text(leaf)] = None
            if value is not None:
                self._walk(value)

    def _walk_declarator(self, node: Node, leaf: Node) -> None:
        # Array bounds may use a preceding local; the declared name itself is
        # processed separately so an outer variable cannot capture it.
        if node == leaf:
            return
        for child in node.named_children:
            self._walk_declarator(child, leaf) if child.start_byte <= leaf.start_byte < child.end_byte else self._walk(child)

    def _walk(self, node: Node) -> None:
        if node.type in {"compound_statement", "for_statement"}:
            self.scopes.append({})
            for child in node.named_children:
                self._walk(child)
            self.scopes.pop()
            return
        if node.type in {"declaration", "type_definition"}:
            self._local_declaration(node)
            return
        if node.type == "enumerator":
            name = node.child_by_field_name("name")
            if name is not None:
                if node_text(name) in self.scopes[-1]:
                    self.invalid = True
                self.scopes[-1][node_text(name)] = None
            value = node.child_by_field_name("value")
            if value is not None:
                self._walk(value)
            return
        if node.type == "identifier":
            identity = self._lookup(node_text(node))
            if identity is not None:
                self._occurrence(node, identity)
            return
        for child in node.named_children:
            self._walk(child)

    def _function(self, function: Node) -> None:
        if not self.bodies or function.has_error:
            return
        text = node_text(function)
        if re.search(rb"(?m)^\s*#|\b(?:asm|__asm__|__attribute__|__attribute|_Pragma|__pragma)\b", text):
            return
        if parse_source(text).root_node.has_error:
            return
        if sum(node.type == "function_definition" for node in nodes(function)) != 1:
            return
        declarator = function.child_by_field_name("declarator")
        body = function.child_by_field_name("body")
        if declarator is None or body is None:
            return
        parameters = declarator.child_by_field_name("parameters")
        # Pointer-return declarators wrap the function declarator.
        while parameters is None and (nested := declarator.child_by_field_name("declarator")) is not None:
            declarator = nested
            parameters = declarator.child_by_field_name("parameters")
        if parameters is None:
            return
        if any(node.type == "function_declarator" for parameter in parameters.named_children for node in nodes(parameter)):
            return
        self.type_names = {node_text(node) for node in nodes(function) if node.type == "type_identifier"}
        self.environment = frozenset(node_text(node).decode() for node in nodes(function) if node.type == "identifier")
        before = len(self.bindings)
        self.invalid = False
        self.scopes.append({})
        for parameter in parameters.named_children:
            if parameter.type != "parameter_declaration":
                continue
            item = parameter.child_by_field_name("declarator")
            leaf = declarator_name(item) if item is not None else None
            if (leaf is not None and leaf.type == "identifier" and node_text(leaf) not in self.type_names
                    and b"__" not in node_text(leaf)
                    and re.fullmatch(rb"[A-Za-z_][A-Za-z_0-9]*", node_text(leaf)) is not None):
                assert item is not None
                if node_text(leaf) in self.scopes[-1]:
                    self.invalid = True
                self._walk_declarator(item, leaf)
                identity = self._declare(leaf, BindingKind.PARAMETER)
                self.scopes[-1][node_text(leaf)] = identity
        # Function parameters and the outermost body share one C scope.
        for child in body.named_children:
            self._walk(child)
        self.scopes.pop()
        if self.invalid:
            self.bindings[before:] = []
            self.replacements = {start: value for start, value in self.replacements.items()
                                 if not function.start_byte <= start < function.end_byte}
            self.invoked = {identity for identity in self.invoked if identity < before}
        self.invalid = False
        self.type_names.clear()
        self.environment = frozenset()

    def normalize(self) -> _View:
        tree = parse_source(self.source)
        pending = [tree.root_node]
        while pending:
            node = pending.pop()
            if node.type == "function_definition":
                self._function(node)
            elif node.type in {"declaration", "type_definition"}:
                self._prototype(node)
            else:
                pending.extend(reversed(node.named_children))
        pieces: list[bytes] = []
        start = 0
        for offset, (end, identity) in sorted(self.replacements.items()):
            pieces.extend((self.source[start:offset], b"\0" + str(identity).encode() + b"\0"))
            start = end
        pieces.append(self.source[start:])
        return _View(b"".join(pieces), tuple(self.bindings), frozenset(self.invoked))


def compare_bindings(old: bytes, new: bytes, *, bodies: bool = False) -> BindingComparison | None:
    """Compare complete sources after resolving supported lexical bindings.

    NUL-delimited binding identities cannot collide with a C source identifier.
    Unknown constructs remain unnormalized and therefore retain changed text.
    """
    if b"\0" in old + new:
        return None
    first, second = _Normalizer(old, bodies).normalize(), _Normalizer(new, bodies).normalize()
    if len(first.bindings) != len(second.bindings):
        return None
    tokens = tokenize_c_source(first.source.decode())
    if tokens is None or tokens != tokenize_c_source(second.source.decode()):
        return None
    changed: list[BindingRename] = []
    macro_identifiers: set[str] = set()
    invoked_names: set[str] = set()
    for identity, (a, b) in enumerate(zip(first.bindings, second.bindings, strict=True)):
        if a.kind is not b.kind:
            return None
        if a.name != b.name:
            changed.append(BindingRename(a.kind, a.name.decode(), b.name.decode()))
            macro_identifiers.update(a.environment | b.environment)
            if identity in first.invoked or identity in second.invoked:
                invoked_names.update((a.name.decode(), b.name.decode()))
    return BindingComparison(tuple(changed), frozenset(macro_identifiers), frozenset(invoked_names)) if changed else None
