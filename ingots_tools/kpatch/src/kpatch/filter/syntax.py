"""Small Tree-sitter analyses shared by source equivalence and use filtering."""

from collections.abc import Iterator
from dataclasses import dataclass, replace
import re

from tree_sitter import Language, Node, Parser, Query, QueryCursor, Tree
import tree_sitter_c

from .whitespace.c_lexer import CTokenKind, tokenize_c_source


_C_LANGUAGE = Language(tree_sitter_c.language())
IDENTIFIER = re.compile(rb"[A-Za-z_$][A-Za-z_0-9$]*")
MAX_SOURCE_BYTES = 2 * 1024 * 1024
_DEFINITIONS_QUERY = Query(_C_LANGUAGE, "\n".join(
    f"({kind}) @item" for kind in ("function_definition", "preproc_def", "preproc_function_def", "struct_specifier")
))
_DECLARATIONS_QUERY = Query(_C_LANGUAGE, "\n".join(
    f"({kind}) @item" for kind in ("function_definition", "declaration", "parameter_declaration", "field_declaration", "type_definition", "struct_specifier", "union_specifier", "enum_specifier", "enumerator", "preproc_def", "preproc_function_def")
))
_COMMENTS_QUERY = Query(_C_LANGUAGE, "(comment) @item")
_SENSITIVE_QUERY = Query(_C_LANGUAGE, "(function_definition) @item (string_literal) @item (preproc_arg) @item")
_ARGUMENTS_QUERY = Query(_C_LANGUAGE, "(argument_list) @item")
_CALLS_QUERY = Query(_C_LANGUAGE, "(call_expression) @item")
_MACROS_QUERY = Query(_C_LANGUAGE, "(preproc_def) @item (preproc_function_def) @item")


@dataclass(frozen=True, slots=True)
class Definition:
    name: str
    kind: str
    start: int
    end: int
    line: int
    end_line: int
    introduced_names: frozenset[str] = frozenset()
    tag_names: frozenset[str] = frozenset()
    scope_names: frozenset[str] = frozenset()
    external_linkage: bool = False

    @property
    def names(self) -> frozenset[str]:
        return self.introduced_names | {self.name}


@dataclass(frozen=True, slots=True)
class SyntaxToken:
    kind: str
    value: bytes
    has_error: bool


def parse_source(source: bytes) -> Tree:
    return Parser(_C_LANGUAGE).parse(source)


def nodes(root: Node) -> Iterator[Node]:
    """Walk without retaining a Python object for each node in a large file."""

    cursor = root.walk()
    while True:
        node = cursor.node
        assert node is not None
        yield node
        if cursor.goto_first_child():
            continue
        while not cursor.goto_next_sibling():
            if not cursor.goto_parent():
                return


def node_text(node: Node) -> bytes:
    text = node.text
    assert text is not None
    return text


def comments(tree: Tree) -> list[Node]:
    return QueryCursor(_COMMENTS_QUERY).captures(tree.root_node).get("item", [])


def sensitive_nodes(tree: Tree) -> list[Node]:
    return QueryCursor(_SENSITIVE_QUERY).captures(tree.root_node).get("item", [])


def argument_lists(tree: Tree) -> list[Node]:
    return QueryCursor(_ARGUMENTS_QUERY).captures(tree.root_node).get("item", [])


def call_expressions(tree: Tree) -> list[Node]:
    return QueryCursor(_CALLS_QUERY).captures(tree.root_node).get("item", [])


def macro_definitions(tree: Tree) -> list[Node]:
    return QueryCursor(_MACROS_QUERY).captures(tree.root_node).get("item", [])


def has_opaque_tokens(tree: Tree, *, implicit_names: bool = True) -> bool:
    """Find actual opaque constructs, excluding comments/literals/include paths.

    Macro replacement tokens still count: stringification, token pasting and
    implicit function-name constructs can escape an otherwise unused definition.
    """
    identifiers = {b"asm", b"__asm", b"__asm__"}
    if implicit_names:
        identifiers.update({b"__func__", b"__FUNCTION__", b"__PRETTY_FUNCTION__", b"__builtin_FUNCTION"})
    for token in syntax_tokens(tree):
        if token.kind == "ERROR":
            return True
        if token.kind in {"identifier", "type_identifier", "field_identifier", "asm", "__asm", "__asm__"} and token.value in identifiers:
            return True
        if token.kind in {"##", str(CTokenKind.PUNCTUATOR)} and token.value in {b"##", b"%:%:"}:
            return True
        if token.kind == str(CTokenKind.PUNCTUATOR) and token.value in {b"#", b"%:"}:
            return True
    return False


def recover_static_functions(source: bytes, names: frozenset[bytes]) -> list[Node]:
    """Reparse at a declaration boundary after an unrelated kernel macro error."""

    recovered: list[Node] = []
    for start in re.finditer(rb"(?m)^[ \t]*static\b", source):
        end = source.find(b"{", start.start(), start.start() + 2048)
        if end < 0:
            continue
        header = source[start.start():end]
        if b";" in header or b"=" in header or not (set(IDENTIFIER.findall(header)) & names):
            continue
        tree = parse_source(source[start.start():])
        for node in sensitive_nodes(tree):
            if node.type != "function_definition" or node.start_byte != 0:
                continue
            declaration = node.child_by_field_name("declarator")
            name = declarator_name(declaration) if declaration is not None else None
            if name is not None and node_text(name) in names:
                recovered.append(node)
    return recovered


def declarator_name(node: Node) -> Node | None:
    current: Node | None = node
    while current is not None:
        if current.type in {"identifier", "type_identifier", "field_identifier"}:
            return current
        current = current.child_by_field_name("declarator")
    return None


def macro_parameter_names(text: bytes) -> frozenset[str] | None:
    """Names from the supported complete ASCII macro-parameter grammar."""
    if re.fullmatch(rb"\(\s*(?:(?:[A-Za-z_]\w*\s*,\s*)*"
                    rb"(?:[A-Za-z_]\w*(?:\s*\.\.\.)?|\.\.\.)\s*)?\)", text) is None:
        return None
    names = re.findall(rb"[A-Za-z_]\w*", text)
    if len(set(names)) != len(names):
        return None
    result = frozenset(name.decode() for name in names)
    return result | {"__VA_ARGS__"} if re.search(rb"(?:\(|,)\s*\.\.\.\s*\)", text) else result


def definitions(source: bytes, tree: Tree) -> tuple[Definition, ...]:
    """Only standalone definitions whose removal has no initialization effects."""

    found: list[Definition] = []
    for node in QueryCursor(_DEFINITIONS_QUERY).captures(tree.root_node).get("item", []):
        name: Node | None = None
        if node.has_error:
            continue
        if node.type in {"function_definition", "struct_specifier"} and re.search(
            rb"(?m)^[ \t]*#|\b(?:_Pragma|__pragma)\b", node_text(node)
        ):
            # Translation-time effects can escape an unused C definition.
            continue
        if node.type == "function_definition":
            specifiers = {child.text for child in node.children if child.type == "storage_class_specifier"}
            if b"static" not in specifiers:
                continue
            declaration = node.child_by_field_name("declarator")
            name = declarator_name(declaration) if declaration is not None else None
            # Registration, linker placement and implicit-name constructs are
            # outside the zero-reference rule, even on a static function.
            if re.search(rb"\b__(?:init|exit|attribute|section|used|visible|alias)\w*\b", node_text(node)):
                continue
        elif node.type in {"preproc_def", "preproc_function_def"}:
            name = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            # Function-like expansions can generate registrations/declarations;
            # retain these until macro expansion is represented in the index.
            if value is not None and re.search(rb"[A-Za-z_]\w*\s*\(", node_text(value)):
                continue
        elif node.type == "struct_specifier":
            name = node.child_by_field_name("name")
            parent = node.parent
            if parent is None or parent.type not in {"translation_unit", "preproc_if", "preproc_ifdef", "preproc_else"}:
                continue
            if node.child_by_field_name("body") is None:
                continue
            body = node.child_by_field_name("body")
            assert body is not None
            # Nested tag definitions and enumerators introduce other names
            # that can be used without mentioning the enclosing structure.
            if any(child.type in {"struct_specifier", "union_specifier", "enum_specifier"}
                   and child.child_by_field_name("body") is not None for child in nodes(body)):
                continue
        if name is None:
            continue
        if re.fullmatch(rb"[A-Za-z_][A-Za-z_0-9]*", node_text(name)) is None:
            continue
        found.append(Definition(
            node_text(name).decode(), node.type, node.start_byte, node.end_byte,
            node.start_point.row + 1, node.start_point.row + node_text(node).rstrip(b"\r\n").count(b"\n") + 1,
        ))
    return tuple(found)


_FILE_SCOPE_CONDITIONALS = frozenset({"preproc_if", "preproc_ifdef", "preproc_else", "preproc_elif"})
_PLACEMENT_EFFECT = re.compile(rb"\b__(?:init|exit|attribute|section|used|visible|alias|weak|constructor)\w*\b|\b(?:_Pragma|__pragma|asm|__asm|__asm__)\b")
_TAG_KINDS = frozenset({"struct_specifier", "union_specifier", "enum_specifier"})


@dataclass(frozen=True, slots=True)
class _TagDeclaration:
    kind: str
    name: str
    start: int
    scope: tuple[tuple[int, int], ...]


@dataclass(frozen=True, slots=True)
class _TagDependencies:
    introduced: frozenset[str]
    bindings: frozenset[str]


def _conditional_scope(node: Node) -> tuple[tuple[int, int], ...] | None:
    scope: list[tuple[int, int]] = []
    parent = node.parent
    while parent is not None:
        if parent.type in {"preproc_elifdef", "preproc_elifndef"}:
            return None
        if parent.type in {"preproc_if", "preproc_ifdef", "preproc_elif"}:
            alternative = parent.child_by_field_name("alternative")
            arm = (alternative.start_byte if alternative is not None
                   and alternative.start_byte <= node.start_byte < alternative.end_byte else parent.start_byte)
            scope.append((parent.start_byte, arm))
            if len(scope) > 128:
                return None
        parent = parent.parent
    return tuple(reversed(scope))


def _global_tag(node: Node) -> bool:
    parent = node.parent
    while parent is not None:
        if parent.type in {"compound_statement", "parameter_list", "ERROR", "preproc_def", "preproc_function_def"}:
            return False
        parent = parent.parent
    return True


def _tag_declarations(tree: Tree) -> dict[tuple[str, str], list[_TagDeclaration]]:
    declarations: dict[tuple[str, str], list[_TagDeclaration]] = {}
    for node in nodes(tree.root_node):
        if node.type not in _TAG_KINDS or node.has_error or not _global_tag(node):
            continue
        name, scope = node.child_by_field_name("name"), _conditional_scope(node)
        if name is not None and scope is not None:
            text = node_text(name).decode()
            declarations.setdefault((node.type, text), []).append(_TagDeclaration(node.type, text, node.start_byte, scope))
    return declarations


def _escaping_tags(node: Node, declarations: dict[tuple[str, str], list[_TagDeclaration]]) -> _TagDependencies | None:
    scope = _conditional_scope(node)
    if scope is None:
        return None
    introduced: set[str] = set()
    bindings: set[str] = set()
    for tag in nodes(node):
        if tag.type not in _TAG_KINDS or not _global_tag(tag):
            continue
        name = tag.child_by_field_name("name")
        if name is None:
            continue
        if re.fullmatch(rb"[A-Za-z_][A-Za-z_0-9]*", node_text(name)) is None:
            return None
        text = node_text(name).decode()
        bindings.add(text)
        prior = declarations.get((tag.type, text), ())
        if not any(item.start < node.start_byte and scope[:len(item.scope)] == item.scope for item in prior):
            introduced.add(text)
    return _TagDependencies(frozenset(introduced), frozenset(bindings))


def _file_scope(node: Node) -> bool:
    parent = node.parent
    while parent is not None and parent.type in _FILE_SCOPE_CONDITIONALS:
        parent = parent.parent
    return parent is not None and parent.type == "translation_unit"


def _prototype_declarator(node: Node) -> bool:
    """Permit pointer return types, excluding function-pointer objects."""
    for _ in range(16):
        if node.type == "function_declarator":
            name = node.child_by_field_name("declarator")
            return name is not None and name.type == "identifier"
        if node.type not in {"pointer_declarator", "attributed_declarator"}:
            return False
        child = node.child_by_field_name("declarator")
        if child is None:
            return False
        node = child
    return False


def unused_definitions(source: bytes, tree: Tree) -> tuple[Definition, ...]:
    """Standalone declaration groups, with every escaping name represented.

    Global functions still require the caller's repository-wide use/export
    checks. Enum groups include all enumerators: removing an individual entry
    could change subsequent values or the underlying enum representation.
    """
    found = list(definitions(source, tree))
    covered = {item.start for item in found}
    for node in nodes(tree.root_node):
        if node.start_byte in covered or node.has_error or not _file_scope(node):
            continue
        if _PLACEMENT_EFFECT.search(node_text(node)):
            continue
        names: set[str] = set()
        name: Node | None = None
        if node.type == "function_definition":
            if re.search(rb"(?m)^[ \t]*#", node_text(node)):
                continue
            declarator = node.child_by_field_name("declarator")
            name = declarator_name(declarator) if declarator is not None else None
            if name is not None and node_text(name) in {
                b"main", b"_start", b"start_kernel", b"init_module", b"cleanup_module", b"secondary_start_kernel",
            }:
                continue
        elif node.type == "declaration":
            declarators = node.children_by_field_name("declarator")
            if len(declarators) != 1 or not _prototype_declarator(declarators[0]):
                continue
            name = declarator_name(declarators[0])
        elif node.type == "type_definition":
            declarators = node.children_by_field_name("declarator")
            if len(declarators) != 1:
                continue
            name = declarator_name(declarators[0])
        elif node.type in {"union_specifier", "enum_specifier"}:
            if node.child_by_field_name("body") is None:
                continue
            name = node.child_by_field_name("name")
            if node.type == "enum_specifier":
                enumerators = [child.child_by_field_name("name") for child in nodes(node) if child.type == "enumerator"]
                names.update(node_text(child).decode() for child in enumerators if child is not None)
                if name is None and enumerators:
                    name = enumerators[0]
        else:
            continue
        if name is None or re.fullmatch(rb"[A-Za-z_][A-Za-z_0-9]*", node_text(name)) is None:
            continue
        # Nested tag definitions escape prototypes/typedefs independently of
        # their apparent outer name and need their own declaration-site model.
        if any(child != node and child.type in {"struct_specifier", "union_specifier", "enum_specifier"}
               and child.child_by_field_name("body") is not None for child in nodes(node)):
            continue
        found.append(Definition(node_text(name).decode(), node.type, node.start_byte, node.end_byte,
                                node.start_point.row + 1,
                                node.start_point.row + node_text(node).rstrip(b"\r\n").count(b"\n") + 1,
                                frozenset(names)))
    declarations = _tag_declarations(tree)
    by_start = {(node.start_byte, node.type): node for node in nodes(tree.root_node)
                if node.type in {"function_definition", "declaration", "type_definition", *_TAG_KINDS}}
    result: list[Definition] = []
    for item in found:
        definition_node = by_start.get((item.start, item.kind))
        if definition_node is None:
            result.append(item)
            continue
        body = definition_node.child_by_field_name("body") if item.kind == "function_definition" else None
        if body is not None and any(tag.type in _TAG_KINDS and tag.start_byte < body.start_byte
                                    and tag.child_by_field_name("body") is not None for tag in nodes(definition_node)):
            continue
        introduced = _escaping_tags(definition_node, declarations)
        region = source[item.start:body.start_byte] if body is not None else node_text(definition_node)
        tokens = tokenize_c_source(region.decode())
        if introduced is not None and tokens is not None:
            result.append(replace(item, introduced_names=item.introduced_names | introduced.introduced,
                                  tag_names=introduced.bindings,
                                  scope_names=frozenset(token.value for token in tokens if token.kind is CTokenKind.IDENTIFIER),
                                  external_linkage=(item.kind == "function_definition"
                                                    and not any(child.type == "storage_class_specifier" and node_text(child) == b"static"
                                                                for child in definition_node.children))))
    return tuple(result)


def declaration_names(tree: Tree) -> frozenset[bytes]:
    """Names eligible to anchor a consistent rename, never call targets alone."""

    names: set[bytes] = set()
    for node in QueryCursor(_DECLARATIONS_QUERY).captures(tree.root_node).get("item", []):
        name: Node | None = None
        if node.type in {"function_definition", "declaration", "parameter_declaration", "field_declaration", "type_definition"}:
            declaration = node.child_by_field_name("declarator")
            name = declarator_name(declaration) if declaration is not None else None
        elif node.type in {"struct_specifier", "union_specifier", "enum_specifier", "enumerator", "preproc_def", "preproc_function_def"}:
            name = node.child_by_field_name("name")
        if name is not None:
            names.add(node_text(name))
    return frozenset(names)


def unclosed_declaration_names(tree: Tree) -> frozenset[bytes]:
    """Names requiring linkage/type proof beyond local source references.

    Other translation units can construct external symbol names with macros.
    Block-scope function/type-alias declarations also need semantic types before
    their linkage can be classified. Static and ordinary scalar locals remain
    eligible for the separate include/reference proof.
    """

    names: set[bytes] = set()
    for node in nodes(tree.root_node):
        if node.type not in {"function_definition", "declaration"}:
            continue
        storage = {node_text(child) for child in node.children if child.type == "storage_class_specifier"}
        if storage & {b"static", b"typedef"}:
            continue
        parent = node.parent
        while parent is not None and parent.type in {"preproc_if", "preproc_ifdef", "preproc_else", "preproc_elif"}:
            parent = parent.parent
        file_scope = parent is not None and parent.type == "translation_unit"
        semantic_type = any(child.type in {"function_declarator", "type_identifier"} for child in nodes(node))
        if not (file_scope or b"extern" in storage or node.type == "function_definition" or semantic_type):
            continue
        for declarator in node.children_by_field_name("declarator"):
            name = declarator_name(declarator)
            if name is not None:
                names.add(node_text(name))
            else:
                # Parenthesized/function-pointer declarators do not always
                # expose a declarator field in raw C syntax. Their identifiers
                # need semantic classification, never an empty linkage set.
                names.update(node_text(child) for child in nodes(declarator)
                             if child.type in {"identifier", "type_identifier"})
    return frozenset(names)


def renamed_region_identifiers(tree: Tree, names: frozenset[bytes]) -> frozenset[str] | None:
    """Identifier footprint of C constructs whose names change.

    A raw AST cannot certify macro definitions or expansion-generated C syntax.
    The caller must establish that these identifiers have no macro bindings in
    every included/consumer context before relying on the raw declarations.
    """

    identifiers: set[str] = set()
    # A macro can turn any C keyword/type-looking construct into a declaration
    # with different linkage. Cover every top-level construct rather than
    # certifying an empty footprint for syntax outside a declaration whitelist.
    for node in tree.root_node.named_children:
        tokens = tokenize_c_source(node_text(node).decode())
        if tokens is None:
            return None
        found = {token.value for token in tokens if token.kind is CTokenKind.IDENTIFIER}
        if not any(name.encode() in names for name in found):
            continue
        for macro in QueryCursor(_MACROS_QUERY).captures(node).get("item", []):
            replacement = tokenize_c_source(node_text(macro).decode())
            if replacement is None or any(token.kind is CTokenKind.IDENTIFIER and token.value.encode() in names
                                          for token in replacement):
                return None
        identifiers.update(found)
    return frozenset(identifiers)


def syntax_tokens(tree: Tree) -> Iterator[SyntaxToken]:
    """Concrete syntax leaves; comments ignored, macro bodies tokenized intact."""

    for node in nodes(tree.root_node):
        if node.type == "comment" or node.child_count:
            continue
        if node.type == "preproc_arg":
            tokens = tokenize_c_source(node_text(node).decode("utf-8", errors="strict"))
            if tokens is None:
                yield SyntaxToken("ERROR", node_text(node), True)
            else:
                for token in tokens:
                    kind = "identifier" if token.kind is CTokenKind.IDENTIFIER else str(token.kind)
                    yield SyntaxToken(kind, token.value.encode(), False)
            continue
        error = node.is_error or node.is_missing
        parent = node.parent if tree.root_node.has_error else None
        while parent is not None and not error:
            error = parent.is_error
            parent = parent.parent
        yield SyntaxToken(node.type, node_text(node), error)


def outside_definitions(source: bytes, items: tuple[Definition, ...]) -> bytes:
    result: list[bytes] = []
    position = 0
    for item in sorted(items, key=lambda item: item.start):
        if item.start < position:
            continue
        result.extend((source[position:item.start], b" "))
        position = item.end
    result.append(source[position:])
    return b"".join(result)
