"""Small Tree-sitter analyses shared by source equivalence and use filtering."""

from collections.abc import Iterator
from dataclasses import dataclass
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


@dataclass(frozen=True, slots=True)
class Definition:
    name: str
    kind: str
    start: int
    end: int
    line: int
    end_line: int


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
            node.start_point.row + 1, node.end_point.row + 1,
        ))
    return tuple(found)


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
