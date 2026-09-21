import bisect
from dataclasses import dataclass
from enum import StrEnum
from typing import Sequence
from tree_sitter import Language, Parser, Node
import tree_sitter_c as tsc

_C_LANGUAGE = Language(tsc.language())

# Common C keywords, standard primitives, and compiler builtins to exclude from references
_IGNORED_IDENTIFIERS: frozenset[str] = frozenset({
    "if", "while", "for", "do", "switch", "case", "default", "return", "goto", "break",
    "continue", "sizeof", "typeof", "__typeof__", "typeof_unqual", "offsetof", "container_of",
    "likely", "unlikely", "void", "int", "char", "short", "long", "unsigned", "signed",
    "float", "double", "bool", "_Bool", "size_t", "ssize_t", "int8_t", "int16_t", "int32_t",
    "int64_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t", "u8", "u16", "u32", "u64",
    "s8", "s16", "s32", "s64", "__u8", "__u16", "__u32", "__u64", "__s8", "__s16", "__s32",
    "__s64", "static", "inline", "__inline", "__inline__", "extern", "const", "volatile",
    "__volatile", "__volatile__", "register", "auto", "restrict", "__restrict", "__restrict__",
    "NULL", "true", "false",
})


class ItemKind(StrEnum):
    """The syntactic category of a top-level C item."""

    FUNCTION = "function"
    STRUCT = "struct"
    UNION = "union"
    ENUM = "enum"
    MACRO = "macro"
    DECLARATION = "declaration"
    DIRECTIVE = "directive"


@dataclass(frozen=True, slots=True)
class ItemSpan:
    """A top-level C item with its 1-indexed line span and complete text."""

    kind: ItemKind
    start_line: int       # 1-indexed, inclusive (includes preceding doc comments)
    end_line: int         # 1-indexed, inclusive
    name: str             # Identifier or signature summary
    code: str             # Full source text including comments
    node_byte_range: tuple[int, int]  # (start_byte, end_byte) for AST queries


@dataclass(frozen=True, slots=True)
class IncludeDirective:
    """A parsed #include preprocessor directive."""

    path: str             # Header path without delimiters, e.g. "uring_cmd.h" or "linux/security.h"
    is_system: bool       # True for <...>, False for "..."
    line: int             # 1-indexed line where #include occurs


@dataclass(frozen=True, slots=True)
class ItemReferences:
    """Identifiers referenced inside an item body."""

    called_functions: frozenset[str]
    referenced_types: frozenset[str]
    referenced_macros: frozenset[str]


@dataclass(frozen=True, slots=True)
class ParsedCFile:
    """A C source or header file parsed into top-level items and include directives."""

    path: str
    items: tuple[ItemSpan, ...]
    includes: tuple[IncludeDirective, ...]
    name_to_item: dict[str, ItemSpan]


def _build_newline_offsets(source_bytes: bytes) -> list[int]:
    """Return 0-indexed byte offsets of the start of every 1-indexed line."""
    offsets = [0]
    for index, byte in enumerate(source_bytes):
        if byte == 10:  # ord('\n')
            offsets.append(index + 1)
    return offsets


def _byte_to_line(newline_offsets: Sequence[int], byte_offset: int) -> int:
    """Convert a byte offset to a 1-indexed line number."""
    return bisect.bisect_right(newline_offsets, byte_offset)


def _extract_function_name(node: Node, source_bytes: bytes) -> str:
    """Extract the function name identifier from a function_definition node."""
    decl = node.child_by_field_name("declarator")
    if decl is None:
        return ""

    def find_ident(n: Node) -> Node | None:
        if n.type == "identifier":
            return n
        for child in n.children:
            # Avoid traversing inside the parameter_list
            if child.type != "parameter_list":
                found = find_ident(child)
                if found is not None:
                    return found
        return None

    ident = find_ident(decl)
    if ident is not None:
        return source_bytes[ident.start_byte:ident.end_byte].decode("utf-8", errors="replace")
    return ""


def extract_item_references(item: ItemSpan, source: str | bytes) -> ItemReferences:
    """Extract called functions, referenced struct/enum types, and macros from an item."""
    source_bytes = source.encode("utf-8") if isinstance(source, str) else source
    start_byte, end_byte = item.node_byte_range
    item_bytes = source_bytes[start_byte:end_byte]

    parser = Parser(_C_LANGUAGE)
    tree = parser.parse(item_bytes)

    called_functions: set[str] = set()
    referenced_types: set[str] = set()
    referenced_macros: set[str] = set()

    def visit(node: Node) -> None:
        if node.type == "call_expression":
            fn = node.child_by_field_name("function")
            if fn is not None:
                if fn.type == "identifier":
                    name = item_bytes[fn.start_byte:fn.end_byte].decode("utf-8", errors="replace")
                    if name not in _IGNORED_IDENTIFIERS:
                        called_functions.add(name)
                elif fn.type == "field_expression":
                    field = fn.child_by_field_name("field")
                    if field is not None and field.type == "field_identifier":
                        name = item_bytes[field.start_byte:field.end_byte].decode("utf-8", errors="replace")
                        if name not in _IGNORED_IDENTIFIERS:
                            called_functions.add(name)
        elif node.type == "struct_specifier":
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                name = item_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")
                if name not in _IGNORED_IDENTIFIERS:
                    referenced_types.add(f"struct {name}")
                    referenced_types.add(name)
        elif node.type == "union_specifier":
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                name = item_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")
                if name not in _IGNORED_IDENTIFIERS:
                    referenced_types.add(f"union {name}")
                    referenced_types.add(name)
        elif node.type == "enum_specifier":
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                name = item_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")
                if name not in _IGNORED_IDENTIFIERS:
                    referenced_types.add(f"enum {name}")
                    referenced_types.add(name)
        elif node.type == "type_identifier":
            name = item_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
            if name not in _IGNORED_IDENTIFIERS:
                referenced_types.add(name)

        for child in node.children:
            visit(child)

    visit(tree.root_node)

    return ItemReferences(
        called_functions=frozenset(called_functions),
        referenced_types=frozenset(referenced_types),
        referenced_macros=frozenset(referenced_macros),
    )


def parse_c_file(path: str, source: str) -> ParsedCFile:
    """Parse a C source or header file into top-level items and include directives."""
    source_bytes = source.encode("utf-8")
    newline_offsets = _build_newline_offsets(source_bytes)

    parser = Parser(_C_LANGUAGE)
    tree = parser.parse(source_bytes)

    items: list[ItemSpan] = []
    includes: list[IncludeDirective] = []
    name_to_item: dict[str, ItemSpan] = {}

    pending_comment_byte_start: int | None = None

    def process_nodes(nodes: Sequence[Node]) -> None:
        nonlocal pending_comment_byte_start
        for node in nodes:
            if node.type == "comment":
                if pending_comment_byte_start is None:
                    pending_comment_byte_start = node.start_byte
                continue

            node_start_byte = pending_comment_byte_start if pending_comment_byte_start is not None else node.start_byte
            node_end_byte = node.end_byte

            start_l = _byte_to_line(newline_offsets, node_start_byte)
            end_l = _byte_to_line(newline_offsets, node_end_byte)

            # Handle conditional compilation / linkage containers
            if node.type in ("preproc_ifdef", "preproc_if", "preproc_else", "preproc_elif", "linkage_specification"):
                pending_comment_byte_start = None
                process_nodes(node.children)
                continue

            # Handle includes
            if node.type == "preproc_include":
                path_node = node.child_by_field_name("path")
                if path_node is not None:
                    raw_text = source_bytes[path_node.start_byte:path_node.end_byte].decode("utf-8", errors="replace")
                    is_sys = path_node.type == "system_lib_string" or raw_text.startswith("<")
                    inc_path = raw_text.strip('<">')
                    includes.append(IncludeDirective(
                        path=inc_path,
                        is_system=is_sys,
                        line=start_l,
                    ))
                pending_comment_byte_start = None
                continue

            # Handle functions
            if node.type == "function_definition":
                func_name = _extract_function_name(node, source_bytes)
                code = source_bytes[node_start_byte:node_end_byte].decode("utf-8", errors="replace")
                item = ItemSpan(
                    kind=ItemKind.FUNCTION,
                    start_line=start_l,
                    end_line=end_l,
                    name=func_name,
                    code=code,
                    node_byte_range=(node.start_byte, node.end_byte),
                )
                items.append(item)
                if func_name:
                    name_to_item[func_name] = item
                pending_comment_byte_start = None
                continue

            # Handle macros
            if node.type in ("preproc_def", "preproc_function_def"):
                name_node = node.child_by_field_name("name")
                m_name = ""
                if name_node is not None:
                    m_name = source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")
                code = source_bytes[node_start_byte:node_end_byte].decode("utf-8", errors="replace")
                item = ItemSpan(
                    kind=ItemKind.MACRO,
                    start_line=start_l,
                    end_line=end_l,
                    name=m_name,
                    code=code,
                    node_byte_range=(node.start_byte, node.end_byte),
                )
                items.append(item)
                if m_name:
                    name_to_item[m_name] = item
                pending_comment_byte_start = None
                continue

            # Handle struct, union, enum definitions (direct or wrapped in declaration/typedef)
            spec_node: Node | None = None
            if node.type in ("struct_specifier", "union_specifier", "enum_specifier") and node.child_by_field_name("body") is not None:
                spec_node = node
            elif node.type in ("declaration", "type_definition"):
                for sub in node.children:
                    if sub.type in ("struct_specifier", "union_specifier", "enum_specifier") and sub.child_by_field_name("body") is not None:
                        spec_node = sub
                        break

            if spec_node is not None:
                tag_node = spec_node.child_by_field_name("name")
                tag = ""
                if tag_node is not None:
                    tag = source_bytes[tag_node.start_byte:tag_node.end_byte].decode("utf-8", errors="replace")
                kind = (
                    ItemKind.STRUCT
                    if spec_node.type == "struct_specifier"
                    else (ItemKind.ENUM if spec_node.type == "enum_specifier" else ItemKind.UNION)
                )
                code = source_bytes[node_start_byte:node_end_byte].decode("utf-8", errors="replace")
                full_name = f"{kind.value} {tag}".strip() if tag else kind.value
                item = ItemSpan(
                    kind=kind,
                    start_line=start_l,
                    end_line=end_l,
                    name=full_name,
                    code=code,
                    node_byte_range=(node.start_byte, node.end_byte),
                )
                items.append(item)
                if full_name:
                    name_to_item[full_name] = item
                if tag:
                    name_to_item[tag] = item
                if node.type == "type_definition":
                    decl_node = node.child_by_field_name("declarator")
                    if decl_node is not None:
                        typedef_name = source_bytes[decl_node.start_byte:decl_node.end_byte].decode("utf-8", errors="replace")
                        if typedef_name:
                            name_to_item[typedef_name] = item
                pending_comment_byte_start = None
                continue

            pending_comment_byte_start = None

    process_nodes(tree.root_node.children)

    return ParsedCFile(
        path=path,
        items=tuple(items),
        includes=tuple(includes),
        name_to_item=name_to_item,
    )
