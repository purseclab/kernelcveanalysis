"""Bounded, same-file permutations of adjacent independent static helpers.

Declarations and preprocessing directives are barriers. Function bodies and
signatures must match exactly, and references between crossed functions are
rejected. A separate repository macro check covers ordinary identifier macros.
As with the other raw-source analyses, compiler keyword macros, generated and
forced includes/flags require the standard kernel compilation model.
"""

from collections import Counter, OrderedDict
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass
import re

from tree_sitter import Node

from .source_filter import _iter_git_grep
from .reference_index import ReferenceSite
from .syntax import (
    call_expressions, declaration_names, definitions, has_opaque_tokens,
    macro_definitions, node_text, nodes, parse_source,
)
from .whitespace.c_lexer import CToken, CTokenKind, replace_c_comments, tokenize_c_source
from ..diff import DiffFile
from ..git import GitRepo


_KEYWORDS = frozenset("auto break case char const continue default do double else enum extern float for goto if inline int long register restrict return short signed sizeof static struct switch typedef union unsigned void volatile while _Alignas _Alignof _Atomic _Bool _Complex _Generic _Imaginary _Noreturn _Static_assert _Thread_local".split())
_TOP_LEVEL = frozenset({"preproc_if", "preproc_ifdef", "preproc_else", "preproc_elif"})
_NUMERIC_OPERATORS = frozenset("( ) + - * / % << >> & | ^ ~ ! && || == != < > <= >= ? :".split())


@dataclass(frozen=True, slots=True)
class ReorderProof:
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


@dataclass(frozen=True, slots=True)
class _Macro:
    function_like: bool
    value: bytes


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
    """Small lazy macro-definition cache, distinct from ordinary use facts.

    Unknown, function-like and nonliteral replacements retain the candidate.
    Searches cover tracked C/header/assembly/include fragments. They do not
    infer compiler-generated definitions or command-line macro bindings.
    """

    def __init__(self, repo: GitRepo, read_file: Callable[[str, str], bytes],
                 active_site: Callable[[str, ReferenceSite], bool]) -> None:
        self.repo, self.read_file = repo, read_file
        self.active_site = active_site
        self._cache: OrderedDict[tuple[str, str], tuple[_Macro, ...] | None] = OrderedDict()
        self.repository_scans = 0

    def _lookup(self, revision: str, names: frozenset[str]) -> dict[str, tuple[_Macro, ...] | None]:
        missing = names - {name for name in names if (revision, name) in self._cache}
        if missing:
            found = self._scan(revision, missing)
            for name, macros in found.items():
                self._cache[revision, name] = macros
                if len(self._cache) > 512:
                    self._cache.popitem(last=False)
        return {name: self._cache.get((revision, name)) for name in names}

    def _scan(self, revision: str, names: frozenset[str]) -> dict[str, tuple[_Macro, ...] | None]:
        result: dict[str, list[_Macro]] = {name: [] for name in names}
        alternation = "|".join(re.escape(name) for name in sorted(names))
        pattern = r"^[[:space:]]*#[[:space:]]*define[[:space:]]+(" + alternation + r")([[:space:](]|/\*|$)"
        # A continuation before/in a macro name cannot establish absence from
        # the ordinary spelling search. These rare directives retain the query.
        split_name = r"^[[:space:]]*#[[:space:]]*([a-zA-Z_]*\\|define[[:space:]]+[a-zA-Z_0-9]*\\)[[:space:]]*$"
        unusual = r"^[[:space:]]*(%:|#[[:space:]]*(/\*|define[[:space:]]*/\*)|/\*.*\*/[[:space:]]*#|\*/[[:space:]]*#)"
        partial_name = re.compile(rb"^\s*#\s*define\s+([A-Za-z_0-9]+)\\\s*$")
        arguments = ["grep", "--threads=4", "-n", "-z", "-I", "-P", "-e", pattern, "-e", split_name, "-e", unusual, revision,
                     "--", "*.c", "*.h", "*.S", "*.s", "*.inc"]
        seen: set[str] = set()
        prefix = (revision + ":").encode()
        total_bytes = 0
        self.repository_scans += 1
        with closing(_iter_git_grep(self.repo, arguments)) as rows:
            for count, row in enumerate(rows):
                fields = row.split(b"\0", 2)
                if len(fields) != 3:
                    return {name: None for name in names}
                partial = partial_name.search(fields[2])
                if partial is not None and not any(name.startswith(partial[1].decode()) for name in names):
                    continue
                path = fields[0]
                if count >= 4096 or not path.startswith(prefix):
                    return {name: None for name in names}
                filename = path[len(prefix):].decode()
                if filename in seen or not self.active_site(revision, ReferenceSite(filename, int(fields[1]))):
                    continue
                seen.add(filename)
                source = self.read_file(revision, filename)
                total_bytes += len(source)
                if len(seen) > 32 or total_bytes > 512 * 1024:
                    return {name: None for name in names}
                clean = replace_c_comments(source.decode())
                if clean is None:
                    return {name: None for name in names}
                clean = re.sub(r"(?m)^(\s*)%:", r"\1#", clean)
                for node in macro_definitions(parse_source(clean.encode())):
                    name_node = node.child_by_field_name("name")
                    if name_node is None or (name := node_text(name_node).decode()) not in names:
                        continue
                    if node.has_error:
                        return {name: None for name in names}
                    value = node.child_by_field_name("value")
                    result[name].append(_Macro(node.type == "preproc_function_def", node_text(value) if value is not None else b""))
        return {name: tuple(macros) for name, macros in result.items()}

    def allows(self, revision: str, proof: ReorderProof) -> bool:
        if len(proof.identifiers) > 64:
            return False
        for name, macros in self._lookup(revision, proof.identifiers).items():
            if macros is None:
                return False
            if not macros:
                continue
            if name not in proof.numeric_names:
                return False
            for macro in macros:
                tokens = tokenize_c_source(macro.value.decode())
                if macro.function_like or not tokens or not all(
                    t.kind is CTokenKind.PP_NUMBER or t.kind is CTokenKind.PUNCTUATOR and t.value in _NUMERIC_OPERATORS
                    for t in tokens
                ):
                    return False
        return True
