"""Bounded macro observations which preserve positive facts after uncertainty.

These are discovery facts, not a certificate for a complete preprocessing
context. Consumers decide whether their explicit model can assume an incomplete
source scope. Operational failures cannot be assumed away.
"""

from collections import OrderedDict
from collections.abc import Callable, Iterable, Iterator
from contextlib import closing
from dataclasses import dataclass, field
from enum import StrEnum
from hashlib import sha256
from itertools import chain, islice
import re
import subprocess

from tree_sitter import Node

from .git_output import GitGrepProtocolError, iter_git_grep_rows
from .reference_index import ReferenceSite
from .syntax import macro_definitions, macro_parameter_names, node_text, nodes, parse_source
from .whitespace.c_lexer import preprocessor_directive_text, replace_c_comments
from ..git import GitRepo


class MacroOrigin(StrEnum):
    SOURCE = "source_definition"
    COMPILER = "compiler_definition"
    UNCLASSIFIED = "unclassified_option"


@dataclass(frozen=True, slots=True)
class MacroDefinition:
    function_like: bool
    replacement: bytes | None
    origin: MacroOrigin = MacroOrigin.SOURCE
    parameters: frozenset[str] = frozenset()


_ASSUMABLE_UNCERTAINTIES = frozenset({
    "nul_source", "trigraph_source", "carriage_return_source", "byte_order_mark", "gnu_whitespace_splice",
    "universal_character_spelling", "non_utf8_source", "opaque_directive_context", "unparsed_definition",
    "definition_budget", "file_budget", "byte_budget", "row_budget", "unclassified_compiler_option",
})


@dataclass(frozen=True, slots=True)
class MacroObservation:
    definitions: tuple[MacroDefinition, ...] = ()
    uncertainties: frozenset[str] = frozenset()

    @property
    def assumable(self) -> bool:
        """Whether all uncertainty is model/budget scope, rather than failed IO."""
        return self.uncertainties.issubset(_ASSUMABLE_UNCERTAINTIES)


@dataclass(frozen=True, slots=True)
class MacroFileDefinition:
    name: str
    definition: MacroDefinition


@dataclass(frozen=True, slots=True)
class MacroFileFacts:
    definitions: tuple[MacroFileDefinition, ...]
    uncertainties: frozenset[str]
    input_bytes: int


@dataclass(frozen=True, slots=True)
class _Budget:
    rows: int
    files: int
    input_bytes: int


_STRICT_BUDGET = _Budget(4096, 128, 2 * 1024 * 1024)
_ASSUMPTION_BUDGET = _Budget(16384, 512, 8 * 1024 * 1024)
_FILE_DEFINITIONS = 4096
_FILE_CACHE_COUNT = 256
_FILE_CACHE_BYTES = 16 * 1024 * 1024
_FILE_CACHE_DEFINITIONS = 16384
_POSITIVE_READ_FILES = 32
_POSITIVE_READ_BYTES = 512 * 1024
_POSITIVE_DEFINE = re.compile(rb"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_][A-Za-z_0-9]*)(?=[ \t(]|$)")
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z")
_COMMENT_SPACE = r"(?:\s|/\*[\s\S]*?\*/)"
_LITERAL_DEFINE = re.compile(r"(?:#|%:|\?\?=)" + _COMMENT_SPACE + r"*define" + _COMMENT_SPACE
                             + r"+([A-Za-z_][A-Za-z_0-9]*)(\()?")
_COMPILER_DEFINE = re.compile(r"-D[\s\"']*([A-Za-z_][A-Za-z_0-9]*)(?=[^A-Za-z_0-9]|$)")
_COMPILER_CONTEXT = re.compile(r"\b[A-Za-z_0-9]*flags(?:[-_A-Za-z_0-9.$()/]*)?\s*[:+?]?=|"
                               r"\$\((?:CC|HOSTCC|HOSTCXX|CXX|CPP|CLANG)\)|"
                               r"\$\{(?:CC|HOSTCC|HOSTCXX|CXX|CPP|CLANG)(?::[-+?][^}]*)?\}|"
                               r"\$(?:CC|HOSTCC|HOSTCXX|CXX|CPP|CLANG)\b|"
                               r"\b(?:clang(?:\+\+)?|gcc|g\+\+|cc|c\+\+|cpp)"
                               r"(?:-[0-9][A-Za-z_0-9.+-]*)?(?=[\s\"'])", re.IGNORECASE)


def _definition_key(item: MacroDefinition) -> tuple[str, bool, bool, bytes, tuple[str, ...]]:
    return item.origin.value, item.function_like, item.replacement is None, item.replacement or b"", tuple(sorted(item.parameters))


def _loose_logical_text(source: bytes) -> str:
    """Positive-only variants; none of these transformations proves absence."""
    text = source.decode("utf-8", errors="replace").replace("\x00", "").replace("\ufeff", "")
    text = text.replace("??=", "#").replace("??/", "\\").replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\\[^\S\r\n]*\n", "", text)
    def universal(match: re.Match[str]) -> str:
        value = int(match[1] or match[2], 16)
        return chr(value) if value < 128 else match[0]
    return re.sub(r"\\(?:u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8}))", universal, text)


def _positive_texts(source: bytes) -> Iterator[str]:
    yield _loose_logical_text(source)
    if b"\0" in source or b"\xef\xbb\xbf" in source:
        # GCC/Clang also treat embedded NUL as a token boundary. Joining alone
        # would miss '#define\0NAME' or the NAME in '#define NAME\0OTHER'.
        yield _loose_logical_text(source.replace(b"\0", b" ").replace(b"\xef\xbb\xbf", b" "))


def _literal_definitions(text: str) -> Iterator[MacroFileDefinition]:
    for match in _LITERAL_DEFINE.finditer(text):
        yield MacroFileDefinition(match[1], MacroDefinition(match[2] is not None, None))


def _compiler_definitions(text: str) -> Iterator[MacroFileDefinition]:
    if "-D" not in text:
        return
    for line in text.splitlines():
        if "-D" not in line:
            continue
        context = _COMPILER_CONTEXT.search(line)
        for match in _COMPILER_DEFINE.finditer(line):
            origin = (MacroOrigin.COMPILER if context is not None and context.end() <= match.start()
                      else MacroOrigin.UNCLASSIFIED)
            function_like = line[match.end():match.end() + 1] == "("
            yield MacroFileDefinition(match[1], MacroDefinition(function_like, None, origin))


def _positive_literals(source: bytes) -> Iterator[MacroFileDefinition]:
    return chain.from_iterable(_literal_definitions(text) for text in _positive_texts(source))


def _positive_compiler_flags(source: bytes) -> Iterator[MacroFileDefinition]:
    return chain.from_iterable(_compiler_definitions(text) for text in _positive_texts(source))


def _parameters(node: Node) -> frozenset[str] | None:
    if node.type != "preproc_function_def":
        return frozenset()
    parameters = node.child_by_field_name("parameters")
    if parameters is None:
        return None
    return macro_parameter_names(node_text(parameters))


def _source_uncertainties(source: bytes) -> set[str]:
    result: set[str] = set()
    for marker, reason in ((b"\0", "nul_source"), (b"??", "trigraph_source"), (b"\r", "carriage_return_source"),
                           (b"\xef\xbb\xbf", "byte_order_mark")):
        if marker in source:
            result.add(reason)
    if re.search(rb"\\[ \t\f\v]+\n", source):
        result.add("gnu_whitespace_splice")
    if re.search(rb"\\(?:u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})", source):
        result.add("universal_character_spelling")
    return result


def _parse_file(source: bytes) -> MacroFileFacts:
    uncertainties = _source_uncertainties(source)
    compiler = tuple(islice(_positive_compiler_flags(source), _FILE_DEFINITIONS + 1))
    if len(compiler) > _FILE_DEFINITIONS:
        uncertainties.add("definition_budget")
    try:
        text = source.decode()
    except UnicodeError:
        uncertainties.add("non_utf8_source")
        text = ""
    clean = replace_c_comments(text) if not uncertainties else None
    if clean is None or preprocessor_directive_text(text, strict_multiline=True) is None:
        uncertainties.add("opaque_directive_context")
        definitions = (*compiler, *islice(_positive_literals(source), _FILE_DEFINITIONS + 1))
        if len(definitions) > _FILE_DEFINITIONS:
            uncertainties.add("definition_budget")
        return MacroFileFacts(tuple(definitions[:_FILE_DEFINITIONS]), frozenset(uncertainties), len(source))

    clean = re.sub(r"(?m)^(\s*)%:", r"\1#", clean)
    definitions_list = list(compiler[:_FILE_DEFINITIONS])
    positions: set[int] = set()
    for node in macro_definitions(parse_source(clean.encode())):
        if len(definitions_list) >= _FILE_DEFINITIONS:
            uncertainties.add("definition_budget")
            break
        name = node.child_by_field_name("name")
        if name is None or _IDENTIFIER.fullmatch(node_text(name).decode()) is None:
            uncertainties.add("unparsed_definition")
            continue
        positions.add(name.start_byte)
        value = node.child_by_field_name("value")
        parameters = _parameters(node)
        supported = parameters is not None
        if node.has_error:
            args = node.child_by_field_name("parameters")
            supported = (supported and node.type == "preproc_function_def" and args is not None
                         and re.fullmatch(rb"\(\s*(?:[A-Za-z_]\w*\s*,\s*)*[A-Za-z_]\w*\s*\.\.\.\s*\)", node_text(args)) is not None
                         and value is not None
                         and not any(child.is_error and child.start_byte >= value.start_byte for child in nodes(node)))
        if not supported:
            uncertainties.add("unparsed_definition")
        definition = MacroDefinition(node.type == "preproc_function_def",
                                     (node_text(value) if value is not None else b"") if supported else None,
                                     parameters=parameters or frozenset())
        definitions_list.append(MacroFileDefinition(node_text(name).decode(), definition))
    # Recover literal directives omitted by an error-tolerant C parser.
    for match in re.finditer(rb"(?m)^[ \t]*#[ \t]*define[ \t]+([A-Za-z_][A-Za-z_0-9]*)(\()?", clean.encode()):
        if match.start(1) not in positions:
            uncertainties.add("unparsed_definition")
            if len(definitions_list) < _FILE_DEFINITIONS:
                definitions_list.append(MacroFileDefinition(match[1].decode(), MacroDefinition(match[2] is not None, None)))
            else:
                uncertainties.add("definition_budget")
    return MacroFileFacts(tuple(definitions_list), frozenset(uncertainties), len(source))


@dataclass(slots=True)
class _Discovery:
    definitions: dict[str, set[MacroDefinition]]
    uncertainties: dict[str, set[str]]
    processed: set[str] = field(default_factory=set)
    fallback: set[str] = field(default_factory=set)
    files: int = 0
    input_bytes: int = 0
    read_budget_hit: bool = False
    positive_attempts: int = 0
    positive_input_bytes: int = 0
    complete_positive_files: set[str] = field(default_factory=set)

    @classmethod
    def for_names(cls, names: frozenset[str]) -> "_Discovery":
        return cls({name: set() for name in names}, {name: set() for name in names})

    def uncertain(self, reason: str) -> None:
        for reasons in self.uncertainties.values():
            reasons.add(reason)

    def add(self, facts: Iterable[MacroFileDefinition]) -> None:
        for fact in facts:
            if fact.name not in self.definitions:
                continue
            self.definitions[fact.name].add(fact.definition)
            if fact.definition.origin is MacroOrigin.UNCLASSIFIED:
                self.uncertainties[fact.name].add("unclassified_compiler_option")

    def observations(self) -> dict[str, MacroObservation]:
        return {name: MacroObservation(tuple(sorted(values, key=_definition_key)), frozenset(self.uncertainties[name]))
                for name, values in self.definitions.items()}


class MacroLookup:
    def __init__(self, repo: GitRepo, read_file: Callable[[str, str], bytes],
                 active_site: Callable[[str, ReferenceSite], bool], *, allow_unknown: bool = False) -> None:
        self.repo, self.read_file, self.active_site = repo, read_file, active_site
        self._budget = _ASSUMPTION_BUDGET if allow_unknown else _STRICT_BUDGET
        self._cache: OrderedDict[tuple[str, str], MacroObservation] = OrderedDict()
        self._files: OrderedDict[str, MacroFileFacts] = OrderedDict()
        self.repository_scans = 0
        self.file_parses = 0
        self.file_cache_hits = 0
        self.file_cache_input_bytes = 0
        self._file_definition_count = 0
        self.positive_file_reads = 0
        self.positive_read_bytes = 0

    def lookup(self, revision: str, names: frozenset[str]) -> dict[str, MacroObservation]:
        result: dict[str, MacroObservation] = {}
        missing: set[str] = set()
        for name in names:
            if _IDENTIFIER.fullmatch(name) is None:
                result[name] = MacroObservation(uncertainties=frozenset({"unsupported_identifier"}))
            elif (revision, name) in self._cache:
                result[name] = self._cache[revision, name]
                self._cache.move_to_end((revision, name))
            else:
                missing.add(name)
        if missing:
            found = self._scan(revision, frozenset(missing))
            result.update(found)
            for name, observation in found.items():
                self._cache[revision, name] = observation
                if len(self._cache) > 512:
                    self._cache.popitem(last=False)
        return result

    def _file_facts(self, source: bytes) -> MacroFileFacts:
        digest = sha256(source).hexdigest()
        if digest in self._files:
            self.file_cache_hits += 1
            self._files.move_to_end(digest)
            return self._files[digest]
        self.file_parses += 1
        facts = _parse_file(source)
        if facts.input_bytes <= _FILE_CACHE_BYTES and len(facts.definitions) <= _FILE_CACHE_DEFINITIONS:
            self._files[digest] = facts
            self.file_cache_input_bytes += facts.input_bytes
            self._file_definition_count += len(facts.definitions)
            while (len(self._files) > _FILE_CACHE_COUNT or self.file_cache_input_bytes > _FILE_CACHE_BYTES
                   or self._file_definition_count > _FILE_CACHE_DEFINITIONS):
                _, old = self._files.popitem(last=False)
                self.file_cache_input_bytes -= old.input_bytes
                self._file_definition_count -= len(old.definitions)
        return facts

    @staticmethod
    def _arguments(revision: str, names: frozenset[str]) -> list[str]:
        alternation = "|".join(re.escape(name) for name in sorted(names))
        marker = r"(?:#|%:|\?\?=)"
        whitespace = r"(?:[[:space:]\x00]|" + "\ufeff" + ")"
        splice = r"(?:\\|\?\?/|\x00|" + "\ufeff" + ")"
        option_space = r"(?:[[:space:]\"'\x00]|" + "\ufeff" + ")"
        patterns = (marker + whitespace + r"*define" + whitespace + r"+(" + alternation + r")(" + whitespace + r"|\(|/\*|$)",
                    marker + whitespace + r"*([a-zA-Z_]*" + splice + r"|define" + whitespace + r"+[a-zA-Z_0-9]*" + splice + r")",
                    marker + whitespace + r"*(/\*|define" + whitespace + r"*/\*)",
                    r"-D" + option_space + r"*(" + alternation + r")([^A-Za-z_0-9]|$)",
                    r"-D" + option_space + r"*[A-Za-z_0-9]*" + splice,
                    r"-" + splice + r"[[:space:]]*$")
        return ["grep", "--threads=4", "-n", "-z", "-a", "-P",
                *(part for pattern in patterns for part in ("-e", pattern)), revision, "--"]

    @staticmethod
    def _refine_literal_facts(
        discovery: _Discovery, raw: tuple[MacroFileDefinition, ...], prior: frozenset[MacroFileDefinition],
    ) -> None:
        # A preexisting identical placeholder can belong to another file.
        # Complete evidence for this file must never erase that observation.
        for fact in raw:
            if fact not in prior:
                discovery.definitions[fact.name].discard(fact.definition)

    def _positive_file(self, revision: str, filename: str, discovery: _Discovery) -> MacroFileFacts | None:
        if discovery.positive_attempts >= _POSITIVE_READ_FILES:
            return None
        discovery.positive_attempts += 1
        try:
            size_field = self.repo._run_git(["cat-file", "-s", revision + ":" + filename]).strip()
            if not size_field.isdigit() or len(size_field) > 20:
                raise ValueError("Invalid Git blob size")
            size = int(size_field)
            if size > _POSITIVE_READ_BYTES - discovery.positive_input_bytes:
                return None
            self.positive_file_reads += 1
            source = self.read_file(revision, filename)
            self.positive_read_bytes += len(source)
            discovery.positive_input_bytes += len(source)
            if len(source) != size:
                raise ValueError("Git blob size disagrees with the source reader")
            return self._file_facts(source)
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
            discovery.uncertain("positive_source_read_failure")
            return None

    def _source(self, revision: str, filename: str, text: bytes, discovery: _Discovery) -> None:
        complete = filename in discovery.complete_positive_files
        match = _POSITIVE_DEFINE.match(text)
        recover = (filename not in discovery.processed
                   and (discovery.read_budget_hit or discovery.files >= self._budget.files)
                   and match is not None and match[1].decode() in discovery.definitions)
        if not complete and not recover:
            self._source_with_budget(revision, filename, text, discovery)
            return
        raw = tuple({fact for fact in _positive_literals(text) if fact.name in discovery.definitions})
        prior = frozenset(fact for fact in raw if fact.definition in discovery.definitions[fact.name])
        # Preserve every baseline read, counter, uncertainty and boundary rule.
        # Extra complete-file evidence uses its own bounded read allowance.
        self._source_with_budget(revision, filename, text, discovery)
        if complete:
            self._refine_literal_facts(discovery, raw, prior)
            return
        facts = self._positive_file(revision, filename, discovery)
        if facts is None:
            return
        if not facts.uncertainties:
            self._refine_literal_facts(discovery, raw, prior)
            discovery.complete_positive_files.add(filename)
        discovery.add(facts.definitions)
        for reason in facts.uncertainties:
            discovery.uncertain(reason)

    def _source_with_budget(self, revision: str, filename: str, text: bytes, discovery: _Discovery) -> None:
        if filename in discovery.processed:
            if filename in discovery.fallback:
                discovery.add(_positive_literals(text))
            return
        discovery.processed.add(filename)
        if discovery.read_budget_hit or discovery.files >= self._budget.files:
            discovery.read_budget_hit = True
            discovery.uncertain("file_budget" if discovery.files >= self._budget.files else "byte_budget")
            discovery.fallback.add(filename)
            discovery.add(_positive_literals(text))
            return
        discovery.files += 1
        try:
            source = self.read_file(revision, filename)
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
            discovery.uncertain("source_read_failure")
            discovery.fallback.add(filename)
            discovery.add(_positive_literals(text))
            return
        discovery.input_bytes += len(source)
        if discovery.input_bytes > self._budget.input_bytes:
            discovery.uncertain("byte_budget")
            discovery.read_budget_hit = True
            discovery.fallback.add(filename)
            discovery.add(_positive_literals(text))
            return
        facts = self._file_facts(source)
        discovery.add(facts.definitions)
        for reason in facts.uncertainties:
            discovery.uncertain(reason)
        if facts.uncertainties:
            discovery.fallback.add(filename)
            discovery.add(_positive_literals(text))

    @staticmethod
    def _site(path: bytes, line: int, revision: str) -> ReferenceSite:
        prefix = (revision + ":").encode()
        if not path.startswith(prefix):
            raise ValueError("Unexpected revision prefix")
        filename = path[len(prefix):].decode()
        if not filename or line < 1:
            raise ValueError("Invalid source coordinate")
        return ReferenceSite(filename, line)

    def _scan(self, revision: str, names: frozenset[str]) -> dict[str, MacroObservation]:
        discovery = _Discovery.for_names(names)
        self.repository_scans += 1
        try:
            # These patterns require PCRE: never reinterpret them as POSIX ERE
            # after an unsupported-PCRE error and manufacture a negative fact.
            with closing(iter_git_grep_rows(self.repo, self._arguments(revision, names))) as rows:
                for count, row in enumerate(rows):
                    if count >= self._budget.rows:
                        discovery.uncertain("row_budget")
                        # The boundary row has already been observed. Keep its
                        # literal positives without reading another source.
                        discovery.add(_positive_compiler_flags(row.contents))
                        discovery.add(_positive_literals(row.contents))
                        try:
                            self._site(row.path, row.line, revision)
                        except (ValueError, UnicodeError):
                            discovery.uncertain("malformed_grep_row")
                        break
                    discovery.add(_positive_compiler_flags(row.contents))
                    try:
                        site = self._site(row.path, row.line, revision)
                    except (ValueError, UnicodeError):
                        discovery.uncertain("malformed_grep_row")
                        discovery.add(_positive_literals(row.contents))
                        continue
                    try:
                        active = self.active_site(revision, site)
                    except (OSError, ValueError, subprocess.SubprocessError):
                        discovery.uncertain("active_site_failure")
                        discovery.add(_positive_literals(row.contents))
                        continue
                    if active:
                        self._source(revision, site.path, row.contents, discovery)
        except GitGrepProtocolError:
            discovery.uncertain("malformed_grep_row")
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
            discovery.uncertain("repository_scan_failure")
        return discovery.observations()
