"""Positive raw-input consumers, never a certificate of input-role closure.

Only literal assembly inputs and explicit Make generator prerequisites are
recognized. Empty observations say nothing about other consumers or languages.
Operational/budget uncertainty must retain the proposed source mask.
"""

from bisect import bisect_right
from collections import OrderedDict, defaultdict
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass, field, replace
from enum import StrEnum
from hashlib import sha256
import posixpath
import re
import subprocess
from time import perf_counter

from ..git import GitRepo
from .config_filter import KbuildMakefile
from .git_output import iter_git_records


class RawInputKind(StrEnum):
    ASSEMBLER_INCBIN = 'assembler_incbin'
    ASSEMBLER_INCLUDE = 'assembler_include'
    MAKE_GENERATOR = 'make_generator'


@dataclass(frozen=True, slots=True)
class RawInputConsumer:
    path: str
    line: int
    kind: RawInputKind
    target: str | None = None


@dataclass(frozen=True, slots=True)
class RawInputObservation:
    consumers: tuple[RawInputConsumer, ...] = ()
    uncertainties: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class RawInputIndexStats:
    repository_scans: int = 0
    incremental_updates: int = 0
    revision_cache_hits: int = 0
    file_parses: int = 0
    file_cache_hits: int = 0
    input_bytes: int = 0
    scan_seconds: float = 0.0
    marker_queries: int = 0
    witness_reads: int = 0
    witness_hits: int = 0
    veto_cache_hits: int = 0


@dataclass(frozen=True, slots=True)
class _Reference:
    name: str
    line: int
    kind: RawInputKind
    target: str | None = None


@dataclass(frozen=True, slots=True)
class _FileFacts:
    references: tuple[_Reference, ...] = ()
    uncertainties: frozenset[str] = frozenset()


@dataclass(slots=True)
class _Snapshot:
    revision: str
    files: dict[str, _FileFacts] = field(default_factory=dict)
    links: dict[str, str] = field(default_factory=dict)
    uncertainties: set[str] = field(default_factory=set)
    exact: dict[str, list[RawInputConsumer]] = field(default_factory=lambda: defaultdict(list))
    basenames: dict[str, list[RawInputConsumer]] = field(default_factory=lambda: defaultdict(list))
    inventory_complete: bool = False


class _InventoryLimit(ValueError):
    pass


@dataclass(slots=True)
class _ReadBudget:
    files: int = 0
    input_bytes: int = 0


@dataclass(frozen=True, slots=True)
class _CachedFacts:
    facts: _FileFacts
    input_bytes: int


@dataclass(frozen=True, slots=True)
class _UncertaintyWitness:
    path: str
    source_sha256: bytes
    uncertainties: frozenset[str]


_MAX_FILES = 8192
_MAX_BYTES = 16 * 1024 * 1024
_MAX_FILE_BYTES = 1024 * 1024
_MAX_REFERENCES = 32768
_MAX_CHANGED_PATHS = 1024
_MAX_TREE_ROWS = 500000
_MAX_SNAPSHOTS = 4
_MAX_FILE_CACHE = 4096
_MAX_FILE_CACHE_BYTES = 16 * 1024 * 1024
_MARKER_BATCH_PATHS = 2048
_MARKER_BATCH_BYTES = 64 * 1024
_MAX_VETO_REVISIONS = 128
_FULL_REVISION = re.compile(r'(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\Z')
_ASM_MARKER = re.compile(rb'\.(incbin|include)\b')
_ASM_LITERAL = re.compile(rb'\.(incbin|include)\b[ \t]*"([^"\r\n]+)"')
_SOURCE_SUFFIXES = ('.c', '.h', '.cc', '.cpp', '.hpp', '.S', '.s', '.asm', '.inc')
_ASSEMBLY_SUFFIXES = ('.S', '.s', '.asm', '.inc')
_GENERATED_SUFFIXES = _SOURCE_SUFFIXES + ('.bin', '.dat', '.data', '.hex', '.tbl', '.json', '.yaml', '.txt', '.dtb', '.fw')
_MAKE_WORD = re.compile(r'(?:\\.|[^\s])+')
_MAKE_VARIABLE = re.compile(r'\$\(([A-Za-z_][A-Za-z_0-9]*)\)|\$\{([A-Za-z_][A-Za-z_0-9]*)\}')
_COMPILE = re.compile(r'\$[({](?:CC|HOSTCC|CXX|HOSTCXX|CPP)[)}]|\b(?:gcc|clang|cc|cpp|g\+\+|clang\+\+)\b|'
                      r'\$\(call\s+(?:if_changed(?:_rule|_dep)?|cmd),\s*(?:cc_o_c|cc_s_c|as_o_S|cpp_s_S)\s*\)')
_RAW_TOOL = re.compile(r'\b(?:perl|python[0-9.]*|awk|sed|cat|cp|xxd|objcopy)\b')


def _make_path(path: str) -> bool:
    name = posixpath.basename(path)
    return name.startswith(('Makefile', 'Kbuild')) or name.endswith('.mk') or name in {'makefile', 'GNUmakefile'}


def _logical_make(source: str) -> tuple[tuple[int, str], ...]:
    starts: list[int] = []
    pending = False
    for number, line in enumerate(source.splitlines(), 1):
        if not pending:
            starts.append(number)
        pending = line.rstrip().endswith('\\')
    return tuple(zip(starts, KbuildMakefile._logical_lines(source), strict=True))


def _expand_make(word: str, variables: dict[str, set[str]], seen: frozenset[str] = frozenset()) -> tuple[tuple[str, ...], bool]:
    for match in _MAKE_VARIABLE.finditer(word):
        name = match[1] or match[2]
        if name in {'src', 'obj', 'srctree'}:
            continue
        values = variables.get(name)
        if values is None or name in seen or len(seen) >= 8:
            return (word,), True
        output: list[str] = []
        unknown = False
        for value in sorted(values):
            expanded, uncertain = _expand_make(word[:match.start()] + value + word[match.end():], variables, seen | {name})
            output.extend(expanded)
            unknown |= uncertain
            if len(output) > 128:
                raise _InventoryLimit('make_expansion_budget')
        return tuple(output), unknown
    remaining = _MAKE_VARIABLE.sub('', word)
    return (word,), '$' in remaining


def _make_facts(source: str) -> _FileFacts:
    logical_lines = _logical_make(source)
    variables: dict[str, set[str]] = defaultdict(set)
    for _, logical in logical_lines:
        assignment = re.match(r'\s*(?:override\s+|export\s+)?([A-Za-z_][A-Za-z_0-9]*)\s*([:+?!]?=)\s*(.*)', logical)
        if assignment is not None:
            values = {'$unresolved_shell_input'} if assignment[2] == '!=' else set(_MAKE_WORD.findall(KbuildMakefile._strip_comment(assignment[3])))
            variables[assignment[1]].update(values)
    found: list[_Reference] = []
    uncertainty: set[str] = set()
    pending: tuple[int, tuple[str, ...], tuple[str, ...], bool] | None = None
    for line_number, logical in logical_lines:
        if logical.startswith('\t'):
            if pending is not None and (not _COMPILE.search(logical) or _RAW_TOOL.search(logical)):
                rule_line, rule_targets, inputs, unknown = pending
                if unknown and (inputs or _RAW_TOOL.search(logical) or any(target.endswith(_GENERATED_SUFFIXES) for target in rule_targets)):
                    uncertainty.add('unresolved_make_input')
                if len(found) + len(rule_targets) * len(inputs) > _MAX_REFERENCES:
                    raise _InventoryLimit('reference_budget')
                found.extend(_Reference(name, rule_line, RawInputKind.MAKE_GENERATOR, target)
                             for target in rule_targets for name in inputs)
            continue
        pending = None
        line = KbuildMakefile._strip_comment(logical).strip()
        if not line or ':' not in line or re.match(r'[^:=]*[:+?!]?=', line):
            continue
        targets, _, prerequisites = line.partition(':')
        prerequisites, inline, recipe = prerequisites.partition(';')
        output = tuple(_MAKE_WORD.findall(targets))
        inputs_list: list[str] = []
        unknown = False
        for word in _MAKE_WORD.findall(prerequisites):
            expanded, uncertain = _expand_make(word, variables)
            unknown |= uncertain or any(char in name for name in expanded for char in '*?[]%')
            inputs_list.extend(name for name in expanded if name.replace('\\ ', ' ').endswith(_SOURCE_SUFFIXES))
        inputs = tuple(inputs_list)
        if output and (inputs or unknown):
            pending = (line_number, output, inputs, unknown)
            if inline and (not _COMPILE.search(recipe) or _RAW_TOOL.search(recipe)):
                if unknown and (inputs or _RAW_TOOL.search(recipe) or any(target.endswith(_GENERATED_SUFFIXES) for target in output)):
                    uncertainty.add('unresolved_make_input')
                if len(found) + len(output) * len(inputs) > _MAX_REFERENCES:
                    raise _InventoryLimit('reference_budget')
                found.extend(_Reference(name, line_number, RawInputKind.MAKE_GENERATOR, target)
                             for target in output for name in inputs)
    return _FileFacts(tuple(found), frozenset(uncertainty))


def _facts(source: bytes, make: bool) -> _FileFacts:
    text = source.decode('utf-8')
    make_facts = _make_facts(text) if make else _FileFacts()
    references = list(make_facts.references)
    uncertainties = set(make_facts.uncertainties)
    positions: list[int] = []
    parts: list[bytes] = []
    offset = 0
    length = 0
    for splice in re.finditer(rb'\\\r?\n', source):
        part = source[offset:splice.start()]
        parts.append(part)
        length += len(part)
        positions.append(length)
        offset = splice.end()
    parts.append(source[offset:])
    normalized = b''.join(parts).replace(b'\\"', b'"')
    for match in _ASM_LITERAL.finditer(normalized):
        if len(references) >= _MAX_REFERENCES:
            raise _InventoryLimit('reference_budget')
        line = normalized.count(b'\n', 0, match.start()) + bisect_right(positions, match.start()) + 1
        kind = RawInputKind.ASSEMBLER_INCBIN if match[1] == b'incbin' else RawInputKind.ASSEMBLER_INCLUDE
        if b'\\' in match[2]:
            uncertainties.add('unresolved_assembler_input')
        references.append(_Reference(match[2].decode('utf-8'), line, kind))
    unresolved = any(_ASM_LITERAL.match(normalized, marker.start()) is None
                     and re.search(rb'(?:^|\n|\\n|"|;|:)[ \t]*$', normalized[:marker.start()])
                     for marker in _ASM_MARKER.finditer(normalized))
    if unresolved:
        uncertainties.add('unresolved_assembler_input')
    if len(references) > _MAX_REFERENCES:
        raise _InventoryLimit('reference_budget')
    return _FileFacts(tuple(references), frozenset(uncertainties))


def _normal(path: str) -> str | None:
    if not path or '\0' in path or posixpath.isabs(path):
        return None
    normalized = posixpath.normpath(path)
    return None if normalized == '..' or normalized.startswith('../') else normalized


def _link_target(path: str, links: dict[str, str]) -> str | None:
    for _ in range(16):
        prefixes = [path[:index] for index, char in enumerate(path) if char == '/'] + [path]
        prefix = next((item for item in prefixes if item in links), None)
        if prefix is None:
            return path
        target = posixpath.join(posixpath.dirname(prefix), links[prefix]) + path[len(prefix):]
        resolved = _normal(target)
        if resolved is None:
            return None
        path = resolved
    return None


def _index(snapshot: _Snapshot) -> None:
    total = 0
    for path, facts in snapshot.files.items():
        snapshot.uncertainties.update(facts.uncertainties)
        for reference in facts.references:
            total += 1
            if total > _MAX_REFERENCES:
                raise _InventoryLimit('reference_budget')
            consumer = RawInputConsumer(path, reference.line, reference.kind, reference.target)
            name = reference.name.replace('\\ ', ' ')
            substitutions = {'$(srctree)/': '', '${srctree}/': '', '$(src)/': posixpath.dirname(path) + '/',
                             '${src}/': posixpath.dirname(path) + '/', '$(obj)/': posixpath.dirname(path) + '/',
                             '${obj}/': posixpath.dirname(path) + '/'}
            for prefix, replacement in substitutions.items():
                if name.startswith(prefix):
                    name = replacement + name[len(prefix):]
                    break
            candidates = (name, posixpath.join(posixpath.dirname(path), name))
            for candidate in candidates:
                normalized = _normal(candidate)
                if normalized is not None and '$' not in normalized and '%' not in normalized:
                    resolved = _link_target(normalized, snapshot.links)
                    if resolved is not None:
                        snapshot.exact[resolved].append(consumer)
                    else:
                        snapshot.uncertainties.add('unresolved_input_alias')
            basename = posixpath.basename(name)
            if basename and not any(char in basename for char in '$%{}()'):
                snapshot.basenames[basename].append(consumer)


class RawInputIndex:
    """One bounded positive inventory per immutable Git revision, with deltas.

    The repository/object view and reader are borrowed for this index's lifetime.
    No empty lookup or successful scan establishes complete consumer closure.
    """

    def __init__(self, repo: GitRepo, read_file: Callable[[str, str], bytes]) -> None:
        self.repo, self.read_file = repo, read_file
        self._snapshots: OrderedDict[str, _Snapshot] = OrderedDict()
        self._file_cache: OrderedDict[tuple[bytes, bool], _CachedFacts] = OrderedDict()
        self._file_cache_bytes = 0
        self._file_cache_references = 0
        self._witness: _UncertaintyWitness | None = None
        self._veto_cache: OrderedDict[str, RawInputObservation] = OrderedDict()
        self._stats = RawInputIndexStats()

    def stats(self) -> RawInputIndexStats:
        return self._stats

    def veto_observation(self, revision: str, path: str) -> RawInputObservation:
        """Retain cheaply on one byte-verified file-local uncertainty.

        This mask-provider shortcut cannot establish absence or role closure.
        ``lookup`` continues to assemble the full recognized inventory.
        """

        if _normal(path) is None or _FULL_REVISION.fullmatch(revision) is None:
            return self.lookup(revision, path)
        cached = self._veto_cache.get(revision)
        if cached is not None:
            self._veto_cache.move_to_end(revision)
            self._stats = replace(self._stats, veto_cache_hits=self._stats.veto_cache_hits + 1)
            return cached
        witness = self._witness
        if witness is not None:
            self._stats = replace(self._stats, witness_reads=self._stats.witness_reads + 1)
            try:
                source = self.read_file(revision, witness.path)
                unchanged = sha256(source).digest() == witness.source_sha256
            except (OSError, ValueError, subprocess.SubprocessError):
                unchanged = False
            if unchanged:
                self._stats = replace(self._stats, witness_hits=self._stats.witness_hits + 1)
                return self._cache_veto(revision, witness.uncertainties)
            self._witness = None
        observed = self.lookup(revision, path)
        if self._witness is not None:
            self._cache_veto(revision, self._witness.uncertainties)
        return observed

    def _cache_veto(self, revision: str, uncertainties: frozenset[str]) -> RawInputObservation:
        assert uncertainties
        observed = RawInputObservation(uncertainties=uncertainties)
        self._veto_cache[revision] = observed
        self._veto_cache.move_to_end(revision)
        if len(self._veto_cache) > _MAX_VETO_REVISIONS:
            self._veto_cache.popitem(last=False)
        return observed

    def lookup(self, revision: str, path: str) -> RawInputObservation:
        normalized = _normal(path)
        if normalized is None or _FULL_REVISION.fullmatch(revision) is None:
            return RawInputObservation(uncertainties=frozenset({'unsupported_coordinate'}))
        snapshot = self._snapshots.get(revision)
        if snapshot is None:
            snapshot = self._build(revision)
            self._snapshots[revision] = snapshot
            if len(self._snapshots) > _MAX_SNAPSHOTS:
                self._snapshots.popitem(last=False)
        else:
            self._stats = replace(self._stats, revision_cache_hits=self._stats.revision_cache_hits + 1)
            self._snapshots.move_to_end(revision)
        consumers = set(snapshot.exact.get(normalized, ())) | set(snapshot.basenames.get(posixpath.basename(normalized), ()))
        return RawInputObservation(tuple(sorted(consumers, key=lambda item: (item.path, item.line, item.kind, item.target or ''))),
                                   frozenset(snapshot.uncertainties))

    def _markers(self, revision: str, paths: tuple[str, ...]) -> set[str]:
        assert paths
        self._stats = replace(self._stats, marker_queries=self._stats.marker_queries + 1)
        prefix = (revision + ':').encode()
        found: set[str] = set()
        args = ['grep', '--threads=1', '-l', '-z', '-a', '-E',
                '-e', r'\.(incbin|include)', '-e', r'\.(i|in|inc|incb|incbi|incl|inclu|includ)?\\[[:space:]]*$',
                revision, '--', *paths]
        with closing(iter_git_records(self.repo, args, b'\0', (0, 1))) as rows:
            for row in rows:
                if not row.startswith(prefix) or len(row) == len(prefix):
                    raise ValueError('invalid_marker_path')
                path = row[len(prefix):].decode('utf-8')
                if _make_path(path) or path.endswith(_SOURCE_SUFFIXES):
                    found.add(path)
                if len(found) > _MAX_FILES:
                    raise _InventoryLimit('file_budget')
        return found

    def _changed_markers(self, revision: str, paths: tuple[str, ...]) -> set[str]:
        found: set[str] = set()
        batch: list[str] = []
        size = 0
        for path in paths:
            path_size = len(path.encode('utf-8')) + 1
            if path_size > _MARKER_BATCH_BYTES:
                raise _InventoryLimit('path_budget')
            if batch and (len(batch) >= _MARKER_BATCH_PATHS or size + path_size > _MARKER_BATCH_BYTES):
                found.update(self._markers(revision, tuple(batch)))
                batch.clear()
                size = 0
            batch.append(path)
            size += path_size
        if batch:
            found.update(self._markers(revision, tuple(batch)))
        return found

    def _read(self, snapshot: _Snapshot, path: str, mode: bytes, budget: _ReadBudget) -> None:
        if mode == b'000000':
            snapshot.files.pop(path, None)
            snapshot.links.pop(path, None)
            return
        if mode not in {b'100644', b'100755', b'120000'}:
            snapshot.files[path] = _FileFacts(uncertainties=frozenset({'nonregular_consumer'}))
            return
        source = self.read_file(snapshot.revision, path)
        budget.files += 1
        budget.input_bytes += len(source)
        if budget.files > _MAX_FILES or budget.input_bytes > _MAX_BYTES or len(source) > _MAX_FILE_BYTES:
            raise _InventoryLimit('input_budget')
        self._stats = replace(self._stats, input_bytes=self._stats.input_bytes + len(source))
        if mode == b'120000':
            snapshot.links[path] = source.decode('utf-8')
            if _make_path(path) or path.endswith(_ASSEMBLY_SUFFIXES):
                snapshot.files[path] = _FileFacts(uncertainties=frozenset({'nonregular_consumer'}))
            return
        snapshot.links.pop(path, None)
        key = (sha256(source).digest(), _make_path(path))
        cached = self._file_cache.get(key)
        if cached is None:
            try:
                facts = _facts(source, key[1])
            except _InventoryLimit as error:
                # This file was fully read, but its parser budget cannot
                # establish its inputs. Preserve that veto while inventorying
                # other consumers; only aggregate inventory limits abort scans.
                facts = _FileFacts(uncertainties=frozenset({str(error)}))
            self._file_cache[key] = _CachedFacts(facts, len(source))
            self._file_cache_bytes += len(source)
            self._file_cache_references += len(facts.references)
            while (len(self._file_cache) > _MAX_FILE_CACHE or self._file_cache_bytes > _MAX_FILE_CACHE_BYTES
                   or self._file_cache_references > _MAX_REFERENCES):
                _, evicted = self._file_cache.popitem(last=False)
                self._file_cache_bytes -= evicted.input_bytes
                self._file_cache_references -= len(evicted.facts.references)
            self._stats = replace(self._stats, file_parses=self._stats.file_parses + 1)
        else:
            facts = cached.facts
            self._file_cache.move_to_end(key)
            self._stats = replace(self._stats, file_cache_hits=self._stats.file_cache_hits + 1)
        snapshot.files[path] = facts
        if facts.uncertainties and self._witness is None:
            self._witness = _UncertaintyWitness(path, key[0], facts.uncertainties)

    def _cold(self, snapshot: _Snapshot, budget: _ReadBudget) -> None:
        self._stats = replace(self._stats, repository_scans=self._stats.repository_scans + 1)
        batch: dict[str, bytes] = {}
        batch_bytes = 0
        def flush() -> None:
            for path in self._markers(snapshot.revision, tuple(batch)):
                self._read(snapshot, path, batch[path], budget)
            batch.clear()
        args = ['ls-tree', '-r', '-z', snapshot.revision]
        with closing(iter_git_records(self.repo, args, b'\0', (0,))) as rows:
            for count, row in enumerate(rows):
                if count >= _MAX_TREE_ROWS:
                    raise _InventoryLimit('tree_budget')
                metadata, separator, raw_path = row.partition(b'\t')
                fields = metadata.split()
                if (not separator or not raw_path or len(fields) != 3 or len(fields[2]) != len(snapshot.revision)
                        or re.fullmatch(rb'[0-9a-fA-F]+', fields[2]) is None):
                    raise ValueError('invalid_tree_entry')
                path = raw_path.decode('utf-8')
                if fields[0] == b'120000' or _make_path(path):
                    self._read(snapshot, path, fields[0], budget)
                elif path.endswith(_SOURCE_SUFFIXES):
                    size = len(raw_path) + 1
                    if size > _MARKER_BATCH_BYTES:
                        raise _InventoryLimit('path_budget')
                    if batch and (len(batch) >= _MARKER_BATCH_PATHS or batch_bytes + size > _MARKER_BATCH_BYTES):
                        flush()
                        batch_bytes = 0
                    batch[path] = fields[0]
                    batch_bytes += size
        if batch:
            flush()

    def _incremental(self, snapshot: _Snapshot, anchor: _Snapshot, budget: _ReadBudget) -> None:
        changes: dict[str, bytes] = {}
        args = ['diff-tree', '--no-commit-id', '-r', '--raw', '-z', '--no-abbrev', '--no-renames', anchor.revision, snapshot.revision]
        with closing(iter_git_records(self.repo, args, b'\0', (0,))) as rows:
            for header in rows:
                fields = header.split()
                raw_path = next(rows, b'')
                if (len(fields) != 5 or not header.startswith(b':') or not raw_path
                        or fields[4] not in {b'A', b'D', b'M', b'T'}):
                    raise ValueError('invalid_tree_delta')
                changes[raw_path.decode('utf-8')] = fields[1]
                if len(changes) > _MAX_CHANGED_PATHS:
                    raise _InventoryLimit('changed_path_budget')
        snapshot.files = anchor.files.copy()
        snapshot.links = anchor.links.copy()
        live = tuple(path for path, mode in changes.items() if mode != b'000000')
        markers = self._changed_markers(snapshot.revision, live) if live else set()
        for path, mode in changes.items():
            snapshot.files.pop(path, None)
            snapshot.links.pop(path, None)
            if path in markers or _make_path(path) or mode == b'120000':
                self._read(snapshot, path, mode, budget)
        self._stats = replace(self._stats, incremental_updates=self._stats.incremental_updates + 1)

    def _build(self, revision: str) -> _Snapshot:
        begun = perf_counter()
        snapshot = _Snapshot(revision)
        budget = _ReadBudget()
        anchor = next((item for item in reversed(self._snapshots.values()) if item.inventory_complete), None)
        try:
            if anchor is None:
                self._cold(snapshot, budget)
            else:
                self._incremental(snapshot, anchor, budget)
            _index(snapshot)
            snapshot.inventory_complete = True
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError) as error:
            snapshot.uncertainties.add(str(error) if isinstance(error, _InventoryLimit) else 'inventory_failure')
        self._stats = replace(self._stats, scan_seconds=self._stats.scan_seconds + perf_counter() - begun)
        return snapshot
