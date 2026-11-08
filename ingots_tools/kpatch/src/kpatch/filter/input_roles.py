"""Positive raw-input consumers, never a certificate of input-role closure.

Only literal assembly inputs and explicit Make generator prerequisites are
recognized. Empty observations say nothing about other consumers or languages.
Operational/budget uncertainty must retain the proposed source mask.
"""

from bisect import bisect_right
from collections import OrderedDict, defaultdict
from collections.abc import Callable, Generator, Iterable
from contextlib import closing
from dataclasses import dataclass, field, replace
from hashlib import sha256
import posixpath
import re
import subprocess
from time import perf_counter

from ..git import GitRepo
from .config_filter import KbuildMakefile
from .git_output import _iter_git_chunks, iter_git_records
from .input_role_models import (InputInventoryState, RawInputConsumer, RawInputFailure, RawInputFailureKind,
                                RawInputKind, RawInputObservation, RawInputUnknown, RawInputUnknownKind)


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
    delta_rows: int = 0
    candidate_paths: int = 0
    consumer_rebuilds: int = 0


@dataclass(frozen=True, slots=True)
class _Reference:
    name: str
    line: int
    kind: RawInputKind
    target: str | None = None


@dataclass(frozen=True, slots=True)
class _Unknown:
    line: int | None
    kind: RawInputUnknownKind
    operand: str | None


@dataclass(frozen=True, slots=True)
class _FileFacts:
    references: tuple[_Reference, ...] = ()
    unknowns: tuple[_Unknown, ...] = ()
    failures: tuple[RawInputFailure, ...] = ()
    source_sha256: str = ''
    source_path: str | None = None


@dataclass(slots=True)
class _Snapshot:
    revision: str
    files: dict[str, _FileFacts] = field(default_factory=dict)
    links: dict[str, str] = field(default_factory=dict)
    aliases: set[str] = field(default_factory=set)
    unknowns: list[RawInputUnknown] = field(default_factory=list)
    failures: list[RawInputFailure] = field(default_factory=list)
    exact: dict[str, list[RawInputConsumer]] = field(default_factory=lambda: defaultdict(list))
    basenames: dict[str, list[RawInputConsumer]] = field(default_factory=lambda: defaultdict(list))
    inventory_complete: bool = False


class _InventoryLimit(ValueError):
    def __init__(self, kind: RawInputFailureKind, path: str | None = None) -> None:
        self.failure = RawInputFailure(kind, path)
        super().__init__(kind.value)


class _InventoryAbort(Exception):
    def __init__(self, failure: RawInputFailure) -> None:
        self.failure = failure
        super().__init__(failure.kind.value)


@dataclass(slots=True)
class _ReadBudget:
    files: int = 0
    input_bytes: int = 0


@dataclass(slots=True)
class _MarkerBatch:
    modes: dict[str, bytes] = field(default_factory=dict)
    path_bytes: int = 0


@dataclass(frozen=True, slots=True)
class _DeltaEntry:
    path: str
    mode: bytes
    path_bytes: int


@dataclass(frozen=True, slots=True)
class _CachedFacts:
    facts: _FileFacts
    input_bytes: int


@dataclass(frozen=True, slots=True)
class _UncertaintyWitness:
    path: str
    source_sha256: bytes
    unknowns: tuple[RawInputUnknown, ...]


_MAX_FILES = 8192
_MAX_BYTES = 16 * 1024 * 1024
_MAX_FILE_BYTES = 1024 * 1024
_MAX_REFERENCES = 32768
_MAX_DELTA_ROWS = 500000
_MAX_DELTA_PATH_BYTES = 16 * 1024 * 1024
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


def _delta_entry(header: bytes, raw_path: bytes, oid_width: int) -> _DeltaEntry:
    fields = header.split(b' ')
    if len(fields) != 5 or not fields[0].startswith(b':') or not raw_path:
        raise ValueError('invalid_tree_delta')
    old_mode, new_mode = fields[0][1:], fields[1]
    modes = {b'000000', b'100644', b'100755', b'120000', b'160000'}
    if old_mode not in modes or new_mode not in modes or fields[4] not in {b'A', b'D', b'M', b'T'}:
        raise ValueError('invalid_tree_delta_mode_or_status')
    for mode, oid in ((old_mode, fields[2]), (new_mode, fields[3])):
        if (len(oid) != oid_width or re.fullmatch(rb'[0-9a-fA-F]+', oid) is None
                or (mode == b'000000') != (oid == b'0' * oid_width)):
            raise ValueError('invalid_tree_delta_object')
    if ((fields[4] == b'A') != (old_mode == b'000000')
            or (fields[4] == b'D') != (new_mode == b'000000')):
        raise ValueError('invalid_tree_delta_status')
    path = raw_path.decode('utf-8')
    if _normal(path) != path:
        raise ValueError('invalid_tree_delta_path')
    return _DeltaEntry(path, new_mode, len(raw_path) + 1)


def _iter_delta_entries(chunks: Iterable[bytes], oid_width: int) -> Generator[_DeltaEntry, None, None]:
    """Require both NUL fields, including the final path terminator."""

    pending = bytearray()
    header: bytes | None = None
    rows = path_bytes = 0
    for chunk in chunks:
        offset = 0
        while offset < len(chunk):
            end = chunk.find(b'\0', offset)
            field_end = len(chunk) if end < 0 else end
            pending.extend(chunk[offset:field_end])
            limit = 2 * oid_width + 32 if header is None else _MAX_DELTA_PATH_BYTES - path_bytes - 1
            if len(pending) > limit:
                if header is None:
                    raise ValueError('oversize_tree_delta_header')
                raise _InventoryLimit(RawInputFailureKind.DELTA_PATH_BUDGET)
            if end < 0:
                break
            offset = end + 1
            if header is None:
                header = bytes(pending)
            else:
                entry = _delta_entry(header, bytes(pending), oid_width)
                rows += 1
                path_bytes += entry.path_bytes
                if rows > _MAX_DELTA_ROWS:
                    raise _InventoryLimit(RawInputFailureKind.DELTA_ROW_BUDGET)
                yield entry
                header = None
            pending.clear()
    if header is not None or pending:
        raise ValueError('unterminated_tree_delta')


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


def _expand_make(word: str, variables: dict[str, set[str]], seen: frozenset[str] = frozenset()) -> tuple[tuple[str, ...], RawInputUnknownKind | None]:
    for match in _MAKE_VARIABLE.finditer(word):
        name = match[1] or match[2]
        if name in {'src', 'obj', 'srctree'}:
            continue
        values = variables.get(name)
        if values is None or name in seen:
            return (word,), RawInputUnknownKind.MAKE_OPERAND
        if len(seen) >= 8:
            return (word,), RawInputUnknownKind.MAKE_EXPANSION
        output: list[str] = []
        unknown: RawInputUnknownKind | None = None
        for value in sorted(values):
            expanded, uncertain = _expand_make(word[:match.start()] + value + word[match.end():], variables, seen | {name})
            output.extend(expanded)
            unknown = uncertain or unknown
            if len(output) > 128:
                return tuple(output[:128]), RawInputUnknownKind.MAKE_EXPANSION
        return tuple(output), unknown
    remaining = _MAKE_VARIABLE.sub('', word)
    return (word,), RawInputUnknownKind.MAKE_OPERAND if '$' in remaining else None


def _literal_make_inputs(word: str, variables: dict[str, set[str]]) -> set[str]:
    """Harvest independent literal operands even when expansion is bounded."""
    pending = [word]
    seen: set[str] = set()
    found: set[str] = set()
    while pending:
        value = pending.pop()
        if value.replace('\\ ', ' ').endswith(_SOURCE_SUFFIXES) and not any(char in value for char in '*?[]%'):
            found.add(value)
        for match in _MAKE_VARIABLE.finditer(value):
            name = match[1] or match[2]
            if name not in seen and name not in {'src', 'obj', 'srctree'}:
                seen.add(name)
                pending.extend(variables.get(name, ()))
        if len(found) + len(pending) > _MAX_REFERENCES:
            raise _InventoryLimit(RawInputFailureKind.REFERENCE_BUDGET)
    return found


@dataclass(frozen=True, slots=True)
class _MakeRule:
    line: int
    targets: tuple[str, ...]
    inputs: tuple[str, ...]
    unknowns: tuple[_Unknown, ...]


def _record_make_rule(rule: _MakeRule, recipe: str, found: list[_Reference], unknowns: list[_Unknown]) -> None:
    if _COMPILE.search(recipe) and not _RAW_TOOL.search(recipe):
        return
    if rule.unknowns and (rule.inputs or _RAW_TOOL.search(recipe) or any(target.endswith(_GENERATED_SUFFIXES) for target in rule.targets)):
        unknowns.extend(rule.unknowns)
    if len(found) + len(rule.targets) * len(rule.inputs) + len(unknowns) > _MAX_REFERENCES:
        raise _InventoryLimit(RawInputFailureKind.REFERENCE_BUDGET)
    found.extend(_Reference(name, rule.line, RawInputKind.MAKE_GENERATOR, target)
                 for target in rule.targets for name in rule.inputs)


def _make_facts(source: str) -> _FileFacts:
    logical_lines = _logical_make(source)
    variables: dict[str, set[str]] = defaultdict(set)
    for _, logical in logical_lines:
        assignment = re.match(r'\s*(?:override\s+|export\s+)?([A-Za-z_][A-Za-z_0-9]*)\s*([:+?!]?=)\s*(.*)', logical)
        if assignment is not None:
            values = {'$unresolved_shell_input'} if assignment[2] == '!=' else set(_MAKE_WORD.findall(KbuildMakefile._strip_comment(assignment[3])))
            variables[assignment[1]].update(values)
    found: list[_Reference] = []
    unknowns: list[_Unknown] = []
    pending: _MakeRule | None = None
    for line_number, logical in logical_lines:
        if logical.startswith('\t'):
            if pending is not None:
                _record_make_rule(pending, logical, found, unknowns)
            continue
        pending = None
        line = KbuildMakefile._strip_comment(logical).strip()
        if not line or ':' not in line or re.match(r'[^:=]*[:+?!]?=', line):
            continue
        targets, _, prerequisites = line.partition(':')
        prerequisites, inline, recipe = prerequisites.partition(';')
        output = tuple(_MAKE_WORD.findall(targets))
        inputs: set[str] = set()
        notes: list[_Unknown] = []
        for word in _MAKE_WORD.findall(prerequisites):
            inputs.update(_literal_make_inputs(word, variables))
            expanded, uncertain = _expand_make(word, variables)
            if any(char in name for name in expanded for char in '*?[]%'):
                uncertain = uncertain or RawInputUnknownKind.MAKE_OPERAND
            inputs.update(name for name in expanded if name.replace('\\ ', ' ').endswith(_SOURCE_SUFFIXES)
                          and not any(char in name for char in '*?[]%'))
            if uncertain is not None:
                notes.append(_Unknown(line_number, uncertain, word))
        if output and (inputs or notes):
            pending = _MakeRule(line_number, output, tuple(sorted(inputs)), tuple(notes))
            if inline:
                _record_make_rule(pending, recipe, found, unknowns)
    return _FileFacts(tuple(found), tuple(unknowns))


def _facts(source: bytes, make: bool) -> _FileFacts:
    text = source.decode('utf-8')
    make_facts = _make_facts(text) if make else _FileFacts()
    references = list(make_facts.references)
    unknowns = list(make_facts.unknowns)
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
        if len(references) + len(unknowns) >= _MAX_REFERENCES:
            raise _InventoryLimit(RawInputFailureKind.REFERENCE_BUDGET)
        line = normalized.count(b'\n', 0, match.start()) + bisect_right(positions, match.start()) + 1
        kind = RawInputKind.ASSEMBLER_INCBIN if match[1] == b'incbin' else RawInputKind.ASSEMBLER_INCLUDE
        operand = match[2].decode('utf-8')
        if b'\\' in match[2]:
            unknowns.append(_Unknown(line, RawInputUnknownKind.ASM_OPERAND, operand))
        references.append(_Reference(operand, line, kind))
    for marker in _ASM_MARKER.finditer(normalized):
        if (_ASM_LITERAL.match(normalized, marker.start()) is None
                and re.search(rb'(?:^|\n|\\n|"|;|:)[ \t]*$', normalized[:marker.start()])):
            line = normalized.count(b'\n', 0, marker.start()) + bisect_right(positions, marker.start()) + 1
            operand = normalized[marker.end():].split(b'\n', 1)[0][:4096].decode('utf-8').strip()
            unknowns.append(_Unknown(line, RawInputUnknownKind.ASM_OPERAND, operand or None))
            if len(references) + len(unknowns) > _MAX_REFERENCES:
                raise _InventoryLimit(RawInputFailureKind.REFERENCE_BUDGET)
    return _FileFacts(tuple(references), tuple(unknowns))


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
        total += len(facts.unknowns)
        if total > _MAX_REFERENCES:
            raise _InventoryLimit(RawInputFailureKind.REFERENCE_BUDGET)
        snapshot.unknowns.extend(RawInputUnknown(facts.source_path or path, note.line, note.kind, note.operand, facts.source_sha256)
                                 for note in facts.unknowns)
        snapshot.failures.extend(replace(failure, consumer_path=path) for failure in facts.failures)
        for reference in facts.references:
            total += 1
            if total > _MAX_REFERENCES:
                raise _InventoryLimit(RawInputFailureKind.REFERENCE_BUDGET)
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
                        snapshot.failures.append(RawInputFailure(RawInputFailureKind.INPUT_ALIAS, path, reference.line, candidate))
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
                return self._cache_veto(revision, witness.unknowns)
            self._witness = None
        observed = self.lookup(revision, path)
        if self._witness is not None:
            self._cache_veto(revision, self._witness.unknowns)
        return observed

    def _cache_veto(self, revision: str, unknowns: tuple[RawInputUnknown, ...]) -> RawInputObservation:
        assert unknowns
        observed = RawInputObservation(InputInventoryState.RETENTION_WITNESS, unknowns=unknowns)
        self._veto_cache[revision] = observed
        self._veto_cache.move_to_end(revision)
        if len(self._veto_cache) > _MAX_VETO_REVISIONS:
            self._veto_cache.popitem(last=False)
        return observed

    def lookup(self, revision: str, path: str) -> RawInputObservation:
        normalized = _normal(path)
        if normalized is None or _FULL_REVISION.fullmatch(revision) is None:
            return RawInputObservation(InputInventoryState.INCOMPLETE,
                                       failures=(RawInputFailure(RawInputFailureKind.UNSUPPORTED_COORDINATE),))
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
        return RawInputObservation(InputInventoryState.FULL if snapshot.inventory_complete else InputInventoryState.INCOMPLETE,
                                   tuple(sorted(consumers, key=lambda item: (item.path, item.line, item.kind, item.target or ''))),
                                   tuple(dict.fromkeys(snapshot.unknowns)), tuple(dict.fromkeys(snapshot.failures)))

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
                    raise _InventoryLimit(RawInputFailureKind.FILE_BUDGET)
        return found

    def _account(self, path: str, source: bytes, budget: _ReadBudget) -> None:
        budget.files += 1
        budget.input_bytes += len(source)
        if budget.files > _MAX_FILES:
            raise _InventoryLimit(RawInputFailureKind.FILE_BUDGET, path)
        if budget.input_bytes > _MAX_BYTES or len(source) > _MAX_FILE_BYTES:
            raise _InventoryLimit(RawInputFailureKind.INPUT_BUDGET, path)
        self._stats = replace(self._stats, input_bytes=self._stats.input_bytes + len(source))

    def _store(self, snapshot: _Snapshot, path: str, source: bytes, budget: _ReadBudget, *, alias: bool = False,
               source_path: str | None = None) -> None:
        self._account(path, source, budget)
        key = (sha256(source).digest(), _make_path(path))
        cached = self._file_cache.get(key)
        if cached is None:
            try:
                facts = _facts(source, key[1])
            except _InventoryLimit as error:
                facts = _FileFacts(failures=(error.failure,))
            except UnicodeError as error:
                facts = _FileFacts(failures=(RawInputFailure(RawInputFailureKind.CONSUMER_PARSE, detail=str(error)),))
            facts = replace(facts, source_sha256=key[0].hex())
            self._file_cache[key] = _CachedFacts(facts, len(source))
            self._file_cache_bytes += len(source)
            self._file_cache_references += len(facts.references) + len(facts.unknowns)
            while (len(self._file_cache) > _MAX_FILE_CACHE or self._file_cache_bytes > _MAX_FILE_CACHE_BYTES
                   or self._file_cache_references > _MAX_REFERENCES):
                _, evicted = self._file_cache.popitem(last=False)
                self._file_cache_bytes -= evicted.input_bytes
                self._file_cache_references -= len(evicted.facts.references) + len(evicted.facts.unknowns)
            self._stats = replace(self._stats, file_parses=self._stats.file_parses + 1)
        else:
            facts = cached.facts
            self._file_cache.move_to_end(key)
            self._stats = replace(self._stats, file_cache_hits=self._stats.file_cache_hits + 1)
        snapshot.files[path] = replace(facts, source_path=source_path or path)
        if facts.unknowns and self._witness is None and not alias:
            unknowns = tuple(RawInputUnknown(path, note.line, note.kind, note.operand, facts.source_sha256) for note in facts.unknowns)
            self._witness = _UncertaintyWitness(path, key[0], unknowns)

    def _read(self, snapshot: _Snapshot, path: str, mode: bytes, budget: _ReadBudget) -> None:
        self._stats = replace(self._stats, consumer_rebuilds=self._stats.consumer_rebuilds + 1)
        snapshot.aliases.discard(path)
        if mode == b'000000':
            snapshot.files.pop(path, None)
            snapshot.links.pop(path, None)
            return
        if mode not in {b'100644', b'100755', b'120000'}:
            snapshot.files[path] = _FileFacts(failures=(RawInputFailure(RawInputFailureKind.NONREGULAR_CONSUMER),))
            return
        try:
            source = self.read_file(snapshot.revision, path)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            raise _InventoryAbort(RawInputFailure(RawInputFailureKind.CONSUMER_READ, path, detail=str(error))) from error
        if mode == b'120000':
            self._account(path, source, budget)
            try:
                snapshot.links[path] = source.decode('utf-8')
            except UnicodeError as error:
                snapshot.files[path] = _FileFacts(failures=(RawInputFailure(RawInputFailureKind.CONSUMER_PARSE, detail=str(error)),))
                return
            if _make_path(path) or path.endswith(_ASSEMBLY_SUFFIXES):
                snapshot.aliases.add(path)
            return
        snapshot.links.pop(path, None)
        self._store(snapshot, path, source, budget)

    def _refresh_aliases(self, snapshot: _Snapshot, budget: _ReadBudget) -> None:
        for path in sorted(snapshot.aliases):
            target = _link_target(path, snapshot.links)
            snapshot.files.pop(path, None)
            if target is None:
                snapshot.files[path] = _FileFacts(failures=(RawInputFailure(RawInputFailureKind.INPUT_ALIAS),))
                continue
            try:
                mode = self.repo.read_file_mode(snapshot.revision, target)
                if mode not in {'100644', '100755'}:
                    kind = RawInputFailureKind.INPUT_ALIAS if mode is None else RawInputFailureKind.NONREGULAR_CONSUMER
                    snapshot.files[path] = _FileFacts(failures=(RawInputFailure(kind, detail=target),))
                    continue
                source = self.read_file(snapshot.revision, target)
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                snapshot.files[path] = _FileFacts(failures=(RawInputFailure(RawInputFailureKind.CONSUMER_READ, detail=str(error)),))
                continue
            self._store(snapshot, path, source, budget, alias=True, source_path=target)

    def _flush_markers(self, snapshot: _Snapshot, batch: _MarkerBatch, budget: _ReadBudget) -> None:
        if not batch.modes:
            return
        for path in self._markers(snapshot.revision, tuple(batch.modes)):
            self._read(snapshot, path, batch.modes[path], budget)
        batch.modes.clear()
        batch.path_bytes = 0

    def _inventory_path(self, snapshot: _Snapshot, path: str, mode: bytes, batch: _MarkerBatch, budget: _ReadBudget) -> None:
        # Cold and delta inventories use precisely the same recognized scope.
        if mode == b'120000' or _make_path(path):
            self._read(snapshot, path, mode, budget)
        elif path.endswith(_SOURCE_SUFFIXES):
            size = len(path.encode('utf-8')) + 1
            if size > _MARKER_BATCH_BYTES:
                raise _InventoryLimit(RawInputFailureKind.PATH_BUDGET)
            if batch.modes and (len(batch.modes) >= _MARKER_BATCH_PATHS or batch.path_bytes + size > _MARKER_BATCH_BYTES):
                self._flush_markers(snapshot, batch, budget)
            batch.modes[path] = mode
            batch.path_bytes += size
            self._stats = replace(self._stats, candidate_paths=self._stats.candidate_paths + 1)

    def _cold(self, snapshot: _Snapshot, budget: _ReadBudget) -> None:
        self._stats = replace(self._stats, repository_scans=self._stats.repository_scans + 1)
        batch = _MarkerBatch()
        args = ['ls-tree', '-r', '-z', snapshot.revision]
        with closing(iter_git_records(self.repo, args, b'\0', (0,))) as rows:
            for count, row in enumerate(rows):
                if count >= _MAX_TREE_ROWS:
                    raise _InventoryLimit(RawInputFailureKind.TREE_BUDGET)
                metadata, separator, raw_path = row.partition(b'\t')
                fields = metadata.split()
                if (not separator or not raw_path or len(fields) != 3 or len(fields[2]) != len(snapshot.revision)
                        or re.fullmatch(rb'[0-9a-fA-F]+', fields[2]) is None):
                    raise ValueError('invalid_tree_entry')
                path = raw_path.decode('utf-8')
                self._inventory_path(snapshot, path, fields[0], batch, budget)
        self._flush_markers(snapshot, batch, budget)

    def _incremental(self, snapshot: _Snapshot, anchor: _Snapshot, budget: _ReadBudget) -> None:
        snapshot.files = anchor.files.copy()
        snapshot.links = anchor.links.copy()
        snapshot.aliases = anchor.aliases.copy()
        batch = _MarkerBatch()
        args = ['diff-tree', '--no-commit-id', '-r', '--raw', '-z', '--no-abbrev', '--no-renames', anchor.revision, snapshot.revision]
        with closing(_iter_git_chunks(self.repo, args, (0,))) as chunks:
            for entry in _iter_delta_entries(chunks, len(snapshot.revision)):
                self._stats = replace(self._stats, delta_rows=self._stats.delta_rows + 1)
                snapshot.files.pop(entry.path, None)
                snapshot.links.pop(entry.path, None)
                snapshot.aliases.discard(entry.path)
                if entry.mode != b'000000':
                    self._inventory_path(snapshot, entry.path, entry.mode, batch, budget)
        self._flush_markers(snapshot, batch, budget)
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
            self._refresh_aliases(snapshot, budget)
            _index(snapshot)
            snapshot.inventory_complete = True
        except (_InventoryLimit, _InventoryAbort) as error:
            snapshot.failures.append(error.failure)
        except subprocess.SubprocessError as error:
            snapshot.failures.append(RawInputFailure(RawInputFailureKind.NATIVE_SCAN, detail=str(error)))
        except OSError as error:
            snapshot.failures.append(RawInputFailure(RawInputFailureKind.CONSUMER_READ, detail=str(error)))
        except (ValueError, UnicodeError) as error:
            snapshot.failures.append(RawInputFailure(RawInputFailureKind.PROTOCOL, detail=str(error)))
        self._stats = replace(self._stats, scan_seconds=self._stats.scan_seconds + perf_counter() - begun)
        return snapshot
