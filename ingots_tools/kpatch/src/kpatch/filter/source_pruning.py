"""Tree-sitter renames, helper reorders, diagnostic wording and unused code."""

from collections.abc import Callable, Generator, Iterable
from collections import OrderedDict
from contextlib import closing
from dataclasses import dataclass, replace
from itertools import zip_longest
import re
import subprocess
from typing import ClassVar

from .base import FilterContext, FilteredCommit, StreamingCommitFilter, repository_file_reader
from .config_filter import KbuildMakefileCache, KbuildState, KernelConfig
from .diagnostic_strings import normalize_diagnostic_strings
from .ifdef_filter import get_active_lines
from .masking import CodeMask, EditMask, FileIdentity, LineRange, MaskReason, SourceSide, SourceVersions, line_macro_locations, line_ranges
from .reference_index import ReferenceIndex, ReferenceIndexStats, ReferenceSite, spelling_guards
from .reordering import ReorderMacroGuard, ReorderProof, hunk_reorder_candidate, independent_reorder
from .syntax import (
    MAX_SOURCE_BYTES, Definition, argument_lists, comments, declaration_names, declarator_name, definitions, has_opaque_tokens,
    node_text, outside_definitions, parse_source, recover_static_functions, sensitive_nodes, syntax_tokens,
)
from .whitespace.c_lexer import CTokenKind, replace_c_comments, tokenize_c_source
from .whitespace.whitespace_filter import WhitespaceFilter
from ..diff import DiffFile, DiffFileType


_NAME_KINDS = frozenset({"identifier", "type_identifier", "field_identifier"})
_NONSTANDARD_LINEBREAK = re.compile(r"\r(?!\n)|[\v\f\x1c-\x1e\x85\u2028\u2029]")


@dataclass(frozen=True, slots=True)
class PruningDecision:
    commit_id: str
    paths: tuple[str, ...]
    rule: str
    symbols: tuple[str, ...]
    edit_masks: tuple[EditMask, ...] = ()
    code_masks: tuple[CodeMask, ...] = ()


@dataclass(slots=True)
class SourcePruningStats:
    processed_commits: int = 0
    eliminated_commits: int = 0
    pruned_files: int = 0


@dataclass(frozen=True, slots=True)
class SourcePair:
    file: DiffFile
    old: bytes
    new: bytes


@dataclass(frozen=True, slots=True)
class SourceAnalysis:
    pair: SourcePair
    code_masks: tuple[CodeMask, ...]


@dataclass(frozen=True, slots=True)
class SourceComparison:
    mapping: dict[bytes, bytes]
    diagnostics: bool
    reorder: ReorderProof | None = None


def _eligible(file: DiffFile) -> bool:
    return (
        file.file.endswith((".c", ".h")) and file.change_type is DiffFileType.DEFAULT
        and not file.binary and not file.mode_changed and bool(file.chunks)
    )


class _SourceFilter(StreamingCommitFilter):
    requires_reference_index: ClassVar[bool] = True
    def __init__(
        self,
        config: KernelConfig | None = None,
        on_pruned: Callable[[PruningDecision], None] | None = None,
    ) -> None:
        self.config = config
        self.on_pruned = on_pruned
        self._stats = SourcePruningStats()
        self._read_file: Callable[[str, str], bytes] | None = None
        self._index: ReferenceIndex | None = None
        self.index_stats: ReferenceIndexStats | None = None
        self._makefiles = KbuildMakefileCache(config) if config is not None else None
        self._site_cache: OrderedDict[tuple[str, str], bool] = OrderedDict()
        self._state: KbuildState | None = None
        self._reorder_macros: ReorderMacroGuard | None = None

    def stats(self) -> SourcePruningStats:
        return replace(self._stats)

    def iter_filter_mutable_commits(
        self, commits: Iterable[FilteredCommit], context: FilterContext,
        show_progress: bool = True, *, total: int | None = None,
    ) -> Generator[FilteredCommit, None, None]:
        with repository_file_reader(context) as reader:
            self._read_file = reader.read_file
            self._index = context.reference_index or ReferenceIndex(context.repo, reader.read_file)
            try:
                with closing(self._planned_input(commits)) as planned:
                    yield from super().iter_filter_mutable_commits(
                        planned, context, show_progress, total=total,
                    )
            finally:
                self.index_stats = self._index.stats()
                if context.reference_index is None:
                    self._index.close()
                self._read_file = None
                self._index = None
                self._site_cache.clear()
                self._state = None
                self._reorder_macros = None

    def _planned_input(self, commits: Iterable[FilteredCommit]) -> Generator[FilteredCommit, None, None]:
        assert self._index is not None
        pending: list[FilteredCommit] = []
        size = 0
        for commit in commits:
            if self._index.source_includes is not None:
                yield commit
                continue
            pending.append(commit)
            size += sum(len(line) for file in commit.diff.files for chunk in file.chunks for line in chunk.lines)
            if len(pending) >= 32 or size >= 2 * 1024 * 1024:
                self._index.plan_diffs(commit.diff for commit in pending)
                yield from pending
                pending.clear()
                size = 0
        if pending:
            self._index.plan_diffs(commit.diff for commit in pending)
            yield from pending

    def _pair(self, commit: FilteredCommit, file: DiffFile, context: FilterContext) -> SourcePair | None:
        if not _eligible(file) or commit.original.parent is None:
            return None
        read = self._read_file or context.repo.read_file
        try:
            old = read(commit.original.parent.commit_id, file.old_file or file.file)
            new = read(commit.original.commit_id, file.file)
            if max(len(old), len(new)) > MAX_SOURCE_BYTES or b"\0" in old + new:
                return None
            if any(_NONSTANDARD_LINEBREAK.search(source.decode("utf-8", errors="strict")) for source in (old, new)):
                return None
        except (OSError, UnicodeError, subprocess.CalledProcessError):
            return None
        return SourcePair(file, old, new)

    def _record(self, commit: FilteredCommit, files: tuple[str, ...], rule: str, names: tuple[str, ...]) -> None:
        self._stats.pruned_files += len(files)
        if self.on_pruned is not None:
            self.on_pruned(PruningDecision(commit.original.commit_id, files, rule, names, commit.edit_masks, commit.code_masks))

    def _active_site(self, revision: str, site: ReferenceSite, context: FilterContext) -> bool:
        if self.config is None or ".lds" in site.path or not site.path.endswith((".c", ".S", ".s")):
            return True
        key = (revision, site.path)
        if key in self._site_cache:
            self._site_cache.move_to_end(key)
            return self._site_cache[key]
        if self._state is None or self._state.base_commit != revision:
            self._state = KbuildState(
                context.repo, self.config, revision, read_file=self._read_file,
                makefile_cache=self._makefiles,
            )
        result = self._state.get(site.path) is not None
        self._site_cache[key] = result
        if len(self._site_cache) > 1024:
            self._site_cache.popitem(last=False)
        # Unknown/local preprocessor state in headers is never used to reject a
        # reference. Configuration gating here is only for translation units.
        return result

    def _effective_source(self, source: bytes) -> bytes:
        source = _without_comments(source)
        if self.config is None:
            return source
        text = re.sub(r"[\r\v\f\x1c-\x1e\x85\u2028\u2029]", " ", source.decode("utf-8", errors="strict"))
        active = get_active_lines(text, self.config) | get_active_lines(text, self.config, is_module=True)
        return "\n".join(line if number in active else "" for number, line in enumerate(text.split("\n"), 1)).encode()

    def _reference_is_live(self, revision: str, name: str, site: ReferenceSite, context: FilterContext, commit: FilteredCommit) -> bool:
        if not self._active_site(revision, site, context):
            return False
        read = self._read_file or context.repo.read_file
        side = SourceSide.NEW if revision == commit.original.commit_id else SourceSide.OLD
        source = commit.code_source(site.path, side, read(revision, site.path))
        lines = self._effective_source(source).split(b"\n")
        return site.line <= len(lines) and re.search(rb"\b" + re.escape(name.encode()) + rb"\b", lines[site.line - 1]) is not None

    def _probe_consumers(self, revision: str, roots: frozenset[str], names: frozenset[str], context: FilterContext, commit: FilteredCommit) -> bool:
        """Positive-only shortcut; an incomplete include sample proves no absence."""

        if self._index is None or self._index.source_includes is None:
            return False
        graph = self._index.source_includes
        read = self._read_file or context.repo.read_file
        seen = set(roots)
        pending = list(roots)
        inspected = 0
        changed = {file.file for file in commit.original_diff.files}
        families = tuple(path.split("/", 2)[1] + "/" if path.startswith("include/") else path.split("/", 1)[0] + "/" for path in roots)
        while pending and inspected < 16 and len(seen) < 256:
            consumers = sorted(graph.includers(pending.pop()), key=lambda path: (path not in changed, not path.endswith(".h"), not path.startswith(families), path))
            for source in consumers:
                if inspected >= 16 or len(seen) >= 256:
                    break
                if source in seen:
                    continue
                seen.add(source)
                if source.endswith(".h"):
                    pending.append(source)
                elif not source.endswith((".c", ".S")):
                    continue
                inspected += 1
                try:
                    contents = read(revision, source)
                except (FileNotFoundError, subprocess.CalledProcessError):
                    continue
                for name in names:
                    for match in re.finditer(rb"\b" + re.escape(name.encode()) + rb"\b", contents):
                        site = ReferenceSite(source, contents.count(b"\n", 0, match.start()) + 1)
                        if self._reference_is_live(revision, name, site, context, commit):
                            return True
        return False


def _hunk_rename_candidate(file: DiffFile, *, allow_strings: bool = False) -> bool:
    old: list[str] = []
    new: list[str] = []
    for chunk in file.chunks:
        old.extend(line[1:] for line in chunk.lines if line.startswith("-"))
        new.extend(line[1:] for line in chunk.lines if line.startswith("+"))
    a = tokenize_c_source("\n".join(old))
    b = tokenize_c_source("\n".join(new))
    if a is None or b is None or len(a) != len(b):
        return False
    return all(
        x == y or (x.kind is y.kind and (x.kind is CTokenKind.IDENTIFIER
                                        or allow_strings and x.kind is CTokenKind.STRING_LITERAL))
        for x, y in zip(a, b)
    )


_OPAQUE_NAMES = re.compile(rb"##|\b(?:__func__|__FUNCTION__|__PRETTY_FUNCTION__|__builtin_FUNCTION|asm|__asm__)\b|^\s*#\s*define[^\n]*#[^#]", re.MULTILINE)


class RenameFilter(_SourceFilter):
    """Consistent renames, independent helper reorders and diagnostic wording."""

    name: ClassVar[str] = "Filtering equivalent renames, reorders and diagnostic wording"

    def _compare(self, pairs: list[SourcePair], *, masked_reorder: bool) -> SourceComparison | None:
        if masked_reorder or all(hunk_reorder_candidate(pair.file) for pair in pairs):
            proofs = [independent_reorder(pair.old, pair.new) for pair in pairs]
            if all(proof is not None for proof in proofs):
                identifiers = frozenset(name for proof in proofs if proof is not None for name in proof.identifiers)
                protected = frozenset(name for proof in proofs if proof is not None for name in proof.identifiers - proof.numeric_names)
                reorder = ReorderProof(tuple(sorted({name for proof in proofs if proof is not None for name in proof.symbols})),
                                       identifiers, identifiers - protected)
                return SourceComparison({}, False, reorder)
        if all(_hunk_rename_candidate(pair.file) for pair in pairs):
            mapping = self._mapping(pairs)
            return SourceComparison(mapping, False) if mapping is not None else None
        normalized: list[SourcePair] = []
        diagnostics = False
        for pair in pairs:
            old = normalize_diagnostic_strings(pair.old)
            new = normalize_diagnostic_strings(pair.new)
            diagnostics |= old.literals != new.literals
            normalized.append(SourcePair(pair.file, old.contents, new.contents))
        if any(max(len(pair.old), len(pair.new)) > MAX_SOURCE_BYTES for pair in normalized):
            return None
        if not diagnostics:
            mapping = self._mapping(pairs)
            return SourceComparison(mapping, False) if mapping is not None else None
        if any(line_macro_locations(pair.old) != line_macro_locations(pair.new)
               or b"__COUNTER__" in pair.old + pair.new for pair in pairs):
            return None
        # No identifier changes: no outside-reference proof is needed. Compare
        # complete preprocessing tokens, retaining every non-diagnostic change.
        if all((tokens := tokenize_c_source(pair.old.decode())) is not None
               and tokens == tokenize_c_source(pair.new.decode()) for pair in normalized):
            return SourceComparison({}, True)
        mapping = self._mapping(normalized)
        return SourceComparison(mapping, True) if mapping is not None else None

    def _mapping(self, pairs: list[SourcePair]) -> dict[bytes, bytes] | None:
        mapping: dict[bytes, bytes] = {}
        old_names: set[bytes] = set()
        new_names: set[bytes] = set()
        unchanged: set[bytes] = set()
        recovered = []
        has_error_changes = False
        for pair in pairs:
            if re.search(rb"\b(?:__LINE__|__COUNTER__)\b", pair.old + b"\n" + pair.new):
                return None
            if re.search(rb"##|^\s*#\s*define[^\n]*#[^#]", pair.old + b"\n" + pair.new, re.MULTILINE):
                return None
            a, b = parse_source(pair.old), parse_source(pair.new)
            old_names.update(declaration_names(a))
            new_names.update(declaration_names(b))
            for x, y in zip_longest(syntax_tokens(a), syntax_tokens(b)):
                if x is None or y is None or x.kind != y.kind:
                    return None
                if x.value == y.value:
                    if x.kind in _NAME_KINDS:
                        unchanged.add(x.value)
                    continue
                if x.kind not in _NAME_KINDS or x.has_error != y.has_error:
                    return None
                has_error_changes |= x.has_error
                if mapping.setdefault(x.value, y.value) != y.value:
                    return None
        if not mapping or len(set(mapping.values())) != len(mapping):
            return None
        if (mapping.keys() | set(mapping.values())) & unchanged:
            return None
        if mapping.keys() & set(mapping.values()):
            return None
        if any(re.fullmatch(rb"[A-Za-z_][A-Za-z_0-9]*", name) is None for name in mapping.keys() | set(mapping.values())):
            return None
        if has_error_changes:
            for pair in pairs:
                old_functions = recover_static_functions(pair.old, frozenset(mapping))
                new_functions = recover_static_functions(pair.new, frozenset(mapping.values()))
                for node in old_functions:
                    old_names.update(declaration_names(parse_source(node_text(node))))
                for node in new_functions:
                    new_names.update(declaration_names(parse_source(node_text(node))))
                recovered.extend(old_functions)
                old_tokens, new_tokens = tokenize_c_source(pair.old.decode()), tokenize_c_source(pair.new.decode())
                if old_tokens is None or new_tokens is None or len(old_tokens) != len(new_tokens):
                    return None
                if any(a.kind != b.kind or mapping.get(a.value.encode(), a.value.encode()) != b.value.encode() for a, b in zip(old_tokens, new_tokens)):
                    return None
        if not mapping.keys() <= old_names or not set(mapping.values()) <= new_names:
            return None
        if any(_OPAQUE_NAMES.search(node_text(node)) for node in recovered):
            return None
        for pair in pairs:
            tree = parse_source(pair.old)
            arguments = argument_lists(tree)
            for node in sensitive_nodes(tree):
                if node.type == "preproc_arg":
                    arguments.extend(argument_lists(parse_source(node_text(node))))
                if node.type == "function_definition":
                    declarator = node.child_by_field_name("declarator")
                    name_node = declarator_name(declarator) if declarator is not None else None
                    if name_node is not None and node_text(name_node) in mapping and _OPAQUE_NAMES.search(node_text(node)):
                        return None
                if node.type == "string_literal" and any(re.search(rb"\b" + re.escape(name) + rb"\b", node_text(node)) for name in mapping):
                    return None
            if any(re.search(rb"\b" + re.escape(name) + rb"\b", node_text(node)) for node in arguments for name in mapping):
                return None
            for name in mapping:
                if re.search(rb"\b(?:EXPORT_SYMBOL\w*|SYMBOL_ALIAS)\s*\(\s*" + re.escape(name) + rb"\b", pair.old):
                    return None
        return mapping

    def _closed_scope(
        self, commit: FilteredCommit, pairs: list[SourcePair], mapping: dict[bytes, bytes], context: FilterContext,
    ) -> bool:
        # Included macros can capture even a local parameter's proposed name.
        # Keep local substitutions conservative until compiler bindings exist.
        external = frozenset(name.decode() for name in mapping)
        if self._index is None or not hasattr(context.repo, "repo"):
            return False
        assert commit.original.parent is not None
        paths = {pair.file.file for pair in pairs}
        old = commit.original.parent.commit_id
        requested = external | frozenset(value.decode() for name, value in mapping.items() if name.decode() in external)
        private: set[bytes] = set()
        if not self._index.has_bootstrap(requested):
            for pair in pairs:
                tree = parse_source(pair.old)
                private.update(item.name.encode() for item in definitions(pair.old, tree) if item.kind in {"function_definition", "preproc_def", "preproc_function_def"})
                for node in recover_static_functions(pair.old, frozenset(mapping)):
                    declarator = node.child_by_field_name("declarator")
                    function_name = declarator_name(declarator) if declarator is not None else None
                    if function_name is not None:
                        private.add(node_text(function_name))
        changes = self._index.changed_paths(old, commit.original.commit_id)
        for revision in (old, commit.original.commit_id):
            scope = None
            if not self._index.has_bootstrap(requested):
                if self._probe_consumers(revision, frozenset(paths), requested, context, commit):
                    return False
                if all(name.encode() in private for name in external):
                    scope = self._index.scope_for(paths, revision)
            def is_live(name: str, site: ReferenceSite) -> bool:
                return site.path not in paths and self._reference_is_live(revision, name, site, context, commit)
            lookups = self._index.lookup(revision, requested, parent=old if revision != old else None,
                                         changed_paths=changes, scope=scope, is_live=is_live)
            if any(sites is None or any(is_live(name, site) for site in sites) for name, sites in lookups.items()):
                return False
        return True

    def _analysis_pair(self, commit: FilteredCommit, pair: SourcePair) -> SourceAnalysis:
        # Standalone use also supports configured projection. In the pipeline
        # IfdefFilter has already recorded these original-coordinate masks.
        analyzed = any(mask.reason is MaskReason.IFDEF for mask in commit.code_masks_for(pair.file))
        pending: list[CodeMask] = []
        if self.config is not None and not analyzed:
            modes = commit.build_modes.get((pair.file.old_file, pair.file.file))
            for side, source in ((SourceSide.OLD, pair.old), (SourceSide.NEW, pair.new)):
                mode = (modes.old if side is SourceSide.OLD else modes.new) if modes is not None else None
                active = get_active_lines(source.decode(), self.config, is_module=mode == "m")
                if modes is None:
                    active |= get_active_lines(source.decode(), self.config, is_module=True)
                inactive = line_ranges(number for number in range(1, len(source.splitlines()) + 1) if number not in active)
                if inactive:
                    pending.append(CodeMask(FileIdentity.of(pair.file), side, MaskReason.IFDEF, inactive))
        sources = commit.active_sources(pair.file, SourceVersions(pair.old, pair.new), extra_code_masks=tuple(pending))
        return SourceAnalysis(SourcePair(pair.file, sources.old, sources.new), tuple(pending))

    def filter_mutable_commit(self, commit: FilteredCommit, context: FilterContext) -> FilteredCommit | None:
        self._stats.processed_commits += 1
        if commit.original.is_merge or not commit.diff.files:
            return commit
        if not all(_eligible(file) and (_hunk_rename_candidate(file, allow_strings=True) or hunk_reorder_candidate(file)
                                      or any(mask.reason is MaskReason.DEAD_CODE for mask in commit.code_masks_for(file)))
                   for file in commit.diff.files):
            return commit
        pairs: list[SourcePair] = []
        analyses: list[SourceAnalysis] = []
        for file in commit.diff.files:
            pair = self._pair(commit, file, context)
            if pair is None:
                return commit
            try:
                analysis = self._analysis_pair(commit, pair)
                analyses.append(analysis)
                pairs.append(analysis.pair)
            except (ValueError, UnicodeError):
                return commit
        try:
            comparison = self._compare(pairs, masked_reorder=any(mask.reason is MaskReason.DEAD_CODE for mask in commit.code_masks))
            if comparison is None:
                return commit
            mapping, diagnostics = comparison.mapping, comparison.diagnostics
            if comparison.reorder is not None:
                if self._reorder_macros is None:
                    self._reorder_macros = ReorderMacroGuard(
                        context.repo, self._read_file or context.repo.read_file,
                        lambda revision, site: self._active_site(revision, site, context),
                    )
                assert commit.original.parent is not None
                if not all(self._reorder_macros.allows(revision, comparison.reorder)
                           for revision in (commit.original.parent.commit_id, commit.original.commit_id)):
                    return commit
            if mapping and not self._closed_scope(commit, pairs, mapping, context):
                return commit
        except (OSError, ValueError, UnicodeError, subprocess.CalledProcessError):
            return commit
        for analysis in analyses:
            for mask in analysis.code_masks:
                commit.mask_code(analysis.pair.file, mask.side, mask.lines, mask.reason)
        reason = MaskReason.RENAME
        symbols = tuple(name.decode() for name in mapping)
        if comparison.reorder is not None:
            reason = MaskReason.REORDER
            symbols = comparison.reorder.symbols
        if diagnostics:
            reason = MaskReason.RENAME_DIAGNOSTICS if mapping else MaskReason.DIAGNOSTIC_WORDING
        self._record(commit, tuple(file.file for file in commit.diff.files), reason.value, symbols)
        for file in commit.diff.files:
            commit.mask_file(file, reason)
        self._stats.eliminated_commits += 1
        return None


def _changed_definitions(source: bytes, changed: frozenset[int]) -> tuple[Definition, ...]:
    items = definitions(source, parse_source(source))
    return tuple(item for item in items if any(item.line <= line <= item.end_line for line in changed))


def _definition_lines(source: bytes, item: Definition) -> LineRange | None:
    """A line mask may not erase an adjacent declaration or statement."""
    start = source.rfind(b"\n", 0, item.start) + 1
    end = item.end
    while end > item.start and source[end - 1:end] in (b"\n", b"\r"):
        end -= 1
    last = source.find(b"\n", end)
    if last < 0:
        last = len(source)
    suffix = source[end:last].strip()
    if source[start:item.start].strip() or suffix not in (b"", b";"):
        return None
    return LineRange(item.line, source.count(b"\n", 0, end) + 2)


@dataclass(frozen=True, slots=True)
class UnusedDefinition:
    name: str
    old_lines: tuple[LineRange, ...]
    new_lines: tuple[LineRange, ...]


def _without_comments(source: bytes) -> bytes:
    """Keep line positions stable for raw reference locations."""

    output = bytearray(source)
    for node in comments(parse_source(source)):
        output[node.start_byte:node.end_byte] = re.sub(rb"[^\r\n]", b" ", node_text(node))
    return bytes(output)


def _unconditional_text(source: bytes) -> bytes:
    """Cheap retention hint; never use this lexical approximation to prune.

    Repeated spellings outside conditional regions usually identify live code.
    Comments may add false uses, which only retain additional candidates.
    """

    parts: list[bytes] = []
    depth, start = 0, 0
    for match in re.finditer(rb"(?m)^[ \t]*#[ \t]*(if|ifdef|ifndef|endif)\b[^\n]*(?:\n|$)", source):
        if match[1] != b"endif":
            if depth == 0:
                parts.append(source[start:match.start()])
            depth += 1
        elif depth:
            depth -= 1
            if depth == 0:
                start = match.end()
    if depth == 0:
        parts.append(source[start:])
    return b"".join(parts)


class DeadCodeFilter(_SourceFilter):
    """Prune files whose changes are confined to definitions with no found uses.

    This is a zero-reference analysis, not arbitrary whole-program dead-code
    elimination. Ambiguous external references, generated names, and implicit
    registrations must be retained rather than inferred unreachable.
    """

    name: ClassVar[str] = "Filtering unreferenced definitions"

    def _unused(
        self, revision: str, pair: SourcePair, source: bytes,
        items: tuple[Definition, ...], context: FilterContext,
        parent: str | None, changed_paths: frozenset[str], commit: FilteredCommit,
        *, partial: bool = False,
    ) -> bool:
        if not items:
            return True
        side = SourceSide.NEW if revision == commit.original.commit_id else SourceSide.OLD
        source = commit.code_source(pair.file.old_file or pair.file.file if side is SourceSide.OLD else pair.file.file, side, source)
        names = frozenset(item.name for item in items)
        outside = self._effective_source(outside_definitions(source, items))
        if any(re.search(rb"\b" + re.escape(name.encode()) + rb"\b", outside) for name in names):
            return False
        if has_opaque_tokens(parse_source(source)):
            return False
        if re.search(rb"\b(?:__LINE__|__COUNTER__)\b", source):
            return False
        # Prefix/suffix spellings also retain common token-paste registrations.
        external = frozenset(guard for name in names for guard in spelling_guards(name))
        if self._index is None or not hasattr(context.repo, "repo"):
            return False
        if self._probe_consumers(revision, frozenset({pair.file.file}), names, context, commit):
            return False
        def is_live(name: str, site: ReferenceSite) -> bool:
            if site.path == pair.file.file and any(item.line <= site.line <= item.end_line for item in items):
                return False
            return self._reference_is_live(revision, name, site, context, commit)
        scope = None if self._index.has_bootstrap(external) else self._index.scope_for((pair.file.file,), revision, max_paths=256 if partial else None)
        if partial and self._index.source_includes is not None and not self._index.has_bootstrap(external):
            if scope is None or len(scope) > 256:
                return False
        references = self._index.lookup(revision, external, parent=parent, changed_paths=changed_paths, scope=scope, is_live=is_live)
        for name, sites in references.items():
            if sites is None:
                return False
            for site in sites:
                if is_live(name, site):
                    return False
        return True

    def _prune_file(self, commit: FilteredCommit, file: DiffFile, context: FilterContext) -> tuple[str, ...]:
        whitespace = WhitespaceFilter()
        if all(whitespace.is_chunk_noop(chunk) for chunk in file.chunks):
            return ()
        pair = self._pair(commit, file, context)
        if pair is None or max(len(pair.old), len(pair.new)) > 64 * 1024:
            return ()
        raw_sources = SourceVersions(pair.old, pair.new)
        pair = SourcePair(file,
                          commit.code_source(file.old_file or file.file, SourceSide.OLD, pair.old),
                          commit.code_source(file.file, SourceSide.NEW, pair.new))
        if file.file.endswith(".c") and file.chunks:
            sections = [re.findall(r"\b([A-Za-z_]\w*)\s*\(", chunk.section or "") for chunk in file.chunks]
            if all(sections):
                sources = (_unconditional_text(pair.old), _unconditional_text(pair.new))
                if all(all(len(re.findall(rb"\b" + re.escape(section[0].encode()) + rb"\b", source)) > 1 for source in sources) for section in sections):
                    return ()
        old_items = {item.name: item for item in _changed_definitions(pair.old, commit.changed_lines(file, SourceSide.OLD))}
        new_items = {item.name: item for item in _changed_definitions(pair.new, commit.changed_lines(file, SourceSide.NEW))}
        if not (old_items or new_items):
            return ()
        # Let the cheaper seeded rename check handle name-only definition
        # changes. Dead-code analysis is useful when other edits remain.
        if old_items.keys() != new_items.keys() and _hunk_rename_candidate(file):
            return ()
        # A reduced patch loaded without its mask history may have shifted new
        # coordinates. Refuse to prove unused code against mismatched sources.
        commit.effective_sources(file, raw_sources)
        old_outside = replace_c_comments(outside_definitions(pair.old, tuple(old_items.values())).decode())
        new_outside = replace_c_comments(outside_definitions(pair.new, tuple(new_items.values())).decode())
        whole_file = old_outside is not None and new_outside is not None and old_outside == new_outside
        if not whole_file and old_outside is not None and new_outside is not None:
            old_tokens, new_tokens = tokenize_c_source(old_outside), tokenize_c_source(new_outside)
            whole_file = old_tokens is not None and new_tokens is not None and old_tokens == new_tokens
        assert commit.original.parent is not None
        parent = commit.original.parent.commit_id
        if self._index is None or getattr(context.repo, "repo", None) is None:
            return ()
        paths = self._index.changed_paths(parent, commit.original.commit_id)
        candidates: list[UnusedDefinition] = []
        for name in sorted(old_items.keys() | new_items.keys()):
            old_item, new_item = old_items.get(name), new_items.get(name)
            old_span = _definition_lines(pair.old, old_item) if old_item is not None else None
            new_span = _definition_lines(pair.new, new_item) if new_item is not None else None
            if (old_item is not None and old_span is None) or (new_item is not None and new_span is None):
                continue
            candidates.append(UnusedDefinition(name, (old_span,) if old_span is not None else (), (new_span,) if new_span is not None else ()))
        if whole_file and len(candidates) > 1:
            names = {item.name for item in candidates}
            old_group = tuple(item for name, item in old_items.items() if name in names)
            new_group = tuple(item for name, item in new_items.items() if name in names)
            if (self._unused(parent, pair, pair.old, old_group, context, None, frozenset(), commit)
                    and self._unused(commit.original.commit_id, pair, pair.new, new_group, context, parent, paths, commit)):
                for item in candidates:
                    commit.mask_code(file, SourceSide.OLD, item.old_lines, MaskReason.DEAD_CODE)
                    commit.mask_code(file, SourceSide.NEW, item.new_lines, MaskReason.DEAD_CODE)
                return tuple(item.name for item in candidates)
        partial_fallback = not whole_file or len(candidates) > 1
        if partial_fallback:
            # Partial function pruning exposes mixed rename commits without
            # issuing separate repository queries for generated macro tables.
            candidates = [item for item in candidates
                          if (item.name not in old_items or old_items[item.name].kind == "function_definition")
                          and (item.name not in new_items or new_items[item.name].kind == "function_definition")]
        if len(candidates) > 8:
            return ()
        pruned: list[str] = []
        for decision in candidates:
            name = decision.name
            old_item, new_item = old_items.get(name), new_items.get(name)
            old_group = (old_item,) if old_item is not None else ()
            new_group = (new_item,) if new_item is not None else ()
            if not self._unused(parent, pair, pair.old, old_group, context, None, frozenset(), commit, partial=partial_fallback):
                continue
            if not self._unused(commit.original.commit_id, pair, pair.new, new_group, context, parent, paths, commit, partial=partial_fallback):
                continue
            commit.mask_code(file, SourceSide.OLD, decision.old_lines, MaskReason.DEAD_CODE)
            commit.mask_code(file, SourceSide.NEW, decision.new_lines, MaskReason.DEAD_CODE)
            pruned.append(name)
        return tuple(pruned)

    def filter_mutable_commit(self, commit: FilteredCommit, context: FilterContext) -> FilteredCommit | None:
        self._stats.processed_commits += 1
        if commit.original.is_merge:
            return commit
        for file in commit.diff.files:
            try:
                names = self._prune_file(commit, file, context)
            except (OSError, ValueError, UnicodeError, subprocess.CalledProcessError):
                names = ()
            if names:
                self._record(commit, (file.file,), "unreferenced_definition", names)
        if commit.diff.files:
            return commit
        self._stats.eliminated_commits += 1
        return None


def source_pruning_tail(
    config: KernelConfig | None = None,
    on_pruned: Callable[[PruningDecision], None] | None = None,
) -> tuple[StreamingCommitFilter, ...]:
    """Prune definitions, clean up comments, then compare remaining source."""
    return DeadCodeFilter(config, on_pruned), WhitespaceFilter(), RenameFilter(config, on_pruned)


__all__ = ["DeadCodeFilter", "PruningDecision", "RenameFilter", "SourcePruningStats", "source_pruning_tail"]
