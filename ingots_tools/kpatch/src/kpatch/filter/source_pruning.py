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
from .binding_renames import BindingComparison, compare_bindings
from .config_filter import BuildInputClosure, KbuildMakefileCache, KbuildState, KernelConfig
from .diagnostic_strings import normalize_diagnostic_strings
from .ifdef_filter import get_active_lines
from .masking import CodeMask, EditMask, FileIdentity, LineRange, MaskReason, SourceSide, SourceVersions, has_compiler_source_locations, line_macro_locations, line_ranges
from .macro_environment import MacroEnvironmentGuard
from .reference_index import ReferenceIndex, ReferenceIndexStats, ReferenceSite, spelling_guards
from .reordering import COLUMN_BUILTINS, LINE_BUILTINS, ReorderMacroGuard, ReorderProof, hunk_reorder_candidate, independent_reorder
from .switch_reordering import independent_switch_reorder
from .source_filter import SourceIncludeIndex
from .source_locations import SourcePositionExemptions, changed_identifier_positions
from .syntax import (
    MAX_SOURCE_BYTES, Definition, argument_lists, comments, declaration_names, declarator_name, definitions, has_opaque_tokens,
    node_text, outside_definitions, parse_source, recover_static_functions, sensitive_nodes, syntax_tokens,
    renamed_region_identifiers, unclosed_declaration_names,
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
    lossy: bool = False
    risk_reasons: tuple[str, ...] = ()


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
    bindings: BindingComparison | None = None
    reorder_reason: MaskReason = MaskReason.REORDER


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
        *, lossy: bool = False,
    ) -> None:
        self.config = config
        self.on_pruned = on_pruned
        self.lossy = lossy
        self._stats = SourcePruningStats()
        self._read_file: Callable[[str, str], bytes] | None = None
        self._index: ReferenceIndex | None = None
        self.index_stats: ReferenceIndexStats | None = None
        self._makefiles = KbuildMakefileCache(config) if config is not None else None
        self._site_cache: OrderedDict[tuple[str, str, int], bool] = OrderedDict()
        self._state: KbuildState | None = None
        self._reorder_macros: ReorderMacroGuard | None = None
        self._macro_environment: MacroEnvironmentGuard | None = None

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
                self._macro_environment = None

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
            if has_compiler_source_locations(old) or has_compiler_source_locations(new):
                return None
            if any(_NONSTANDARD_LINEBREAK.search(source.decode("utf-8", errors="strict")) for source in (old, new)):
                return None
        except (OSError, UnicodeError, subprocess.CalledProcessError):
            return None
        return SourcePair(file, old, new)

    def _record(self, commit: FilteredCommit, files: tuple[str, ...], rule: str, names: tuple[str, ...],
                *, lossy: bool = False, risks: tuple[str, ...] = ()) -> None:
        self._stats.pruned_files += len(files)
        if self.on_pruned is not None:
            self.on_pruned(PruningDecision(commit.original.commit_id, files, rule, names, commit.edit_masks, commit.code_masks,
                                          lossy, risks))

    def _compiler_names_safe(self, revision: str, names: frozenset[str], context: FilterContext) -> bool:
        return self._macro_guard(context).compiler_names_safe(revision, names)

    @property
    def _allow_unknown_macros(self) -> bool:
        return False

    def _macro_guard(self, context: FilterContext) -> ReorderMacroGuard:
        if self._reorder_macros is None:
            self._reorder_macros = ReorderMacroGuard(context.repo, self._read_file or context.repo.read_file,
                                                    lambda target, site: self._active_site(target, site, context),
                                                    allow_unknown=self._allow_unknown_macros)
        return self._reorder_macros

    def _active_site(self, revision: str, site: ReferenceSite, context: FilterContext) -> bool:
        if self.config is None or ".lds" in site.path or not site.path.endswith((".c", ".S", ".s")):
            return True
        if self._index is None:
            return True
        if self._state is None or self._state.base_commit != revision:
            self._state = KbuildState(
                context.repo, self.config, revision, read_file=self._read_file,
                makefile_cache=self._makefiles, source_includes=self._index.source_includes,
            )
        if self._state.build_input_closure is BuildInputClosure.UNKNOWN:
            # No exclusion is possible, so do not scan/advance the repository
            # include graph merely to rediscover the same unknown context.
            return True
        if self._index.source_includes is None:
            self._index.bind_includes(
                SourceIncludeIndex.from_repository(context.repo, revision, self.config.srcarch), revision,
            )
        if not self._index.ensure_includes(revision):
            self._state = None
            return True
        includes = self._index.source_includes
        assert includes is not None
        key = (revision, site.path, includes.generation)
        if key in self._site_cache:
            self._site_cache.move_to_end(key)
            return self._site_cache[key]
        if (self._state is None or self._state.base_commit != revision
                or self._state.source_includes is not includes):
            self._state = KbuildState(
                context.repo, self.config, revision, read_file=self._read_file,
                makefile_cache=self._makefiles, source_includes=includes,
            )
        result = self._state.get(site.path) is not None
        self._site_cache[key] = result
        if len(self._site_cache) > 1024:
            self._site_cache.popitem(last=False)
        # Unknown/local preprocessor state in headers is never used to reject a
        # reference. Configuration gating here is only for translation units.
        return result

    def _effective_source(self, source: bytes, *, cpp_complete: bool = False) -> bytes:
        source = _without_comments(source)
        if self.config is None or not cpp_complete:
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
        complete = (self._state is not None and self._state.base_commit == revision
                    and self._state.cpp_context_complete(site.path))
        lines = self._effective_source(source, cpp_complete=complete).split(b"\n")
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

    @property
    def _allow_unknown_macros(self) -> bool:
        return self.lossy

    def _compare(self, pairs: list[SourcePair], *, masked_reorder: bool) -> SourceComparison | None:
        if masked_reorder or all(hunk_reorder_candidate(pair.file) for pair in pairs):
            for reason, compare in ((MaskReason.REORDER, independent_reorder),
                                    (MaskReason.SWITCH_REORDER, independent_switch_reorder)):
                proofs = [compare(pair.old, pair.new) for pair in pairs]
                if all(proof is not None for proof in proofs):
                    identifiers = frozenset(name for proof in proofs if proof is not None for name in proof.identifiers)
                    protected = frozenset(name for proof in proofs if proof is not None for name in proof.identifiers - proof.numeric_names)
                    reorder = ReorderProof(tuple(sorted({name for proof in proofs if proof is not None for name in proof.symbols})),
                                           identifiers, identifiers - protected)
                    return SourceComparison({}, False, reorder, reorder_reason=reason)
        if self.lossy and all(line_macro_locations(pair.old) == line_macro_locations(pair.new)
               and b"__COUNTER__" not in pair.old + pair.new for pair in pairs):
            binding_proofs = [compare_bindings(pair.old, pair.new, bodies=self.lossy) for pair in pairs]
            if any(binding_proofs) and all(proof is not None or tokenize_c_source(pair.old.decode()) == tokenize_c_source(pair.new.decode())
                                          for pair, proof in zip(pairs, binding_proofs, strict=True)):
                return SourceComparison({}, False, bindings=BindingComparison(tuple(
                    rename for proof in binding_proofs if proof is not None for rename in proof.renames),
                    frozenset(name for proof in binding_proofs if proof is not None for name in proof.macro_identifiers),
                    frozenset(name for proof in binding_proofs if proof is not None for name in proof.invoked_names)))
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
        if any(b"__" in name for name in mapping.keys() | set(mapping.values())):
            # Kernel/compiler-reserved identifiers can encode metadata contracts.
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
        for pair in pairs:
            if (unclosed_declaration_names(parse_source(pair.old)) & mapping.keys()
                    or unclosed_declaration_names(parse_source(pair.new)) & set(mapping.values())):
                # Absence of a spelling cannot close external linkage: another
                # TU can construct both declarations and calls with token paste.
                return False
        external = frozenset(name.decode() for name in mapping)
        if self._index is None or not hasattr(context.repo, "repo"):
            return False
        assert commit.original.parent is not None
        paths = {pair.file.file for pair in pairs}
        old = commit.original.parent.commit_id
        if self._macro_environment is None:
            self._macro_environment = MacroEnvironmentGuard(context.repo, self._read_file or context.repo.read_file,
                                                            self.config.srcarch if self.config is not None else "")
        footprint: set[str] = set()
        for revision, names in ((old, frozenset(mapping)), (commit.original.commit_id, frozenset(mapping.values()))):
            for pair in pairs:
                source = pair.old if revision == old else pair.new
                identifiers = renamed_region_identifiers(parse_source(source), names)
                environment = self._macro_environment.inspect(revision, pair.file.file)
                if identifiers is None or not environment.closed or identifiers & environment.macros:
                    return False
                footprint.update(identifiers)
        if len(footprint) > 256:
            return False
        if self.lossy and any(not self._macro_guard(context).source_names_unbound(revision, frozenset(footprint))
                              for revision in (old, commit.original.commit_id)):
            return False
        requested = external | frozenset(value.decode() for name, value in mapping.items() if name.decode() in external)
        if any(not self._compiler_names_safe(revision, requested | frozenset(footprint), context)
               for revision in (old, commit.original.commit_id)):
            return False
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
        # Only certified exclusive CPP contexts permit new projection. In the
        # pipeline IfdefFilter may already have recorded those code masks.
        analyzed = any(mask.reason is MaskReason.IFDEF for mask in commit.code_masks_for(pair.file))
        pending: list[CodeMask] = []
        modes = commit.build_modes.get((pair.file.old_file, pair.file.file))
        if self.config is not None and not analyzed and modes is not None and modes.complete:
            for side, source in ((SourceSide.OLD, pair.old), (SourceSide.NEW, pair.new)):
                mode = modes.old if side is SourceSide.OLD else modes.new
                if mode is None:
                    continue
                active = get_active_lines(source.decode(), self.config, is_module=mode == "m")
                inactive = line_ranges(number for number in range(1, len(source.splitlines()) + 1) if number not in active)
                if inactive:
                    pending.append(CodeMask(FileIdentity.of(pair.file), side, MaskReason.IFDEF, inactive))
        sources = commit.active_sources(pair.file, SourceVersions(pair.old, pair.new), extra_code_masks=tuple(pending))
        return SourceAnalysis(SourcePair(pair.file, sources.old, sources.new), tuple(pending))

    def filter_mutable_commit(self, commit: FilteredCommit, context: FilterContext) -> FilteredCommit | None:
        self._stats.processed_commits += 1
        if self._reorder_macros is not None:
            self._reorder_macros.reset_assumptions()
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
            if mapping and not self.lossy:
                # Source references do not establish name nonobservability:
                # BTF/CO-RE, kallsyms and compiler metadata preserve spellings.
                return commit
            # Raw global-reference searches need a closed spelling/include
            # context even in lossy mode. Establish it before global position
            # queries so an already unsupported rename stops cheaply.
            if mapping and not self._closed_scope(commit, pairs, mapping, context):
                return commit
            if comparison.bindings is not None or mapping or diagnostics or comparison.reorder is not None:
                names = (comparison.bindings.names if comparison.bindings is not None else
                         frozenset(name.decode() for name in (*mapping.keys(), *mapping.values())))
                assert commit.original.parent is not None
                for pair in pairs:
                    # Only recognized logger callee sites receive the logging
                    # exemption. The same spelling in an evaluated argument
                    # or another expression can still hide a location builtin.
                    exemptions = SourcePositionExemptions()
                    if diagnostics:
                        exemptions = SourcePositionExemptions(
                            normalize_diagnostic_strings(pair.old).logger_offsets,
                            normalize_diagnostic_strings(pair.new).logger_offsets)
                    positions = changed_identifier_positions(pair.old, pair.new, names, exemptions=exemptions)
                    if positions is None:
                        return commit
                    for revision in (commit.original.parent.commit_id, commit.original.commit_id):
                        guard = self._macro_guard(context)
                        if (not guard.location_independent(revision, positions.lines, LINE_BUILTINS)
                                or not guard.location_independent(revision, positions.columns, COLUMN_BUILTINS)):
                            return commit
            if comparison.reorder is not None:
                guard = self._macro_guard(context)
                assert commit.original.parent is not None
                if not all(guard.allows(revision, comparison.reorder)
                           for revision in (commit.original.parent.commit_id, commit.original.commit_id)):
                    return commit
            if comparison.bindings is not None:
                guard = self._macro_guard(context)
                assert commit.original.parent is not None
                if not all(guard.binding_names_safe(revision, comparison.bindings.names)
                           for revision in (commit.original.parent.commit_id, commit.original.commit_id)):
                    return commit
                if comparison.bindings.lossy and not all(guard.preserves_bindings(
                        revision, (comparison.bindings.macro_identifiers - comparison.bindings.names)
                                  | comparison.bindings.invoked_names, comparison.bindings.names)
                        for revision in (commit.original.parent.commit_id, commit.original.commit_id)):
                    return commit
        except (OSError, ValueError, UnicodeError, subprocess.CalledProcessError):
            return commit
        for analysis in analyses:
            for mask in analysis.code_masks:
                commit.mask_code(analysis.pair.file, mask.side, mask.lines, mask.reason)
        reason = MaskReason.RENAME
        symbols = tuple(name.decode() for name in mapping)
        if comparison.reorder is not None:
            reason = comparison.reorder_reason
            symbols = comparison.reorder.symbols
        if diagnostics:
            reason = MaskReason.RENAME_DIAGNOSTICS if mapping else MaskReason.DIAGNOSTIC_WORDING
        uncertainties = self._reorder_macros.assumed_uncertainties if self._reorder_macros is not None else frozenset()
        lossy = bool(mapping) or comparison.bindings is not None or bool(uncertainties)
        risks: tuple[str, ...] = (
            "preprocessing_inputs_and_compiler_flags_not_fully_pinned",
            "symbol_type_and_member_names_may_be_observable_through_btf_or_kallsyms",
        ) if mapping else ()
        if comparison.bindings is not None:
            reason = MaskReason.LOCAL_RENAME if comparison.bindings.lossy else MaskReason.PROTOTYPE_PARAMETERS
            symbols = tuple(sorted({item.old + "->" + item.new for item in comparison.bindings.renames}))
            risks = ("preprocessing_inputs_and_compiler_flags_not_fully_pinned",
                     "lexical_binding_equivalence_without_complete_macro_expansion",
                     "debug_and_btf_parameter_names_may_change")
        if uncertainties:
            risks += ("incomplete_macro_discovery_assumed", "unobserved_macro_bindings_can_change_runtime_behavior")
            risks += tuple("macro_discovery_" + reason for reason in sorted(uncertainties))
        self._record(commit, tuple(file.file for file in commit.diff.files), reason.value, symbols, lossy=lossy, risks=risks)
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

    def _locations_safe(
        self, commit: FilteredCommit, pair: SourcePair,
        old_items: tuple[Definition, ...], new_items: tuple[Definition, ...],
        context: FilterContext,
    ) -> bool:
        def outside(source: bytes, items: tuple[Definition, ...]) -> bytes:
            result = bytearray(source)
            for item in items:
                result[item.start:item.end] = re.sub(rb"[^\r\n]", b" ", source[item.start:item.end])
            return bytes(result)

        positions = changed_identifier_positions(outside(pair.old, old_items), outside(pair.new, new_items), frozenset())
        if positions is None:
            return False
        assert commit.original.parent is not None
        guard = self._macro_guard(context)
        return all(guard.location_independent(revision, positions.lines, LINE_BUILTINS)
                   and guard.location_independent(revision, positions.columns, COLUMN_BUILTINS)
                   for revision in (commit.original.parent.commit_id, commit.original.commit_id))

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
        if self._macro_environment is None:
            self._macro_environment = MacroEnvironmentGuard(context.repo, self._read_file or context.repo.read_file,
                                                            self.config.srcarch if self.config is not None else "")
        environment = self._macro_environment.inspect(revision, pair.file.file)
        if not environment.closed:
            return False
        footprint: set[str] = set()
        for item in items:
            if item.kind in {"preproc_def", "preproc_function_def"}:
                continue
            tokens = tokenize_c_source(source[item.start:item.end].decode())
            if tokens is None:
                return False
            footprint.update(token.value for token in tokens if token.kind is CTokenKind.IDENTIFIER)
        if len(footprint) > 256 or footprint & environment.macros:
            return False
        if not self._compiler_names_safe(revision, names | frozenset(footprint), context):
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
                    and self._unused(commit.original.commit_id, pair, pair.new, new_group, context, parent, paths, commit)
                    and self._locations_safe(commit, pair, old_group, new_group, context)):
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
            if not self._locations_safe(commit, pair, old_group, new_group, context):
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
    *, lossy: bool = False,
) -> tuple[StreamingCommitFilter, ...]:
    """Prune definitions, clean up comments, then compare remaining source."""
    return DeadCodeFilter(config, on_pruned, lossy=lossy), WhitespaceFilter(), RenameFilter(config, on_pruned, lossy=lossy)


__all__ = ["DeadCodeFilter", "PruningDecision", "RenameFilter", "SourcePruningStats", "source_pruning_tail"]
