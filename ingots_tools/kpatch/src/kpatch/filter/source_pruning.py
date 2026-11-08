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
from .config_filter import KbuildMakefileCache, KbuildState, KernelConfig, SourceAnalysisCache
from .constant_filter import ConstantConditionalFilter
from .diagnostic_strings import normalize_diagnostic_strings
from .ifdef_filter import get_active_lines
from .input_role_models import SourceRoleDecision, SourceRoleStatus
from .masking import CodeMask, EditMask, FileIdentity, LineRange, MaskReason, SourceSide, SourceVersions, has_compiler_source_locations, line_macro_locations, line_ranges
from .pruning_decision import PruningDecision
from .source_roles import SourceMaskPlan, decorate_source_decision, publish_source_masks, source_role_decision
from .macro_environment import MacroEnvironmentGuard
from .macro_lookup import MacroOrigin
from .reference_index import ReferenceIndex, ReferenceIndexStats, ReferenceSite, spelling_guards
from .reordering import COLUMN_BUILTINS, LINE_BUILTINS, ReorderMacroGuard, ReorderProof, hunk_reorder_candidate, independent_reorder
from .switch_reordering import independent_switch_reorder
from .source_filter import SourceIncludeIndex
from .source_locations import SourcePositionExemptions, changed_identifier_positions
from .source_modes import regular_source_change
from .syntax import (
    MAX_SOURCE_BYTES, Definition, argument_lists, comments, declaration_names, declarator_name, definitions, has_opaque_tokens,
    node_text, outside_definitions, parse_source, recover_static_functions, sensitive_nodes, syntax_tokens,
    renamed_region_identifiers, unclosed_declaration_names, unused_definitions,
)
from .whitespace.c_lexer import CTokenKind, replace_c_comments, tokenize_c_source
from .whitespace.whitespace_filter import WhitespaceFilter
from ..diff import DiffFile, DiffFileType


_NAME_KINDS = frozenset({"identifier", "type_identifier", "field_identifier"})
_NONSTANDARD_LINEBREAK = re.compile(r"\r(?!\n)|[\v\f\x1c-\x1e\x85\u2028\u2029]")
_PHASE_TWO_SPLICE = re.compile(rb"\\[^\S\r\n]*(?:\r\n|\n|\r)")


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
        self._states: OrderedDict[str, KbuildState] = OrderedDict()
        self._source_analysis_cache: SourceAnalysisCache | None = None
        self._reorder_macros: ReorderMacroGuard | None = None
        self._macro_environment: MacroEnvironmentGuard | None = None
        self._environment_assumptions: set[str] = set()
        self._prototype_cache: OrderedDict[tuple[str, str], tuple[Definition, ...]] = OrderedDict()
        self._configured_reference_assumed = False

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
                        planned, replace(context, file_reader=reader), show_progress, total=total,
                    )
            finally:
                self.index_stats = self._index.stats()
                if context.reference_index is None:
                    self._index.close()
                self._read_file = None
                self._index = None
                self._site_cache.clear()
                self._prototype_cache.clear()
                self._state = None
                self._states.clear()
                self._source_analysis_cache = None
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
        if not regular_source_change(file, context.repo, commit.original.parent.commit_id, commit.original.commit_id):
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

    def _record(self, decision: PruningDecision, roles: tuple[SourceRoleDecision, ...]) -> None:
        self._stats.pruned_files += len(decision.paths)
        if self.on_pruned is not None:
            self.on_pruned(decorate_source_decision(decision, roles))

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
        basename = site.path.rsplit("/", 1)[-1]
        if (self.config is None or ".lds" in site.path
                or basename in {"Makefile", "Kbuild"}
                or basename.startswith(("Makefile.", "Kbuild.")) or basename.endswith(".mk")):
            return True
        if self._index is None:
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
        if self._source_analysis_cache is None or self._source_analysis_cache.source_includes is not includes:
            self._states.clear()
            self._site_cache.clear()
            self._source_analysis_cache = SourceAnalysisCache(self.config, includes)
        if revision not in self._states:
            self._states[revision] = KbuildState(
                context.repo, self.config, revision, read_file=self._read_file,
                makefile_cache=self._makefiles, source_includes=includes,
                source_analysis_cache=self._source_analysis_cache,
            )
            if len(self._states) > 2:
                self._states.popitem(last=False)
        self._states.move_to_end(revision)
        self._state = self._states[revision]
        if self._state.has_input_failures:
            return True
        key = (revision, site.path, includes.generation)
        if key in self._site_cache:
            self._site_cache.move_to_end(key)
            result = self._site_cache[key]
            self._configured_reference_assumed |= not result
            return result
        result = self._state.get(site.path) is not None or self._state.has_input_failures
        self._configured_reference_assumed |= not result
        self._site_cache[revision, site.path, includes.generation] = result
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
        read = self._read_file or context.repo.read_file
        side = SourceSide.NEW if revision == commit.original.commit_id else SourceSide.OLD
        source = commit.code_source(site.path, side, read(revision, site.path))
        unfiltered = self._effective_source(source).split(b"\n")
        pattern = rb"\b" + re.escape(name.encode()) + rb"\b"
        if site.line > len(unfiltered) or re.search(pattern, unfiltered[site.line - 1]) is None:
            return False
        if not self._active_site(revision, site, context):
            return False
        complete = (self._state is not None and self._state.base_commit == revision
                    and self._state.cpp_context_complete(site.path))
        lines = self._effective_source(source, cpp_complete=True).split(b"\n") if complete else unfiltered
        return site.line <= len(lines) and re.search(pattern, lines[site.line - 1]) is not None

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
                except FileNotFoundError:
                    continue
                side = SourceSide.NEW if revision == commit.original.commit_id else SourceSide.OLD
                contents = commit.code_source(source, side, contents)
                # Positive discovery must also see names assembled by ordinary
                # phase-two splices, including GNU's whitespace extension.
                # Splicing precedes comment recognition in preprocessing.
                normalized = _PHASE_TWO_SPLICE.sub(b"", contents)
                effective = self._effective_source(normalized)
                if not any(re.search(rb"\b" + re.escape(name.encode()) + rb"\b", effective) for name in names):
                    continue
                if not self._active_site(revision, ReferenceSite(source, 1), context):
                    continue
                complete = self._state is not None and self._state.cpp_context_complete(source)
                if complete:
                    effective = self._effective_source(normalized, cpp_complete=True)
                if any(re.search(rb"\b" + re.escape(name.encode()) + rb"\b", effective) for name in names):
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
        if all(line_macro_locations(pair.old) == line_macro_locations(pair.new)
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
            # Source permutations do not preserve observable function/return
            # addresses. Require the explicit assumption and an audit sink.
            if comparison.reorder is not None and (not self.lossy or self.on_pruned is None):
                return commit
            mapping, diagnostics = comparison.mapping, comparison.diagnostics
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
        roles = tuple(source_role_decision(commit, pair.file, context) for pair in pairs)
        if any(role.status is SourceRoleStatus.BLOCKED for role in roles):
            return commit
        reason = MaskReason.RENAME
        symbols = tuple(name.decode() for name in mapping)
        if comparison.reorder is not None:
            reason = comparison.reorder_reason
            symbols = comparison.reorder.symbols
        if diagnostics:
            reason = MaskReason.RENAME_DIAGNOSTICS if mapping else MaskReason.DIAGNOSTIC_WORDING
        uncertainties = self._reorder_macros.assumed_uncertainties if self._reorder_macros is not None else frozenset()
        lossy = (comparison.bindings is not None and comparison.bindings.lossy
                 or comparison.reorder is not None or bool(uncertainties))
        risks: tuple[str, ...] = (
            "preprocessing_inputs_and_compiler_flags_not_fully_pinned",
            "symbol_type_and_member_names_may_be_observable_through_btf_or_kallsyms",
        ) if mapping else ()
        if comparison.reorder is not None:
            risks += (
                "function_and_callsite_addresses_may_change_runtime_behavior",
                "compiler_generated_layout_and_instrumentation_not_proven_equivalent",
            )
        if comparison.bindings is not None:
            reason = MaskReason.LOCAL_RENAME if comparison.bindings.lossy else MaskReason.PROTOTYPE_PARAMETERS
            symbols = tuple(sorted({item.old + "->" + item.new for item in comparison.bindings.renames}))
            risks = ("preprocessing_inputs_and_compiler_flags_not_fully_pinned",
                     "lexical_binding_equivalence_without_complete_macro_expansion",
                     "debug_and_btf_parameter_names_may_change")
        if uncertainties:
            risks += ("incomplete_macro_discovery_assumed", "unobserved_macro_bindings_can_change_runtime_behavior")
            risks += tuple("macro_discovery_" + reason for reason in sorted(uncertainties))
        paths = tuple(pair.file.file for pair in pairs)
        edits = tuple(EditMask(FileIdentity.of(pair.file), reason, whole_file=True) for pair in pairs)
        codes = tuple(mask for analysis in analyses for mask in analysis.code_masks)
        # Replaying the rule's own edit masks would erase the rename/reorder
        # being verified. Preserve the comparison's input edit context and its
        # proposed inactive-code context in the existing source audit.
        decision = PruningDecision(commit.original.commit_id, paths, reason.value, symbols,
                                   commit.edit_masks, commit.code_masks + codes, lossy, risks)
        publish_source_masks(commit, context, SourceMaskPlan(roles, edits, codes),
                             before_masks=lambda: self._record(decision, roles))
        self._stats.eliminated_commits += 1
        return None


def _changed_definitions(source: bytes, changed: frozenset[int], *, include_external: bool) -> tuple[Definition, ...]:
    items = unused_definitions(source, parse_source(source))
    return tuple(item for item in items if (include_external or not item.external_linkage)
                 and any(item.line <= line <= item.end_line for line in changed))


def _group_definitions(items: tuple[Definition, ...]) -> dict[str, tuple[Definition, ...]]:
    groups: dict[str, list[Definition]] = {}
    for item in items:
        groups.setdefault(item.name, []).append(item)
    return {name: tuple(group) for name, group in groups.items()}


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


@dataclass(frozen=True, slots=True)
class _UnusedCodeProof:
    names: tuple[str, ...]
    masks: tuple[CodeMask, ...]


def _unused_masks(file: DiffFile, item: UnusedDefinition) -> tuple[CodeMask, ...]:
    identity = FileIdentity.of(file)
    return tuple(CodeMask(identity, side, MaskReason.DEAD_CODE, lines)
                 for side, lines in ((SourceSide.OLD, item.old_lines), (SourceSide.NEW, item.new_lines)) if lines)


def _mask_preview(commit: FilteredCommit) -> FilteredCommit:
    preview = FilteredCommit(commit.original, build_modes=commit.build_modes.copy())
    for edit in commit.edit_masks:
        preview.apply_edit_mask(edit)
    for code in commit.code_masks:
        preview.apply_code_mask(code)
    return preview


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

    def __init__(
        self, config: KernelConfig | None = None,
        on_pruned: Callable[[PruningDecision], None] | None = None, *, lossy: bool = False,
        line_numbers_lossy: bool = False,
        on_line_numbers_assumed: Callable[[PruningDecision], None] | None = None,
    ) -> None:
        if line_numbers_lossy and on_line_numbers_assumed is None:
            raise ValueError("Unused-code line-number assumptions require a whitespace audit callback")
        super().__init__(config, on_pruned or on_line_numbers_assumed, lossy=lossy)
        self.line_numbers_lossy = line_numbers_lossy
        self.on_line_numbers_assumed = on_line_numbers_assumed
        self._line_numbers_assumed = False

    @property
    def _allow_unknown_macros(self) -> bool:
        return self.lossy

    def _prototype_reference(self, revision: str, name: str, site: ReferenceSite, context: FilterContext) -> bool:
        """A redundant prototype is not a call/address/export of its function."""
        key = revision, site.path
        if key not in self._prototype_cache:
            source = (self._read_file or context.repo.read_file)(revision, site.path)
            items = (() if len(source) > MAX_SOURCE_BYTES else
                     tuple(item for item in unused_definitions(source, parse_source(source)) if item.kind == "declaration"))
            self._prototype_cache[key] = items if len(items) <= 1024 else ()
            if len(self._prototype_cache) > 64:
                self._prototype_cache.popitem(last=False)
        self._prototype_cache.move_to_end(key)
        return any(item.name == name and item.line <= site.line <= item.end_line
                   for item in self._prototype_cache[key])

    def _definition_macros_safe(
        self, revision: str, names: frozenset[str], tag_names: frozenset[str],
        scope_names: frozenset[str], context: FilterContext,
    ) -> bool:
        return (self._macro_replacements_safe(revision, scope_names, tag_names, context, declarations=True)
                and self._macro_replacements_safe(revision, names, tag_names, context, declarations=False))

    def _macro_replacements_safe(
        self, revision: str, names: frozenset[str], tag_names: frozenset[str], context: FilterContext,
        *, declarations: bool,
    ) -> bool:
        """Reject observed expansions with nonlocal preprocessing/code effects.

        Balanced expression/type/inline modifiers may occur in an unused body;
        rejecting every ordinary kernel macro would defeat configured pruning.
        Missing discovery remains an explicit lossy assumption, never a way to
        discard a known opaque or escaping expansion.
        """
        guard = self._macro_guard(context)
        pending, visited = set(names), set[str]()
        forbidden = {"#", "##", "%:", "%:%:", "asm", "__asm", "__asm__", "_Pragma", "__pragma",
                     "__COUNTER__", "section", "__section__", "__section", "constructor", "destructor",
                     "__constructor__", "__destructor__",
                     "alias", "__alias__", "used", "__used", "__used__", ";", "{", "}"}
        if declarations:
            forbidden.update({"struct", "union", "enum"})
        for _ in range(8):
            pending.difference_update(visited)
            if not pending:
                return True
            if len(visited | pending) > 256:
                return False
            batch = frozenset(pending)
            pending.clear()
            for name, observation in guard._lookup(revision, batch).items():
                if observation.uncertainties:
                    if not self.lossy or not observation.assumable:
                        return False
                    self._environment_assumptions.update(observation.uncertainties)
                for macro in observation.definitions:
                    if macro.origin is not MacroOrigin.SOURCE or macro.replacement is None:
                        return False
                    if name in tag_names and not macro.function_like:
                        return False
                    if name in {"static", "extern"} and not macro.function_like:
                        return False
                    tokens = tokenize_c_source(macro.replacement.decode())
                    if tokens is None or any(token.value in forbidden for token in tokens):
                        return False
                    stack: list[str] = []
                    for token in tokens:
                        if token.value == "," and not stack:
                            return False
                        if token.value in {"(", "[", "{"}:
                            stack.append({"(": ")", "[": "]", "{": "}"}[token.value])
                        elif token.value in {")", "]", "}"} and (not stack or stack.pop() != token.value):
                            return False
                    if stack:
                        return False
                    pending.update(token.value for token in tokens if token.kind is CTokenKind.IDENTIFIER
                                   and token.value not in macro.parameters and token.value != name)
            visited.update(batch)
        return False

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
        revisions = (commit.original.parent.commit_id, commit.original.commit_id)
        if not all(guard.location_independent(revision, positions.columns, COLUMN_BUILTINS) for revision in revisions):
            return False
        if self.line_numbers_lossy and positions.lines:
            self._line_numbers_assumed = True
            return True
        return all(guard.location_independent(revision, positions.lines, LINE_BUILTINS) for revision in revisions)

    def _unused(
        self, revision: str, pair: SourcePair, source: bytes,
        items: tuple[Definition, ...], context: FilterContext,
        parent: str | None, changed_paths: frozenset[str], commit: FilteredCommit,
        *, partial: bool = False,
    ) -> bool:
        if not items:
            return True
        self._configured_reference_assumed |= any(item.external_linkage for item in items)
        side = SourceSide.NEW if revision == commit.original.commit_id else SourceSide.OLD
        source = commit.code_source(pair.file.old_file or pair.file.file if side is SourceSide.OLD else pair.file.file, side, source)
        names = frozenset(name for item in items for name in item.names)
        external = frozenset(guard for name in names for guard in spelling_guards(name))
        function_names = frozenset(item.name for item in items if item.kind in {"function_definition", "declaration"})
        prototypes = tuple(item for item in unused_definitions(source, parse_source(source))
                           if item.kind == "declaration" and item.name in function_names)
        outside = self._effective_source(outside_definitions(source, items + prototypes))
        if any(re.search(rb"\b" + re.escape(name.encode()) + rb"\b", outside) for name in external):
            return False
        fragments = tuple(source[item.start:item.end] for item in items)
        if any(has_opaque_tokens(parse_source(fragment), implicit_names=False) for fragment in fragments):
            return False
        if any(re.search(rb"\b__COUNTER__\b", fragment) for fragment in fragments):
            return False
        if self._macro_environment is None:
            self._macro_environment = MacroEnvironmentGuard(context.repo, self._read_file or context.repo.read_file,
                                                            self.config.srcarch if self.config is not None else "")
        environment = self._macro_environment.inspect(revision, pair.file.file)
        if not environment.closed and (not self.lossy or self.on_pruned is None):
            return False
        if not environment.closed:
            self._environment_assumptions.add(environment.reason)
        footprint: set[str] = set()
        for item in items:
            if item.kind in {"preproc_def", "preproc_function_def"}:
                continue
            tokens = tokenize_c_source(source[item.start:item.end].decode())
            if tokens is None:
                return False
            footprint.update(token.value for token in tokens if token.kind is CTokenKind.IDENTIFIER)
        if len(footprint) > 256:
            return False
        tag_names = frozenset(name for item in items for name in item.tag_names)
        scope_names = frozenset(name for item in items for name in item.scope_names)
        if footprint and not self._definition_macros_safe(revision, frozenset(footprint), tag_names, scope_names, context):
            # A known expansion may escape the apparent function/type body.
            # Incomplete discovery can be audited; an observed binding cannot.
            return False
        if not self._compiler_names_safe(revision, names | frozenset(footprint), context):
            return False
        # Prefix/suffix spellings also retain common token-paste registrations.
        if self._index is None or not hasattr(context.repo, "repo"):
            return False
        if self._index.source_includes is None:
            self._index.bind_includes(SourceIncludeIndex.from_repository(
                context.repo, revision, self.config.srcarch if self.config is not None else "",
            ), revision)
        if not self._index.ensure_includes(revision):
            return False
        if self._probe_consumers(revision, frozenset({pair.file.file}), names, context, commit):
            return False
        def is_live(name: str, site: ReferenceSite) -> bool:
            if site.path == pair.file.file and any(item.line <= site.line <= item.end_line for item in items):
                return False
            if not self._reference_is_live(revision, name, site, context, commit):
                return False
            return name not in function_names or not self._prototype_reference(revision, name, site, context)
        scope = None if self._index.has_bootstrap(external) else self._index.scope_for((pair.file.file,), revision, max_paths=256 if partial else None)
        if partial and self._index.source_includes is not None and not self._index.has_bootstrap(external):
            if scope is None or len(scope) > 256:
                return False
        if len(external) > 2048:
            return False
        ordered = sorted(external)
        for offset in range(0, len(ordered), 256):
            references = self._index.lookup(revision, frozenset(ordered[offset:offset + 256]),
                                            parent=parent, changed_paths=changed_paths, scope=scope, is_live=is_live)
            for name, sites in references.items():
                if sites is None or any(is_live(name, site) for site in sites):
                    return False
        return True

    def _prune_file(self, commit: FilteredCommit, file: DiffFile, context: FilterContext) -> _UnusedCodeProof | None:
        self._environment_assumptions.clear()
        self._line_numbers_assumed = False
        self._configured_reference_assumed = False
        self._macro_guard(context).reset_assumptions()
        whitespace = WhitespaceFilter()
        if all(whitespace.is_chunk_noop(chunk) for chunk in file.chunks):
            return None
        pair = self._pair(commit, file, context)
        if pair is None:
            return None
        raw_sources = SourceVersions(pair.old, pair.new)
        pair = SourcePair(file,
                          commit.code_source(file.old_file or file.file, SourceSide.OLD, pair.old),
                          commit.code_source(file.file, SourceSide.NEW, pair.new))
        if file.file.endswith(".c") and file.chunks:
            sections = [re.findall(r"\b([A-Za-z_]\w*)\s*\(", chunk.section or "") for chunk in file.chunks]
            if all(sections):
                sources = (_unconditional_text(pair.old), _unconditional_text(pair.new))
                if all(all(len(re.findall(rb"\b" + re.escape(section[0].encode()) + rb"\b", source)) > 1 for source in sources) for section in sections):
                    return None
        old_items = _group_definitions(_changed_definitions(pair.old, commit.changed_lines(file, SourceSide.OLD),
                                                          include_external=self.config is not None))
        new_items = _group_definitions(_changed_definitions(pair.new, commit.changed_lines(file, SourceSide.NEW),
                                                          include_external=self.config is not None))
        if not (old_items or new_items):
            return None
        # Let the cheaper seeded rename check handle name-only definition
        # changes. Dead-code analysis is useful when other edits remain.
        if old_items.keys() != new_items.keys() and _hunk_rename_candidate(file):
            return None
        # A reduced patch loaded without its mask history may have shifted new
        # coordinates. Refuse to prove unused code against mismatched sources.
        commit.effective_sources(file, raw_sources)
        old_outside = replace_c_comments(outside_definitions(pair.old, tuple(item for group in old_items.values() for item in group)).decode())
        new_outside = replace_c_comments(outside_definitions(pair.new, tuple(item for group in new_items.values() for item in group)).decode())
        whole_file = old_outside is not None and new_outside is not None and old_outside == new_outside
        if not whole_file and old_outside is not None and new_outside is not None:
            old_tokens, new_tokens = tokenize_c_source(old_outside), tokenize_c_source(new_outside)
            whole_file = old_tokens is not None and new_tokens is not None and old_tokens == new_tokens
        assert commit.original.parent is not None
        parent = commit.original.parent.commit_id
        if self._index is None or getattr(context.repo, "repo", None) is None:
            return None
        paths = self._index.changed_paths(parent, commit.original.commit_id)
        candidates: list[UnusedDefinition] = []
        for name in sorted(old_items.keys() | new_items.keys()):
            old_spans = tuple(_definition_lines(pair.old, item) for item in old_items.get(name, ()))
            new_spans = tuple(_definition_lines(pair.new, item) for item in new_items.get(name, ()))
            if any(span is None for span in old_spans + new_spans):
                continue
            candidates.append(UnusedDefinition(name, tuple(span for span in old_spans if span is not None),
                                               tuple(span for span in new_spans if span is not None)))
        if whole_file and len(candidates) > 1:
            names = {item.name for item in candidates}
            old_group = tuple(item for name, group in old_items.items() if name in names for item in group)
            new_group = tuple(item for name, group in new_items.items() if name in names for item in group)
            if (self._unused(parent, pair, pair.old, old_group, context, None, frozenset(), commit)
                    and self._unused(commit.original.commit_id, pair, pair.new, new_group, context, parent, paths, commit)
                    and self._locations_safe(commit, pair, old_group, new_group, context)):
                masks = tuple(mask for item in candidates for mask in _unused_masks(file, item))
                return _UnusedCodeProof(tuple(item.name for item in candidates), masks)
        partial_fallback = not whole_file or len(candidates) > 1
        if len(candidates) > 8:
            return None
        pruned: list[str] = []
        pending: list[CodeMask] = []
        preview: FilteredCommit | None = None
        for decision in candidates:
            name = decision.name
            old_group, new_group = old_items.get(name, ()), new_items.get(name, ())
            view = preview if preview is not None else commit
            if not self._unused(parent, pair, pair.old, old_group, context, None, frozenset(), view, partial=partial_fallback):
                continue
            if not self._unused(commit.original.commit_id, pair, pair.new, new_group, context, parent, paths, view, partial=partial_fallback):
                continue
            if not self._locations_safe(view, pair, old_group, new_group, context):
                continue
            if preview is None:
                preview = _mask_preview(commit)
            masks = _unused_masks(file, decision)
            for mask in masks:
                preview.apply_code_mask(mask)
            pending.extend(masks)
            pruned.append(name)
        return _UnusedCodeProof(tuple(pruned), tuple(pending)) if pruned else None

    def filter_mutable_commit(self, commit: FilteredCommit, context: FilterContext) -> FilteredCommit | None:
        self._stats.processed_commits += 1
        if commit.original.is_merge:
            return commit
        for file in commit.diff.files:
            try:
                proof = self._prune_file(commit, file, context)
            except (OSError, ValueError, UnicodeError, subprocess.CalledProcessError):
                proof = None
            if proof is None:
                continue
            roles = source_role_decision(commit, file, context)
            if roles.status is SourceRoleStatus.BLOCKED:
                continue
            uncertainties = self._environment_assumptions | set(self._macro_guard(context).assumed_uncertainties)
            risks = (("incomplete_macro_discovery_assumed", "unobserved_macro_bindings_can_change_runtime_behavior")
                     + tuple("macro_discovery_" + reason for reason in sorted(uncertainties))) if uncertainties else ()
            if self._line_numbers_assumed:
                risks += ("source_line_number_observations_may_change_runtime_behavior",
                          "included_macros_may_observe_changed_lines")
            if self._configured_reference_assumed:
                risks += ("configured_kernel_reference_scope_assumed",
                          "unmodeled_compilation_roots_may_reference_definitions")
            rule = "unreferenced_definition_line_numbers_lossy" if self._line_numbers_assumed else "unreferenced_definition"
            decision = PruningDecision(commit.original.commit_id, (file.file,), rule, proof.names,
                                       commit.edit_masks, commit.code_masks + proof.masks,
                                       lossy=bool(uncertainties) or self._line_numbers_assumed or self._configured_reference_assumed,
                                       risk_reasons=risks)
            def record() -> None:
                if (self._line_numbers_assumed and self.on_line_numbers_assumed is not None
                        and self.on_line_numbers_assumed is not self.on_pruned):
                    self.on_line_numbers_assumed(decorate_source_decision(decision, (roles,)))
                self._record(decision, (roles,))
            publish_source_masks(commit, context, SourceMaskPlan((roles,), code_masks=proof.masks),
                                 before_masks=record)
        if commit.diff.files:
            return commit
        self._stats.eliminated_commits += 1
        return None


def source_pruning_tail(
    config: KernelConfig | None = None,
    on_pruned: Callable[[PruningDecision], None] | None = None,
    *, lossy: bool = False, constant_branches: bool = False,
    whitespace_line_numbers_lossy: bool = False,
    whitespace_audit: Callable[[PruningDecision], None] | None = None,
) -> tuple[StreamingCommitFilter, ...]:
    """Optionally fold constants, prune definitions, then compare source."""
    constant_stage: tuple[StreamingCommitFilter, ...] = (
        ConstantConditionalFilter(
            on_pruned, line_numbers_lossy=whitespace_line_numbers_lossy,
            on_line_numbers_assumed=whitespace_audit,
        ),
    ) if constant_branches else ()
    return (
        *constant_stage,
        DeadCodeFilter(config, on_pruned, lossy=lossy, line_numbers_lossy=whitespace_line_numbers_lossy,
                       on_line_numbers_assumed=whitespace_audit),
        WhitespaceFilter(line_numbers_lossy=whitespace_line_numbers_lossy, on_pruned=whitespace_audit),
        RenameFilter(config, on_pruned, lossy=lossy),
    )


__all__ = ["DeadCodeFilter", "PruningDecision", "RenameFilter", "SourcePruningStats", "source_pruning_tail"]
