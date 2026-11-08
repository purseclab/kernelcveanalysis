"""Configured compiler-input equivalence, independently of policy reachability.

Compare the real parent and child after compiler expansion. Debug provenance,
unused macro definitions and include spelling are outside this comparison;
expanded values, declarations, executable tokens and semantic pragmas remain.
"""

from collections import OrderedDict
from collections.abc import Callable, Generator, Iterable, Mapping
from contextlib import closing
from dataclasses import dataclass, field, replace
from pathlib import Path
import subprocess
from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict

from .base import FilterContext, FilteredCommit, StreamingCommitFilter
from .config_filter import ConfigValue, KbuildMakefileCache, KbuildState, KernelConfig
from .input_role_models import SourceRoleEvidence, SourceRoleStatus
from .masking import EditMask, FileIdentity, MaskReason
from .policy_clang import ClangAnalyzer, PreprocessorFingerprint
from .policy_context import PolicyBuildContext, RevisionCompiler
from .reference_index import ReferenceIndex
from .source_filter import SourceIncludeIndex
from .source_modes import regular_source_change
from .source_roles import INPUT_ROLE_RISK, SourceMaskPlan, publish_source_masks, source_assumption_evidence, source_role_decision
from ..diff import DiffFile, DiffFileType


class PreprocessedUnit(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    path: str
    old_digest: str | None
    new_digest: str | None
    old_tokens: int
    new_tokens: int


class PreprocessingDecision(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    commit_id: str
    path: str
    status: Literal["excluded", "retained", "unknown"]
    reason: str
    build_context_sha256: str
    units: tuple[PreprocessedUnit, ...] = ()
    ignored_observations: tuple[str, ...] = ("debug_and_btf_provenance",)
    lossy: bool = False
    risk_reasons: tuple[str, ...] = ()
    input_role_evidence: tuple[SourceRoleEvidence, ...] = ()


@dataclass(slots=True)
class PreprocessingStats:
    processed_files: int = 0
    excluded_files: int = 0
    reasons: dict[str, int] = field(default_factory=dict)
    baseline_units: int = 0
    dirty_units: int = 0
    revision_cache_hits: int = 0


@dataclass(frozen=True, slots=True)
class _ExpandedUnit:
    digest: str
    tokens: int
    sources: frozenset[str]


class TargetPreprocessorFilter(StreamingCommitFilter):
    """Prune unchanged expanded inputs under the supplied kernel build model."""

    name: ClassVar[str] = "Filtering equivalent preprocessed inputs"
    requires_reference_index: ClassVar[bool] = True

    def __init__(self, build_context: PolicyBuildContext, *, cache_path: Path | None = None,
                 on_decision: Callable[[PreprocessingDecision], None] | None = None,
                 analyzer: ClangAnalyzer | None = None,
                 additional_inputs: Mapping[str, ConfigValue] | None = None) -> None:
        self.build = build_context
        self.cache_path, self.on_decision, self.analyzer = cache_path, on_decision, analyzer
        self.config = KernelConfig(build_context.config_file.read_text(), additional_inputs=additional_inputs)
        self.stats = PreprocessingStats()
        self.compiler: RevisionCompiler | None = None
        self._references: ReferenceIndex | None = None
        self._makefiles = KbuildMakefileCache(self.config)
        self._baseline: dict[str, _ExpandedUnit] = {}
        self._reverse: dict[str, set[str]] = {}
        self._paths: dict[str, str] = {}
        self._baseline_ready = False
        self._baseline_failure = ""
        self._revision_units: OrderedDict[str, dict[str, _ExpandedUnit]] = OrderedDict()

    def iter_filter_mutable_commits(self, commits: Iterable[FilteredCommit], context: FilterContext,
                                   show_progress: bool = True, *, total: int | None = None) -> Generator[FilteredCommit, None, None]:
        analyzer = self.analyzer or ClangAnalyzer()
        compiler = RevisionCompiler(context.repo, self.build, analyzer, cache_path=self.cache_path)
        references = context.reference_index or ReferenceIndex(context.repo, compiler.reader.read_file)
        self.compiler, self._references = compiler, references
        self._baseline.clear()
        self._reverse.clear()
        self._paths.clear()
        self._baseline_ready = False
        self._baseline_failure = ""
        self._revision_units.clear()
        try:
            reader_context = replace(context, file_reader=context.file_reader or compiler.reader)
            with closing(super().iter_filter_mutable_commits(commits, reader_context, show_progress, total=total)) as result:
                yield from result
        finally:
            if context.reference_index is None:
                references.close()
            self._references = None
            compiler.close()
            if self.analyzer is None:
                analyzer.close()

    def _expanded_unit(self, unit: str, fingerprint: PreprocessorFingerprint) -> _ExpandedUnit:
        assert self.compiler is not None
        if not fingerprint.complete or fingerprint.digest is None:
            raise ValueError(next(iter(fingerprint.diagnostics), "incomplete_preprocessing"))
        sources: set[str] = set()
        for path in fingerprint.dependencies:
            if path.is_relative_to(self.build.source_root):
                relative = path.relative_to(self.build.source_root).as_posix()
                sources.add(self._paths.setdefault(relative, relative))
        if self.compiler.commands[unit].file.is_relative_to(self.build.source_root):
            sources.add(self._paths.setdefault(unit, unit))
        return _ExpandedUnit(fingerprint.digest, fingerprint.tokens, frozenset(sources))

    def _bootstrap_consumers(self) -> None:
        assert self.compiler is not None
        if self._baseline_ready:
            return
        if self._baseline_failure:
            raise ValueError(self._baseline_failure)
        if len(self.compiler.commands) > 65536:
            raise ValueError("consumer_inventory_unit_budget")
        baseline: dict[str, _ExpandedUnit] = {}
        reverse: dict[str, set[str]] = {}
        edges = 0
        try:
            for path in sorted(self.compiler.commands):
                record = self._expanded_unit(path, self.compiler.preprocess(self.build.base_revision, path))
                edges += len(record.sources)
                if edges > 8_000_000:
                    raise ValueError("consumer_inventory_reference_budget")
                baseline[path] = record
                for source in record.sources:
                    reverse.setdefault(source, set()).add(path)
                self.stats.baseline_units += 1
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError) as error:
            self._baseline_failure = "consumer_inventory_incomplete:" + str(error)[:256]
            raise ValueError(self._baseline_failure) from error
        self._baseline, self._reverse = baseline, reverse
        self._baseline_ready = True

    def _revision_records(self, revision: str) -> dict[str, _ExpandedUnit]:
        assert self.compiler is not None
        changed = self.compiler.changed_paths(revision)
        self._bootstrap_consumers()
        if revision in self._revision_units:
            self._revision_units.move_to_end(revision)
            self.stats.revision_cache_hits += 1
            return self._revision_units[revision]
        dirty = {unit for source in changed for unit in self._reverse.get(source, ())}
        if len(dirty) > 128:
            raise ValueError("translation_unit_budget")
        records: dict[str, _ExpandedUnit] = {}
        for path in sorted(dirty):
            records[path] = self._expanded_unit(path, self.compiler.preprocess(revision, path))
            self.stats.dirty_units += 1
        self._revision_units[revision] = records
        self._revision_units.move_to_end(revision)
        while len(self._revision_units) > 8:
            self._revision_units.popitem(last=False)
        return records

    def _units(self, revision: str, path: str, context: FilterContext) -> tuple[str, ...]:
        assert self.compiler is not None and self._references is not None
        # Reject an incompatible build epoch or oversized historical overlay
        # before bootstrapping any global include/consumer inventory.
        self.compiler.changed_paths(revision)
        references = self._references
        if references.source_includes is None:
            references.bind_includes(SourceIncludeIndex.from_repository(
                context.repo, self.build.base_revision, self.config.srcarch,
            ), self.build.base_revision)
        if not references.ensure_includes(revision):
            raise ValueError("incomplete_consumer_update")
        includes = references.source_includes
        assert includes is not None
        state = KbuildState(context.repo, self.config, revision, includes, self.compiler.reader.read_file,
                            makefile_cache=self._makefiles)
        # Normalize configured positive includes before asking the reverse
        # index for edges (spliced directives need this exact-source analysis).
        state.get(path)
        if state.has_input_failures:
            raise ValueError("consumer_input_failure")
        # The configured object inventory catches plain C inputs supplied a
        # forced header by Kbuild too; '#' discovery alone cannot find them.
        # Actual CPP dependencies, rather than source suffixes, identify the
        # consumers among recorded units below.
        for source in sorted(state.modeled_sources()):
            if source not in self.compiler.commands:
                raise ValueError("missing_consumer_compilation_command:" + source)
        if state.has_input_failures:
            raise ValueError("consumer_input_failure")
        records = self._revision_records(revision)
        units = {unit for unit in self._reverse.get(path, ()) if unit not in records or path in records[unit].sources}
        units.update(unit for unit, record in records.items() if path in record.sources)
        if len(units) > 128:
            raise ValueError("translation_unit_budget")
        if not units:
            raise ValueError("missing_compilation_command")
        return tuple(sorted(units))

    def _compare(self, commit: FilteredCommit, file: DiffFile, context: FilterContext) -> PreprocessingDecision:
        assert self.compiler is not None and commit.original.parent is not None
        decision = PreprocessingDecision(commit_id=commit.original.commit_id, path=file.file,
                                         status="unknown", reason="unsupported_source_change",
                                         build_context_sha256=self.build.fingerprint)
        if (file.change_type is not DiffFileType.DEFAULT or file.binary or file.mode_changed
                or not file.file.endswith((".c", ".h"))
                or not regular_source_change(file, context.repo, commit.original.parent.commit_id, commit.original.commit_id)):
            return decision
        old, new = commit.original.parent.commit_id, commit.original.commit_id
        try:
            units = set(self._units(old, file.old_file or file.file, context)) | set(self._units(new, file.file, context))
            if len(units) > 128:
                raise ValueError("translation_unit_budget")
            pairs: list[PreprocessedUnit] = []
            for path in sorted(units):
                before = self._revision_units[old].get(path, self._baseline[path])
                after = self._revision_units[new].get(path, self._baseline[path])
                pairs.append(PreprocessedUnit(path=path, old_digest=before.digest, new_digest=after.digest,
                                              old_tokens=before.tokens, new_tokens=after.tokens))
                if before.digest != after.digest:
                    return decision.model_copy(update={"status": "retained", "reason": "expanded_inputs_changed", "units": tuple(pairs)})
            return decision.model_copy(update={"status": "excluded", "reason": "equivalent_expanded_inputs", "units": tuple(pairs)})
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError) as error:
            return decision.model_copy(update={"reason": str(error)[:256]})

    def _record(self, decision: PreprocessingDecision) -> None:
        self.stats.reasons[decision.reason] = self.stats.reasons.get(decision.reason, 0) + 1
        if self.on_decision is not None:
            self.on_decision(decision)

    def filter_mutable_commit(self, commit: FilteredCommit, context: FilterContext) -> FilteredCommit | None:
        if commit.original.is_merge or commit.original.parent is None:
            return commit
        for file in tuple(commit.diff.files):
            self.stats.processed_files += 1
            decision = self._compare(commit, file, context)
            if decision.status != "excluded":
                self._record(decision)
                continue
            role = source_role_decision(commit, file, context)
            if role.status is SourceRoleStatus.BLOCKED:
                self._record(decision.model_copy(update={"status": "retained", "reason": "raw_source_input_or_failed_inventory"}))
                continue
            assumptions = source_assumption_evidence((role,))
            decision = decision.model_copy(update={"lossy": bool(assumptions), "input_role_evidence": assumptions,
                                                    "risk_reasons": (INPUT_ROLE_RISK,) if assumptions else ()})
            edit = EditMask(FileIdentity.of(file), MaskReason.PREPROCESSED, whole_file=True)
            publish_source_masks(commit, context, SourceMaskPlan((role,), (edit,)),
                                 before_masks=lambda: self._record(decision))
            self.stats.excluded_files += 1
        return commit if commit.diff.files else None
