"""Conservative CFG-gated changes, with explicit policy and caller scope.

Only runtime expressions and closed static callees are excluded. Declarations,
headers, exports, unknown effects and incomplete extraction retain the commit.
Policy masks are published only after every remaining file qualifies on both
real revisions. A direct-subject finding is never promoted to service closure.
"""

from collections.abc import Callable, Generator, Iterable
from contextlib import closing
from dataclasses import dataclass, replace
from pathlib import Path
import re
from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict

from .base import FilterContext, FilteredCommit, StreamingCommitFilter, repository_file_reader
from .config_filter import ConfigValue, KernelConfig
from .input_role_models import SourceRoleDecision, SourceRoleEvidence, SourceRoleStatus
from .masking import EditMask, FileIdentity, MaskReason, SourceSide
from .source_roles import INPUT_ROLE_RISK, SourceMaskPlan, publish_source_masks, source_assumption_evidence, source_role_decision
from .policy_clang import ClangAnalyzer, ClangByteExclusion, ClangCall, ClangConstraint, ClangFunction, ClangGuard, ClangWriteEffect, TranslationUnitFacts
from .policy_context import PolicyBuildContext, RevisionCompiler
from .policy_entry import Arm64SeccompEntries
from .policy_profile import AnalysisScope, PolicyTargetProfile, SELinuxPolicyEvaluator
from .policy_rules import GateExclusion, LinuxPolicyRules, POLICY_RULES_VERSION
from .policy_seccomp import PinnedSeccompFilter
from .policy_source import caller_closure_complete, execution_spans
from .whitespace.c_lexer import CTokenKind, tokenize_c_source
from ..diff import DiffFile, DiffFileType


_MAX_FILE_BYTES = 1024 * 1024
_MAX_EXCLUSIONS = 512
_NONEXECUTABLE = frozenset({"CompoundStmt", "DeclStmt", "IfStmt", "SwitchStmt", "CaseStmt", "DefaultStmt",
                          "LabelStmt", "GotoStmt", "IndirectGotoStmt", "ForStmt", "WhileStmt", "DoStmt",
                          "GCCAsmStmt", "MSAsmStmt", "AttributedStmt", "NullStmt"})
_CREDENTIAL_APIS = frozenset({"override_creds", "revert_creds", "commit_creds", "install_exec_creds",
                            "prepare_kernel_cred", "set_fs", "set_current_cred", "switch_task_namespaces"})
_PRESERVING_APIS = frozenset({"capable", "ns_capable", "ns_capable_noaudit", "security_bpf", "security_perf_event_open",
                            "memcmp", "strlen", "strcmp", "strncmp", "strnlen", "copy_to_user", "_copy_to_user", "access_ok"})
_PRESERVING_BUILTINS = frozenset({"__builtin_expect", "__builtin_expect_with_probability", "__builtin_constant_p",
                                "__builtin_clz", "__builtin_clzl", "__builtin_clzll", "__builtin_ctz", "__builtin_ctzl",
                                "__builtin_ctzll", "__builtin_popcount", "__builtin_popcountl", "__builtin_popcountll",
                                "__builtin_bswap16", "__builtin_bswap32", "__builtin_bswap64"})
_GATE_NAMES = frozenset({"capable", "ns_capable", "ns_capable_noaudit", "security_bpf", "security_perf_event_open"})


class SpanExclusion(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    function: str
    start: int
    end: int
    start_line: int
    end_line: int
    gate: str
    reason: str


class PolicyFileDecision(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    path: str
    equivalent_outside_exclusions: bool = False
    old_exclusions: tuple[SpanExclusion, ...] = ()
    new_exclusions: tuple[SpanExclusion, ...] = ()
    reasons: tuple[str, ...] = ()


class PolicyCommitDecision(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    commit_id: str
    status: Literal["excluded", "direct_app_candidate", "retained", "unknown"]
    scope: AnalysisScope
    profile_sha256: str
    policy_sha256: str
    build_context_sha256: str
    model_version: str = POLICY_RULES_VERSION
    files: tuple[PolicyFileDecision, ...] = ()
    reasons: tuple[str, ...] = ()
    lossy: bool = False
    risk_reasons: tuple[str, ...] = ()
    input_role_evidence: tuple[SourceRoleEvidence, ...] = ()


@dataclass(frozen=True, slots=True)
class _FingerprintRequest:
    revision: str
    exclusions: tuple[ClangByteExclusion, ...]


def _span_exclusion(function: ClangFunction, span: ClangByteExclusion, gate: GateExclusion, source: bytes) -> SpanExclusion:
    end = span.end
    return SpanExclusion(function=function.name, start=span.start, end=end,
                         start_line=source.count(b"\n", 0, span.start) + 1,
                         end_line=source.count(b"\n", 0, end) + 1, gate=gate.gate, reason=gate.reason)


def _blank(source: bytes, exclusions: tuple[SpanExclusion, ...]) -> bytes:
    output = bytearray(source)
    for item in exclusions:
        if not 0 <= item.start <= item.end <= len(output):
            raise ValueError("Invalid compiler source coordinates")
        output[item.start:item.end] = re.sub(rb"[^\r\n]", b" ", source[item.start:item.end])
    return bytes(output)


def _same_guard(first: ClangGuard, second: ClangGuard) -> bool:
    # Nested macros can give distinct calls identical expansion and spelling
    # spans. Only the exact, uniquely recorded CFG call occurrence is reusable.
    return (first.callee_usr == second.callee_usr and first.span == second.span
            and first.arguments == second.arguments and first.outcome == second.outcome
            and first.call_block is not None and first.call_order is not None
            and (first.call_block, first.call_order) == (second.call_block, second.call_order))


class LocalPolicyProof:
    """A deliberately small synchronous-entry/closed-static-call model.

    A changed statement must require a denied gate and have a known current
    subject context. Entry wrappers are recognized from actual SYSCALL_DEFINE
    spelling, not an arbitrary function name. Unknown callees before the gate
    do not get an implicit credential-preservation contract.
    """

    def __init__(self, source: bytes, path: Path, facts: TranslationUnitFacts, rules: LinuxPolicyRules,
                 *, static_closure_complete: bool = False) -> None:
        self.source, self.path, self.facts, self.rules = source, path, facts, rules
        self.static_closure_complete = static_closure_complete
        self.functions = {function.usr: function for function in facts.functions
                          if function.body_span.start.path == path and function.body_span.end.path == path}
        self.incoming: dict[str, list[tuple[ClangFunction, ClangCall]]] = {usr: [] for usr in self.functions}
        for caller in self.functions.values():
            for call in caller.calls:
                if call.callee_usr in self.incoming:
                    self.incoming[call.callee_usr].append((caller, call))

    def _root(self, function: ClangFunction) -> bool:
        if not function.name.startswith(("__do_sys_", "__se_sys_", "sys_")):
            return False
        if any(reference.usr == function.usr for reference in self.facts.address_taken):
            return False
        if any(not call.span.macro or call.span.start.offset != function.span.start.offset
               for _, call in self.incoming[function.usr]):
            return False
        prefix = self.source[function.span.start.offset:function.body_span.start.offset]
        tokens = tokenize_c_source(prefix.decode())
        return (tokens is not None and len(tokens) >= 3 and tokens[0].kind is CTokenKind.IDENTIFIER
                and re.fullmatch(r"(?:COMPAT_)?SYSCALL_DEFINE[0-6]", tokens[0].value) is not None
                and tokens[1].value == "(" and tokens[-1].value == ")")

    def _closed_static(self, function: ClangFunction) -> bool:
        if (not self.static_closure_complete or not function.is_static or not self.incoming[function.usr]
                or not caller_closure_complete(self.facts)):
            return False
        if any(ref.usr == function.usr for ref in self.facts.address_taken):
            return False
        # Every literal occurrence must be a declaration or a resolved direct
        # call. Strings, asm names, generated registrations and prototypes retain.
        ranges = [(function.span.start.offset, function.body_span.start.offset)]
        ranges.extend((call.span.start.offset, call.span.end.offset)
                      for _, call in self.incoming[function.usr] if not call.span.macro)
        return all(any(start <= match.start() < end for start, end in ranges)
                   for match in re.finditer(rb"\b" + re.escape(function.name.encode()) + rb"\b", self.source))

    def _unknowns(self, function: ClangFunction) -> tuple[str, ...]:
        # Standard syscall macros generate the signature, while the executable
        # body is physically present in the tracked TU and has a real CFG.
        allowed = {"macro_function_definition"} if self._root(function) and not function.body_span.macro else set()
        reasons = tuple(reason for reason in function.unknowns if reason not in allowed)
        if not function.write_coverage_complete:
            reasons += ("write_coverage_incomplete",)
        return reasons

    def _preserves_credentials(self, function: ClangFunction, visiting: frozenset[str] = frozenset()) -> bool:
        if function.usr in visiting or self._unknowns(function) or function.write_effects:
            return False
        seen = visiting | {function.usr}
        for call in function.calls:
            if call.callee in _CREDENTIAL_APIS or call.callee is None:
                return False
            target = self.functions.get(call.callee_usr or "")
            if target is not None:
                if not self._preserves_credentials(target, seen):
                    return False
                continue
            known_api = call.callee_usr == "c:@F@" + call.callee
            if known_api and (call.callee in _PRESERVING_APIS or call.callee in _PRESERVING_BUILTINS):
                continue
            else:
                return False
        return True

    @staticmethod
    def _write_precedes(function: ClangFunction, effect: ClangWriteEffect, offset: int,
                        required: ClangGuard | None) -> bool | None:
        """Whether an effect can execute before the target call, including loops.

        Source order cannot locate macro expansions, call arguments or backedges.
        Missing/ambiguous CFG metadata therefore yields an unknown prefix.
        """

        graph = {block.block: block.successors for block in function.cfg_blocks}
        if (len(graph) != len(function.cfg_blocks) or function.cfg_entry not in graph
                or effect.block not in graph or effect.order < 0
                or any(successor not in graph for successors in graph.values() for successor in successors)):
            return None
        targets: set[tuple[int, int]] = set()
        if required is not None and required.call_block is not None and required.call_order is not None:
            if not any(call.block == required.call_block and call.order == required.call_order
                       and call.callee_usr == required.callee_usr and call.span == required.span
                       and call.arguments == required.arguments for call in function.calls):
                return None
            targets.add((required.call_block, required.call_order))
        else:
            calls = [call for call in function.calls if call.span.start.offset == offset]
            if not calls:
                return None
            for call in calls:
                if call.block is None or call.order is None:
                    return None
                targets.add((call.block, call.order))
        if any(block not in graph or order < 0 for block, order in targets):
            return None
        if any(block == effect.block and effect.order < order for block, order in targets):
            return True
        # Start from successors, rather than the effect block itself. Returning
        # to the same block then proves a real cycle after this effect site.
        seen: set[int] = set()
        work = list(graph[effect.block])
        while work:
            block = work.pop()
            if block in seen:
                continue
            seen.add(block)
            if any(block == target for target, _ in targets):
                return True
            work.extend(graph[block])
        return False

    def _before(self, function: ClangFunction, offset: int, required: ClangGuard | None = None) -> bool:
        if self._unknowns(function):
            return False
        for effect in function.write_effects:
            precedes = self._write_precedes(function, effect, offset, required)
            if precedes is None:
                return False
            if required is not None and any(_same_guard(required, guard) for guard in effect.guards):
                # No such mutation can run before the first successful
                # evaluation of this exact gate occurrence.
                continue
            if precedes:
                return False
        tokens = tokenize_c_source(self.source[function.body_span.start.offset:function.body_span.end.offset].decode())
        if tokens is None:
            return False
        has_backedges = (any(token.value in {"for", "while", "do", "goto"} for token in tokens)
                         or any(statement.span.macro for statement in function.statements)
                         or any(call.span.macro for call in function.calls))
        for call in function.calls:
            if required is not None and any(_same_guard(required, guard) for guard in call.guards):
                # A mutation requiring the same successful gate cannot run
                # before its first evaluation; this is not an API contract.
                continue
            nested_argument = (required is not None and required.span.start.offset <= call.span.start.offset < required.span.end.offset)
            if call.span.start.offset >= offset and not has_backedges and not nested_argument:
                continue
            target = self.functions.get(call.callee_usr or "")
            if target is not None:
                if not self._preserves_credentials(target):
                    return False
                continue
            known_api = call.callee is not None and call.callee_usr == "c:@F@" + call.callee
            if known_api and (call.callee in _PRESERVING_APIS or call.callee in _PRESERVING_BUILTINS):
                continue
            else:
                return False
        return True

    def _gate(self, function: ClangFunction, guards: tuple[ClangGuard, ...],
              constraints: tuple[ClangConstraint, ...] = ()) -> GateExclusion | None:
        for guard in guards:
            if guard.callee_usr in self.functions:
                # A definition in the changed TU needs a proved implementation,
                # even when its global name resembles a modeled Linux API.
                continue
            if not self._before(function, guard.span.start.offset, guard):
                continue
            if (proof := self.rules.excludes(guard, constraints)) is not None:
                return proof
        return None

    def exclusions(self) -> tuple[SpanExclusion, ...]:
        if not self.facts.complete or self.facts.unknowns:
            return ()
        stable = {usr for usr, function in self.functions.items() if self._root(function)}
        for _ in range(min(len(self.functions), 64)):
            additions = {usr for usr, function in self.functions.items() if usr not in stable and self._closed_static(function)
                         and all(caller.usr in stable and self._before(caller, call.span.start.offset)
                                 for caller, call in self.incoming[usr])}
            if not additions:
                break
            stable |= additions
        blocked: dict[str, GateExclusion] = {}
        for _ in range(min(len(self.functions), 64)):
            previous_count = len(blocked)
            for usr, function in self.functions.items():
                if usr in blocked or not self._closed_static(function):
                    continue
                reasons: list[GateExclusion] = []
                for caller, call in self.incoming[usr]:
                    reason = blocked.get(caller.usr)
                    if reason is None and caller.usr in stable:
                        reason = self._gate(caller, call.guards, call.constraints)
                    if reason is None:
                        break
                    reasons.append(reason)
                else:
                    blocked[usr] = reasons[0]
            if len(blocked) == previous_count:
                break
        result: list[SpanExclusion] = []
        for usr, function in self.functions.items():
            body = self.source[function.body_span.start.offset:function.body_span.end.offset]
            tokens = tokenize_c_source(body.decode())
            declaration_effects = (tokens is None or any(token.value in {"static", "struct", "union", "enum", "typedef", "__attribute__", "asm", "__asm__"}
                                                        for token in tokens)
                                   or any(statement.kind == "DeclStmt" for statement in function.statements))
            if usr in blocked and not function.body_span.macro and not function.unknowns and not declaration_effects:
                result.extend(_span_exclusion(function, span, blocked[usr], self.source)
                              for span in execution_spans(function, function.body_span, self.path))
                continue
            if usr not in stable or self._unknowns(function):
                continue
            for statement in function.statements:
                span = statement.span
                if (statement.kind in _NONEXECUTABLE or span.macro or span.start.path != self.path
                        or span.end.path != self.path):
                    continue
                reason = self._gate(function, statement.guards, statement.constraints)
                if reason is not None:
                    result.extend(_span_exclusion(function, runtime, reason, self.source)
                                  for runtime in execution_spans(function, span, self.path))
        unique = {(item.start, item.end): item for item in result}
        if len(unique) > _MAX_EXCLUSIONS:
            return ()
        return tuple(sorted(unique.values(), key=lambda item: (item.start, -item.end)))


class PolicyFilter(StreamingCommitFilter):
    name: ClassVar[str] = "Filtering proven policy exclusions"

    def __init__(self, profile: PolicyTargetProfile, build_context: PolicyBuildContext,
                 evaluator: SELinuxPolicyEvaluator, *, cache_path: Path | None = None,
                 on_decision: Callable[[PolicyCommitDecision], None] | None = None,
                 analyzer: ClangAnalyzer | None = None) -> None:
        self.profile, self.build_context, self.evaluator = profile, build_context, evaluator
        self.cache_path, self.on_decision = cache_path, on_decision
        self.analyzer = analyzer
        self.rules = LinuxPolicyRules(profile, evaluator, KernelConfig(build_context.config_file.read_text()))
        self.seccomp_filter = (PinnedSeccompFilter.load(profile.seccomp.filter_file, profile.seccomp.filter_sha256)
                               if profile.seccomp.filter_file is not None and profile.seccomp.filter_sha256 is not None
                               else None)
        self.compiler: RevisionCompiler | None = None

    def iter_filter_mutable_commits(self, commits: Iterable[FilteredCommit], context: FilterContext,
                                   show_progress: bool = True, *, total: int | None = None) -> Generator[FilteredCommit, None, None]:
        owned = self.analyzer is None
        analyzer = self.analyzer or ClangAnalyzer()
        compiler: RevisionCompiler | None = None
        try:
            compiler = RevisionCompiler(context.repo, self.build_context, analyzer, cache_path=self.cache_path)
            self.compiler = compiler
            with repository_file_reader(context) as reader:
                with closing(super().iter_filter_mutable_commits(
                    commits, replace(context, file_reader=reader), show_progress, total=total,
                )) as output:
                    yield from output
        finally:
            if compiler is not None:
                compiler.close()
            if owned:
                analyzer.close()

    def _file(self, commit: FilteredCommit, file: DiffFile) -> PolicyFileDecision:
        assert self.compiler is not None and commit.original.parent is not None
        if (file.change_type is not DiffFileType.DEFAULT or not file.file.endswith(".c")
                or file.binary or file.mode_changed):
            return PolicyFileDecision(path=file.file, reasons=("unsupported_file_or_header_effects",))
        sources = tuple(self.compiler.reader.read_file(revision, file.file) for revision in
                        (commit.original.parent.commit_id, commit.original.commit_id))
        if not any(re.search(rb"\b(?:COMPAT_)?SYSCALL_DEFINE[0-6]\s*\(", source)
                   and (self.seccomp_filter is not None
                        or any(re.search(rb"\b" + name.encode() + rb"\s*\(", source) for name in _GATE_NAMES))
                   for source in sources):
            return PolicyFileDecision(path=file.file, reasons=("outside_modeled_entry_gate_subset",))
        # Optimization can select different emitted types even when every
        # declaration/type spelling is unchanged (e.g. changing a constant
        # branch). AST source masks do not certify the runtime BTF graph.
        if self.rules.config.get("CONFIG_DEBUG_INFO_BTF") is ConfigValue.ENABLED:
            return PolicyFileDecision(path=file.file, reasons=("emitted_btf_equivalence_unproved",))
        exclusions: list[tuple[SpanExclusion, ...]] = []
        normalized: list[bytes] = []
        fingerprints: list[str | None] = []
        fingerprint_requests: list[_FingerprintRequest] = []
        reasons: list[str] = []
        for side, revision in ((SourceSide.OLD, commit.original.parent.commit_id),
                               (SourceSide.NEW, commit.original.commit_id)):
            source = sources[0 if side is SourceSide.OLD else 1]
            if len(source) > _MAX_FILE_BYTES:
                return PolicyFileDecision(path=file.file, reasons=("policy_source_budget",))
            facts = self.compiler.facts(revision, file.file)
            if not facts.complete:
                reasons.extend(facts.unknowns or facts.diagnostics or ("incomplete_compiler_facts",))
                return PolicyFileDecision(path=file.file, reasons=tuple(reasons))
            path = self.build_context.source_root / file.file
            spans = LocalPolicyProof(source, path, facts, self.rules,
                                     static_closure_complete=self.compiler.is_single_translation_unit()).exclusions()
            if self.seccomp_filter is not None:
                entries = Arm64SeccompEntries.for_revision(self.compiler, revision, self.rules.config,
                                                           self.profile, self.seccomp_filter)
                if entries is not None:
                    spans += tuple(_span_exclusion(item.function, span, item.gate, source)
                                   for item in entries.exclusions(source, path, facts) for span in item.spans)
            if len(spans) > _MAX_EXCLUSIONS:
                return PolicyFileDecision(path=file.file, reasons=("policy_exclusion_budget",))
            exclusions.append(spans)
            masked = commit.code_source(file.file, side, source)
            normalized.append(_blank(masked, spans))
            byte_ranges = [ClangByteExclusion(path, item.start, item.end) for item in spans]
            physical_lines = source.splitlines(keepends=True)
            starts = [0]
            for line in physical_lines:
                starts.append(starts[-1] + len(line))
            for mask in commit.code_masks_for(file):
                if mask.side is not side:
                    continue
                if mask.whole_file:
                    byte_ranges.append(ClangByteExclusion(path, 0, len(source)))
                for line_range in mask.lines:
                    if line_range.start - 1 >= len(starts) or line_range.end - 1 >= len(starts):
                        return PolicyFileDecision(path=file.file, reasons=("invalid_previous_code_mask",))
                    byte_ranges.append(ClangByteExclusion(path, starts[line_range.start - 1], starts[min(line_range.end - 1, len(physical_lines))]))
            fingerprint_requests.append(_FingerprintRequest(revision, tuple(byte_ranges)))
        if any(exclusions):
            for request in fingerprint_requests:
                fingerprint = self.compiler.fingerprint(request.revision, file.file, request.exclusions)
                fingerprints.append(fingerprint.digest if fingerprint.complete else None)
                if not fingerprint.complete:
                    reasons.extend(fingerprint.diagnostics or ("incomplete_preprocessor_fingerprint",))
        else:
            fingerprints.extend((None, None))
        first = tokenize_c_source(normalized[0].decode())
        second = tokenize_c_source(normalized[1].decode())
        qualifies = (bool(exclusions[0] or exclusions[1]) and not reasons and first is not None and first == second
                     and fingerprints[0] is not None and fingerprints[0] == fingerprints[1])
        if not qualifies and not reasons:
            reasons.append("remaining_reachable_or_unmodeled_changes")
        return PolicyFileDecision(path=file.file, equivalent_outside_exclusions=qualifies,
                                  old_exclusions=exclusions[0], new_exclusions=exclusions[1], reasons=tuple(reasons))

    def filter_mutable_commit(self, commit: FilteredCommit, context: FilterContext) -> FilteredCommit | None:
        if commit.original.is_merge or not commit.diff.files or commit.original.parent is None:
            return commit
        try:
            files = tuple(self._file(commit, file) for file in commit.diff.files)
        except (OSError, ValueError, UnicodeError) as error:
            files = (PolicyFileDecision(path="", reasons=("analysis_failure: " + str(error)[:256],)),)
        qualifies = bool(files) and all(file.equivalent_outside_exclusions for file in files)
        status: Literal["excluded", "direct_app_candidate", "retained", "unknown"] = "retained"
        reasons: tuple[str, ...] = ()
        if qualifies:
            # A domain list cannot bind a different process to this thread's
            # seccomp filter, even when the caller declares SELinux mediation
            # complete. Such findings remain direct-app candidates.
            seccomp_used = any(span.gate == "seccomp" for file in files
                               for span in (*file.old_exclusions, *file.new_exclusions))
            scope_closed = self.rules.scope_closed and (not seccomp_used or self.profile.scope is AnalysisScope.DIRECT_APP)
            status = "excluded" if scope_closed else "direct_app_candidate"
            if not scope_closed:
                reasons = ("service_delegation_and_async_scope_not_closed",)
        elif any(file.reasons and file.reasons != ("remaining_reachable_or_unmodeled_changes",) for file in files):
            status = "unknown"
        roles: tuple[SourceRoleDecision, ...] = ()
        if status == "excluded":
            roles = tuple(source_role_decision(commit, file, context) for file in commit.diff.files)
            if any(role.status is SourceRoleStatus.BLOCKED for role in roles):
                status = "unknown"
                reasons = ("raw_input_consumer_or_unresolved_consumer_inventory",)
        assumptions = source_assumption_evidence(roles) if status == "excluded" else ()
        decision = PolicyCommitDecision(commit_id=commit.original.commit_id, status=status, scope=self.profile.scope,
                                        profile_sha256=self.profile.fingerprint, policy_sha256=self.profile.policy_sha256,
                                        build_context_sha256=self.build_context.fingerprint, files=files, reasons=reasons,
                                        lossy=bool(assumptions), risk_reasons=(INPUT_ROLE_RISK,) if assumptions else (),
                                        input_role_evidence=assumptions)

        def record_decision() -> None:
            if self.on_decision is not None:
                self.on_decision(decision)

        if status != "excluded":
            record_decision()
            return commit
        edits = tuple(EditMask(FileIdentity.of(file), MaskReason.POLICY, whole_file=True) for file in commit.diff.files)
        publish_source_masks(commit, context, SourceMaskPlan(roles, edits), before_masks=record_decision)
        return None
