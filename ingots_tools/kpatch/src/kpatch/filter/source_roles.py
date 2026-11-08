"""Authorize source masks and audit explicit input-role assumptions."""

from collections.abc import Callable
from dataclasses import dataclass, replace
import subprocess
from typing import TYPE_CHECKING

from ..diff import DiffFile, DiffFileType
from .input_role_models import (
    InputInventoryState, RawInputUnknownKind, SourceRoleDecision,
    SourceRoleEvidence, SourceRoleStatus,
)
from .masking import CodeMask, EditMask, FileIdentity, SourceSide

if TYPE_CHECKING:
    from .base import FilterContext, FilteredCommit
    from .pruning_decision import PruningDecision


INPUT_ROLE_RISK = "unresolved_raw_consumers_may_change_build_or_runtime_behavior"
_ASSUMABLE_UNKNOWNS = frozenset({
    RawInputUnknownKind.MAKE_OPERAND,
    RawInputUnknownKind.ASM_OPERAND,
    RawInputUnknownKind.MAKE_EXPANSION,
})


@dataclass(frozen=True, slots=True)
class SourceInputAssumptionPolicy:
    on_pruned: "Callable[[PruningDecision], None]"


@dataclass(frozen=True, slots=True)
class SourceMaskPlan:
    roles: tuple[SourceRoleDecision, ...]
    edit_masks: tuple[EditMask, ...] = ()
    code_masks: tuple[CodeMask, ...] = ()


def source_role_decision(
    commit: "FilteredCommit", file: DiffFile, context: "FilterContext",
) -> SourceRoleDecision:
    """Query original sides; an assumption never waives positive or failed scans."""

    identity = FileIdentity.of(file)
    versions: list[tuple[SourceSide, str, str]] = []
    if file.change_type is not DiffFileType.NEW:
        parent = commit.original.parent
        if parent is None:
            return SourceRoleDecision(identity, SourceRoleStatus.BLOCKED)
        versions.append((SourceSide.OLD, parent.commit_id, file.old_file or file.file))
    if file.change_type is not DiffFileType.DELETE:
        versions.append((SourceSide.NEW, commit.original.commit_id, file.file))
    evidence: list[SourceRoleEvidence] = []
    try:
        for side, revision, path in versions:
            observed = context.input_roles.lookup(context, revision, path)
            evidence.append(SourceRoleEvidence(side, revision, path, observed))
            if (observed.state is not InputInventoryState.FULL or observed.consumers or observed.failures
                    or (observed.unknowns and context.input_role_policy is None)
                    or any(item.kind not in _ASSUMABLE_UNKNOWNS for item in observed.unknowns)):
                return SourceRoleDecision(identity, SourceRoleStatus.BLOCKED, tuple(evidence))
    except (OSError, UnicodeError, ValueError, RuntimeError, subprocess.SubprocessError):
        return SourceRoleDecision(identity, SourceRoleStatus.BLOCKED, tuple(evidence))
    assumed = any(item.observation.unknowns for item in evidence)
    status = SourceRoleStatus.ASSUMED if assumed else SourceRoleStatus.OBSERVED_CLEAR
    return SourceRoleDecision(identity, status, tuple(evidence))


def source_assumption_evidence(roles: tuple[SourceRoleDecision, ...]) -> tuple[SourceRoleEvidence, ...]:
    return tuple(item for role in roles if role.status is SourceRoleStatus.ASSUMED for item in role.evidence)


def decorate_source_decision(
    decision: "PruningDecision", roles: tuple[SourceRoleDecision, ...],
) -> "PruningDecision":
    evidence = source_assumption_evidence(roles)
    if not evidence:
        return decision
    return replace(decision, lossy=True,
                   risk_reasons=tuple(dict.fromkeys((*decision.risk_reasons, INPUT_ROLE_RISK))),
                   input_role_evidence=evidence)


def _coherent_authorization(role: SourceRoleDecision) -> bool:
    if role.status is SourceRoleStatus.BLOCKED or not role.evidence:
        return False
    observations = tuple(item.observation for item in role.evidence)
    if any(item.state is not InputInventoryState.FULL or item.consumers or item.failures for item in observations):
        return False
    unknowns = tuple(unknown for item in observations for unknown in item.unknowns)
    if any(item.kind not in _ASSUMABLE_UNKNOWNS for item in unknowns):
        return False
    return bool(unknowns) == (role.status is SourceRoleStatus.ASSUMED)


def publish_source_masks(
    commit: "FilteredCommit", context: "FilterContext", plan: SourceMaskPlan, *,
    before_masks: Callable[[], None] | None = None,
) -> None:
    """Write the mandatory assumption audit before adding any planned masks."""

    edits = tuple(mask for mask in plan.edit_masks if mask.whole_file or mask.old_lines or mask.new_lines)
    codes = tuple(mask for mask in plan.code_masks if mask.whole_file or mask.lines)
    if not edits and not codes:
        return
    if not plan.roles or any(not _coherent_authorization(role) for role in plan.roles):
        raise ValueError("Source masks require an accepted input-role decision")
    authorized = {role.file for role in plan.roles}
    files = tuple(mask.file for mask in edits) + tuple(mask.file for mask in codes)
    if any(file not in authorized for file in files):
        raise ValueError("Source masks exceed their input-role authorization")
    if source_assumption_evidence(plan.roles):
        from .pruning_decision import PruningDecision

        if context.input_role_policy is None:
            raise ValueError("Source input assumptions require an audit policy")
        paths = tuple(sorted({file.path for file in files}))
        decision = PruningDecision(commit.original.commit_id, paths, "unresolved_input_roles_assumed", (), edits, codes)
        context.input_role_policy.on_pruned(decorate_source_decision(decision, plan.roles))
    if before_masks is not None:
        before_masks()
    for code in codes:
        commit.apply_code_mask(code)
    for edit in edits:
        commit.apply_edit_mask(edit)
