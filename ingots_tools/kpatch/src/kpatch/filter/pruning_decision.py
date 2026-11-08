"""Shared, original-coordinate audit record for source pruning stages."""

from dataclasses import dataclass

from .masking import CodeMask, EditMask
from .input_role_models import SourceRoleEvidence


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
    input_role_evidence: tuple[SourceRoleEvidence, ...] = ()
