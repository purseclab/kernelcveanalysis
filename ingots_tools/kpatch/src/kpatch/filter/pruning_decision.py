"""Shared, original-coordinate audit record for source pruning stages."""

from dataclasses import dataclass

from .masking import CodeMask, EditMask


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
