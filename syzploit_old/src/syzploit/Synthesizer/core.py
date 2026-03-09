"""
core.py

Unified core data models for the Synthesizer module.
All exploit plan representations use these canonical types.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Union
from typing_extensions import TypedDict, NotRequired
from enum import Enum


# ---------------------------------------------------------------------------
# Canonical step format
# ---------------------------------------------------------------------------

class ExploitStep(TypedDict, total=False):
    """
    Canonical representation of a single exploit plan step.

    Every step MUST have at least ``name`` and ``action`` (kept in sync).
    The remaining fields are optional and carry extra metadata when available.
    """
    name: str                           # Canonical function / action name
    action: str                         # Alias kept in sync with *name*
    description: str                    # Human-readable description
    requires: List[str]                 # Pre-conditions / dependencies
    provides: List[str]                 # Post-conditions / capabilities
    provider: str                       # Component that owns this step
    code_hint: str                      # Inline code snippet hint


def normalize_step(raw: Union[str, Dict[str, Any]]) -> ExploitStep:
    """
    Convert any step representation to the canonical ``ExploitStep`` form.

    Accepted inputs
    ---------------
    * ``str``  – plain step/action name  
    * ``dict`` with ``name`` key (exploit_generator style)  
    * ``dict`` with ``action`` key (synth.py / stitcher style)  
    * ``dict`` with both
    """
    if isinstance(raw, str):
        canon_name = raw.strip().lower().replace("-", "_").strip("()")
        return ExploitStep(
            name=canon_name,
            action=canon_name,
            description=raw,
        )

    if not isinstance(raw, dict):
        return ExploitStep(name="unknown", action="unknown", description=str(raw))

    # Determine canonical name: prefer 'name', fall back to 'action'
    name = raw.get("name", raw.get("action", "unknown"))
    if isinstance(name, dict):
        # Edge-case: step is nested (e.g. {"action": {"name": ...}})
        name = name.get("name", "unknown")
    name = str(name).strip().lower().replace("-", "_").strip("()")

    step: ExploitStep = {
        "name": name,
        "action": name,
    }

    # Carry over optional fields when present
    if "description" in raw:
        step["description"] = str(raw["description"])
    if "requires" in raw:
        req = raw["requires"]
        step["requires"] = req if isinstance(req, list) else [str(req)]
    if "provides" in raw:
        prov = raw["provides"]
        step["provides"] = prov if isinstance(prov, list) else [str(prov)]
    if "provider" in raw:
        step["provider"] = str(raw["provider"])
    if "code_hint" in raw:
        step["code_hint"] = str(raw["code_hint"])

    return step


def normalize_steps(raw_steps: List[Any]) -> List[ExploitStep]:
    """Normalize an entire list of heterogeneous step representations."""
    return [normalize_step(s) for s in raw_steps]


class VulnType(Enum):
    """Known vulnerability types."""
    UAF = "uaf"
    OOB_READ = "oob_read"
    OOB_WRITE = "oob_write"
    DOUBLE_FREE = "double_free"
    RACE_CONDITION = "race_condition"
    TYPE_CONFUSION = "type_confusion"
    INTEGER_OVERFLOW = "integer_overflow"
    USE_BEFORE_INIT = "use_before_init"
    NULL_DEREF = "null_deref"
    LOGIC_BUG = "logic_bug"
    UNKNOWN = "unknown"

    @classmethod
    def from_str(cls, s: str) -> "VulnType":
        """Parse a vulnerability type string (case-insensitive)."""
        s_lower = s.lower().replace("-", "_").replace(" ", "_")
        for member in cls:
            if member.value == s_lower:
                return member
        if "uaf" in s_lower or "use_after_free" in s_lower:
            return cls.UAF
        if "oob" in s_lower and "read" in s_lower:
            return cls.OOB_READ
        if "oob" in s_lower and "write" in s_lower:
            return cls.OOB_WRITE
        if "double" in s_lower and "free" in s_lower:
            return cls.DOUBLE_FREE
        if "race" in s_lower:
            return cls.RACE_CONDITION
        if "type" in s_lower and "confusion" in s_lower:
            return cls.TYPE_CONFUSION
        if "integer" in s_lower or "overflow" in s_lower:
            return cls.INTEGER_OVERFLOW
        if "uninit" in s_lower or "use_before" in s_lower:
            return cls.USE_BEFORE_INIT
        if "null" in s_lower:
            return cls.NULL_DEREF
        return cls.UNKNOWN


@dataclass
class Primitive:
    """A capability primitive contributed by an adapter (syzanalyze, kernel-research, etc.)."""
    name: str
    description: str
    requirements: Dict[str, Any] = field(default_factory=dict)
    provides: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExploitPlan:
    """
    Canonical exploit plan representation.

    This is the single, unified ExploitPlan used across the entire Synthesizer.
    Previously there were three incompatible definitions; now everything
    uses this one.
    """
    # What vulnerability we're exploiting
    vulnerability_type: str = "unknown"
    target_struct: str = ""
    slab_cache: str = ""

    # How we plan to exploit it
    technique: str = ""
    steps: List[Dict[str, Any]] = field(default_factory=list)

    # What we're trying to achieve
    goal: str = "privilege_escalation"

    # Target environment
    platform: str = "linux"
    target_arch: str = "x86_64"
    target_kernel: str = ""

    # Structural offsets (from BTF or manual)
    offsets: Dict[str, int] = field(default_factory=dict)

    # Metadata
    target_info: Dict[str, Any] = field(default_factory=dict)
    primitives: List[Primitive] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    constants: Dict[str, Any] = field(default_factory=dict)

    # LLM-planner extras
    exploitation_technique: str = ""
    description: str = ""
    code_hints: Dict[str, str] = field(default_factory=dict)

    # PoC integration
    poc_path: Optional[str] = None
    poc_source: Optional[str] = None

    # ------------------------------------------------------------------
    # Normalization
    # ------------------------------------------------------------------
    def normalize(self) -> "ExploitPlan":
        """
        Normalize ``steps`` in-place so every element is a canonical
        ``ExploitStep`` dict with at least ``name`` and ``action`` keys.

        Returns *self* for chaining.
        """
        self.steps = normalize_steps(self.steps)  # type: ignore[arg-type]
        return self

    def get_action_names(self) -> List[str]:
        """Return an ordered list of action/step names (after normalization)."""
        self.normalize()
        return [s.get("name", s.get("action", "unknown")) for s in self.steps]


class PrimitiveRegistry:
    """Registry of capability primitives from all adapters."""

    def __init__(self) -> None:
        self._primitives: Dict[str, Primitive] = {}

    def add(self, prim: Primitive) -> None:
        self._primitives[prim.name] = prim

    def get(self, name: str) -> Optional[Primitive]:
        return self._primitives.get(name)

    def list(self) -> List[Primitive]:
        return list(self._primitives.values())

    def list_capabilities(self) -> List[str]:
        """Return a flat list of all capability strings across primitives."""
        caps: List[str] = []
        for prim in self._primitives.values():
            pc = prim.provides.get("caps", [])
            if isinstance(pc, str):
                pc = [pc]
            caps.extend(pc)
        return list(set(caps))
