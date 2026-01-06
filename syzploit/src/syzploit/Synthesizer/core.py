from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class Primitive:
    name: str
    description: str
    requirements: Dict[str, Any] = field(default_factory=dict)
    provides: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ExploitPlan:
    goal: str
    target_info: Dict[str, Any]
    primitives: List[Primitive] = field(default_factory=list)
    steps: List[Dict[str, Any]] = field(default_factory=list)

class PrimitiveRegistry:
    def __init__(self) -> None:
        self._primitives: Dict[str, Primitive] = {}
    def add(self, prim: Primitive) -> None:
        self._primitives[prim.name] = prim
    def get(self, name: str) -> Optional[Primitive]:
        return self._primitives.get(name)
    def list(self) -> List[Primitive]:
        return list(self._primitives.values())
