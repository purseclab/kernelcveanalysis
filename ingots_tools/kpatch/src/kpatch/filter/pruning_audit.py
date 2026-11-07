"""Append-only decision output with short-lived file handles."""

from dataclasses import asdict, dataclass
import json
from pathlib import Path

from .source_pruning import PruningDecision


@dataclass(frozen=True, slots=True)
class PruningAudit:
    path: Path

    @classmethod
    def create(cls, path: Path, source_root: Path, protected: tuple[Path, ...]) -> "PruningAudit":
        path = path.resolve()
        if path.exists() and path.stat().st_nlink > 1:
            raise ValueError("Source-pruning report must not be hardlinked to another file")
        if path.is_relative_to(source_root.resolve()) or path in {item.resolve() for item in protected}:
            raise ValueError("Source-pruning report must differ from source/build inputs, caches and databases")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("")
        return cls(path)

    def __call__(self, decision: PruningDecision) -> None:
        # Decisions are infrequent compared with inspected commits. Closing per
        # event avoids holding a report stream through unrelated pipeline stages.
        with self.path.open("a") as stream:
            print(json.dumps(asdict(decision)), file=stream)
