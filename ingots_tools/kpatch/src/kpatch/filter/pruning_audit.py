"""Append-only decision output with short-lived file handles."""

from dataclasses import asdict, dataclass
import json
from pathlib import Path

from .output_paths import repository_input_roots, validate_output_paths
from .pruning_decision import PruningDecision


@dataclass(frozen=True, slots=True)
class PruningAudit:
    path: Path

    @classmethod
    def validate_destination(cls, path: Path, source_root: Path, protected: tuple[Path, ...]) -> Path:
        return validate_output_paths((path,), protected=protected,
                                     protected_roots=repository_input_roots(source_root))[0]

    @classmethod
    def create(cls, path: Path, source_root: Path, protected: tuple[Path, ...]) -> "PruningAudit":
        path = cls.validate_destination(path, source_root, protected)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("")
        return cls(path)

    def __call__(self, decision: PruningDecision) -> None:
        # Decisions are infrequent compared with inspected commits. Closing per
        # event avoids holding a report stream through unrelated pipeline stages.
        with self.path.open("a") as stream:
            print(json.dumps(asdict(decision)), file=stream)
