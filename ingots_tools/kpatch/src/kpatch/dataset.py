from pathlib import Path
from enum import StrEnum
from typing import Self
from dataclasses import dataclass
import re

from pydantic import BaseModel

DATASET_PATH = Path(__file__).parent.parent.parent / "lpe_dataset" / "linux_lpe_rce_fix_commits.json"

class VulnCertainty(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class VulnType(StrEnum):
    LPE = "lpe"
    RCE = "rce"

class VulnSource(StrEnum):
    CVE = "cve"
    NON_CVE = "non-cve"

class CommitScope(StrEnum):
    STABLE = "stable-linux"
    UPSTREAM = "upstream-linux"
    ANDROID = "android-kernel"
    LIB = "upstream-project"


# not all fields filled out rn, mostly the ones I care about
class Commit(BaseModel):
    cve: str | None = None
    source_url: str
    # this is the cve summary, or codex generated one for non cve, idk exactly what it did
    summary: str
    evidence_group: str
    certainty: VulnCertainty
    source_kind: VulnSource
    commit_id: str
    # this is url of fixing commit in html form
    commit_url: str
    # this is like similar to above but raw text
    patch_url: str
    # actual patch text
    patch_text: str
    # which tree commit is from
    commit_scope: CommitScope

class Patch:
    pass

class Dataset(BaseModel):
    records: list[Commit]

    @classmethod
    def load(cls, file: Path) -> Self:
        return cls.model_validate_json(file.read_text())

    def deduplicate(self) -> list[Commit]:
        patches: set[str] = set()
        out: list[Commit] = []

        for commit in self.records:
            # don't dedup non cve commits for now
            if commit.cve is None:
                out.append(commit)
                continue
            patch_no_commit = re.sub(r"(?i)\b[0-9a-f]{12,}\b", "", commit.patch_text)
            patch_no_commit = re.sub(r"\b\d+\b\s*", "", patch_no_commit)
            print(commit.patch_text)
            print(patch_no_commit)
            print("\n\n\n\n\n\n")
            if patch_no_commit not in patches:
                patches.add(patch_no_commit)
                out.append(commit)

        return out


def analyze_dataset():
    dataset = Dataset.load(DATASET_PATH)
    print(len(dataset.deduplicate()))
