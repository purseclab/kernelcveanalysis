from pathlib import Path
from enum import StrEnum
from typing import Self
from dataclasses import dataclass
from difflib import SequenceMatcher
import re

from pydantic import BaseModel, PrivateAttr

DATASET_PATH = Path(__file__).parent.parent.parent / "lpe_dataset" / "linux_lpe_rce_fix_commits.json"

@dataclass(slots=True)
class PatchChunk:
    header: str
    lines: list[str]
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    section: str | None

    @property
    def line_count(self) -> int:
        return len(self.lines)

    @property
    def changed_line_count(self) -> int:
        return sum(line.startswith(("+", "-")) for line in self.lines)


@dataclass(slots=True)
class PatchFile:
    old_path: str | None
    new_path: str | None
    header_lines: list[str]
    chunks: list[PatchChunk]

    @property
    def path(self) -> str:
        return self.new_path or self.old_path or ""


@dataclass(slots=True)
class Patch:
    text: str
    files: list[PatchFile]

    @classmethod
    def parse(cls, patch_text: str) -> Self:
        """Parse a unified diff into files and hunks."""

        lines = patch_text.splitlines()
        file_starts = [
            index for index, line in enumerate(lines) if line.startswith("diff --git ")
        ]
        if not file_starts and lines:
            file_starts = [
                index
                for index, line in enumerate(lines[:-1])
                if line.startswith("--- ") and lines[index + 1].startswith("+++ ")
            ]

        def parse_path(value: str, prefix: str) -> str | None:
            value = value.split("\t", 1)[0].strip()
            if value == "/dev/null":
                return None
            return value.removeprefix(prefix)

        parsed_files: list[PatchFile] = []
        for file_index, start in enumerate(file_starts):
            end = file_starts[file_index + 1] if file_index + 1 < len(file_starts) else len(lines)
            file_lines = lines[start:end]
            hunk_starts = [
                index for index, line in enumerate(file_lines) if line.startswith("@@ ")
            ]
            header_end = hunk_starts[0] if hunk_starts else len(file_lines)
            header_lines = file_lines[:header_end]
            old_path = None
            new_path = None

            for line in header_lines:
                if line.startswith("--- "):
                    old_path = parse_path(line[4:], "a/")
                elif line.startswith("+++ "):
                    new_path = parse_path(line[4:], "b/")

            if old_path is None and new_path is None and file_lines:
                diff_match = re.match(r"^diff --git (.+?) (.+)$", file_lines[0])
                if diff_match:
                    old_path = parse_path(diff_match.group(1), "a/")
                    new_path = parse_path(diff_match.group(2), "b/")

            chunks: list[PatchChunk] = []
            for chunk_index, chunk_start in enumerate(hunk_starts):
                chunk_end = (
                    hunk_starts[chunk_index + 1]
                    if chunk_index + 1 < len(hunk_starts)
                    else len(file_lines)
                )
                chunk_header = file_lines[chunk_start]
                chunk_match = re.match(
                    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: ?(.*))?$",
                    chunk_header,
                )
                if chunk_match is None:
                    continue
                chunks.append(
                    PatchChunk(
                        header=chunk_header,
                        lines=file_lines[chunk_start + 1 : chunk_end],
                        old_start=int(chunk_match.group(1)),
                        old_count=int(chunk_match.group(2) or "1"),
                        new_start=int(chunk_match.group(3)),
                        new_count=int(chunk_match.group(4) or "1"),
                        section=chunk_match.group(5) or None,
                    )
                )

            parsed_files.append(
                PatchFile(
                    old_path=old_path,
                    new_path=new_path,
                    header_lines=header_lines,
                    chunks=chunks,
                )
            )

        return cls(text=patch_text, files=parsed_files)

    def patch_similarity(self, other: Self) -> float:
        """Compare corresponding files after combining all of their hunks."""

        self_files = {file.path: file for file in self.files}
        other_files = {file.path: file for file in other.files}
        if len(self_files) != len(self.files) or len(other_files) != len(other.files):
            return 0.0
        if set(self_files) != set(other_files):
            return 0.0

        weighted_similarity = 0.0
        total_changed_lines = 0
        for path, self_file in self_files.items():
            other_file = other_files[path]
            self_lines = [
                line
                for chunk in self_file.chunks
                for line in chunk.lines
            ]
            other_lines = [
                line
                for chunk in other_file.chunks
                for line in chunk.lines
            ]
            changed_lines = max(
                sum(line.startswith(("+", "-")) for line in self_lines),
                sum(line.startswith(("+", "-")) for line in other_lines),
                1,
            )
            similarity = SequenceMatcher(
                None,
                self_lines,
                other_lines,
                autojunk=False,
            ).ratio()
            weighted_similarity += similarity * changed_lines
            total_changed_lines += changed_lines

        return weighted_similarity / total_changed_lines if total_changed_lines else 1.0


@dataclass(slots=True)
class ParsedPatchText:
    fixing_commit: str | None
    upstream_commit: str | None
    author: str | None
    date: str | None
    subject: str | None
    description: str
    patch: Patch
    trailers: dict[str, list[str]]
    raw_text: str

    @classmethod
    def parse(cls, patch_text: str) -> Self:
        """Parse a git email patch or a raw unified diff."""

        lines = patch_text.splitlines()
        fixing_commit = None
        upstream_commit = None
        author = None
        date = None
        subject = None

        commit_match = re.match(r"^From ([0-9a-fA-F]{7,64})(?:\s|$)", lines[0]) if lines else None
        if commit_match:
            fixing_commit = commit_match.group(1).lower()

        upstream_pattern = re.compile(
            r"^(?:\[\s*Upstream commit\s+([0-9a-fA-F]{7,64})\s*\]|"
            r"commit\s+([0-9a-fA-F]{7,64})\s+upstream\.?)$",
            re.IGNORECASE,
        )
        upstream_match = next(
            (
                match
                for line in lines
                if (match := upstream_pattern.match(line.strip())) is not None
            ),
            None,
        )
        if upstream_match:
            upstream_commit = (upstream_match.group(1) or upstream_match.group(2)).lower()

        header_end = None
        if commit_match:
            header_end = next(
                (index for index, line in enumerate(lines[1:], start=1) if not line),
                None,
            )

        if header_end is not None:
            header_lines = lines[:header_end]
            for index, line in enumerate(header_lines):
                if line.startswith("From: ") and author is None:
                    author = line.removeprefix("From: ")
                elif line.startswith("Date: ") and date is None:
                    date = line.removeprefix("Date: ")
                elif line.startswith("Subject: ") and subject is None:
                    subject_parts = [line.removeprefix("Subject: ")]
                    continuation = index + 1
                    while continuation < len(header_lines) and header_lines[continuation].startswith((" ", "\t")):
                        subject_parts.append(header_lines[continuation].strip())
                        continuation += 1
                    subject = " ".join(subject_parts)

        diff_start = next(
            (index for index, line in enumerate(lines) if line.startswith("diff --git ")),
            None,
        )
        if diff_start is None:
            diff_start = next(
                (
                    index
                    for index, line in enumerate(lines[:-1])
                    if line.startswith("--- ") and lines[index + 1].startswith("+++ ")
                ),
                len(lines),
            )

        patch_end = len(lines)
        if diff_start < len(lines):
            patch_end = next(
                (index for index, line in enumerate(lines[diff_start + 1:], start=diff_start + 1) if line == "-- "),
                len(lines),
            )
        patch_lines = lines[diff_start:patch_end]
        actual_patch = "\n".join(patch_lines)

        description = ""
        trailers: dict[str, list[str]] = {}
        if header_end is not None:
            body_start = header_end + 1
            separators = [
                index
                for index in range(body_start, diff_start)
                if lines[index] == "---"
            ]
            separator = separators[-1] if separators else diff_start
            body_lines = lines[body_start:separator]

            body_end = len(body_lines)
            while body_end and not body_lines[body_end - 1].strip():
                body_end -= 1
            trailer_start = body_end
            trailer_pattern = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):\s*(.*)$")
            while trailer_start:
                line = body_lines[trailer_start - 1]
                if trailer_pattern.match(line) or (
                    line.startswith((" ", "\t")) and trailer_start < body_end
                ):
                    trailer_start -= 1
                else:
                    break

            trailer_lines = body_lines[trailer_start:body_end]
            current_key = None
            for line in trailer_lines:
                trailer_match = trailer_pattern.match(line)
                if trailer_match:
                    current_key = trailer_match.group(1)
                    trailers.setdefault(current_key, []).append(trailer_match.group(2))
                elif current_key is not None:
                    trailers[current_key][-1] += f"\n{line.strip()}"

            description = "\n".join(body_lines[:trailer_start]).strip()

        return cls(
            fixing_commit=fixing_commit,
            upstream_commit=upstream_commit,
            author=author,
            date=date,
            subject=subject,
            description=description,
            patch=Patch.parse(actual_patch),
            trailers=trailers,
            raw_text=patch_text,
        )


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

    _cached_parsed_patch: ParsedPatchText | None = PrivateAttr()

    @property
    def parsed_patch(self) -> ParsedPatchText:
        if self._cached_parsed_patch is None:
            self._cached_parsed_patch = ParsedPatchText.parse(self.patch_text)

        return self._cached_parsed_patch

class Dataset(BaseModel):
    records: list[Commit]

    @classmethod
    def load(cls, file: Path) -> Self:
        return cls.model_validate_json(file.read_text())

    def deduplicate(self, threshhold: float = 0.9) -> list[Commit]:
        out: list[Commit] = []
        out_parsed: list[ParsedPatchText] = []

        for commit in self.records:
            patch = ParsedPatchText.parse(commit.patch_text)

            dedup = False
            for parsed_commit in out_parsed:
                if patch.patch.patch_similarity(parsed_commit.patch) >= threshhold:
                    dedup = True
                    break

            if not dedup:
                out.append(commit)
                out_parsed.append(patch)

        return out



def analyze_dataset():
    dataset = Dataset.load(DATASET_PATH)
    dedup = dataset.deduplicate()
    # dataset.inspect_threshhold_diff(0.7, 0.8)
    for commit in dedup:
        print("\n\n\n\n\n")
        print(commit.patch_text)
        # print(ParsedCommitText.parse(commit.patch_text).patch.text)
    print(len(dedup))
