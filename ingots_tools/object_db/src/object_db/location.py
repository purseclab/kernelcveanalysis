from dataclasses import dataclass
import hashlib
import re
from pathlib import Path
from typing import Any, Self


@dataclass
class Position:
    line: int
    column: int


@dataclass
class Location:
    file_path: str
    start: Position
    end: Position

    @classmethod
    def from_str(cls, s: str) -> Self:
        s = s.strip('"')
        pattern = r"^(?:file:///src/)?(.*?):(\d+):(\d+):(\d+):(\d+)$"
        match = re.match(pattern, s)

        if not match:
            return cls(file_path=s, start=Position(0, 0), end=Position(0, 0))

        path, l1, c1, l2, c2 = match.groups()
        return cls(
            file_path=path,
            start=Position(line=int(l1), column=int(c1)),
            end=Position(line=int(l2), column=int(c2)),
        )

    @classmethod
    def from_multilspy_location(cls, location: Any) -> Self:
        return cls(
            file_path=location["relative_path"],
            start=Position(
                line=location["range"]["start"]["line"] + 1,
                column=location["range"]["start"]["character"] + 1,
            ),
            end=Position(
                line=location["range"]["end"]["line"] + 1,
                column=location["range"]["end"]["character"] + 1,
            ),
        )

    def __str__(self):
        return f"{self.file_path}:{self.start.line}:{self.start.column}:{self.end.line}:{self.end.column}"

    def to_db_id(self) -> int:
        digest = hashlib.sha256(str(self).encode()).hexdigest()
        return int(digest, 16) & (2**63 - 1)

    def read_source(self, source_context: Any) -> str:
        linux_src = source_context
        if hasattr(source_context, "linux_src"):
            linux_src = source_context.linux_src

        path = Path(linux_src) / self.file_path
        if not path.exists():
            return f"/* Error: File {path} not found */"

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception as e:
            return f"/* Error reading file: {e} */"

        if not lines:
            return ""

        s_line = max(0, self.start.line - 1)
        s_col = max(0, self.start.column - 1)
        e_line = min(len(lines) - 1, self.end.line - 1)
        e_col = self.end.column

        if s_line >= len(lines):
            return f"/* Error: start line {self.start.line} out of range */"

        if s_line == e_line:
            return lines[s_line][s_col:e_col]

        res = []
        res.append(lines[s_line][s_col:])
        for i in range(s_line + 1, e_line):
            res.append(lines[i])
        res.append(lines[e_line][:e_col])
        return "".join(res)
