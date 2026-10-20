"""Disk-backed, disposable preparation data; original patch payloads stay in GitDb."""

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
import re
import sqlite3
from tempfile import TemporaryDirectory
from types import TracebackType
import weakref

from pydantic import TypeAdapter

from ..config_filter import ConfigValue
from ...diff import Diff


@dataclass(frozen=True, slots=True)
class FileDecision:
    old: ConfigValue | None
    new: ConfigValue | None


@dataclass(frozen=True, slots=True)
class _StoredDecision:
    old_file: str | None
    file: str
    old: ConfigValue | None
    new: ConfigValue | None


_DIFF_ADAPTER = TypeAdapter(Diff)
_DECISIONS_ADAPTER = TypeAdapter(list[_StoredDecision])
_PATCH_LINE_RE = re.compile(
    r"([^\r\n\v\f\x1c-\x1e\x85\u2028\u2029]*)(?:\r\n|[\r\n\v\f\x1c-\x1e\x85\u2028\u2029]|$)"
)


def _history_patch_text(patch_text: str) -> str:
    """Select headers/directives before allocating a full parsed merge patch."""

    if not patch_text.startswith("diff --git "):
        # Retain the general parser's behavior for legacy raw unified diffs.
        return patch_text

    retained: list[str] = []
    in_header = True
    in_binary = False
    pending_hunk: str | None = None
    for match in _PATCH_LINE_RE.finditer(patch_text):
        if match.start() == match.end():
            continue
        line = match.group(1)
        if line.startswith("diff --git "):
            in_header, in_binary, pending_hunk = True, False, None
        elif in_binary:
            continue
        elif line.startswith("@@ "):
            in_header, pending_hunk = False, line
            continue
        elif not in_header:
            if not line.startswith(("+", "-")) or not line[1:].lstrip().startswith("#"):
                continue
            if pending_hunk is not None:
                retained.append(pending_hunk)
                pending_hunk = None
        if line == "GIT binary patch":
            in_binary = True
        retained.append(line)
    return "\n".join(retained)


def parse_history_diff(patch_text: str) -> Diff:
    """Parse only the structure and changed directives needed by preparation."""

    diff = Diff.parse(_history_patch_text(patch_text))
    diff.text = ""
    for diff_file in diff.files:
        diff_file.header_lines = []
        directives = []
        for chunk in diff_file.chunks:
            chunk.lines = [
                line
                for line in chunk.lines
                if line.startswith(("+", "-")) and line[1:].lstrip().startswith("#")
            ]
            if chunk.lines:
                directives.append(chunk)
        diff_file.chunks = directives
    return diff


def _close_store(
    connection: sqlite3.Connection, directory: TemporaryDirectory[str]
) -> None:
    try:
        connection.close()
    finally:
        directory.cleanup()


class ConfigHistoryStore:
    """Bound RAM used by history summaries and configuration decisions.

    This is scratch data, not a reusable cache. The temporary database is
    deleted on close, on failed preparation, or when its owner is collected.
    """

    def __init__(self) -> None:
        directory = TemporaryDirectory(prefix="kpatch-history-")
        self.path = Path(directory.name) / "history.sqlite"
        try:
            connection = sqlite3.connect(self.path)
        except BaseException:
            directory.cleanup()
            raise
        self._connection = connection
        self._finalizer = weakref.finalize(self, _close_store, connection, directory)
        try:
            connection.executescript(
                """
                PRAGMA journal_mode = OFF;
                PRAGMA synchronous = OFF;
                PRAGMA cache_size = -4096;
                PRAGMA temp_store = FILE;
                CREATE TABLE history (
                    position INTEGER PRIMARY KEY,
                    commit_id TEXT UNIQUE NOT NULL,
                    payload BLOB NOT NULL
                );
                CREATE TABLE decisions (
                    commit_id TEXT PRIMARY KEY,
                    payload BLOB NOT NULL
                ) WITHOUT ROWID;
                """
            )
        except BaseException:
            self.close()
            raise

    def add_history(self, commit_id: str, diff: Diff) -> None:
        self._connection.execute(
            "INSERT INTO history (commit_id, payload) VALUES (?, ?)",
            (commit_id, _DIFF_ADAPTER.dump_json(diff)),
        )

    def iter_history(self) -> Iterator[Diff]:
        # Preserve original insertion order: include aliases across renames can
        # depend on the order in which historical include candidates are added.
        rows = self._connection.execute("SELECT payload FROM history ORDER BY position")
        for row in rows:
            yield _DIFF_ADAPTER.validate_json(row[0])

    def get_history(self, commit_id: str) -> Diff:
        row = self._connection.execute(
            "SELECT payload FROM history WHERE commit_id = ?", (commit_id,)
        ).fetchone()
        if row is None:
            raise KeyError(commit_id)
        return _DIFF_ADAPTER.validate_json(row[0])

    def add_decisions(
        self,
        commit_id: str,
        decisions: dict[tuple[str | None, str], FileDecision],
    ) -> None:
        if not decisions:
            return
        records = [
            _StoredDecision(old_file, file, decision.old, decision.new)
            for (old_file, file), decision in decisions.items()
        ]
        self._connection.execute(
            "INSERT INTO decisions (commit_id, payload) VALUES (?, ?)",
            (commit_id, _DECISIONS_ADAPTER.dump_json(records)),
        )

    def get_decisions(self, commit_id: str) -> dict[tuple[str | None, str], FileDecision]:
        row = self._connection.execute(
            "SELECT payload FROM decisions WHERE commit_id = ?", (commit_id,)
        ).fetchone()
        if row is None:
            return {}
        return {
            (record.old_file, record.file): FileDecision(record.old, record.new)
            for record in _DECISIONS_ADAPTER.validate_json(row[0])
        }

    def commit(self) -> None:
        self._connection.commit()

    def close(self) -> None:
        self._finalizer()

    def __enter__(self) -> "ConfigHistoryStore":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
