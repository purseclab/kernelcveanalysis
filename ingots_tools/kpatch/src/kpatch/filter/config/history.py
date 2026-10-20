"""Disk-backed, disposable preparation data; original patch payloads stay in GitDb."""

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
import re
import sqlite3
from tempfile import TemporaryDirectory
from types import TracebackType
from typing import Self, cast
import weakref

from pydantic import TypeAdapter

from ..config_filter import ConfigValue
from ...diff import Diff
from ...git import GitCommit


@dataclass(frozen=True, slots=True)
class HistoryCommit:
    commit_id: str
    parent_ids: tuple[str, ...]

    @classmethod
    def from_commit(cls, commit: GitCommit) -> Self:
        return cls(commit.commit_id, tuple(parent.commit_id for parent in commit.parents))

    @property
    def parent_id(self) -> str | None:
        return self.parent_ids[0] if self.parent_ids else None

    @property
    def is_merge(self) -> bool:
        return len(self.parent_ids) > 1


@dataclass(slots=True)
class PrimaryHistory:
    commits: dict[str, HistoryCommit]
    primary_children: dict[str, list[str]]
    subtree_sizes: dict[str, int]
    root_commits: tuple[str, ...]


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
_HEADER_ADAPTER = TypeAdapter(HistoryCommit)
_DECISIONS_ADAPTER = TypeAdapter(list[_StoredDecision])
_SQLITE_CACHE_KIB = 4096
_DECISIONS_SCHEMA = """
    CREATE TABLE decisions (
        commit_id TEXT PRIMARY KEY,
        payload BLOB NOT NULL
    ) WITHOUT ROWID;
"""
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


def _configure_connection(connection: sqlite3.Connection) -> None:
    connection.executescript(
        f"""
        PRAGMA cache_size = -{_SQLITE_CACHE_KIB};
        PRAGMA mmap_size = 0;
        PRAGMA temp_store = FILE;
        """
    )


def _open_readonly(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(
        f"{path.resolve().as_uri()}?mode=ro", uri=True, check_same_thread=False
    )
    try:
        _configure_connection(connection)
        connection.execute("PRAGMA query_only = ON")
    except BaseException:
        connection.close()
        raise
    return connection


def _open_scratch(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path, check_same_thread=False)
    try:
        _configure_connection(connection)
        connection.executescript("PRAGMA journal_mode = OFF; PRAGMA synchronous = OFF;")
    except BaseException:
        connection.close()
        raise
    return connection


def _get_history(connection: sqlite3.Connection, commit_id: str) -> Diff:
    row = connection.execute(
        "SELECT payload FROM history WHERE commit_id = ?", (commit_id,)
    ).fetchone()
    if row is None:
        raise KeyError(commit_id)
    return _DIFF_ADAPTER.validate_json(row[0])


def _add_decisions(
    connection: sqlite3.Connection,
    commit_id: str,
    decisions: dict[tuple[str | None, str], FileDecision],
) -> None:
    if not decisions:
        return
    records = [
        _StoredDecision(old_file, file, decision.old, decision.new)
        for (old_file, file), decision in decisions.items()
    ]
    connection.execute(
        "INSERT INTO decisions (commit_id, payload) VALUES (?, ?)",
        (commit_id, _DECISIONS_ADAPTER.dump_json(records)),
    )


def _close_store(
    history: sqlite3.Connection,
    decisions: sqlite3.Connection,
    directory: TemporaryDirectory[str],
) -> None:
    try:
        history.close()
    finally:
        try:
            decisions.close()
        finally:
            directory.cleanup()


class ConfigHistoryReader:
    """Read immutable history summaries without opening the decisions database."""

    def __init__(self, path: Path) -> None:
        self._connection = _open_readonly(path)
        self._finalizer = weakref.finalize(self, self._connection.close)

    def get_history(self, commit_id: str) -> Diff:
        return _get_history(self._connection, commit_id)

    def load_root(self, root_id: str) -> PrimaryHistory:
        rows = self._connection.execute(
            """
            WITH RECURSIVE subtree(commit_id) AS (
                SELECT commit_id FROM history WHERE commit_id = ?
                UNION
                SELECT child.commit_id FROM history AS child
                JOIN subtree ON child.primary_parent = subtree.commit_id
            )
            SELECT history.header, history.subtree_size
            FROM history JOIN subtree USING (commit_id)
            ORDER BY history.position
            """,
            (root_id,),
        )
        commits: dict[str, HistoryCommit] = {}
        sizes: dict[str, int] = {}
        for header_json, subtree_size in rows:
            header = _HEADER_ADAPTER.validate_json(header_json)
            commits[header.commit_id] = header
            sizes[header.commit_id] = cast(int, subtree_size)
        if not commits:
            raise KeyError(root_id)

        children: dict[str, list[str]] = {commit_id: [] for commit_id in commits}
        for header in commits.values():
            parent_id = header.parent_id
            if parent_id is not None and parent_id in children:
                children[parent_id].append(header.commit_id)
        return PrimaryHistory(commits, children, sizes, (root_id,))

    def close(self) -> None:
        self._finalizer()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


class DecisionShard:
    """One worker job's disk-backed decisions, merged by the owning process."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._connection = _open_scratch(path)
        self._finalizer = weakref.finalize(self, self._connection.close)
        try:
            self._connection.executescript(_DECISIONS_SCHEMA)
        except BaseException:
            self.close()
            raise

    def add_decisions(
        self, commit_id: str, decisions: dict[tuple[str | None, str], FileDecision]
    ) -> None:
        _add_decisions(self._connection, commit_id, decisions)

    def commit(self) -> None:
        self._connection.commit()

    def close(self) -> None:
        self._finalizer()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


class ConfigHistoryStore:
    """Bound RAM used by history summaries and configuration decisions.

    This is scratch data, not a reusable cache. Both temporary databases and
    job artifacts are deleted on close, failed preparation, or collection.
    """

    def __init__(self) -> None:
        directory = TemporaryDirectory(prefix="kpatch-history-")
        self.path = Path(directory.name) / "history.sqlite"
        self.decisions_path = Path(directory.name) / "decisions.sqlite"
        try:
            connection = _open_scratch(self.path)
        except BaseException:
            directory.cleanup()
            raise
        try:
            decisions = _open_scratch(self.decisions_path)
        except BaseException:
            connection.close()
            directory.cleanup()
            raise
        self._connection = connection
        self._decisions_connection = decisions
        self._finalizer = weakref.finalize(
            self, _close_store, connection, decisions, directory
        )
        try:
            connection.executescript(
                """
                CREATE TABLE history (
                    position INTEGER PRIMARY KEY,
                    commit_id TEXT UNIQUE NOT NULL,
                    header BLOB NOT NULL,
                    primary_parent TEXT,
                    subtree_size INTEGER NOT NULL CHECK (subtree_size > 0),
                    payload BLOB NOT NULL
                );
                CREATE INDEX history_primary_parent ON history(primary_parent);
                """
            )
            decisions.executescript(_DECISIONS_SCHEMA)
        except BaseException:
            self.close()
            raise

    def add_history(self, header: HistoryCommit, diff: Diff, subtree_size: int) -> None:
        self._connection.execute(
            """
            INSERT INTO history (commit_id, header, primary_parent, subtree_size, payload)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                header.commit_id,
                _HEADER_ADAPTER.dump_json(header),
                header.parent_id,
                subtree_size,
                _DIFF_ADAPTER.dump_json(diff),
            ),
        )

    def iter_history(self) -> Iterator[Diff]:
        # Preserve original insertion order: include aliases across renames can
        # depend on the order in which historical include candidates are added.
        rows = self._connection.execute("SELECT payload FROM history ORDER BY position")
        for row in rows:
            yield _DIFF_ADAPTER.validate_json(row[0])

    def get_history(self, commit_id: str) -> Diff:
        return _get_history(self._connection, commit_id)

    def add_decisions(
        self,
        commit_id: str,
        decisions: dict[tuple[str | None, str], FileDecision],
    ) -> None:
        _add_decisions(self._decisions_connection, commit_id, decisions)

    def merge_decisions(self, path: Path) -> None:
        connection = _open_readonly(path)
        try:
            # Pass the cursor through directly: neither decision objects nor a
            # job-sized result dictionary are materialized in the parent.
            self._decisions_connection.executemany(
                "INSERT INTO decisions (commit_id, payload) VALUES (?, ?)",
                connection.execute("SELECT commit_id, payload FROM decisions"),
            )
        finally:
            connection.close()
        path.unlink()

    def get_decisions(self, commit_id: str) -> dict[tuple[str | None, str], FileDecision]:
        row = self._decisions_connection.execute(
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
        self._decisions_connection.commit()

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
