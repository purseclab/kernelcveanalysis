from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from itertools import groupby
from pathlib import Path
import sqlite3
import subprocess
from typing import Self, Iterable, Iterator, Protocol, runtime_checkable, override
from functools import cached_property

from .diff import Diff

GIT_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S%z"
LOG_RECORD_START = bytes.fromhex("9a3d71ce04f862b5")
LOG_MESSAGE_END = bytes.fromhex("27d08c5ae139a6f4")
LOG_FIELD_SEPARATOR = bytes.fromhex("6bfe129443ad78c1")


def _git_format_bytes(value: bytes) -> str:
    return "".join(f"%x{byte:02x}" for byte in value)


GIT_LOG_FORMAT = (
    f"{_git_format_bytes(LOG_RECORD_START)}%H"
    f"{_git_format_bytes(LOG_FIELD_SEPARATOR)}%an"
    f"{_git_format_bytes(LOG_FIELD_SEPARATOR)}%ae"
    f"{_git_format_bytes(LOG_FIELD_SEPARATOR)}%aI"
    f"{_git_format_bytes(LOG_FIELD_SEPARATOR)}%cI"
    f"{_git_format_bytes(LOG_FIELD_SEPARATOR)}%P"
    f"{_git_format_bytes(LOG_FIELD_SEPARATOR)}%B"
    f"{_git_format_bytes(LOG_MESSAGE_END)}"
)
_LOG_RECORD_START_BYTES = LOG_RECORD_START
_LOG_MESSAGE_END_BYTES = LOG_MESSAGE_END
_LOG_FIELD_SEPARATOR_BYTES = LOG_FIELD_SEPARATOR
_GIT_TIMESTAMP_RESOLUTION = timedelta(seconds=1)
_UPSERT_COMMIT_SQL = """
    INSERT INTO commits (
        commit_id,
        author_name,
        author_email,
        author_date,
        committer_date,
        author_timestamp,
        committer_timestamp,
        message,
        is_merge
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(commit_id) DO UPDATE SET
        author_name = excluded.author_name,
        author_email = excluded.author_email,
        author_date = excluded.author_date,
        committer_date = excluded.committer_date,
        author_timestamp = excluded.author_timestamp,
        committer_timestamp = excluded.committer_timestamp,
        message = excluded.message,
        is_merge = excluded.is_merge
"""


@dataclass
class CommitParent:
    """A parent edge and the patch from that parent to its child commit."""

    commit_id: str
    diff_str: str

    @cached_property
    def diff(self) -> Diff:
        return Diff.parse(self.diff_str)


@dataclass
class GitCommit:
    """A commit whose ordered parent edges each carry their own patch."""

    commit_id: str
    author_name: str
    author_email: str
    author_date: datetime
    committer_date: datetime
    parents: tuple[CommitParent, ...]
    message: str

    @property
    def parent(self) -> CommitParent | None:
        """Return the first parent, or ``None`` for a root commit."""

        return self.parents[0] if self.parents else None

    @property
    def secondary_parents(self) -> list[CommitParent]:
        return list(self.parents[1:])

    @property
    def diff_str(self) -> str:
        """Return the patch from the first parent to this commit."""

        return self.parent.diff_str if self.parent is not None else ""

    @property
    def diff(self) -> Diff:
        """Return the parsed first-parent patch."""

        return self.parent.diff if self.parent is not None else Diff.parse("")

    @property
    def is_merge(self) -> bool:
        return len(self.parents) > 1

    @override
    def __repr__(self) -> str:
        format = "%m-%d-%Y"
        return f"""commit {self.commit_id}
From: {self.author_name} <{self.author_email}>
Author Date: {self.author_date.strftime(format)}
Commit Date: {self.committer_date.strftime(format)}

{self.message}
------------------------------
{self.diff_str}
------------------------------"""


@runtime_checkable
class GitStore(Protocol):
    """A source of commits that can be queried by date."""

    def commits_between(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        include_merges: bool = False,
    ) -> list[GitCommit]:
        """Return commits in ``[start, end)``; optionally include merges."""

        ...


_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def _looks_like_record_start(data: bytearray, index: int) -> bool:
    metadata = data[index + len(_LOG_RECORD_START_BYTES) :]
    fields = metadata.split(_LOG_FIELD_SEPARATOR_BYTES, 6)
    if len(fields) != 7:
        return False

    commit_id, _, _, author_date, committer_date, _, _ = fields
    if len(commit_id) not in (40, 64) or any(
        byte not in b"0123456789abcdefABCDEF" for byte in commit_id
    ):
        return False
    try:
        datetime.fromisoformat(author_date.decode("ascii"))
        datetime.fromisoformat(committer_date.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        return False
    return True


def _find_record_start(data: bytearray, offset: int) -> int:
    candidate = data.find(_LOG_RECORD_START_BYTES, offset)
    while candidate >= 0:
        if _looks_like_record_start(data, candidate):
            return candidate
        candidate = data.find(_LOG_RECORD_START_BYTES, candidate + 1)
    return -1


def _timestamp(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Git dates must be timezone-aware")

    value_utc = value.astimezone(UTC)
    delta = value_utc - _UNIX_EPOCH
    return (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds


@dataclass
class _GitLogRecord:
    commit_id: str
    author_name: str
    author_email: str
    author_date: datetime
    committer_date: datetime
    parent_ids: tuple[str, ...]
    message: str
    diff_str: str


def _parse_git_log_record(record: bytes) -> _GitLogRecord:
    try:
        metadata, diff = record.removeprefix(_LOG_RECORD_START_BYTES).split(
            _LOG_MESSAGE_END_BYTES,
            1,
        )
    except ValueError as error:
        raise ValueError("Unable to split git log message from diff") from error

    fields = metadata.split(_LOG_FIELD_SEPARATOR_BYTES, 6)
    if len(fields) != 7:
        raise ValueError("Unexpected git log record format")

    commit_id, author_name, author_email, author_date, committer_date, parents, message = (
        field.decode("utf-8", errors="replace") for field in fields
    )
    return _GitLogRecord(
        commit_id=commit_id,
        author_name=author_name,
        author_email=author_email,
        author_date=datetime.fromisoformat(author_date),
        committer_date=datetime.fromisoformat(committer_date),
        parent_ids=tuple(parents.split()),
        message=message,
        diff_str=diff.lstrip(b"\n").decode("utf-8", errors="replace"),
    )


def _git_commit_from_record(record: _GitLogRecord) -> GitCommit:
    parents = tuple(
        CommitParent(
            commit_id=parent_id,
            diff_str=record.diff_str if parent_index == 0 else "",
        )
        for parent_index, parent_id in enumerate(record.parent_ids)
    )
    return GitCommit(
        commit_id=record.commit_id,
        author_name=record.author_name,
        author_email=record.author_email,
        author_date=record.author_date,
        committer_date=record.committer_date,
        parents=parents,
        message=record.message,
    )


class GitRepo(GitStore):
    repo: Path

    def __init__(self, repo: Path):
        self.repo = repo

    def _run_git(self, args: list[str]) -> bytes:
        return subprocess.run(
            ["git", "-C", str(self.repo)] + args,
            check=True,
            text=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ).stdout

    def checkout(self, commit: str):
        _ = self._run_git(["checkout", commit])

    def read_file(self, commit: str, path: str) -> bytes:
        return self._run_git(["show", f"{commit}:{path}"])

    def _iter_git_records(self, args: list[str]) -> Iterator[bytes]:
        command = ["git", "-C", str(self.repo)] + args
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert process.stdout is not None
        assert process.stderr is not None
        pending = bytearray()
        record_started = False
        try:
            while chunk := process.stdout.read(64 * 1024):
                pending.extend(chunk)
                while True:
                    if not record_started:
                        record_start = pending.find(_LOG_RECORD_START_BYTES)
                        if record_start < 0:
                            keep = len(_LOG_RECORD_START_BYTES) - 1
                            if keep:
                                del pending[:-keep]
                            else:
                                pending.clear()
                            break
                        del pending[:record_start]
                        record_started = True

                    next_record = _find_record_start(
                        pending,
                        len(_LOG_RECORD_START_BYTES),
                    )
                    if next_record < 0:
                        break
                    yield bytes(pending[:next_record])
                    del pending[:next_record]

            if record_started and pending:
                yield bytes(pending)

            stderr = process.stderr.read()
            return_code = process.wait()
            if return_code:
                raise subprocess.CalledProcessError(
                    return_code,
                    command,
                    stderr=stderr,
                )
        finally:
            process.stdout.close()
            process.stderr.close()
            if process.poll() is None:
                process.kill()
                process.wait()

    @staticmethod
    def _format_git_time(value: datetime) -> str:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Git date boundaries must be timezone-aware")
        return value.strftime(GIT_TIME_FORMAT)

    def iter_commits_between(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        include_merges: bool = False,
    ) -> Iterator[GitCommit]:
        """Yield commits in ``[start, end)`` with their messages and diffs."""

        query_start = start - _GIT_TIMESTAMP_RESOLUTION if start is not None else None

        args = [
            "log",
            "--full-history",
        ]
        if query_start is not None:
            args.append(f"--since-as-filter={self._format_git_time(query_start)}")
        query_end = end
        if end is not None:
            query_end = end + _GIT_TIMESTAMP_RESOLUTION
            args.append(f"--before={self._format_git_time(query_end)}")
        if not include_merges:
            args.append("--no-merges")
        else:
            # Only the first-parent patch is needed to advance a state derived
            # from that parent. Later parent edges retain IDs but no patch.
            args.append("--diff-merges=first-parent")
        args.extend([
            f"--format={GIT_LOG_FORMAT}",
            "--patch",
            "--no-color",
            "--no-ext-diff",
            "--full-index",
            "--binary",
        ])

        for record in self._iter_git_records(args):
            commit = _git_commit_from_record(_parse_git_log_record(record))
            if start is not None and commit.committer_date < start:
                continue
            if end is not None and commit.committer_date >= end:
                continue
            yield commit

    @override
    def commits_between(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        include_merges: bool = False,
    ) -> list[GitCommit]:
        """Return commits in ``[start, end)`` with their messages and diffs."""

        return list(self.iter_commits_between(start, end, include_merges))


class GitDb(GitStore):
    """A SQLite-backed store for commits extracted from a Git repository."""

    db: Path

    def __init__(self, db: Path):
        self.db = Path(db)
        self.db.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db)
        connection.row_factory = sqlite3.Row
        _ = connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            with connection:
                existing_columns = {
                    row["name"]
                    for row in connection.execute("PRAGMA table_info(commits)")
                }
                if "parents" in existing_columns or "diff" in existing_columns:
                    raise RuntimeError(
                        "Legacy commit database schema detected; regenerate "
                        "the database to store per-parent diffs"
                    )

                _ = connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS commits (
                        commit_id TEXT PRIMARY KEY,
                        author_name TEXT NOT NULL,
                        author_email TEXT NOT NULL,
                        author_date TEXT NOT NULL,
                        committer_date TEXT NOT NULL,
                        author_timestamp INTEGER NOT NULL,
                        committer_timestamp INTEGER NOT NULL,
                        message TEXT NOT NULL,
                        is_merge INTEGER NOT NULL DEFAULT 0
                    )
                    """
                )

                _ = connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS commit_parents (
                        commit_id TEXT NOT NULL,
                        parent_index INTEGER NOT NULL CHECK (parent_index >= 0),
                        parent_commit_id TEXT NOT NULL,
                        diff TEXT NOT NULL,
                        PRIMARY KEY (commit_id, parent_index),
                        FOREIGN KEY (commit_id) REFERENCES commits(commit_id)
                            ON DELETE CASCADE
                    )
                    """
                )

                _ = connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS commits_committer_timestamp_idx
                    ON commits (committer_timestamp)
                    """
                )

                _ = connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS commit_parents_parent_commit_id_idx
                    ON commit_parents (parent_commit_id)
                    """
                )
        finally:
            connection.close()

    @staticmethod
    def _store_commits(
        connection: sqlite3.Connection,
        commits: Iterable[GitCommit],
    ) -> int:
        stored = 0
        for commit in commits:
            _ = connection.execute(
                _UPSERT_COMMIT_SQL,
                (
                    commit.commit_id,
                    commit.author_name,
                    commit.author_email,
                    commit.author_date.isoformat(),
                    commit.committer_date.isoformat(),
                    _timestamp(commit.author_date),
                    _timestamp(commit.committer_date),
                    commit.message,
                    commit.is_merge,
                ),
            )
            _ = connection.execute(
                "DELETE FROM commit_parents WHERE commit_id = ?",
                (commit.commit_id,),
            )
            _ = connection.executemany(
                """
                INSERT INTO commit_parents (
                    commit_id,
                    parent_index,
                    parent_commit_id,
                    diff
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    (
                        commit.commit_id,
                        parent_index,
                        parent.commit_id,
                        parent.diff_str,
                    )
                    for parent_index, parent in enumerate(commit.parents)
                ),
            )
            stored += 1
        return stored

    def store_commits(self, commits: Iterable[GitCommit]) -> int:
        """Insert an iterable of commits without materializing it in memory."""

        connection = self._connect()
        try:
            with connection:
                return self._store_commits(connection, commits)
        finally:
            connection.close()

    def replace_commits(self, commits: Iterable[GitCommit]) -> int:
        """Atomically replace every commit currently stored in this database."""

        connection = self._connect()
        try:
            with connection:
                _ = connection.execute("DELETE FROM commits")
                return self._store_commits(connection, commits)
        finally:
            connection.close()

    @override
    def commits_between(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        include_merges: bool = False,
    ) -> list[GitCommit]:
        """Return stored commits in ``[start, end)`` by committer date."""

        where_clauses: list[str] = []
        parameters: list[int] = []
        if not include_merges:
            where_clauses.append("is_merge = 0")
        if start is not None:
            where_clauses.append("committer_timestamp >= ?")
            parameters.append(_timestamp(start))
        if end is not None:
            where_clauses.append("committer_timestamp < ?")
            parameters.append(_timestamp(end))
        where_clause = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        connection = self._connect()
        try:
            rows = connection.execute(
                f"""
                SELECT
                    commits.commit_id,
                    commits.author_name,
                    commits.author_email,
                    commits.author_date,
                    commits.committer_date,
                    commits.message,
                    commits.is_merge,
                    commit_parents.parent_index,
                    commit_parents.parent_commit_id,
                    commit_parents.diff AS parent_diff
                FROM commits
                LEFT JOIN commit_parents
                    ON commit_parents.commit_id = commits.commit_id
                {where_clause}
                ORDER BY
                    commits.committer_timestamp DESC,
                    commits.rowid DESC,
                    commit_parents.parent_index
                """,
                parameters,
            ).fetchall()
        finally:
            connection.close()

        commits: list[GitCommit] = []
        for _, commit_rows_iter in groupby(rows, key=lambda row: row["commit_id"]):
            commit_rows = list(commit_rows_iter)
            row = commit_rows[0]
            parents = tuple(
                CommitParent(
                    commit_id=parent_row["parent_commit_id"],
                    diff_str=parent_row["parent_diff"],
                )
                for parent_row in commit_rows
                if parent_row["parent_index"] is not None
            )
            commit = GitCommit(
                commit_id=row["commit_id"],
                author_name=row["author_name"],
                author_email=row["author_email"],
                author_date=datetime.fromisoformat(row["author_date"]),
                committer_date=datetime.fromisoformat(row["committer_date"]),
                parents=parents,
                message=row["message"],
            )
            if commit.is_merge != bool(row["is_merge"]):
                raise ValueError(
                    f"Stored merge flag does not match parents for {commit.commit_id}"
                )
            commits.append(commit)

        return commits

@dataclass
class CommitChildren:
    # commits who have this commit as first child
    primary_children: list[str]
    # merge commits who have this commit as second or later child
    secondary_children: list[str]

@dataclass
class StructuredCommits:
    commits: dict[str, GitCommit]
    commit_children: dict[str, CommitChildren]
    # commits who have no primary parent
    root_commits: set[str]
    # commits who have no primary child
    leaf_commits: set[str]

    @classmethod
    def from_commits(cls, commits: list[GitCommit]) -> Self:
        all_commits = { commit.commit_id: commit for commit in commits }
        root_commits: set[str] = set()

        commit_children = { commit.commit_id: CommitChildren(
            primary_children=[],
            secondary_children=[],
        ) for commit in commits }

        for commit in commits:
            parent = commit.parent
            if parent is None or parent.commit_id not in all_commits:
                root_commits.add(commit.commit_id)
            else:
                commit_children[parent.commit_id].primary_children.append(commit.commit_id)

            for second_parent in commit.secondary_parents:
                if second_parent.commit_id in all_commits:
                    commit_children[second_parent.commit_id].secondary_children.append(commit.commit_id)

        leaf_commits: set[str] = {
            commit_id for commit_id, child_info in commit_children.items() if len(child_info.primary_children) == 0
        }

        return cls(
            commits=all_commits,
            commit_children=commit_children,
            root_commits=root_commits,
            leaf_commits=leaf_commits,
        )




def extract_to_db(
    repo: GitRepo,
    db: GitDb,
    start: datetime | None = None,
    end: datetime | None = None,
) -> int:
    """Stream repository commits directly into the SQLite store."""

    return db.store_commits(repo.iter_commits_between(start, end, include_merges=True))


def _path_for_db_name(db_name: str) -> Path:
    db_folder = Path(__file__).parent.parent.parent / "db"

    return db_folder / f"{db_name}.sqlite"

def save_commits_to_db(db_name: str, commits: list[GitCommit]):
    """Replace a database in the db folder with the supplied commits."""

    save_path = _path_for_db_name(db_name)
    _ = GitDb(save_path).replace_commits(commits)
    print(f"Saved {len(commits)} commits to sqlite database `{save_path}`")


def load_commits_from_db(db_name: str) -> list[GitCommit]:
    return GitDb(_path_for_db_name(db_name)).commits_between()


def parse_time(time: str) -> datetime:
    return datetime.strptime(time, "%m-%d-%Y").replace(
        tzinfo=UTC,
    )
