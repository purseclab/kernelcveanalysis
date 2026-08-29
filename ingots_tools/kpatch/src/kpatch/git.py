from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import sqlite3
import subprocess
from typing import Iterable, Iterator, Protocol, runtime_checkable
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
    f"{_git_format_bytes(LOG_FIELD_SEPARATOR)}%an <%ae>"
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
        author,
        author_date,
        committer_date,
        author_timestamp,
        committer_timestamp,
        parents,
        message,
        diff
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(commit_id) DO UPDATE SET
        author = excluded.author,
        author_date = excluded.author_date,
        committer_date = excluded.committer_date,
        author_timestamp = excluded.author_timestamp,
        committer_timestamp = excluded.committer_timestamp,
        parents = excluded.parents,
        message = excluded.message,
        diff = excluded.diff
"""


@dataclass
class GitCommit:
    """A commit and the patch emitted for it by ``git log --patch``."""

    commit_id: str
    author: str
    author_date: datetime
    committer_date: datetime
    parents: tuple[str, ...]
    message: str
    diff_str: str

    @cached_property
    def diff(self) -> Diff:
        return Diff.parse(self.diff_str)


@runtime_checkable
class GitStore(Protocol):
    """A source of commits that can be queried by date."""

    def commits_between(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> list[GitCommit]:
        """Return commits in ``[start, end)``; either bound may be omitted."""

        ...


_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def _looks_like_record_start(data: bytearray, index: int) -> bool:
    metadata = data[index + len(_LOG_RECORD_START_BYTES) :]
    fields = metadata.split(_LOG_FIELD_SEPARATOR_BYTES, 5)
    if len(fields) != 6:
        return False

    commit_id, _, author_date, committer_date, _, _ = fields
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


class GitRepo(GitStore):
    repo: Path

    def __init__(self, repo: Path):
        self.repo = repo

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
        args.extend([
            "--no-merges",
            f"--format={GIT_LOG_FORMAT}",
            "--patch",
            "--no-color",
            "--no-ext-diff",
            "--full-index",
            "--binary",
        ])

        for record in self._iter_git_records(args):
            try:
                metadata, diff = record.removeprefix(_LOG_RECORD_START_BYTES).split(
                    _LOG_MESSAGE_END_BYTES,
                    1,
                )
            except ValueError as error:
                raise ValueError("Unable to split git log message from diff") from error

            fields = metadata.split(_LOG_FIELD_SEPARATOR_BYTES, 5)
            if len(fields) != 6:
                raise ValueError("Unexpected git log record format")

            commit_id, author, author_date, committer_date, parents, message = (
                field.decode("utf-8", errors="replace") for field in fields
            )
            commit = GitCommit(
                commit_id=commit_id,
                author=author,
                author_date=datetime.fromisoformat(author_date),
                committer_date=datetime.fromisoformat(committer_date),
                parents=tuple(parents.split()),
                message=message,
                diff_str=diff.lstrip(b"\n").decode("utf-8", errors="replace"),
            )
            if start is not None and commit.committer_date < start:
                continue
            if end is not None and commit.committer_date >= end:
                continue
            yield commit

    def commits_between(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> list[GitCommit]:
        """Return commits in ``[start, end)`` with their messages and diffs."""

        return list(self.iter_commits_between(start, end))


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
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            with connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS commits (
                        commit_id TEXT PRIMARY KEY,
                        author TEXT NOT NULL,
                        author_date TEXT NOT NULL,
                        committer_date TEXT NOT NULL,
                        author_timestamp INTEGER NOT NULL,
                        committer_timestamp INTEGER NOT NULL,
                        parents TEXT NOT NULL,
                        message TEXT NOT NULL,
                        diff TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS commits_committer_timestamp_idx
                    ON commits (committer_timestamp)
                    """
                )
        finally:
            connection.close()

    def store_commits(self, commits: Iterable[GitCommit]) -> int:
        """Insert an iterable of commits without materializing it in memory."""

        stored = 0
        connection = self._connect()
        try:
            with connection:
                for commit in commits:
                    connection.execute(
                        _UPSERT_COMMIT_SQL,
                        (
                            commit.commit_id,
                            commit.author,
                            commit.author_date.isoformat(),
                            commit.committer_date.isoformat(),
                            _timestamp(commit.author_date),
                            _timestamp(commit.committer_date),
                            json.dumps(commit.parents),
                            commit.message,
                            commit.diff_str,
                        ),
                    )
                    stored += 1
        finally:
            connection.close()
        return stored

    def commits_between(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> list[GitCommit]:
        """Return stored commits in ``[start, end)`` by committer date."""

        where_clauses: list[str] = []
        parameters: list[int] = []
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
                    commit_id,
                    author,
                    author_date,
                    committer_date,
                    parents,
                    message,
                    diff
                FROM commits
                {where_clause}
                ORDER BY committer_timestamp DESC, rowid DESC
                """,
                parameters,
            ).fetchall()
        finally:
            connection.close()

        return [
            GitCommit(
                commit_id=row["commit_id"],
                author=row["author"],
                author_date=datetime.fromisoformat(row["author_date"]),
                committer_date=datetime.fromisoformat(row["committer_date"]),
                parents=tuple(json.loads(row["parents"])),
                message=row["message"],
                diff_str=row["diff"],
            )
            for row in rows
        ]


def extract_to_db(
    repo: GitRepo,
    db: GitDb,
    start: datetime | None = None,
    end: datetime | None = None,
) -> int:
    """Stream repository commits directly into the SQLite store."""

    return db.store_commits(repo.iter_commits_between(start, end))


def parse_time(time: str) -> datetime:
    return datetime.strptime(time, "%m-%d-%Y").replace(
        tzinfo=UTC,
    )


def git_scan():
    repo = GitRepo(Path("./linux"))
    print(repo.commits_between(parse_time("01-01-2024"), parse_time("01-02-2024"))[0])
