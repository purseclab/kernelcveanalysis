"""Atomically extend a complete raw database's continuous date coverage."""

from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import sqlite3
from typing import cast

from .git import GitDb, GitRepo, HistoryKind
from .update_state import (
    clear_extraction_bounds,
    invalidate_update_state,
    read_extraction_bounds,
    read_update_state,
    write_extraction_bounds,
    write_update_state,
)


@dataclass(frozen=True, slots=True)
class AddResult:
    added_commits: int
    total_commits: int
    start_date: datetime | None
    end_date: datetime | None
    tip_commit: str


@dataclass(frozen=True, slots=True)
class _Coverage:
    start: datetime | None
    end: datetime | None
    tip_commit: str | None = None


@dataclass(frozen=True, slots=True)
class _StoredDates:
    first: datetime | None
    last: datetime | None


def _stored_dates(connection: sqlite3.Connection) -> _StoredDates:
    row = connection.execute(
        "SELECT MIN(committer_timestamp), MAX(committer_timestamp) FROM commits"
    ).fetchone()
    first = cast(int | None, row[0])
    last = cast(int | None, row[1])
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    return _StoredDates(
        None if first is None else epoch + timedelta(microseconds=first),
        None if last is None else epoch + timedelta(microseconds=last),
    )


def _load_coverage(
    db: GitDb, connection: sqlite3.Connection, dates: _StoredDates,
) -> _Coverage | None:
    kind = db._get_history_kind(connection)
    bounds = read_extraction_bounds(connection)
    state = read_update_state(connection)
    if kind is HistoryKind.SPARSE or (kind is HistoryKind.UNKNOWN and dates.first is not None):
        raise ValueError("Range additions require a COMPLETE raw commit database")
    coverage: _Coverage | None = None
    if bounds is not None:
        coverage = _Coverage(bounds.start_date, bounds.end_date, bounds.tip_commit)
    elif state is not None:
        coverage = _Coverage(state.start_date, None, state.tip_commit)
    elif dates.first is not None:
        raise ValueError(
            "Stored date coverage is unknown; commit timestamps alone cannot prove "
            "continuous coverage. Use a database created by extract or add."
        )
    if coverage is not None and dates.first is not None and dates.last is not None:
        if (
            coverage.start is not None and dates.first < coverage.start
            or coverage.end is not None and dates.last >= coverage.end
        ):
            raise ValueError("Stored commits fall outside the recorded date coverage")
    return coverage


def _utc_date(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Date boundaries must be timezone-aware")
    return value.astimezone(UTC)


def _union_coverage(existing: _Coverage | None, requested: _Coverage) -> _Coverage:
    if requested.start is not None and requested.end is not None:
        if requested.start >= requested.end:
            raise ValueError("Start date must be before the exclusive end date")
    if existing is None:
        return requested
    if (
        existing.end is not None and requested.start is not None
        and requested.start > existing.end
        or requested.end is not None and existing.start is not None
        and requested.end < existing.start
    ):
        raise ValueError(
            "Requested range leaves a gap in database coverage; "
            "ranges must overlap or touch the stored range"
        )
    start = (
        None if existing.start is None or requested.start is None
        else min(existing.start, requested.start)
    )
    end = (
        None if existing.end is None or requested.end is None
        else max(existing.end, requested.end)
    )
    return _Coverage(start, end)


def _resolve_request(
    start: datetime | None,
    end: datetime | None,
    coverage: _Coverage | None,
    dates: _StoredDates,
    *,
    start_at_stored_end: bool,
    end_at_stored_start: bool,
) -> _Coverage:
    if start_at_stored_end or end_at_stored_start:
        if coverage is None or dates.first is None or dates.last is None:
            raise ValueError("Stored-boundary flags require existing commits with known coverage")
        if start_at_stored_end:
            start = coverage.end if coverage.end is not None else dates.last
        if end_at_stored_start:
            end = coverage.start if coverage.start is not None else dates.first
    return _Coverage(start, end)


def _validate_history(
    repo: GitRepo,
    connection: sqlite3.Connection,
    existing: _Coverage | None,
    tip: str,
) -> None:
    if existing is None:
        return
    if existing.tip_commit is not None:
        matches_history = repo.is_ancestor(existing.tip_commit, tip)
    else:
        stored_ids = (
            cast(str, row["commit_id"])
            for row in connection.execute("SELECT commit_id FROM commits")
        )
        matches_history = repo.contains_commits(stored_ids, tip)
    if not matches_history:
        raise ValueError(
            "HEAD diverges from stored history; refusing a rewind or wrong repository"
        )


def _write_coverage(
    connection: sqlite3.Connection, coverage: _Coverage, tip: str, repo: GitRepo,
) -> None:
    clear_extraction_bounds(connection)
    invalidate_update_state(connection)
    if coverage.end is None:
        write_update_state(
            connection, start_date=coverage.start, tip_commit=tip,
            repo_path=str(repo.repo.resolve()),
        )
    else:
        write_extraction_bounds(
            connection, coverage.start, coverage.end, tip_commit=tip,
        )


def add_to_db(
    repo: GitRepo,
    db: GitDb,
    start: datetime | None = None,
    end: datetime | None = None,
    *,
    start_at_stored_end: bool = False,
    end_at_stored_start: bool = False,
) -> AddResult:
    """Add ``[start, end)`` from HEAD, rejecting gaps and preserving stored IDs.

    Omitted dates mean all history / through HEAD. Stored-boundary flags use
    recorded coverage endpoints, falling back to commit timestamps for open
    endpoints. The entire union is scanned, so advancing HEAD also picks up
    late merges inside previously covered dates. No pull is performed.
    """

    if start is None and end is None and not start_at_stored_end and not end_at_stored_start:
        raise ValueError("Specify --start, --end, or a stored-boundary flag")
    if start is not None and start_at_stored_end:
        raise ValueError("--start conflicts with --start-at-stored-end")
    if end is not None and end_at_stored_start:
        raise ValueError("--end conflicts with --end-at-stored-start")
    start, end = _utc_date(start), _utc_date(end)
    with closing(db._connect()) as connection, connection:
        _ = connection.execute("BEGIN IMMEDIATE")
        dates = _stored_dates(connection)
        existing = _load_coverage(db, connection, dates)
        requested = _resolve_request(
            start, end, existing, dates,
            start_at_stored_end=start_at_stored_end,
            end_at_stored_start=end_at_stored_start,
        )
        coverage = _union_coverage(existing, requested)
        tip = repo.resolve_head()
        _validate_history(repo, connection, existing, tip)
        with closing(repo.iter_commits_from_revision(tip, coverage.start, end=coverage.end)) as commits:
            added = db._store_missing_commits(connection, commits)
        db._set_history_kind(connection, HistoryKind.COMPLETE)
        _write_coverage(connection, coverage, tip, repo)
        row = connection.execute("SELECT COUNT(*) FROM commits").fetchone()
        return AddResult(added, cast(int, row[0]), coverage.start, coverage.end, tip)
