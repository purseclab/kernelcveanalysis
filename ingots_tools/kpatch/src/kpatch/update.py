"""Atomic, graph-based updates of a complete raw commit database."""

from contextlib import ExitStack, closing, contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import sqlite3
import subprocess
from tempfile import NamedTemporaryFile
from typing import Generator, cast

from .git import GitDb, GitRepo, HistoryKind
from .update_state import (
    UpdateState,
    read_extraction_bounds,
    read_update_state,
    write_update_state,
)


@dataclass(frozen=True, slots=True)
class UpdateResult:
    added_commits: int
    total_commits: int
    tip_commit: str
    start_date: datetime | None


@dataclass(frozen=True, slots=True)
class _UpdatePlan:
    state: UpdateState | None
    start_date: datetime | None


def _load_plan(
    db: GitDb,
    connection: sqlite3.Connection,
    start: datetime | None,
) -> _UpdatePlan:
    if db._get_history_kind(connection) is not HistoryKind.COMPLETE:
        raise ValueError("Incremental updates require a COMPLETE raw commit database")
    bounds = read_extraction_bounds(connection)
    if bounds is not None:
        raise ValueError(
            f"This extraction was capped at {bounds.end_date.isoformat()}; "
            "create a fresh unbounded extraction before updating"
        )
    state = read_update_state(connection)
    if state is None:
        if start is None:
            raise ValueError(
                "No extraction sync provenance is stored; provide --start with "
                "the database's actual original extraction start date"
            )
        return _UpdatePlan(None, start)
    if start is not None and start != state.start_date:
        raise ValueError("--start cannot change the persisted extraction start date")
    return _UpdatePlan(state, state.start_date)


@contextmanager
def _bootstrap_revisions(connection: sqlite3.Connection) -> Generator[Path, None, None]:
    """Exclude every stored commit and its ancestors without a large argv."""

    with NamedTemporaryFile(mode="w", encoding="ascii", suffix=".revisions") as file:
        for row in connection.execute("SELECT commit_id FROM commits"):
            commit_id = cast(str, row["commit_id"])
            file.write(f"^{commit_id}\n")
        file.flush()
        yield Path(file.name)


def _validate_checkpoint(repo: GitRepo, state: UpdateState, tip_commit: str) -> None:
    try:
        fast_forward = repo.is_ancestor(state.tip_commit, tip_commit)
    except subprocess.CalledProcessError as error:
        raise ValueError(
            f"Stored tip {state.tip_commit} is unavailable in this repository; "
            f"the database was last synced from {state.repo_path}"
        ) from error
    if not fast_forward:
        raise ValueError(
            f"HEAD {tip_commit} is not a fast-forward of stored tip {state.tip_commit}; "
            "refusing a rewind, divergent history, or wrong repository"
        )


def _stream_update(
    repo: GitRepo,
    db: GitDb,
    connection: sqlite3.Connection,
    state: UpdateState | None,
    tip_commit: str,
    start_date: datetime | None,
) -> int:
    with ExitStack() as resources:
        revisions_file: Path | None = None
        if state is None:
            revision = tip_commit
            revisions_file = resources.enter_context(_bootstrap_revisions(connection))
        else:
            revision = f"{state.tip_commit}..{tip_commit}"
        commits = resources.enter_context(closing(repo.iter_commits_from_revision(
            revision, start_date, revisions_file=revisions_file,
        )))
        return db._store_missing_commits(connection, commits)


def update_to_db(
    repo: GitRepo,
    db: GitDb,
    start: datetime | None = None,
    *,
    pull: bool = True,
) -> UpdateResult:
    """Pull, pin HEAD, and atomically append missing commits to a complete DB.

    A legacy database needs its actual extraction start explicitly on the first
    update. Its COMPLETE contract allows excluding all stored history during
    bootstrap. Legacy bootstrap assumes an uncapped extraction; known bounded
    extractions are rejected. Later updates use the saved tip's newly reachable graph,
    never the database's maximum date: late merges may contain older commits.
    """

    if start is not None and (start.tzinfo is None or start.utcoffset() is None):
        raise ValueError("The extraction start date must be timezone-aware")
    # Reject unusable inputs before a pull changes the checkout. This read is
    # advisory: the authoritative plan is loaded again after taking the lock.
    with closing(db._connect()) as connection:
        _ = _load_plan(db, connection, start)
    if pull:
        repo.pull_ff_only()
    tip_commit = repo.resolve_head()

    with closing(db._connect()) as connection, connection:
        _ = connection.execute("BEGIN IMMEDIATE")
        plan = _load_plan(db, connection, start)
        if plan.state is not None:
            _validate_checkpoint(repo, plan.state, tip_commit)

        added = _stream_update(
            repo, db, connection, plan.state, tip_commit, plan.start_date,
        )
        write_update_state(
            connection,
            start_date=plan.start_date,
            tip_commit=tip_commit,
            repo_path=str(repo.repo.resolve()),
        )
        row = connection.execute("SELECT COUNT(*) FROM commits").fetchone()
        return UpdateResult(
            added_commits=added,
            total_commits=cast(int, row[0]),
            tip_commit=tip_commit,
            start_date=plan.start_date,
        )
