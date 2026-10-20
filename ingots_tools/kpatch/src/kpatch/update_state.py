"""Validated extraction provenance shared by extraction and incremental updates."""

from datetime import datetime
import sqlite3
from typing import Literal, cast

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


UPDATE_STATE_KEY = "incremental_sync_state"
BOUNDED_EXTRACTION_KEY = "bounded_extraction"


class UpdateState(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[1] = 1
    start_date: AwareDatetime | None
    tip_commit: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    repo_path: str = Field(min_length=1)


class ExtractionBounds(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    start_date: AwareDatetime | None
    end_date: AwareDatetime
    tip_commit: str | None = Field(default=None, pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


def read_extraction_bounds(connection: sqlite3.Connection) -> ExtractionBounds | None:
    row = connection.execute(
        "SELECT value FROM database_metadata WHERE key = ?",
        (BOUNDED_EXTRACTION_KEY,),
    ).fetchone()
    if row is None:
        return None
    return ExtractionBounds.model_validate_json(cast(str, row["value"]))


def write_extraction_bounds(
    connection: sqlite3.Connection,
    start_date: datetime | None,
    end_date: datetime,
    *,
    tip_commit: str | None = None,
) -> None:
    bounds = ExtractionBounds(
        start_date=start_date, end_date=end_date, tip_commit=tip_commit
    )
    _write_metadata(connection, BOUNDED_EXTRACTION_KEY, bounds.model_dump_json())


def read_update_state(connection: sqlite3.Connection) -> UpdateState | None:
    row = connection.execute(
        "SELECT value FROM database_metadata WHERE key = ?",
        (UPDATE_STATE_KEY,),
    ).fetchone()
    if row is None:
        return None
    return UpdateState.model_validate_json(cast(str, row["value"]))


def write_update_state(
    connection: sqlite3.Connection,
    *,
    start_date: datetime | None,
    tip_commit: str,
    repo_path: str,
) -> None:
    state = UpdateState(
        start_date=start_date,
        tip_commit=tip_commit,
        repo_path=repo_path,
    )
    _write_metadata(connection, UPDATE_STATE_KEY, state.model_dump_json())


def _write_metadata(connection: sqlite3.Connection, key: str, value: str) -> None:
    _ = connection.execute(
        """
        INSERT INTO database_metadata (key, value) VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """,
        (key, value),
    )


def invalidate_update_state(connection: sqlite3.Connection) -> None:
    """Forget the tip checkpoint without laundering known extraction bounds."""

    _ = connection.execute(
        "DELETE FROM database_metadata WHERE key = ?",
        (UPDATE_STATE_KEY,),
    )


def clear_extraction_bounds(connection: sqlite3.Connection) -> None:
    """Clear bounds only when replacing the dataset or extracting into an empty DB."""

    _ = connection.execute(
        "DELETE FROM database_metadata WHERE key = ?",
        (BOUNDED_EXTRACTION_KEY,),
    )
