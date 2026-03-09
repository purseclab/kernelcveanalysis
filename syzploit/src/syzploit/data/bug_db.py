"""
data.bug_db — SQLite-backed bug database for syzbot bugs.

Stores metadata about pulled/analysed bugs with simple CRUD operations.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .storage import syzkaller_db_dir


@dataclass
class Bug:
    """Representation of a syzbot bug."""

    id: str = ""
    title: str = ""
    kernel_name: str = ""
    status: str = ""
    crash_type: str = ""
    subsystem: str = ""
    syzbot_url: str = ""
    crash_log_url: str = ""
    reproducer_url: str = ""
    reproducer_c_url: str = ""
    fix_commit: str = ""
    report_date: str = ""
    last_crash_date: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Local paths (populated after pull)
    crash_log_path: str = ""
    reproducer_path: str = ""
    analysis_path: str = ""


class BugDatabase:
    """
    SQLite database storing syzbot bug metadata.

    Usage::

        db = BugDatabase("android-6.1")
        db.upsert(bug)
        bugs = db.get_all()
        db.close()
    """

    def __init__(self, kernel_name: str, db_path: Optional[Path] = None) -> None:
        self.kernel_name = kernel_name
        if db_path is None:
            db_path = syzkaller_db_dir() / f"{kernel_name}.db"
        self.db_path = db_path
        self._conn = sqlite3.connect(str(db_path))
        self._conn.row_factory = sqlite3.Row
        self._create_tables()

    def __enter__(self) -> "BugDatabase":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def _create_tables(self) -> None:
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS bugs (
                id TEXT PRIMARY KEY,
                title TEXT,
                kernel_name TEXT,
                status TEXT,
                crash_type TEXT,
                subsystem TEXT,
                syzbot_url TEXT,
                crash_log_url TEXT,
                reproducer_url TEXT,
                reproducer_c_url TEXT,
                fix_commit TEXT,
                report_date TEXT,
                last_crash_date TEXT,
                metadata TEXT,
                crash_log_path TEXT,
                reproducer_path TEXT,
                analysis_path TEXT
            )
        """)
        self._conn.commit()

    def upsert(self, bug: Bug) -> None:
        """Insert or update a bug record."""
        self._conn.execute(
            """
            INSERT OR REPLACE INTO bugs
            (id, title, kernel_name, status, crash_type, subsystem,
             syzbot_url, crash_log_url, reproducer_url, reproducer_c_url,
             fix_commit, report_date, last_crash_date, metadata,
             crash_log_path, reproducer_path, analysis_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                bug.id, bug.title, bug.kernel_name, bug.status,
                bug.crash_type, bug.subsystem, bug.syzbot_url,
                bug.crash_log_url, bug.reproducer_url, bug.reproducer_c_url,
                bug.fix_commit, bug.report_date, bug.last_crash_date,
                json.dumps(bug.metadata),
                bug.crash_log_path, bug.reproducer_path, bug.analysis_path,
            ),
        )
        self._conn.commit()

    def get(self, bug_id: str) -> Optional[Bug]:
        """Fetch a single bug by ID."""
        row = self._conn.execute("SELECT * FROM bugs WHERE id = ?", (bug_id,)).fetchone()
        if row is None:
            return None
        return self._row_to_bug(row)

    def get_all(self) -> List[Bug]:
        """Return all bugs for this kernel."""
        rows = self._conn.execute(
            "SELECT * FROM bugs WHERE kernel_name = ?", (self.kernel_name,)
        ).fetchall()
        return [self._row_to_bug(r) for r in rows]

    def search(self, query: str) -> List[Bug]:
        """Search bugs by title or crash type."""
        rows = self._conn.execute(
            "SELECT * FROM bugs WHERE title LIKE ? OR crash_type LIKE ?",
            (f"%{query}%", f"%{query}%"),
        ).fetchall()
        return [self._row_to_bug(r) for r in rows]

    def close(self) -> None:
        self._conn.close()

    @staticmethod
    def _row_to_bug(row: sqlite3.Row) -> Bug:
        meta = {}
        try:
            meta = json.loads(row["metadata"] or "{}")
        except (json.JSONDecodeError, TypeError):
            pass
        return Bug(
            id=row["id"],
            title=row["title"],
            kernel_name=row["kernel_name"],
            status=row["status"],
            crash_type=row["crash_type"],
            subsystem=row["subsystem"],
            syzbot_url=row["syzbot_url"],
            crash_log_url=row["crash_log_url"],
            reproducer_url=row["reproducer_url"],
            reproducer_c_url=row["reproducer_c_url"],
            fix_commit=row["fix_commit"],
            report_date=row["report_date"],
            last_crash_date=row["last_crash_date"],
            metadata=meta,
            crash_log_path=row["crash_log_path"] or "",
            reproducer_path=row["reproducer_path"] or "",
            analysis_path=row["analysis_path"] or "",
        )
