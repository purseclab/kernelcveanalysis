from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from .models import ACTIVE_STATES, InstanceRecord


class InstanceDb:
    def __init__(self, database_path: Path) -> None:
        self._database_path = database_path
        self._lock = threading.Lock()
        self._connection: sqlite3.Connection | None = None

    def initialize(self) -> None:
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            if self._connection is None:
                self._connection = sqlite3.connect(
                    self._database_path,
                    check_same_thread=False,
                )
                self._connection.row_factory = sqlite3.Row

            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS instances (
                    instance_id TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    instance_name TEXT,
                    state TEXT NOT NULL,
                    instance_num INTEGER NOT NULL,
                    config_json TEXT NOT NULL,
                    runtime_dir TEXT NOT NULL,
                    launch_command_json TEXT NOT NULL,
                    adb_port INTEGER,
                    adb_serial TEXT,
                    webrtc_port INTEGER,
                    expires_at TEXT,
                    failure_reason TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_instances_state
                    ON instances(state);

                CREATE INDEX IF NOT EXISTS idx_instances_expires_at
                    ON instances(expires_at);

                CREATE INDEX IF NOT EXISTS idx_instances_instance_num
                    ON instances(instance_num);
                """
            )
            self._migrate_legacy_unique_instance_num()
            self._migrate_add_instance_name_column()
            self._migrate_add_adb_port_column()
            self._migrate_nullable_expires_at_column()
            self._connection.commit()

    def close(self) -> None:
        with self._lock:
            if self._connection is None:
                return
            self._connection.close()
            self._connection = None

    def upsert(self, record: InstanceRecord) -> None:
        with self._lock:
            connection = self._require_connection()
            connection.execute(
                """
                INSERT INTO instances (
                    instance_id,
                    owner_id,
                    instance_name,
                    state,
                    instance_num,
                    config_json,
                    runtime_dir,
                    launch_command_json,
                    adb_port,
                    adb_serial,
                    webrtc_port,
                    expires_at,
                    failure_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(instance_id) DO UPDATE SET
                    owner_id = excluded.owner_id,
                    instance_name = excluded.instance_name,
                    state = excluded.state,
                    instance_num = excluded.instance_num,
                    config_json = excluded.config_json,
                    runtime_dir = excluded.runtime_dir,
                    launch_command_json = excluded.launch_command_json,
                    adb_port = excluded.adb_port,
                    adb_serial = excluded.adb_serial,
                    webrtc_port = excluded.webrtc_port,
                    expires_at = excluded.expires_at,
                    failure_reason = excluded.failure_reason
                """,
                (
                    record.instance_id,
                    record.owner_id,
                    record.instance_name,
                    record.state,
                    record.instance_num,
                    record.config.model_dump_json(),
                    str(record.runtime_dir),
                    json.dumps(record.launch_command),
                    record.adb_port,
                    record.adb_serial,
                    record.webrtc_port,
                    record.expires_at.isoformat() if record.expires_at else None,
                    record.failure_reason,
                ),
            )
            connection.commit()

    def get(self, instance_id: str) -> InstanceRecord | None:
        with self._lock:
            connection = self._require_connection()
            row = connection.execute(
                "SELECT * FROM instances WHERE instance_id = ?",
                (instance_id,),
            ).fetchone()
        return self._row_to_record(row) if row else None

    def list_instances(self, owner_id: str | None = None) -> list[InstanceRecord]:
        with self._lock:
            connection = self._require_connection()
            if owner_id is None:
                rows = connection.execute(
                    "SELECT * FROM instances ORDER BY expires_at DESC"
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT * FROM instances
                    WHERE owner_id = ?
                    ORDER BY expires_at DESC
                    """,
                    (owner_id,),
                ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def list_instances_by_name(
        self,
        instance_name: str,
        owner_id: str | None = None,
    ) -> list[InstanceRecord]:
        with self._lock:
            connection = self._require_connection()
            if owner_id is None:
                rows = connection.execute(
                    """
                    SELECT * FROM instances
                    WHERE instance_name = ?
                    ORDER BY expires_at DESC
                    """,
                    (instance_name,),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT * FROM instances
                    WHERE owner_id = ? AND instance_name = ?
                    ORDER BY expires_at DESC
                    """,
                    (owner_id, instance_name),
                ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def has_active_instance_name(self, owner_id: str, instance_name: str) -> bool:
        placeholders = ", ".join("?" for _ in ACTIVE_STATES)
        params: tuple[object, ...] = (owner_id, instance_name, *ACTIVE_STATES)
        with self._lock:
            connection = self._require_connection()
            row = connection.execute(
                f"""
                SELECT 1
                FROM instances
                WHERE owner_id = ? AND instance_name = ? AND state IN ({placeholders})
                LIMIT 1
                """,
                params,
            ).fetchone()
        return row is not None

    def list_active_instance_numbers(self) -> set[int]:
        placeholders = ", ".join("?" for _ in ACTIVE_STATES)
        with self._lock:
            connection = self._require_connection()
            rows = connection.execute(
                f"""
                SELECT instance_num
                FROM instances
                WHERE state IN ({placeholders})
                """,
                tuple(ACTIVE_STATES),
            ).fetchall()
        return {int(row["instance_num"]) for row in rows}

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise RuntimeError("database has not been initialized")
        return self._connection

    def _migrate_legacy_unique_instance_num(self) -> None:
        connection = self._require_connection()
        create_sql_row = connection.execute(
            """
            SELECT sql
            FROM sqlite_master
            WHERE type = 'table' AND name = 'instances'
            """
        ).fetchone()
        if create_sql_row is None:
            return

        create_sql = create_sql_row["sql"] or ""
        if "instance_num INTEGER NOT NULL UNIQUE" not in create_sql:
            return

        connection.executescript(
            """
            ALTER TABLE instances RENAME TO instances_old;

            CREATE TABLE instances (
                instance_id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                instance_name TEXT,
                state TEXT NOT NULL,
                instance_num INTEGER NOT NULL,
                config_json TEXT NOT NULL,
                runtime_dir TEXT NOT NULL,
                launch_command_json TEXT NOT NULL,
                adb_port INTEGER,
                adb_serial TEXT,
                webrtc_port INTEGER,
                expires_at TEXT,
                failure_reason TEXT
            );

            INSERT INTO instances (
                instance_id,
                owner_id,
                instance_name,
                state,
                instance_num,
                config_json,
                runtime_dir,
                launch_command_json,
                adb_port,
                adb_serial,
                webrtc_port,
                expires_at,
                failure_reason
            )
            SELECT
                instance_id,
                owner_id,
                NULL AS instance_name,
                state,
                instance_num,
                config_json,
                runtime_dir,
                launch_command_json,
                NULL AS adb_port,
                adb_serial,
                webrtc_port,
                expires_at,
                failure_reason
            FROM instances_old;

            DROP TABLE instances_old;

            CREATE INDEX IF NOT EXISTS idx_instances_state
                ON instances(state);

            CREATE INDEX IF NOT EXISTS idx_instances_expires_at
                ON instances(expires_at);

            CREATE INDEX IF NOT EXISTS idx_instances_instance_num
                ON instances(instance_num);
            """
        )

    def _migrate_add_instance_name_column(self) -> None:
        connection = self._require_connection()
        columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(instances)").fetchall()
        }
        if "instance_name" not in columns:
            connection.execute("ALTER TABLE instances ADD COLUMN instance_name TEXT")

    def _migrate_add_adb_port_column(self) -> None:
        connection = self._require_connection()
        columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(instances)").fetchall()
        }
        if "adb_port" not in columns:
            connection.execute("ALTER TABLE instances ADD COLUMN adb_port INTEGER")

    def _migrate_nullable_expires_at_column(self) -> None:
        connection = self._require_connection()
        create_sql_row = connection.execute(
            """
            SELECT sql
            FROM sqlite_master
            WHERE type = 'table' AND name = 'instances'
            """
        ).fetchone()
        if create_sql_row is None:
            return

        create_sql = create_sql_row["sql"] or ""
        if "expires_at TEXT NOT NULL" not in create_sql:
            return

        connection.executescript(
            """
            ALTER TABLE instances RENAME TO instances_old_expires_at;

            CREATE TABLE instances (
                instance_id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                instance_name TEXT,
                state TEXT NOT NULL,
                instance_num INTEGER NOT NULL,
                config_json TEXT NOT NULL,
                runtime_dir TEXT NOT NULL,
                launch_command_json TEXT NOT NULL,
                adb_port INTEGER,
                adb_serial TEXT,
                webrtc_port INTEGER,
                expires_at TEXT,
                failure_reason TEXT
            );

            INSERT INTO instances (
                instance_id,
                owner_id,
                instance_name,
                state,
                instance_num,
                config_json,
                runtime_dir,
                launch_command_json,
                adb_port,
                adb_serial,
                webrtc_port,
                expires_at,
                failure_reason
            )
            SELECT
                instance_id,
                owner_id,
                instance_name,
                state,
                instance_num,
                config_json,
                runtime_dir,
                launch_command_json,
                adb_port,
                adb_serial,
                webrtc_port,
                expires_at,
                failure_reason
            FROM instances_old_expires_at;

            DROP TABLE instances_old_expires_at;

            CREATE INDEX IF NOT EXISTS idx_instances_state
                ON instances(state);

            CREATE INDEX IF NOT EXISTS idx_instances_expires_at
                ON instances(expires_at);

            CREATE INDEX IF NOT EXISTS idx_instances_instance_num
                ON instances(instance_num);
            """
        )

    def _row_to_record(self, row: sqlite3.Row) -> InstanceRecord:
        return InstanceRecord.model_validate(
            {
                "instance_id": row["instance_id"],
                "owner_id": row["owner_id"],
                "instance_name": row["instance_name"],
                "state": row["state"],
                "instance_num": row["instance_num"],
                "config": json.loads(row["config_json"]),
                "runtime_dir": row["runtime_dir"],
                "launch_command": json.loads(row["launch_command_json"]),
                "adb_port": row["adb_port"],
                "adb_serial": row["adb_serial"],
                "webrtc_port": row["webrtc_port"],
                "expires_at": row["expires_at"],
                "failure_reason": row["failure_reason"],
            }
        )
