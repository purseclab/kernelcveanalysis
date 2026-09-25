#!/usr/bin/env python3
"""Migrates legacy kexploit agent traces to the new SessionInfoEvent schema."""

from __future__ import annotations

import json
from pathlib import Path
from kexploit_utils import llm_workdir


def migrate_trace_file(path: Path) -> bool:
    content = path.read_text(encoding="utf-8").strip()
    if not content:
        return False

    raw_lines = [line for line in content.splitlines() if line.strip()]
    if not raw_lines:
        return False

    first_event = json.loads(raw_lines[0])
    if first_event.get("kind") == "session_info":
        print(f"Skipping {path.name}: already migrated.")
        return False

    if first_event.get("kind") != "session_start":
        print(f"Skipping {path.name}: first event is {first_event.get('kind')}")
        return False

    session_id, _, filename_name = path.stem.partition("_")
    timestamp = first_event.get("timestamp")

    parsed_events = [json.loads(line) for line in raw_lines]

    # Find root agent info from first root agent_start
    root_agent_id = None
    agent_name = ""
    for ev in parsed_events[1:]:
        if ev.get("kind") == "agent_start" and ev.get("parent_agent_id") is None:
            root_agent_id = ev.get("agent_id")
            agent_name = ev.get("agent_name", "")
            break

    session_info = {
        "seq": 1,
        "timestamp": timestamp,
        "turn_id": None,
        "turn_agent_id": None,
        "agent_id": None,
        "kind": "session_info",
        "trace_version": first_event.get("trace_version", 2),
        "session_id": session_id,
        "sandbox_id": first_event.get("sandbox_id", ""),
        "agent_class": first_event.get("agent_class", ""),
        "agent_name": agent_name,
        "provider": first_event.get("provider", ""),
        "root_agent_id": root_agent_id,
        "provider_session_id": None,
        "container_home": None,
        "tools": first_event.get("tools", []),
        "mounts": first_event.get("mounts", []),
        "agent_group": first_event.get("agent_group"),
        "steering_support": first_event.get("steering_support", "none"),
    }

    session_start = {
        "seq": 2,
        "timestamp": timestamp,
        "turn_id": None,
        "turn_agent_id": None,
        "agent_id": None,
        "kind": "session_start",
        "run_id": None,
    }

    migrated_lines = [json.dumps(session_info), json.dumps(session_start)]

    for ev in parsed_events[1:]:
        ev["seq"] = ev.get("seq", 0) + 1
        if ev.get("kind") == "session_end" and "delete_sandbox" not in ev:
            ev["delete_sandbox"] = False
        migrated_lines.append(json.dumps(ev))

    tmp_path = path.with_suffix(".tmp")
    tmp_path.write_text("\n".join(migrated_lines) + "\n", encoding="utf-8")
    tmp_path.replace(path)
    print(f"Migrated {path.name} ({len(migrated_lines)} events)")
    return True


def main() -> None:
    history_dir = llm_workdir() / "agent_history"
    if not history_dir.is_dir():
        print(f"History dir {history_dir} does not exist.")
        return

    migrated_count = 0
    for p in sorted(history_dir.glob("*.jsons")):
        if migrate_trace_file(p):
            migrated_count += 1

    print(f"Total migrated: {migrated_count} traces.")


if __name__ == "__main__":
    main()
