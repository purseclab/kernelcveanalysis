"""
data.scraper — Syzbot bug scraping and filtering.

Pulls open bugs from the syzkaller dashboard, filters for interesting
ones, and stores them in the ``BugDatabase``.
"""

from __future__ import annotations

import json
import re
import urllib.request
from typing import Any, Dict, List, Optional

from ..core.log import console
from .bug_db import Bug, BugDatabase

SYZBOT_BASE = "https://syzkaller.appspot.com"


def pull_bugs(
    db: BugDatabase,
    kernel_name: str,
    *,
    apply_filter: bool = True,
    max_bugs: int = 200,
) -> List[Bug]:
    """
    Pull open bugs from syzbot for *kernel_name* and upsert into *db*.

    Args:
        db: Target database.
        kernel_name: Kernel identifier (e.g., "upstream", "android-6.1").
        apply_filter: Skip bugs without C reproducers.
        max_bugs: Maximum bugs to fetch.

    Returns:
        List of ``Bug`` objects that were upserted.
    """
    console.print(f"[bold]Pulling bugs for {kernel_name}…[/]")

    url = f"{SYZBOT_BASE}/{kernel_name}?json=1"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "syzploit/0.2"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as exc:
        console.print(f"[red]Failed to fetch bug list: {exc}[/]")
        return []

    bugs_data = data.get("bugs", [])[:max_bugs]
    result: List[Bug] = []

    for item in bugs_data:
        bug = _parse_bug_item(item, kernel_name)

        # Filter: require C reproducer
        if apply_filter and not bug.reproducer_c_url:
            continue

        db.upsert(bug)
        result.append(bug)

    console.print(f"  Pulled {len(result)} bugs (filtered={apply_filter})")
    return result


def _parse_bug_item(item: Dict[str, Any], kernel_name: str) -> Bug:
    """Parse a single bug JSON object from syzbot API."""
    bug_id = item.get("id", "")
    title = item.get("title", "")
    status = item.get("status", "open")

    # Determine crash type from title
    crash_type = ""
    for pattern in ("KASAN:", "UBSAN:", "KMSAN:", "BUG:", "WARNING:"):
        if pattern in title:
            crash_type = pattern.rstrip(":")
            break

    # Extract URLs
    syzbot_url = f"{SYZBOT_BASE}/bug?id={bug_id}" if bug_id else ""
    repro_url = item.get("syz-reproducer", "")
    repro_c_url = item.get("c-reproducer", "")
    crash_log_url = ""

    crashes = item.get("crashes", [])
    if crashes:
        crash0 = crashes[0]
        crash_id = crash0.get("crash-id", "")
        if crash_id:
            crash_log_url = f"{SYZBOT_BASE}/text?tag=CrashLog&x={crash_id}"

    return Bug(
        id=bug_id,
        title=title,
        kernel_name=kernel_name,
        status=status,
        crash_type=crash_type,
        syzbot_url=syzbot_url,
        crash_log_url=crash_log_url,
        reproducer_url=repro_url,
        reproducer_c_url=repro_c_url,
        fix_commit=item.get("fix-commit", ""),
        report_date=item.get("first-crash", ""),
        last_crash_date=item.get("last-crash", ""),
    )
