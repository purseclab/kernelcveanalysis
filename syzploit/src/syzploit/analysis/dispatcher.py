"""
analysis.dispatcher — High-level analysis entry-point.

``analyze_input`` inspects the ``TaskContext.input_type`` and delegates
to the appropriate analyser (crash_parser, cve_analyzer, blog_analyzer),
then runs root-cause analysis and exploitability classification.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from ..core.config import Config
from ..core.log import console
from ..core.models import CrashReport
from ..orchestrator.context import TaskContext
from .crash_parser import parse_crash_log
from .cve_analyzer import analyze_cve
from .blog_analyzer import analyze_blog
from .root_cause import root_cause_analysis
from .exploitability import classify_exploitability


def analyze_input(ctx: TaskContext, cfg: Config) -> TaskContext:
    """
    Analyse the input stored in *ctx* and populate crash_report / root_cause.

    Dispatches based on ``ctx.input_type``:
        - ``cve``       → CVE lookup + LLM analysis
        - ``syzbot``    → Fetch crash from syzbot, parse crash log
        - ``crash_log`` → Direct crash log parsing
        - ``blog_post`` → Blog scraping + LLM analysis
        - ``poc``       → Read PoC source, minimal analysis
    """
    input_type = ctx.input_type
    input_value = ctx.input_value

    if input_type == "cve":
        console.print(f"[bold]Analysing CVE: {input_value}[/]")
        rca = analyze_cve(input_value, cfg=cfg)
        ctx.root_cause = rca
        ctx.log("analysis", "analyze_cve", f"type={rca.vulnerability_type.value}")

    elif input_type == "syzbot":
        console.print(f"[bold]Fetching syzbot crash: {input_value}[/]")
        crash_log = _fetch_syzbot_crash(input_value)
        if crash_log:
            crash = parse_crash_log(crash_log)
            ctx.crash_report = crash
            rca = root_cause_analysis(crash, cfg=cfg)
            rca = classify_exploitability(crash, rca, cfg=cfg)
            ctx.root_cause = rca
            ctx.log("analysis", "analyze_syzbot", f"type={rca.vulnerability_type.value}")
        else:
            ctx.errors.append(f"Failed to fetch syzbot crash: {input_value}")

    elif input_type == "crash_log":
        console.print("[bold]Parsing crash log…[/]")
        # Could be a file path or raw text
        raw = input_value
        p = Path(input_value)
        if p.exists() and p.is_file():
            raw = p.read_text()
        crash = parse_crash_log(raw)
        ctx.crash_report = crash
        rca = root_cause_analysis(crash, cfg=cfg)
        rca = classify_exploitability(crash, rca, cfg=cfg)
        ctx.root_cause = rca
        ctx.log("analysis", "parse_crash", f"type={crash.bug_type.value}")

    elif input_type == "blog_post":
        console.print(f"[bold]Analysing blog post: {input_value}[/]")
        rca = analyze_blog(input_value, cfg=cfg)
        ctx.root_cause = rca
        ctx.log("analysis", "analyze_blog", f"type={rca.vulnerability_type.value}")

    elif input_type == "poc":
        console.print(f"[bold]Reading PoC: {input_value}[/]")
        p = Path(input_value)
        if p.exists():
            ctx.crash_report = CrashReport(reproducer_c=p.read_text())
            ctx.log("analysis", "read_poc", str(p))
        else:
            ctx.errors.append(f"PoC file not found: {input_value}")

    else:
        ctx.errors.append(f"Unknown input type: {input_type}")

    return ctx


# ── Syzbot helper ─────────────────────────────────────────────────────


def _fetch_syzbot_crash(input_value: str) -> Optional[str]:
    """
    Fetch crash log from syzbot.  Accepts either a full URL or a bug ID.
    """
    import urllib.request
    import json

    # Normalise to bug ID
    bug_id = input_value
    if "syzkaller.appspot.com" in input_value:
        # Extract bug ID from URL
        import re
        m = re.search(r"bug\?id=([a-f0-9]+)", input_value)
        if m:
            bug_id = m.group(1)
        else:
            m = re.search(r"bug\?extid=(\S+)", input_value)
            if m:
                bug_id = m.group(1)

    # Try syzbot API
    url = f"https://syzkaller.appspot.com/bug?json=1&id={bug_id}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "syzploit/0.2"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))

        crashes = data.get("crashes", [])
        if crashes:
            # Get crash log from first crash
            crash_id = crashes[0].get("crash-id", "")
            if crash_id:
                log_url = f"https://syzkaller.appspot.com/text?tag=CrashLog&x={crash_id}"
                req2 = urllib.request.Request(log_url, headers={"User-Agent": "syzploit/0.2"})
                with urllib.request.urlopen(req2, timeout=30) as resp2:
                    return resp2.read().decode("utf-8", errors="replace")
    except Exception:
        pass

    return None
