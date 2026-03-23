"""
analysis.cve_hunter — Autonomous CVE discovery for a target kernel.

Given a kernel version string, this module:
  1. Queries NVD for Linux kernel CVEs affecting that version range
  2. Searches Android Security Bulletins for kernel CVEs
  3. Queries syzbot for open bugs on the kernel branch
  4. Filters candidates by exploitability (UAF, OOB, race > info leak)
  5. Uses LLM to rank and select the most promising candidates
  6. Returns a prioritised list of CVE targets for automated exploitation

Usage::

    from syzploit.analysis.cve_hunter import hunt_cves

    candidates = hunt_cves("5.10.107", platform="android", max_results=20)
    for c in candidates:
        print(c.cve_id, c.priority, c.reason)
"""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..core.config import Config, load_config
from ..core.llm import LLMClient
from ..core.log import console


# ── Data models ───────────────────────────────────────────────────────


@dataclass
class CVECandidate:
    """A CVE identified as a potential exploitation target."""
    cve_id: str = ""
    description: str = ""
    cvss_score: float = 0.0
    severity: str = ""
    vuln_type: str = ""              # uaf, oob_write, race, etc.
    affected_subsystem: str = ""     # binder, netfilter, io_uring, etc.
    affected_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    has_public_exploit: bool = False
    exploit_urls: list[str] = field(default_factory=list)
    priority: int = 0               # 1=highest, 5=lowest
    reason: str = ""                # Why this was selected
    source: str = ""                # "nvd", "android_bulletin", "syzbot"
    patch_status: str = ""          # "patched", "unpatched", "unknown"
    raw_data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "description": self.description[:500],
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "vuln_type": self.vuln_type,
            "affected_subsystem": self.affected_subsystem,
            "has_public_exploit": self.has_public_exploit,
            "exploit_urls": self.exploit_urls,
            "priority": self.priority,
            "reason": self.reason,
            "source": self.source,
            "patch_status": self.patch_status,
        }


# ── HTTP helpers ──────────────────────────────────────────────────────


def _fetch_url(url: str, timeout: int = 30) -> str:
    req = urllib.request.Request(url, headers={
        "User-Agent": "syzploit/0.2 (kernel-security-research)",
        "Accept": "text/html,application/json,*/*",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _fetch_json(url: str, timeout: int = 30) -> Any:
    try:
        raw = _fetch_url(url, timeout)
        return json.loads(raw)
    except Exception:
        return {}


def _github_search(query: str, cfg: Optional[Config] = None) -> list[dict]:
    """Search GitHub for repos matching query."""
    headers = {
        "User-Agent": "syzploit/0.2",
        "Accept": "application/vnd.github.v3+json",
    }
    token = None
    if cfg and getattr(cfg, "github_token", None):
        token = cfg.github_token
    if not token:
        import os
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"

    encoded = urllib.parse.quote(query)
    url = f"https://api.github.com/search/repositories?q={encoded}&sort=stars&per_page=10"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
            return data.get("items", [])
    except Exception:
        return []


# ── NVD query ─────────────────────────────────────────────────────────


def _query_nvd_kernel_cves(
    kernel_version: str,
    max_results: int = 50,
) -> list[CVECandidate]:
    """Query NVD for Linux kernel CVEs.

    Uses keyword search since NVD CPE matching for kernel versions
    is unreliable. Filters results by kernel subsystem keywords.
    """
    candidates: list[CVECandidate] = []

    # Extract major.minor from version (e.g. "5.10.107" → "5.10")
    m = re.match(r"(\d+\.\d+)", kernel_version)
    branch = m.group(1) if m else kernel_version

    # Search NVD for recent kernel CVEs
    keyword = urllib.parse.quote(f"linux kernel {branch}")
    url = (
        f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?keywordSearch={keyword}"
        f"&resultsPerPage={min(max_results * 2, 100)}"
    )

    console.print(f"  [dim]Querying NVD for kernel {branch} CVEs…[/]")
    try:
        data = _fetch_json(url)
    except Exception as e:
        console.print(f"  [yellow]NVD query failed: {e}[/]")
        return candidates

    vulns = data.get("vulnerabilities", [])
    for item in vulns:
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "")
        if not cve_id.startswith("CVE-"):
            continue

        # Get description
        desc_list = cve_data.get("descriptions", [])
        desc = ""
        for d in desc_list:
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # Skip non-kernel CVEs
        desc_lower = desc.lower()
        if "linux kernel" not in desc_lower and "android" not in desc_lower:
            continue

        # Get CVSS
        metrics = cve_data.get("metrics", {})
        cvss_score = 0.0
        severity = ""
        for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(version_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "")
                break

        # Get references
        refs = [
            r.get("url", "")
            for r in cve_data.get("references", [])
            if r.get("url")
        ]

        c = CVECandidate(
            cve_id=cve_id,
            description=desc,
            cvss_score=cvss_score,
            severity=severity,
            references=refs,
            source="nvd",
            raw_data=cve_data,
        )
        candidates.append(c)

    console.print(f"  [dim]NVD returned {len(candidates)} kernel CVEs[/]")
    return candidates


# ── Android Security Bulletin ─────────────────────────────────────────


def _query_android_bulletins(
    kernel_version: str,
    max_results: int = 30,
) -> list[CVECandidate]:
    """Scrape Android Security Bulletins for kernel CVEs.

    Checks the last 12 months of bulletins for kernel component entries.
    """
    candidates: list[CVECandidate] = []

    try:
        from bs4 import BeautifulSoup
    except ImportError:
        console.print("  [yellow]bs4 not available, skipping bulletin scrape[/]")
        return candidates

    # Android bulletins are at source.android.com
    from datetime import datetime, timedelta

    console.print("  [dim]Checking Android Security Bulletins…[/]")

    now = datetime.now()
    for months_ago in range(0, 12):
        dt = now - timedelta(days=months_ago * 30)
        year, month = dt.year, dt.month
        url = (
            f"https://source.android.com/docs/security/bulletin/"
            f"{year}-{month:02d}-01"
        )
        try:
            html = _fetch_url(url, timeout=15)
            soup = BeautifulSoup(html, "html.parser")

            # Find tables with kernel CVEs
            for table in soup.find_all("table"):
                header_text = ""
                prev = table.find_previous(["h2", "h3", "h4"])
                if prev:
                    header_text = prev.get_text().lower()

                # Only kernel component tables
                if "kernel" not in header_text:
                    continue

                for row in table.find_all("tr"):
                    cells = row.find_all("td")
                    if len(cells) < 2:
                        continue
                    cve_text = cells[0].get_text().strip()
                    cve_match = re.search(r"(CVE-\d{4}-\d+)", cve_text)
                    if not cve_match:
                        continue

                    # Additional columns often have severity, component
                    severity = cells[2].get_text().strip() if len(cells) > 2 else ""
                    component = cells[3].get_text().strip() if len(cells) > 3 else ""

                    candidates.append(CVECandidate(
                        cve_id=cve_match.group(1),
                        severity=severity,
                        affected_subsystem=component,
                        source="android_bulletin",
                        reason=f"Android bulletin {year}-{month:02d}",
                    ))

        except Exception:
            continue  # Bulletin page may not exist

        if len(candidates) >= max_results:
            break

    console.print(f"  [dim]Found {len(candidates)} kernel CVEs in Android bulletins[/]")
    return candidates


# ── GitHub exploit search ─────────────────────────────────────────────


def _search_github_exploits_for_kernel(
    kernel_version: str,
    cfg: Optional[Config] = None,
) -> list[CVECandidate]:
    """Search GitHub for kernel exploit repos targeting this version."""
    candidates: list[CVECandidate] = []

    branch = re.match(r"(\d+\.\d+)", kernel_version)
    branch_str = branch.group(1) if branch else kernel_version

    queries = [
        f"linux kernel {branch_str} exploit",
        f"kernel {branch_str} CVE poc",
        f"android kernel {branch_str} exploit",
    ]

    seen_cves: set[str] = set()
    for query in queries:
        repos = _github_search(query, cfg)
        for repo in repos:
            name = repo.get("full_name", "")
            desc = repo.get("description", "") or ""
            stars = repo.get("stargazers_count", 0)

            # Extract CVE IDs from repo name/description
            cve_matches = re.findall(r"(CVE-\d{4}-\d+)", f"{name} {desc}", re.IGNORECASE)
            for cve_id in cve_matches:
                cve_id = cve_id.upper()
                if cve_id in seen_cves:
                    continue
                seen_cves.add(cve_id)

                candidates.append(CVECandidate(
                    cve_id=cve_id,
                    description=desc[:300],
                    has_public_exploit=True,
                    exploit_urls=[repo.get("html_url", "")],
                    source="github",
                    reason=f"GitHub repo with {stars} stars",
                ))

    console.print(f"  [dim]GitHub search found {len(candidates)} CVEs with public exploits[/]")
    return candidates


# ── nomi-sec PoC aggregator ──────────────────────────────────────────


def _search_nomi_sec(kernel_version: str) -> list[CVECandidate]:
    """Check nomi-sec PoC-in-GitHub aggregator for kernel CVEs."""
    candidates: list[CVECandidate] = []

    branch = re.match(r"(\d+\.\d+)", kernel_version)
    if not branch:
        return candidates

    # nomi-sec indexes CVE → GitHub PoCs. We check recent years.
    import datetime
    current_year = datetime.datetime.now().year

    console.print("  [dim]Checking nomi-sec PoC aggregator…[/]")
    for year in range(current_year, current_year - 4, -1):
        url = f"https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}.json"
        try:
            data = _fetch_json(url)
            if not isinstance(data, dict):
                continue
            for cve_id, repos in data.items():
                if not isinstance(repos, list) or not repos:
                    continue
                # Check if any repo description mentions kernel
                for repo in repos[:3]:
                    desc = (repo.get("description") or "").lower()
                    if any(k in desc for k in ("kernel", "linux", "android", "lpe")):
                        candidates.append(CVECandidate(
                            cve_id=cve_id.upper(),
                            description=desc[:300],
                            has_public_exploit=True,
                            exploit_urls=[repo.get("html_url", "")],
                            source="nomi_sec",
                            reason="PoC-in-GitHub aggregator",
                        ))
                        break
        except Exception:
            continue

    console.print(f"  [dim]nomi-sec found {len(candidates)} kernel CVEs with PoCs[/]")
    return candidates


# ── LLM-based ranking ────────────────────────────────────────────────


_RANKING_PROMPT = """\
You are a kernel security researcher selecting CVEs for automated exploitation.

Target kernel: {kernel_version}
Platform: {platform}
Architecture: {arch}

Below is a list of CVE candidates. For each one, assess:
1. Whether it likely affects kernel {kernel_version}
2. Exploitability (UAF/double-free > OOB write > race > info leak > DoS)
3. Whether the bug is in an accessible subsystem (binder, io_uring, netfilter,
   pipe, filesystem, socket > less-accessible drivers)
4. Availability of public exploits or detailed write-ups
5. Whether it gives privilege escalation potential (not just crash)

CANDIDATES:
{candidates_text}

Return a JSON array of the TOP {max_results} most promising candidates,
ordered by exploitation priority (best first). For each entry:
{{
  "cve_id": "CVE-XXXX-XXXXX",
  "priority": 1-5,
  "vuln_type": "uaf|oob_write|oob_read|race_condition|double_free|type_confusion|integer_overflow|buffer_overflow",
  "affected_subsystem": "binder|netfilter|io_uring|pipe|filesystem|socket|driver|other",
  "reason": "Brief explanation of why this is a good target",
  "likely_affects_target": true/false
}}

Return ONLY the JSON array. No explanation.
"""


def _rank_candidates(
    candidates: list[CVECandidate],
    kernel_version: str,
    platform: str = "android",
    arch: str = "arm64",
    max_results: int = 15,
    cfg: Optional[Config] = None,
) -> list[CVECandidate]:
    """Use LLM to rank and filter candidates by exploitability."""
    if not candidates:
        return []

    cfg = cfg or load_config()
    llm = LLMClient(cfg).for_task("analysis")

    # Build candidate text
    lines: list[str] = []
    for i, c in enumerate(candidates[:60], 1):  # Cap at 60 for prompt size
        lines.append(
            f"{i}. {c.cve_id} (CVSS {c.cvss_score}, {c.severity})\n"
            f"   Source: {c.source}\n"
            f"   {c.description[:200]}\n"
            f"   Public exploit: {c.has_public_exploit}\n"
            f"   Subsystem: {c.affected_subsystem or 'unknown'}\n"
        )

    prompt = _RANKING_PROMPT.format(
        kernel_version=kernel_version,
        platform=platform,
        arch=arch,
        candidates_text="\n".join(lines),
        max_results=max_results,
    )

    response = llm.chat(
        [{"role": "user", "content": prompt}],
        max_retries=2,
        max_tokens=4096,
    )

    # Parse JSON response
    try:
        from ..core.llm import _extract_json
        ranked = _extract_json(response)
        if not isinstance(ranked, list):
            ranked = [ranked]
    except Exception:
        console.print("  [yellow]Failed to parse LLM ranking response[/]")
        return candidates[:max_results]

    # Merge LLM rankings back into candidates
    cve_map = {c.cve_id: c for c in candidates}
    result: list[CVECandidate] = []
    for entry in ranked:
        cve_id = entry.get("cve_id", "")
        if cve_id in cve_map:
            c = cve_map[cve_id]
            c.priority = entry.get("priority", 3)
            c.vuln_type = entry.get("vuln_type", c.vuln_type)
            c.affected_subsystem = entry.get("affected_subsystem", c.affected_subsystem)
            c.reason = entry.get("reason", c.reason)
            if entry.get("likely_affects_target", True):
                result.append(c)
        else:
            # LLM mentioned a CVE not in our list — could be hallucinated
            # but worth noting
            result.append(CVECandidate(
                cve_id=cve_id,
                priority=entry.get("priority", 3),
                vuln_type=entry.get("vuln_type", ""),
                affected_subsystem=entry.get("affected_subsystem", ""),
                reason=entry.get("reason", "LLM-suggested"),
                source="llm_suggested",
            ))

    return result[:max_results]


# ── Main entry point ─────────────────────────────────────────────────


def hunt_cves(
    kernel_version: str,
    *,
    platform: str = "android",
    arch: str = "arm64",
    max_results: int = 15,
    cfg: Optional[Config] = None,
    skip_nvd: bool = False,
    skip_bulletins: bool = False,
    skip_github: bool = False,
    skip_nomi_sec: bool = False,
) -> list[CVECandidate]:
    """Discover CVEs affecting a kernel version and rank by exploitability.

    Searches multiple sources (NVD, Android bulletins, GitHub, nomi-sec)
    and uses LLM ranking to select the most promising candidates.

    Returns a list of CVECandidate objects sorted by priority (1=best).
    """
    console.print(f"[bold]Hunting CVEs for kernel {kernel_version} ({platform}/{arch})…[/]")

    all_candidates: list[CVECandidate] = []
    seen_cves: set[str] = set()

    def _add(candidates: list[CVECandidate]) -> None:
        for c in candidates:
            if c.cve_id and c.cve_id not in seen_cves:
                seen_cves.add(c.cve_id)
                all_candidates.append(c)

    # Gather from all sources
    if not skip_nvd:
        _add(_query_nvd_kernel_cves(kernel_version, max_results=50))

    if not skip_bulletins and platform == "android":
        _add(_query_android_bulletins(kernel_version, max_results=30))

    if not skip_github:
        _add(_search_github_exploits_for_kernel(kernel_version, cfg))

    if not skip_nomi_sec:
        _add(_search_nomi_sec(kernel_version))

    console.print(
        f"  [bold]Total unique candidates: {len(all_candidates)}[/]"
    )

    if not all_candidates:
        return []

    # LLM-based ranking
    ranked = _rank_candidates(
        all_candidates,
        kernel_version,
        platform=platform,
        arch=arch,
        max_results=max_results,
        cfg=cfg,
    )

    console.print(f"  [bold green]Selected {len(ranked)} targets for exploitation[/]")
    for i, c in enumerate(ranked, 1):
        console.print(
            f"  {i}. {c.cve_id} (P{c.priority}) — {c.vuln_type} "
            f"in {c.affected_subsystem}: {c.reason[:80]}"
        )

    return ranked
