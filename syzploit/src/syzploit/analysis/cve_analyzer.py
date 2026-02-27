"""
analysis.cve_analyzer — Fetch and analyse a CVE from NVD / MITRE,
                        search for PoCs on GitHub, and produce LLM
                        classification.
"""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

from ..core.config import Config, load_config
from ..core.llm import LLMClient, _extract_json
from ..core.log import console
from ..core.models import CrashReport, RootCauseAnalysis, VulnType

# ── NVD / MITRE fetchers ─────────────────────────────────────────────


def _fetch_url(url: str, timeout: int = 30) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "syzploit/0.2"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _fetch_nvd(cve_id: str) -> Dict[str, Any]:
    """Fetch CVE data from NVD 2.0 API."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        raw = _fetch_url(url)
        data = json.loads(raw)
        vulns = data.get("vulnerabilities", [])
        if vulns:
            return vulns[0].get("cve", {})
    except Exception:
        pass
    return {}


def _fetch_mitre(cve_id: str) -> Dict[str, Any]:
    """Fetch from MITRE CVE API as fallback."""
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    try:
        raw = _fetch_url(url)
        return json.loads(raw)
    except Exception:
        return {}


# ── GitHub PoC search ─────────────────────────────────────────────────


def _search_github_pocs(cve_id: str) -> List[Dict[str, str]]:
    """Search GitHub for PoC repositories matching *cve_id*."""
    query = urllib.parse.quote(f"{cve_id} poc exploit kernel")
    url = f"https://api.github.com/search/repositories?q={query}&sort=stars&per_page=5"
    try:
        raw = _fetch_url(url)
        data = json.loads(raw)
        results = []
        for item in data.get("items", [])[:5]:
            results.append({
                "name": item.get("full_name", ""),
                "url": item.get("html_url", ""),
                "description": item.get("description", ""),
                "stars": str(item.get("stargazers_count", 0)),
            })
        return results
    except Exception:
        return []


# ── LLM analysis ─────────────────────────────────────────────────────

_CVE_ANALYSIS_PROMPT = """\
Analyze this Linux kernel CVE and provide a structured assessment.

CVE ID: {cve_id}

NVD Description:
{nvd_description}

References:
{references}

Known PoC repositories:
{pocs}

Return JSON with:
{{
    "vulnerability_type": "<uaf|oob_read|oob_write|double_free|race_condition|type_confusion|integer_overflow|null_deref|logic_bug|unknown>",
    "affected_subsystem": "<kernel subsystem>",
    "affected_structs": ["<struct names>"],
    "affected_functions": ["<function names>"],
    "syscalls": ["<related syscalls>"],
    "slab_caches": ["<if applicable>"],
    "root_cause_description": "<detailed root cause explanation>",
    "trigger_conditions": ["<conditions needed to trigger the bug>"],
    "exploitability_score": <0-100>,
    "fix_commit": "<commit hash if known>",
    "summary": "<1-2 sentence summary>"
}}
"""


def analyze_cve(
    cve_id: str,
    *,
    cfg: Optional[Config] = None,
) -> RootCauseAnalysis:
    """
    Fetch CVE data from NVD/MITRE, search for PoCs, and produce
    an LLM-driven root cause analysis.
    """
    cfg = cfg or load_config()
    llm = LLMClient(cfg).for_task("analysis")

    console.print(f"[bold]Analyzing {cve_id}…[/]")

    # Fetch from NVD
    nvd = _fetch_nvd(cve_id)
    descriptions = nvd.get("descriptions", [])
    nvd_desc = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        str(descriptions),
    )

    # Collect references
    refs = nvd.get("references", [])
    ref_text = "\n".join(
        f"  - {r.get('url', '')} ({r.get('source', '')})" for r in refs[:10]
    )

    # Search GitHub PoCs
    pocs = _search_github_pocs(cve_id)
    poc_text = "\n".join(
        f"  - {p['name']} ({p['url']}) ★{p['stars']}: {p['description']}"
        for p in pocs
    ) or "  (none found)"

    # LLM analysis
    prompt = _CVE_ANALYSIS_PROMPT.format(
        cve_id=cve_id,
        nvd_description=nvd_desc,
        references=ref_text or "  (none)",
        pocs=poc_text,
    )
    result = llm.ask_json(prompt, system="You are a kernel security analyst.")

    return RootCauseAnalysis(
        summary=result.get("summary", ""),
        vulnerability_type=VulnType.from_str(result.get("vulnerability_type", "unknown")),
        root_cause_description=result.get("root_cause_description", ""),
        trigger_conditions=result.get("trigger_conditions", []),
        affected_subsystem=result.get("affected_subsystem", ""),
        affected_structs=result.get("affected_structs", []),
        kernel_functions=result.get("affected_functions", []),
        syscalls=result.get("syscalls", []),
        slab_caches=result.get("slab_caches", []),
        exploitability_score=result.get("exploitability_score", 0),
        fix_commit=result.get("fix_commit"),
    )
