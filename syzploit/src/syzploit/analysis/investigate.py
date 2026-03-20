"""
analysis.investigate — Automated CVE investigation via web scraping.

Given a CVE number, this module automatically:
  1. Fetches CVE details from NVD / MITRE
  2. Searches for existing exploits on GitHub / Exploit-DB
  3. Discovers and scrapes relevant blog posts & write-ups
  4. Locates kernel patch notes / fix commits
  5. Extracts source code references (files, functions, structs)
  6. Pulls the actual patched source from git.kernel.org
  7. Produces a comprehensive InvestigationReport combining all findings

Usage::

    from syzploit.analysis.investigate import investigate_cve

    report = investigate_cve("CVE-2023-20938")
    print(report.summary())
"""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..core.config import Config, load_config
from ..core.llm import LLMClient, _extract_json
from ..core.log import console
from ..core.models import RootCauseAnalysis, VulnType

try:
    from bs4 import BeautifulSoup
    _HAS_BS4 = True
except ImportError:
    _HAS_BS4 = False


# ── Data Models ───────────────────────────────────────────────────────


@dataclass
class ExploitReference:
    """A reference to an existing exploit or PoC."""
    source: str = ""       # "github", "exploit-db", "blog", "patchwork"
    url: str = ""
    title: str = ""
    description: str = ""
    stars: int = 0
    code_snippet: str = ""  # Key code excerpt if available
    language: str = ""


@dataclass
class PatchInfo:
    """Information about a kernel patch / fix commit."""
    commit_hash: str = ""
    commit_url: str = ""
    commit_message: str = ""
    author: str = ""
    date: str = ""
    files_changed: List[str] = field(default_factory=list)
    diff_excerpt: str = ""
    patch_source: str = ""  # "kernel.org", "android", "github"
    vulnerability_analysis: str = ""  # Deep LLM analysis of what the fix changed


@dataclass
class SourceCodeContext:
    """Extracted source code context from the kernel tree."""
    file_path: str = ""
    function_name: str = ""
    source_code: str = ""
    source_url: str = ""
    version: str = ""       # Kernel version / tag


@dataclass
class BlogPostAnalysis:
    """Analysis extracted from a blog post / write-up."""
    url: str = ""
    title: str = ""
    text_excerpt: str = ""
    code_blocks: List[str] = field(default_factory=list)
    exploitation_technique: str = ""
    key_insights: List[str] = field(default_factory=list)


@dataclass
class InvestigationReport:
    """Comprehensive investigation report for a CVE."""
    cve_id: str = ""
    nvd_description: str = ""
    cvss_score: float = 0.0
    severity: str = ""
    affected_subsystem: str = ""
    vulnerability_type: str = ""

    # Discovered references
    exploit_references: List[ExploitReference] = field(default_factory=list)
    patch_info: List[PatchInfo] = field(default_factory=list)
    blog_analyses: List[BlogPostAnalysis] = field(default_factory=list)
    source_contexts: List[SourceCodeContext] = field(default_factory=list)

    # Extracted identifiers
    affected_files: List[str] = field(default_factory=list)
    affected_functions: List[str] = field(default_factory=list)
    affected_structs: List[str] = field(default_factory=list)
    fix_commits: List[str] = field(default_factory=list)
    related_cves: List[str] = field(default_factory=list)

    # LLM-synthesised understanding
    root_cause: Optional[RootCauseAnalysis] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)

    # Errors encountered during investigation
    errors: List[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            f"═══ Investigation Report: {self.cve_id} ═══",
            f"  Description: {self.nvd_description[:200]}{'…' if len(self.nvd_description) > 200 else ''}",
            f"  CVSS: {self.cvss_score} ({self.severity})",
            f"  Type: {self.vulnerability_type}",
            f"  Subsystem: {self.affected_subsystem}",
            f"  Affected files: {', '.join(self.affected_files[:5]) or 'N/A'}",
            f"  Affected functions: {', '.join(self.affected_functions[:5]) or 'N/A'}",
            f"  Affected structs: {', '.join(self.affected_structs[:5]) or 'N/A'}",
            f"  Fix commits: {len(self.fix_commits)}",
            f"  Exploits found: {len(self.exploit_references)}",
            f"  Blog posts: {len(self.blog_analyses)}",
            f"  Patches: {len(self.patch_info)}",
            f"  Source contexts: {len(self.source_contexts)}",
        ]
        if self.errors:
            lines.append(f"  Errors: {len(self.errors)}")
            for e in self.errors[:3]:
                lines.append(f"    - {e[:100]}")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a JSON-compatible dict."""
        return {
            "cve_id": self.cve_id,
            "nvd_description": self.nvd_description,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "affected_subsystem": self.affected_subsystem,
            "vulnerability_type": self.vulnerability_type,
            "affected_files": self.affected_files,
            "affected_functions": self.affected_functions,
            "affected_structs": self.affected_structs,
            "fix_commits": self.fix_commits,
            "related_cves": self.related_cves,
            "exploit_references": [
                {"source": e.source, "url": e.url, "title": e.title,
                 "description": e.description, "stars": e.stars,
                 "code_snippet": e.code_snippet, "language": e.language}
                for e in self.exploit_references
            ],
            "patch_info": [
                {"commit_hash": p.commit_hash, "commit_url": p.commit_url,
                 "commit_message": p.commit_message, "files_changed": p.files_changed,
                 "patch_source": p.patch_source, "diff_excerpt": p.diff_excerpt[:8000],
                 "vulnerability_analysis": p.vulnerability_analysis[:6000]}
                for p in self.patch_info
            ],
            "blog_analyses": [
                {"url": b.url, "title": b.title,
                 "exploitation_technique": b.exploitation_technique,
                 "key_insights": b.key_insights,
                 "text_excerpt": b.text_excerpt[:8000],
                 "code_blocks": [cb[:4000] for cb in b.code_blocks[:15]]}
                for b in self.blog_analyses
            ],
            "source_contexts": [
                {"file_path": s.file_path, "function_name": s.function_name,
                 "source_url": s.source_url, "source_code": s.source_code[:5000]}
                for s in self.source_contexts
            ],
            "errors": self.errors,
        }


# ── HTTP helpers ──────────────────────────────────────────────────────


def _fetch_url(url: str, timeout: int = 30) -> str:
    """Fetch a URL and return its text content."""
    req = urllib.request.Request(url, headers={
        "User-Agent": "syzploit/0.2 (kernel-security-research)",
        "Accept": "text/html,application/json,*/*",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _fetch_json(url: str, timeout: int = 30) -> Dict[str, Any]:
    """Fetch a URL and parse as JSON."""
    try:
        raw = _fetch_url(url, timeout)
        return json.loads(raw)
    except Exception:
        return {}


def _github_headers(cfg: Optional[Config] = None) -> Dict[str, str]:
    """Build HTTP headers for GitHub API, with auth token if available."""
    headers = {
        "User-Agent": "syzploit/0.2 (kernel-security-research)",
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
    return headers


def _fetch_github_json(url: str, cfg: Optional[Config] = None, timeout: int = 30) -> Dict[str, Any]:
    """Fetch a GitHub API URL with optional auth token."""
    try:
        req = urllib.request.Request(url, headers=_github_headers(cfg))
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        return {}


def _extract_text(html: str) -> str:
    """Extract readable text from HTML."""
    if _HAS_BS4:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script", "style", "nav", "footer", "header"]):
            tag.decompose()
        return soup.get_text(separator="\n", strip=True)
    text = re.sub(r"<[^>]+>", " ", html)
    return re.sub(r"\s+", " ", text).strip()


def _extract_code_blocks(html: str) -> List[str]:
    """Extract code blocks from HTML, preserving whitespace.

    Modern blogs use syntax-highlighter markup (Hugo/Chroma, Prism, hljs)
    which wraps each token in ``<span>``.  Using ``get_text(strip=True)``
    would collapse all whitespace (``int fd`` → ``intfd``).  Instead we
    use ``.text`` which respects the original whitespace in the source.

    We search ``<pre>`` only (not bare ``<code>``) to avoid duplicates;
    ``<code>`` blocks inside ``<pre>`` are already captured.
    """
    blocks: List[str] = []
    seen_hashes: set = set()
    if _HAS_BS4:
        soup = BeautifulSoup(html, "html.parser")
        # First pass: <pre> blocks (which may contain <code>)
        for pre in soup.find_all("pre"):
            code = pre.text  # preserves whitespace
            if len(code.strip()) < 30:
                continue
            # De-duplicate (blogs often repeat code blocks)
            h = hash(code.strip()[:300])
            if h in seen_hashes:
                continue
            seen_hashes.add(h)
            blocks.append(code)
        # Second pass: standalone <code> NOT inside <pre>
        for code_tag in soup.find_all("code"):
            if code_tag.find_parent("pre"):
                continue  # already captured above
            code = code_tag.text
            if len(code.strip()) < 30:
                continue
            h = hash(code.strip()[:300])
            if h in seen_hashes:
                continue
            seen_hashes.add(h)
            blocks.append(code)
    else:
        # Regex fallback
        for m in re.finditer(r'<pre[^>]*>(.*?)</pre>', html, re.DOTALL | re.IGNORECASE):
            code = re.sub(r'<[^>]+>', '', m.group(1))
            if len(code.strip()) > 30:
                blocks.append(code)
    return blocks


# ── NVD / MITRE fetchers ─────────────────────────────────────────────


def _fetch_nvd(cve_id: str) -> Dict[str, Any]:
    """Fetch CVE data from NVD 2.0 API."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        data = _fetch_json(url)
        vulns = data.get("vulnerabilities", [])
        if vulns:
            return vulns[0].get("cve", {})
    except Exception:
        pass
    return {}


def _fetch_mitre(cve_id: str) -> Dict[str, Any]:
    """Fetch from MITRE CVE API as fallback."""
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    return _fetch_json(url)


def _extract_nvd_info(nvd: Dict[str, Any]) -> Dict[str, Any]:
    """Extract key fields from NVD CVE record."""
    descriptions = nvd.get("descriptions", [])
    desc = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        str(descriptions),
    )

    # CVSS score
    cvss_score = 0.0
    severity = "unknown"
    metrics = nvd.get("metrics", {})
    for version in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(version, [])
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            severity = cvss_data.get("baseSeverity", "unknown")
            break

    # References
    refs = nvd.get("references", [])
    ref_urls = [r.get("url", "") for r in refs]

    # Weaknesses (CWE)
    weaknesses = nvd.get("weaknesses", [])
    cwes = []
    for w in weaknesses:
        for d in w.get("description", []):
            if d.get("value", "").startswith("CWE-"):
                cwes.append(d["value"])

    return {
        "description": desc,
        "cvss_score": cvss_score,
        "severity": severity,
        "references": ref_urls,
        "cwes": cwes,
    }


# ── Exploit / PoC search ─────────────────────────────────────────────


def _search_github_exploits(cve_id: str, cfg: Optional[Config] = None) -> List[ExploitReference]:
    """Search GitHub for PoC repositories.

    Uses multiple search strategies:
    1. Repo search with just the CVE ID (broadest — finds repos named after the CVE)
    2. Repo search with CVE ID + "exploit" (finds repos mentioning it)
    3. nomi-sec/PoC-in-GitHub direct JSON lookup (no auth needed)
    4. GitHub code search in nomi-sec aggregator (needs auth)
    """
    results: List[ExploitReference] = []
    seen_urls: set = set()

    def _add(ref: ExploitReference) -> None:
        if ref.url and ref.url not in seen_urls:
            seen_urls.add(ref.url)
            results.append(ref)

    # Search 1: Just CVE ID (catches repos named CVE-YYYY-NNNNN)
    for search_query in [cve_id, f"{cve_id} exploit", f"{cve_id} poc"]:
        query = urllib.parse.quote(search_query)
        url = f"https://api.github.com/search/repositories?q={query}&sort=stars&per_page=10"
        try:
            data = _fetch_github_json(url, cfg)
            for item in data.get("items", [])[:10]:
                _add(ExploitReference(
                    source="github",
                    url=item.get("html_url", ""),
                    title=item.get("full_name", ""),
                    description=item.get("description", "") or "",
                    stars=item.get("stargazers_count", 0),
                    language=item.get("language", "") or "",
                ))
        except Exception:
            pass

    # Search 2: nomi-sec/PoC-in-GitHub direct JSON lookup
    #   This aggregator maintains per-CVE JSON files that list all known
    #   GitHub PoC repos.  Accessing raw.githubusercontent.com doesn't
    #   require auth and never hits API rate limits.
    year = cve_id.split("-")[1] if "-" in cve_id else ""
    if year:
        nomi_url = (
            f"https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/"
            f"master/{year}/{cve_id}.json"
        )
        try:
            raw = _fetch_url(nomi_url, timeout=15)
            entries = json.loads(raw)
            if isinstance(entries, list):
                for entry in entries[:10]:
                    _add(ExploitReference(
                        source="github",
                        url=entry.get("html_url", ""),
                        title=entry.get("full_name", ""),
                        description=entry.get("description", "") or "",
                        stars=entry.get("stargazers_count", 0),
                        language=entry.get("language", "") or "",
                    ))
        except Exception:
            pass

    # Search 3: GitHub code search in nomi-sec aggregator (needs auth)
    agg_query = urllib.parse.quote(f"{cve_id}")
    agg_url = (
        f"https://api.github.com/search/code?q={agg_query}"
        f"+filename:README.md+repo:nomi-sec/PoC-in-GitHub&per_page=5"
    )
    try:
        data = _fetch_github_json(agg_url, cfg)
        for item in data.get("items", [])[:3]:
            repo = item.get("repository", {})
            _add(ExploitReference(
                source="github-aggregator",
                url=item.get("html_url", ""),
                title=repo.get("full_name", ""),
                description=f"PoC aggregator entry for {cve_id}",
            ))
    except Exception:
        pass

    return results


def _search_exploit_db(cve_id: str) -> List[ExploitReference]:
    """Search Exploit-DB for matching exploits via the web interface."""
    results: List[ExploitReference] = []
    # Exploit-DB search by CVE
    search_url = f"https://www.exploit-db.com/search?cve={cve_id.replace('CVE-', '')}"
    try:
        html = _fetch_url(search_url)
        # Parse EDB entries — look for links to /exploits/ pages
        if _HAS_BS4:
            soup = BeautifulSoup(html, "html.parser")
            for link in soup.find_all("a", href=True):
                href = link["href"]
                if "/exploits/" in str(href):
                    results.append(ExploitReference(
                        source="exploit-db",
                        url=f"https://www.exploit-db.com{href}" if href.startswith("/") else href,
                        title=link.get_text(strip=True)[:200],
                        description=f"Exploit-DB entry for {cve_id}",
                    ))
        if not results:
            # Fallback: regex search for exploit IDs
            for m in re.finditer(r'/exploits/(\d+)', html):
                eid = m.group(1)
                results.append(ExploitReference(
                    source="exploit-db",
                    url=f"https://www.exploit-db.com/exploits/{eid}",
                    title=f"EDB-{eid}",
                    description=f"Exploit-DB entry for {cve_id}",
                ))
    except Exception:
        pass

    # Deduplicate by URL
    seen: set[str] = set()
    deduped: List[ExploitReference] = []
    for r in results:
        if r.url not in seen:
            seen.add(r.url)
            deduped.append(r)
    return deduped[:5]


# ── Recursive extraction helpers ──────────────────────────────────────


def _extract_urls_from_text(text: str) -> List[str]:
    """Extract HTTP(S) URLs from raw text."""
    return re.findall(r'https?://[^\s<>"\')]+', text)


def _extract_commit_hashes_from_text(text: str) -> List[str]:
    """Extract plausible git commit hashes from raw text."""
    # Match 12-40 hex chars that look like commit hashes
    # (must be bounded by non-hex so we don't match random hex strings)
    hashes = re.findall(r'(?<![0-9a-f])([0-9a-f]{12,40})(?![0-9a-f])', text)
    return list(dict.fromkeys(hashes))  # deduplicate, preserve order


def _extract_kernel_paths_from_text(text: str) -> List[str]:
    """Extract kernel source file paths from raw text."""
    paths = re.findall(
        r'(?:^|\s|/)([a-z][a-z0-9_/]*(?:/[a-z][a-z0-9_]*)+\.[ch])\b',
        text,
    )
    # Filter to plausible kernel paths
    plausible = [
        p for p in paths
        if any(p.startswith(d) for d in (
            "drivers/", "fs/", "kernel/", "mm/", "net/", "security/",
            "ipc/", "block/", "sound/", "arch/", "include/", "lib/",
            "crypto/", "io_uring/",
        ))
    ]
    return list(dict.fromkeys(plausible))


def _extract_cves_from_text(text: str) -> List[str]:
    """Extract CVE identifiers from raw text."""
    return list(dict.fromkeys(
        re.findall(r'CVE-\d{4}-\d{4,}', text, re.IGNORECASE)
    ))


def _extract_patch_urls_from_text(text: str) -> List[str]:
    """Extract URLs that look like patch/commit links from text."""
    urls = _extract_urls_from_text(text)
    patch_patterns = [
        "git.kernel.org",
        "github.com/torvalds/linux/commit",
        "android.googlesource.com",
        "lore.kernel.org",
        "patchwork.kernel.org",
        "patchwork.ozlabs.org",
    ]
    return [u for u in urls if any(p in u.lower() for p in patch_patterns)]


# ── Blog / write-up discovery ────────────────────────────────────────


# Android / binder / driver-specific research blogs — searched first for
# Android CVEs and always included in the search set.
_ANDROID_BLOG_DOMAINS = [
    "androidoffsec.withgoogle.com",
    "research.google",
    "bughunters.google.com",
    "googleprojectzero.blogspot.com",
    "google.github.io/security-research",
    "bugs.chromium.org",
]

# General kernel / security research blogs.
_GENERAL_BLOG_DOMAINS = [
    "blog.google",
    "securitylab.github.com",
    "starlabs.sg",
    "zerodayinitiative.com",
    "ssd-disclosure.com",
    "a13xk.github.io",
    "github.blog",
    "phrack.org",
    "labs.bluefrostsecurity.de",
    "blog.exodusintel.com",
    "securelist.com",
    "i.blackhat.com",
    "paper.seebug.org",
    "blog.longterm.io",
    "markof.dev",
    "blog.thalium.re",
    "blog.hacktivesecurity.com",
    "struct.github.io",
    "duasynt.com",
    "pwning.tech",
    "lkmidas.github.io",
    "syst3mfailure.io",
    "www.willsroot.io",
]

# Combined list (used for URL matching in NVD references, etc.)
_BLOG_SEARCH_DOMAINS = _ANDROID_BLOG_DOMAINS + _GENERAL_BLOG_DOMAINS


def _discover_blog_posts(
    cve_id: str,
    nvd_refs: List[str],
) -> List[str]:
    """
    Discover blog posts / write-ups about a CVE.

    Sources:
    1. NVD reference URLs (often link to advisories, patches, blogs)
    2. GitHub search (README/writeup files mentioning the CVE)
    3. Known security blog domains
    """
    discovered: List[str] = []

    # 1. Filter NVD references for blog-like URLs
    blog_indicators = [
        "blog", "writeup", "write-up", "advisory", "analysis",
        "disclosure", "research", "exploit", "vulnerability",
        "security", "poc", "paper",
    ]
    for ref in nvd_refs:
        ref_lower = ref.lower()
        # Skip pure patch / commit URLs — they go to patch_info
        if any(x in ref_lower for x in [
            "git.kernel.org/pub/scm",
            "github.com/torvalds/linux/commit",
            "android.googlesource.com",
            "lore.kernel.org",
        ]):
            continue
        # Include if it looks like a blog / advisory
        if any(indicator in ref_lower for indicator in blog_indicators):
            discovered.append(ref)
        elif any(domain in ref_lower for domain in _BLOG_SEARCH_DOMAINS):
            discovered.append(ref)

    # 2. Search GitHub for writeups
    query = urllib.parse.quote(f"{cve_id} writeup analysis exploit kernel")
    gurl = f"https://api.github.com/search/code?q={query}+extension:md&per_page=5"
    try:
        data = _fetch_json(gurl)
        for item in data.get("items", [])[:5]:
            html_url = item.get("html_url", "")
            if html_url and html_url not in discovered:
                discovered.append(html_url)
    except Exception:
        pass

    # 3. DuckDuckGo HTML search for known security blog domains.
    # Always search Android-specific blogs first, then general ones
    # up to a budget of 15 total DDG queries.
    is_android = any(kw in cve_id.lower() or kw in " ".join(nvd_refs).lower()
                     for kw in ["android", "binder", "mali", "qualcomm",
                                "mediatek", "pixel"])
    search_order: List[str] = list(_ANDROID_BLOG_DOMAINS)
    for d in _GENERAL_BLOG_DOMAINS:
        if d not in search_order:
            search_order.append(d)
    ddg_budget = 20 if is_android else 15
    for domain in search_order[:ddg_budget]:
        try:
            ddg_query = urllib.parse.quote(f"site:{domain} {cve_id}")
            ddg_url = f"https://html.duckduckgo.com/html/?q={ddg_query}"
            html = _fetch_url(ddg_url, timeout=10)
            # Extract result URLs from DuckDuckGo HTML
            for m in re.finditer(r'href="(https?://[^"]+)"', html):
                href = m.group(1)
                # Filter: must be from the target domain, not DDG infra
                if domain in href and href not in discovered:
                    discovered.append(href)
        except Exception:
            pass

    return discovered[:15]


def _scrape_blog_post(
    url: str,
    *,
    cve_id: str = "",
    cfg: Optional[Config] = None,
) -> Optional[BlogPostAnalysis]:
    """Scrape a single blog post URL and extract key content.

    Extracts text, code blocks, and uses LLM to identify
    exploitation techniques and key insights when *cfg* is provided.
    """
    try:
        html = _fetch_url(url, timeout=20)
    except Exception:
        return None

    text = _extract_text(html)
    code_blocks = _extract_code_blocks(html)

    # Extract title
    title = ""
    if _HAS_BS4:
        soup = BeautifulSoup(html, "html.parser")
        title_tag = soup.find("title")
        if title_tag:
            title = title_tag.get_text(strip=True)
    if not title:
        m = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        if m:
            title = m.group(1).strip()

    analysis = BlogPostAnalysis(
        url=url,
        title=title[:200],
        text_excerpt=text[:16000],
        code_blocks=code_blocks[:15],
    )

    # Use LLM to extract exploitation technique & key insights
    if cfg is not None and text:
        try:
            llm = LLMClient(cfg).for_task("analysis")
            extract_prompt = (
                f"Given the following blog post excerpt about {cve_id or 'a kernel vulnerability'}, "
                f"extract the exploitation technique and key insights.\n\n"
                f"Title: {title}\n"
                f"Text (truncated):\n{text[:8000]}\n\n"
                f"Respond in JSON:\n"
                f'{{"exploitation_technique": "<brief technique description>",'
                f' "key_insights": ["<insight 1>", "<insight 2>", ...]}}'
            )
            result = llm.ask_json(extract_prompt, system="You are a kernel security analyst.")
            analysis.exploitation_technique = result.get("exploitation_technique", "")
            analysis.key_insights = result.get("key_insights", [])
        except Exception:
            pass

    return analysis


# ── Patch / fix commit discovery ──────────────────────────────────────


def _discover_patches(
    cve_id: str,
    nvd_refs: List[str],
    cfg: Optional[Config] = None,
) -> List[PatchInfo]:
    """
    Discover kernel patches / fix commits for a CVE.

    Sources:
    1. NVD reference URLs → git.kernel.org / android.googlesource.com
    2. lore.kernel.org patches
    3. GitHub torvalds/linux commits
    """
    patches: List[PatchInfo] = []
    seen_commits: set[str] = set()

    # 1. Extract commits from NVD references
    for ref in nvd_refs:
        ref_lower = ref.lower()

        # git.kernel.org commit URLs
        if "git.kernel.org" in ref_lower:
            commit_hash = _extract_commit_from_url(ref)
            if commit_hash and commit_hash not in seen_commits:
                seen_commits.add(commit_hash)
                patch = _fetch_kernel_org_commit(ref, commit_hash)
                if patch:
                    patches.append(patch)

        # GitHub Linux kernel commits
        elif "github.com/torvalds/linux/commit" in ref_lower:
            commit_hash = ref.rstrip("/").split("/")[-1]
            if commit_hash and commit_hash not in seen_commits:
                seen_commits.add(commit_hash)
                patch = _fetch_github_commit(commit_hash, cfg=cfg)
                if patch:
                    patches.append(patch)

        # Android source commits
        elif "android.googlesource.com" in ref_lower and "/+/" in ref:
            commit_hash = ref.split("/+/")[-1].split("?")[0].split("^")[0]
            if commit_hash and commit_hash not in seen_commits:
                seen_commits.add(commit_hash)
                patches.append(PatchInfo(
                    commit_hash=commit_hash,
                    commit_url=ref,
                    patch_source="android",
                ))

        # lore.kernel.org
        elif "lore.kernel.org" in ref_lower:
            patches.append(PatchInfo(
                commit_url=ref,
                patch_source="lore",
            ))

    # 2. Search GitHub for fix commits if none found
    if not patches:
        query = urllib.parse.quote(f"{cve_id}")
        url = f"https://api.github.com/search/commits?q={query}+repo:torvalds/linux&per_page=5"
        try:
            headers = _github_headers(cfg)
            headers["Accept"] = "application/vnd.github.cloak-preview+json"
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
            for item in data.get("items", [])[:3]:
                sha = item.get("sha", "")
                if sha and sha not in seen_commits:
                    seen_commits.add(sha)
                    commit_data = item.get("commit", {})
                    patches.append(PatchInfo(
                        commit_hash=sha,
                        commit_url=item.get("html_url", ""),
                        commit_message=commit_data.get("message", "")[:500],
                        author=commit_data.get("author", {}).get("name", ""),
                        date=commit_data.get("author", {}).get("date", ""),
                        patch_source="github",
                    ))
        except Exception:
            pass

    # 3. Search Android common kernel repos on GitHub
    # Android-specific CVEs often have fixes in android/kernel-common repos
    if not patches:
        for repo in [
            "torvalds/linux",
            "nicklaskvist/linux",  # mirrors sometimes index faster
        ]:
            query = urllib.parse.quote(f"{cve_id}")
            url = (
                f"https://api.github.com/search/commits?q={query}"
                f"+repo:{repo}&per_page=5"
            )
            try:
                headers = _github_headers(cfg)
                headers["Accept"] = "application/vnd.github.cloak-preview+json"
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read().decode())
                for item in data.get("items", [])[:3]:
                    sha = item.get("sha", "")
                    if sha and sha not in seen_commits:
                        seen_commits.add(sha)
                        commit_data = item.get("commit", {})
                        patches.append(PatchInfo(
                            commit_hash=sha,
                            commit_url=item.get("html_url", ""),
                            commit_message=commit_data.get("message", "")[:500],
                            author=commit_data.get("author", {}).get("name", ""),
                            date=commit_data.get("author", {}).get("date", ""),
                            patch_source="github",
                        ))
                if patches:
                    break
            except Exception:
                pass

    # 4. Scrape Android Security Bulletin for AOSP commit links
    # Many Android CVEs only reference the bulletin, which lists AOSP
    # change links like android.googlesource.com/...
    # IMPORTANT: The bulletin lists ALL CVEs for that month, so we must
    # extract only the commits associated with OUR specific CVE ID.
    for ref in nvd_refs:
        if "source.android.com/security/bulletin" not in ref.lower():
            continue
        try:
            html = _fetch_url(ref, timeout=20)
            found_for_cve = False

            # Preferred: Use BS4 to find table rows containing the CVE ID
            # and extract commit links only from those rows.
            if _HAS_BS4:
                soup = BeautifulSoup(html, "html.parser")
                for td in soup.find_all("td"):
                    if cve_id not in td.get_text():
                        continue
                    # Found a cell mentioning our CVE — check the entire row
                    row = td.find_parent("tr")
                    if not row:
                        continue
                    for a in row.find_all("a", href=True):
                        href = a["href"]
                        if "googlesource.com" not in href or "/+/" not in href:
                            continue
                        ch = href.split("/+/")[-1].split("?")[0].split("^")[0].split("%")[0]
                        if ch and ch not in seen_commits and len(ch) >= 7:
                            seen_commits.add(ch)
                            patches.append(PatchInfo(
                                commit_hash=ch,
                                commit_url=href if href.startswith("http") else f"https://android.googlesource.com{href}",
                                patch_source="android",
                            ))
                            found_for_cve = True

            # Fallback (no BS4): Narrow search to the HTML region
            # around the CVE ID mention — scan ±2000 chars.
            if not found_for_cve:
                for m_cve in re.finditer(re.escape(cve_id), html):
                    region_start = max(0, m_cve.start() - 500)
                    region_end = min(len(html), m_cve.end() + 2000)
                    region = html[region_start:region_end]
                    for m in re.finditer(
                        r'href="(https://android\.googlesource\.com/[^"]+/\+/([0-9a-f]{7,40}))"',
                        region,
                    ):
                        commit_url = m.group(1)
                        commit_hash = m.group(2)
                        if commit_hash not in seen_commits:
                            seen_commits.add(commit_hash)
                            patches.append(PatchInfo(
                                commit_hash=commit_hash,
                                commit_url=commit_url,
                                patch_source="android",
                            ))
        except Exception:
            pass

    return patches


def _extract_commit_from_url(url: str) -> str:
    """Extract commit hash from a git.kernel.org URL."""
    # Patterns:
    # ...;h=abc123
    # .../commit/?id=abc123
    m = re.search(r'[;?&](?:h|id)=([0-9a-f]{7,40})', url)
    if m:
        return m.group(1)
    # ...commit/abc123
    m = re.search(r'/commit/([0-9a-f]{7,40})', url)
    if m:
        return m.group(1)
    return ""


def _fetch_kernel_org_commit(url: str, commit_hash: str) -> Optional[PatchInfo]:
    """Fetch commit details from git.kernel.org."""
    try:
        html = _fetch_url(url, timeout=20)
        text = _extract_text(html)

        # Extract commit message (usually first paragraph)
        msg_lines = []
        in_msg = False
        for line in text.split("\n")[:50]:
            line = line.strip()
            if not line:
                if in_msg:
                    break
                continue
            if commit_hash[:7] in line or "commit" in line.lower():
                in_msg = True
                continue
            if in_msg:
                msg_lines.append(line)

        # Extract changed files from diff
        files = re.findall(r'(?:a|b)/([^\s]+\.[ch])', html)
        files = list(dict.fromkeys(files))  # Deduplicate preserving order

        return PatchInfo(
            commit_hash=commit_hash,
            commit_url=url,
            commit_message="\n".join(msg_lines[:20])[:1000],
            files_changed=files[:30],
            patch_source="kernel.org",
        )
    except Exception:
        return PatchInfo(
            commit_hash=commit_hash,
            commit_url=url,
            patch_source="kernel.org",
        )


def _fetch_github_commit(commit_hash: str, cfg: Optional[Config] = None) -> Optional[PatchInfo]:
    """Fetch commit details from GitHub."""
    url = f"https://api.github.com/repos/torvalds/linux/commits/{commit_hash}"
    try:
        data = _fetch_github_json(url, cfg)
        if not data:
            return None

        commit_data = data.get("commit", {})
        files = [f.get("filename", "") for f in data.get("files", [])[:30]]

        # Build diff excerpt from the patches — include more context
        diff_lines: List[str] = []
        for f in data.get("files", [])[:10]:
            patch = f.get("patch", "")
            if patch:
                diff_lines.append(f"--- {f.get('filename', '')}")
                diff_lines.append(patch[:4000])

        return PatchInfo(
            commit_hash=commit_hash,
            commit_url=data.get("html_url", ""),
            commit_message=commit_data.get("message", "")[:1000],
            author=commit_data.get("author", {}).get("name", ""),
            date=commit_data.get("author", {}).get("date", ""),
            files_changed=files,
            diff_excerpt="\n".join(diff_lines)[:8000],
            patch_source="github",
        )
    except Exception:
        return None


# ── Deep fix-commit analysis ─────────────────────────────────────────

_DEEP_ANALYSIS_PROMPT = """\
You are a kernel vulnerability researcher. Analyze the following fix commit \
for {cve_id} and extract a detailed understanding of the vulnerability.

## Commit info
Commit: {commit_hash}
Message: {commit_message}

## Files changed
{files_changed}

## Full diff
{diff_excerpt}

## Pre-fix source (vulnerable version)
{pre_fix_source}

## Post-fix source (patched version)
{post_fix_source}

Provide a detailed analysis in the following structure:
1. **What was vulnerable**: Describe the exact code path and condition that \
was exploitable before the fix. Identify the vulnerable function(s), the \
type of memory safety violation (UAF, double-free, OOB, race condition, etc.), \
and what data structures are involved.
2. **What the fix changed**: Describe precisely what the patch does — what \
checks/locks/refcounts/ordering were added or changed.
3. **Vulnerability pattern**: Describe the high-level pattern — e.g. \
"RCU-protected pointer read without holding the right lock, allowing a \
concurrent free" or "missing refcount increment before async callback \
registration".
4. **Trigger conditions**: How could an attacker trigger the vulnerable path? \
Which syscalls, ioctls, or operations reach it? What race conditions or \
timing windows exist?
5. **Exploitation primitives**: What exploitation primitive does this bug \
provide? (e.g. UAF on a specific slab cache, arbitrary write via corrupted \
struct field, info leak via uninitialized memory)
6. **Key structs and sizes**: List all kernel structs involved, their \
approximate sizes, and which slab caches they belong to.
7. **Recommended exploitation approach**: Based on the bug class and \
affected objects, what exploitation strategy would you recommend?

Be technically precise. Reference specific function names, struct fields, \
and line numbers from the diff.
"""


def _deep_analyze_fix_commit(
    patch: PatchInfo,
    cve_id: str,
    cfg: Config,
) -> str:
    """Perform deep LLM analysis of a fix commit to extract vulnerability patterns.

    Fetches pre-fix and post-fix source for the primary changed files,
    then uses LLM to produce a detailed vulnerability analysis comparing
    the two versions.

    Returns the analysis text, also stored in ``patch.vulnerability_analysis``.
    """
    if not patch.commit_hash or not patch.diff_excerpt:
        return ""

    # Fetch pre-fix (parent commit) and post-fix source for key files
    pre_fix_parts: List[str] = []
    post_fix_parts: List[str] = []
    source_files = [f for f in patch.files_changed if f.endswith((".c", ".h"))]

    for fpath in source_files[:3]:
        # Pre-fix: parent commit
        pre_ctx = _fetch_kernel_source(
            fpath, version=f"{patch.commit_hash}^",
        )
        if pre_ctx and pre_ctx.source_code:
            pre_fix_parts.append(
                f"--- {fpath} (pre-fix) ---\n{pre_ctx.source_code[:8000]}"
            )

        # Post-fix: fix commit
        post_ctx = _fetch_kernel_source(
            fpath, version=patch.commit_hash,
        )
        if post_ctx and post_ctx.source_code:
            post_fix_parts.append(
                f"--- {fpath} (post-fix) ---\n{post_ctx.source_code[:8000]}"
            )

    pre_fix_source = "\n\n".join(pre_fix_parts) or "(could not fetch pre-fix source)"
    post_fix_source = "\n\n".join(post_fix_parts) or "(could not fetch post-fix source)"

    prompt = _DEEP_ANALYSIS_PROMPT.format(
        cve_id=cve_id,
        commit_hash=patch.commit_hash,
        commit_message=patch.commit_message[:1500],
        files_changed=", ".join(patch.files_changed[:15]),
        diff_excerpt=patch.diff_excerpt[:12000],
        pre_fix_source=pre_fix_source[:16000],
        post_fix_source=post_fix_source[:16000],
    )

    try:
        llm = LLMClient(cfg).for_task("analysis")
        analysis = llm.chat(
            prompt,
            system="You are an expert kernel vulnerability researcher.",
            max_tokens=4096,
        )
        patch.vulnerability_analysis = analysis
        return analysis
    except Exception as exc:
        console.print(f"  [yellow]Deep fix analysis failed: {exc}[/]")
        return ""


# ── Kernel source fetching ────────────────────────────────────────────


def _fetch_kernel_source(
    file_path: str,
    *,
    function_name: str = "",
    version: str = "master",
) -> Optional[SourceCodeContext]:
    """
    Fetch kernel source code from git.kernel.org or GitHub.

    Tries to retrieve the specific function if *function_name* is given,
    otherwise returns the whole file (truncated).
    """
    # Try GitHub raw content first (more reliable for automated fetching)
    github_url = f"https://raw.githubusercontent.com/torvalds/linux/{version}/{file_path}"
    try:
        source = _fetch_url(github_url, timeout=20)

        if function_name:
            # Extract function body
            func_source = _extract_function(source, function_name)
            if func_source:
                return SourceCodeContext(
                    file_path=file_path,
                    function_name=function_name,
                    source_code=func_source,
                    source_url=github_url,
                    version=version,
                )

        # Return file (truncated if large)
        return SourceCodeContext(
            file_path=file_path,
            source_code=source[:20000],
            source_url=github_url,
            version=version,
        )
    except Exception:
        pass

    return None


def _extract_function(source: str, func_name: str) -> str:
    """Extract a C function body from source code by name."""
    # Match function definition — handle various styles
    pattern = re.compile(
        rf'^[^\n]*\b{re.escape(func_name)}\s*\([^)]*\)\s*\{{',
        re.MULTILINE,
    )
    m = pattern.search(source)
    if not m:
        return ""

    start = m.start()
    # Find matching closing brace
    depth = 0
    i = m.end() - 1  # Start at the opening brace
    while i < len(source):
        if source[i] == '{':
            depth += 1
        elif source[i] == '}':
            depth -= 1
            if depth == 0:
                return source[start:i + 1]
        i += 1

    # If we didn't find the closing brace, return what we have
    return source[start:min(start + 5000, len(source))]


# ── LLM synthesis ────────────────────────────────────────────────────


_INVESTIGATION_SYNTHESIS_PROMPT = """\
You are a kernel security researcher. Synthesise all gathered intelligence
about {cve_id} into a structured analysis.

=== NVD Description ===
{nvd_description}

=== Existing Exploits / PoCs ===
{exploits_text}

=== Fix Commits / Patches ===
{patches_text}

=== Blog Posts / Write-ups ===
{blogs_text}

=== Source Code Context ===
{source_text}

Based on ALL of the above, produce a comprehensive JSON analysis.
Fill in every field you can infer from the data above.  Use null for fields
you truly cannot determine.

{{
    "vulnerability_type": "<uaf|oob_read|oob_write|double_free|race_condition|type_confusion|integer_overflow|null_deref|logic_bug|unknown>",
    "affected_subsystem": "<kernel subsystem, e.g. 'Android Binder IPC'>",
    "affected_file": "<primary file path, e.g. 'drivers/android/binder.c'>",
    "vulnerable_function": "<function containing the bug>",
    "affected_structs": ["<struct names used in the bug>"],
    "affected_functions": ["<all function names involved in the vulnerable path>"],
    "syscalls": ["<related syscalls, e.g. 'ioctl', 'open'>"],
    "slab_caches": ["<applicable slab caches, e.g. 'kmalloc-128'>"],
    "root_cause_description": "<detailed root cause — include WHY the bug occurs, the exact code path, and what memory safety violation happens>",
    "trigger_conditions": ["<precise conditions/steps to trigger the bug>"],
    "exploitation_details": {{
        "device_or_interface": "<device or interface used, e.g. '/dev/binder'>",
        "trigger_method": "<how to trigger the vulnerability, be specific with ioctls/syscalls>",
        "uaf_object_type": "<freed object type, struct name, slab cache, and size>",
        "reclaim_object_type": "<object used to reclaim freed memory and its slab>",
        "reclaim_strategy": "<how to reclaim the freed memory — cross-cache, same-slab, etc.>",
        "leak_method": "<how to leak kernel addresses — which side-channel or info leak>",
        "rw_primitive_method": "<how to get arbitrary read/write — which kernel object/field>",
        "heap_spray_details": "<what objects to spray, how many, which syscalls>",
        "kernel_structs_exploited": ["<struct names used for exploitation>"],
        "key_constants": ["<important constants like buffer sizes, offsets, alignment requirements>"],
        "process_architecture": "<single process, multi-process, client-server, etc.>",
        "service_discovery": "<how services are discovered if applicable>",
        "privilege_escalation_path": "<exact path from kernel R/W to root — e.g. overwrite task_struct->cred>",
        "binder_specific": {{
            "binder_device": "<e.g. /dev/binder, /dev/hwbinder>",
            "uses_context_manager": <true or false>,
            "transaction_types": "<BC_TRANSACTION, BC_REPLY, etc.>",
            "vulnerability_in_function": "<exact function name>"
        }},
        "android_specific": {{
            "selinux_domain": "<target SELinux domain if applicable>",
            "target_service": "<target Android service if applicable>",
            "required_permissions": "<permissions needed>"
        }},
        "code_snippets": ["<key code patterns extracted from blogs/PoCs that show HOW to trigger or exploit — include actual C code when available>"]
    }},
    "exploitability_score": <0-100>,
    "key_insights": ["<most important technical insights from blogs and PoCs that would help someone write an exploit>"],
    "summary": "<2-3 sentence summary of the vulnerability and how it can be exploited>"
}}
"""


def _synthesise_investigation(
    report: InvestigationReport,
    cfg: Config,
) -> RootCauseAnalysis:
    """Use LLM to synthesise all gathered data into a RootCauseAnalysis."""
    llm = LLMClient(cfg).for_task("analysis")

    # Format exploits — include code snippets when available
    exploit_parts: List[str] = []
    for e in report.exploit_references:
        part = f"  - [{e.source}] {e.title}: {e.url}\n    {e.description}"
        if e.code_snippet:
            # Include up to 4000 chars of exploit code for context
            part += f"\n    --- Exploit code excerpt ---\n    {e.code_snippet[:4000]}"
        exploit_parts.append(part)
    exploits_text = "\n".join(exploit_parts) or "  (none found)"

    # Format patches
    patch_parts: List[str] = []
    for p in report.patch_info:
        part = (
            f"  - {p.commit_hash[:12]} ({p.patch_source}): {p.commit_message[:500]}\n"
            f"    Files: {', '.join(p.files_changed[:10])}\n"
            f"    {p.diff_excerpt[:2000] if p.diff_excerpt else ''}"
        )
        if p.vulnerability_analysis:
            part += f"\n    Vulnerability analysis: {p.vulnerability_analysis[:3000]}"
        patch_parts.append(part)
    patches_text = "\n".join(patch_parts) or "  (none found)"

    # Format blogs — include text and code blocks for full context
    blog_parts: List[str] = []
    for b in report.blog_analyses:
        part = f"  - {b.title}: {b.url}\n    {b.text_excerpt[:4000]}"
        if b.code_blocks:
            code_text = "\n\n".join(cb[:3000] for cb in b.code_blocks[:8])
            part += f"\n    --- Code blocks ({len(b.code_blocks)} total) ---\n    {code_text[:8000]}"
        blog_parts.append(part)
    blogs_text = "\n".join(blog_parts) or "  (none found)"

    # Format source
    source_text = "\n".join(
        f"  --- {s.file_path}:{s.function_name} ---\n"
        f"  {s.source_code[:5000]}"
        for s in report.source_contexts
    ) or "  (none fetched)"

    prompt = _INVESTIGATION_SYNTHESIS_PROMPT.format(
        cve_id=report.cve_id,
        nvd_description=report.nvd_description,
        exploits_text=exploits_text,
        patches_text=patches_text,
        blogs_text=blogs_text,
        source_text=source_text,
    )

    result = llm.ask_json(prompt, system="You are a kernel security analyst.")

    exploitation_details = result.get("exploitation_details", {})

    # Build source_snippets from investigation source_contexts
    src_snippets: Dict[str, str] = {}
    for sc in report.source_contexts:
        key = f"{sc.file_path}:{sc.function_name}" if sc.function_name else sc.file_path
        src_snippets[key] = sc.source_code[:4000]

    rca = RootCauseAnalysis(
        summary=result.get("summary", ""),
        vulnerable_function=result.get("vulnerable_function", ""),
        vulnerable_file=result.get("affected_file", ""),
        vulnerability_type=VulnType.from_str(result.get("vulnerability_type", "unknown")),
        root_cause_description=result.get("root_cause_description", ""),
        trigger_conditions=result.get("trigger_conditions", []),
        affected_subsystem=result.get("affected_subsystem", ""),
        affected_structs=result.get("affected_structs", []),
        kernel_functions=result.get("affected_functions", []),
        syscalls=result.get("syscalls", []),
        slab_caches=result.get("slab_caches", []),
        exploitability_score=result.get("exploitability_score", 0),
        exploitation_details=exploitation_details,
        source_snippets=src_snippets,
        key_insights=result.get("key_insights", []),
    )
    return rca


# ── Main entry-point ──────────────────────────────────────────────────


def investigate_cve(
    cve_id: str,
    *,
    cfg: Optional[Config] = None,
    scrape_blogs: bool = True,
    fetch_source: bool = True,
    max_blogs: int = 5,
    blog_urls: Optional[List[str]] = None,
) -> InvestigationReport:
    """
    Perform a comprehensive automated investigation of a CVE.

    This is the main entry-point. Given a CVE ID, it:
    1. Fetches NVD + MITRE data
    2. Searches GitHub + Exploit-DB for existing exploits
    3. Discovers and scrapes blog posts / write-ups
    4. Locates fix commits and extracts patch diffs
    5. Fetches affected kernel source code
    6. Uses LLM to synthesise everything into a structured analysis

    Parameters
    ----------
    cve_id : str
        CVE identifier (e.g. "CVE-2023-20938").
    cfg : Config, optional
        Configuration (loaded from .env if not provided).
    scrape_blogs : bool
        Whether to scrape discovered blog URLs (default True).
    fetch_source : bool
        Whether to fetch kernel source code (default True).
    max_blogs : int
        Maximum number of blogs to scrape (default 5).
    blog_urls : list of str, optional
        User-provided blog / write-up URLs to scrape in addition to
        automatically discovered ones.

    Returns
    -------
    InvestigationReport
        Comprehensive report with all gathered intelligence.
    """
    cfg = cfg or load_config()
    report = InvestigationReport(cve_id=cve_id)

    console.print(f"[bold]═══ Investigating {cve_id} ═══[/]")

    # ── Step 1: NVD / MITRE ───────────────────────────────────────────
    console.print("[dim]  → Fetching NVD data…[/]")
    nvd = _fetch_nvd(cve_id)
    nvd_info = _extract_nvd_info(nvd) if nvd else {}

    if nvd_info:
        report.nvd_description = nvd_info.get("description", "")
        report.cvss_score = nvd_info.get("cvss_score", 0.0)
        report.severity = nvd_info.get("severity", "unknown")
    else:
        console.print("  [yellow]NVD lookup failed, trying MITRE…[/]")
        mitre = _fetch_mitre(cve_id)
        if mitre:
            containers = mitre.get("containers", {}).get("cna", {})
            descriptions = containers.get("descriptions", [])
            if descriptions:
                report.nvd_description = descriptions[0].get("value", "")
            report.raw_data["mitre"] = mitre
        else:
            report.errors.append("Failed to fetch CVE data from NVD and MITRE")

    nvd_refs = nvd_info.get("references", [])
    console.print(f"  [dim]  Found {len(nvd_refs)} NVD references[/]")

    # ── Step 2: Search for existing exploits ──────────────────────────
    console.print("[dim]  → Searching for existing exploits…[/]")
    gh_exploits = _search_github_exploits(cve_id, cfg=cfg)
    report.exploit_references.extend(gh_exploits)
    console.print(f"  [dim]  GitHub: {len(gh_exploits)} results[/]")

    edb_exploits = _search_exploit_db(cve_id)
    report.exploit_references.extend(edb_exploits)
    console.print(f"  [dim]  Exploit-DB: {len(edb_exploits)} results[/]")

    # ── Step 3: Discover and scrape blog posts ────────────────────────
    console.print("[dim]  → Discovering blog posts & write-ups…[/]")
    discovered_blog_urls = _discover_blog_posts(cve_id, nvd_refs)

    # Merge user-provided blog URLs (prepend so they get priority)
    if blog_urls:
        for u in reversed(blog_urls):
            if u not in discovered_blog_urls:
                discovered_blog_urls.insert(0, u)
        console.print(f"  [dim]  Added {len(blog_urls)} user-provided blog URL(s)[/]")

    console.print(f"  [dim]  Found {len(discovered_blog_urls)} blog URLs[/]")

    if scrape_blogs:
        scraped_urls: set = set()
        for url in discovered_blog_urls[:max_blogs]:
            # Deduplicate by normalised URL (strip trailing slash, fragments)
            norm_url = url.rstrip("/").split("#")[0].split("?")[0]
            if norm_url in scraped_urls:
                continue
            scraped_urls.add(norm_url)
            console.print(f"  [dim]  Scraping: {url[:80]}…[/]")
            analysis = _scrape_blog_post(url, cve_id=cve_id, cfg=cfg)
            if analysis:
                report.blog_analyses.append(analysis)

    # ── Step 3b: Recursive extraction from blog content ───────────────
    # Extract commit/patch URLs, file paths, and related CVEs from blogs
    blog_patch_urls: List[str] = []
    blog_file_paths: List[str] = []
    blog_commits: List[str] = []
    for blog in report.blog_analyses:
        combined_text = blog.text_excerpt + "\n".join(blog.code_blocks)
        blog_patch_urls.extend(_extract_patch_urls_from_text(combined_text))
        blog_file_paths.extend(_extract_kernel_paths_from_text(combined_text))
        blog_commits.extend(_extract_commit_hashes_from_text(combined_text))
        related = _extract_cves_from_text(combined_text)
        for cid in related:
            if cid.upper() != cve_id.upper() and cid not in report.related_cves:
                report.related_cves.append(cid)

    blog_patch_urls = list(dict.fromkeys(blog_patch_urls))
    blog_file_paths = list(dict.fromkeys(blog_file_paths))
    blog_commits = list(dict.fromkeys(blog_commits))

    if blog_patch_urls or blog_commits:
        console.print(
            f"  [dim]  Recursive: {len(blog_patch_urls)} patch URLs, "
            f"{len(blog_commits)} commit hashes from blogs[/]"
        )

    # ── Step 4: Discover patches / fix commits ────────────────────────
    console.print("[dim]  → Discovering patches & fix commits…[/]")
    # Include blog-discovered patch URLs alongside NVD refs
    all_refs = list(dict.fromkeys(nvd_refs + blog_patch_urls))
    patches = _discover_patches(cve_id, all_refs, cfg=cfg)

    # Also create PatchInfo for commit hashes found in blogs
    existing_hashes = {p.commit_hash for p in patches if p.commit_hash}
    for ch in blog_commits:
        if ch not in existing_hashes:
            gh_patch = _fetch_github_commit(ch, cfg=cfg)
            if gh_patch:
                patches.append(gh_patch)
                existing_hashes.add(ch)
                console.print(f"  [dim]  Blog-discovered commit: {ch[:12]}[/]")

    report.patch_info = patches
    console.print(f"  [dim]  Found {len(patches)} patches[/]")

    # Collect affected files and fix commits from patches
    for patch in patches:
        if patch.commit_hash:
            report.fix_commits.append(patch.commit_hash)
        report.affected_files.extend(patch.files_changed)

    # Also include file paths discovered from blog content
    report.affected_files.extend(blog_file_paths)

    # Infer well-known kernel paths from NVD description and blog content
    # Many Android CVEs mention just "binder.c" without the full path
    _KNOWN_FILE_MAP = {
        "binder.c": "drivers/android/binder.c",
        "binder_alloc.c": "drivers/android/binder_alloc.c",
        "binder_internal.h": "drivers/android/binder_internal.h",
        "binder_alloc.h": "drivers/android/binder_alloc.h",
        "io_uring.c": "io_uring/io_uring.c",
        "pipe.c": "fs/pipe.c",
        "epoll.c": "fs/eventpoll.c",
        "eventpoll.c": "fs/eventpoll.c",
    }
    all_text = report.nvd_description
    for b in report.blog_analyses:
        all_text += " " + b.text_excerpt + " ".join(b.code_blocks)
    for short_name, full_path in _KNOWN_FILE_MAP.items():
        if short_name in all_text and full_path not in report.affected_files:
            report.affected_files.append(full_path)

    report.affected_files = list(dict.fromkeys(report.affected_files))

    # ── Step 4b: Deep fix-commit analysis ─────────────────────────────
    # For each patch with a diff, perform deep LLM analysis comparing
    # pre-fix and post-fix code to extract vulnerability patterns.
    if cfg and report.patch_info:
        console.print("[dim]  → Deep-analysing fix commits…[/]")
        for patch in report.patch_info[:3]:  # Analyse top 3 patches
            if patch.diff_excerpt and patch.commit_hash:
                console.print(f"  [dim]  Analysing: {patch.commit_hash[:12]}[/]")
                _deep_analyze_fix_commit(patch, cve_id, cfg)
                if patch.vulnerability_analysis:
                    console.print(f"  [dim]  ✓ Deep analysis complete ({len(patch.vulnerability_analysis)} chars)[/]")

    # ── Step 5: Fetch kernel source code ──────────────────────────────
    if fetch_source and report.affected_files:
        console.print("[dim]  → Fetching kernel source code…[/]")

        # Determine which version to fetch — prefer pre-fix version
        # For now, use 'master' which has the fix; we also try the
        # parent commit if we have a fix commit.
        for fpath in report.affected_files[:5]:
            if not fpath.endswith((".c", ".h")):
                continue
            console.print(f"  [dim]  Fetching: {fpath}[/]")

            # Try to fetch from the parent of the fix commit (pre-fix)
            version = "master"
            if report.fix_commits:
                version = f"{report.fix_commits[0]}^"

            ctx = _fetch_kernel_source(fpath, version=version)
            if ctx:
                report.source_contexts.append(ctx)
            else:
                # Fallback to master
                ctx = _fetch_kernel_source(fpath, version="master")
                if ctx:
                    report.source_contexts.append(ctx)

    # ── Step 6: LLM synthesis ─────────────────────────────────────────
    console.print("[dim]  → Synthesising analysis with LLM…[/]")
    try:
        rca = _synthesise_investigation(report, cfg)
        report.root_cause = rca
        report.vulnerability_type = rca.vulnerability_type.value
        report.affected_subsystem = rca.affected_subsystem
        report.affected_functions = rca.kernel_functions
        report.affected_structs = rca.affected_structs
    except Exception as exc:
        report.errors.append(f"LLM synthesis failed: {exc}")

    # ── Step 7: Recursive source fetch for identified functions ───────
    # After LLM synthesis we may know function names that weren't in the
    # original patch data.  Fetch those specific function bodies.
    if fetch_source and report.affected_functions:
        existing_funcs = {sc.function_name for sc in report.source_contexts if sc.function_name}
        new_funcs = [
            fn for fn in report.affected_functions
            if fn and fn not in existing_funcs
        ]
        if new_funcs:
            console.print(f"[dim]  → Recursive: fetching {len(new_funcs)} functions identified by LLM…[/]")
            version = "master"
            if report.fix_commits:
                version = f"{report.fix_commits[0]}^"

            # Build a map of file → known functions so we know where to look
            # Start with affected_files, then fall back to searching all source_contexts
            func_files: Dict[str, str] = {}  # fn_name → file_path
            for sc in report.source_contexts:
                if sc.source_code and sc.file_path:
                    for fn in new_funcs:
                        if fn in sc.source_code:
                            func_files[fn] = sc.file_path

            for fn in new_funcs[:10]:
                fpath = func_files.get(fn)
                if fpath:
                    console.print(f"  [dim]  Extracting {fn}() from {fpath}[/]")
                    ctx = _fetch_kernel_source(
                        fpath, function_name=fn, version=version,
                    )
                    if not ctx:
                        ctx = _fetch_kernel_source(
                            fpath, function_name=fn, version="master",
                        )
                    if ctx and ctx.function_name:
                        report.source_contexts.append(ctx)
                else:
                    # Try each affected file
                    for af in report.affected_files[:5]:
                        if not af.endswith((".c", ".h")):
                            continue
                        ctx = _fetch_kernel_source(
                            af, function_name=fn, version=version,
                        )
                        if not ctx:
                            ctx = _fetch_kernel_source(
                                af, function_name=fn, version="master",
                            )
                        if ctx and ctx.function_name:
                            console.print(f"  [dim]  Found {fn}() in {af}[/]")
                            report.source_contexts.append(ctx)
                            break

    # ── Step 8: Fetch code from GitHub exploit repos ──────────────────
    # Grab both the README AND actual exploit source files (.c, .py, .sh)
    # from discovered GitHub exploit repos for later use in generation.
    console.print("[dim]  → Fetching exploit code from GitHub repos…[/]")
    for ref in report.exploit_references:
        if ref.source != "github" or not ref.url:
            continue
        try:
            parts = ref.url.rstrip("/").split("/")
            if len(parts) < 5 or "github.com" not in ref.url:
                continue
            owner_repo = "/".join(parts[-2:])

            # 1. List repo contents (root tree)
            tree_url = f"https://api.github.com/repos/{owner_repo}/contents/"
            tree_data = _fetch_github_json(tree_url, cfg)
            if not isinstance(tree_data, list):
                # Fallback to just README
                readme_url = f"https://api.github.com/repos/{owner_repo}/readme"
                data = _fetch_github_json(readme_url, cfg)
                if data.get("content"):
                    import base64
                    content = base64.b64decode(data["content"]).decode(
                        "utf-8", errors="replace"
                    )
                    ref.code_snippet = content[:5000]
                continue

            # 2. Find exploit-relevant source files
            exploit_extensions = (".c", ".h", ".py", ".sh", ".cpp", ".cc")
            source_files: List[Dict[str, Any]] = []
            readme_file: Optional[Dict[str, Any]] = None

            for item in tree_data:
                name = item.get("name", "").lower()
                if name in ("readme.md", "readme.txt", "readme"):
                    readme_file = item
                elif any(name.endswith(ext) for ext in exploit_extensions):
                    source_files.append(item)

            # 3. Fetch README
            collected_code: List[str] = []
            if readme_file and readme_file.get("download_url"):
                try:
                    readme_text = _fetch_url(readme_file["download_url"], timeout=15)
                    collected_code.append(
                        f"=== README ({readme_file.get('name', 'README')}) ===\n"
                        f"{readme_text[:3000]}"
                    )
                except Exception:
                    pass

            # 4. Fetch actual exploit source files (up to 3, prioritise .c)
            source_files.sort(
                key=lambda f: (
                    0 if f.get("name", "").lower().endswith(".c") else
                    1 if f.get("name", "").lower().endswith(".h") else 2
                )
            )
            for src_file in source_files[:3]:
                dl_url = src_file.get("download_url")
                if not dl_url:
                    continue
                try:
                    src_text = _fetch_url(dl_url, timeout=15)
                    fname = src_file.get("name", "unknown")
                    collected_code.append(
                        f"=== SOURCE: {fname} ({src_file.get('size', '?')} bytes) ===\n"
                        f"{src_text[:8000]}"
                    )
                    console.print(f"  [dim]  Fetched exploit source: {owner_repo}/{fname}[/]")
                except Exception:
                    pass

            if collected_code:
                ref.code_snippet = "\n\n".join(collected_code)[:15000]
                ref.language = source_files[0].get("name", "").rsplit(".", 1)[-1] if source_files else ""

        except Exception:
            pass

    # ── Done ──────────────────────────────────────────────────────────
    if report.related_cves:
        console.print(f"  [dim]  Related CVEs: {', '.join(report.related_cves[:5])}[/]")
    console.print(f"\n{report.summary()}")
    return report
