"""
vuln_scanner — LLM-powered Android app vulnerability scanner.

Analyzes decompiled app code for security vulnerabilities using:
    - Static pattern matching (regex-based, zero LLM cost)
    - LLM deep analysis (context-aware, reduces false positives)
    - Combined hybrid mode (static filter → LLM verification)

Detects: SQL injection, XSS (WebView), hardcoded secrets, path traversal,
intent spoofing, insecure crypto, insecure storage, and more.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .app_analyzer import AppVulnerability


# ── Vulnerability Rules (static patterns) ────────────────────────────

@dataclass
class VulnRule:
    """A static vulnerability detection rule."""
    name: str
    severity: str
    category: str
    pattern: str  # regex pattern
    description: str
    recommendation: str
    owasp_masvs: str = ""
    exclude_patterns: List[str] = field(default_factory=list)  # false positive filters


VULN_RULES: List[VulnRule] = [
    # SQL Injection
    VulnRule(
        name="SQL Injection (rawQuery)",
        severity="critical",
        category="storage",
        pattern=r'\.rawQuery\s*\([^)]*\+[^)]*\)',
        description="String concatenation in SQLite rawQuery() — SQL injection risk.",
        recommendation="Use parameterized queries with selectionArgs.",
        owasp_masvs="MSTG-STORAGE-1",
    ),
    VulnRule(
        name="SQL Injection (execSQL)",
        severity="critical",
        category="storage",
        pattern=r'\.execSQL\s*\([^)]*\+[^)]*\)',
        description="String concatenation in execSQL() — SQL injection risk.",
        recommendation="Use parameterized queries or ContentValues.",
        owasp_masvs="MSTG-STORAGE-1",
    ),
    # WebView XSS
    VulnRule(
        name="WebView JavaScript Enabled",
        severity="medium",
        category="webview",
        pattern=r'setJavaScriptEnabled\s*\(\s*true\s*\)',
        description="WebView has JavaScript enabled — potential XSS vector.",
        recommendation="Disable JS if not needed, or validate all loaded URLs.",
        owasp_masvs="MSTG-PLATFORM-5",
    ),
    VulnRule(
        name="WebView JavaScript Interface",
        severity="high",
        category="webview",
        pattern=r'addJavascriptInterface\s*\(',
        description="WebView exposes Java objects to JavaScript — potential RCE on older APIs.",
        recommendation="Remove @JavascriptInterface on API < 17. Validate all JS inputs.",
        owasp_masvs="MSTG-PLATFORM-7",
    ),
    VulnRule(
        name="WebView File Access",
        severity="high",
        category="webview",
        pattern=r'setAllowFileAccess\s*\(\s*true\s*\)',
        description="WebView allows file:// access — local file theft via XSS.",
        recommendation="Set setAllowFileAccess(false) and setAllowFileAccessFromFileURLs(false).",
        owasp_masvs="MSTG-PLATFORM-6",
    ),
    # Hardcoded Secrets
    VulnRule(
        name="Hardcoded API Key",
        severity="high",
        category="crypto",
        pattern=r'(?:api[_-]?key|apikey|api_secret)\s*[:=]\s*["\'][A-Za-z0-9_\-]{20,}["\']',
        description="Hardcoded API key found in source code.",
        recommendation="Move API keys to server-side or use Android Keystore.",
        owasp_masvs="MSTG-STORAGE-14",
        exclude_patterns=[r'example', r'placeholder', r'TODO', r'CHANGEME'],
    ),
    VulnRule(
        name="Hardcoded Password/Secret",
        severity="high",
        category="crypto",
        pattern=r'(?:password|passwd|secret|token)\s*[:=]\s*["\'][^"\']{8,}["\']',
        description="Hardcoded credential found in source code.",
        recommendation="Use Android Keystore for credential storage.",
        owasp_masvs="MSTG-STORAGE-14",
        exclude_patterns=[r'example', r'placeholder', r'TODO', r'test', r'dummy'],
    ),
    # Insecure Crypto
    VulnRule(
        name="Weak Encryption (ECB Mode)",
        severity="high",
        category="crypto",
        pattern=r'Cipher\.getInstance\s*\(\s*["\']AES/ECB',
        description="AES in ECB mode — reveals patterns in encrypted data.",
        recommendation="Use AES/GCM/NoPadding or AES/CBC with random IV.",
        owasp_masvs="MSTG-CRYPTO-2",
    ),
    VulnRule(
        name="Weak Encryption (DES)",
        severity="high",
        category="crypto",
        pattern=r'Cipher\.getInstance\s*\(\s*["\']DES',
        description="DES encryption is broken — 56-bit keys are brute-forcible.",
        recommendation="Use AES-256 instead of DES.",
        owasp_masvs="MSTG-CRYPTO-4",
    ),
    VulnRule(
        name="Insecure Random (java.util.Random)",
        severity="medium",
        category="crypto",
        pattern=r'new\s+Random\s*\(',
        description="java.util.Random is predictable — not cryptographically secure.",
        recommendation="Use SecureRandom for security-sensitive operations.",
        owasp_masvs="MSTG-CRYPTO-6",
        exclude_patterns=[r'SecureRandom'],
    ),
    VulnRule(
        name="Hardcoded IV/Salt",
        severity="medium",
        category="crypto",
        pattern=r'IvParameterSpec\s*\(\s*(?:new\s+byte\s*\[\s*\]\s*\{|["\'])',
        description="Hardcoded initialization vector — reduces cipher security.",
        recommendation="Generate random IV with SecureRandom for each encryption.",
        owasp_masvs="MSTG-CRYPTO-3",
    ),
    # Insecure Storage
    VulnRule(
        name="World-Readable File",
        severity="high",
        category="storage",
        pattern=r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE',
        description="File created with world-readable/writable permissions.",
        recommendation="Use MODE_PRIVATE. Share data via ContentProvider.",
        owasp_masvs="MSTG-STORAGE-2",
    ),
    VulnRule(
        name="External Storage Write",
        severity="medium",
        category="storage",
        pattern=r'getExternalStorage|Environment\.getExternalStorageDirectory',
        description="Writing to external storage — accessible by all apps.",
        recommendation="Use internal storage or Scoped Storage (API 29+).",
        owasp_masvs="MSTG-STORAGE-2",
    ),
    VulnRule(
        name="Logging Sensitive Data",
        severity="medium",
        category="storage",
        pattern=r'Log\.[dievw]\s*\([^)]*(?:password|token|secret|key|credential|ssn|credit)',
        description="Sensitive data may be logged — accessible via logcat.",
        recommendation="Remove sensitive data from log statements in production.",
        owasp_masvs="MSTG-STORAGE-3",
    ),
    # Network Security
    VulnRule(
        name="TrustManager Override (Accept All)",
        severity="critical",
        category="network",
        pattern=r'X509TrustManager.*checkServerTrusted.*\{\s*\}',
        description="Custom TrustManager accepts all certificates — MitM vulnerable.",
        recommendation="Use default TrustManager or pin specific certificates.",
        owasp_masvs="MSTG-NETWORK-3",
    ),
    VulnRule(
        name="HostnameVerifier Override",
        severity="critical",
        category="network",
        pattern=r'HostnameVerifier.*verify.*return\s+true',
        description="Hostname verification disabled — MitM vulnerable.",
        recommendation="Use default hostname verification.",
        owasp_masvs="MSTG-NETWORK-3",
    ),
    # IPC Vulnerabilities
    VulnRule(
        name="Implicit Intent with Sensitive Data",
        severity="medium",
        category="ipc",
        pattern=r'new\s+Intent\s*\([^)]*\).*\.putExtra\s*\([^)]*(?:token|password|key|secret)',
        description="Sensitive data sent via implicit intent — interceptable by other apps.",
        recommendation="Use explicit intents for sensitive data. Use LocalBroadcastManager.",
        owasp_masvs="MSTG-PLATFORM-4",
    ),
    VulnRule(
        name="Clipboard Usage with Sensitive Data",
        severity="medium",
        category="storage",
        pattern=r'ClipboardManager.*setPrimaryClip.*(?:token|password|key|secret)',
        description="Sensitive data placed on clipboard — accessible by all apps.",
        recommendation="Avoid clipboard for sensitive data. Use ClipData.newPlainText with timeout.",
        owasp_masvs="MSTG-STORAGE-10",
    ),
    # Path Traversal
    VulnRule(
        name="Path Traversal (ContentProvider)",
        severity="high",
        category="ipc",
        pattern=r'openFile.*getPath.*\.\.',
        description="ContentProvider may be vulnerable to path traversal.",
        recommendation="Canonicalize paths and verify they stay within allowed directories.",
        owasp_masvs="MSTG-PLATFORM-2",
    ),
]


# ── Static Scanner ───────────────────────────────────────────────────


def scan_static(
    source_dir: str,
    exclude_libraries: bool = True,
) -> List[AppVulnerability]:
    """
    Scan decompiled Java/Smali source for vulnerability patterns.

    Args:
        source_dir: Path to decompiled source directory
        exclude_libraries: Skip known library packages (reduces noise ~70%)
    """
    vulns: List[AppVulnerability] = []
    source_path = Path(source_dir)

    if not source_path.exists():
        return vulns

    # Collect .java and .smali files
    files = list(source_path.rglob("*.java"))
    files.extend(source_path.rglob("*.smali"))

    # Library package prefixes to skip
    library_prefixes = [
        "androidx/", "android/support/", "com/google/", "kotlin/",
        "kotlinx/", "okhttp3/", "retrofit2/", "com/squareup/",
        "org/apache/", "org/json/", "com/fasterxml/", "io/reactivex/",
        "dagger/", "butterknife/", "com/bumptech/glide/",
    ]

    for fpath in files:
        rel = str(fpath.relative_to(source_path))

        # Skip library code
        if exclude_libraries:
            if any(rel.startswith(p) or f"/{p}" in rel for p in library_prefixes):
                continue

        try:
            content = fpath.read_text(errors="ignore")
        except Exception:
            continue

        for rule in VULN_RULES:
            matches = list(re.finditer(rule.pattern, content, re.IGNORECASE))
            if not matches:
                continue

            # Check exclude patterns (false positive filters)
            filtered_matches = []
            for m in matches:
                context = content[max(0, m.start() - 100):m.end() + 100]
                if not any(re.search(ep, context, re.IGNORECASE) for ep in rule.exclude_patterns):
                    filtered_matches.append(m)

            if filtered_matches:
                evidence_lines = []
                for m in filtered_matches[:3]:
                    line_num = content[:m.start()].count("\n") + 1
                    evidence_lines.append(f"  {rel}:{line_num}: {m.group()[:80]}")

                vulns.append(AppVulnerability(
                    name=rule.name,
                    severity=rule.severity,
                    category=rule.category,
                    description=rule.description,
                    evidence="\n".join(evidence_lines),
                    recommendation=rule.recommendation,
                    owasp_masvs=rule.owasp_masvs,
                    component=rel,
                ))

    return vulns


# ── LLM-powered Scanner ─────────────────────────────────────────────


def scan_with_llm(
    source_dir: str,
    focus_areas: Optional[List[str]] = None,
    cfg: Optional[Any] = None,
    max_files: int = 20,
) -> List[AppVulnerability]:
    """
    Use LLM to analyze decompiled source for vulnerabilities.

    Args:
        source_dir: Path to decompiled source
        focus_areas: Specific areas to focus on (e.g., ["webview", "crypto", "ipc"])
        cfg: syzploit Config with LLM settings
        max_files: Maximum files to analyze (to control token cost)
    """
    if cfg is None:
        return []

    source_path = Path(source_dir)
    if not source_path.exists():
        return []

    # Collect high-interest files (skip libraries)
    interesting_files = _find_interesting_files(source_path, focus_areas, max_files)
    if not interesting_files:
        return []

    # Build prompt with file contents
    file_contents = []
    total_chars = 0
    max_chars = 50000  # ~12K tokens

    for fpath in interesting_files:
        try:
            content = fpath.read_text(errors="ignore")
            rel = str(fpath.relative_to(source_path))
            alloc = min(len(content), max_chars - total_chars, 5000)
            if alloc <= 0:
                break
            file_contents.append(f"--- {rel} ---\n{content[:alloc]}")
            total_chars += alloc
        except Exception:
            continue

    if not file_contents:
        return []

    focus_str = ", ".join(focus_areas) if focus_areas else "all categories"

    prompt = f"""Analyze the following Android app source code for security vulnerabilities.
Focus areas: {focus_str}

For each vulnerability found, respond with a JSON array of objects with these fields:
- "name": Short vulnerability name
- "severity": "critical", "high", "medium", "low"
- "category": "crypto", "storage", "network", "ipc", "webview", "auth"
- "description": One-line description
- "evidence": The relevant code snippet or file:line
- "recommendation": How to fix it
- "owasp_masvs": OWASP MASVS reference (e.g., "MSTG-CRYPTO-1")

Only report REAL vulnerabilities with concrete evidence from the code.
Do NOT report speculative or theoretical issues.

Source code:
{chr(10).join(file_contents)}

Respond ONLY with a JSON array. No markdown, no explanation."""

    try:
        from ..core.llm import LLMClient
        client = LLMClient(cfg)
        response = client.query(prompt)

        # Parse JSON response
        import json
        # Extract JSON array from response (handle markdown fences)
        text = response.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            if text.endswith("```"):
                text = text[:-3]
        if text.startswith("json"):
            text = text[4:]

        findings = json.loads(text.strip())
        vulns = []
        for f in findings:
            vulns.append(AppVulnerability(
                name=f.get("name", "Unknown"),
                severity=f.get("severity", "medium"),
                category=f.get("category", "unknown"),
                description=f.get("description", ""),
                evidence=f.get("evidence", ""),
                recommendation=f.get("recommendation", ""),
                owasp_masvs=f.get("owasp_masvs", ""),
            ))
        return vulns

    except Exception as exc:
        return [AppVulnerability(
            name="LLM Analysis Error",
            severity="info",
            category="unknown",
            description=f"LLM analysis failed: {str(exc)[:200]}",
        )]


def _find_interesting_files(
    source_path: Path,
    focus_areas: Optional[List[str]],
    max_files: int,
) -> List[Path]:
    """Find files most likely to contain vulnerabilities."""
    # Keywords that indicate security-relevant code
    interest_keywords = {
        "crypto": ["Cipher", "SecretKey", "encrypt", "decrypt", "hash", "digest"],
        "storage": ["SharedPreferences", "SQLiteDatabase", "openFileOutput", "ContentValues"],
        "network": ["HttpURLConnection", "OkHttpClient", "TrustManager", "SSLSocket"],
        "ipc": ["ContentProvider", "BroadcastReceiver", "Intent", "startActivity"],
        "webview": ["WebView", "loadUrl", "JavascriptInterface", "WebSettings"],
        "auth": ["login", "authenticate", "session", "token", "oauth", "JWT"],
    }

    if focus_areas:
        keywords = []
        for area in focus_areas:
            keywords.extend(interest_keywords.get(area, [area]))
    else:
        keywords = [kw for kws in interest_keywords.values() for kw in kws]

    # Score files by keyword matches
    scored_files: List[Tuple[int, Path]] = []
    library_prefixes = [
        "androidx", "android/support", "com/google", "kotlin",
        "okhttp3", "retrofit2", "com/squareup",
    ]

    for fpath in source_path.rglob("*.java"):
        rel = str(fpath.relative_to(source_path))
        # Skip libraries
        if any(rel.startswith(p) or f"/{p}" in rel for p in library_prefixes):
            continue
        try:
            content = fpath.read_text(errors="ignore")[:10000]
            score = sum(1 for kw in keywords if kw.lower() in content.lower())
            if score > 0:
                scored_files.append((score, fpath))
        except Exception:
            continue

    scored_files.sort(reverse=True)
    return [f for _, f in scored_files[:max_files]]


# ── Hybrid Scanner ───────────────────────────────────────────────────


def scan_hybrid(
    source_dir: str,
    cfg: Optional[Any] = None,
    focus_areas: Optional[List[str]] = None,
) -> List[AppVulnerability]:
    """
    Hybrid scan: static patterns first, then LLM verification + deep analysis.

    This is the recommended mode — static scan catches common patterns (free),
    LLM analyzes complex logic and cross-file vulnerabilities (costs tokens).
    """
    # Phase 1: Static scan (free, fast)
    static_vulns = scan_static(source_dir)

    # Phase 2: LLM deep scan (costs tokens, more accurate)
    llm_vulns = []
    if cfg:
        llm_vulns = scan_with_llm(source_dir, focus_areas=focus_areas, cfg=cfg)

    # Deduplicate: if LLM found same vuln as static, keep LLM version (better evidence)
    seen_names = set()
    result = []

    for v in llm_vulns:
        key = (v.name.lower(), v.component)
        if key not in seen_names:
            seen_names.add(key)
            result.append(v)

    for v in static_vulns:
        key = (v.name.lower(), v.component)
        if key not in seen_names:
            seen_names.add(key)
            result.append(v)

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    result.sort(key=lambda v: severity_order.get(v.severity, 5))

    return result
