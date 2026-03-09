"""
cve_analyzer.py

Analyze a CVE identifier or blog post URL and produce structured analysis
data compatible with the syzploit pipeline (``static_analysis.json`` format).

Two main entry-points:

1. ``analyze_cve(cve_id, ...)`` — Fetches NVD/MITRE data, searches for
   existing PoCs on GitHub/exploit-db, and uses an LLM to classify the
   vulnerability and generate a syzploit-compatible analysis + initial PoC.

2. ``analyze_blog_post(url, ...)`` — Fetches a blog post, extracts code
   blocks and vulnerability narrative, and uses an LLM to turn it into a
   structured analysis + PoC skeleton.

Both produce:
- A ``static_analysis.json`` that plugs directly into the SyzAnalyze
  adapter → Synthesizer pipeline.
- An optional C PoC (``poc.c``) stub suitable for compilation and testing.
"""

from __future__ import annotations

import json
import os
import re
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..utils.debug import debug_print
from ..utils.env import load_env, get_api_key


def _ca_debug(msg: str, enabled: bool = True):
    debug_print("CVEAnalyzer", msg, enabled)


# ---------------------------------------------------------------------------
# LLM helpers (reuse syzploit's litellm plumbing)
# ---------------------------------------------------------------------------

def _llm_chat(model: str, messages: list, debug: bool = False) -> str:
    """Send a chat completion via litellm and return the assistant text."""
    load_env()
    try:
        from litellm import completion as litellm_completion
        resp = litellm_completion(model=model, messages=messages)
        return resp.choices[0].message.content
    except Exception as e:
        _ca_debug(f"LLM call failed: {e}", debug)
        raise


# ---------------------------------------------------------------------------
# Web fetching helpers
# ---------------------------------------------------------------------------

def _fetch_url(url: str, timeout: int = 30) -> str:
    """Fetch URL content as text."""
    import requests
    resp = requests.get(url, timeout=timeout, headers={
        "User-Agent": "syzploit-cve-analyzer/1.0",
    })
    resp.raise_for_status()
    return resp.text


def _fetch_nvd(cve_id: str, debug: bool = False) -> Optional[Dict[str, Any]]:
    """Fetch CVE data from NVD 2.0 API."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    _ca_debug(f"Fetching NVD: {url}", debug)
    try:
        raw = _fetch_url(url)
        data = json.loads(raw)
        vulns = data.get("vulnerabilities", [])
        if vulns:
            return vulns[0].get("cve", {})
    except Exception as e:
        _ca_debug(f"NVD fetch failed: {e}", debug)
    return None


def _fetch_mitre(cve_id: str, debug: bool = False) -> Optional[Dict[str, Any]]:
    """Fetch CVE data from cvelistV5 on GitHub (MITRE raw JSON)."""
    # CVE-2023-20938 → 2023/20xxx/CVE-2023-20938.json
    parts = cve_id.split("-")
    if len(parts) != 3:
        return None
    year, seq = parts[1], parts[2]
    bucket = seq[:-3] + "xxx" if len(seq) > 3 else "0xxx"
    url = f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{bucket}/{cve_id}.json"
    _ca_debug(f"Fetching MITRE cvelistV5: {url}", debug)
    try:
        raw = _fetch_url(url)
        return json.loads(raw)
    except Exception as e:
        _ca_debug(f"MITRE fetch failed: {e}", debug)
    return None


def _search_github_pocs(cve_id: str, debug: bool = False) -> List[Dict[str, str]]:
    """Search GitHub for PoC repositories matching a CVE ID."""
    import requests
    url = f"https://api.github.com/search/repositories?q={cve_id}+language:c&sort=stars&per_page=5"
    _ca_debug(f"Searching GitHub PoCs: {url}", debug)
    try:
        resp = requests.get(url, timeout=15, headers={
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "syzploit-cve-analyzer/1.0",
        })
        if resp.status_code == 200:
            items = resp.json().get("items", [])
            return [
                {
                    "name": item["full_name"],
                    "url": item["html_url"],
                    "description": item.get("description", ""),
                    "stars": item.get("stargazers_count", 0),
                }
                for item in items
            ]
    except Exception as e:
        _ca_debug(f"GitHub search failed: {e}", debug)
    return []


def _classify_code_block(code: str) -> str:
    """Heuristically classify a code block by language/purpose."""
    c = code.strip()
    if re.search(r'#include\s*<', c) or re.search(r'\b(void|int|struct|static)\s+\w+\s*\(', c):
        if re.search(r'(main|printf|perror|syscall|ioctl|mmap|open|close)\s*\(', c):
            return "c_exploit_code"
        if re.search(r'(struct\s+\w+\s*\{|union\s+\w+\s*\{)', c):
            return "c_kernel_struct"
        return "c_source"
    if re.search(r'(\[\s*<[0-9a-f]+>\]|Call Trace|BUG:|KASAN:)', c):
        return "crash_log"
    if re.search(r'^(diff --git|@@\s+[-+]|[+-]{3}\s+[ab]/)', c, re.MULTILINE):
        return "patch_diff"
    if re.search(r'(gdb|pwndbg|pwntools|from pwn import)', c):
        return "exploit_script"
    if re.search(r'^\$?\s*(echo|cat|grep|adb|gcc|make|cd\s)', c, re.MULTILINE):
        return "shell_command"
    return "other"


def _extract_kernel_identifiers(code: str) -> Dict[str, List[str]]:
    """Extract kernel-relevant identifiers from a code block."""
    ids: Dict[str, List[str]] = {
        "structs": [],
        "functions": [],
        "syscalls": [],
        "ioctls": [],
        "defines": [],
        "slab_caches": [],
    }
    # Struct names
    for m in re.finditer(r'\bstruct\s+([a-z_][a-z0-9_]*)', code):
        name = m.group(1)
        if name not in ids["structs"] and len(name) > 2:
            ids["structs"].append(name)
    # Function calls and definitions
    for m in re.finditer(r'\b([a-z_][a-z0-9_]*)\s*\(', code):
        name = m.group(1)
        if name not in ids["functions"] and len(name) > 2 and name not in (
            "if", "while", "for", "switch", "return", "sizeof", "typeof",
            "printf", "fprintf", "perror", "exit", "main",
        ):
            ids["functions"].append(name)
    # Syscalls via syscall(__NR_xxx) or SYS_xxx
    for m in re.finditer(r'(?:__NR_|SYS_)([a-z_][a-z0-9_]*)', code):
        name = m.group(1)
        if name not in ids["syscalls"]:
            ids["syscalls"].append(name)
    # Direct syscall wrappers
    for m in re.finditer(r'\b(ioctl|mmap|mprotect|sendmsg|recvmsg|msgget|msgsnd|msgrcv|'
                         r'socket|bind|listen|connect|accept|setsockopt|getsockopt|'
                         r'io_uring_setup|io_uring_enter|io_uring_register|'
                         r'binder_ioctl|open|openat|close|read|write|writev|'
                         r'epoll_create|epoll_ctl|pipe|pipe2|dup|dup2|clone|fork|'
                         r'prctl|setns|unshare|mount|umount|pivot_root)\s*\(', code):
        name = m.group(1)
        if name not in ids["syscalls"]:
            ids["syscalls"].append(name)
    # ioctl request codes
    for m in re.finditer(r'\b([A-Z][A-Z0-9_]{3,})\b', code):
        name = m.group(1)
        if ('IOCTL' in name or 'BINDER' in name or name.startswith('BR_') or
                name.startswith('BC_') or '_IOC' in name or 'TIOCSTI' in name):
            if name not in ids["ioctls"]:
                ids["ioctls"].append(name)
    # #define constants
    for m in re.finditer(r'#define\s+([A-Z_][A-Z0-9_]+)', code):
        name = m.group(1)
        if name not in ids["defines"]:
            ids["defines"].append(name)
    # Slab cache names (kmalloc-xxx, filp, etc.)
    for m in re.finditer(r'["\']?(kmalloc-\d+|kmem_cache_\w+|filp|inode_cache|'
                         r'dentry|task_struct|cred_jar|signal_cache|'
                         r'pid|files_cache|sock_inode_cache)["\']?', code):
        name = m.group(1)
        if name not in ids["slab_caches"]:
            ids["slab_caches"].append(name)
    return ids


def _fetch_blog_text(url: str, debug: bool = False) -> str:
    """Fetch a blog post and extract readable text + deeply parsed code blocks."""
    _ca_debug(f"Fetching blog: {url}", debug)
    try:
        from bs4 import BeautifulSoup
        html = _fetch_url(url)
        soup = BeautifulSoup(html, "html.parser")

        # Remove nav, header, footer, sidebar
        for tag in soup.find_all(["nav", "header", "footer", "aside", "script", "style"]):
            tag.decompose()

        # ── Deep code block extraction ──
        code_blocks: List[Dict[str, Any]] = []
        seen_hashes: set = set()
        for code_tag in soup.find_all(["code", "pre"]):
            code_text = code_tag.get_text(strip=True)
            if len(code_text) < 30:
                continue
            # De-duplicate (blogs often nest <code> inside <pre>)
            h = hash(code_text[:200])
            if h in seen_hashes:
                continue
            seen_hashes.add(h)

            # Detect language from class attribute
            lang = ""
            cls = code_tag.get("class", [])
            if isinstance(cls, list):
                for c in cls:
                    if "language-" in c:
                        lang = c.split("language-")[-1]
                    elif "lang-" in c:
                        lang = c.split("lang-")[-1]
                    elif c in ("c", "cpp", "python", "bash", "sh", "diff"):
                        lang = c

            block_type = _classify_code_block(code_text)
            identifiers = _extract_kernel_identifiers(code_text)

            code_blocks.append({
                "text": code_text,
                "lang": lang,
                "type": block_type,
                "identifiers": identifiers,
            })

        # Get main text
        body = soup.find("article") or soup.find("main") or soup.find("body")
        text = body.get_text(separator="\n", strip=True) if body else soup.get_text(separator="\n", strip=True)

        # ── Build enriched output ──
        # Prioritize exploit-relevant code blocks (c_exploit_code, patch_diff,
        # c_kernel_struct, crash_log) over generic "other" blocks
        priority_order = [
            "c_exploit_code", "patch_diff", "c_kernel_struct",
            "crash_log", "c_source", "exploit_script", "shell_command", "other",
        ]
        sorted_blocks = sorted(
            code_blocks, key=lambda b: priority_order.index(b["type"])
            if b["type"] in priority_order else 99
        )

        if sorted_blocks:
            text += "\n\n=== EXTRACTED CODE BLOCKS ===\n"
            for i, block in enumerate(sorted_blocks, 1):
                ids = block["identifiers"]
                id_summary_parts = []
                for k in ("structs", "functions", "syscalls", "ioctls", "slab_caches"):
                    vals = ids.get(k, [])
                    if vals:
                        id_summary_parts.append(f"{k}: {', '.join(vals[:10])}")
                id_line = " | ".join(id_summary_parts) if id_summary_parts else ""

                text += (
                    f"\n--- Code Block {i} "
                    f"[type={block['type']}"
                    f"{', lang=' + block['lang'] if block['lang'] else ''}] ---\n"
                )
                if id_line:
                    text += f"  Identifiers: {id_line}\n"
                text += f"{block['text']}\n"

            # ── Aggregate identifier summary across all blocks ──
            all_structs: List[str] = []
            all_funcs: List[str] = []
            all_syscalls: List[str] = []
            all_ioctls: List[str] = []
            all_caches: List[str] = []
            for b in sorted_blocks:
                ids = b["identifiers"]
                for s in ids.get("structs", []):
                    if s not in all_structs:
                        all_structs.append(s)
                for s in ids.get("functions", []):
                    if s not in all_funcs:
                        all_funcs.append(s)
                for s in ids.get("syscalls", []):
                    if s not in all_syscalls:
                        all_syscalls.append(s)
                for s in ids.get("ioctls", []):
                    if s not in all_ioctls:
                        all_ioctls.append(s)
                for s in ids.get("slab_caches", []):
                    if s not in all_caches:
                        all_caches.append(s)

            text += "\n\n=== AGGREGATE CODE IDENTIFIERS ===\n"
            if all_structs:
                text += f"Kernel structs: {', '.join(all_structs[:30])}\n"
            if all_funcs:
                text += f"Functions: {', '.join(all_funcs[:40])}\n"
            if all_syscalls:
                text += f"Syscalls: {', '.join(all_syscalls[:20])}\n"
            if all_ioctls:
                text += f"IOCTL codes: {', '.join(all_ioctls[:20])}\n"
            if all_caches:
                text += f"Slab caches: {', '.join(all_caches[:10])}\n"

            # Count exploit-relevant blocks
            exploit_blocks = [b for b in sorted_blocks if b["type"] in
                              ("c_exploit_code", "c_source", "exploit_script")]
            text += (
                f"\nTotal code blocks: {len(sorted_blocks)} "
                f"({len(exploit_blocks)} exploit-relevant)\n"
            )

        # Truncate to ~50k chars (larger limit for richer context)
        if len(text) > 50000:
            text = text[:50000] + "\n\n[TRUNCATED]"

        _ca_debug(
            f"Extracted {len(code_blocks)} code blocks "
            f"({sum(1 for b in code_blocks if b['type'] in ('c_exploit_code','c_source'))} C blocks) "
            f"from blog", debug
        )
        return text
    except Exception as e:
        _ca_debug(f"Blog fetch failed: {e}", debug)
        return ""


# ---------------------------------------------------------------------------
# CVE -> analysis JSON schema
# ---------------------------------------------------------------------------

_CVE_ANALYSIS_SYSTEM_PROMPT = """\
You are a Linux kernel vulnerability analyst. Given information about a CVE
(description, references, affected versions, and optionally a blog post or
existing PoC), produce a **structured JSON analysis** suitable for automated
exploit synthesis.

Output ONLY valid JSON matching this schema (no markdown fences, no commentary):

{
  "parsed": {
    "kind": "<vulnerability class, e.g. 'KASAN: slab-use-after-free'>",
    "raw": "<original description or summary>",
    "access": {
      "op": "<read|write|execute|unknown>",
      "size": <integer or 0>,
      "addr": ""
    },
    "frames": [
      {"function": "<kernel function name>", "file": "<source file>", "line": <int>}
    ],
    "object_info": {
      "cache": "<slab cache name, e.g. kmalloc-256, or empty>",
      "obj_size": <integer or 0>
    }
  },
  "openai_llm": {
    "parsed": {
      "overview": {
        "bug_type": "<use-after-free | out-of-bounds | race-condition | ...>",
        "exploitability": "<HIGH | MEDIUM | LOW>",
        "primitive_capabilities": "<description of what an attacker can achieve>"
      },
      "postconditions": [
        {
          "type": "<postcondition type>",
          "controlability": ["<controllability factor>"]
        }
      ]
    }
  },
  "cve_metadata": {
    "cve_id": "<CVE-YYYY-NNNNN>",
    "cvss_score": <float or null>,
    "affected_subsystem": "<kernel subsystem>",
    "affected_versions": ["<version range>"],
    "patch_commit": "<commit hash or empty>",
    "references": ["<url>"]
  },
  "vuln_type": "<uaf | oob_read | oob_write | double_free | race_condition | type_confusion | integer_overflow | null_deref | logic_bug | unknown>",
  "target_struct": "<primary affected kernel struct or empty>",
  "slab_cache": "<target slab cache or empty>",
  "exploitation_hints": {
    "technique": "<recommended exploitation technique>",
    "difficulty": "<easy | medium | hard>",
    "mitigations_to_bypass": ["<mitigation name>"],
    "key_functions": ["<kernel function names relevant to exploitation>"],
    "notes": "<any additional exploitation notes>"
  },
  "code_analysis": {
    "trigger_syscalls": ["<syscalls needed to trigger the vulnerability, e.g. ioctl, sendmsg>"],
    "trigger_sequence": "<step-by-step description of how to trigger the bug from userspace>",
    "vulnerable_path": ["<callchain from userspace to vulnerable code, e.g. ioctl -> binder_thread_write -> binder_transaction>"],
    "spray_objects": ["<kernel objects suitable for heap spray, e.g. msg_msg, pipe_buffer>"],
    "spray_syscalls": ["<syscalls to allocate spray objects, e.g. msgsnd, pipe>"],
    "useful_structs": [
      {"name": "<struct name>", "size": "<size or empty>", "cache": "<slab cache or empty>",
       "purpose": "<why this struct is useful for exploitation>"}
    ],
    "race_window": "<if race condition: describe the race window, otherwise empty>",
    "code_snippets": [
      {"purpose": "<what this snippet does>", "code": "<relevant C code extracted from blog/PoC>"}
    ]
  }
}

IMPORTANT CODE EXTRACTION RULES:
- If the input contains code blocks from a blog post or PoC, extract ALL
  exploitation-relevant code into "code_analysis.code_snippets".
- For each snippet, describe its PURPOSE (trigger, spray, leak, escalate, etc.)
- Extract the EXACT syscall sequences used to trigger the vulnerability.
- Identify the full kernel call chain from userspace to the vulnerable function.
- List ALL kernel structs mentioned in code blocks with their sizes and slab caches.
- Be as specific as possible. Use real kernel function names, struct names,
  and slab cache names when identifiable. If data is missing, use empty
  strings or null – never omit a field.
"""

_CVE_POC_SYSTEM_PROMPT = """\
You are a senior Linux kernel security engineer writing proof-of-concept
regression tests for known, public kernel vulnerabilities.

Given a structured CVE analysis and optionally an existing PoC or blog post
with code, produce a **complete, compilable C program** that:

1. Runs as an unprivileged user
2. Triggers the vulnerability described in the analysis
3. Attempts to achieve privilege escalation (uid 0)
4. Compiles with: gcc -static -o poc poc.c -lpthread
5. Is designed for execution inside a QEMU/Cuttlefish test VM

The code must be COMPLETE – no placeholders, no TODOs, no stubs.
Include all necessary #include directives and implement all functions.

If the vulnerability requires specific kernel objects, use appropriate
syscalls to create them (open, socket, io_uring_setup, sendmsg, etc.).

Wrap all syscall failures with perror() and early-exit so the tester
knows which step failed.

Output ONLY the C source code. No markdown fences.
"""


# ---------------------------------------------------------------------------
# Blog post -> analysis
# ---------------------------------------------------------------------------

_BLOG_ANALYSIS_SYSTEM_PROMPT = """\
You are a Linux kernel vulnerability analyst. You have been given
extracted text from a security blog post that describes a kernel
vulnerability or exploit. 

Analyze the content and produce a **structured JSON analysis** identical
to the schema used for CVE analysis.

Output ONLY valid JSON matching this schema (no markdown fences, no commentary):

{
  "parsed": {
    "kind": "<vulnerability class>",
    "raw": "<summary of the vulnerability from the blog>",
    "access": {
      "op": "<read|write|execute|unknown>",
      "size": <integer or 0>,
      "addr": ""
    },
    "frames": [
      {"function": "<kernel function name>", "file": "<source file>", "line": <int>}
    ],
    "object_info": {
      "cache": "<slab cache>",
      "obj_size": <integer or 0>
    }
  },
  "openai_llm": {
    "parsed": {
      "overview": {
        "bug_type": "<type>",
        "exploitability": "<HIGH | MEDIUM | LOW>",
        "primitive_capabilities": "<description>"
      },
      "postconditions": [
        {
          "type": "<type>",
          "controlability": ["<factor>"]
        }
      ]
    }
  },
  "cve_metadata": {
    "cve_id": "<if identifiable from blog, else empty>",
    "cvss_score": null,
    "affected_subsystem": "<subsystem>",
    "affected_versions": [],
    "patch_commit": "<if mentioned>",
    "references": ["<blog url>"]
  },
  "vuln_type": "<uaf | oob_read | oob_write | double_free | race_condition | ...>",
  "target_struct": "<struct>",
  "slab_cache": "<cache>",
  "exploitation_hints": {
    "technique": "<technique>",
    "difficulty": "<easy | medium | hard>",
    "mitigations_to_bypass": [],
    "key_functions": [],
    "notes": ""
  }
}

Extract as much concrete detail as possible from the blog post.
Use real kernel struct names, function names, and subsystem names.
"""


# ---------------------------------------------------------------------------
# Core analysis functions
# ---------------------------------------------------------------------------

@dataclass
class CVEAnalysisResult:
    """Complete analysis result that feeds into the syzploit pipeline."""
    cve_id: str
    analysis_json: Dict[str, Any]
    poc_source: Optional[str] = None
    output_dir: str = ""
    github_pocs: List[Dict[str, str]] = field(default_factory=list)
    source_urls: List[str] = field(default_factory=list)


def analyze_cve(
    cve_id: str,
    output_dir: Optional[str] = None,
    model: str = "gpt-4o",
    generate_poc: bool = True,
    blog_urls: Optional[List[str]] = None,
    extra_context: Optional[str] = None,
    debug: bool = False,
) -> CVEAnalysisResult:
    """
    Analyze a CVE and produce syzploit-compatible analysis + optional PoC.

    Steps:
      1. Fetch CVE data from NVD + MITRE
      2. Search GitHub for existing PoCs
      3. Optionally fetch blog post content
      4. LLM analysis → static_analysis.json
      5. LLM PoC generation → poc.c

    Args:
        cve_id:        CVE identifier (e.g. ``CVE-2023-20938``)
        output_dir:    Directory for output files (auto-created)
        model:         LiteLLM model string
        generate_poc:  Whether to generate a C PoC
        blog_urls:     Optional list of blog post URLs to include as context
        extra_context: Additional free-form context (patch diff, etc.)
        debug:         Enable verbose logging

    Returns:
        ``CVEAnalysisResult`` with analysis JSON and optional PoC source.
    """
    _ca_debug(f"Analyzing {cve_id}", debug)

    # Setup output directory
    if output_dir is None:
        output_dir = os.path.join(os.getcwd(), f"cve_analysis_{cve_id}")
    os.makedirs(output_dir, exist_ok=True)

    # 1. Fetch CVE data
    nvd_data = _fetch_nvd(cve_id, debug)
    mitre_data = _fetch_mitre(cve_id, debug)

    # Build context from gathered data
    context_parts: List[str] = []

    if nvd_data:
        desc_list = nvd_data.get("descriptions", [])
        for d in desc_list:
            if d.get("lang") == "en":
                context_parts.append(f"NVD Description: {d['value']}")
        
        # CVSS
        metrics = nvd_data.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                score = metrics[key][0].get("cvssData", {}).get("baseScore")
                if score:
                    context_parts.append(f"CVSS Score: {score}")
                break

        # References
        refs = nvd_data.get("references", [])
        ref_urls = [r["url"] for r in refs[:10]]
        if ref_urls:
            context_parts.append(f"References: {', '.join(ref_urls)}")

    if mitre_data:
        # Extract from cvelistV5 format
        cna = mitre_data.get("containers", {}).get("cna", {})
        for desc in cna.get("descriptions", []):
            if desc.get("lang") == "en":
                context_parts.append(f"MITRE Description: {desc['value']}")
        affected = cna.get("affected", [])
        for aff in affected[:3]:
            product = aff.get("product", "")
            versions = [v.get("version", "") for v in aff.get("versions", [])]
            if product:
                context_parts.append(f"Affected: {product} versions {', '.join(versions)}")

    # 2. Search for existing PoCs on GitHub
    github_pocs = _search_github_pocs(cve_id, debug)
    if github_pocs:
        poc_summary = "\n".join(
            f"  - {p['name']} ({p['stars']}★): {p['description']}" for p in github_pocs
        )
        context_parts.append(f"GitHub PoCs found:\n{poc_summary}")

    # 3. Fetch blog posts if provided
    blog_texts: List[str] = []
    source_urls: List[str] = []
    if blog_urls:
        for url in blog_urls:
            text = _fetch_blog_text(url, debug)
            if text:
                blog_texts.append(f"Blog ({url}):\n{text}")
                source_urls.append(url)

    # 4. Extra context
    if extra_context:
        context_parts.append(f"Additional Context:\n{extra_context}")

    # 5. LLM analysis
    combined_context = f"CVE: {cve_id}\n\n" + "\n\n".join(context_parts)
    if blog_texts:
        combined_context += "\n\n=== BLOG POSTS ===\n" + "\n\n".join(blog_texts)

    _ca_debug(f"Sending {len(combined_context)} chars to LLM for analysis", debug)

    analysis_messages = [
        {"role": "system", "content": _CVE_ANALYSIS_SYSTEM_PROMPT},
        {"role": "user", "content": combined_context},
    ]

    try:
        raw_analysis = _llm_chat(model, analysis_messages, debug)
        # Strip markdown fences if present
        raw_analysis = re.sub(r"^```(?:json)?\s*", "", raw_analysis.strip())
        raw_analysis = re.sub(r"\s*```$", "", raw_analysis.strip())
        analysis_json = json.loads(raw_analysis)
    except json.JSONDecodeError as e:
        _ca_debug(f"Failed to parse LLM JSON: {e}", debug)
        # Construct minimal valid analysis
        analysis_json = _build_fallback_analysis(cve_id, combined_context)
    except Exception as e:
        _ca_debug(f"LLM analysis failed: {e}", debug)
        analysis_json = _build_fallback_analysis(cve_id, combined_context)

    # Save analysis
    analysis_path = os.path.join(output_dir, "static_analysis.json")
    with open(analysis_path, "w") as f:
        json.dump(analysis_json, f, indent=2)
    _ca_debug(f"Wrote static_analysis.json to {analysis_path}", debug)

    # Save raw context for reference
    context_path = os.path.join(output_dir, "cve_context.txt")
    with open(context_path, "w") as f:
        f.write(combined_context)

    # Save GitHub PoC list
    if github_pocs:
        pocs_path = os.path.join(output_dir, "github_pocs.json")
        with open(pocs_path, "w") as f:
            json.dump(github_pocs, f, indent=2)

    # 6. Generate PoC
    poc_source = None
    if generate_poc:
        poc_source = _generate_poc_from_analysis(
            cve_id, analysis_json, combined_context, model, output_dir, debug
        )

    result = CVEAnalysisResult(
        cve_id=cve_id,
        analysis_json=analysis_json,
        poc_source=poc_source,
        output_dir=output_dir,
        github_pocs=github_pocs,
        source_urls=source_urls,
    )

    _ca_debug(f"Analysis complete for {cve_id}", debug)
    return result


def analyze_blog_post(
    url: str,
    output_dir: Optional[str] = None,
    model: str = "gpt-4o",
    generate_poc: bool = True,
    extra_context: Optional[str] = None,
    debug: bool = False,
) -> CVEAnalysisResult:
    """
    Analyze a security blog post and produce syzploit-compatible analysis.

    Fetches the blog, extracts text and code blocks, then uses an LLM to
    classify the vulnerability and optionally generate a PoC.
    """
    _ca_debug(f"Analyzing blog: {url}", debug)

    # Determine a short name for the output directory
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", url.split("//")[-1])[:60]
    if output_dir is None:
        output_dir = os.path.join(os.getcwd(), f"blog_analysis_{slug}")
    os.makedirs(output_dir, exist_ok=True)

    # Fetch blog content
    blog_text = _fetch_blog_text(url, debug)
    if not blog_text:
        _ca_debug("Failed to fetch blog content", debug)
        return CVEAnalysisResult(
            cve_id="",
            analysis_json=_build_fallback_analysis("", "Blog fetch failed"),
            output_dir=output_dir,
            source_urls=[url],
        )

    # Save raw blog text
    blog_path = os.path.join(output_dir, "blog_text.txt")
    with open(blog_path, "w") as f:
        f.write(blog_text)

    # Optional extra context
    full_context = f"Source URL: {url}\n\n{blog_text}"
    if extra_context:
        full_context += f"\n\nAdditional Context:\n{extra_context}"

    # LLM analysis
    analysis_messages = [
        {"role": "system", "content": _BLOG_ANALYSIS_SYSTEM_PROMPT},
        {"role": "user", "content": full_context},
    ]

    try:
        raw_analysis = _llm_chat(model, analysis_messages, debug)
        raw_analysis = re.sub(r"^```(?:json)?\s*", "", raw_analysis.strip())
        raw_analysis = re.sub(r"\s*```$", "", raw_analysis.strip())
        analysis_json = json.loads(raw_analysis)
    except json.JSONDecodeError as e:
        _ca_debug(f"Failed to parse LLM JSON: {e}", debug)
        analysis_json = _build_fallback_analysis("", full_context)
    except Exception as e:
        _ca_debug(f"LLM analysis failed: {e}", debug)
        analysis_json = _build_fallback_analysis("", full_context)

    # Try to detect a CVE ID from the analysis or blog text
    cve_id = analysis_json.get("cve_metadata", {}).get("cve_id", "")
    if not cve_id:
        cve_match = re.search(r"(CVE-\d{4}-\d{4,})", blog_text)
        if cve_match:
            cve_id = cve_match.group(1)
            analysis_json.setdefault("cve_metadata", {})["cve_id"] = cve_id

    # Save analysis
    analysis_path = os.path.join(output_dir, "static_analysis.json")
    with open(analysis_path, "w") as f:
        json.dump(analysis_json, f, indent=2)

    # Generate PoC
    poc_source = None
    if generate_poc:
        poc_source = _generate_poc_from_analysis(
            cve_id or "unknown", analysis_json, full_context, model, output_dir, debug
        )

    return CVEAnalysisResult(
        cve_id=cve_id,
        analysis_json=analysis_json,
        poc_source=poc_source,
        output_dir=output_dir,
        source_urls=[url],
    )


# ---------------------------------------------------------------------------
# PoC generation
# ---------------------------------------------------------------------------

def _generate_poc_from_analysis(
    cve_id: str,
    analysis_json: Dict[str, Any],
    full_context: str,
    model: str,
    output_dir: str,
    debug: bool,
) -> Optional[str]:
    """Use the structured analysis + context to generate a C PoC."""
    _ca_debug(f"Generating PoC for {cve_id}", debug)

    # Build a focused prompt with maximum code context
    vuln_type = analysis_json.get("vuln_type", "unknown")
    target_struct = analysis_json.get("target_struct", "")
    slab_cache = analysis_json.get("slab_cache", "")
    hints = analysis_json.get("exploitation_hints", {})
    technique = hints.get("technique", "")
    key_functions = hints.get("key_functions", [])
    parsed = analysis_json.get("parsed", {})
    kind = parsed.get("kind", "")
    raw_desc = parsed.get("raw", "")
    code_analysis = analysis_json.get("code_analysis", {})

    # Build code-specific context section
    code_context_parts: List[str] = []
    trigger_seq = code_analysis.get("trigger_sequence", "")
    if trigger_seq:
        code_context_parts.append(f"TRIGGER SEQUENCE:\n{trigger_seq}")
    trigger_syscalls = code_analysis.get("trigger_syscalls", [])
    if trigger_syscalls:
        code_context_parts.append(f"TRIGGER SYSCALLS: {', '.join(trigger_syscalls)}")
    vuln_path = code_analysis.get("vulnerable_path", [])
    if vuln_path:
        code_context_parts.append(f"VULNERABLE CALL CHAIN: {' -> '.join(vuln_path)}")
    spray_objects = code_analysis.get("spray_objects", [])
    spray_syscalls = code_analysis.get("spray_syscalls", [])
    if spray_objects:
        code_context_parts.append(f"SPRAY OBJECTS: {', '.join(spray_objects)}")
    if spray_syscalls:
        code_context_parts.append(f"SPRAY SYSCALLS: {', '.join(spray_syscalls)}")
    useful_structs = code_analysis.get("useful_structs", [])
    if useful_structs:
        struct_lines = []
        for s in useful_structs:
            struct_lines.append(
                f"  - {s.get('name', '?')} (size={s.get('size', '?')}, "
                f"cache={s.get('cache', '?')}): {s.get('purpose', '')}"
            )
        code_context_parts.append(f"USEFUL STRUCTS:\n" + "\n".join(struct_lines))
    code_snippets = code_analysis.get("code_snippets", [])
    if code_snippets:
        snippet_text = []
        for sn in code_snippets:
            snippet_text.append(f"  // {sn.get('purpose', 'unknown')}\n{sn.get('code', '')}")
        code_context_parts.append(
            "REFERENCE CODE FROM BLOG/POC (adapt and use these directly):\n"
            + "\n\n".join(snippet_text)
        )
    race_window = code_analysis.get("race_window", "")
    if race_window:
        code_context_parts.append(f"RACE WINDOW: {race_window}")
    code_context_str = "\n\n".join(code_context_parts) if code_context_parts else ""

    user_prompt = textwrap.dedent(f"""\
        CVE: {cve_id}
        Vulnerability Type: {vuln_type}
        Kind: {kind}
        Description: {raw_desc}
        Target Struct: {target_struct}
        Slab Cache: {slab_cache}
        Recommended Technique: {technique}
        Key Functions: {', '.join(key_functions)}

        === EXTRACTED CODE ANALYSIS ===
        {code_context_str}

        === RAW CONTEXT (CVE data, blog posts, references) ===
        {full_context[:20000]}

        INSTRUCTIONS:
        Write a complete C proof-of-concept that triggers this vulnerability
        and attempts privilege escalation. The program MUST:
        - Use the EXACT syscall sequences and struct layouts from the code
          analysis and blog post snippets above
        - Implement the trigger sequence step by step
        - Use the identified spray objects and spray syscalls for heap manipulation
        - Compile with: gcc -static -o poc poc.c -lpthread
        - Run as unprivileged user on Android/Cuttlefish (aarch64)
        - Print "[+] got root!" when escalation succeeds
        - Handle errors gracefully with perror()
        - Include comments referencing which step of the exploit each section implements

        If the blog post contains exploit code snippets, adapt them directly
        rather than writing from scratch. Preserve the exploitation logic.
    """)

    messages = [
        {"role": "system", "content": _CVE_POC_SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]

    try:
        raw_poc = _llm_chat(model, messages, debug)

        # Strip markdown fences
        raw_poc = re.sub(r"^```(?:c|C)?\s*\n?", "", raw_poc.strip())
        raw_poc = re.sub(r"\n?```\s*$", "", raw_poc.strip())

        # Basic validation: must contain main() and #include
        if "main" not in raw_poc or "#include" not in raw_poc:
            _ca_debug("Generated PoC looks malformed, saving anyway", debug)

        # Save
        poc_path = os.path.join(output_dir, "poc.c")
        with open(poc_path, "w") as f:
            f.write(raw_poc)
        _ca_debug(f"Wrote PoC to {poc_path}", debug)

        # Also generate a Makefile
        makefile_path = os.path.join(output_dir, "Makefile")
        with open(makefile_path, "w") as f:
            f.write(textwrap.dedent(f"""\
                # Auto-generated Makefile for {cve_id} PoC
                CC ?= gcc
                CFLAGS ?= -static -lpthread -Wall -O2
                TARGET = poc

                # Cross-compile for ARM64 Android
                CC_ARM64 = aarch64-linux-gnu-gcc
                # Cross-compile for x86_64
                CC_X86 = gcc

                .PHONY: all clean arm64 x86_64

                all: x86_64

                x86_64:
                \t$(CC_X86) $(CFLAGS) -o $(TARGET) poc.c

                arm64:
                \t$(CC_ARM64) $(CFLAGS) -o $(TARGET)_arm64 poc.c

                clean:
                \trm -f $(TARGET) $(TARGET)_arm64
            """))

        return raw_poc

    except Exception as e:
        _ca_debug(f"PoC generation failed: {e}", debug)
        return None


# ---------------------------------------------------------------------------
# Fallback analysis builder
# ---------------------------------------------------------------------------

def _build_fallback_analysis(cve_id: str, context: str) -> Dict[str, Any]:
    """Build a minimal valid static_analysis.json when LLM fails."""
    return {
        "parsed": {
            "kind": "unknown vulnerability",
            "raw": context[:2000] if context else "",
            "access": {"op": "unknown", "size": 0, "addr": ""},
            "frames": [],
            "object_info": {"cache": "", "obj_size": 0},
        },
        "openai_llm": {
            "parsed": {
                "overview": {
                    "bug_type": "unknown",
                    "exploitability": "LOW",
                    "primitive_capabilities": "",
                },
                "postconditions": [],
            }
        },
        "cve_metadata": {
            "cve_id": cve_id,
            "cvss_score": None,
            "affected_subsystem": "",
            "affected_versions": [],
            "patch_commit": "",
            "references": [],
        },
        "vuln_type": "unknown",
        "target_struct": "",
        "slab_cache": "",
        "exploitation_hints": {
            "technique": "",
            "difficulty": "hard",
            "mitigations_to_bypass": [],
            "key_functions": [],
            "notes": "",
        },
    }


# ---------------------------------------------------------------------------
# Pipeline integration: feed analysis into synthesizer
# ---------------------------------------------------------------------------

def run_cve_pipeline(
    cve_id: str,
    output_dir: Optional[str] = None,
    model: str = "gpt-4o",
    blog_urls: Optional[List[str]] = None,
    extra_context: Optional[str] = None,
    kernel_name: Optional[str] = None,
    platform: str = "linux",
    planner: str = "auto",
    synthesize: bool = True,
    debug: bool = False,
) -> Dict[str, Any]:
    """
    Full pipeline: CVE → analysis → PoC → synthesis → exploit.

    Combines ``analyze_cve`` with the existing ``Synthesizer.synthesize``
    to produce an exploit plan + generated C exploit from a CVE ID.
    """
    _ca_debug(f"Running full CVE pipeline for {cve_id}", debug)

    # Step 1: Analyze the CVE
    result = analyze_cve(
        cve_id=cve_id,
        output_dir=output_dir,
        model=model,
        generate_poc=True,
        blog_urls=blog_urls,
        extra_context=extra_context,
        debug=debug,
    )

    pipeline_result: Dict[str, Any] = {
        "cve_id": cve_id,
        "analysis_dir": result.output_dir,
        "analysis_json": result.analysis_json,
        "poc_source": result.poc_source,
        "github_pocs": result.github_pocs,
    }

    if not synthesize:
        return pipeline_result

    # Step 2: Feed into Synthesizer
    try:
        from ..Synthesizer.synth import synthesize as run_synthesize

        synth_result = run_synthesize(
            bug_id=cve_id,
            goal="privilege_escalation",
            analysis_dir=result.output_dir,
            platform=platform,
            planner=planner,
            model=model,
            debug=debug,
        )
        pipeline_result["synthesis"] = synth_result
        _ca_debug(f"Synthesis complete: {synth_result.get('exploits', [])}", debug)

    except Exception as e:
        _ca_debug(f"Synthesis failed: {e}", debug)
        pipeline_result["synthesis"] = {"success": False, "error": str(e)}

    # Step 3: Optionally enrich with kexploit data
    if kernel_name:
        try:
            from ..Synthesizer.adapters.kexploit_adapter import (
                resolve_struct_offsets_from_kexploit,
                kexploit_available,
            )
            target_struct = result.analysis_json.get("target_struct", "")
            if kexploit_available() and target_struct:
                offsets = resolve_struct_offsets_from_kexploit(
                    kernel_name, target_struct, debug=debug
                )
                pipeline_result["kexploit_offsets"] = offsets
        except Exception as e:
            _ca_debug(f"kexploit offset resolution failed: {e}", debug)

    return pipeline_result


def run_blog_pipeline(
    url: str,
    output_dir: Optional[str] = None,
    model: str = "gpt-4o",
    extra_context: Optional[str] = None,
    platform: str = "linux",
    planner: str = "auto",
    synthesize: bool = True,
    debug: bool = False,
) -> Dict[str, Any]:
    """
    Full pipeline: Blog post → analysis → PoC → synthesis → exploit.
    """
    _ca_debug(f"Running blog pipeline for {url}", debug)

    result = analyze_blog_post(
        url=url,
        output_dir=output_dir,
        model=model,
        generate_poc=True,
        extra_context=extra_context,
        debug=debug,
    )

    pipeline_result: Dict[str, Any] = {
        "source_url": url,
        "cve_id": result.cve_id,
        "analysis_dir": result.output_dir,
        "analysis_json": result.analysis_json,
        "poc_source": result.poc_source,
    }

    if not synthesize:
        return pipeline_result

    # Feed into Synthesizer
    bug_id = result.cve_id or re.sub(r"[^a-zA-Z0-9]+", "_", url.split("//")[-1])[:40]
    try:
        from ..Synthesizer.synth import synthesize as run_synthesize

        synth_result = run_synthesize(
            bug_id=bug_id,
            goal="privilege_escalation",
            analysis_dir=result.output_dir,
            platform=platform,
            planner=planner,
            model=model,
            debug=debug,
        )
        pipeline_result["synthesis"] = synth_result

    except Exception as e:
        _ca_debug(f"Synthesis failed: {e}", debug)
        pipeline_result["synthesis"] = {"success": False, "error": str(e)}

    return pipeline_result
