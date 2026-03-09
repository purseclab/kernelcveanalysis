"""
analysis.blog_analyzer — Scrape a security blog post / write-up
                         and extract structured vulnerability analysis.
"""

from __future__ import annotations

import re
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


# ── Fetching & scraping ──────────────────────────────────────────────


def _fetch_page(url: str) -> str:
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "syzploit/0.2"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _extract_text(html: str) -> str:
    """Extract readable text from HTML."""
    if _HAS_BS4:
        soup = BeautifulSoup(html, "html.parser")
        # Remove script/style
        for tag in soup(["script", "style", "nav", "footer", "header"]):
            tag.decompose()
        return soup.get_text(separator="\n", strip=True)
    # Fallback: regex strip tags
    text = re.sub(r"<[^>]+>", " ", html)
    return re.sub(r"\s+", " ", text).strip()


def _extract_code_blocks(html: str) -> List[Dict[str, str]]:
    """Extract code blocks from HTML."""
    blocks: List[Dict[str, str]] = []
    if _HAS_BS4:
        soup = BeautifulSoup(html, "html.parser")
        for pre in soup.find_all(["pre", "code"]):
            code = pre.get_text(strip=True)
            if len(code) > 20:
                lang = ""
                classes = pre.get("class", [])
                for cls in classes:
                    if "language-" in str(cls):
                        lang = str(cls).replace("language-", "")
                blocks.append({"code": code, "language": lang})
    return blocks


# ── LLM analysis prompt ──────────────────────────────────────────────

_BLOG_ANALYSIS_PROMPT = """\
Analyze this kernel security blog post / write-up and extract DETAILED
vulnerability AND exploitation technique information.

Blog text (truncated to fit context):
{text}

Code blocks found:
{code_blocks}

Return JSON with ALL of these fields filled in as completely as possible.
For exploitation technique details, read the blog carefully — the technique
description is the MOST IMPORTANT output.

{{
    "cve_id": "<CVE-YYYY-NNNNN or empty>",
    "vulnerability_type": "<uaf|oob_read|oob_write|double_free|race_condition|type_confusion|integer_overflow|null_deref|logic_bug|unknown>",
    "affected_subsystem": "<kernel subsystem>",
    "affected_structs": ["<struct names mentioned>"],
    "affected_functions": ["<function names mentioned>"],
    "syscalls": ["<related syscalls>"],
    "slab_caches": ["<slab/kmalloc caches mentioned>"],
    "root_cause_description": "<detailed root cause — HOW the bug is triggered>",
    "trigger_conditions": ["<specific conditions to trigger>"],
    "exploit_technique": "<high-level technique name>",
    "exploitability_score": <0-100>,
    "fix_commit": "<commit hash if mentioned>",
    "summary": "<1-2 sentence summary>",

    "exploitation_details": {{
        "device_or_interface": "<which device/file/syscall interface is used, e.g. /dev/binder, /dev/hwbinder, io_uring, pipe, etc.>",
        "trigger_method": "<EXACT method to trigger the vulnerability — e.g. 'send transaction with corrupted offsets_size causing refcount double-decrement', 'race between io_uring submit and cancel'>",
        "uaf_object_type": "<name and size of the freed object, e.g. 'binder_node (128 bytes, kmalloc-128)'>",
        "reclaim_object_type": "<what object type is used to reclaim the freed memory, e.g. 'epitem via epoll_ctl (128 bytes, same slab)', 'msg_msg via msgsnd', 'pipe_buffer'>",
        "leak_method": "<how kernel addresses are leaked — e.g. 'read dangling binder transaction to leak epitem and struct file addresses', 'pipe_buffer.ops leak'>",
        "rw_primitive_method": "<how arbitrary R/W is achieved — e.g. 'hlist_del unlink write primitive + epoll_ctl(MOD) + ioctl(FIGETBSZ) for 32-bit read', 'corrupt pipe_buffer.page for page-level R/W'>",
        "process_architecture": "<how many processes/threads, how they coordinate — e.g. '5 processes: root(parent), A(orchestrator), B(UAF trigger), C(holder), D(holder) — communicate via Unix pipes', 'single process with 2 racing threads'>",
        "service_discovery": "<how processes find each other — e.g. 'ITokenManager HIDL service on /dev/hwbinder for handle lookup', 'shared file descriptors via fork', 'N/A'>",
        "privilege_escalation_path": "<how root is achieved — e.g. 'traverse binder_node.proc → binder_proc.tsk → task_struct → cred, zero uid/gid fields, disable SELinux', 'overwrite modprobe_path'>",
        "kernel_structs_exploited": ["<list of kernel structs actively used in the exploit, e.g. 'binder_node', 'epitem', 'struct file', 'binder_proc', 'task_struct', 'struct cred'>"],
        "heap_spray_details": "<spray strategy — count, timing, fragmentation approach>",
        "key_constants": ["<important constants mentioned, e.g. 'binder_node size=128', 'EP_ITEM_LIST_HEAD_OFFSET=88', 'kmalloc-128 slab'>"],
        "binder_specific": {{
            "binder_device": "<e.g. /dev/binder or /dev/hwbinder>",
            "uses_context_manager": "<true/false — does exploit become context manager?>",
            "transaction_types": "<types of binder transactions used>",
            "vulnerability_in_function": "<specific function with the bug>"
        }},
        "android_specific": {{
            "selinux_bypass": "<how SELinux is handled>",
            "seccomp_handling": "<how seccomp is handled>",
            "platform_constraints": "<Android-specific limitations>"
        }},
        "code_snippets": ["<key code patterns from the blog, up to 5 most important>"]
    }}
}}
"""


def analyze_blog(
    url: str,
    *,
    cfg: Optional[Config] = None,
) -> RootCauseAnalysis:
    """
    Fetch a blog post URL, extract text and code blocks,
    then use LLM to produce a structured root cause analysis.
    """
    cfg = cfg or load_config()
    llm = LLMClient(cfg).for_task("analysis")

    console.print(f"[bold]Fetching blog: {url}[/]")
    html = _fetch_page(url)
    text = _extract_text(html)
    code_blocks = _extract_code_blocks(html)

    # Use larger truncation to capture exploitation technique details
    max_text = 24000
    if len(text) > max_text:
        text = text[:max_text] + "\n\n[…truncated…]"

    code_text = "\n\n".join(
        f"```{b.get('language', '')}\n{b['code'][:3000]}\n```"
        for b in code_blocks[:15]
    ) or "(none found)"

    prompt = _BLOG_ANALYSIS_PROMPT.format(text=text, code_blocks=code_text)
    result = llm.ask_json(prompt, system="You are a kernel security analyst.")

    # Extract exploitation_details sub-dict
    exploitation_details = result.get("exploitation_details", {})

    rca = RootCauseAnalysis(
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
        exploitation_details=exploitation_details,
    )
    cve_id = result.get("cve_id", "")
    if cve_id:
        rca.summary = f"[{cve_id}] {rca.summary}"
    return rca
