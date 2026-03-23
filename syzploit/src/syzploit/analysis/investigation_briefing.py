"""
analysis.investigation_briefing — Structured prompt context from investigation.

Transforms raw investigation data into templated "briefings" — structured
documents that downstream LLM stages (reproducer, exploit generator, completer,
template adapter) can consume directly as prompt context.

The key insight is that instead of each downstream stage independently
extracting what it needs from a raw JSON blob, the investigation stage
synthesises purpose-built prompt sections using an LLM, and those sections
are designed to be copy-pasted into downstream prompts.

Usage::

    from syzploit.analysis.investigation_briefing import InvestigationBriefing

    briefing = InvestigationBriefing.from_investigation_report(report, root_cause)
    # or: briefing = InvestigationBriefing.from_dict(saved_dict)

    # Get a full briefing for the exploit generator
    prompt_ctx = briefing.for_exploit_generation()

    # Get a focused briefing for the reproducer
    prompt_ctx = briefing.for_reproducer()

    # Get a focused briefing for the completer
    prompt_ctx = briefing.for_completion()
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..core.models import RootCauseAnalysis


@dataclass
class InvestigationBriefing:
    """Structured, prompt-ready synthesis of investigation results.

    Instead of threading raw dicts through the pipeline and hoping each stage
    picks the right fields, this class pre-formats investigation data into
    purpose-built sections that can be directly inserted into LLM prompts.

    Each section is a self-contained text block with proper headers, context,
    and formatting — ready for inclusion via simple string interpolation.
    """

    # ── Core identity ─────────────────────────────────────────────────
    cve_id: str = ""
    nvd_description: str = ""
    severity: str = ""
    cvss_score: float = 0.0
    vulnerability_type: str = ""
    affected_subsystem: str = ""

    # ── Pre-formatted prompt sections ─────────────────────────────────

    # Root cause section — WHY the bug exists
    root_cause_section: str = ""

    # Trigger section — HOW to trigger the bug
    trigger_section: str = ""

    # Exploitation technique section — HOW to exploit it
    exploitation_section: str = ""

    # Reference exploit section — EXISTING code that works
    reference_exploit_section: str = ""

    # Patch analysis section — WHAT was fixed (inverse = what's vulnerable)
    patch_section: str = ""

    # Key insights section — IMPORTANT findings from blogs/PoCs
    key_insights_section: str = ""

    # Kernel source section — RELEVANT source code
    kernel_source_section: str = ""

    # Blog narrative section — PROSE descriptions of exploitation
    blog_narrative_section: str = ""

    # Struct/slab section — MEMORY layout information
    memory_layout_section: str = ""

    # ── Raw data for downstream queries ───────────────────────────────
    affected_files: List[str] = field(default_factory=list)
    affected_functions: List[str] = field(default_factory=list)
    affected_structs: List[str] = field(default_factory=list)
    fix_commits: List[str] = field(default_factory=list)
    slab_caches: List[str] = field(default_factory=list)
    syscalls: List[str] = field(default_factory=list)

    @classmethod
    def from_investigation_report(
        cls,
        report_dict: Dict[str, Any],
        root_cause: Optional[RootCauseAnalysis] = None,
    ) -> "InvestigationBriefing":
        """Build a briefing from a serialised investigation report + RCA.

        Parameters
        ----------
        report_dict
            The ``investigation_report`` dict from ``ctx.analysis_data``, or
            the result of ``InvestigationReport.to_dict()``.
        root_cause
            Optional ``RootCauseAnalysis`` from investigation synthesis.
        """
        b = cls()
        b.cve_id = report_dict.get("cve_id", "")
        b.nvd_description = report_dict.get("nvd_description", "")
        b.severity = report_dict.get("severity", "")
        b.cvss_score = report_dict.get("cvss_score", 0.0)
        b.vulnerability_type = report_dict.get("vulnerability_type", "")
        b.affected_subsystem = report_dict.get("affected_subsystem", "")
        b.affected_files = report_dict.get("affected_files", [])
        b.affected_functions = report_dict.get("affected_functions", [])
        b.affected_structs = report_dict.get("affected_structs", [])
        b.fix_commits = report_dict.get("fix_commits", [])

        if root_cause:
            b.slab_caches = root_cause.slab_caches
            b.syscalls = root_cause.syscalls

        # ── Build sections ────────────────────────────────────────────

        # Root cause
        rca_parts: list[str] = []
        if root_cause:
            if root_cause.root_cause_description:
                rca_parts.append(root_cause.root_cause_description)
            if root_cause.trigger_conditions:
                rca_parts.append("Trigger conditions:")
                for tc in root_cause.trigger_conditions:
                    rca_parts.append(f"  - {tc}")
            if root_cause.vulnerable_function:
                rca_parts.append(f"Vulnerable function: {root_cause.vulnerable_function}")
            if root_cause.vulnerable_file:
                rca_parts.append(f"Vulnerable file: {root_cause.vulnerable_file}")
        if rca_parts:
            b.root_cause_section = (
                "=== ROOT CAUSE ANALYSIS ===\n" + "\n".join(rca_parts)
            )

        # Trigger
        trigger_parts: list[str] = []
        exploitation_details = {}
        if root_cause and root_cause.exploitation_details:
            exploitation_details = root_cause.exploitation_details
        elif report_dict.get("exploitation_details"):
            exploitation_details = report_dict["exploitation_details"]

        if exploitation_details:
            tm = exploitation_details.get("trigger_method", "")
            dev = exploitation_details.get("device_or_interface", "")
            if dev:
                trigger_parts.append(f"Device/Interface: {dev}")
            if tm:
                trigger_parts.append(f"Trigger method: {tm}")
            pa = exploitation_details.get("process_architecture", "")
            if pa:
                trigger_parts.append(f"Process architecture: {pa}")
        if trigger_parts:
            b.trigger_section = (
                "=== VULNERABILITY TRIGGER ===\n" + "\n".join(trigger_parts)
            )

        # Exploitation technique (full details)
        b.exploitation_section = _format_exploitation_details_full(exploitation_details)

        # Reference exploits
        ref_parts: list[str] = []
        for ref in report_dict.get("exploit_references", [])[:3]:
            title = ref.get("title", ref.get("url", "?"))
            snippet = ref.get("code_snippet", "")
            lang = ref.get("language", "c")
            stars = ref.get("stars", 0)
            ref_parts.append(f"--- {title} ({stars}★, {lang}) ---")
            if snippet and len(snippet) > 50:
                ref_parts.append(snippet[:10000])
            ref_parts.append("")
        if ref_parts:
            b.reference_exploit_section = (
                "=== REFERENCE EXPLOITS (from GitHub) ===\n"
                "These are REAL exploit/PoC implementations found online.\n"
                "Study their approach and adapt for your implementation.\n\n"
                + "\n".join(ref_parts)
            )

        # Patch analysis
        patch_parts: list[str] = []
        for pi in report_dict.get("patch_info", [])[:4]:
            commit = pi.get("commit_hash", "")[:12]
            msg = pi.get("commit_message", "")
            files = pi.get("files_changed", [])
            diff = pi.get("diff_excerpt", "")
            src = pi.get("patch_source", "")
            patch_parts.append(f"commit {commit} ({src})")
            if msg:
                patch_parts.append(f"  {msg[:500]}")
            if files:
                patch_parts.append(f"  Files: {', '.join(files[:10])}")
            if diff:
                patch_parts.append(f"  Diff:\n{diff[:5000]}")
            vuln_analysis = pi.get("vulnerability_analysis", "")
            if vuln_analysis:
                patch_parts.append(f"  Vulnerability Analysis:\n{vuln_analysis[:5000]}")
            patch_parts.append("")
        if patch_parts:
            b.patch_section = (
                "=== FIX PATCHES ===\n"
                "These patches show exactly what was changed to fix the bug.\n"
                "The INVERSE of the fix is the vulnerable behavior you need to trigger.\n\n"
                + "\n".join(patch_parts)
            )

        # Key insights
        insight_parts: list[str] = []
        if root_cause and root_cause.key_insights:
            for ins in root_cause.key_insights:
                insight_parts.append(f"  - {ins}")
        for blog in report_dict.get("blog_analyses", []):
            for ins in blog.get("key_insights", []):
                if ins not in insight_parts:
                    insight_parts.append(f"  - {ins}")
        if insight_parts:
            b.key_insights_section = (
                "=== KEY INSIGHTS ===\n"
                "Important technical findings from blogs, PoCs, and analysis:\n"
                + "\n".join(insight_parts[:12])
            )

        # Kernel source
        src_parts: list[str] = []
        if root_cause and root_cause.source_snippets:
            for key, code in list(root_cause.source_snippets.items())[:3]:
                src_parts.append(f"--- {key} ---\n{code[:6000]}")
        for sc in report_dict.get("source_contexts", [])[:4]:
            key = sc.get("file_path", "?")
            fn = sc.get("function_name", "")
            if fn:
                key = f"{key}:{fn}"
            code = sc.get("source_code", "")
            if code and key not in (
                k.split("\n")[0].strip("- ") for k in src_parts
            ):
                src_parts.append(f"--- {key} ---\n{code[:6000]}")
        if src_parts:
            b.kernel_source_section = (
                "=== KERNEL SOURCE CODE ===\n"
                + "\n\n".join(src_parts)
            )

        # Blog narrative
        blog_parts: list[str] = []
        for blog in report_dict.get("blog_analyses", [])[:3]:
            title = blog.get("title", blog.get("url", ""))
            excerpt = blog.get("text_excerpt", "")
            blocks = blog.get("code_blocks", [])
            tech = blog.get("exploitation_technique", "")

            if excerpt and len(excerpt) > 100:
                blog_parts.append(f"--- {title} ---")
                if tech:
                    blog_parts.append(f"Technique: {tech}")
                blog_parts.append(excerpt[:6000])
                blog_parts.append("")

            if blocks:
                cb_text = "\n\n".join(cb[:3000] for cb in blocks[:8])
                blog_parts.append(f"Code from {title}:")
                blog_parts.append(cb_text[:8000])
                blog_parts.append("")
        if blog_parts:
            b.blog_narrative_section = (
                "=== BLOG ANALYSIS ===\n"
                + "\n".join(blog_parts)
            )

        # Memory layout
        mem_parts: list[str] = []
        if root_cause:
            if root_cause.slab_caches:
                mem_parts.append(f"Slab caches: {', '.join(root_cause.slab_caches)}")
            if root_cause.affected_structs:
                mem_parts.append(f"Affected structs: {', '.join(root_cause.affected_structs)}")
        if exploitation_details:
            uaf = exploitation_details.get("uaf_object_type", "")
            reclaim = exploitation_details.get("reclaim_object_type", "")
            spray = exploitation_details.get("heap_spray_details", "")
            if uaf:
                mem_parts.append(f"UAF object: {uaf}")
            if reclaim:
                mem_parts.append(f"Reclaim object: {reclaim}")
            if spray:
                mem_parts.append(f"Heap spray: {spray}")
            ks = exploitation_details.get("kernel_structs_exploited", [])
            if ks:
                mem_parts.append(f"Exploited structs: {', '.join(ks)}")
        if mem_parts:
            b.memory_layout_section = (
                "=== MEMORY LAYOUT ===\n" + "\n".join(mem_parts)
            )

        return b

    # ── Purpose-specific formatters ───────────────────────────────────

    def for_exploit_generation(self, max_chars: int = 20000) -> str:
        """Full briefing for exploit code generation.

        Includes everything: root cause, exploitation technique, reference
        exploits, patches, blog code, kernel source, key insights.
        """
        sections = [
            f"═══ INVESTIGATION BRIEFING: {self.cve_id} ═══",
            f"Severity: {self.severity} (CVSS {self.cvss_score})",
            f"Type: {self.vulnerability_type}",
            f"Subsystem: {self.affected_subsystem}",
            f"Files: {', '.join(self.affected_files)}",
            "",
        ]

        # Priority order for exploit generation
        for section in [
            self.root_cause_section,
            self.exploitation_section,
            self.trigger_section,
            self.memory_layout_section,
            self.reference_exploit_section,
            self.patch_section,
            self.key_insights_section,
            self.kernel_source_section,
            self.blog_narrative_section,
        ]:
            if section:
                sections.append(section)
                sections.append("")

        result = "\n".join(sections)
        return result[:max_chars]

    def for_reproducer(self, max_chars: int = 12000) -> str:
        """Focused briefing for reproducer/trigger generation.

        Prioritises trigger details, root cause, reference exploit trigger
        code, and patch analysis.
        """
        sections = [
            f"═══ INVESTIGATION BRIEFING (reproducer): {self.cve_id} ═══",
            f"Type: {self.vulnerability_type} in {self.affected_subsystem}",
            "",
        ]

        for section in [
            self.root_cause_section,
            self.trigger_section,
            self.key_insights_section,
            self.patch_section,
            self.reference_exploit_section,
            self.blog_narrative_section,
        ]:
            if section:
                sections.append(section)
                sections.append("")

        result = "\n".join(sections)
        return result[:max_chars]

    def for_completion(self, max_chars: int = 10000) -> str:
        """Focused briefing for completing stub/skeleton exploits.

        Prioritises exploitation technique details, reference exploit code,
        and key insights — the things needed to fill in TODOs.
        """
        sections = [
            f"═══ INVESTIGATION BRIEFING (completion): {self.cve_id} ═══",
        ]

        for section in [
            self.exploitation_section,
            self.memory_layout_section,
            self.key_insights_section,
            self.reference_exploit_section,
            self.kernel_source_section,
        ]:
            if section:
                sections.append(section)
                sections.append("")

        result = "\n".join(sections)
        return result[:max_chars]

    def for_template_adaptation(self, max_chars: int = 12000) -> str:
        """Focused briefing for adapting a template to a specific CVE.

        Prioritises root cause, exploitation details, and patches.
        """
        sections = [
            f"═══ INVESTIGATION BRIEFING (adaptation): {self.cve_id} ═══",
            f"Type: {self.vulnerability_type}",
            f"Subsystem: {self.affected_subsystem}",
            "",
        ]

        for section in [
            self.root_cause_section,
            self.exploitation_section,
            self.trigger_section,
            self.memory_layout_section,
            self.patch_section,
            self.key_insights_section,
        ]:
            if section:
                sections.append(section)
                sections.append("")

        result = "\n".join(sections)
        return result[:max_chars]

    # ── Serialisation ─────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to dict for JSON storage."""
        return {
            "cve_id": self.cve_id,
            "nvd_description": self.nvd_description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "vulnerability_type": self.vulnerability_type,
            "affected_subsystem": self.affected_subsystem,
            "affected_files": self.affected_files,
            "affected_functions": self.affected_functions,
            "affected_structs": self.affected_structs,
            "fix_commits": self.fix_commits,
            "slab_caches": self.slab_caches,
            "syscalls": self.syscalls,
            "sections": {
                "root_cause": self.root_cause_section,
                "trigger": self.trigger_section,
                "exploitation": self.exploitation_section,
                "reference_exploit": self.reference_exploit_section,
                "patch": self.patch_section,
                "key_insights": self.key_insights_section,
                "kernel_source": self.kernel_source_section,
                "blog_narrative": self.blog_narrative_section,
                "memory_layout": self.memory_layout_section,
            },
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "InvestigationBriefing":
        """Deserialise from dict."""
        b = cls()
        b.cve_id = d.get("cve_id", "")
        b.nvd_description = d.get("nvd_description", "")
        b.severity = d.get("severity", "")
        b.cvss_score = d.get("cvss_score", 0.0)
        b.vulnerability_type = d.get("vulnerability_type", "")
        b.affected_subsystem = d.get("affected_subsystem", "")
        b.affected_files = d.get("affected_files", [])
        b.affected_functions = d.get("affected_functions", [])
        b.affected_structs = d.get("affected_structs", [])
        b.fix_commits = d.get("fix_commits", [])
        b.slab_caches = d.get("slab_caches", [])
        b.syscalls = d.get("syscalls", [])
        sections = d.get("sections", {})
        b.root_cause_section = sections.get("root_cause", "")
        b.trigger_section = sections.get("trigger", "")
        b.exploitation_section = sections.get("exploitation", "")
        b.reference_exploit_section = sections.get("reference_exploit", "")
        b.patch_section = sections.get("patch", "")
        b.key_insights_section = sections.get("key_insights", "")
        b.kernel_source_section = sections.get("kernel_source", "")
        b.blog_narrative_section = sections.get("blog_narrative", "")
        b.memory_layout_section = sections.get("memory_layout", "")
        return b


def _format_exploitation_details_full(details: Dict[str, Any]) -> str:
    """Format exploitation details dict into a comprehensive prompt section.

    Similar to ``pipeline._format_exploitation_details`` but more thorough —
    includes all sub-dicts and does not truncate code_snippets as aggressively.
    """
    if not details:
        return ""

    lines = [
        "=== EXPLOITATION TECHNIQUE ===",
        "IMPORTANT: Follow these technique details closely — they describe",
        "what WORKS for this CVE based on real analysis and PoCs.",
        "",
    ]

    field_labels = {
        "device_or_interface": "Device/Interface",
        "trigger_method": "Trigger Method",
        "uaf_object_type": "UAF Object (type & size)",
        "reclaim_object_type": "Reclaim Object",
        "reclaim_strategy": "Reclaim Strategy",
        "leak_method": "Address Leak Method",
        "rw_primitive_method": "R/W Primitive",
        "heap_spray_details": "Heap Spray Strategy",
        "process_architecture": "Process Architecture",
        "service_discovery": "Service Discovery",
        "privilege_escalation_path": "Privilege Escalation Path",
    }

    for key, label in field_labels.items():
        val = details.get(key, "")
        if val:
            lines.append(f"  {label}: {val}")

    structs = details.get("kernel_structs_exploited", [])
    if structs:
        lines.append(f"  Kernel Structs: {', '.join(structs)}")

    constants = details.get("key_constants", [])
    if constants:
        lines.append(f"  Key Constants: {'; '.join(constants)}")

    binder = details.get("binder_specific", {})
    if binder and any(v for v in binder.values() if v):
        lines.append("")
        lines.append("  BINDER-SPECIFIC:")
        for k, v in binder.items():
            if v:
                lines.append(f"    {k}: {v}")

    android = details.get("android_specific", {})
    if android and any(v for v in android.values() if v):
        lines.append("")
        lines.append("  ANDROID-SPECIFIC:")
        for k, v in android.items():
            if v:
                lines.append(f"    {k}: {v}")

    snippets = details.get("code_snippets", [])
    if snippets:
        lines.append("")
        lines.append("  Key exploitation code patterns:")
        for i, snippet in enumerate(snippets[:8], 1):
            lines.append(f"  Pattern {i}:\n    {snippet[:800]}")

    lines.append("")
    return "\n".join(lines)
