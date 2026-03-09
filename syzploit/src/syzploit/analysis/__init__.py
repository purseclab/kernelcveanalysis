"""
analysis — Crash parsing, CVE/blog analysis, root-cause reasoning,
           exploitability classification, cross-version feasibility,
           slab cache oracle, kernel source context extraction, and
           kexploit bridge (struct offsets, CodeQL, offset adaptation).

Entry-points:
    analyze_input(ctx, cfg)           High-level dispatcher (used by orchestrator)
    parse_crash_log(raw)              Parse KASAN / UBSAN / generic kernel crash
    analyze_cve(cve_id)               Fetch NVD + PoCs, LLM classification
    analyze_blog(url)                 Scrape blog, extract code, LLM analysis
    root_cause_analysis(...)          LLM root-cause reasoning from crash + source
    assess_feasibility(...)           Cross-version feasibility checks (all)
    assess_feasibility_static(...)    Static-only feasibility (symbols, fixes, source diff)
    assess_feasibility_dynamic(...)   Dynamic feasibility (GDB + dmesg log analysis)
    SlabOracle                        Slab cache knowledge base & spray advisor
    KernelSourceContext               Kernel source tree extraction
    kexploit_bridge                   Bridge to kexploit (BTF, CodeQL, offset adaptation)
"""

from .crash_parser import parse_crash_log
from .cve_analyzer import analyze_cve
from .blog_analyzer import analyze_blog
from .root_cause import root_cause_analysis
from .exploitability import classify_exploitability
from .feasibility import (
    assess_feasibility,
    assess_feasibility_static,
    assess_feasibility_dynamic,
    extract_vuln_info,
)
from .dispatcher import analyze_input
from .slab_oracle import SlabOracle, SPRAY_OBJECTS
from .kernel_source import KernelSourceContext
from . import kexploit_bridge
from .kaslr_oracle import KASLROracle

__all__ = [
    "analyze_input",
    "parse_crash_log",
    "analyze_cve",
    "analyze_blog",
    "root_cause_analysis",
    "classify_exploitability",
    "assess_feasibility",
    "assess_feasibility_static",
    "assess_feasibility_dynamic",
    "extract_vuln_info",
    "SlabOracle",
    "SPRAY_OBJECTS",
    "KernelSourceContext",
    "kexploit_bridge",
    "KASLROracle",
]
