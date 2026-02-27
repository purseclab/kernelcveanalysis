"""
cli — Typer CLI entry-point for syzploit.

Organized into command groups:
    analyze     Crash / CVE / blog analysis
    reproduce   Reproducer generation
    exploit     Exploit generation
    data        Bug DB / scraping
    pipeline    Full end-to-end pipeline
    agent       Agentic (LLM-driven) mode
"""

from .app import app, main

__all__ = ["app", "main"]
