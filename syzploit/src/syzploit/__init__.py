"""
syzploit — Agentic kernel vulnerability analysis and exploit synthesis toolkit.

Architecture:
    core/         Shared models, configuration, LLM client, enums
    orchestrator/ Central agent that coordinates all components
    analysis/     Crash parsing, CVE/blog analysis, root-cause reasoning
    reproducer/   Reproducer generation, compilation, verification
    exploit/      Exploit planning (PDDL + LLM), code synthesis
    infra/        VM management (QEMU/Cuttlefish), GDB, SSH, ADB
    data/         Bug database, syzbot scraping, file storage
    cli/          Typer CLI entry-points
"""

__version__ = "0.2.0"
