"""
orchestrator — Agentic orchestration centre for syzploit.

The ``Agent`` class is the brain of the pipeline.  Given an input
(CVE id, syzbot URL, crash log, blog post URL), it:

1. Classifies the input type
2. Builds a ``TaskContext`` that accumulates artefacts
3. Iteratively calls *tools* (analysis, reproducer, exploit, infra)
   decided by an LLM-driven reasoning loop
4. Returns a final ``PipelineResult``

Lower-level, deterministic pipelines (``analyze``, ``reproduce``,
``exploit``) are also exposed for scripted / non-agentic usage.
"""

from .agent import Agent
from .context import TaskContext
from .pipeline import run_pipeline, PipelineResult
from .tools import ToolRegistry, default_registry

# Import builtin tools to auto-register them in default_registry
from . import builtin_tools as _builtin_tools  # noqa: F401

__all__ = [
    "Agent",
    "TaskContext",
    "run_pipeline",
    "PipelineResult",
    "ToolRegistry",
    "default_registry",
]
