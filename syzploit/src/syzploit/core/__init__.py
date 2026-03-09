"""
core — Shared models, configuration, LLM client, and type definitions.

This package is the foundation layer with zero intra-project dependencies
(i.e., nothing in ``core`` imports from ``analysis``, ``exploit``, etc.).
"""

from .config import Config, load_config
from .llm import LLMClient, llm_chat
from .models import (
    CrashReport,
    CrashFrame,
    DmesgLogAnalysis,
    RootCauseAnalysis,
    TargetSystemInfo,
    VulnType,
    ExploitPlan,
    ExploitStep,
    Primitive,
    FeasibilityReport,
    ReproducerResult,
    ExploitResult,
    TraceStep,
    ExecutionTrace,
)
from .reporting import save_report, save_pipeline_summary, save_execution_trace

__all__ = [
    "Config",
    "load_config",
    "LLMClient",
    "llm_chat",
    "CrashReport",
    "CrashFrame",
    "DmesgLogAnalysis",
    "RootCauseAnalysis",
    "TargetSystemInfo",
    "VulnType",
    "ExploitPlan",
    "ExploitStep",
    "Primitive",
    "FeasibilityReport",
    "ReproducerResult",
    "ExploitResult",
    "TraceStep",
    "ExecutionTrace",
    "save_report",
    "save_pipeline_summary",
    "save_execution_trace",
]
