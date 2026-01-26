"""
Stitcher module for kernel exploit synthesis.

This module takes PDDL plan actions and stitches together
actual C code to create a working exploit.

Two stitcher implementations are available:
1. ExploitStitcher - Template-based stitching (fallback)
2. LLMExploitStitcher - LLM-powered stitching using library code
"""

from .stitcher import ExploitStitcher
from .code_templates import CodeTemplateRegistry
from .llm_stitcher import (
    LLMExploitStitcher, 
    StitcherConfig, 
    stitch_from_plan,
    ACTION_TO_LIBRARY,
    LibraryCodeMapping,
)

__all__ = [
    'ExploitStitcher', 
    'CodeTemplateRegistry',
    'LLMExploitStitcher',
    'StitcherConfig',
    'stitch_from_plan',
    'ACTION_TO_LIBRARY',
    'LibraryCodeMapping',
]
