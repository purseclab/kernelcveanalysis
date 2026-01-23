"""
Synthesizer module for kernel exploit plan generation.

This module provides:
- synthesize: Main orchestration function for exploit synthesis
- synthesize_from_facts: Generate plans from pre-extracted vulnerability facts
- PowerliftedSolver: Direct interface to powerlifted PDDL planner
- PDDLGenerator: Generate PDDL problem files for exploit synthesis
- KernelDomain: Standalone PDDL domain definitions for kernel exploits
- TargetPlatform: Enum for target platforms (Linux, Android, Generic)
- ExploitStitcher: Stitch PDDL plans into C exploit code
- CodeTemplateRegistry: Registry of C code templates for exploit actions

This module is standalone and does not depend on chainreactor.
Supports both Linux and Android kernel exploitation scenarios.
"""

from .synth import synthesize, synthesize_from_facts
from .powerlifted_integration import PowerliftedSolver
from .pddl_generator import PDDLGenerator
from .core import Primitive, PrimitiveRegistry, ExploitPlan
from .domains import KernelDomain, TargetPlatform
from .stitcher import (
    ExploitStitcher, 
    CodeTemplateRegistry,
    LLMExploitStitcher,
    StitcherConfig,
    stitch_from_plan,
    ACTION_TO_LIBRARY,
)

__all__ = [
    'synthesize',
    'synthesize_from_facts',
    'PowerliftedSolver',
    'PDDLGenerator',
    'KernelDomain',
    'TargetPlatform',
    'Primitive',
    'PrimitiveRegistry',
    'ExploitPlan',
    'ExploitStitcher',
    'LLMExploitStitcher',
    'CodeTemplateRegistry',
    'StitcherConfig',
    'stitch_from_plan',
    'ACTION_TO_LIBRARY',
]