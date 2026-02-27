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
- generate_exploit: LLM-driven exploit generation
- ExploitGenerator: Main generator class
- VulnType: Vulnerability type enum with fuzzy matching
- BTFData / resolve_offsets: Dynamic struct offset resolution via BTF
- KernelResearchAdapter: libxdk code generation integration

This module is standalone and does not depend on chainreactor.
Supports both Linux and Android kernel exploitation scenarios.
"""

from .synth import synthesize, synthesize_from_facts
from .powerlifted_integration import PowerliftedSolver
from .pddl_generator import PDDLGenerator
from .core import Primitive, PrimitiveRegistry, ExploitPlan, VulnType, ExploitStep, normalize_step, normalize_steps
from .btf_resolver import BTFData, resolve_offsets
from .domains import KernelDomain, TargetPlatform
from .correlation import build_correlation, CorrelationReport, FunctionRecord
from .stitcher import (
    ExploitStitcher, 
    CodeTemplateRegistry,
    LLMExploitStitcher,
    StitcherConfig,
    stitch_from_plan,
    ACTION_TO_LIBRARY,
)
from .exploit_generator import (
    generate_exploit,
    ExploitGenerator,
    ExploitTemplateGenerator,
    FunctionGenerator,
    LLMExploitPlanner,
)
from .adapters.kernelresearch_adapter import KernelResearchAdapter
from .adapters.kexploit_adapter import (
    kexploit_available,
    kexploit_agent_available,
    enrich_primitives_from_object_db,
    adapt_exploit_to_kernel,
    annotate_exploit_source,
    resolve_struct_offsets_from_kexploit,
    list_primitives as kexploit_list_primitives,
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
    'ExploitStep',
    'normalize_step',
    'normalize_steps',
    'VulnType',
    'BTFData',
    'resolve_offsets',
    'ExploitStitcher',
    'LLMExploitStitcher',
    'CodeTemplateRegistry',
    'StitcherConfig',
    'stitch_from_plan',
    'ACTION_TO_LIBRARY',
    'generate_exploit',
    'ExploitGenerator',
    'ExploitTemplateGenerator',
    'FunctionGenerator',
    'LLMExploitPlanner',
    'KernelResearchAdapter',
    # kexploit integration
    'kexploit_available',
    'kexploit_agent_available',
    'enrich_primitives_from_object_db',
    'adapt_exploit_to_kernel',
    'annotate_exploit_source',
    'resolve_struct_offsets_from_kexploit',
    'kexploit_list_primitives',
    # cross-domain correlation
    'build_correlation',
    'CorrelationReport',
    'FunctionRecord',
]