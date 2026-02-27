"""
Standalone PDDL domain definitions for kernel exploit synthesis.

This module provides domain files for different target platforms:
- Linux kernel exploits
- Android kernel exploits
"""

from .kernel_domain import KernelDomain, TargetPlatform

__all__ = ['KernelDomain', 'TargetPlatform']
