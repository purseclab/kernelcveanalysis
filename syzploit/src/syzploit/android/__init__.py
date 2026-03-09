"""
android — Android-specific exploit analysis and attack surface tools.

Provides:
    AttackSurfaceAnalyzer    SELinux + syscall + binder service enumeration
    BinderFuzzer             Binder transaction C code generator
"""

from .surface_analyzer import AttackSurfaceAnalyzer
from .binder_fuzzer import BinderFuzzer

__all__ = [
    "AttackSurfaceAnalyzer",
    "BinderFuzzer",
]
