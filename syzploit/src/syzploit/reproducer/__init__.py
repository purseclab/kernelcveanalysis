"""
reproducer — Generate, compile, and verify kernel bug reproducers.

Entry-points:
    generate_reproducer(ctx, cfg)   Full pipeline: generate → compile → verify
    generate_reproducer_code(...)   LLM-driven C code generation
    compile_reproducer(...)         Cross-compile for target arch
    verify_reproducer(...)          Run on target and check for crash
"""

from .generator import generate_reproducer_code
from .compiler import compile_reproducer
from .verifier import verify_reproducer
from .pipeline import generate_reproducer

__all__ = [
    "generate_reproducer",
    "generate_reproducer_code",
    "compile_reproducer",
    "verify_reproducer",
]
