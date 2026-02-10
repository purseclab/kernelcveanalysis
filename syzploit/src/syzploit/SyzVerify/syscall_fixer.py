#!/usr/bin/env python3
"""
syscall_fixer.py

LLM-powered module to fix architecture-specific syscall compatibility issues
in syzkaller reproducer C code. This handles cases like:
- __NR_epoll_create not available on ARM64 (use epoll_create1 instead)
- Other x86-specific syscalls that need ARM64 equivalents
- Missing headers or macros for different architectures

Uses the existing LLM infrastructure from SyzAnalyze.crash_analyzer.
"""

import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Tuple, List, Dict
from dataclasses import dataclass

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    # Load from local .env file in SyzVerify directory
    env_path = Path(__file__).parent / '.env'
    if env_path.exists():
        load_dotenv(env_path)
    else:
        # Fallback to SyzAnalyze/.env
        env_path = Path(__file__).parent.parent / 'SyzAnalyze' / '.env'
        if env_path.exists():
            load_dotenv(env_path)
        else:
            load_dotenv()  # Default search
except ImportError:
    pass

# Import LLM utilities from crash_analyzer
try:
    from ..SyzAnalyze.crash_analyzer import get_openai_response
except ImportError:
    # Fallback for direct execution
    get_openai_response = None


@dataclass
class CompilationError:
    """Represents a compilation error with context."""
    file: str
    line: int
    column: int
    error_type: str
    message: str
    raw_error: str


# Common syscall mapping from x86_64 to ARM64 equivalents
# These are syscalls that don't exist on ARM64 and need alternative implementations
SYSCALL_ALTERNATIVES = {
    "__NR_epoll_create": {
        "replacement": "__NR_epoll_create1",
        "note": "epoll_create is not available on ARM64, use epoll_create1 with flags=0 for same behavior",
        "code_transform": lambda code: code.replace(
            "syscall(__NR_epoll_create,",
            "syscall(__NR_epoll_create1, 0,"  # Add 0 as flags argument
        ).replace(
            "syscall(__NR_epoll_create)",
            "syscall(__NR_epoll_create1, 0)"
        )
    },
    "__NR_fork": {
        "replacement": "__NR_clone",
        "note": "fork is not available on ARM64, clone with specific flags can be used"
    },
    "__NR_open": {
        "replacement": "__NR_openat",
        "note": "open is not available on ARM64, use openat with AT_FDCWD as first argument"
    },
    "__NR_dup2": {
        "replacement": "__NR_dup3",
        "note": "dup2 is not available on ARM64, use dup3 with flags=0"
    },
    "__NR_pipe": {
        "replacement": "__NR_pipe2",
        "note": "pipe is not available on ARM64, use pipe2 with flags=0"
    },
    "__NR_poll": {
        "replacement": "__NR_ppoll",
        "note": "poll is not available on ARM64, use ppoll with NULL timeout and sigmask"
    },
    "__NR_select": {
        "replacement": "__NR_pselect6",
        "note": "select is not available on ARM64, use pselect6"
    },
    "__NR_stat": {
        "replacement": "__NR_fstatat",
        "note": "stat is not available on ARM64, use fstatat with AT_FDCWD"
    },
    "__NR_lstat": {
        "replacement": "__NR_fstatat",
        "note": "lstat is not available on ARM64, use fstatat with AT_SYMLINK_NOFOLLOW"
    },
    "__NR_access": {
        "replacement": "__NR_faccessat",
        "note": "access is not available on ARM64, use faccessat with AT_FDCWD"
    },
    "__NR_rename": {
        "replacement": "__NR_renameat",
        "note": "rename is not available on ARM64, use renameat with AT_FDCWD"
    },
    "__NR_mkdir": {
        "replacement": "__NR_mkdirat",
        "note": "mkdir is not available on ARM64, use mkdirat with AT_FDCWD"
    },
    "__NR_rmdir": {
        "replacement": "__NR_unlinkat",
        "note": "rmdir is not available on ARM64, use unlinkat with AT_REMOVEDIR"
    },
    "__NR_unlink": {
        "replacement": "__NR_unlinkat",
        "note": "unlink is not available on ARM64, use unlinkat with AT_FDCWD and flags=0"
    },
    "__NR_symlink": {
        "replacement": "__NR_symlinkat",
        "note": "symlink is not available on ARM64, use symlinkat"
    },
    "__NR_readlink": {
        "replacement": "__NR_readlinkat",
        "note": "readlink is not available on ARM64, use readlinkat with AT_FDCWD"
    },
    "__NR_chmod": {
        "replacement": "__NR_fchmodat",
        "note": "chmod is not available on ARM64, use fchmodat with AT_FDCWD"
    },
    "__NR_chown": {
        "replacement": "__NR_fchownat",
        "note": "chown is not available on ARM64, use fchownat with AT_FDCWD"
    },
    "__NR_lchown": {
        "replacement": "__NR_fchownat",
        "note": "lchown is not available on ARM64, use fchownat with AT_SYMLINK_NOFOLLOW"
    },
    "__NR_mmap": {
        "replacement": "__NR_mmap2",
        "note": "Some ARM platforms use mmap2 instead of mmap"
    },
    "__NR_getdents": {
        "replacement": "__NR_getdents64",
        "note": "getdents is not available on ARM64, use getdents64"
    },
}


def parse_compilation_errors(stderr: str) -> List[CompilationError]:
    """Parse compiler error output into structured errors."""
    errors = []
    
    # Pattern for clang/gcc errors: file:line:col: error: message
    pattern = r'([^:]+):(\d+):(\d+):\s*(error|warning):\s*(.+)'
    
    for match in re.finditer(pattern, stderr):
        errors.append(CompilationError(
            file=match.group(1),
            line=int(match.group(2)),
            column=int(match.group(3)),
            error_type=match.group(4),
            message=match.group(5).strip(),
            raw_error=match.group(0)
        ))
    
    return errors


def try_quick_fix(c_code: str, errors: List[CompilationError], target_arch: str) -> Tuple[str, bool]:
    """
    Attempt quick fixes for common syscall issues without using LLM.
    Returns (fixed_code, was_fixed).
    """
    fixed_code = c_code
    any_fixed = False
    
    for error in errors:
        if "undeclared identifier" in error.message:
            # Extract the undeclared identifier
            match = re.search(r"'(__NR_\w+)'", error.message)
            if match:
                missing_syscall = match.group(1)
                
                # Check if we have a known alternative
                if missing_syscall in SYSCALL_ALTERNATIVES:
                    alt = SYSCALL_ALTERNATIVES[missing_syscall]
                    
                    # Apply code transformation if available
                    if "code_transform" in alt:
                        fixed_code = alt["code_transform"](fixed_code)
                        any_fixed = True
                        print(f"[QUICK FIX] Replaced {missing_syscall} with {alt['replacement']}")
                        print(f"  Note: {alt['note']}")
    
    return fixed_code, any_fixed


def create_llm_fix_prompt(c_code: str, errors: List[CompilationError], target_arch: str) -> str:
    """Create a prompt for the LLM to fix compilation errors."""
    
    error_descriptions = "\n".join([
        f"  Line {e.line}: {e.message}"
        for e in errors if e.error_type == "error"
    ])
    
    prompt = f"""You are an expert C programmer specializing in Linux kernel and syscall programming.

I have a syzkaller reproducer C program that was generated for x86_64 but needs to run on {target_arch}.
The code has compilation errors because some syscalls don't exist on {target_arch}.

## Compilation Errors:
{error_descriptions}

## Current Code:
```c
{c_code}
```

## Your Task:
Fix the compilation errors by replacing x86_64-specific syscalls with their {target_arch} equivalents.

Common replacements for ARM64:
- __NR_epoll_create -> __NR_epoll_create1 (add 0 as flags argument)
- __NR_open -> __NR_openat (use AT_FDCWD as first argument)
- __NR_dup2 -> __NR_dup3 (add 0 as flags argument)
- __NR_pipe -> __NR_pipe2 (add 0 as flags argument)
- __NR_poll -> __NR_ppoll (adjust arguments accordingly)
- __NR_fork -> __NR_clone (with appropriate flags)
- __NR_stat/__NR_lstat -> __NR_fstatat (use AT_FDCWD)
- __NR_access -> __NR_faccessat (use AT_FDCWD)
- __NR_rename -> __NR_renameat (use AT_FDCWD for both paths)
- __NR_mkdir -> __NR_mkdirat (use AT_FDCWD)
- __NR_unlink -> __NR_unlinkat (use AT_FDCWD, flags=0)
- __NR_rmdir -> __NR_unlinkat (use AT_FDCWD, AT_REMOVEDIR flag)
- __NR_getdents -> __NR_getdents64

Important rules:
1. Keep the logic and behavior of the original program intact
2. Only modify what's necessary to fix the compilation errors
3. Add any necessary headers or defines
4. The fixed code must compile with Android NDK clang for {target_arch}
5. Preserve all comments and structure where possible

Return ONLY the fixed C code, no explanations. The code should be complete and ready to compile.
"""
    
    return prompt


def fix_with_llm(c_code: str, errors: List[CompilationError], target_arch: str) -> Optional[str]:
    """Use LLM to fix compilation errors."""
    if get_openai_response is None:
        print("[WARN] LLM module not available, cannot fix with LLM")
        return None
    
    # Get API key from environment
    api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("OPENAI_KEY", "")
    if not api_key:
        print("[WARN] OPENAI_API_KEY not set in environment, cannot use LLM for fixes")
        return None
    
    prompt = create_llm_fix_prompt(c_code, errors, target_arch)
    
    try:
        response = get_openai_response(prompt, api_key)
        
        # Extract code from response
        if response:
            # Try to extract code block
            code_match = re.search(r'```c?\s*\n(.*?)```', response, re.DOTALL)
            if code_match:
                return code_match.group(1).strip()
            
            # If no code block, check if response looks like C code
            if '#include' in response or 'int main' in response or 'syscall(' in response:
                return response.strip()
        
        return None
    except Exception as e:
        print(f"[ERROR] LLM fix failed: {e}")
        return None


def try_compile(c_path: Path, output_path: Path, arch: str, ndk_path: str = None) -> Tuple[bool, str]:
    """
    Try to compile the C code and return (success, stderr).
    """
    if ndk_path is None:
        ndk_path = os.environ.get("ANDROID_NDK_HOME", os.environ.get("ANDROID_NDK", "/workspace/android_sdk/ndk/25.2.9519653/"))
    
    if arch == "arm64":
        target = "aarch64"
        api = "30"
    else:
        target = "x86_64"
        api = "30"
    
    toolchain = f"{ndk_path}/toolchains/llvm/prebuilt/linux-x86_64"
    compiler = f"{toolchain}/bin/{target}-linux-android{api}-clang"
    
    # Check if compiler exists
    if not os.path.exists(compiler):
        # Try fallback compilers
        if arch == "arm64":
            compiler = "aarch64-linux-gnu-gcc"
        else:
            compiler = "x86_64-linux-gnu-gcc"
    
    cmd = [compiler, "-fsyntax-only", str(c_path)]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0, result.stderr
    except FileNotFoundError:
        return False, f"Compiler not found: {compiler}"


def fix_syscall_compatibility(
    c_code_path: Path,
    output_path: Path,
    target_arch: str,
    ndk_path: str = None,
    max_attempts: int = 3,
    use_llm: bool = True
) -> Tuple[bool, Path]:
    """
    Main function to fix syscall compatibility issues in C code.
    
    Args:
        c_code_path: Path to the C source file
        output_path: Path to write the fixed binary
        target_arch: Target architecture (e.g., "arm64", "x86_64")
        ndk_path: Path to Android NDK
        max_attempts: Maximum number of LLM fix attempts
        use_llm: Whether to use LLM for fixes (True) or only quick fixes (False)
    
    Returns:
        (success, final_c_path) - whether fix succeeded and path to fixed C file
    """
    if ndk_path is None:
        ndk_path = os.environ.get("ANDROID_NDK_HOME", os.environ.get("ANDROID_NDK", "/workspace/android_sdk/ndk/25.2.9519653/"))
    
    # Read original code
    with open(c_code_path, 'r') as f:
        c_code = f.read()
    
    # First, try compilation to see if there are errors
    success, stderr = try_compile(c_code_path, output_path, target_arch, ndk_path)
    
    if success:
        print(f"[INFO] Code compiles successfully for {target_arch}")
        return True, c_code_path
    
    print(f"[INFO] Compilation errors detected, attempting to fix...")
    errors = parse_compilation_errors(stderr)
    
    if not errors:
        print(f"[WARN] Could not parse compilation errors:\n{stderr}")
        return False, c_code_path
    
    # Try quick fixes first
    fixed_code, was_fixed = try_quick_fix(c_code, errors, target_arch)
    
    if was_fixed:
        # Write fixed code and try to compile
        fixed_path = c_code_path.parent / f"{c_code_path.stem}_fixed.c"
        with open(fixed_path, 'w') as f:
            f.write(fixed_code)
        
        success, stderr = try_compile(fixed_path, output_path, target_arch, ndk_path)
        
        if success:
            print(f"[INFO] Quick fix successful, code now compiles for {target_arch}")
            return True, fixed_path
        else:
            print(f"[INFO] Quick fix not sufficient, remaining errors detected")
            errors = parse_compilation_errors(stderr)
            c_code = fixed_code
    
    # If quick fixes didn't work and LLM is enabled, try LLM
    if use_llm and get_openai_response is not None:
        for attempt in range(max_attempts):
            print(f"[INFO] LLM fix attempt {attempt + 1}/{max_attempts}...")
            
            llm_fixed_code = fix_with_llm(c_code, errors, target_arch)
            
            if llm_fixed_code is None:
                print(f"[WARN] LLM returned no fix")
                continue
            
            # Write and try to compile
            fixed_path = c_code_path.parent / f"{c_code_path.stem}_llm_fixed.c"
            with open(fixed_path, 'w') as f:
                f.write(llm_fixed_code)
            
            success, stderr = try_compile(fixed_path, output_path, target_arch, ndk_path)
            
            if success:
                print(f"[INFO] LLM fix successful on attempt {attempt + 1}")
                return True, fixed_path
            else:
                print(f"[INFO] LLM fix attempt {attempt + 1} still has errors")
                errors = parse_compilation_errors(stderr)
                c_code = llm_fixed_code  # Use LLM output for next iteration
    
    print(f"[ERROR] Could not fix compilation errors after all attempts")
    return False, c_code_path


def compile_with_fix(
    c_code_path: Path,
    output_path: Path,
    arch: str,
    ndk_path: str = None,
    use_llm: bool = True
) -> bool:
    """
    Compile C code with automatic syscall compatibility fixes.
    This is the main entry point for use by bug_db.py.
    
    If a previously fixed file exists (_llm_fixed.c or _fixed.c), it will be used
    first to avoid re-running the LLM.
    
    Returns True if compilation succeeded (possibly after fixes).
    """
    if ndk_path is None:
        ndk_path = os.environ.get("ANDROID_NDK_HOME", os.environ.get("ANDROID_NDK", "/workspace/android_sdk/ndk/25.2.9519653/"))
    
    # First attempt normal compilation
    if arch == "arm64":
        target = "aarch64"
        compile_script = f"./compile_arm64.sh"
    else:
        target = "x86_64"
        compile_script = f"./compile_x86_64.sh"
    
    # Check for existing fixed files first (LLM fix takes precedence)
    llm_fixed_path = c_code_path.parent / f"{c_code_path.stem}_llm_fixed.c"
    quick_fixed_path = c_code_path.parent / f"{c_code_path.stem}_fixed.c"
    
    # Try previously saved LLM fix first
    if llm_fixed_path.exists():
        print(f"[INFO] Found existing LLM-fixed file: {llm_fixed_path.name}")
        result = subprocess.run(
            [compile_script, str(llm_fixed_path), str(output_path)],
            capture_output=True,
            text=True
        )
        if result.returncode == 0 and output_path.exists():
            print(f"[INFO] Compiled successfully using cached LLM fix")
            return True
        else:
            print(f"[INFO] Cached LLM fix no longer compiles, will regenerate")
    
    # Try previously saved quick fix
    if quick_fixed_path.exists():
        print(f"[INFO] Found existing quick-fixed file: {quick_fixed_path.name}")
        result = subprocess.run(
            [compile_script, str(quick_fixed_path), str(output_path)],
            capture_output=True,
            text=True
        )
        if result.returncode == 0 and output_path.exists():
            print(f"[INFO] Compiled successfully using cached quick fix")
            return True
    
    # Try normal compilation
    result = subprocess.run(
        [compile_script, str(c_code_path), str(output_path)],
        capture_output=True,
        text=True
    )
    
    if result.returncode == 0 and output_path.exists():
        return True
    
    print(f"[INFO] Initial compilation failed, attempting fixes...")
    print(f"[DEBUG] Compile stderr: {result.stderr}")
    
    # Try to fix and recompile
    success, fixed_path = fix_syscall_compatibility(
        c_code_path, output_path, arch, ndk_path, use_llm=use_llm
    )
    
    if success and fixed_path != c_code_path:
        # Compile the fixed code
        result = subprocess.run(
            [compile_script, str(fixed_path), str(output_path)],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0 and output_path.exists():
            print(f"[INFO] Fixed code compiled successfully")
            return True
    
    return False
