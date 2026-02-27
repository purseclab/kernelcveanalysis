"""
Compilation utilities for kernel exploit development.

Provides centralized compilation functions for cross-compiling
C source files for different architectures using the project's
compile scripts (compile_arm64.sh, compile_x86_64.sh).

Integrates with syscall_fixer for automatic error correction.
"""

import os
import subprocess
import tempfile
from pathlib import Path
from typing import Tuple, Optional


def compile_exploit(
    source_path: str,
    output_path: str,
    arch: str = "arm64",
    use_llm_fix: bool = True,
    timeout: int = 120,
    workspace_dir: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Compile an exploit C source file for the target architecture.
    
    Uses the project's compile scripts (compile_arm64.sh or compile_x86_64.sh)
    which handle NDK setup and proper cross-compilation. If compilation fails,
    automatically attempts to fix errors using syscall_fixer.
    
    Args:
        source_path: Path to the C source file
        output_path: Path for the compiled binary output
        arch: Target architecture (arm64/x86_64)
        use_llm_fix: Whether to use LLM to fix compilation errors
        timeout: Compilation timeout in seconds
        workspace_dir: Directory containing compile scripts (default: cwd)
        
    Returns:
        Tuple of (success, error_message)
        
    Example:
        >>> success, error = compile_exploit("poc.c", "poc", arch="arm64")
        >>> if success:
        ...     print("Compiled successfully")
    """
    source_path = str(source_path)
    output_path = str(output_path)
    
    if not os.path.exists(source_path):
        return False, f"Source file not found: {source_path}"
    
    # Determine workspace directory for compile scripts
    if workspace_dir is None:
        workspace_dir = os.getcwd()
    
    # Get compile script path
    compile_script = _find_compile_script(arch, workspace_dir)
    
    if compile_script is None:
        return False, f"Compile script not found: compile_{arch}.sh"
    
    print(f"[COMPILE] Using compile script: {compile_script}")
    
    # First attempt: direct compilation
    try:
        result = subprocess.run(
            [str(compile_script), source_path, output_path],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=workspace_dir
        )
        
        if result.returncode == 0 and os.path.exists(output_path):
            os.chmod(output_path, 0o755)
            print(f"[COMPILE] Success: {output_path}")
            return True, ""
        
        initial_error = result.stderr or result.stdout or "Unknown compilation error"
        print(f"[COMPILE] Initial compilation failed, attempting fixes...")
        
    except subprocess.TimeoutExpired:
        return False, "Compilation timed out"
    except Exception as e:
        initial_error = str(e)
        print(f"[COMPILE] Initial compilation error: {e}")
    
    # Second attempt: use syscall_fixer for automatic fixes
    if use_llm_fix:
        try:
            from ..SyzVerify.syscall_fixer import compile_with_fix
            
            source_path_obj = Path(source_path)
            output_path_obj = Path(output_path)
            
            success = compile_with_fix(
                c_code_path=source_path_obj,
                output_path=output_path_obj,
                arch=arch,
                use_llm=True
            )
            
            if success and os.path.exists(output_path):
                os.chmod(output_path, 0o755)
                print(f"[COMPILE] Success after auto-fix: {output_path}")
                return True, ""
            else:
                return False, f"Auto-fix failed. Initial error: {initial_error[:500]}"
                
        except ImportError as e:
            print(f"[COMPILE] syscall_fixer not available: {e}")
            return False, initial_error
        except Exception as e:
            print(f"[COMPILE] Auto-fix error: {e}")
            return False, f"Auto-fix error: {e}. Initial error: {initial_error[:500]}"
    
    return False, initial_error


def _find_compile_script(arch: str, workspace_dir: str) -> Optional[Path]:
    """
    Find the compile script for the given architecture.
    
    Searches in workspace_dir, parent directories, and common locations.
    
    Args:
        arch: Target architecture (arm64/x86_64)
        workspace_dir: Starting directory for search
        
    Returns:
        Path to compile script if found, None otherwise
    """
    script_name = f"compile_{arch}.sh"
    
    # Search locations in order of priority
    search_paths = [
        Path(workspace_dir),
        Path(workspace_dir).parent,
        Path(__file__).parent.parent.parent.parent,  # syzploit root
        Path.cwd(),
    ]
    
    for search_dir in search_paths:
        candidate = search_dir / script_name
        if candidate.exists():
            return candidate
    
    return None


def compile_with_script(
    source_path: str,
    output_path: str,
    arch: str = "arm64",
    timeout: int = 120,
    workspace_dir: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Compile using only the compile script, without auto-fix.
    
    This is a simpler version of compile_exploit that doesn't attempt
    automatic error correction. Useful when you want direct control.
    
    Args:
        source_path: Path to the C source file
        output_path: Path for the compiled binary output
        arch: Target architecture (arm64/x86_64)
        timeout: Compilation timeout in seconds
        workspace_dir: Directory containing compile scripts
        
    Returns:
        Tuple of (success, error_message)
    """
    if workspace_dir is None:
        workspace_dir = os.getcwd()
    
    compile_script = _find_compile_script(arch, workspace_dir)
    
    if compile_script is None:
        return False, f"Compile script not found: compile_{arch}.sh"
    
    try:
        result = subprocess.run(
            [str(compile_script), source_path, output_path],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=workspace_dir
        )
        
        if result.returncode == 0 and os.path.exists(output_path):
            os.chmod(output_path, 0o755)
            return True, ""
        else:
            return False, result.stderr or result.stdout or "Compilation failed"
            
    except subprocess.TimeoutExpired:
        return False, "Compilation timed out"
    except Exception as e:
        return False, str(e)


def verify_syntax(
    code: str,
    platform: str = "android",
    arch: str = "arm64",
) -> Tuple[bool, str]:
    """
    Verify C code syntax by attempting compilation to a temp file.
    
    Uses the compile script to verify syntax in the actual target
    environment rather than just syntax checking.
    
    Args:
        code: C source code to verify
        platform: Target platform (android/linux)
        arch: Target architecture (arm64/x86_64)
        
    Returns:
        Tuple of (syntax_valid, error_messages)
    """
    # Write code to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
        f.write(code)
        temp_source = f.name
    
    temp_output = temp_source.replace('.c', '')
    
    try:
        success, error = compile_with_script(
            temp_source, temp_output, arch, timeout=30
        )
        return success, error
    finally:
        # Cleanup
        try:
            os.unlink(temp_source)
        except OSError:
            pass
        try:
            os.unlink(temp_output)
        except OSError:
            pass
