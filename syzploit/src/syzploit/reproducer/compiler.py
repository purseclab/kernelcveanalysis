"""
reproducer.compiler — Cross-compilation for kernel reproducers.

Wraps the project's compile scripts (compile_arm64.sh / compile_x86_64.sh)
with optional LLM-driven auto-fix on failure.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Tuple

from ..core.config import Config, load_config
from ..core.log import console


def compile_reproducer(
    source_path: str,
    output_path: str,
    *,
    arch: str = "arm64",
    use_llm_fix: bool = True,
    max_fix_attempts: int = 3,
    timeout: int = 120,
    workspace_dir: Optional[str] = None,
    cfg: Optional[Config] = None,
) -> Tuple[bool, str]:
    """
    Compile a C source file for the target architecture.

    Uses ``compile_{arch}.sh`` scripts for NDK / cross-compiler setup.
    On failure, optionally attempts LLM-driven auto-fix.

    Returns ``(success, error_message)``.
    """
    cfg = cfg or load_config()
    source_path = str(source_path)
    output_path = str(output_path)

    if not os.path.exists(source_path):
        return False, f"Source file not found: {source_path}"

    workspace_dir = workspace_dir or str(cfg.workspace_dir)
    script = _find_compile_script(arch, workspace_dir)
    if script is None:
        return False, f"Compile script not found: compile_{arch}.sh"

    console.print(f"  [dim]Compiling with {script.name}…[/]")

    # First attempt
    try:
        result = subprocess.run(
            [str(script), source_path, output_path],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=workspace_dir,
        )
        if result.returncode == 0 and os.path.exists(output_path):
            os.chmod(output_path, 0o755)
            return True, ""
        initial_error = result.stderr or result.stdout or "Unknown compilation error"
    except subprocess.TimeoutExpired:
        return False, "Compilation timed out"
    except Exception as e:
        initial_error = str(e)

    # LLM auto-fix attempts (up to max_fix_attempts)
    if use_llm_fix:
        last_error = initial_error
        for fix_attempt in range(1, max_fix_attempts + 1):
            console.print(
                f"  [dim]Compilation failed, attempting LLM auto-fix "
                f"({fix_attempt}/{max_fix_attempts})…[/]"
            )
            try:
                current_code = Path(source_path).read_text()
                fixed_code = _llm_fix_compilation(
                    current_code, last_error, attempt=fix_attempt, cfg=cfg,
                )
                if fixed_code:
                    Path(source_path).write_text(fixed_code)
                    result = subprocess.run(
                        [str(script), source_path, output_path],
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                        cwd=workspace_dir,
                    )
                    if result.returncode == 0 and os.path.exists(output_path):
                        os.chmod(output_path, 0o755)
                        console.print(
                            f"  [green]Compiled successfully after "
                            f"auto-fix attempt {fix_attempt}[/]"
                        )
                        return True, ""
                    # Update the error for the next attempt
                    last_error = (
                        result.stderr or result.stdout or "Unknown error"
                    )
            except Exception:
                pass

    return False, initial_error


def _find_compile_script(arch: str, workspace_dir: str) -> Optional[Path]:
    """Find compile_{arch}.sh in standard locations."""
    name = f"compile_{arch}.sh"
    for d in [
        Path(workspace_dir),
        Path(workspace_dir).parent,
        Path(__file__).resolve().parent.parent.parent.parent,
        Path.cwd(),
    ]:
        candidate = d / name
        if candidate.exists():
            return candidate
    return None


def _is_truncated(code: str) -> bool:
    """Detect if the C code was likely truncated by the LLM running out of tokens."""
    code = code.rstrip()
    if not code:
        return True
    # Check for obvious truncation: no closing brace, unterminated string/comment
    last_lines = code.split("\n")[-5:]
    last_text = "\n".join(last_lines)
    # Missing main() is a strong signal of truncation
    if "int main(" not in code and "void main(" not in code:
        return True
    # Unbalanced braces
    if code.count("{") - code.count("}") > 2:
        return True
    # Unterminated string literal or comment
    if last_text.count('"') % 2 != 0:
        return True
    if "/*" in last_text and "*/" not in last_text.split("/*")[-1]:
        return True
    return False


def _llm_fix_compilation(
    code: str,
    error: str,
    *,
    attempt: int = 1,
    cfg: Optional[Config] = None,
) -> Optional[str]:
    """Use LLM to fix compilation errors.

    Detects truncation as a special case and asks the LLM to regenerate
    with explicit length awareness.
    """
    from ..core.llm import LLMClient

    cfg = cfg or load_config()
    llm = LLMClient(cfg).for_task("codegen")

    truncated = _is_truncated(code)
    line_count = len(code.split("\n"))

    if truncated:
        prompt = f"""\
The following C exploit source code was TRUNCATED (cut off) during generation.
It has {line_count} lines but is missing the end of the file (functions and/or
main() are incomplete or missing entirely).

Your task: produce a COMPLETE version of this code. Keep all existing working
code but finish every incomplete function and ensure main() exists and is complete.
The code MUST end with a closing brace for main().

KEEP THE CODE AS CONCISE AS POSSIBLE — combine steps, use shorter variable
names if needed, avoid overly verbose comments. The completed code should be
under 600 lines to avoid truncation.

IMPORTANT: This is cross-compiled with Android NDK (aarch64-linux-android clang,
-static -pthread). Do NOT use kernel-internal headers like <linux/binder.h>,
<linux/io_uring.h>, etc. — they don't exist in NDK. Define all kernel structs
and ioctl numbers INLINE in the source.

Truncated source code:
```c
{code[:15000]}
```

Compilation errors:
{error[:2000]}

Return ONLY the complete corrected C source code.
"""
    else:
        prompt = f"""\
Fix the following C code compilation errors (attempt {attempt}).
Return ONLY the corrected C source code, no explanation.
Do NOT truncate the output — the complete file must be returned.

IMPORTANT: This is cross-compiled with Android NDK (aarch64-linux-android clang,
-static -pthread). If the error is "file not found" for a kernel header like
<linux/binder.h>, do NOT try to find the header — instead DEFINE the needed
structs, constants, and ioctl numbers directly in the source file.

Compilation errors:
{error[:3000]}

Source code:
```c
{code[:15000]}
```
"""
    try:
        # Use a generous max_tokens to avoid truncated responses
        fixed = llm.research_chat(
            [{"role": "user", "content": prompt}],
            max_tokens=16384,
        )
        fixed = fixed.strip()
        if fixed.startswith("```"):
            lines = fixed.split("\n")
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            fixed = "\n".join(lines)
        if "#include" in fixed:  # Sanity check — looks like C code
            return fixed
    except Exception:
        pass
    return None


def verify_syntax(code: str, *, arch: str = "arm64") -> Tuple[bool, str]:
    """Quick syntax check by compiling to a temp file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(code)
        tmp_src = f.name
    tmp_out = tmp_src.replace(".c", "")
    try:
        ok, err = compile_reproducer(tmp_src, tmp_out, arch=arch, use_llm_fix=False, timeout=30)
        return ok, err
    finally:
        for p in (tmp_src, tmp_out):
            try:
                os.unlink(p)
            except OSError:
                pass
