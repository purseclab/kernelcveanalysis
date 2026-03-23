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
    module_name: Optional[str] = None,
) -> Optional[str]:
    """Use LLM to fix compilation errors.

    Detects truncation as a special case and asks the LLM to regenerate
    with explicit length awareness.

    Parameters
    ----------
    module_name:
        When set (and not ``"main.c"``), multi-file-project-aware
        instructions are injected so the LLM does not add a rogue
        ``main()`` or redefine shared functions.
    """
    from ..core.llm import LLMClient

    cfg = cfg or load_config()
    llm = LLMClient(cfg).for_task("codegen")

    truncated = _is_truncated(code)
    line_count = len(code.split("\n"))

    # ── Multi-file project instructions ──
    _is_module = module_name and module_name != "main.c"
    _multi_file_note = ""
    if _is_module:
        _multi_file_note = (
            f"\n\nCRITICAL MULTI-FILE RULES — this file is {module_name}, "
            f"a library module in a multi-file project:\n"
            f"• DO NOT write a main() function.  main() exists ONLY in "
            f"main.c.  ANY main() here causes a duplicate-symbol linker "
            f"error.\n"
            f"• DO NOT redefine functions already declared in exploit.h — "
            f"just call them.\n"
            f"• DO NOT redefine types from template headers. Instead, use "
            f"the appropriate #include:\n"
            f'    #include "cross_cache.h"   — xcache_ctx_t, xcache_setup(), '
            f"xcache_spray_pages(), etc.\n"
            f'    #include "heap_spray.h"    — sendmsg_spray_ctx_t, '
            f"sendmsg_spray_init(), etc.\n"
            f'    #include "arb_rw.h"        — arb_read_ctx_t, kread64(), '
            f"arb_read_init(), etc.\n"
            f'    #include "pipe_rw.h"       — pipe_rw_ctx_t, pipe_rw_setup(), '
            f"pipe_rw_arb_read(), etc.\n"
            f'    #include "post_exploit.h"  — task_struct_offsets_t, '
            f"find_task_struct_offsets(), etc.\n"
            f'    #include "multi_process.h" — CommandPipe, '
            f"command_pipe_init(), etc.\n"
            f'    #include "uffd_handler.h"  — uffd_ctx_t, uffd_setup(), '
            f"uffd_start_handler(), etc.\n"
            f"• Use ONLY fields that exist in exploit_ctx_t: kernel_base, "
            f"kread64, kwrite64, target_object_addr, task_addr, cred_addr, "
            f"leaked_addr_1/2, spray_fds[], spray_count, sock_fd, "
            f"sock_fds[], sock_count, msg_qid, pipe_fds[], timer_fds[], "
            f"epoll_fd, leak_fd, scratch[], scratch_ptr[].\n"
            f"• DO NOT invent exploit_ctx_t fields such as linear_map_base, "
            f"vmemmap_base, struct_page_size, reclaim_shm, reclaim_write, "
            f"anon_pipe_buf_ops — these DO NOT EXIST.\n"
            f"\n"
            f"EXACT STRUCT FIELD NAMES (do NOT invent other field names):\n"
            f"  task_struct_offsets_t fields: cred_offset, pid_offset, "
            f"real_parent_offset, comm_offset, valid\n"
            f"  uffd_ctx_t fields: uffd, handler_thread, addr, len, "
            f"running, blocked, handler_fn, user_data, copy_buf\n"
            f"  xcache_ctx_t fields: obj_size, objs_per_page, "
            f"total_objects, n_pages, pages, spray_fn, free_fn, user_data\n"
            f"  arb_read_ctx_t fields: epoll_fd, leak_fd, initialized\n"
            f"  pipe_rw_ctx_t fields: pipe_fds, n_pipes, target_page, "
            f"flags, corrupted_idx, page_size\n"
            f"  CommandPipe fields: send_command_pipe, recv_command_pipe, "
            f"send_response_pipe, recv_response_pipe\n"
            f"\n"
            f"═══ FUNCTION OWNERSHIP — DO NOT REDEFINE ═══\n"
            f"The following functions are DEFINED in other .c files.  You\n"
            f"may CALL them but NEVER define/implement them in {module_name}:\n"
            f"  arb_rw.c: arb_read_init, kread32, kread64, kread, "
            f"kwrite32, kwrite64, kwrite, setup_rw_primitive\n"
            f"  cross_cache.c: xcache_setup, xcache_spray_pages, "
            f"xcache_free_pages, xcache_reclaim, xcache_cleanup\n"
            f"  post_exploit_lib.c / post_exploit.c: find_task_struct_offsets, "
            f"get_cred_address, overwrite_cred_to_root, disable_selinux, "
            f"find_task_by_pid, run_post_exploit\n"
            f"  util.c: pin_to_cpu, hexdump, set_exploit_name\n"
            f"  ns_setup_lib.c: ns_setup, ns_cleanup\n"
            f"Defining ANY of these causes a 'conflicting types' or "
            f"'multiple definition' error.\n"
            f"\n"
            f"═══ DO NOT INVENT KERNEL CONSTANTS ═══\n"
            f"Use ONLY constants defined in kernel_offsets.h or exploit.h:\n"
            f"  KASLR_OFFSET, VMEMMAP_START, LINEAR_MAP_BASE, PAGE_OFFSET, "
            f"PAGE_SHIFT, STRUCT_PAGE_SIZE.\n"
            f"DO NOT invent: KSYM_VMEMMAP_OFFSET, PAGE_OFFSET_BASE, "
            f"VMEMMAP_OFFSET, LINEAR_MAP_BASE_OFFSET, STRUCT_PAGE_SIZE_SHIFT, "
            f"or any KSYM_* constant.\n"
            f"\n"
            f"═══ FUNCTION SIGNATURES MUST MATCH HEADERS EXACTLY ═══\n"
            f"If a function is declared in a header (.h), your implementation "
            f"MUST use the EXACT SAME return type and parameter types.  "
            f"Do not change signatures — the header is the contract.\n"
            f"\n"
            f"• If a 'redefinition' error occurs for struct msgbuf, "
            f"use struct msgbuf_spray instead (Android NDK defines msgbuf).\n"
            f"• DO NOT add #ifdef TEMPLATE_TEST blocks.\n"
            f"• DO NOT use kernel-only APIs: virt_to_page(), kzalloc(), "
            f"kmalloc(), printk(), GFP_KERNEL, struct page pointer, etc.\n"
            f"  If you need virt_to_page logic, use the macro from "
            f"kernel_offsets.h (already #defined) — do NOT define your own.\n"
            f"• Return ONLY the fixed source for {module_name}.\n"
        )

    if truncated:
        if _is_module:
            main_instruction = (
                "Finish every incomplete function.  "
                "DO NOT add a main() — this is a library module, not main.c."
            )
        else:
            main_instruction = (
                "Finish every incomplete function and ensure main() exists "
                "and is complete.  The code MUST end with a closing brace "
                "for main()."
            )
        prompt = f"""\
The following C exploit source code was TRUNCATED (cut off) during generation.
It has {line_count} lines but is missing the end of the file.

Your task: produce a COMPLETE version of this code. Keep all existing working
code.  {main_instruction}

KEEP THE CODE AS CONCISE AS POSSIBLE — combine steps, use shorter variable
names if needed, avoid overly verbose comments. The completed code should be
under 600 lines to avoid truncation.

IMPORTANT: This is cross-compiled with Android NDK (aarch64-linux-android clang,
-static -pthread). Do NOT use kernel-internal headers like <linux/binder.h>,
<linux/io_uring.h>, etc. — they don't exist in NDK. Define all kernel structs
and ioctl numbers INLINE in the source.{_multi_file_note}

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
structs, constants, and ioctl numbers directly in the source file.{_multi_file_note}

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
            close_idx = None
            for _i in range(len(lines) - 1, -1, -1):
                if lines[_i].strip() == "```":
                    close_idx = _i
                    break
            if close_idx is not None:
                lines = lines[:close_idx]
            fixed = "\n".join(lines)

        # Reject LLM output that is prose rather than C code.
        # The LLM sometimes returns explanations starting with words
        # like "To", "The", "Here", "I" instead of actual code.
        if fixed:
            first_line = fixed.lstrip().split("\n")[0].strip()
            _PROSE_STARTS = (
                "To ", "The ", "Here", "I ", "In ", "This ", "For ",
                "Below", "Note", "Let", "Since", "We ", "You ",
                "Based", "After", "First",
            )
            if any(first_line.startswith(w) for w in _PROSE_STARTS):
                # Try to extract C code from within the prose
                import re
                code_match = re.search(
                    r'```(?:c|C)?\s*\n(.*?)```',
                    fixed,
                    re.DOTALL,
                )
                if code_match:
                    fixed = code_match.group(1).strip()
                else:
                    # No code block found — the LLM refused / wrote prose
                    return None

        if "#include" in fixed or "#define" in fixed:
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
