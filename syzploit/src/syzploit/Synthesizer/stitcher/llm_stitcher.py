"""
llm_stitcher.py

LLM-powered exploit stitcher that maps PDDL actions to actual library code
from kernel-research (libxdk) and kernel_PoCs, then uses LLM to intelligently
combine them into a working exploit.

Uses llm_chat from SyzAnalyze.crash_analyzer for LLM calls.
"""

import os
import re
import sys
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from dotenv import load_dotenv

from ...SyzAnalyze.crash_analyzer import get_openai_response


def _ensure_api_key() -> bool:
    """Ensure OPENAI_API_KEY is set in environment. Returns True if key is available."""
    # Check if already set
    if os.environ.get("OPENAI_API_KEY"):
        return True
    
    api_key = os.environ.get("OPENAI_KEY")
    
    # Try loading from .env if python-dotenv is available
    if not api_key:
        try:
            
            load_dotenv()
            api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("OPENAI_KEY")
        except Exception:
            pass
    
    if api_key:
        return True
    
    return False



def extract_code_block(content: str, language: str = "c") -> Optional[str]:
    """Extract code block from markdown-formatted content."""
    if not content:
        return None
    # Try to find code block with language specifier
    pattern = rf"```{language}\s*\n(.*?)```"
    match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
    if match:
        return match.group(1).strip()
    # Try generic code block
    pattern = r"```\s*\n(.*?)```"
    match = re.search(pattern, content, re.DOTALL)
    if match:
        return match.group(1).strip()
    # If no code block markers, return content as-is if it looks like code
    if '#include' in content or 'int main' in content:
        return content.strip()
    return None


def verify_syntax(code: str, platform: str = "linux", arch: str = "x86_64") -> Tuple[bool, str]:
    """Verify C code syntax using compiler's -fsyntax-only flag."""
    # Find appropriate compiler
    if platform == "android":
        ndk_path = os.environ.get("ANDROID_NDK", os.environ.get("ANDROID_NDK_HOME", ""))
        if arch == "arm64":
            compiler = f"{ndk_path}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang" if ndk_path else "clang"
        else:
            compiler = f"{ndk_path}/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android30-clang" if ndk_path else "clang"
    else:
        if arch == "arm64":
            compiler = "aarch64-linux-gnu-gcc"
        else:
            compiler = "gcc"
    
    # Check if compiler exists
    try:
        subprocess.run([compiler, "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fallback to common compilers
        for fallback in ["gcc", "clang", "cc"]:
            try:
                subprocess.run([fallback, "--version"], capture_output=True, check=True)
                compiler = fallback
                break
            except (subprocess.CalledProcessError, FileNotFoundError):
                continue
        else:
            return False, "No C compiler found"
    
    # Write code to temp file and check syntax
    with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
        f.write(code)
        temp_path = f.name
    
    try:
        result = subprocess.run(
            [compiler, "-fsyntax-only", "-Wall", temp_path],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            return True, ""
        else:
            return False, result.stderr
    finally:
        try:
            os.unlink(temp_path)
        except Exception:
            pass


@dataclass
class LibraryCodeMapping:
    """Maps a PDDL action to library code."""
    action: str
    library: str  # "kernel-research", "kernel_PoCs", "common"
    source_files: List[str]  # Relative paths to source files
    headers: List[str]  # Header files to include
    functions: List[str]  # Function names to extract/reference
    description: str


# Mapping of PDDL actions to kernel-research/kernel_PoCs library code
# The LLM will use these as reference to generate exploit-specific code
ACTION_TO_LIBRARY: Dict[str, LibraryCodeMapping] = {
    # === Trigger actions - these use the syzbot reproducer as their implementation ===
    # The syzbot reproducer code IS the trigger - it demonstrates how to trigger the vulnerability
    "trigger_uaf": LibraryCodeMapping(
        action="trigger_uaf",
        library="syzbot_reproducer",
        source_files=[],  # Source comes from analysis_data['reproducer']
        headers=[],
        functions=["main", "loop", "trigger"],
        description="Trigger the use-after-free vulnerability using the syzbot reproducer code. "
                    "The syzbot reproducer IS the implementation of this trigger action.",
    ),
    "trigger_oob_read": LibraryCodeMapping(
        action="trigger_oob_read",
        library="syzbot_reproducer",
        source_files=[],
        headers=[],
        functions=["main", "loop", "trigger"],
        description="Trigger the out-of-bounds read vulnerability using the syzbot reproducer code. "
                    "The syzbot reproducer IS the implementation of this trigger action.",
    ),
    "trigger_oob_write": LibraryCodeMapping(
        action="trigger_oob_write",
        library="syzbot_reproducer",
        source_files=[],
        headers=[],
        functions=["main", "loop", "trigger"],
        description="Trigger the out-of-bounds write vulnerability using the syzbot reproducer code. "
                    "The syzbot reproducer IS the implementation of this trigger action.",
    ),
    "trigger_race_condition": LibraryCodeMapping(
        action="trigger_race_condition",
        library="syzbot_reproducer",
        source_files=[],
        headers=[],
        functions=["main", "loop", "trigger"],
        description="Trigger the race condition vulnerability using the syzbot reproducer code. "
                    "The syzbot reproducer IS the implementation of this trigger action.",
    ),
    "trigger_race": LibraryCodeMapping(
        action="trigger_race",
        library="syzbot_reproducer",
        source_files=[],
        headers=[],
        functions=["main", "loop", "trigger"],
        description="Trigger the race condition vulnerability using the syzbot reproducer code. "
                    "The syzbot reproducer IS the implementation of this trigger action.",
    ),
    "trigger_double_free": LibraryCodeMapping(
        action="trigger_double_free",
        library="syzbot_reproducer",
        source_files=[],
        headers=[],
        functions=["main", "loop", "trigger"],
        description="Trigger the double-free vulnerability using the syzbot reproducer code. "
                    "The syzbot reproducer IS the implementation of this trigger action.",
    ),
    "trigger_binder_bug": LibraryCodeMapping(
        action="trigger_binder_bug",
        library="syzbot_reproducer",
        source_files=[],
        headers=[],
        functions=["main", "loop", "trigger"],
        description="Trigger the binder bug using the syzbot reproducer code. "
                    "The syzbot reproducer IS the implementation of this trigger action.",
    ),
    
    # === Heap spray techniques ===
    "spray_msg_msg": LibraryCodeMapping(
        action="spray_msg_msg",
        library="kernel_PoCs",
        source_files=["badnode_cve-2023-20938_reproduction/src/exploit.c"],
        headers=["sys/ipc.h", "sys/msg.h"],
        functions=["msg_msg_spray", "msg_msg_alloc"],
        description="Spray heap with msg_msg structures for cross-cache attack",
    ),
    "spray_pipe_buffer": LibraryCodeMapping(
        action="spray_pipe_buffer",
        library="kernel-research",
        source_files=["libxdk/samples/pipe_buf_rop/exploit.cpp"],
        headers=["unistd.h", "fcntl.h"],
        functions=["alloc_victim_pipe"],
        description="Spray heap with pipe_buffer structures",
    ),
    "spray_binder_nodes": LibraryCodeMapping(
        action="spray_binder_nodes",
        library="kernel_PoCs",
        source_files=[
            "badnode_cve-2023-20938_reproduction/src/exploit.c",
            "badnode_cve-2023-20938_reproduction/src/binder.c",
        ],
        headers=["linux/binder.h"],
        functions=["uaf_nodes", "spray_binder_nodes"],
        description="Spray binder_node structures",
    ),
    "spray_seq_operations": LibraryCodeMapping(
        action="spray_seq_operations",
        library="kernel_PoCs",
        source_files=["badspin_reproduction/src/exploit.c"],
        headers=["fcntl.h"],
        functions=["spray_seq_ops"],
        description="Spray seq_operations structures",
    ),
    
    # === Arbitrary read/write derivation ===
    "derive_arb_read_from_msg_msg": LibraryCodeMapping(
        action="derive_arb_read_from_msg_msg",
        library="kernel_PoCs",
        source_files=["badnode_cve-2023-20938_reproduction/src/exploit.c"],
        headers=["sys/msg.h"],
        functions=["arb_read", "setup_arb_read"],
        description="Derive arbitrary read from corrupted msg_msg m_list.next",
    ),
    "derive_arb_write_from_msg_msg": LibraryCodeMapping(
        action="derive_arb_write_from_msg_msg",
        library="kernel_PoCs",
        source_files=["badnode_cve-2023-20938_reproduction/src/exploit.c"],
        headers=["sys/msg.h"],
        functions=["arb_write", "unlink_overwrite"],
        description="Derive arbitrary write from msg_msg unlink",
    ),
    "derive_arb_read_from_binder": LibraryCodeMapping(
        action="derive_arb_read_from_binder",
        library="kernel_PoCs",
        source_files=["badnode_cve-2023-20938_reproduction/src/exploit.c"],
        headers=["linux/binder.h"],
        functions=["arb_read_binder"],
        description="Derive arbitrary read from binder structures",
    ),
    
    # === KASLR bypass ===
    "bypass_kaslr": LibraryCodeMapping(
        action="bypass_kaslr",
        library="kernel-research",
        source_files=["libxdk/leak/LeakedBuffer.cpp", "libxdk/samples/pipe_buf_rop/exploit.cpp"],
        headers=[],
        functions=["LeakedBuffer", "GetField", "check_kaslr_base"],
        description="Bypass KASLR by leaking kernel pointer and calculating base",
    ),
    "bypass_kaslr_via_info_leak": LibraryCodeMapping(
        action="bypass_kaslr_via_info_leak",
        library="kernel-research",
        source_files=["libxdk/leak/LeakedBuffer.cpp"],
        headers=[],
        functions=["LeakedBuffer", "GetField"],
        description="Bypass KASLR using info leak primitive",
    ),
    
    # === Stack pivot and ROP ===
    "prepare_rop_chain": LibraryCodeMapping(
        action="prepare_rop_chain",
        library="kernel-research",
        source_files=[
            "libxdk/payloads/RopChain.cpp",
            "libxdk/payloads/PayloadBuilder.cpp",
            "libxdk/samples/pipe_buf_rop/exploit.cpp",
        ],
        headers=["xdk/payloads/RopChain.h", "xdk/payloads/PayloadBuilder.h"],
        functions=["RopChain", "AddRopAction", "PayloadBuilder", "Build"],
        description="Prepare ROP chain for code execution",
    ),
    "prepare_jop_chain": LibraryCodeMapping(
        action="prepare_jop_chain",
        library="kernel-research",
        source_files=["libxdk/payloads/RopChain.cpp"],
        headers=["xdk/payloads/RopChain.h"],
        functions=["RopChain"],
        description="Prepare JOP chain (ARM64)",
    ),
    "perform_stack_pivot": LibraryCodeMapping(
        action="perform_stack_pivot",
        library="kernel-research",
        source_files=[
            "libxdk/pivot/StackPivot.cpp",
            "libxdk/pivot/PivotFinder.cpp",
            "libxdk/samples/pipe_buf_rop/exploit.cpp",
        ],
        headers=["xdk/pivot/StackPivot.h"],
        functions=["StackPivot", "SetRopShift", "PivotFinder"],
        description="Perform stack pivot to controlled buffer",
    ),
    "execute_rop_payload": LibraryCodeMapping(
        action="execute_rop_payload",
        library="kernel-research",
        source_files=["libxdk/samples/pipe_buf_rop/exploit.cpp"],
        headers=[],
        functions=["trigger_rop"],
        description="Trigger ROP chain execution",
    ),
    
    # === Privilege escalation ===
    "direct_cred_overwrite": LibraryCodeMapping(
        action="direct_cred_overwrite",
        library="kernel_PoCs",
        source_files=["badnode_cve-2023-20938_reproduction/src/exploit.c"],
        headers=[],
        functions=["overwrite_cred", "find_task_struct", "patch_cred"],
        description="Directly overwrite task credentials with arbitrary write",
    ),
    "commit_creds_prepare_kernel_cred": LibraryCodeMapping(
        action="commit_creds_prepare_kernel_cred",
        library="kernel-research",
        source_files=["libxdk/payloads/RopChain.cpp", "libxdk/samples/pipe_buf_rop/exploit.cpp"],
        headers=["xdk/payloads/RopChain.h"],
        functions=["COMMIT_INIT_TASK_CREDS", "AddRopAction"],
        description="Call commit_creds(prepare_kernel_cred(0)) via ROP",
    ),
    "overwrite_cred_struct": LibraryCodeMapping(
        action="overwrite_cred_struct",
        library="kernel_PoCs",
        source_files=["badnode_cve-2023-20938_reproduction/src/exploit.c"],
        headers=[],
        functions=["overwrite_cred_struct"],
        description="Overwrite cred struct fields (uid, gid, etc.)",
    ),
    
    # === Vulnerability triggers ===
    "trigger_race_condition": LibraryCodeMapping(
        action="trigger_race_condition",
        library="kernel_PoCs",
        source_files=["badspin_reproduction/src/exploit.c"],
        headers=["pthread.h", "sched.h"],
        functions=["race_thread", "trigger_race"],
        description="Trigger a race condition vulnerability",
    ),
    "trigger_uaf": LibraryCodeMapping(
        action="trigger_uaf",
        library="kernel_PoCs",
        source_files=["badnode_cve-2023-20938_reproduction/src/exploit.c"],
        headers=[],
        functions=["uaf_nodes", "trigger_uaf"],
        description="Trigger use-after-free vulnerability",
    ),
    "trigger_binder_bug": LibraryCodeMapping(
        action="trigger_binder_bug",
        library="kernel_PoCs",
        source_files=[
            "badnode_cve-2023-20938_reproduction/src/binder.c",
            "badnode_cve-2023-20938_reproduction/src/exploit.c",
        ],
        headers=["linux/binder.h"],
        functions=["binder_open", "binder_call"],
        description="Trigger binder-related vulnerability",
    ),
    "trigger_oob_read": LibraryCodeMapping(
        action="trigger_oob_read",
        library="common",
        source_files=[],
        headers=[],
        functions=["trigger_oob_read"],
        description="Trigger out-of-bounds read (CVE-specific)",
    ),
    "trigger_oob_write": LibraryCodeMapping(
        action="trigger_oob_write",
        library="common",
        source_files=[],
        headers=[],
        functions=["trigger_oob_write"],
        description="Trigger out-of-bounds write (CVE-specific)",
    ),
    
    # === SELinux bypass (Android) ===
    "disable_selinux_enforce": LibraryCodeMapping(
        action="disable_selinux_enforce",
        library="kernel_PoCs",
        source_files=["badnode_cve-2023-20938_reproduction/src/exploit.c"],
        headers=[],
        functions=["disable_selinux", "patch_selinux"],
        description="Disable SELinux enforcement via selinux_enforcing write",
    ),
    "patch_selinux_permissive": LibraryCodeMapping(
        action="patch_selinux_permissive",
        library="kernel_PoCs",
        source_files=["badnode_cve-2023-20938_reproduction/src/exploit.c"],
        headers=[],
        functions=["patch_selinux_permissive"],
        description="Patch SELinux to permissive mode",
    ),
    
    # === Mitigation bypasses ===
    "bypass_pan": LibraryCodeMapping(
        action="bypass_pan",
        library="kernel-research",
        source_files=["libxdk/pivot/StackPivot.cpp"],
        headers=[],
        functions=["bypass_pan"],
        description="Bypass PAN (Privileged Access Never) on ARM64",
    ),
    "bypass_pac": LibraryCodeMapping(
        action="bypass_pac",
        library="kernel-research",
        source_files=["libxdk/rip/RipControl.cpp"],
        headers=[],
        functions=["bypass_pac", "forge_pac"],
        description="Bypass PAC (Pointer Authentication) on ARM64",
    ),
    "bypass_mte": LibraryCodeMapping(
        action="bypass_mte",
        library="kernel-research",
        source_files=[],
        headers=[],
        functions=["bypass_mte"],
        description="Bypass MTE (Memory Tagging Extension) on ARM64",
    ),
    "bypass_smep": LibraryCodeMapping(
        action="bypass_smep",
        library="kernel-research",
        source_files=["libxdk/payloads/RopChain.cpp"],
        headers=[],
        functions=["disable_smep"],
        description="Bypass SMEP (Supervisor Mode Execution Prevention)",
    ),
    "bypass_smap": LibraryCodeMapping(
        action="bypass_smap",
        library="kernel-research",
        source_files=["libxdk/payloads/RopChain.cpp"],
        headers=[],
        functions=["disable_smap"],
        description="Bypass SMAP (Supervisor Mode Access Prevention)",
    ),
    
    # === Post-exploitation ===
    "spawn_root_shell": LibraryCodeMapping(
        action="spawn_root_shell",
        library="common",
        source_files=[],
        headers=["unistd.h"],
        functions=["spawn_shell", "execve", "win"],
        description="Spawn a root shell after privilege escalation",
    ),
    "escape_app_sandbox": LibraryCodeMapping(
        action="escape_app_sandbox",
        library="kernel_PoCs",
        source_files=["badnode_cve-2023-20938_reproduction/src/exploit.c"],
        headers=[],
        functions=["escape_sandbox"],
        description="Escape Android app sandbox",
    ),
    "enable_adb_root": LibraryCodeMapping(
        action="enable_adb_root",
        library="common",
        source_files=[],
        headers=[],
        functions=["enable_adb_root"],
        description="Enable ADB root access",
    ),
}


@dataclass
class StitcherConfig:
    """Configuration for LLM-powered stitcher."""
    platform: str = "linux"  # "linux" or "android"
    arch: str = "x86_64"  # "x86_64" or "arm64"
    include_debug: bool = True
    output_dir: Optional[str] = None
    kernel_research_path: Optional[str] = None
    kernel_pocs_path: Optional[str] = None
    llm_model: str = "gpt-5"  # Model for LLM stitching
    verify_compilation: bool = True
    max_llm_retries: int = 3


class LLMExploitStitcher:
    """
    LLM-powered exploit stitcher that:
    1. Maps PDDL actions to actual library code from kernel-research/kernel_PoCs
    2. Uses LLM (via shared utils) to intelligently combine code patterns
    3. Verifies compilation (via shared utils)
    """
    
    def __init__(self, config: Optional[StitcherConfig] = None):
        self.config = config or StitcherConfig()
        self._resolve_library_paths()
        
    def _resolve_library_paths(self) -> None:
        """Resolve paths to library directories."""
        try:
            # Module is at: syzploit/Synthesizer/stitcher/llm_stitcher.py
            src_root = Path(__file__).resolve().parents[4]  # -> src
            
            if not self.config.kernel_research_path:
                kr_path = src_root / 'kernel-research'
                if kr_path.exists():
                    self.config.kernel_research_path = str(kr_path)
                    
            if not self.config.kernel_pocs_path:
                # kernel_PoCs is outside src, at workspace level
                pocs_path = src_root.parent.parent.parent / 'kernel_PoCs'
                if pocs_path.exists():
                    self.config.kernel_pocs_path = str(pocs_path)
        except Exception:
            pass
    
    def _read_library_code(self, mapping: LibraryCodeMapping) -> str:
        """Read source code from library files."""
        code_parts = []
        
        base_path = None
        if mapping.library == "kernel-research" and self.config.kernel_research_path:
            base_path = Path(self.config.kernel_research_path)
        elif mapping.library == "kernel_PoCs" and self.config.kernel_pocs_path:
            base_path = Path(self.config.kernel_pocs_path)
        
        if not base_path:
            return f"// Library {mapping.library} not found\n// Functions to implement: {', '.join(mapping.functions)}\n"
        
        for src_file in mapping.source_files:
            full_path = base_path / src_file
            if full_path.exists():
                try:
                    content = full_path.read_text()
                    # Truncate very long files
                    if len(content) > 15000:
                        content = content[:15000] + "\n// ... (truncated for context) ..."
                    code_parts.append(f"// === From {src_file} ===\n{content}")
                except Exception as e:
                    code_parts.append(f"// Error reading {src_file}: {e}\n")
            else:
                code_parts.append(f"// File not found: {src_file}\n")
        
        return "\n\n".join(code_parts) if code_parts else f"// No source files for {mapping.action}\n"
    
    def _collect_library_code(self, plan_actions: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Collect all relevant library code for the plan actions."""
        collected = {}
        
        for action in plan_actions:
            action_name = action.get('action', '').lower().replace('-', '_').strip('()')
            
            if action_name in ACTION_TO_LIBRARY:
                mapping = ACTION_TO_LIBRARY[action_name]
                if action_name not in collected:
                    code = self._read_library_code(mapping)
                    collected[action_name] = {
                        'code': code,
                        'mapping': mapping,
                    }
        
        return collected
    

    def _build_llm_prompt(self, plan_actions: List[Dict[str, Any]], 
                          collected_code: Dict[str, Dict[str, Any]],
                          bug_id: str,
                          analysis_data: Optional[Dict[str, Any]] = None) -> str:
            """Build prompt for LLM to generate a research-oriented reproducer harness."""

            # Build action list (rename semantics)
            action_list = "\n".join([
                f"  {i+1}. {a.get('action', 'unknown')}  // research execution step"
                for i, a in enumerate(plan_actions)
            ])

            # Build library code context
            code_context = []
            for action_name, data in collected_code.items():
                mapping = data['mapping']
                code = data['code']
                code_context.append(f"""
    === {action_name.upper()} (REFERENCE PATTERN) ===
    Purpose: {mapping.description}
    Library / Source: {mapping.library}
    Relevant functions: {', '.join(mapping.functions)}
    Required headers: {', '.join(mapping.headers) if mapping.headers else 'None'}

    Reference implementation (for adaptation, not exploitation):
    {code}
    """)

            code_context_str = "\n".join(code_context)

            # Extract syzbot reproducer code
            reproducer_context = ""
            if analysis_data:
                reproducer = analysis_data.get('reproducer', {})
                reproducer_source = reproducer.get('source') or reproducer.get('c_source', '')
                if reproducer_source:
                    reproducer_context = f"""
    === SYZBOT REPRODUCER (CORE TRIGGER LOGIC) ===
    This code triggers the vulnerability and MUST be integrated directly.
    It defines the triggering behavior and is NOT optional.

    ```c
    {reproducer_source}
    ```
    """

            # Analysis context (purely descriptive)
            analysis_context = ""
            if analysis_data:
                vuln_type = analysis_data.get('parsed', {}).get(
                    'vulnerability_type',
                    analysis_data.get('vulnerability_type', 'unknown')
                )
                subsystem = analysis_data.get('parsed', {}).get(
                    'subsystem',
                    analysis_data.get('subsystem', 'unknown')
                )
                analysis_context = f"""
    Vulnerability Context:

    Bug ID: {bug_id}

    Type: {vuln_type}

    Subsystem: {subsystem}
    """

            platform_info = f"Target platform: {self.config.platform} / {self.config.arch}"

            prompt = f"""You are an expert kernel security researcher.

    Generate a SINGLE, COMPLETE, compilable C program whose purpose is to
    chain together a known crash with other capabilities to generate an end-to-end PoC for a CTF challenge.

    {platform_info}
    {analysis_context}
    {reproducer_context}

    EXECUTION PLAN (follow in order):
    {action_list}

    REFERENCE CODE PATTERNS:
    {code_context_str}

    REQUIREMENTS:
    1. Output ONE complete C source file
    2. Integrate the syzbot reproducer directly as the trigger logic
    3. Add:
        - Clear function structure
        - Thread coordination if needed
        - Timing controls (sleep, barriers)
        - Extensive logging (printf)
    4. Include all necessary headers
    5. The code must compile with gcc/clang for {self.config.platform} ({self.config.arch})
    6. This code should trigger the entire chain for the CTF challenge.
    7. All of the functions must contain the full code and not be stubs.

    Output ONLY the C source code.
    """

            return prompt

#     def _build_llm_prompt(self, plan_actions: List[Dict[str, Any]], 
#                           collected_code: Dict[str, Dict[str, Any]],
#                           bug_id: str,
#                           analysis_data: Optional[Dict[str, Any]] = None) -> str:
#         """Build prompt for LLM to stitch code together."""
        
#         # Build action list
#         action_list = "\n".join([
#             f"  {i+1}. {a.get('action', 'unknown')}"
#             for i, a in enumerate(plan_actions)
#         ])
        
#         # Build library code context
#         code_context = []
#         for action_name, data in collected_code.items():
#             mapping = data['mapping']
#             code = data['code']
#             code_context.append(f"""
# === {action_name.upper()} ===
# Description: {mapping.description}
# Library: {mapping.library}
# Key functions: {', '.join(mapping.functions)}
# Required headers: {', '.join(mapping.headers) if mapping.headers else 'None'}

# Reference code:
# {code}
# """)
        
#         code_context_str = "\n".join(code_context)
        
#         # Extract syzbot reproducer code if available
#         reproducer_context = ""
#         if analysis_data:
#             reproducer = analysis_data.get('reproducer', {})
#             reproducer_source = reproducer.get('source') or reproducer.get('c_source', '')
#             if reproducer_source:
#                 reproducer_context = f"""
# === SYZBOT REPRODUCER (CORE TRIGGER CODE) ===
# This is the original syzbot reproducer that triggers the vulnerability.
# The trigger_* actions in the plan below (e.g., trigger_race_condition, trigger_uaf)
# MUST BE IMPLEMENTED USING THIS REPRODUCER CODE.
# The reproducer IS the vulnerability trigger - it is not separate from the trigger action.
# Adapt syscalls and structures as needed but preserve the core trigger logic.

# ```c
# {reproducer_source}
# ```
# """
        
#         # Analysis context
#         analysis_context = ""
#         if analysis_data:
#             vuln_type = analysis_data.get('parsed', {}).get('vulnerability_type', 
#                        analysis_data.get('vulnerability_type', 'unknown'))
#             subsystem = analysis_data.get('parsed', {}).get('subsystem',
#                        analysis_data.get('subsystem', 'unknown'))
#             analysis_context = f"""
# Vulnerability Information:
# - Type: {vuln_type}
# - Subsystem: {subsystem}
# - Bug ID: {bug_id}
# """
        
#         platform_info = f"Target: {self.config.platform} / {self.config.arch}"
        
#         prompt = f"""You are an expert kernel security researcher.

# Generate a SINGLE, COMPLETE, compilable C program that reproduces and instruments
# a kernel vulnerability trigger for research and debugging purposes.

# {platform_info}
# {analysis_context}
# {reproducer_context}

# EXPLOITATION PLAN (execute in order):
# {action_list}

# LIBRARY CODE REFERENCES:
# {code_context_str}

# REQUIREMENTS:
# 1. Generate a SINGLE, COMPLETE C file that implements the exploitation plan
# 2. ADAPT the code patterns from the library references - use the same techniques
# 3. Include all necessary headers
# 4. The code must compile with gcc/clang for {self.config.platform} ({self.config.arch})
# 5. Include proper error handling and state tracking
# 6. Add comments explaining each exploitation step
# 7. For Android targets (arch=arm64), use Android NDK compatible code
# 8. **CRITICAL**: The trigger_* actions (trigger_race_condition, trigger_uaf, etc.) MUST be implemented
#    using the syzbot reproducer code provided above. The reproducer IS the trigger implementation.
#    Do not write separate trigger code - adapt and integrate the reproducer code directly.

# IMPORTANT PATTERNS TO USE FROM REFERENCES:
# - msg_msg spray: Use msgsnd/msgrcv with proper struct layout
# - Arbitrary read/write: Corrupt msg_msg->m_list.next for controlled access
# - KASLR bypass: Leak kernel pointer, calculate base from known symbol offset
# - Credential overwrite: Find current task_struct, patch uid/gid or use commit_creds

# Generate the complete C exploit code now:

# ```c
# """
        
#         return prompt
    
    def _call_llm(self, prompt: str) -> Optional[str]:
        """Call LLM to generate code using llm_chat from SyzAnalyze."""
        
        # Ensure API key is loaded into environment
        if not _ensure_api_key():
            print("[ERROR] OpenAI API key not found. Set OPENAI_API_KEY environment variable or create ~/.config/kernelcveanalysis/openai_api_key", file=sys.stderr)
            return None
        
        try:
            
            # llm_chat from crash_analyzer takes (model, messages)
            response = get_openai_response(prompt, "")
                        
            return response
            
        except Exception as e:
            print(f"[ERROR] LLM call failed: {e}", file=sys.stderr)
            return None
    
    def _verify_compilation(self, code: str) -> Tuple[bool, str]:
        """Verify the generated code compiles."""
        return verify_syntax(code, self.config.platform, self.config.arch)
    
    def _fix_compilation_errors(self, code: str, errors: str) -> Optional[str]:
        """Use LLM to fix compilation errors."""
        
        # Ensure API key is loaded into environment
        if not _ensure_api_key():
            return None
        
        prompt = f"""The following C exploit code has compilation errors. Fix ALL errors and return the complete, corrected code.

COMPILATION ERRORS:
{errors[:2000]}

ORIGINAL CODE:
```c
{code}
```

Fix all errors and return the complete corrected C code:

```c
"""
        
        try:
            
            # llm_chat from crash_analyzer takes (model, messages)
            response = get_openai_response(prompt, "")
            
            return response
            
        except Exception as e:
            print(f"[ERROR] LLM fix failed: {e}", file=sys.stderr)
            return None
    
    def stitch(self, plan_actions: List[Dict[str, Any]], 
               bug_id: str,
               output_path: Optional[str] = None,
               analysis_data: Optional[Dict[str, Any]] = None) -> str:
        """
        Stitch plan actions into a complete C exploit using LLM.
        
        Args:
            plan_actions: List of parsed PDDL actions
            bug_id: Bug identifier
            output_path: Path to write the exploit
            analysis_data: Additional analysis data from syzanalyze
            
        Returns:
            Path to the generated exploit file
        """
        print(f"[*] LLM Stitcher: Processing {len(plan_actions)} actions", file=sys.stderr)
        
        # Collect library code for actions
        collected = self._collect_library_code(plan_actions)
        print(f"[*] Collected code from {len(collected)} library sources", file=sys.stderr)
        
        # Build LLM prompt
        prompt = self._build_llm_prompt(plan_actions, collected, bug_id, analysis_data)
        
        # Generate code with LLM
        print(f"[*] Calling LLM ({self.config.llm_model}) to generate exploit...", file=sys.stderr)
        code = self._call_llm(prompt)
        
        if not code:
            print("[ERROR] LLM failed to generate code, falling back to template stitcher", file=sys.stderr)
            from .stitcher import ExploitStitcher, StitcherConfig as TemplateConfig
            fallback_config = TemplateConfig(
                platform=self.config.platform,
                arch=self.config.arch,
                include_debug=self.config.include_debug,
                output_dir=self.config.output_dir
            )
            fallback_stitcher = ExploitStitcher(fallback_config)
            return fallback_stitcher.stitch(plan_actions, bug_id, output_path, analysis_data)
        
        # Verify compilation with retries
        if self.config.verify_compilation:
            for attempt in range(self.config.max_llm_retries):
                print(f"[*] Verifying compilation (attempt {attempt + 1})...", file=sys.stderr)
                success, errors = self._verify_compilation(code)
                
                if success:
                    print("[+] Compilation verification passed", file=sys.stderr)
                    break
                else:
                    print(f"[!] Compilation errors:\n{errors[:500]}...", file=sys.stderr)
                    if attempt < self.config.max_llm_retries - 1:
                        print("[*] Attempting to fix errors with LLM...", file=sys.stderr)
                        fixed_code = self._fix_compilation_errors(code, errors)
                        if fixed_code:
                            code = fixed_code
                        else:
                            print("[!] LLM failed to fix errors", file=sys.stderr)
            else:
                print("[WARN] Could not verify compilation after retries", file=sys.stderr)
        
        # Write output
        if output_path is None:
            output_dir = self.config.output_dir or '.'
            output_path = os.path.join(output_dir, f"exploit_{bug_id}.c")
        
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(code)
        print(f"[+] Generated exploit: {output_path}", file=sys.stderr)
        
        # Generate Makefile
        self._generate_makefile(output_path)
        
        return output_path
    
    def _generate_makefile(self, exploit_path: str) -> None:
        """Generate a Makefile for the exploit."""
        exploit_name = Path(exploit_path).stem
        output_dir = Path(exploit_path).parent
        makefile_path = output_dir / "Makefile"
        
        if self.config.platform == "android":
            if self.config.arch == "arm64":
                cc = "$(ANDROID_NDK)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang"
            else:
                cc = "$(ANDROID_NDK)/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android30-clang"
            cflags = "-Wall -O2 -static -pthread"
        else:
            if self.config.arch == "arm64":
                cc = "aarch64-linux-gnu-gcc"
            else:
                cc = "gcc"
            cflags = "-Wall -O2 -pthread -static"
        
        makefile_content = f"""# Auto-generated Makefile for {exploit_name}
# Platform: {self.config.platform}
# Architecture: {self.config.arch}
# Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

CC = {cc}
CFLAGS = {cflags}
TARGET = {exploit_name}
SRC = {Path(exploit_path).name}

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
\t$(CC) $(CFLAGS) -o $@ $<

clean:
\trm -f $(TARGET)
"""
        
        makefile_path.write_text(makefile_content)
        print(f"[+] Generated Makefile: {makefile_path}", file=sys.stderr)


def stitch_from_plan(plan_file: str, bug_id: str, 
                     output_path: Optional[str] = None,
                     platform: str = "linux",
                     arch: str = "x86_64",
                     use_llm: bool = True,
                     verify: bool = True) -> str:
    """
    Convenience function to stitch an exploit from a plan file.
    
    Args:
        plan_file: Path to plan file from solver
        bug_id: Bug identifier
        output_path: Output path for exploit
        platform: Target platform
        arch: Target architecture
        use_llm: Whether to use LLM for stitching
        verify: Whether to verify compilation
        
    Returns:
        Path to generated exploit
    """
    from ..powerlifted_integration import PowerliftedSolver
    
    # Parse plan file
    solver = PowerliftedSolver()
    plan_actions = solver.parse_plan(plan_file)
    
    if not plan_actions:
        raise ValueError(f"No actions found in plan file: {plan_file}")
    
    # Configure stitcher
    config = StitcherConfig(
        platform=platform,
        arch=arch,
        verify_compilation=verify,
        output_dir=str(Path(output_path).parent) if output_path else None,
    )
    
    if use_llm:
        stitcher = LLMExploitStitcher(config)
    else:
        from .stitcher import ExploitStitcher, StitcherConfig as TemplateConfig
        template_config = TemplateConfig(
            platform=platform,
            arch=arch,
            output_dir=str(Path(output_path).parent) if output_path else None,
        )
        stitcher = ExploitStitcher(template_config)
    
    return stitcher.stitch(plan_actions, bug_id, output_path)
