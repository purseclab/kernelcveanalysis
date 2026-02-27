"""
syzanalyze_adapter.py

Load primitives from SyzAnalyze static and dynamic analysis outputs.
Extracts vulnerability classification, capabilities, and exploit potential
from static_analysis.json and dynamic_analysis.json files.
"""

import json
import os
import sys
from typing import Dict, Any, List, Optional
from ..core import Primitive, PrimitiveRegistry
from ...utils.debug import debug_print


def syz_debug(msg: str, enabled: bool = True):
    """Print debug message if enabled."""
    debug_print("SyzAnalyzeAdapter", msg, enabled)


# Mapping of vulnerability types to PDDL capabilities
VULN_TO_CAPS = {
    # Use-after-free variants
    'use-after-free': ['CAP_uaf_read', 'CAP_uaf_write', 'CAP_arb_read', 'CAP_arb_write'],
    'uaf': ['CAP_uaf_read', 'CAP_uaf_write', 'CAP_arb_read', 'CAP_arb_write'],
    'double-free': ['CAP_uaf_write', 'CAP_arb_write'],
    'double free': ['CAP_uaf_write', 'CAP_arb_write'],
    
    # Buffer overflows
    'buffer-overflow': ['CAP_arb_write', 'CAP_stack_overflow'],
    'buffer overflow': ['CAP_arb_write', 'CAP_stack_overflow'],
    'stack-overflow': ['CAP_stack_overflow', 'CAP_rip_control'],
    'stack overflow': ['CAP_stack_overflow', 'CAP_rip_control'],
    'heap-overflow': ['CAP_arb_write', 'CAP_heap_overflow'],
    'heap overflow': ['CAP_arb_write', 'CAP_heap_overflow'],
    'out-of-bounds': ['CAP_oob_read', 'CAP_oob_write'],
    'out of bounds': ['CAP_oob_read', 'CAP_oob_write'],
    'oob': ['CAP_oob_read', 'CAP_oob_write'],
    
    # Type confusion
    'type-confusion': ['CAP_type_confusion', 'CAP_arb_read', 'CAP_arb_write'],
    'type confusion': ['CAP_type_confusion', 'CAP_arb_read', 'CAP_arb_write'],
    
    # Integer issues
    'integer-overflow': ['CAP_int_overflow'],
    'integer overflow': ['CAP_int_overflow'],
    'integer-underflow': ['CAP_int_overflow'],
    
    # Info leaks
    'info-leak': ['CAP_info_leak', 'CAP_arb_read'],
    'information leak': ['CAP_info_leak', 'CAP_arb_read'],
    'uninitialized': ['CAP_info_leak'],
    
    # Race conditions
    'race': ['CAP_race_condition'],
    'race-condition': ['CAP_race_condition'],
    'toctou': ['CAP_race_condition'],
    
    # Null pointer
    'null-pointer': ['CAP_null_deref'],
    'null pointer': ['CAP_null_deref'],
    'nullptr': ['CAP_null_deref'],
    
    # Command injection (for CVE capabilities)
    'command-injection': ['CAP_cve_shell_command_injection'],
    'shell-injection': ['CAP_cve_shell_command_injection'],
}

# Access operation to capability mapping
ACCESS_TO_CAPS = {
    'read': ['CAP_arb_read'],
    'write': ['CAP_arb_write'],
    'execute': ['CAP_code_exec'],
}


def extract_caps_from_vuln(vuln_str: str) -> List[str]:
    """Extract capabilities from vulnerability type string."""
    caps = []
    vuln_lower = (vuln_str or '').lower()
    
    for key, cap_list in VULN_TO_CAPS.items():
        if key in vuln_lower:
            caps.extend(cap_list)
    
    return list(set(caps))


def extract_caps_from_access(access: Dict[str, Any]) -> List[str]:
    """Extract capabilities from access operation info."""
    caps = []
    op = (access.get('op') or '').lower()
    
    if op in ACCESS_TO_CAPS:
        caps.extend(ACCESS_TO_CAPS[op])
    
    # Large access sizes may indicate more powerful primitives
    size = access.get('size', 0)
    if size >= 8:
        caps.append('CAP_64bit_access')
    
    return list(set(caps))


def extract_caps_from_llm(llm_analysis: Dict[str, Any]) -> List[str]:
    """Extract capabilities from LLM analysis results."""
    caps = []
    
    # Check openai_llm parsed results
    openai = llm_analysis.get('openai_llm', {})
    if isinstance(openai, dict):
        parsed = openai.get('parsed', {})
        if isinstance(parsed, dict):
            # Get overview
            overview = parsed.get('overview', {})
            if isinstance(overview, dict):
                # High exploitability = more caps
                exploit_rating = (overview.get('exploitability') or '').upper()
                if exploit_rating == 'HIGH':
                    caps.extend(['CAP_privilege_escalation', 'CAP_rip_control'])
                elif exploit_rating == 'MEDIUM':
                    caps.append('CAP_privilege_escalation')
                
                # Parse primitive_capabilities text
                prim_caps = overview.get('primitive_capabilities', '')
                if isinstance(prim_caps, str):
                    prim_lower = prim_caps.lower()
                    if 'memory corruption' in prim_lower:
                        caps.extend(['CAP_arb_write', 'CAP_memory_corruption'])
                    if 'double-free' in prim_lower or 'double free' in prim_lower:
                        caps.append('CAP_double_free')
                    if 'info' in prim_lower and 'leak' in prim_lower:
                        caps.append('CAP_info_leak')
                    if 'arbitrary' in prim_lower and 'read' in prim_lower:
                        caps.append('CAP_arb_read')
                    if 'arbitrary' in prim_lower and 'write' in prim_lower:
                        caps.append('CAP_arb_write')
                    if 'rip' in prim_lower or 'control flow' in prim_lower:
                        caps.append('CAP_rip_control')
            
            # Check postconditions for more capabilities
            postconds = parsed.get('postconditions', [])
            if isinstance(postconds, list):
                for pc in postconds:
                    if isinstance(pc, dict):
                        controllability = pc.get('controlability', []) or pc.get('controllability', [])
                        if isinstance(controllability, list):
                            for ctrl in controllability:
                                ctrl_lower = (ctrl or '').lower()
                                if 'timing' in ctrl_lower:
                                    caps.append('CAP_timing_control')
                                if 'syscall' in ctrl_lower:
                                    caps.append('CAP_syscall_control')
    
    return list(set(caps))


def extract_caps_from_object(obj_info: Dict[str, Any]) -> List[str]:
    """Extract capabilities from object/slab info."""
    caps = []
    
    cache = (obj_info.get('cache') or '').lower()
    obj_size = obj_info.get('obj_size', 0)
    
    # Certain caches are more valuable for exploitation
    valuable_caches = {
        'filp': ['CAP_file_struct_control'],
        'cred_jar': ['CAP_cred_control', 'CAP_privilege_escalation'],
        'task_struct': ['CAP_task_control'],
        'inode_cache': ['CAP_inode_control'],
        'kmalloc': ['CAP_heap_control'],
        'pipe_buf': ['CAP_pipe_control'],
        'msg_msg': ['CAP_msg_control'],
        'sk_buff': ['CAP_skb_control'],
    }
    
    for key, cap_list in valuable_caches.items():
        if key in cache:
            caps.extend(cap_list)
    
    # Size-based capabilities
    if obj_size > 0:
        if obj_size <= 64:
            caps.append('CAP_small_object')
        elif obj_size <= 256:
            caps.append('CAP_medium_object')
        else:
            caps.append('CAP_large_object')
    
    return list(set(caps))


def load_from_analysis(analysis_dir: str, registry: PrimitiveRegistry, 
                       debug: bool = False) -> List[Primitive]:
    """
    Load primitives inferred by SyzAnalyze from analysis outputs.
    
    Parses static_analysis.json and dynamic_analysis.json to extract:
    - Vulnerability classification (UAF, overflow, etc.)
    - Access capabilities (read/write sizes)
    - LLM-derived exploitability and primitive capabilities
    - Object/slab information
    
    Args:
        analysis_dir: Directory containing analysis JSON files
        registry: PrimitiveRegistry to add primitives to
        debug: Enable debug output
        
    Returns:
        List of Primitive objects extracted
    """
    prims: List[Primitive] = []
    static_path = os.path.join(analysis_dir, 'static_analysis.json')
    dynamic_path = os.path.join(analysis_dir, 'dynamic_analysis.json')
    
    syz_debug(f"Loading from analysis_dir: {analysis_dir}", debug)
    
    for path in (static_path, dynamic_path):
        if not os.path.exists(path):
            syz_debug(f"  File not found: {path}", debug)
            continue
            
        syz_debug(f"  Processing: {path}", debug)
        
        try:
            with open(path, 'r') as f:
                data = json.load(f)
        except Exception as e:
            syz_debug(f"  Error loading JSON: {e}", debug)
            continue
        
        all_caps: List[str] = []
        prim_name = None
        prim_desc = None
        
        # Extract from parsed section
        parsed = data.get('parsed', {})
        if isinstance(parsed, dict):
            # Get vulnerability kind
            kind = parsed.get('kind', '')
            if kind:
                caps = extract_caps_from_vuln(kind)
                all_caps.extend(caps)
                syz_debug(f"    from kind '{kind}': {caps}", debug)
            
            # Get access info
            access = parsed.get('access', {})
            if isinstance(access, dict):
                caps = extract_caps_from_access(access)
                all_caps.extend(caps)
                syz_debug(f"    from access: {caps}", debug)
            
            # Get object info
            obj_info = parsed.get('object_info', {})
            if isinstance(obj_info, dict):
                caps = extract_caps_from_object(obj_info)
                all_caps.extend(caps)
                syz_debug(f"    from object_info: {caps}", debug)
        
        # Extract from classification section
        classification = data.get('classification', {})
        if isinstance(classification, dict):
            vuln = classification.get('vulnerability', '')
            primitive = classification.get('primitive', '')
            
            if vuln:
                caps = extract_caps_from_vuln(vuln)
                all_caps.extend(caps)
                prim_name = primitive or vuln.split()[0].lower().replace('-', '_')
                prim_desc = vuln
                syz_debug(f"    from classification vuln '{vuln}': {caps}", debug)
            
            # Exploitability rating
            exploit_rating = (classification.get('exploitability') or '').lower()
            if exploit_rating == 'high':
                all_caps.append('CAP_privilege_escalation')
            
            # Overview section
            overview = classification.get('overview', {})
            if isinstance(overview, dict):
                prim_caps_text = overview.get('primitive_capabilities', '')
                if prim_caps_text:
                    prim_desc = prim_caps_text
        
        # Extract from exploitability section
        exploitability = data.get('exploitability', {})
        if isinstance(exploitability, dict):
            obj_info = exploitability.get('object', {})
            if isinstance(obj_info, dict):
                caps = extract_caps_from_object(obj_info)
                all_caps.extend(caps)
                syz_debug(f"    from exploitability object: {caps}", debug)
        
        # Extract from LLM analysis
        llm_analysis = data.get('llm_analysis', {})
        if isinstance(llm_analysis, dict):
            caps = extract_caps_from_llm(llm_analysis)
            all_caps.extend(caps)
            syz_debug(f"    from llm_analysis: {caps}", debug)
        
        # === CVE-specific field extraction ===
        # Extract from vuln_type (top-level field from CVE analyzer)
        vuln_type = data.get('vuln_type', '')
        if vuln_type:
            caps = extract_caps_from_vuln(vuln_type)
            all_caps.extend(caps)
            if not prim_name:
                prim_name = vuln_type.replace('_', '-')
            syz_debug(f"    from vuln_type '{vuln_type}': {caps}", debug)
        
        # Extract from target_struct
        target_struct = data.get('target_struct', '')
        if target_struct:
            prim_desc = f"Affects {target_struct}"
            syz_debug(f"    target_struct: {target_struct}", debug)
        
        # Extract from slab_cache
        slab_cache = data.get('slab_cache', '')
        if slab_cache:
            all_caps.append('CAP_slab_target')
            syz_debug(f"    slab_cache: {slab_cache}", debug)
        
        # Extract from exploitation_hints (CVE analyzer output)
        exploitation_hints = data.get('exploitation_hints', {})
        if isinstance(exploitation_hints, dict):
            technique = exploitation_hints.get('technique', '')
            if technique:
                technique_lower = technique.lower()
                if 'cross-cache' in technique_lower or 'cross_cache' in technique_lower:
                    all_caps.append('CAP_cross_cache')
                if 'msg_msg' in technique_lower:
                    all_caps.append('CAP_msg_msg_spray')
                if 'pipe' in technique_lower:
                    all_caps.append('CAP_pipe_spray')
                if 'dirty' in technique_lower and 'page' in technique_lower:
                    all_caps.append('CAP_dirty_pagetable')
                if 'physmap' in technique_lower:
                    all_caps.append('CAP_physmap')
                syz_debug(f"    from technique '{technique}'", debug)
            
            difficulty = exploitation_hints.get('difficulty', '')
            if difficulty:
                syz_debug(f"    difficulty: {difficulty}", debug)
            
            key_functions = exploitation_hints.get('key_functions', [])
            if key_functions:
                syz_debug(f"    key_functions: {key_functions}", debug)
        
        # Extract from code_analysis (CVE analyzer output)
        code_analysis = data.get('code_analysis', {})
        if isinstance(code_analysis, dict):
            trigger_syscalls = code_analysis.get('trigger_syscalls', [])
            if trigger_syscalls:
                syz_debug(f"    trigger_syscalls: {trigger_syscalls}", debug)
            
            spray_objects = code_analysis.get('spray_objects', [])
            for obj in spray_objects:
                obj_lower = (obj or '').lower()
                if 'msg_msg' in obj_lower:
                    all_caps.append('CAP_msg_msg_spray')
                elif 'pipe' in obj_lower:
                    all_caps.append('CAP_pipe_spray')
                elif 'seq' in obj_lower:
                    all_caps.append('CAP_seq_ops_spray')
            if spray_objects:
                syz_debug(f"    spray_objects: {spray_objects}", debug)
            
            # Check useful_structs for size/cache info
            useful_structs = code_analysis.get('useful_structs', [])
            for struct in useful_structs:
                if isinstance(struct, dict):
                    sname = struct.get('name', '')
                    ssize = struct.get('size', '')
                    scache = struct.get('cache', '')
                    syz_debug(f"    useful_struct: {sname} (size={ssize}, cache={scache})", debug)
        
        # Extract from openai_llm.parsed (alternative nesting for LLM output)
        openai_llm = data.get('openai_llm', {})
        if isinstance(openai_llm, dict):
            parsed_llm = openai_llm.get('parsed', {})
            if isinstance(parsed_llm, dict):
                overview = parsed_llm.get('overview', {})
                if isinstance(overview, dict):
                    bug_type = overview.get('bug_type', '')
                    if bug_type:
                        caps = extract_caps_from_vuln(bug_type)
                        all_caps.extend(caps)
                        syz_debug(f"    from openai_llm bug_type '{bug_type}': {caps}", debug)
                    
                    exploitability = overview.get('exploitability', '')
                    if exploitability and exploitability.upper() == 'HIGH':
                        all_caps.append('CAP_privilege_escalation')
                        syz_debug(f"    exploitability: {exploitability}", debug)
                    
                    prim_caps = overview.get('primitive_capabilities', '')
                    if prim_caps:
                        prim_desc = prim_caps
                        syz_debug(f"    primitive_capabilities: {prim_caps}", debug)
        
        # Deduplicate capabilities
        all_caps = list(set(all_caps))
        
        if all_caps:
            # Generate primitive name from file
            source = 'static' if 'static' in path else 'dynamic'
            name = prim_name or f"syz_{source}_primitive"
            desc = prim_desc or f"Primitive from SyzAnalyze {source} analysis"
            
            prim = Primitive(
                name=name,
                description=desc,
                requirements={},
                provides={
                    "caps": all_caps,
                    "source": source,
                    "analysis_path": path
                }
            )
            registry.add(prim)
            prims.append(prim)
            syz_debug(f"    Created primitive '{name}' with {len(all_caps)} capabilities", debug)
    
    # Also load trace analysis if available
    trace = load_trace_analysis(analysis_dir, registry, debug)
    if trace:
        syz_debug(f"  Trace analysis loaded (verdict: "
                  f"{trace.get('path_verification', {}).get('verdict', '?')})",
                  debug)

    syz_debug(f"  Total primitives loaded: {len(prims)}", debug)
    return prims


def _find_trace_analysis(analysis_dir: str) -> Optional[str]:
    """Locate trace_analysis.json on disk (may be in a log sub-directory)."""
    direct = os.path.join(analysis_dir, "trace_analysis.json")
    if os.path.exists(direct):
        return direct
    # Check sub-directories (controller log dirs)
    try:
        for d in sorted(os.listdir(analysis_dir)):
            dp = os.path.join(analysis_dir, d)
            if os.path.isdir(dp):
                candidate = os.path.join(dp, "trace_analysis.json")
                if os.path.exists(candidate):
                    return candidate
    except OSError:
        pass
    return None


def load_trace_analysis(analysis_dir: str,
                        registry: PrimitiveRegistry,
                        debug: bool = False) -> Optional[Dict[str, Any]]:
    """Load trace_analysis.json and register a runtime-evidence primitive.

    The trace analysis contains:
      - runtime kernel addresses for crash-stack / alloc / free functions
      - path-verification verdict and confidence
      - event statistics from GDB tracing
      - device profile (kernel version, arch, android version)

    This information enriches the PDDL planner's world-state so it can
    account for device-specific constraints (e.g., no KASAN, ARM64 offsets).

    Returns the raw trace dict or *None* if unavailable.
    """
    trace_path = _find_trace_analysis(analysis_dir)
    if trace_path is None:
        syz_debug("  No trace_analysis.json found", debug)
        return None

    syz_debug(f"  Loading trace analysis: {trace_path}", debug)
    try:
        with open(trace_path, "r") as f:
            trace = json.load(f)
    except Exception as e:
        syz_debug(f"  Error loading trace analysis: {e}", debug)
        return None

    pv = trace.get("path_verification", {})
    verdict = pv.get("verdict", "UNKNOWN")
    confidence = pv.get("confidence", 0.0)
    confirmed = pv.get("vulnerable_path_confirmed", False)

    caps: List[str] = []

    # High-confidence runtime verification → strong capability
    if confidence >= 0.6 or confirmed:
        caps.append("CAP_runtime_verified")
    if confidence >= 0.4:
        caps.append("CAP_partially_verified")

    # Address knowledge enables offset-based exploitation
    rt = trace.get("runtime_addresses", {})
    if rt.get("crash_stack"):
        caps.append("CAP_known_crash_addrs")
    if rt.get("alloc_functions"):
        caps.append("CAP_known_alloc_addrs")
    if rt.get("free_functions"):
        caps.append("CAP_known_free_addrs")

    # No KASAN → silent UAF, different exploitation strategy
    crash_detected = trace.get("crash_detected", False)
    no_crash = pv.get("no_crash_explanation", [])
    if not crash_detected and no_crash:
        caps.append("CAP_silent_uaf")

    if caps:
        prim = Primitive(
            name="runtime_trace_evidence",
            description=(f"Runtime trace verification: {verdict} "
                         f"({confidence:.0%} confidence). "
                         f"{len(rt.get('crash_stack', {}))} crash addresses, "
                         f"{trace.get('event_summary', {}).get('total', 0)} "
                         f"GDB events captured."),
            requirements={},
            provides={
                "caps": caps,
                "source": "trace_analysis",
                "analysis_path": trace_path,
                "verdict": verdict,
                "confidence": confidence,
                "kernel_version": trace.get("kernel_version"),
                "arch": trace.get("arch"),
                "runtime_addresses": rt,
            },
        )
        registry.add(prim)
        syz_debug(f"    Created runtime_trace_evidence primitive with "
                  f"{len(caps)} caps: {caps}", debug)

    return trace
