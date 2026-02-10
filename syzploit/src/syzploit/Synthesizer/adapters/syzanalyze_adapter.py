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


def syzsyz_debug(msg: str, enabled: bool = True):
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
    
    syz_debug(f"  Total primitives loaded: {len(prims)}", debug)
    return prims
