"""
llm_planner.py

LLM-based exploit plan generator that analyzes vulnerability context
and generates appropriate exploitation plans without relying solely on
PDDL planning.

This provides more flexibility for complex vulnerability types where
the exploitation strategy depends heavily on the specific vulnerability
mechanics.

NOTE: Patterns are now loaded from JSON files in the patterns/ directory.
See exploit_generator.py for the new pattern-based generation system.
"""

import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

from ..utils.env import get_api_key
from ..SyzAnalyze.crash_analyzer import get_openai_response


def load_patterns_from_json() -> Dict[str, Any]:
    """Load exploitation patterns from JSON files in patterns directory."""
    patterns = {}
    patterns_dir = Path(__file__).parent / "patterns"
    
    if not patterns_dir.exists():
        print(f"[LLMPlanner] Warning: patterns directory not found: {patterns_dir}", file=sys.stderr)
        return patterns
    
    for json_file in patterns_dir.glob("*.json"):
        try:
            with open(json_file) as f:
                data = json.load(f)
            name = data.get("name", json_file.stem)
            # Convert to old format for backward compatibility
            patterns[name] = {
                "description": data.get("description", ""),
                "target_struct": data.get("target_struct", ""),
                "slab_cache": data.get("slab_cache", ""),
                "technique": data.get("technique", ""),
                "steps": [s["name"] for s in data.get("steps", [])],
                "code_hints": extract_code_hints(data),
                "detection_rules": data.get("detection_rules", {}),
            }
        except Exception as e:
            print(f"[LLMPlanner] Error loading {json_file}: {e}", file=sys.stderr)
    
    return patterns


def extract_code_hints(pattern_data: Dict[str, Any]) -> Dict[str, str]:
    """Extract code hints from pattern data (if embedded in steps)."""
    hints = {}
    for step in pattern_data.get("steps", []):
        if isinstance(step, dict) and step.get("code_hint"):
            hints[step["name"]] = step["code_hint"]
    return hints


@dataclass
class ExploitPlan:
    """Represents an exploitation plan."""
    steps: List[str]
    vulnerability_type: str
    target_struct: str
    exploitation_technique: str
    description: str
    code_hints: Dict[str, str]  # step_name -> implementation hints


# Load patterns from JSON files (with fallback to hardcoded)
_LOADED_PATTERNS = load_patterns_from_json()

# Known exploitation patterns for different vulnerability types
# These are fallbacks if JSON patterns are not found
EXPLOITATION_PATTERNS = {
    "uaf_generic": {
        "description": "Generic UAF exploitation via heap spray and object reclaim",
        "target_struct": "unknown",
        "slab_cache": "kmalloc-*",
        "technique": "heap_spray_reclaim",
        "steps": [
            "trigger_uaf",
            "spray_objects",
            "reclaim_freed_object",
            "corrupt_data",
            "leak_kernel_address",
            "get_arb_read_write",
            "escalate_privileges",
        ],
        "code_hints": {},
    },
    "msg_msg_uaf": {
        "description": "Generic UAF exploited via msg_msg spray",
        "target_struct": "msg_msg",
        "slab_cache": "kmalloc-*",
        "technique": "msg_msg_list_corruption",
        "steps": [
            "trigger_uaf",
            "spray_msg_msg",
            "corrupt_msg_next_ptr",
            "leak_via_msg_copy",
            "bypass_kaslr",
            "derive_arb_write",
            "overwrite_modprobe_path",
        ],
        "code_hints": {},
    },
    "pipe_buffer_uaf": {
        "description": "UAF exploited via pipe_buffer spray",
        "target_struct": "pipe_buffer",
        "slab_cache": "kmalloc-1k",
        "technique": "pipe_buffer_ops_hijack",
        "steps": [
            "trigger_uaf",
            "spray_pipe_buffers",
            "corrupt_pipe_ops",
            "trigger_release_for_rip_control",
            "stack_pivot",
            "rop_to_commit_creds",
        ],
        "code_hints": {},
    },
}


def detect_vulnerability_pattern(analysis_data: Dict[str, Any]) -> str:
    """
    Analyze crash data to determine the exploitation pattern.
    
    Returns the pattern key from EXPLOITATION_PATTERNS.
    Uses both loaded JSON patterns and hardcoded fallbacks.
    """
    # Merge loaded patterns with hardcoded fallbacks
    all_patterns = {**EXPLOITATION_PATTERNS, **_LOADED_PATTERNS}
    
    raw_crash = ""
    if "parsed" in analysis_data:
        raw_crash = json.dumps(analysis_data["parsed"]).lower()
    
    reproducer = analysis_data.get("reproducer", {})
    repro_source = reproducer.get("source", "").lower()
    
    # Score each pattern based on detection rules
    best_pattern = "uaf_generic"
    best_score = 0
    
    for pattern_name, pattern_info in all_patterns.items():
        score = 0
        rules = pattern_info.get("detection_rules", {})
        
        # Check crash_contains rules
        for keyword in rules.get("crash_contains", []):
            if keyword.lower() in raw_crash:
                score += 10
        
        # Check reproducer_contains rules
        for keyword in rules.get("reproducer_contains", []):
            if keyword.lower() in repro_source:
                score += 15
        
        # Check slab_cache
        if rules.get("slab_cache"):
            obj_info = analysis_data.get("parsed", {}).get("object_info", {})
            cache = obj_info.get("cache", "")
            if rules["slab_cache"].lower() in cache.lower():
                score += 20
        
        # Check stack_funcs
        crash_stack = analysis_data.get("parsed", {}).get("frames", [])
        stack_funcs = [f.get("func", "") for f in crash_stack if isinstance(f, dict)]
        for func_pattern in rules.get("stack_funcs", []):
            if any(func_pattern.lower() in f.lower() for f in stack_funcs):
                score += 5
        
        if score > best_score:
            best_score = score
            best_pattern = pattern_name
    
    # Fallback heuristics if no rules matched
    if best_score == 0:
        # Default to generic UAF pattern
        best_pattern = "uaf_generic"
    
    print(f"[LLMPlanner] Detected pattern: {best_pattern} (score={best_score})", file=sys.stderr)
    return best_pattern


def generate_plan_with_llm(
    analysis_data: Dict[str, Any],
    pattern: str,
    target_arch: str = "arm64",
) -> ExploitPlan:
    """
    Use LLM to refine or generate an exploitation plan based on vulnerability analysis.
    """
    # Check loaded patterns first, then fallback to hardcoded
    all_patterns = {**EXPLOITATION_PATTERNS, **_LOADED_PATTERNS}
    pattern_info = all_patterns.get(pattern, all_patterns.get("uaf_generic", {}))
    
    # Ensure pattern_info has required fields
    if not pattern_info:
        pattern_info = EXPLOITATION_PATTERNS.get("uaf_generic", {})
    if not pattern_info.get("description"):
        pattern_info["description"] = "Kernel memory corruption exploitation"
    if not pattern_info.get("target_struct"):
        pattern_info["target_struct"] = "unknown"
    if not pattern_info.get("technique"):
        pattern_info["technique"] = "generic"
    if not pattern_info.get("steps"):
        pattern_info["steps"] = ["trigger_vuln", "reclaim_object", "leak_address", "escalate_privileges"]
    
    # Build context for LLM - extract rich information from static analysis
    parsed = analysis_data.get("parsed", {}) or {}
    reproducer = analysis_data.get("reproducer", {}) or {}
    classification = analysis_data.get("classification", {}) or {}
    llm_analysis = analysis_data.get("llm_analysis", {}) or {}
    exploitability_info = analysis_data.get("exploitability", {}) or {}
    
    # Extract detailed info
    vuln_kind = parsed.get("kind", "unknown")
    access = parsed.get("access", {}) or {}
    object_info = parsed.get("object_info", {}) or {}
    allocated_by = parsed.get("allocated_by", []) or []
    freed_by = parsed.get("freed_by", []) or []
    frames = parsed.get("frames", []) or []
    
    # Extract LLM analysis if available
    openai_llm = llm_analysis.get("openai_llm", {}) or {}
    llm_parsed = openai_llm.get("parsed", {}) or {}
    overview = llm_parsed.get("overview", {})
    preconditions = llm_parsed.get("preconditions", [])
    postconditions = llm_parsed.get("postconditions", [])
    
    # Extract key functions from stack
    key_funcs = []
    for frame in frames[:15]:
        func = frame.get("func", "")
        if func and "kasan" not in func.lower() and "dump" not in func.lower():
            key_funcs.append(f"{func} @ {frame.get('file', '?')}:{frame.get('line', '?')}")
    
    # Build preconditions text
    precond_text = ""
    for pc in preconditions:
        precond_text += f"- {pc.get('summary', '')}\n"
        for constraint in pc.get('concrete_constraints', [])[:3]:
            precond_text += f"  * {constraint}\n"
    
    # Build controllability text
    control_text = ""
    for pc in postconditions:
        for ctrl in pc.get('controlability', []):
            control_text += f"- {ctrl}\n"
    
    prompt = f"""You are an expert kernel exploit developer creating an exploitation plan.

## Vulnerability Summary
- Type: {vuln_kind}
- Exploitability: {overview.get('exploitability', classification.get('exploitability', 'MEDIUM'))}
- Capabilities: {overview.get('primitive_capabilities', 'UAF read/write on freed memory')}

## Object Details
- Slab Cache: {object_info.get('cache', 'unknown')}
- Object Size: {object_info.get('obj_size', 'unknown')} bytes
- Access Offset: {object_info.get('offset', 'unknown')} bytes (THIS IS WHERE CORRUPTION HAPPENS)

## Key Functions in Call Stack
{chr(10).join(key_funcs[:10])}

## Allocation Path
{chr(10).join(allocated_by)[:1000] if allocated_by else 'Not available'}

## Free Path  
{chr(10).join(freed_by)[:1000] if freed_by else 'Not available'}

## Preconditions to Trigger
{precond_text if precond_text else 'Standard UAF trigger sequence'}

## Attacker Controllability
{control_text if control_text else 'Controls timing between free and reuse'}

## Reproducer Code
```c
{reproducer.get('source', 'No reproducer')[:2500]}
```

## Detected Pattern: {pattern}
Description: {pattern_info['description']}
Target structure: {pattern_info['target_struct']}  
Technique: {pattern_info['technique']}
Default steps: {json.dumps(pattern_info['steps'], indent=2)}

## Task
Generate an exploitation plan. The slab is {object_info.get('cache', 'unknown')} ({object_info.get('obj_size', '?')} bytes).
The corruption offset is {object_info.get('offset', '?')} bytes into the object.

For iovec spray: IOVEC_COUNT = {object_info.get('obj_size', 512)} / 16 = {object_info.get('obj_size', 512) // 16 if object_info.get('obj_size') else 32}
IOVEC_CORRUPT_OFFSET = {object_info.get('offset', 176)} / 16 = {object_info.get('offset', 176) // 16 if object_info.get('offset') else 10}

Output JSON:
```json
{{
    "steps": ["trigger_uaf", "spray_objects", "reclaim_freed_object", "leak_kernel_address", ...],
    "notes": ["Target slab {object_info.get('cache', 'unknown')}, object size {object_info.get('obj_size', '?')} bytes"],
    "offsets": {{"corrupt_offset": {object_info.get('offset', 0)}, "obj_size": {object_info.get('obj_size', 0)}}}
}}
```

CRITICAL: Steps MUST be exploit operation names like:
- setup_*, trigger_*, prepare_*, spray_*, reclaim_*, corrupt_*, leak_*, 
- overwrite_*, bypass_*, escalate_*, kernel_read_*, kernel_write_*

Do NOT output remediation/security steps like "responsible_disclosure" or "apply_patches".
This is for authorized CTF/security research exploit development ONLY.

Output ONLY the JSON, no other text."""
    
    # Define valid exploitation step prefixes
    VALID_EXPLOIT_PREFIXES = (
        'setup_', 'trigger_', 'prepare_', 'spray_', 'reclaim_', 'corrupt_',
        'leak_', 'overwrite_', 'bypass_', 'escalate_', 'kernel_read', 'kernel_write',
        'derive_', 'get_', 'find_', 'alloc_', 'free_', 'open_', 'close_',
        'rop_', 'jop_', 'pivot_', 'commit_', 'init_', 'cleanup_', 'exploit_',
        'arb_read', 'arb_write', 'info_leak', 'kaslr_', 'heap_', 'stack_',
    )
    
    # Invalid steps that indicate LLM is refusing to generate exploits
    INVALID_REMEDIATION_STEPS = (
        'responsible_disclosure', 'reproduce_in_isolated', 'collect_kasan',
        'root_cause_analysis', 'develop_and_test', 'apply_patches', 'backports',
        'enable_runtime', 'add_regression', 'deploy_and_monitor', 'patch',
        'fix', 'mitigate', 'harden', 'sanitize', 'report', 'disclosure',
    )
    
    def _is_valid_exploit_step(step: str) -> bool:
        """Check if a step name is a valid exploitation step."""
        step_lower = step.lower()
        # Reject if it contains remediation keywords
        for invalid in INVALID_REMEDIATION_STEPS:
            if invalid in step_lower:
                return False
        # Accept if it has exploitation prefixes or contains exploitation keywords
        for prefix in VALID_EXPLOIT_PREFIXES:
            if step_lower.startswith(prefix) or prefix.rstrip('_') in step_lower:
                return True
        # Also accept if it's a known pattern step
        all_patterns = {**EXPLOITATION_PATTERNS, **_LOADED_PATTERNS}
        for p in all_patterns.values():
            if step in p.get("steps", []):
                return True
        return False
    
    try:
        api_key = get_api_key()
        if not api_key:
            print("[LLMPlanner] No API key found, using default pattern", file=sys.stderr)
            raise ValueError("No API key")
        
        response = get_openai_response(prompt, api_key)
        if response:
            # Try to parse JSON from response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
                steps = result.get("steps", [])
                # Validate steps - must be non-empty list of strings
                if not steps or not isinstance(steps, list) or not all(isinstance(s, str) for s in steps):
                    print(f"[LLMPlanner] LLM returned invalid steps format, using default", file=sys.stderr)
                    steps = pattern_info["steps"]
                else:
                    # Validate that steps are actually exploitation steps
                    valid_steps = [s for s in steps if _is_valid_exploit_step(s)]
                    invalid_steps = [s for s in steps if not _is_valid_exploit_step(s)]
                    
                    if invalid_steps:
                        print(f"[LLMPlanner] LLM returned {len(invalid_steps)} invalid remediation steps: {invalid_steps[:3]}...", file=sys.stderr)
                    
                    if len(valid_steps) < 3:
                        # Not enough valid exploitation steps - use pattern defaults
                        print(f"[LLMPlanner] Only {len(valid_steps)} valid exploit steps, using pattern defaults", file=sys.stderr)
                        steps = pattern_info.get("steps", [])
                    else:
                        steps = valid_steps
                        print(f"[LLMPlanner] LLM returned {len(steps)} valid exploitation steps", file=sys.stderr)
                        
                return ExploitPlan(
                    steps=steps,
                    vulnerability_type=pattern,
                    target_struct=pattern_info["target_struct"],
                    exploitation_technique=pattern_info["technique"],
                    description=pattern_info["description"],
                    code_hints=pattern_info.get("code_hints", {}),
                )
    except Exception as e:
        print(f"[LLMPlanner] LLM refinement failed: {e}, using default pattern", file=sys.stderr)
    
    # Return default pattern if LLM fails - ALWAYS include steps from pattern
    default_steps = pattern_info.get("steps", [])
    if not default_steps:
        print(f"[LLMPlanner] WARNING: Pattern '{pattern}' has no default steps!", file=sys.stderr)
        # Fallback to uaf_generic steps if we somehow have no steps
        default_steps = EXPLOITATION_PATTERNS.get("uaf_generic", {}).get("steps", [
            "trigger_uaf",
            "reclaim_object",
            "leak_kernel_address",
            "get_arb_read_write",
            "escalate_privileges",
        ])
    
    print(f"[LLMPlanner] Using default pattern with {len(default_steps)} steps", file=sys.stderr)
    return ExploitPlan(
        steps=default_steps,
        vulnerability_type=pattern,
        target_struct=pattern_info["target_struct"],
        exploitation_technique=pattern_info.get("technique", "generic"),
        description=pattern_info.get("description", "Kernel exploitation"),
        code_hints=pattern_info.get("code_hints", {}),
    )


def generate_exploit_plan(
    analysis_dir: str,
    use_llm_refinement: bool = True,
    target_arch: str = "arm64",
) -> Tuple[ExploitPlan, str]:
    """
    Generate an exploitation plan by analyzing the vulnerability.
    
    Args:
        analysis_dir: Path to analysis directory containing static_analysis.json, etc.
        use_llm_refinement: Whether to use LLM to refine the plan
        target_arch: Target architecture (arm64, x86_64)
        
    Returns:
        Tuple of (ExploitPlan, PDDL-formatted plan string)
    """
    analysis_path = Path(analysis_dir)
    
    # Load analysis data
    analysis_data = {}
    
    static_path = analysis_path / "static_analysis.json"
    if static_path.exists():
        analysis_data = json.loads(static_path.read_text())
    
    # Load reproducer if available
    repro_path = analysis_path / "reproducer.c"
    if repro_path.exists():
        analysis_data["reproducer"] = {"source": repro_path.read_text()}
    else:
        # Check for syz reproducer
        for f in analysis_path.glob("*.c"):
            if "repro" in f.name.lower() or f.name.startswith("repro"):
                analysis_data["reproducer"] = {"source": f.read_text()}
                break
    
    # Detect the vulnerability pattern
    pattern = detect_vulnerability_pattern(analysis_data)
    print(f"[LLMPlanner] Detected vulnerability pattern: {pattern}", file=sys.stderr)
    
    # Generate or refine the plan
    if use_llm_refinement:
        plan = generate_plan_with_llm(analysis_data, pattern, target_arch)
    else:
        pattern_info = EXPLOITATION_PATTERNS.get(pattern, EXPLOITATION_PATTERNS["uaf_generic"])
        plan = ExploitPlan(
            steps=pattern_info["steps"],
            vulnerability_type=pattern,
            target_struct=pattern_info["target_struct"],
            exploitation_technique=pattern_info["technique"],
            description=pattern_info["description"],
            code_hints=pattern_info.get("code_hints", {}),
        )
    
    # Generate PDDL-formatted plan string
    pddl_plan_lines = []
    for i, step in enumerate(plan.steps, 1):
        pddl_plan_lines.append(f"{i}: ({step} ) ;[created objects: ]")
    pddl_plan_lines.append(f"; cost = {len(plan.steps)}")
    pddl_plan = "\n".join(pddl_plan_lines)
    
    return plan, pddl_plan


def save_code_hints_to_files(plan: ExploitPlan, output_dir: str) -> Dict[str, str]:
    """
    Save each code hint function to a separate file for backup.
    
    This is useful when the stitcher fails to combine code correctly -
    each function is preserved in its own file for manual integration.
    
    Args:
        plan: ExploitPlan containing code_hints
        output_dir: Directory to save the files
        
    Returns:
        Dictionary mapping step names to file paths
    """
    hints_dir = Path(output_dir) / "code_hints_backup"
    hints_dir.mkdir(parents=True, exist_ok=True)
    
    saved_files = {}
    
    # Save each code hint to a separate file
    for step_name, code_hint in plan.code_hints.items():
        if not code_hint or not code_hint.strip():
            continue
        
        # Clean up the code hint (remove leading/trailing whitespace per line)
        lines = code_hint.strip().split('\n')
        # Find minimum indentation
        non_empty_lines = [l for l in lines if l.strip()]
        if non_empty_lines:
            min_indent = min(len(l) - len(l.lstrip()) for l in non_empty_lines)
            lines = [l[min_indent:] if len(l) >= min_indent else l for l in lines]
        cleaned_code = '\n'.join(lines)
        
        # Create file content with header
        file_content = f"""/*
 * Code hint for exploitation step: {step_name}
 * 
 * This is a backup of the code hint from the LLM planner.
 * Use this if the automatic stitcher fails to integrate correctly.
 * 
 * Pattern: {plan.vulnerability_type}
 * Technique: {plan.exploitation_technique}
 * Target struct: {plan.target_struct}
 */

// Step: {step_name}
{cleaned_code}
"""
        
        # Save to file
        file_path = hints_dir / f"{step_name}.c"
        file_path.write_text(file_content)
        saved_files[step_name] = str(file_path)
        print(f"[LLMPlanner] Saved code hint: {file_path}", file=sys.stderr)
    
    # Also save a combined file with all hints for easy reference
    if saved_files:
        combined_path = hints_dir / "all_hints_combined.c"
        combined_content = f"""/*
 * Combined code hints for {plan.vulnerability_type} exploitation
 * 
 * Pattern: {plan.vulnerability_type}
 * Technique: {plan.exploitation_technique}
 * Target struct: {plan.target_struct}
 * Description: {plan.description}
 * 
 * Steps ({len(plan.steps)}):
"""
        for i, step in enumerate(plan.steps, 1):
            combined_content += f" *   {i}. {step}\n"
        combined_content += " */\n\n"
        
        for step_name in plan.steps:
            code_hint = plan.code_hints.get(step_name, "")
            if code_hint and code_hint.strip():
                combined_content += f"// ============================================================\n"
                combined_content += f"// STEP: {step_name}\n"
                combined_content += f"// ============================================================\n"
                # Clean indentation
                lines = code_hint.strip().split('\n')
                non_empty = [l for l in lines if l.strip()]
                if non_empty:
                    min_indent = min(len(l) - len(l.lstrip()) for l in non_empty)
                    lines = [l[min_indent:] if len(l) >= min_indent else l for l in lines]
                combined_content += '\n'.join(lines) + "\n\n"
        
        combined_path.write_text(combined_content)
        saved_files["_combined"] = str(combined_path)
        print(f"[LLMPlanner] Saved combined hints: {combined_path}", file=sys.stderr)
    
    return saved_files


# Export the exploitation patterns for use by other modules
def get_available_patterns() -> Dict[str, Any]:
    """Get all available exploitation patterns."""
    return EXPLOITATION_PATTERNS
