"""
synth.py

Main orchestration module for kernel exploit synthesis.
Combines primitives from various sources (syzanalyze, kernel-research)
and uses powerlifted planner to generate exploit plans.

This module is standalone and does not depend on chainreactor.
Supports both Linux and Android kernel exploitation.
"""

import json
import os
import sys
import traceback
from typing import Optional, Dict, Any, List
from pathlib import Path

from ..utils.debug import debug_print
from .core import PrimitiveRegistry, ExploitPlan, Primitive, normalize_steps
from .adapters.syzanalyze_adapter import load_from_analysis
from .adapters.kernelresearch_adapter import KernelResearchAdapter
from .domains import KernelDomain, TargetPlatform
from .pddl_generator import PDDLGenerator, set_debug as set_pddl_debug
from .stitcher import (
    ExploitStitcher, 
    CodeTemplateRegistry,
    LLMExploitStitcher,
    StitcherConfig,
)
from .llm_planner import (
    generate_exploit_plan as llm_generate_plan,
    _LegacyExploitPlan as LLMExploitPlan,
    EXPLOITATION_PATTERNS,
    save_code_hints_to_files,
    detect_vulnerability_pattern,
    _LOADED_PATTERNS,
)


# Import PowerliftedSolver (standalone, no chainreactor dependency)
from .powerlifted_integration import PowerliftedSolver


def plan_to_dict(plan: ExploitPlan) -> Dict[str, Any]:
    """Convert ExploitPlan to JSON-serializable dict."""
    result = {
        "goal": plan.goal,
        "target_info": plan.target_info,
        "primitives": [{"name": p.name, "description": p.description, "provides": p.provides, "requirements": p.requirements} for p in plan.primitives],
        "steps": plan.steps,
    }
    # Include new unified fields if set
    if plan.vulnerability_type:
        result["vulnerability_type"] = plan.vulnerability_type.value if hasattr(plan.vulnerability_type, 'value') else str(plan.vulnerability_type)
    if plan.target_struct:
        result["target_struct"] = plan.target_struct
    if plan.technique:
        result["technique"] = plan.technique
    if plan.platform:
        result["platform"] = plan.platform
    if plan.target_arch:
        result["target_arch"] = plan.target_arch
    if plan.target_kernel:
        result["target_kernel"] = plan.target_kernel
    if plan.offsets:
        result["offsets"] = plan.offsets
    if plan.exploitation_technique:
        result["exploitation_technique"] = plan.exploitation_technique
    return result


def detect_target_arch(analysis_data: Optional[Dict[str, Any]] = None) -> str:
    """
    Auto-detect target architecture from analysis data.
    
    Returns: "arm64" or "x86_64" (default)
    """
    if not analysis_data:
        return "x86_64"
    
    raw = json.dumps(analysis_data).lower()
    
    arm64_indicators = ["aarch64", "arm64", "goldfish", "cuttlefish", "android"]
    x86_indicators = ["x86_64", "amd64", "intel"]
    
    arm_score = sum(1 for ind in arm64_indicators if ind in raw)
    x86_score = sum(1 for ind in x86_indicators if ind in raw)
    
    if arm_score > x86_score:
        return "arm64"
    return "x86_64"


def detect_platform(analysis_dir: Optional[str], kernel_config: Optional[str] = None) -> TargetPlatform:
    """
    Auto-detect target platform from analysis data.
    
    Args:
        analysis_dir: Directory containing analysis results
        kernel_config: Path to kernel config file
        
    Returns:
        Detected TargetPlatform
    """
    indicators = {
        'android': 0,
        'linux': 0,
    }
    
    if analysis_dir:
        analysis_path = Path(analysis_dir)
        
        # Check static_analysis.json
        static_path = analysis_path / 'static_analysis.json'
        if static_path.exists():
            try:
                data = json.loads(static_path.read_text())
                raw = data.get('parsed', {}).get('raw', '').lower()
                
                # Android indicators
                if 'binder' in raw:
                    indicators['android'] += 2
                if 'selinux' in raw:
                    indicators['android'] += 1
                if 'ashmem' in raw:
                    indicators['android'] += 2
                if 'ion_' in raw:
                    indicators['android'] += 1
                if 'goldfish' in raw or 'cuttlefish' in raw:
                    indicators['android'] += 3
                
                # Linux-specific (not just general kernel)
                if 'CONFIG_X86' in raw:
                    indicators['linux'] += 2
                if 'CONFIG_NETFILTER' in raw:
                    indicators['linux'] += 1
                if 'io_uring' in raw:
                    indicators['linux'] += 1
                    
            except Exception:
                pass
        
        # Check for Android-specific files
        if (analysis_path / 'android_info.json').exists():
            indicators['android'] += 3
        
    # Check kernel config if provided
    if kernel_config and Path(kernel_config).exists():
        config_text = Path(kernel_config).read_text().lower()
        if 'config_android' in config_text:
            indicators['android'] += 3
        if 'config_arm64' in config_text:
            indicators['android'] += 1  # ARM64 more common on Android
    
    # Decide
    if indicators['android'] > indicators['linux']:
        return TargetPlatform.ANDROID_KERNEL
    elif indicators['linux'] > 0:
        return TargetPlatform.LINUX_KERNEL
    else:
        return TargetPlatform.GENERIC


def generate_capabilities_toml(primitives: List[Primitive], output_path: str, debug: bool = False) -> None:
    """
    Generate a capabilities.toml file from extracted primitives.
    """
    debug_print("Synthesizer", f"Generating capabilities TOML at {output_path}", debug)
    
    categories: Dict[str, Dict[str, Any]] = {}
    
    for prim in primitives:
        caps = prim.provides.get('caps', [])
        if isinstance(caps, str):
            caps = [caps]
        
        for cap in caps:
            cap_name = cap.replace('CAP_', '')
            category = cap_name.split('_')[0] if '_' in cap_name else cap_name
            
            if category not in categories:
                categories[category] = {
                    'predicates': [],
                    'primitives': [],
                }
            
            if cap not in categories[category]['predicates']:
                categories[category]['predicates'].append(cap)
            
            prim_entry = {
                'name': prim.name,
                'description': prim.description,
                'source': prim.provides.get('source', 'unknown'),
            }
            
            existing_names = [p['name'] for p in categories[category]['primitives']]
            if prim.name not in existing_names:
                categories[category]['primitives'].append(prim_entry)
    
    try:
        lines = [
            "# Auto-generated capabilities TOML",
            "# Generated by syzploit Synthesizer",
            "",
            "[capabilities]",
            "",
        ]
        
        for cat_name, cat_data in sorted(categories.items()):
            lines.append(f"  [{cat_name}]")
            lines.append(f"    predicates = {cat_data['predicates']}")
            lines.append("    primitives = [")
            for prim_entry in cat_data['primitives']:
                desc = prim_entry["description"][:50].replace('"', "'")
                lines.append(f'      {{ name = "{prim_entry["name"]}", '
                           f'description = "{desc}...", '
                           f'source = "{prim_entry["source"]}" }},')
            lines.append("    ]")
            lines.append("")
        
        with open(output_path, 'w') as f:
            f.write('\n'.join(lines))
        
        debug_print("Synthesizer", f"  wrote {len(categories)} capability categories", debug)
    except Exception as e:
        debug_print("Synthesizer", f"  failed to write capabilities TOML: {e}", debug)


def synthesize(bug_id: str, goal: str, 
               kernel_research_path: Optional[str] = None,
               analysis_dir: Optional[str] = None,
               vmlinux_path: Optional[str] = None,
               platform: Optional[str] = None,
               planner: str = "auto",
               model: str = "gpt-4o",
               verbose: bool = False,
               time_limit: Optional[int] = None,
               debug: bool = False) -> Dict[str, Any]:
    """
    Orchestrate exploit synthesis by combining primitives and invoking the planner.
    
    This function:
    1. Loads primitives from syzanalyze analysis
    2. Integrates kernel-research (kernelXDK) primitives if available
    3. Generates PDDL domain and problem files
    4. Invokes planner to find exploit plan
    
    Args:
        bug_id: Bug identifier (e.g., syzbot hash)
        goal: Goal description (e.g., "privilege escalation", "root_shell")
        kernel_research_path: Path to kernel-research repo (optional)
        analysis_dir: Directory containing analysis results
        vmlinux_path: Path to vmlinux for additional analysis
        platform: Target platform ("linux", "android", "generic", or auto-detect)
        planner: Planner to use: "auto", "llm", or "powerlifted"
                 - "auto": Use LLM planner when a known pattern matches, powerlifted otherwise
                 - "llm": Use LLM-based pattern matching planner
                 - "powerlifted": Use PDDL powerlifted planner
        model: LLM model identifier for litellm (e.g. "gpt-4o",
               "openrouter/anthropic/claude-sonnet-4-20250514")
        verbose: Print planner output in real-time
        time_limit: Planner time limit in seconds
        debug: Enable debug output
        
    Returns:
        Dictionary with plan, PDDL files, and solver results
    """
    if debug:
        set_pddl_debug(True)
    
    debug_print("Synthesizer", f"synthesize() called", debug)
    debug_print("Synthesizer", f"  bug_id: {bug_id}", debug)
    debug_print("Synthesizer", f"  goal: {goal}", debug)
    debug_print("Synthesizer", f"  platform: {platform}", debug)
    debug_print("Synthesizer", f"  analysis_dir: {analysis_dir}", debug)
    
    registry = PrimitiveRegistry()

    # Resolve default submodule paths if not provided
    try:
        src_root = Path(__file__).resolve().parents[2]  # src/syzploit/Synthesizer -> src
        debug_print("Synthesizer", f"  src_root: {src_root}", debug)
        if kernel_research_path is None:
            kr_candidate = src_root / 'kernel-research'
            if kr_candidate.exists():
                kernel_research_path = str(kr_candidate)
                debug_print("Synthesizer", f"  auto-detected kernel_research_path: {kernel_research_path}", debug)
    except Exception as e:
        debug_print("Synthesizer", f"  error detecting paths: {e}", debug)

    # Locate analysis directory
    cwd = os.getcwd()
    if not analysis_dir:
        candidates = [d for d in os.listdir(cwd) if d.startswith('analysis_') and bug_id in d]
        analysis_dir = os.path.join(cwd, candidates[0]) if candidates else cwd
    debug_print("Synthesizer", f"  analysis_dir resolved to: {analysis_dir}", debug)

    # Detect or set platform
    if platform:
        platform_map = {
            'linux': TargetPlatform.LINUX_KERNEL,
            'android': TargetPlatform.ANDROID_KERNEL,
            'generic': TargetPlatform.GENERIC,
        }
        target_platform = platform_map.get(platform.lower(), TargetPlatform.GENERIC)
    else:
        target_platform = detect_platform(analysis_dir)
    debug_print("Synthesizer", f"  target platform: {target_platform}", debug)

    # Load primitives from syzanalyze
    debug_print("Synthesizer", "Loading primitives from syzanalyze...", debug)
    syz_prims = load_from_analysis(analysis_dir, registry, debug=debug)
    debug_print("Synthesizer", f"  loaded {len(syz_prims)} primitives from syzanalyze", debug)
    for p in syz_prims:
        caps = p.provides.get('caps', [])
        debug_print("Synthesizer", f"    - {p.name}: {caps}", debug)

    # Integrate kernel-research primitives
    debug_print("Synthesizer", "Loading kernel-research primitives...", debug)
    kr = KernelResearchAdapter(kernel_research_path, debug=debug)
    xdk_prims = kr.list_primitives(registry, debug=debug) if kr.available() else []
    debug_print("Synthesizer", f"  loaded {len(xdk_prims)} primitives from kernel-research", debug)

    # Integrate kexploit primitives (ObjectDb heap objects, adaptation caps)
    debug_print("Synthesizer", "Loading kexploit primitives...", debug)
    try:
        from .adapters.kexploit_adapter import list_primitives as kexploit_list_primitives
        kx_kernel_name = None
        # Try to extract a kernel name from analysis data
        if analysis_dir:
            for fname in ("kexploit.json", "synth_spec.json", "static_analysis.json"):
                fpath = os.path.join(analysis_dir, fname)
                if os.path.exists(fpath):
                    try:
                        with open(fpath) as f:
                            fdata = json.load(f)
                        kx_kernel_name = (
                            fdata.get("kernel_name")
                            or fdata.get("target", {}).get("kernel_name")
                            or fdata.get("cve_metadata", {}).get("kernel_name")
                        )
                        if kx_kernel_name:
                            break
                    except Exception:
                        pass
        kx_prims = kexploit_list_primitives(registry, kernel_name=kx_kernel_name, debug=debug)
        debug_print("Synthesizer", f"  loaded {len(kx_prims)} primitives from kexploit", debug)
    except Exception as e:
        debug_print("Synthesizer", f"  kexploit primitives unavailable: {e}", debug)

    # Compose plan metadata
    target_info: Dict[str, Any] = {
        "bug_id": bug_id,
        "analysis_dir": analysis_dir,
        "vmlinux": vmlinux_path,
        "platform": target_platform.value,
    }
    plan = ExploitPlan(goal=goal, target_info=target_info, primitives=registry.list())
    debug_print("Synthesizer", f"  total primitives in plan: {len(plan.primitives)}", debug)

    # Generate capabilities TOML for reference
    caps_toml_path = os.path.join(analysis_dir, 'generated_capabilities.toml')
    generate_capabilities_toml(plan.primitives, caps_toml_path, debug)

    # Simple heuristic: choose steps based on goal
    steps = []
    goal_lower = goal.lower()
    if 'priv' in goal_lower or 'root' in goal_lower or 'shell' in goal_lower:
        steps.append({"action": "generate_rop_chain", "provider": "kernelXDK"})
        steps.append({"action": "commit_creds_prepare_kernel_cred", "provider": "kernelXDK"})
    plan.steps = steps
    debug_print("Synthesizer", f"  plan steps: {steps}", debug)

    # Write spec for reference
    spec_path = os.path.join(analysis_dir, 'synth_spec.json')
    try:
        with open(spec_path, 'w') as f:
            json.dump({
                "goal": goal,
                "target": target_info,
                "primitives": [p.__dict__ for p in plan.primitives],
                "steps": plan.steps,
            }, f, indent=2)
        debug_print("Synthesizer", f"  wrote synth_spec.json to {spec_path}", debug)
    except Exception as e:
        debug_print("Synthesizer", f"  failed to write synth_spec.json: {e}", debug)

    # Load analysis data early (needed for planner selection and code generation)
    analysis_data = None
    static_path = Path(analysis_dir) / 'static_analysis.json'
    if static_path.exists():
        try:
            analysis_data = json.loads(static_path.read_text())
            debug_print("Synthesizer", f"  Loaded static_analysis.json", debug)
        except Exception as e:
            debug_print("Synthesizer", f"  Failed to load static_analysis.json: {e}", debug)
    
    # Determine which planner to use
    use_llm_planner = False
    if planner == "llm":
        use_llm_planner = True
        debug_print("Synthesizer", "Using LLM-based planner (explicitly requested)", debug)
    elif planner == "auto":
        # Auto-detect: use LLM planner when loaded patterns can match the crash
        raw_crash = ""
        if analysis_data and "parsed" in analysis_data:
            raw_crash = analysis_data["parsed"].get("raw", "").lower()
        
        # Check if any loaded pattern's detection rules match the crash
        all_patterns = {**EXPLOITATION_PATTERNS, **_LOADED_PATTERNS}
        if raw_crash and len(all_patterns) > 1:
            detected = detect_vulnerability_pattern(analysis_data or {})
            if detected != "uaf_generic":
                use_llm_planner = True
                debug_print("Synthesizer", f"Auto-detected pattern '{detected}' - using LLM planner", debug)
    
    # Use LLM planner if selected
    if use_llm_planner:
        debug_print("Synthesizer", "=" * 50, debug)
        debug_print("Synthesizer", "Using LLM-based exploitation pattern planner", debug)
        debug_print("Synthesizer", "=" * 50, debug)
        
        try:
            llm_plan, pddl_plan_str = llm_generate_plan(
                analysis_dir=analysis_dir,
                use_llm_refinement=True,
                target_arch="arm64" if target_platform == TargetPlatform.ANDROID_KERNEL else detect_target_arch(analysis_data),
                model=model,
            )
            
            debug_print("Synthesizer", f"LLM Planner detected pattern: {llm_plan.vulnerability_type}", debug)
            debug_print("Synthesizer", f"LLM Planner exploitation technique: {llm_plan.exploitation_technique}", debug)
            debug_print("Synthesizer", f"LLM Planner steps ({len(llm_plan.steps)}): {llm_plan.steps}", debug)
            
            # Validate steps - should never be empty
            if not llm_plan.steps:
                debug_print("Synthesizer", "WARNING: LLM plan has empty steps! This is a bug.", debug)
                print("[!] WARNING: LLM planner returned empty steps - check llm_planner.py", file=sys.stderr)
            
            # Save code hints to separate files as backup
            debug_print("Synthesizer", "Saving code hints to separate files for backup...", debug)
            try:
                hint_files = save_code_hints_to_files(llm_plan, analysis_dir)
                debug_print("Synthesizer", f"Saved {len(hint_files)} code hint files", debug)
                print(f"[+] Saved {len(hint_files)} code hints to: {os.path.join(analysis_dir, 'code_hints_backup')}", file=sys.stderr)
            except Exception as e:
                debug_print("Synthesizer", f"Failed to save code hints: {e}", debug)
            
            # Write the LLM-generated plan to PDDL format
            pddl_dir = os.path.join(analysis_dir, 'pddl')
            os.makedirs(pddl_dir, exist_ok=True)
            
            plan_path = os.path.join(pddl_dir, 'plan.1')
            with open(plan_path, 'w') as f:
                f.write(pddl_plan_str)
            debug_print("Synthesizer", f"Wrote LLM plan to {plan_path}", debug)
            
            # Also generate domain/problem for reference
            gen = PDDLGenerator(platform=target_platform, analysis_dir=analysis_dir)
            domain_path = gen.domain_path(pddl_dir)
            problem_path = gen.generate_problem(
                f"{bug_id}_goal", 
                plan.primitives, 
                os.path.join(pddl_dir, 'problem.pddl'), 
                goal,
                debug=debug,
                analysis_data=analysis_data
            )
            
            # Create result structure similar to powerlifted
            result = {
                "success": True,
                "planner": "llm",
                "pattern": llm_plan.vulnerability_type,
                "technique": llm_plan.exploitation_technique,
                "plans": [plan_path],
                "parsed_plan": llm_plan.steps,
                "parsed_plans": [{
                    "file": plan_path,
                    "actions": llm_plan.steps,
                    "num_steps": len(llm_plan.steps),
                    "code_hints": llm_plan.code_hints,
                }],
            }
            
            # Generate exploit code
            exploit_files = []
            debug_print("Synthesizer", "Stitching exploit code from LLM plan...", debug)
            
            # Save LLM planner output for debugging
            llm_planner_output_path = os.path.join(analysis_dir, 'llm_planner_output.json')
            try:
                llm_output = {
                    "vulnerability_type": llm_plan.vulnerability_type,
                    "exploitation_technique": llm_plan.exploitation_technique,
                    "target_struct": llm_plan.target_struct,
                    "description": llm_plan.description,
                    "steps": llm_plan.steps,
                    "code_hints": llm_plan.code_hints,
                    "pddl_plan": pddl_plan_str,
                }
                with open(llm_planner_output_path, 'w') as f:
                    json.dump(llm_output, f, indent=2)
                print(f"[+] LLM planner output saved to: {llm_planner_output_path}")
            except Exception as e:
                debug_print("Synthesizer", f"Failed to save LLM planner output: {e}", debug)
            
            try:
                if target_platform == TargetPlatform.ANDROID_KERNEL:
                    stitch_platform = "android"
                    stitch_arch = "arm64"
                else:
                    stitch_platform = "linux"
                    stitch_arch = "x86_64"
                
                # Use LLM-enhanced stitcher with template fallback
                # The LLMExploitStitcher now uses a hybrid approach:
                # 1. Generate base skeleton from templates (guaranteed working code)
                # 2. Try to enhance each function with LLM (benign prompts)
                # 3. Fall back to template code if LLM refuses
                # NOTE: LLMExploitStitcher and StitcherConfig are imported at module level
                
                stitch_config = StitcherConfig(
                    platform=stitch_platform,
                    arch=stitch_arch,
                    include_debug=True,
                    output_dir=analysis_dir,
                    verify_compilation=True,
                    llm_model=model,
                )
                
                # Pass code hints from the LLM plan to the stitcher
                if analysis_data is None:
                    analysis_data = {}
                analysis_data["llm_plan"] = {
                    "pattern": llm_plan.vulnerability_type,
                    "technique": llm_plan.exploitation_technique,
                    "code_hints": llm_plan.code_hints,
                }
                
                exploit_name = f"exploit_{bug_id}"
                exploit_path = os.path.join(analysis_dir, f"{exploit_name}.c")
                
                # Normalize heterogeneous steps to canonical ExploitStep dicts
                llm_plan.normalize()
                plan_actions = llm_plan.steps
                debug_print("Synthesizer", f"Normalized {len(plan_actions)} steps: {plan_actions}", debug)
                print(f"[*] Using LLM-enhanced stitcher (template fallback) with {len(plan_actions)} actions")
                
                # Use LLM-enhanced stitcher (tries LLM per-function, falls back to templates)
                stitcher = LLMExploitStitcher(stitch_config)
                
                generated_path = stitcher.stitch(
                    plan_actions=plan_actions,
                    bug_id=bug_id,
                    output_path=exploit_path,
                    analysis_data=analysis_data
                )
                exploit_files.append(generated_path)
                debug_print("Synthesizer", f"Generated: {generated_path}", debug)
            except Exception as e:
                debug_print("Synthesizer", f"Stitching failed: {e}", debug)
                debug_print("Synthesizer", f"Traceback: {traceback.format_exc()}", debug)
            
            return {
                "plan": plan_to_dict(plan),
                "powerlifted": result,
                "pddl": {
                    "domain": domain_path,
                    "problem": problem_path,
                },
                "exploits": exploit_files,
                "llm_plan": {
                    "pattern": llm_plan.vulnerability_type,
                    "technique": llm_plan.exploitation_technique,
                    "steps": llm_plan.steps,
                    "description": llm_plan.description,
                },
            }
        except Exception as e:
            debug_print("Synthesizer", f"LLM planner failed: {e}, falling back to powerlifted", debug)
            debug_print("Synthesizer", f"Traceback: {traceback.format_exc()}", debug)
            # Fall through to powerlifted

    # Initialize solver (powerlifted)
    debug_print("Synthesizer", "Initializing PowerliftedSolver...", debug)
    solver = PowerliftedSolver(debug=debug)
    
    debug_print("Synthesizer", f"Solver available: {solver.available()}", debug)
    if not solver.available():
        debug_print("Synthesizer", "Powerlifted solver not available!", debug)
        return {
            "plan": plan_to_dict(plan),
            "powerlifted": {
                "success": False, 
                "error": "Powerlifted planner not available",
                "hint": "Install powerlifted or ensure src/powerlifted exists"
            },
            "pddl": None
        }

    # Generate PDDL files
    pddl_dir = os.path.join(analysis_dir, 'pddl')
    os.makedirs(pddl_dir, exist_ok=True)
    debug_print("Synthesizer", f"PDDL output directory: {pddl_dir}", debug)
    
    # Create PDDL generator with detected platform
    debug_print("Synthesizer", "Creating PDDLGenerator...", debug)
    gen = PDDLGenerator(platform=target_platform, analysis_dir=analysis_dir)
    
    # Generate domain file
    debug_print("Synthesizer", "Generating domain PDDL...", debug)
    domain_path = gen.domain_path(pddl_dir, analysis_data=analysis_data)
    debug_print("Synthesizer", f"  domain_path: {domain_path}", debug)
    
    # Generate problem PDDL (analysis_data already loaded earlier)
    debug_print("Synthesizer", "Generating problem PDDL...", debug)
    problem_path = gen.generate_problem(
        f"{bug_id}_goal", 
        plan.primitives, 
        os.path.join(pddl_dir, 'problem.pddl'), 
        goal,
        debug=debug,
        analysis_data=analysis_data
    )
    debug_print("Synthesizer", f"  problem_path: {problem_path}", debug)

    # Run solver
    debug_print("Synthesizer", "Running solver...", debug)
    result = solver.solve(
        domain_path, 
        problem_path, 
        pddl_dir,
        time_limit=time_limit,
        verbose=verbose,
        debug=debug
    )
    debug_print("Synthesizer", f"Solver result: success={result.get('success')}", debug)
    if not result.get('success') and debug:
        solver_stdout = result.get('stdout', '')
        if solver_stdout:
            # Print last 40 lines of solver output to help diagnose failures
            lines = solver_stdout.strip().split('\n')
            tail = lines[-40:] if len(lines) > 40 else lines
            debug_print("Synthesizer", f"Solver output (last {len(tail)} lines):", debug)
            for ln in tail:
                debug_print("Synthesizer", f"  | {ln}", debug)
        if result.get('error'):
            debug_print("Synthesizer", f"Solver error: {result['error']}", debug)
    
    # If solution found, parse ALL plans
    exploit_files = []
    if result.get('success') and result.get('plans'):
        debug_print("Synthesizer", f"Solution found! Plans: {result.get('plans')}", debug)
        all_parsed_plans = []
        for plan_file in result['plans']:
            parsed_actions = solver.parse_plan(plan_file)
            all_parsed_plans.append({
                'file': plan_file,
                'actions': parsed_actions,
                'num_steps': len(parsed_actions)
            })
            debug_print("Synthesizer", f"Parsed {len(parsed_actions)} actions from {plan_file}", debug)
        
        result['parsed_plans'] = all_parsed_plans
        # Keep backward compatibility - first plan in 'parsed_plan'
        if all_parsed_plans:
            result['parsed_plan'] = all_parsed_plans[0]['actions']
        
        debug_print("Synthesizer", f"Total plans found: {len(all_parsed_plans)}", debug)
        
        # STITCH: Generate C exploit code from the plan(s)
        debug_print("Synthesizer", "Stitching exploit code from plans...", debug)
        try:
            # Determine platform for stitcher
            if target_platform == TargetPlatform.ANDROID_KERNEL:
                stitch_platform = "android"
                stitch_arch = "arm64"
            elif target_platform == TargetPlatform.LINUX_KERNEL:
                stitch_platform = "linux"
                stitch_arch = "x86_64"
            else:
                stitch_platform = "linux"
                stitch_arch = "x86_64"
            
            # analysis_data was already loaded earlier for PDDL generation
            
            # Create stitcher config
            stitch_config = StitcherConfig(
                platform=stitch_platform,
                arch=stitch_arch,
                include_debug=debug,
                output_dir=analysis_dir,
                verify_compilation=True,
            )
            
            # Use LLM stitcher if available, otherwise fall back to template stitcher
            debug_print("Synthesizer", "Using LLM-powered stitcher with library code mapping", debug)
            stitcher = LLMExploitStitcher(stitch_config)
            # else:
            #     debug_print("Synthesizer", "LiteLLM not available, using template-based stitcher", debug)
            #     from .stitcher.stitcher import StitcherConfig as TemplateConfig
            #     template_config = TemplateConfig(
            #         platform=stitch_platform,
            #         arch=stitch_arch,
            #         include_debug=debug,
            #         output_dir=analysis_dir,
            #     )
            #     stitcher = ExploitStitcher(template_config)
            
            # Stitch each plan into an exploit
            for i, parsed_plan in enumerate(all_parsed_plans):
                plan_actions = parsed_plan['actions']
                if not plan_actions:
                    continue
                    
                exploit_name = f"exploit_{bug_id}"
                if len(all_parsed_plans) > 1:
                    exploit_name = f"exploit_{bug_id}_plan{i+1}"
                
                exploit_path = os.path.join(analysis_dir, f"{exploit_name}.c")
                
                debug_print("Synthesizer", f"Stitching plan {i+1} -> {exploit_path}", debug)
                
                try:
                    generated_path = stitcher.stitch(
                        plan_actions=plan_actions,
                        bug_id=bug_id,
                        output_path=exploit_path,
                        analysis_data=analysis_data
                    )
                    exploit_files.append(generated_path)
                    debug_print("Synthesizer", f"  Generated: {generated_path}", debug)
                except Exception as e:
                    debug_print("Synthesizer", f"  Failed to stitch plan {i+1}: {e}", debug)
                    debug_print("Synthesizer", f"  Traceback: {traceback.format_exc()}", debug)
            
            if exploit_files:
                debug_print("Synthesizer", f"Generated {len(exploit_files)} exploit file(s)", debug)
        except Exception as e:
            debug_print("Synthesizer", f"Stitching failed: {e}", debug)
            debug_print("Synthesizer", f"Traceback: {traceback.format_exc()}", debug)
    else:
        debug_print("Synthesizer", f"No solution found or no plans generated", debug)
        if result.get('error'):
            debug_print("Synthesizer", f"  error: {result.get('error')}", debug)

        # ── LLM fallback: if planner=auto and PDDL failed, try LLM planner ──
        if planner == "auto" and not use_llm_planner:
            debug_print("Synthesizer", "PDDL planner failed — falling back to LLM planner", debug)
            try:
                llm_plan, pddl_plan_str = llm_generate_plan(
                    analysis_dir=analysis_dir,
                    use_llm_refinement=True,
                    target_arch="arm64" if target_platform == TargetPlatform.ANDROID_KERNEL else detect_target_arch(analysis_data),
                    model=model,
                )
                debug_print("Synthesizer", f"LLM fallback pattern: {llm_plan.vulnerability_type}", debug)
                debug_print("Synthesizer", f"LLM fallback steps: {llm_plan.steps}", debug)

                # Save the LLM plan
                plan_path = os.path.join(pddl_dir, 'plan.1')
                with open(plan_path, 'w') as f:
                    f.write(pddl_plan_str)

                # Save planner output
                try:
                    llm_output = {
                        "vulnerability_type": llm_plan.vulnerability_type,
                        "exploitation_technique": llm_plan.exploitation_technique,
                        "target_struct": llm_plan.target_struct,
                        "description": llm_plan.description,
                        "steps": llm_plan.steps,
                        "code_hints": llm_plan.code_hints,
                        "pddl_plan": pddl_plan_str,
                    }
                    with open(os.path.join(analysis_dir, 'llm_planner_output.json'), 'w') as f:
                        json.dump(llm_output, f, indent=2)
                except Exception:
                    pass

                # Save code hints
                try:
                    save_code_hints_to_files(llm_plan, analysis_dir)
                except Exception:
                    pass

                # Stitch exploit from LLM plan
                if llm_plan.steps:
                    try:
                        if target_platform == TargetPlatform.ANDROID_KERNEL:
                            stitch_platform, stitch_arch = "android", "arm64"
                        else:
                            stitch_platform, stitch_arch = "linux", "x86_64"

                        stitch_config = StitcherConfig(
                            platform=stitch_platform,
                            arch=stitch_arch,
                            include_debug=True,
                            output_dir=analysis_dir,
                            verify_compilation=True,
                            llm_model=model,
                        )
                        if analysis_data is None:
                            analysis_data = {}
                        analysis_data["llm_plan"] = {
                            "pattern": llm_plan.vulnerability_type,
                            "technique": llm_plan.exploitation_technique,
                            "code_hints": llm_plan.code_hints,
                        }
                        llm_plan.normalize()
                        plan_actions = llm_plan.steps
                        stitcher = LLMExploitStitcher(stitch_config)
                        exploit_path = os.path.join(analysis_dir, f"exploit_{bug_id}.c")
                        generated_path = stitcher.stitch(
                            plan_actions=plan_actions,
                            bug_id=bug_id,
                            output_path=exploit_path,
                            analysis_data=analysis_data,
                        )
                        exploit_files.append(generated_path)
                        debug_print("Synthesizer", f"LLM fallback generated: {generated_path}", debug)
                    except Exception as e:
                        debug_print("Synthesizer", f"LLM fallback stitching failed: {e}", debug)

                result = {
                    "success": bool(exploit_files),
                    "planner": "llm_fallback",
                    "pattern": llm_plan.vulnerability_type,
                    "technique": llm_plan.exploitation_technique,
                    "parsed_plans": [{
                        "file": plan_path,
                        "actions": llm_plan.steps,
                        "num_steps": len(llm_plan.steps),
                    }],
                }
            except Exception as e:
                debug_print("Synthesizer", f"LLM fallback also failed: {e}", debug)
                debug_print("Synthesizer", f"Traceback: {traceback.format_exc()}", debug)

    return {
        "plan": plan_to_dict(plan),
        "powerlifted": result,
        "pddl": {
            "domain": domain_path,
            "problem": problem_path
        },
        "exploits": exploit_files
    }


def synthesize_from_facts(bug_id: str, goal: str,
                          facts: Dict[str, Any],
                          platform: Optional[str] = None,
                          output_dir: Optional[str] = None,
                          verbose: bool = False,
                          time_limit: Optional[int] = None,
                          debug: bool = False) -> Dict[str, Any]:
    """
    Synthesize exploit plan from pre-extracted system facts.
    
    This is useful when you have already extracted vulnerability information
    and want to generate a targeted PDDL problem.
    
    Args:
        bug_id: Bug identifier
        goal: Goal description (e.g., "root_shell", "privilege_escalation")
        facts: Dictionary with facts:
            - vulnerabilities: List of vulnerability types (uaf, oob_write, etc.)
            - capabilities: List of capabilities (arb_read, arb_write, etc.)
            - techniques: List of available techniques (msg_msg, pipe_buffer, etc.)
            - state: Dict with state flags (heap_controlled, info_leak, kaslr_bypassed)
        platform: Target platform ("linux", "android", "generic")
        output_dir: Directory for output files
        verbose: Print planner output
        time_limit: Planner time limit
        debug: Enable debug output
        
    Returns:
        Dictionary with plan and solver results
    """
    debug_print("Synthesizer", f"synthesize_from_facts called: bug_id={bug_id}, goal={goal}", debug)
    debug_print("Synthesizer", f"  facts keys: {list(facts.keys())}", debug)
    
    # Determine platform
    if platform:
        platform_map = {
            'linux': TargetPlatform.LINUX_KERNEL,
            'android': TargetPlatform.ANDROID_KERNEL,
            'generic': TargetPlatform.GENERIC,
        }
        target_platform = platform_map.get(platform.lower(), TargetPlatform.GENERIC)
    else:
        # Default based on vulnerability types
        vulns = facts.get('vulnerabilities', [])
        android_indicators = ['binder', 'ashmem', 'ion', 'goldfish', 'cuttlefish']
        if any(ind in v.lower() for v in vulns for ind in android_indicators):
            target_platform = TargetPlatform.ANDROID_KERNEL
        else:
            target_platform = TargetPlatform.LINUX_KERNEL
    
    debug_print("Synthesizer", f"Using platform: {target_platform}", debug)
    
    # Setup output directory
    if not output_dir:
        output_dir = os.path.join(os.getcwd(), f'synth_{bug_id}')
    os.makedirs(output_dir, exist_ok=True)
    
    pddl_dir = os.path.join(output_dir, 'pddl')
    os.makedirs(pddl_dir, exist_ok=True)
    debug_print("Synthesizer", f"PDDL dir: {pddl_dir}", debug)
    
    # Generate PDDL
    gen = PDDLGenerator(platform=target_platform)
    debug_print("Synthesizer", "PDDLGenerator created", debug)
    
    domain_path = gen.domain_path(pddl_dir)
    debug_print("Synthesizer", f"Domain generated: {domain_path}", debug)
    
    problem_path = gen.generate_problem_from_facts(
        f"{bug_id}_facts",
        facts,
        os.path.join(pddl_dir, 'problem.pddl'),
        goal
    )
    debug_print("Synthesizer", f"Problem generated: {problem_path}", debug)
    
    # Solve
    solver = PowerliftedSolver(debug=debug)
    debug_print("Synthesizer", f"PowerliftedSolver created, available={solver.available()}", debug)
    if not solver.available():
        debug_print("Synthesizer", "Powerlifted not available!", debug)
        return {
            "success": False,
            "error": "Powerlifted not available",
            "pddl": {"domain": domain_path, "problem": problem_path}
        }
    
    debug_print("Synthesizer", "Running solver...", debug)
    result = solver.solve(
        domain_path,
        problem_path,
        pddl_dir,
        time_limit=time_limit,
        verbose=verbose,
        debug=debug
    )
    debug_print("Synthesizer", f"Solver result: success={result.get('success')}", debug)
    
    if result.get('success') and result.get('plans'):
        debug_print("Synthesizer", f"Solution found! Parsing plan...", debug)
        for plan_file in result['plans']:
            result['parsed_plan'] = solver.parse_plan(plan_file)
            debug_print("Synthesizer", f"Parsed {len(result['parsed_plan'])} actions", debug)
            break
    else:
        debug_print("Synthesizer", "No solution found or no plans", debug)
    
    return {
        "success": result.get('success', False),
        "powerlifted": result,
        "pddl": {"domain": domain_path, "problem": problem_path}
    }
