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
from dataclasses import asdict
from typing import Optional, Dict, Any, List
from pathlib import Path

from .core import PrimitiveRegistry, ExploitPlan, Primitive
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


# Import PowerliftedSolver (standalone, no chainreactor dependency)
from .powerlifted_integration import PowerliftedSolver


def _debug(msg: str, enabled: bool = True):
    """Print debug message."""
    if enabled:
        print(f"[DEBUG:Synthesizer] {msg}", file=sys.stderr)


def _plan_to_dict(plan: ExploitPlan) -> Dict[str, Any]:
    """Convert ExploitPlan to JSON-serializable dict."""
    return {
        "goal": plan.goal,
        "target_info": plan.target_info,
        "primitives": [asdict(p) for p in plan.primitives],
        "steps": plan.steps,
    }


def _detect_platform(analysis_dir: Optional[str], kernel_config: Optional[str] = None) -> TargetPlatform:
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


def _generate_capabilities_toml(primitives: List[Primitive], output_path: str, debug: bool = False) -> None:
    """
    Generate a capabilities.toml file from extracted primitives.
    """
    _debug(f"Generating capabilities TOML at {output_path}", debug)
    
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
        
        _debug(f"  wrote {len(categories)} capability categories", debug)
    except Exception as e:
        _debug(f"  failed to write capabilities TOML: {e}", debug)


def synthesize(bug_id: str, goal: str, 
               kernel_research_path: Optional[str] = None,
               analysis_dir: Optional[str] = None,
               vmlinux_path: Optional[str] = None,
               platform: Optional[str] = None,
               verbose: bool = False,
               time_limit: Optional[int] = None,
               debug: bool = False) -> Dict[str, Any]:
    """
    Orchestrate exploit synthesis by combining primitives and invoking the planner.
    
    This function:
    1. Loads primitives from syzanalyze analysis
    2. Integrates kernel-research (kernelXDK) primitives if available
    3. Generates PDDL domain and problem files
    4. Invokes powerlifted planner to find exploit plan
    
    Args:
        bug_id: Bug identifier (e.g., syzbot hash)
        goal: Goal description (e.g., "privilege escalation", "root_shell")
        kernel_research_path: Path to kernel-research repo (optional)
        analysis_dir: Directory containing analysis results
        vmlinux_path: Path to vmlinux for additional analysis
        platform: Target platform ("linux", "android", "generic", or auto-detect)
        verbose: Print planner output in real-time
        time_limit: Planner time limit in seconds
        debug: Enable debug output
        
    Returns:
        Dictionary with plan, PDDL files, and solver results
    """
    if debug:
        set_pddl_debug(True)
    
    _debug(f"synthesize() called", debug)
    _debug(f"  bug_id: {bug_id}", debug)
    _debug(f"  goal: {goal}", debug)
    _debug(f"  platform: {platform}", debug)
    _debug(f"  analysis_dir: {analysis_dir}", debug)
    
    registry = PrimitiveRegistry()

    # Resolve default submodule paths if not provided
    try:
        src_root = Path(__file__).resolve().parents[2]  # src/syzploit/Synthesizer -> src
        _debug(f"  src_root: {src_root}", debug)
        if kernel_research_path is None:
            kr_candidate = src_root / 'kernel-research'
            if kr_candidate.exists():
                kernel_research_path = str(kr_candidate)
                _debug(f"  auto-detected kernel_research_path: {kernel_research_path}", debug)
    except Exception as e:
        _debug(f"  error detecting paths: {e}", debug)

    # Locate analysis directory
    cwd = os.getcwd()
    if not analysis_dir:
        candidates = [d for d in os.listdir(cwd) if d.startswith('analysis_') and bug_id in d]
        analysis_dir = os.path.join(cwd, candidates[0]) if candidates else cwd
    _debug(f"  analysis_dir resolved to: {analysis_dir}", debug)

    # Detect or set platform
    if platform:
        platform_map = {
            'linux': TargetPlatform.LINUX_KERNEL,
            'android': TargetPlatform.ANDROID_KERNEL,
            'generic': TargetPlatform.GENERIC,
        }
        target_platform = platform_map.get(platform.lower(), TargetPlatform.GENERIC)
    else:
        target_platform = _detect_platform(analysis_dir)
    _debug(f"  target platform: {target_platform}", debug)

    # Load primitives from syzanalyze
    _debug("Loading primitives from syzanalyze...", debug)
    syz_prims = load_from_analysis(analysis_dir, registry, debug=debug)
    _debug(f"  loaded {len(syz_prims)} primitives from syzanalyze", debug)
    for p in syz_prims:
        caps = p.provides.get('caps', [])
        _debug(f"    - {p.name}: {caps}", debug)

    # Integrate kernel-research primitives
    _debug("Loading kernel-research primitives...", debug)
    kr = KernelResearchAdapter(kernel_research_path, debug=debug)
    xdk_prims = kr.list_primitives(registry, debug=debug) if kr.available() else []
    _debug(f"  loaded {len(xdk_prims)} primitives from kernel-research", debug)

    # Compose plan metadata
    target_info: Dict[str, Any] = {
        "bug_id": bug_id,
        "analysis_dir": analysis_dir,
        "vmlinux": vmlinux_path,
        "platform": target_platform.value,
    }
    plan = ExploitPlan(goal=goal, target_info=target_info, primitives=registry.list())
    _debug(f"  total primitives in plan: {len(plan.primitives)}", debug)

    # Generate capabilities TOML for reference
    caps_toml_path = os.path.join(analysis_dir, 'generated_capabilities.toml')
    _generate_capabilities_toml(plan.primitives, caps_toml_path, debug)

    # Simple heuristic: choose steps based on goal
    steps = []
    goal_lower = goal.lower()
    if 'priv' in goal_lower or 'root' in goal_lower or 'shell' in goal_lower:
        steps.append({"action": "generate_rop_chain", "provider": "kernelXDK"})
        steps.append({"action": "commit_creds_prepare_kernel_cred", "provider": "kernelXDK"})
    plan.steps = steps
    _debug(f"  plan steps: {steps}", debug)

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
        _debug(f"  wrote synth_spec.json to {spec_path}", debug)
    except Exception as e:
        _debug(f"  failed to write synth_spec.json: {e}", debug)

    # Initialize solver
    _debug("Initializing PowerliftedSolver...", debug)
    solver = PowerliftedSolver(debug=debug)
    
    _debug(f"Solver available: {solver.available()}", debug)
    if not solver.available():
        _debug("Powerlifted solver not available!", debug)
        return {
            "plan": _plan_to_dict(plan),
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
    _debug(f"PDDL output directory: {pddl_dir}", debug)
    
    # Create PDDL generator with detected platform
    _debug("Creating PDDLGenerator...", debug)
    gen = PDDLGenerator(platform=target_platform, analysis_dir=analysis_dir)
    
    # Generate domain file
    _debug("Generating domain PDDL...", debug)
    domain_path = gen.domain_path(pddl_dir)
    _debug(f"  domain_path: {domain_path}", debug)
    
    # Load analysis data if available (needed for reproducer info)
    analysis_data = None
    static_path = Path(analysis_dir) / 'static_analysis.json'
    if static_path.exists():
        try:
            analysis_data = json.loads(static_path.read_text())
            _debug(f"  Loaded static_analysis.json", debug)
        except Exception as e:
            _debug(f"  Failed to load static_analysis.json: {e}", debug)
    
    # Generate problem PDDL
    _debug("Generating problem PDDL...", debug)
    problem_path = gen.generate_problem(
        f"{bug_id}_goal", 
        plan.primitives, 
        os.path.join(pddl_dir, 'problem.pddl'), 
        goal,
        debug=debug,
        analysis_data=analysis_data
    )
    _debug(f"  problem_path: {problem_path}", debug)

    # Run solver
    _debug("Running solver...", debug)
    result = solver.solve(
        domain_path, 
        problem_path, 
        pddl_dir,
        time_limit=time_limit,
        verbose=verbose,
        debug=debug
    )
    _debug(f"Solver result: success={result.get('success')}", debug)
    
    # If solution found, parse ALL plans
    exploit_files = []
    if result.get('success') and result.get('plans'):
        _debug(f"Solution found! Plans: {result.get('plans')}", debug)
        all_parsed_plans = []
        for plan_file in result['plans']:
            parsed_actions = solver.parse_plan(plan_file)
            all_parsed_plans.append({
                'file': plan_file,
                'actions': parsed_actions,
                'num_steps': len(parsed_actions)
            })
            _debug(f"Parsed {len(parsed_actions)} actions from {plan_file}", debug)
        
        result['parsed_plans'] = all_parsed_plans
        # Keep backward compatibility - first plan in 'parsed_plan'
        if all_parsed_plans:
            result['parsed_plan'] = all_parsed_plans[0]['actions']
        
        _debug(f"Total plans found: {len(all_parsed_plans)}", debug)
        
        # STITCH: Generate C exploit code from the plan(s)
        _debug("Stitching exploit code from plans...", debug)
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
            _debug("Using LLM-powered stitcher with library code mapping", debug)
            stitcher = LLMExploitStitcher(stitch_config)
            # else:
            #     _debug("LiteLLM not available, using template-based stitcher", debug)
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
                
                _debug(f"Stitching plan {i+1} -> {exploit_path}", debug)
                
                try:
                    generated_path = stitcher.stitch(
                        plan_actions=plan_actions,
                        bug_id=bug_id,
                        output_path=exploit_path,
                        analysis_data=analysis_data
                    )
                    exploit_files.append(generated_path)
                    _debug(f"  Generated: {generated_path}", debug)
                except Exception as e:
                    _debug(f"  Failed to stitch plan {i+1}: {e}", debug)
                    import traceback
                    _debug(f"  Traceback: {traceback.format_exc()}", debug)
            
            if exploit_files:
                _debug(f"Generated {len(exploit_files)} exploit file(s)", debug)
        except Exception as e:
            _debug(f"Stitching failed: {e}", debug)
            import traceback
            _debug(f"Traceback: {traceback.format_exc()}", debug)
    else:
        _debug(f"No solution found or no plans generated", debug)
        if result.get('error'):
            _debug(f"  error: {result.get('error')}", debug)
    
    return {
        "plan": _plan_to_dict(plan),
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
    _debug(f"synthesize_from_facts called: bug_id={bug_id}, goal={goal}", debug)
    _debug(f"  facts keys: {list(facts.keys())}", debug)
    
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
        if any('binder' in v.lower() for v in vulns):
            target_platform = TargetPlatform.ANDROID_KERNEL
        else:
            target_platform = TargetPlatform.LINUX_KERNEL
    
    _debug(f"Using platform: {target_platform}", debug)
    
    # Setup output directory
    if not output_dir:
        output_dir = os.path.join(os.getcwd(), f'synth_{bug_id}')
    os.makedirs(output_dir, exist_ok=True)
    
    pddl_dir = os.path.join(output_dir, 'pddl')
    os.makedirs(pddl_dir, exist_ok=True)
    _debug(f"PDDL dir: {pddl_dir}", debug)
    
    # Generate PDDL
    gen = PDDLGenerator(platform=target_platform)
    _debug("PDDLGenerator created", debug)
    
    domain_path = gen.domain_path(pddl_dir)
    _debug(f"Domain generated: {domain_path}", debug)
    
    problem_path = gen.generate_problem_from_facts(
        f"{bug_id}_facts",
        facts,
        os.path.join(pddl_dir, 'problem.pddl'),
        goal
    )
    _debug(f"Problem generated: {problem_path}", debug)
    
    # Solve
    solver = PowerliftedSolver(debug=debug)
    _debug(f"PowerliftedSolver created, available={solver.available()}", debug)
    if not solver.available():
        _debug("Powerlifted not available!", debug)
        return {
            "success": False,
            "error": "Powerlifted not available",
            "pddl": {"domain": domain_path, "problem": problem_path}
        }
    
    _debug("Running solver...", debug)
    result = solver.solve(
        domain_path,
        problem_path,
        pddl_dir,
        time_limit=time_limit,
        verbose=verbose,
        debug=debug
    )
    _debug(f"Solver result: success={result.get('success')}", debug)
    
    if result.get('success') and result.get('plans'):
        _debug(f"Solution found! Parsing plan...", debug)
        for plan_file in result['plans']:
            result['parsed_plan'] = solver.parse_plan(plan_file)
            _debug(f"Parsed {len(result['parsed_plan'])} actions", debug)
            break
    else:
        _debug("No solution found or no plans", debug)
    
    return {
        "success": result.get('success', False),
        "powerlifted": result,
        "pddl": {"domain": domain_path, "problem": problem_path}
    }
