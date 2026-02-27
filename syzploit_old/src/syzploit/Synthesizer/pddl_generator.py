"""
pddl_generator.py

Generates PDDL problem files for kernel exploit planning.

This module:
1. Loads predicate mappings from config/*.json instead of hardcoded dicts
2. Auto-populates the problem init from SyzAnalyze primitives
3. Models the PoC as a PDDL action that contributes its effects to init
4. Generates goal predicates from user-specified goals

All hardcoded VULN_TO_PREDICATES, CAP_TO_PREDICATES, TECHNIQUE_TO_PREDICATES,
and GOAL_MAPPINGS have been moved to config/*.json files.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Any, Set

from .core import Primitive
from .domains import KernelDomain, TargetPlatform

# Module-level debug flag
_DEBUG = False


def set_debug(val: bool) -> None:
    global _DEBUG
    _DEBUG = val


def _debug(msg: str) -> None:
    if _DEBUG:
        print(f"  [PDDLGen] {msg}")


def _config_dir() -> Path:
    """Return the config/ directory path."""
    return Path(__file__).parent / "config"


def _load_config(name: str) -> Dict[str, Any]:
    """Load a JSON config file from the config/ directory."""
    path = _config_dir() / f"{name}.json"
    if path.exists():
        with open(path) as f:
            data = json.load(f)
        # Remove documentation key
        data.pop("_doc", None)
        return data
    _debug(f"Config file not found: {path}")
    return {}


# Lazy-loaded config caches
_VULN_PREDICATES: Optional[Dict[str, List[str]]] = None
_CAP_PREDICATES: Optional[Dict[str, List[str]]] = None
_TECHNIQUE_PREDICATES: Optional[Dict[str, List[str]]] = None
_GOAL_PREDICATES: Optional[Dict[str, List[str]]] = None


def _get_vuln_predicates() -> Dict[str, List[str]]:
    global _VULN_PREDICATES
    if _VULN_PREDICATES is None:
        _VULN_PREDICATES = _load_config("vuln_predicates")
    return _VULN_PREDICATES


def _get_cap_predicates() -> Dict[str, List[str]]:
    global _CAP_PREDICATES
    if _CAP_PREDICATES is None:
        _CAP_PREDICATES = _load_config("capability_predicates")
    return _CAP_PREDICATES


def _get_technique_predicates() -> Dict[str, List[str]]:
    global _TECHNIQUE_PREDICATES
    if _TECHNIQUE_PREDICATES is None:
        _TECHNIQUE_PREDICATES = _load_config("technique_predicates")
    return _TECHNIQUE_PREDICATES


def _get_goal_predicates() -> Dict[str, List[str]]:
    global _GOAL_PREDICATES
    if _GOAL_PREDICATES is None:
        _GOAL_PREDICATES = _load_config("goal_predicates")
    return _GOAL_PREDICATES


# Capabilities that should NOT be in init if they can be derived by the planner.
# These represent *outcomes* of exploit steps, not starting conditions.
# The vulnerability gives us (has_vuln X) and (vuln_triggered X); everything
# else must be achieved by the planner through domain actions.
DERIVED_CAPABILITIES = {
    # Exploit outcomes that must be built up by the planner
    "CAP_ARB_READ", "CAP_ARB_WRITE", "CAP_CODE_EXEC",
    "CAP_CRED_OVERWRITE", "CAP_NAMESPACE_ESCAPE",
    "CAP_KASLR_BYPASS", "CAP_SMEP_BYPASS", "CAP_SMAP_BYPASS",
    "CAP_PAN_BYPASS", "CAP_PAC_BYPASS", "CAP_MTE_BYPASS",
    "CAP_SELINUX_DISABLE",
    # Heap/spray capabilities that are steps in the exploitation chain,
    # not starting conditions:
    "CAP_HEAP_CONTROL", "CAP_HEAP_SPRAY", "CAP_CROSS_CACHE",
    "CAP_INFO_LEAK", "CAP_STACK_PIVOT", "CAP_ROP_CHAIN", "CAP_JOP_CHAIN",
    "CAP_RIP_CONTROL",
    # Vulnerability sub-capabilities (UAF/OOB gives you (has_vuln X),
    # but the read/write/spray steps must still be planned):
    "CAP_UAF_READ", "CAP_UAF_WRITE", "CAP_SEQ_OPS_SPRAY",
    "CAP_SLAB_TARGET", "CAP_PRIVILEGE_ESCALATION",
    "CAP_PIPE_BUF", "CAP_MSG_MSG", "CAP_DIRTY_PAGETABLE",
    "CAP_KERNEL_WRITE", "CAP_KERNEL_READ",
    "CAP_RET2USR", "CAP_TELEFORK", "CAP_FORK",
    "CAP_CONTAINER_ESCAPE", "CAP_ROOT",
    "CAP_KERNEL_SLEEP", "CAP_TIMING_CONTROL",
    "CAP_GADGET_FINDER", "CAP_PAYLOAD_GEN",
    "CAP_TARGET_DETECTION", "CAP_SYMBOL_RESOLUTION", "CAP_STRUCT_INFO",
}

# Capabilities that are goals and should not be in init
GOAL_CAPABILITIES = {
    "CAP_CODE_EXEC", "CAP_CRED_OVERWRITE", "CAP_NAMESPACE_ESCAPE",
    "CAP_PRIVILEGE_ESCALATION", "CAP_ROOT",
}


def generate_poc_action(analysis_data: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """
    Generate a PDDL action representing the PoC's effects.

    Analyzes the SyzAnalyze data to determine what the PoC trigger provides
    (e.g., UAF in a specific slab cache) and encodes it as a PDDL action.

    Returns:
        PDDL action string, or None if insufficient data.
    """
    if not analysis_data:
        return None

    parsed = analysis_data.get("parsed", {})
    vuln_type = parsed.get("vulnerability_type", "").lower()
    subsystem = parsed.get("subsystem", "unknown")
    slab_cache = parsed.get("slab_cache", "")

    if not vuln_type:
        return None

    # Map vulnerability type to effects
    vuln_map = _get_vuln_predicates()
    effects = []

    for vtype_key, predicates in vuln_map.items():
        if vtype_key in vuln_type or vuln_type in vtype_key:
            effects.extend(predicates)
            break

    if not effects:
        effects = ["(has_vuln UAF)", "(vuln_triggered UAF)"]

    # Deduplicate
    effects = list(dict.fromkeys(effects))

    effect_str = " ".join(effects)

    action = f"""  (:action poc_trigger
    :parameters ()
    :precondition (and (running_context USERSPACE))
    :effect (and {effect_str})
  )"""

    _debug(f"Generated PoC action for {vuln_type} in {subsystem}")
    return action


class PDDLGenerator:
    """
    Generates PDDL problem files for kernel exploit planning.

    Uses config-loaded mappings instead of hardcoded dictionaries.
    Supports auto-population from SyzAnalyze primitives and PoC modeling.
    """

    def __init__(self, platform: TargetPlatform = TargetPlatform.GENERIC,
                 analysis_dir: Optional[str] = None,
                 available_techniques: Optional[List[str]] = None):
        self.platform = platform
        self.analysis_dir = analysis_dir
        self.available_techniques = available_techniques
        self._domain = KernelDomain(
            platform=platform,
            available_techniques=available_techniques,
        )

    def domain_path(self, output_dir: str,
                    analysis_data: Optional[Dict[str, Any]] = None) -> str:
        """
        Generate and write the PDDL domain file.

        If analysis_data is provided, a PoC-derived action is injected.
        """
        os.makedirs(output_dir, exist_ok=True)
        path = os.path.join(output_dir, "domain.pddl")

        # Generate PoC action if we have analysis data
        extra_actions = []
        poc_action = generate_poc_action(analysis_data)
        if poc_action:
            extra_actions.append(poc_action)

        self._domain.generate_domain(output_path=path, extra_actions=extra_actions or None)
        _debug(f"Domain written to {path}")
        return path

    def generate_problem(self, problem_name: str,
                         primitives: List[Primitive],
                         output_path: str,
                         goal: str,
                         debug: bool = False,
                         analysis_data: Optional[Dict[str, Any]] = None) -> str:
        """
        Generate a PDDL problem file from primitives and analysis data.

        This replaces the old version that used hardcoded mapping dicts.
        Now loads mappings from config/*.json.
        """
        if debug:
            set_debug(True)

        _debug(f"Generating problem: {problem_name}")
        _debug(f"  Platform: {self.platform}")
        _debug(f"  Primitives: {len(primitives)}")
        _debug(f"  Goal: {goal}")

        # Collect init predicates from primitives
        init_predicates: Set[str] = set()
        init_predicates.add("(running_context USERSPACE)")

        # Add platform-specific context
        if self.platform == TargetPlatform.ANDROID_KERNEL:
            init_predicates.add("(kaslr_active)")

            # Check for specific mitigations from analysis
            if analysis_data:
                raw = analysis_data.get("parsed", {}).get("raw", "").lower()
                if "pan" in raw or "arm64" in raw:
                    init_predicates.add("(pan_active)")
                if "pac" in raw:
                    init_predicates.add("(pac_active)")
                if "mte" in raw:
                    init_predicates.add("(mte_active)")
                if "selinux" in raw:
                    init_predicates.add("(selinux_active)")
        elif self.platform == TargetPlatform.LINUX_KERNEL:
            init_predicates.add("(kaslr_active)")
            if analysis_data:
                raw = analysis_data.get("parsed", {}).get("raw", "").lower()
                if "smep" in raw:
                    init_predicates.add("(smep_active)")
                if "smap" in raw:
                    init_predicates.add("(smap_active)")
                if "kpti" in raw:
                    init_predicates.add("(kpti_active)")
        else:
            init_predicates.add("(kaslr_active)")

        # Process primitives to extract capabilities
        vuln_preds = _get_vuln_predicates()
        cap_preds = _get_cap_predicates()
        tech_preds = _get_technique_predicates()

        # Sources whose primitives describe the vulnerability / trace evidence
        # and therefore *may* contribute to the PDDL init state.
        # Library / tool primitives (e.g. kernel-research/libxdk) describe what
        # techniques are *available*, not what state is already achieved — those
        # are modelled by the domain actions, not by init predicates.
        INIT_SOURCES = {"static", "trace_analysis", "syzbot", "cve_analysis", ""}

        for prim in primitives:
            prim_source = prim.provides.get("source", "")

            # Library tool primitives do NOT contribute to init state.
            # They describe available building blocks (ROP gadgets, heap
            # spray techniques, etc.) that the planner must assemble via
            # domain actions — they are NOT "already done".
            if prim_source and prim_source not in INIT_SOURCES:
                _debug(f"  Skipping library primitive '{prim.name}' (source={prim_source})")
                continue

            caps = prim.provides.get("caps", [])
            if isinstance(caps, str):
                caps = [caps]

            for cap in caps:
                cap_upper = cap.upper()

                # Skip derived capabilities — let the planner figure these out
                if cap_upper in DERIVED_CAPABILITIES:
                    _debug(f"  Skipping derived capability: {cap}")
                    continue

                # Skip goal capabilities
                if cap_upper in GOAL_CAPABILITIES:
                    _debug(f"  Skipping goal capability: {cap}")
                    continue

                # Look up in capability predicates
                if cap_upper in cap_preds:
                    for pred in cap_preds[cap_upper]:
                        init_predicates.add(pred)
                        _debug(f"  Added cap predicate: {pred}")

            # Check for vulnerability info in the primitive
            vuln_type = prim.provides.get("vulnerability_type", "")
            if vuln_type:
                vt_lower = vuln_type.lower()
                for vt_key, preds in vuln_preds.items():
                    if vt_key in vt_lower or vt_lower in vt_key:
                        for pred in preds:
                            init_predicates.add(pred)
                            _debug(f"  Added vuln predicate: {pred}")
                        break

            # Check for technique info — only from vulnerability/trace sources
            technique = prim.provides.get("technique", "")
            if technique:
                t_lower = technique.lower()
                if t_lower in tech_preds:
                    for pred in tech_preds[t_lower]:
                        init_predicates.add(pred)
                        _debug(f"  Added technique predicate: {pred}")

        # Extract vulnerability type from analysis data if available
        if analysis_data:
            # Check multiple locations where vuln type might live:
            #   1. top-level "vuln_type" (from cve_analyzer)
            #   2. "parsed.vulnerability_type" (from syzbot crash analyzer)
            #   3. "parsed.kind" (KASAN report string, e.g. "Use-after-free in ...")
            vuln_type = (
                analysis_data.get("vuln_type", "")
                or analysis_data.get("parsed", {}).get("vulnerability_type", "")
                or ""
            ).lower().replace("-", "_")

            # Also try to infer from parsed.kind (e.g. "Use-after-free in binder_...")
            if not vuln_type:
                kind = analysis_data.get("parsed", {}).get("kind", "").lower()
                if "use-after-free" in kind or "use_after_free" in kind:
                    vuln_type = "uaf"
                elif "out-of-bounds" in kind or "slab-out-of-bounds" in kind:
                    vuln_type = "oob_write" if "write" in kind else "oob_read"
                elif "double-free" in kind or "double free" in kind:
                    vuln_type = "double_free"
                elif "null-ptr-deref" in kind:
                    vuln_type = "null_deref"
                elif "data-race" in kind or "race" in kind:
                    vuln_type = "race_condition"

            if vuln_type:
                _debug(f"  Vuln type from analysis data: {vuln_type}")
                matched = False
                for vt_key, preds in vuln_preds.items():
                    if vt_key in vuln_type or vuln_type in vt_key:
                        for pred in preds:
                            init_predicates.add(pred)
                            _debug(f"  Added vuln init predicate: {pred}")
                        matched = True
                        break
                if not matched:
                    # Fallback: at least ensure has_vuln UAF for common case
                    _debug(f"  No vuln predicate match for '{vuln_type}', adding generic UAF")
                    init_predicates.add("(has_vuln UAF)")
                    init_predicates.add("(vuln_triggered UAF)")

        # Build goal predicates
        goal_preds = _get_goal_predicates()
        goal_predicates: List[str] = []
        goal_lower = goal.lower().replace("-", "_").replace(" ", "_")

        if goal_lower in goal_preds:
            goal_predicates.extend(goal_preds[goal_lower])
        else:
            # Fuzzy match
            for gk, gp in goal_preds.items():
                if gk in goal_lower or goal_lower in gk:
                    goal_predicates.extend(gp)
                    break

        if not goal_predicates:
            goal_predicates = ["(privilege_escalated)"]
            _debug(f"  No goal match for '{goal}', defaulting to privilege_escalated")

        # Generate the PDDL problem text
        problem_text = self._format_problem(
            problem_name,
            sorted(init_predicates),
            goal_predicates,
            analysis_data=analysis_data,
        )

        # Write to file
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            f.write(problem_text)

        _debug(f"Problem written to {output_path}")
        _debug(f"  Init predicates: {len(init_predicates)}")
        _debug(f"  Goal predicates: {goal_predicates}")

        return output_path

    def generate_problem_from_facts(self, problem_name: str,
                                    facts: Dict[str, Any],
                                    output_path: str,
                                    goal: str) -> str:
        """
        Generate a PDDL problem from pre-extracted vulnerability facts.

        Facts dict should contain:
        - vulnerabilities: List[str] — vulnerability types
        - capabilities: List[str] — available capabilities
        - techniques: List[str] — available techniques
        - state: Dict[str, bool] — state flags
        """
        _debug(f"Generating problem from facts: {list(facts.keys())}")

        init_predicates: Set[str] = set()
        init_predicates.add("(running_context USERSPACE)")
        init_predicates.add("(kaslr_active)")

        vuln_preds = _get_vuln_predicates()
        cap_preds = _get_cap_predicates()
        tech_preds = _get_technique_predicates()
        goal_preds_map = _get_goal_predicates()

        # Process vulnerabilities
        for vuln in facts.get("vulnerabilities", []):
            v_lower = vuln.lower()
            for vt_key, preds in vuln_preds.items():
                if vt_key in v_lower or v_lower in vt_key:
                    for pred in preds:
                        init_predicates.add(pred)
                    break

        # Process capabilities (skip derived ones)
        for cap in facts.get("capabilities", []):
            cap_upper = cap.upper()
            if cap_upper not in DERIVED_CAPABILITIES and cap_upper not in GOAL_CAPABILITIES:
                if cap_upper in cap_preds:
                    for pred in cap_preds[cap_upper]:
                        init_predicates.add(pred)

        # Process techniques
        for tech in facts.get("techniques", []):
            t_lower = tech.lower()
            if t_lower in tech_preds:
                for pred in tech_preds[t_lower]:
                    init_predicates.add(pred)

        # Process state flags
        state = facts.get("state", {})
        if state.get("heap_controlled"):
            init_predicates.add("(heap_controlled)")
        if state.get("info_leak"):
            init_predicates.add("(has_info_leak)")
        if state.get("kaslr_bypassed"):
            init_predicates.add("(kaslr_bypassed)")

        # Build goal
        goal_predicates: List[str] = []
        goal_lower = goal.lower().replace("-", "_").replace(" ", "_")
        if goal_lower in goal_preds_map:
            goal_predicates.extend(goal_preds_map[goal_lower])
        else:
            for gk, gp in goal_preds_map.items():
                if gk in goal_lower or goal_lower in gk:
                    goal_predicates.extend(gp)
                    break
        if not goal_predicates:
            goal_predicates = ["(privilege_escalated)"]

        problem_text = self._format_problem(
            problem_name,
            sorted(init_predicates),
            goal_predicates,
        )

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            f.write(problem_text)

        return output_path

    def _format_problem(self, name: str,
                        init_preds: List[str],
                        goal_preds: List[str],
                        analysis_data: Optional[Dict[str, Any]] = None) -> str:
        """Format the PDDL problem text."""
        init_block = "\n    ".join(init_preds)
        goal_block = " ".join(goal_preds)
        if len(goal_preds) > 1:
            goal_block = f"(and {goal_block})"

        # Extract vulnerability metadata for the header comment
        vuln_lines = []
        if analysis_data:
            bug_id = (
                analysis_data.get("cve_metadata", {}).get("cve_id", "")
                or analysis_data.get("bug_id", "")
                or ""
            )
            vuln_type = analysis_data.get("vuln_type", "")
            target_struct = analysis_data.get("target_struct", "")
            slab_cache = analysis_data.get("slab_cache", "")
            if bug_id:
                vuln_lines.append(f";; Bug ID: {bug_id}")
            if vuln_type:
                vuln_lines.append(f";; Vulnerability: {vuln_type}")
            if target_struct:
                vuln_lines.append(f";; Target struct: {target_struct}")
            if slab_cache:
                vuln_lines.append(f";; Slab cache: {slab_cache}")
        vuln_header = "\n".join(vuln_lines)
        if vuln_header:
            vuln_header = "\n" + vuln_header

        return f""";; Auto-generated PDDL problem for kernel exploit synthesis
;; Platform: {self.platform.value}{vuln_header}
;;
;; NOTE: All typed constants (vuln_primitive, capability, target_struct)
;; are declared in the domain file as (:constants ...).  Do NOT re-declare
;; them here as (:objects) — the PDDL parser would reject duplicates or
;; (worse) fail to resolve them when parsing the domain actions first.

(define (problem {name})
  (:domain kernel-exploit)

  (:init
    {init_block}
  )

  (:goal
    {goal_block}
  )
)
"""
