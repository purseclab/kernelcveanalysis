"""
pddl_generator.py

Generate PDDL problem files for kernel exploit synthesis.
This module is standalone and does not depend on chainreactor.
Supports both Linux and Android kernel exploitation.
"""

import json
import re
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple

from .core import Primitive
from .domains import KernelDomain, TargetPlatform


# Module-level debug flag
_DEBUG_ENABLED = False


def set_debug(enabled: bool):
    """Enable or disable debug output for this module."""
    global _DEBUG_ENABLED
    _DEBUG_ENABLED = enabled


def _debug(msg: str):
    """Print debug message if debug is enabled."""
    if _DEBUG_ENABLED:
        print(f"[DEBUG:PDDLGenerator] {msg}", file=sys.stderr)


class PDDLGenerator:
    """
    Generate PDDL problem files for kernel exploit synthesis.
    
    This generator creates problem files that work with the standalone
    kernel exploit domains (Linux or Android).
    """
    
    # Mapping from vulnerability types to PDDL predicates
    VULN_TO_PREDICATES = {
        'uaf': '(has_vulnerability UAF)',
        'use-after-free': '(has_vulnerability UAF)',
        'use_after_free': '(has_vulnerability UAF)',
        'oob_read': '(has_vulnerability OOB_READ)',
        'oob-read': '(has_vulnerability OOB_READ)',
        'out-of-bounds-read': '(has_vulnerability OOB_READ)',
        'oob_write': '(has_vulnerability OOB_WRITE)',
        'oob-write': '(has_vulnerability OOB_WRITE)',
        'out-of-bounds-write': '(has_vulnerability OOB_WRITE)',
        'race': '(has_vulnerability RACE)',
        'race_condition': '(has_vulnerability RACE)',
        'race-condition': '(has_vulnerability RACE)',
        'double_free': '(has_vulnerability DOUBLE_FREE)',
        'double-free': '(has_vulnerability DOUBLE_FREE)',
        'type_confusion': '(has_vulnerability TYPE_CONFUSION)',
        'type-confusion': '(has_vulnerability TYPE_CONFUSION)',
        'integer_overflow': '(has_vulnerability INTEGER_OVERFLOW)',
        'binder': '(has_vulnerability BINDER_BUG)',
    }
    
    # Mapping from capability names to PDDL predicates
    # NOTE: Only "primitive" capabilities should be in init state.
    # Goal capabilities (CODE_EXEC, CRED_OVERWRITE, etc.) should be derived.
    CAP_TO_PREDICATES = {
        'arb_read': '(has_capability ARB_READ)',
        'arb_write': '(has_capability ARB_WRITE)',
        'arbitrary_read': '(has_capability ARB_READ)',
        'arbitrary_write': '(has_capability ARB_WRITE)',
        'code_exec': '(has_capability CODE_EXEC)',
        'cred_overwrite': '(has_capability CRED_OVERWRITE)',
        'namespace_escape': '(has_capability NAMESPACE_ESCAPE)',
        'selinux_bypass': '(has_capability SELINUX_BYPASS)',
        'modprobe_hijack': '(has_capability MODPROBE_HIJACK)',
    }
    
    # Capabilities that represent GOAL states - should NOT be in init
    # These should be achieved through the plan, not given as initial facts
    GOAL_CAPABILITIES = {
        'CODE_EXEC', 'CRED_OVERWRITE', 'NAMESPACE_ESCAPE', 
        'SELINUX_BYPASS', 'MODPROBE_HIJACK',
    }
    
    # Capabilities that should be DERIVED if we have a suitable vulnerability
    # These should NOT be in init if we have UAF, OOB_WRITE, etc.
    DERIVED_CAPABILITIES = {
        'ARB_READ', 'ARB_WRITE',
    }
    
    # Vulnerabilities that can derive ARB_READ/ARB_WRITE capabilities
    # If we have these, ARB_READ/ARB_WRITE should be derived through the plan
    VULNS_THAT_DERIVE_CAPS = {'UAF', 'OOB_WRITE', 'BINDER_BUG', 'RACE'}
    
    # Platform-specific capability sets (constants defined in each domain)
    PLATFORM_CAPABILITIES = {
        TargetPlatform.GENERIC: {'ARB_READ', 'ARB_WRITE', 'CODE_EXEC', 'CRED_OVERWRITE', 'NAMESPACE_ESCAPE'},
        TargetPlatform.LINUX_KERNEL: {'ARB_READ', 'ARB_WRITE', 'CODE_EXEC', 'CRED_OVERWRITE', 'NAMESPACE_ESCAPE', 'MODPROBE_HIJACK'},
        TargetPlatform.ANDROID_KERNEL: {'ARB_READ', 'ARB_WRITE', 'CODE_EXEC', 'CRED_OVERWRITE', 'SELINUX_BYPASS'},
    }
    
    # Platform-specific vulnerability types
    PLATFORM_VULNERABILITIES = {
        TargetPlatform.GENERIC: {'UAF', 'OOB_READ', 'OOB_WRITE', 'RACE', 'DOUBLE_FREE', 'TYPE_CONFUSION'},
        TargetPlatform.LINUX_KERNEL: {'UAF', 'OOB_READ', 'OOB_WRITE', 'RACE', 'DOUBLE_FREE', 'TYPE_CONFUSION', 'INTEGER_OVERFLOW'},
        TargetPlatform.ANDROID_KERNEL: {'UAF', 'OOB_READ', 'OOB_WRITE', 'RACE', 'DOUBLE_FREE', 'TYPE_CONFUSION', 'BINDER_BUG'},
    }
    
    # Platform-specific target structures
    PLATFORM_TARGETS = {
        TargetPlatform.GENERIC: set(),
        TargetPlatform.LINUX_KERNEL: {'CRED_STRUCT', 'MSG_MSG', 'SEQ_OPERATIONS', 'TTYOPS', 'PIPE_BUFFER', 'SK_BUFF', 'TIMERFD_CTX'},
        TargetPlatform.ANDROID_KERNEL: {'BINDER_NODE', 'BINDER_REF', 'MSG_MSG', 'PIPE_BUFFER', 'SEQ_OPERATIONS'},
    }
    
    # Mapping from exploit technique names to PDDL predicates
    TECHNIQUE_TO_PREDICATES = {
        'msg_msg': '(heap_sprayed MSG_MSG)',
        'pipe_buffer': '(heap_sprayed PIPE_BUFFER)',
        'pipe_buf': '(heap_sprayed PIPE_BUFFER)',
        'sk_buff': '(heap_sprayed SK_BUFF)',
        'tty': '(heap_sprayed TTYOPS)',
        'seq_operations': '(heap_sprayed SEQ_OPERATIONS)',
        'binder_node': '(heap_sprayed BINDER_NODE)',
        'binder_ref': '(heap_sprayed BINDER_REF)',
        'kaslr_bypass': '(kaslr_bypassed)',
        'smep_bypass': '(smep_bypassed)',
        'smap_bypass': '(smap_bypassed)',
        'kpti_bypass': '(kpti_bypassed)',
        'pan_bypass': '(pan_bypassed)',
        'pac_bypass': '(pac_bypassed)',
        'mte_bypass': '(mte_bypassed)',
        'stack_pivot': '(stack_pivoted)',
        'rop': '(rop_chain_ready)',
        'jop': '(jop_chain_ready)',
        'info_leak': '(info_leak_available)',
    }
    
    # Techniques that should be DERIVED through the plan, not given as initial state
    # These represent intermediate/goal states that require exploitation steps
    DERIVED_TECHNIQUES = {
        '(rop_chain_ready)', '(jop_chain_ready)', '(stack_pivoted)',
        '(payload_prepared)', '(kaslr_bypassed)', '(smep_bypassed)',
        '(smap_bypassed)', '(kpti_bypassed)', '(pan_bypassed)',
        '(pac_bypassed)', '(mte_bypassed)',
        # Heap spray results should also be derived from heap_controlled
        '(heap_sprayed MSG_MSG)', '(heap_sprayed PIPE_BUFFER)',
        '(heap_sprayed SK_BUFF)', '(heap_sprayed TTYOPS)',
        '(heap_sprayed SEQ_OPERATIONS)', '(heap_sprayed BINDER_NODE)',
        '(heap_sprayed BINDER_REF)',
    }
        # Goal mappings
    GOAL_MAPPINGS = {
        'root': '(privilege_escalated)',
        'privilege_escalation': '(privilege_escalated)',
        'privesc': '(privilege_escalated)',
        'root_shell': '(root_shell)',
        'shell': '(root_shell)',
        'code_exec': '(kernel_code_execution)',
        'kernel_exec': '(kernel_code_execution)',
        'container_escape': '(container_escaped)',
        'sandbox_escape': '(escaped_sandbox)',
        'selinux': '(selinux_disabled)',
        'adb_root': '(adb_root)',
    }

    def __init__(self, platform: TargetPlatform = TargetPlatform.GENERIC,
                 analysis_dir: Optional[str] = None) -> None:
        """
        Initialize the PDDL generator.
        
        Args:
            platform: Target platform (LINUX_KERNEL, ANDROID_KERNEL, GENERIC)
            analysis_dir: Directory containing analysis results
        """
        self.platform = platform
        self.analysis_dir = Path(analysis_dir) if analysis_dir else None
        self.kernel_domain = KernelDomain(platform)
        
        # Get platform-specific valid constants
        self._valid_capabilities = self.PLATFORM_CAPABILITIES.get(platform, set())
        self._valid_vulnerabilities = self.PLATFORM_VULNERABILITIES.get(platform, set())
        self._valid_targets = self.PLATFORM_TARGETS.get(platform, set())
        # Track found vulnerabilities to determine what capabilities should be derived
        self._found_vulnerabilities: Set[str] = set()
    
    def _is_valid_capability_predicate(self, pred: str) -> bool:
        """Check if a capability predicate is valid for the current platform."""
        # Extract capability name from predicate like "(has_capability ARB_READ)"
        import re
        match = re.search(r'\(has_capability\s+(\w+)\)', pred)
        if match:
            cap_name = match.group(1)
            return cap_name in self._valid_capabilities
        return True  # Allow non-capability predicates
    
    def _should_derive_capability(self, pred: str) -> bool:
        """
        Check if a capability should be derived (not in init) because we have
        a vulnerability that can provide it through the plan.
        
        If we have UAF, OOB_WRITE, etc., ARB_READ/ARB_WRITE should be derived,
        not given as initial facts - this forces the planner to use the vuln.
        """
        import re
        match = re.search(r'\(has_capability\s+(\w+)\)', pred)
        if match:
            cap_name = match.group(1)
            # If this is a derived capability AND we have a vulnerability that can derive it
            if cap_name in self.DERIVED_CAPABILITIES:
                # Check if we have any vulnerability that can derive this capability
                if self._found_vulnerabilities & self.VULNS_THAT_DERIVE_CAPS:
                    return True  # Should be derived, not in init
        return False
    
    def _is_goal_capability(self, pred: str) -> bool:
        """Check if a capability is a goal (should never be in init)."""
        import re
        match = re.search(r'\(has_capability\s+(\w+)\)', pred)
        if match:
            cap_name = match.group(1)
            return cap_name in self.GOAL_CAPABILITIES
        return False
    
    def _is_valid_vulnerability_predicate(self, pred: str) -> bool:
        """Check if a vulnerability predicate is valid for the current platform."""
        import re
        match = re.search(r'\(has_vulnerability\s+(\w+)\)', pred)
        if match:
            vuln_name = match.group(1)
            return vuln_name in self._valid_vulnerabilities
        return True
    
    def _is_valid_target_predicate(self, pred: str) -> bool:
        """Check if a heap spray predicate is valid for the current platform."""
        import re
        match = re.search(r'\(heap_sprayed\s+(\w+)\)', pred)
        if match:
            target_name = match.group(1)
            return target_name in self._valid_targets
        return True
    
    @staticmethod
    def normalize_string(s: str) -> str:
        """
        Normalize a string for use in PDDL.
        Replaces special characters with underscores.
        PDDL identifiers cannot start with a digit.
        """
        result = s.replace('/', '_').replace('.', '_').replace('-', '_')
        result = result.replace(' ', '_').replace(':', '_')
        while result.startswith('_'):
            result = result[1:]
        result = result.lower()
        if result and result[0].isdigit():
            result = 'p_' + result
        return result
    
    def domain_path(self, output_dir: Optional[str] = None) -> str:
        """
        Generate and return the path to the domain file.
        
        Args:
            output_dir: Directory to write the domain file
            
        Returns:
            Path to the generated domain file
        """
        if output_dir:
            output_path = Path(output_dir) / 'domain.pddl'
        else:
            output_path = Path('/tmp') / f'{self.platform.value}_domain.pddl'
        
        self.kernel_domain.generate_domain(str(output_path))
        _debug(f"Generated domain at: {output_path}")
        return str(output_path)
    
    def generate_problem(self, problem_name: str, primitives: List[Primitive],
                         output_path: str, goal: str,
                         debug: bool = False) -> str:
        """
        Generate a PDDL problem file from primitives.
        
        Args:
            problem_name: Name for the PDDL problem
            primitives: List of exploit primitives
            output_path: Path to write the problem file
            goal: Goal description (e.g., "privilege escalation")
            debug: Enable debug output
            
        Returns:
            Path to the generated problem file
        """
        if debug:
            set_debug(True)
        
        _debug(f"Generating problem: {problem_name}")
        _debug(f"  platform: {self.platform}")
        _debug(f"  primitives: {len(primitives)}")
        _debug(f"  goal: {goal}")
        
        lines = []
        
        # Header
        domain_name = KernelDomain.get_domain_name(self.platform)
        normalized_name = self.normalize_string(problem_name)
        lines.append(f"(define (problem {normalized_name})")
        lines.append(f"  (:domain {domain_name})")
        
        # Objects section (empty for now - using constants from domain)
        lines.append("  (:objects")
        lines.append("  )")
        
        # Init section
        lines.append("  (:init")
        
        # FIRST PASS: Collect all vulnerabilities to determine what caps should be derived
        self._found_vulnerabilities = set()
        for prim in primitives:
            vuln_preds = self._extract_vulnerability_predicates(prim)
            for pred in vuln_preds:
                # Extract vuln name from "(has_vulnerability UAF)"
                import re
                match = re.search(r'\(has_vulnerability\s+(\w+)\)', pred)
                if match:
                    self._found_vulnerabilities.add(match.group(1))
        
        _debug(f"  found vulnerabilities: {self._found_vulnerabilities}")
        
        # Add vulnerability predicates from primitives
        added_predicates: Set[str] = set()
        
        lines.append("    ; Vulnerabilities from analysis")
        for prim in primitives:
            vuln_preds = self._extract_vulnerability_predicates(prim)
            for pred in vuln_preds:
                if pred not in added_predicates and self._is_valid_vulnerability_predicate(pred):
                    lines.append(f"    {pred}")
                    added_predicates.add(pred)
        
        # Add capability predicates - exclude both GOAL caps and DERIVED caps
        # DERIVED caps (ARB_READ/ARB_WRITE) should come from exploiting the vulnerability
        lines.append("    ; Capabilities from primitives")
        for prim in primitives:
            cap_preds = self._extract_capability_predicates(prim)
            for pred in cap_preds:
                # Must be valid for platform, not a goal cap, and not a derived cap
                if pred not in added_predicates and \
                   self._is_valid_capability_predicate(pred) and \
                   not self._is_goal_capability(pred) and \
                   not self._should_derive_capability(pred):
                    lines.append(f"    {pred}")
                    added_predicates.add(pred)
        
        # Add technique predicates - filter out derived techniques
        # Things like rop_chain_ready, heap_sprayed X should be derived through the plan
        lines.append("    ; Available techniques")
        for prim in primitives:
            tech_preds = self._extract_technique_predicates(prim)
            for pred in tech_preds:
                # Exclude derived techniques - they should come from exploitation
                if pred not in added_predicates and \
                   self._is_valid_target_predicate(pred) and \
                   pred not in self.DERIVED_TECHNIQUES:
                    lines.append(f"    {pred}")
                    added_predicates.add(pred)
        
        # Add facts from static analysis if available
        if self.analysis_dir:
            analysis_preds = self._extract_from_static_analysis()
            if analysis_preds:
                lines.append("    ; Facts from static analysis")
                for pred in analysis_preds:
                    # Filter all predicates - no derived/goal caps/techniques
                    if pred not in added_predicates:
                        if self._is_valid_capability_predicate(pred) and \
                           not self._is_goal_capability(pred) and \
                           not self._should_derive_capability(pred) and \
                           self._is_valid_vulnerability_predicate(pred) and \
                           self._is_valid_target_predicate(pred) and \
                           pred not in self.DERIVED_TECHNIQUES:
                            lines.append(f"    {pred}")
                            added_predicates.add(pred)
        
        # Android-specific initial state
        if self.platform == TargetPlatform.ANDROID_KERNEL:
            lines.append("    ; Android initial state")
            if '(in_untrusted_app)' not in added_predicates:
                lines.append("    (in_untrusted_app)")
                added_predicates.add('(in_untrusted_app)')
        
        lines.append("  )")
        
        # Goal section
        goal_pred = self._parse_goal(goal)
        lines.append(f"  (:goal {goal_pred})")
        
        lines.append(")")
        
        # Write to file
        content = '\n'.join(lines)
        Path(output_path).write_text(content)
        _debug(f"Generated problem at: {output_path}")
        
        return output_path
    
    def _extract_vulnerability_predicates(self, prim: Primitive) -> List[str]:
        """Extract vulnerability predicates from a primitive."""
        predicates = []
        
        name_lower = prim.name.lower()
        desc_lower = prim.description.lower()
        
        # Check provides field
        provides = prim.provides or {}
        vuln_type = provides.get('vuln_type', '') or provides.get('vulnerability', '')
        if vuln_type:
            vuln_type_lower = vuln_type.lower()
            if vuln_type_lower in self.VULN_TO_PREDICATES:
                predicates.append(self.VULN_TO_PREDICATES[vuln_type_lower])
        
        # Scan name and description for vulnerability keywords
        combined = f"{name_lower} {desc_lower}"
        for vuln_key, vuln_pred in self.VULN_TO_PREDICATES.items():
            if vuln_key.replace('_', '-') in combined or vuln_key.replace('-', '_') in combined:
                if vuln_pred not in predicates:
                    predicates.append(vuln_pred)
        
        return predicates
    
    def _extract_capability_predicates(self, prim: Primitive) -> List[str]:
        """Extract capability predicates from a primitive."""
        predicates = []
        
        name_lower = prim.name.lower()
        provides = prim.provides or {}
        
        # Check explicit capabilities
        caps = provides.get('caps', [])
        if isinstance(caps, str):
            caps = [caps]
        
        for cap in caps:
            cap_lower = cap.lower().replace('cap_', '')
            if cap_lower in self.CAP_TO_PREDICATES:
                predicates.append(self.CAP_TO_PREDICATES[cap_lower])
        
        # Infer from name
        if 'arb_read' in name_lower or 'arbitrary_read' in name_lower:
            predicates.append('(has_capability ARB_READ)')
        if 'arb_write' in name_lower or 'arbitrary_write' in name_lower:
            predicates.append('(has_capability ARB_WRITE)')
        if 'code_exec' in name_lower or 'rce' in name_lower:
            predicates.append('(has_capability CODE_EXEC)')
        if 'cred' in name_lower and 'overwrite' in name_lower:
            predicates.append('(has_capability CRED_OVERWRITE)')
        
        return list(set(predicates))
    
    def _extract_technique_predicates(self, prim: Primitive) -> List[str]:
        """Extract technique predicates from a primitive."""
        predicates = []
        
        name_lower = prim.name.lower()
        provides = prim.provides or {}
        
        # Check explicit techniques
        techniques = provides.get('techniques', [])
        if isinstance(techniques, str):
            techniques = [techniques]
        
        for tech in techniques:
            tech_lower = tech.lower()
            if tech_lower in self.TECHNIQUE_TO_PREDICATES:
                predicates.append(self.TECHNIQUE_TO_PREDICATES[tech_lower])
        
        # Infer from name
        for tech_key, tech_pred in self.TECHNIQUE_TO_PREDICATES.items():
            if tech_key in name_lower:
                if tech_pred not in predicates:
                    predicates.append(tech_pred)
        
        return predicates
    
    def _extract_from_static_analysis(self) -> List[str]:
        """Extract predicates from static analysis JSON."""
        predicates = []
        
        if not self.analysis_dir:
            return predicates
        
        static_path = self.analysis_dir / 'static_analysis.json'
        if not static_path.exists():
            return predicates
        
        try:
            data = json.loads(static_path.read_text())
            
            # Extract crash type
            crash_type = data.get('crash_type', '') or ''
            parsed = data.get('parsed', {}) or {}
            kind = parsed.get('kind', '') or ''
            
            combined = f"{crash_type} {kind}".lower()
            
            for vuln_key, vuln_pred in self.VULN_TO_PREDICATES.items():
                if vuln_key in combined:
                    if vuln_pred not in predicates:
                        predicates.append(vuln_pred)
            
            # Extract from classification
            classification = data.get('classification', {}) or {}
            vuln_type = classification.get('vulnerability', '') or classification.get('type', '')
            if vuln_type:
                vuln_lower = vuln_type.lower()
                for vuln_key, vuln_pred in self.VULN_TO_PREDICATES.items():
                    if vuln_key in vuln_lower:
                        if vuln_pred not in predicates:
                            predicates.append(vuln_pred)
            
            # Check exploitability analysis
            exploitability = data.get('exploitability', {}) or {}
            if exploitability.get('likely_exploitable'):
                # Add info leak if crash provides it
                if 'leak' in combined or 'info' in combined:
                    predicates.append('(info_leak_available)')
            
            # Check for heap control indicators
            if 'slab' in combined or 'kmalloc' in combined or 'heap' in combined:
                predicates.append('(heap_controlled)')
            
        except Exception as e:
            _debug(f"Error reading static analysis: {e}")
        
        return predicates
    
    def _parse_goal(self, goal: str) -> str:
        """Parse goal string into PDDL goal predicate."""
        goal_lower = goal.lower()
        
        # Check for known goals
        for goal_key, goal_pred in self.GOAL_MAPPINGS.items():
            if goal_key in goal_lower:
                return goal_pred
        
        # Default based on platform
        if self.platform == TargetPlatform.ANDROID_KERNEL:
            return '(root_shell)'
        else:
            return '(privilege_escalated)'
    
    def generate_problem_from_facts(self, problem_name: str,
                                    facts: Dict[str, Any],
                                    output_path: str,
                                    goal: str) -> str:
        """
        Generate a PDDL problem from pre-extracted facts.
        
        Args:
            problem_name: Name for the PDDL problem
            facts: Dictionary with facts (vulnerabilities, capabilities, techniques)
            output_path: Path to write the problem file
            goal: Goal description
            
        Returns:
            Path to the generated problem file
        """
        _debug(f"Generating problem from facts: {problem_name}")
        
        lines = []
        
        # Header
        domain_name = KernelDomain.get_domain_name(self.platform)
        normalized_name = self.normalize_string(problem_name)
        lines.append(f"(define (problem {normalized_name})")
        lines.append(f"  (:domain {domain_name})")
        
        # Objects (empty)
        lines.append("  (:objects")
        lines.append("  )")
        
        # Init
        lines.append("  (:init")
        
        added_predicates: Set[str] = set()
        
        # Add vulnerabilities
        vulns = facts.get('vulnerabilities', [])
        if vulns:
            lines.append("    ; Vulnerabilities")
            for vuln in vulns:
                vuln_lower = vuln.lower()
                if vuln_lower in self.VULN_TO_PREDICATES:
                    pred = self.VULN_TO_PREDICATES[vuln_lower]
                    if pred not in added_predicates:
                        lines.append(f"    {pred}")
                        added_predicates.add(pred)
        
        # Add capabilities
        caps = facts.get('capabilities', [])
        if caps:
            lines.append("    ; Initial capabilities")
            for cap in caps:
                cap_lower = cap.lower().replace('cap_', '')
                if cap_lower in self.CAP_TO_PREDICATES:
                    pred = self.CAP_TO_PREDICATES[cap_lower]
                    if pred not in added_predicates:
                        lines.append(f"    {pred}")
                        added_predicates.add(pred)
        
        # Add techniques
        techniques = facts.get('techniques', [])
        if techniques:
            lines.append("    ; Available techniques")
            for tech in techniques:
                tech_lower = tech.lower()
                if tech_lower in self.TECHNIQUE_TO_PREDICATES:
                    pred = self.TECHNIQUE_TO_PREDICATES[tech_lower]
                    if pred not in added_predicates:
                        lines.append(f"    {pred}")
                        added_predicates.add(pred)
        
        # Add state predicates
        state = facts.get('state', {})
        if state:
            lines.append("    ; State predicates")
            if state.get('heap_controlled'):
                lines.append("    (heap_controlled)")
            if state.get('info_leak'):
                lines.append("    (info_leak_available)")
            if state.get('kaslr_bypassed'):
                lines.append("    (kaslr_bypassed)")
        
        # Android-specific
        if self.platform == TargetPlatform.ANDROID_KERNEL:
            lines.append("    ; Android initial state")
            lines.append("    (in_untrusted_app)")
        
        lines.append("  )")
        
        # Goal
        goal_pred = self._parse_goal(goal)
        lines.append(f"  (:goal {goal_pred})")
        
        lines.append(")")
        
        content = '\n'.join(lines)
        Path(output_path).write_text(content)
        _debug(f"Generated problem at: {output_path}")
        
        return output_path
