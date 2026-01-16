"""
pddl_generator.py

Generate PDDL problem files for exploit synthesis using the chainreactor domain.
This module borrows patterns from chainreactor's encoder.py and uses its capabilities.toml
for mapping binaries to PDDL predicates.
"""

import json
import re
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple

try:
    import toml
    HAS_TOML = True
except ImportError:
    HAS_TOML = False

from .core import Primitive


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


class CapabilityMapper:
    """
    Maps binaries/primitives to PDDL capability predicates using chainreactor's
    capabilities.toml configuration.
    """
    
    # Fallback capability mappings if TOML not available
    DEFAULT_CAPABILITIES = {
        "read": ["CAP_read_file"],
        "write": ["CAP_write_file"],
        "download": ["CAP_download_file"],
        "upload": ["CAP_upload_file"],
        "change_permission": ["CAP_change_permission"],
        "shell": ["CAP_shell"],
        "command": ["CAP_command"],
        "change_file_owner": ["CAP_change_file_owner"],
    }
    
    # Known binary to capability mappings
    BINARY_CAPABILITIES = {
        "cat": ["CAP_read_file"],
        "less": ["CAP_read_file"],
        "vim": ["CAP_read_file", "CAP_write_file"],
        "nano": ["CAP_read_file", "CAP_write_file"],
        "tee": ["CAP_write_file"],
        "sed": ["CAP_write_file"],
        "cp": ["CAP_write_file"],
        "curl": ["CAP_download_file", "CAP_write_file"],
        "wget": ["CAP_download_file", "CAP_write_file"],
        "chmod": ["CAP_change_permission"],
        "chown": ["CAP_change_file_owner"],
        "bash": ["CAP_shell", "CAP_command"],
        "sh": ["CAP_shell", "CAP_command"],
        "python": ["CAP_command", "CAP_write_file"],
        "perl": ["CAP_command", "CAP_write_file"],
    }
    
    def __init__(self, chainreactor_root: Optional[Path] = None, debug: bool = False):
        self.chainreactor_root = chainreactor_root
        self.debug = debug
        self.capabilities: Dict[str, Dict[str, Any]] = {}
        self.cve_capabilities: Dict[str, Dict[str, Any]] = {}
        self._load_capabilities()
    
    def _load_capabilities(self) -> None:
        """Load capabilities from TOML files if available."""
        _debug(f"Loading capabilities, HAS_TOML={HAS_TOML}, root={self.chainreactor_root}")
        
        if not HAS_TOML:
            _debug("toml module not available, using fallback mappings")
            return
        if not self.chainreactor_root:
            _debug("chainreactor_root not set, using fallback mappings")
            return
        
        # Load main capabilities
        cap_file = self.chainreactor_root / 'modules' / 'resources' / 'capabilities.toml'
        _debug(f"Checking capabilities file: {cap_file}")
        if cap_file.exists():
            try:
                data = toml.load(cap_file)
                self.capabilities = data.get('capabilities', {})
                _debug(f"Loaded {len(self.capabilities)} capability groups from capabilities.toml")
            except Exception as e:
                _debug(f"Error loading capabilities.toml: {e}")
        else:
            _debug(f"capabilities.toml not found at {cap_file}")
        
        # Load CVE capabilities
        cve_file = self.chainreactor_root / 'modules' / 'resources' / 'CVE_capabilities.toml'
        _debug(f"Checking CVE capabilities file: {cve_file}")
        if cve_file.exists():
            try:
                data = toml.load(cve_file)
                self.cve_capabilities = data.get('capabilities', {})
                _debug(f"Loaded {len(self.cve_capabilities)} CVE capability groups")
            except Exception as e:
                _debug(f"Error loading CVE_capabilities.toml: {e}")
        else:
            _debug(f"CVE_capabilities.toml not found at {cve_file}")
    
    def get_binary_predicates(self, binary_name: str) -> List[str]:
        """Get PDDL capability predicates for a binary."""
        predicates = []
        
        # Check loaded TOML capabilities
        for cap_name, cap_data in self.capabilities.items():
            binaries = cap_data.get('binaries', [])
            for binary in binaries:
                if isinstance(binary, dict):
                    name = binary.get('name', '')
                else:
                    name = str(binary)
                if name.lower() == binary_name.lower():
                    predicates.extend(cap_data.get('predicates', []))
        
        # Check CVE capabilities
        for cap_name, cap_data in self.cve_capabilities.items():
            binaries = cap_data.get('binaries', [])
            for binary in binaries:
                if isinstance(binary, dict):
                    name = binary.get('name', '')
                else:
                    name = str(binary)
                if name.lower() == binary_name.lower():
                    predicates.extend(cap_data.get('predicates', []))
        
        # Fallback to hardcoded mappings
        if not predicates:
            predicates = self.BINARY_CAPABILITIES.get(binary_name.lower(), [])
        
        return list(set(predicates))
    
    def get_syscall_predicates(self, syscalls: List[str]) -> List[str]:
        """Map syscalls to capability predicates."""
        predicates = []
        
        syscall_mapping = {
            'open': ['CAP_read_file'],
            'read': ['CAP_read_file'],
            'stat': ['CAP_read_file'],
            'write': ['CAP_write_file'],
            'creat': ['CAP_write_file'],
            'chmod': ['CAP_change_permission'],
            'chown': ['CAP_change_file_owner'],
            'truncate': ['CAP_write_file'],
            'close': ['CAP_write_file'],
            'execve': ['CAP_command'],
            'clone': ['CAP_command'],
            'fork': ['CAP_command'],
        }
        
        for sc in syscalls:
            sc_lower = sc.lower().strip()
            if sc_lower in syscall_mapping:
                predicates.extend(syscall_mapping[sc_lower])
        
        return list(set(predicates))

    def get_capabilities(self, binary_name: str) -> List[str]:
        """
        Get capability predicates for a binary.
        Alias for get_binary_predicates for convenience.
        """
        return self.get_binary_predicates(binary_name)


class PDDLGenerator:
    """
    Generate PDDL problem files for exploit synthesis.
    
    Uses chainreactor's domain.pddl and generates problem files with:
    - Objects (users, groups, files, executables, etc.)
    - Init predicates (permissions, ownership, capabilities)
    - Goal conditions
    """

    # Valid capability predicates defined in the domain.pddl
    # Only these can be used in problem files
    VALID_DOMAIN_CAPS = {
        'CAP_write_file', 'CAP_read_file', 'CAP_upload_file', 'CAP_download_file',
        'CAP_change_permission', 'CAP_shell', 'CAP_command', 'CAP_change_file_owner',
        'CAP_cve_shell_command_injection', 'CAP_cve_shell_command_injection_needs_writable_directory',
        'CAP_CVE_write_any_file', 'CAP_CVE_read_any_file',
    }

    def __init__(self, chainreactor_root: str, analysis_dir: Optional[str] = None) -> None:
        self.chainreactor_root = Path(chainreactor_root) if chainreactor_root else None
        self.analysis_dir = Path(analysis_dir) if analysis_dir else None
        self.capability_mapper = CapabilityMapper(self.chainreactor_root)
        
        # Normalization cache for PDDL names
        self._name_cache: Dict[str, str] = {}

    def _is_valid_cap(self, cap: str) -> bool:
        """Check if capability predicate is valid in the domain."""
        return cap in self.VALID_DOMAIN_CAPS

    @staticmethod
    def normalize_string(s: str) -> str:
        """
        Normalize a string for use in PDDL (from chainreactor encoder).
        Replaces special characters with underscores.
        PDDL identifiers cannot start with a digit.
        """
        # Replace common special chars
        result = s.replace('/', '_').replace('.', '_').replace('-', '_')
        result = result.replace(' ', '_').replace(':', '_')
        # Remove leading underscores
        while result.startswith('_'):
            result = result[1:]
        # Ensure lowercase
        result = result.lower()
        # PDDL identifiers cannot start with a digit - prefix with 'p_'
        if result and result[0].isdigit():
            result = 'p_' + result
        return result

    def _default_objects(self) -> Dict[str, List[str]]:
        """Default PDDL objects for the problem.
        Note: FS_READ, FS_WRITE, FS_EXEC, SHELL, SYSFILE_PASSWD are constants 
        defined in the domain, not objects in the problem.
        """
        return {
            'user': ['attacker', 'root'],
            'group': ['g_attacker', 'g_root'],
            'executable': ['exploit_binary', 'target_exec'],
            'file': ['target_file', 'payload_file', 'passwd_file'],
            'directory': ['target_dir', 'tmp_dir'],
            'process': ['proc'],
            'data': ['payload_data'],
            'local': ['local'],
            'remote': ['remote'],
            # permission and purpose types use domain constants, not problem objects
        }

    def _header(self, problem_name: str) -> List[str]:
        """Generate PDDL problem header."""
        return [f"(define (problem {self.normalize_string(problem_name)})", "  (:domain micronix)"]

    def _objects_section(self, objs: Dict[str, List[str]]) -> List[str]:
        """Generate PDDL objects section."""
        lines = ["  (:objects"]
        
        # Output each type's objects on its own line
        type_order = ['user', 'group', 'executable', 'file', 'directory', 
                      'process', 'data', 'local', 'remote', 'permission', 'purpose']
        
        for obj_type in type_order:
            if obj_type in objs and objs[obj_type]:
                normalized = [self.normalize_string(o) for o in objs[obj_type]]
                unique = list(dict.fromkeys(normalized))  # Preserve order, remove duplicates
                lines.append(f"    {' '.join(unique)} - {obj_type}")
        
        lines.append("  )")
        return lines

    def _init_base_predicates(self, objs: Dict[str, List[str]]) -> List[str]:
        """Generate base init predicates (users, groups, ownership)."""
        lines = ["  (:init"]
        
        # User-group relationships
        lines.append("    ; User-group relationships")
        lines.append("    (user_group attacker g_attacker)")
        lines.append("    (user_group root g_root)")
        
        # Admin predicates
        lines.append("    (user_is_admin root)")
        lines.append("    (group_is_admin g_root)")
        
        # Controlled user (attacker starts with control)
        lines.append("    (controlled_user attacker)")
        
        # Exploit binary setup
        lines.append("    ; Exploit binary setup")
        lines.append("    (file_owner exploit_binary attacker g_attacker)")
        lines.append("    (user_file_permission attacker exploit_binary FS_EXEC)")
        lines.append("    (user_file_permission attacker exploit_binary FS_READ)")
        lines.append("    (user_file_permission attacker exploit_binary FS_WRITE)")
        lines.append("    (system_executable exploit_binary)")
        lines.append("    (file_present_at_location exploit_binary local)")
        
        # Target file/exec defaults
        lines.append("    ; Target files (owned by root)")
        lines.append("    (file_owner target_exec root g_root)")
        lines.append("    (file_present_at_location target_exec local)")
        lines.append("    (file_owner target_file root g_root)")
        lines.append("    (file_present_at_location target_file local)")
        
        # Passwd file - key for privilege escalation path
        lines.append("    ; Passwd file for privilege escalation")
        lines.append("    (file_owner passwd_file root g_root)")
        lines.append("    (file_present_at_location passwd_file local)")
        lines.append("    (file_purpose passwd_file SYSFILE_PASSWD)")
        # Kernel exploits can write anywhere, so passwd is writable
        lines.append("    (default_file_permission passwd_file FS_WRITE)")
        
        # Tmp directory (world writable)
        lines.append("    ; Temporary directory (world writable)")
        lines.append("    (directory_owner tmp_dir root g_root)")
        lines.append("    (default_directory_permission tmp_dir FS_WRITE)")
        lines.append("    (default_directory_permission tmp_dir FS_READ)")
        
        return lines

    def _capability_predicates_from_primitives(self, primitives: List[Primitive]) -> List[str]:
        """Generate capability predicates from primitives.
        Only adds capabilities that are defined in the domain.pddl.
        """
        lines = []
        added_caps: Set[str] = set()
        
        lines.append("    ; Capabilities from primitives")
        
        def add_cap(cap: str) -> None:
            """Add capability if valid and not already added."""
            if cap and cap not in added_caps and self._is_valid_cap(cap):
                lines.append(f"    ({cap} exploit_binary)")
                added_caps.add(cap)
        
        for prim in primitives:
            # Check provides for explicit capabilities
            provides = prim.provides or {}
            
            # Single cap
            cap = provides.get('cap')
            if isinstance(cap, str):
                add_cap(cap)
            
            # Multiple caps
            caps = provides.get('caps') or []
            for c in caps:
                if isinstance(c, str):
                    add_cap(c)
            
            # Map primitive name to capabilities
            name = prim.name.lower()
            if 'read' in name:
                add_cap('CAP_read_file')
            if 'write' in name:
                add_cap('CAP_write_file')
            if 'arb' in name or 'arbitrary' in name:
                add_cap('CAP_write_file')
                add_cap('CAP_read_file')
                add_cap('CAP_shell')  # Arbitrary write can lead to shell
            if 'exec' in name or 'shell' in name or 'command' in name:
                add_cap('CAP_command')
                add_cap('CAP_shell')
            if 'xdk_' in name or 'privilege' in name or 'root' in name or 'cred' in name:
                # Kernel exploit primitives that give shell access
                add_cap('CAP_command')
                add_cap('CAP_shell')
        
        # For kernel exploits, always add CAP_shell since they typically provide root
        if any('kernel' in (p.source or '').lower() or 'xdk' in p.name.lower() 
               for p in primitives):
            add_cap('CAP_shell')
        
        return lines

    def _facts_from_static_analysis(self) -> Tuple[List[str], Set[str]]:
        """Extract facts from static analysis JSON if available."""
        lines = []
        added_caps: Set[str] = set()
        
        if not self.analysis_dir:
            return lines, added_caps
        
        static_path = self.analysis_dir / 'static_analysis.json'
        if not static_path.exists():
            return lines, added_caps
        
        try:
            data = json.loads(static_path.read_text())
            
            lines.append("    ; Facts from static analysis")
            
            # Extract syscalls from various sources
            syscalls: List[str] = []
            
            # From parsed raw text
            raw = (data.get('parsed', {}) or {}).get('raw', '')
            for match in re.finditer(r"__x64_sys_([a-z0-9_]+)", raw):
                syscalls.append(match.group(1))
            
            # From classification support
            support = (data.get('classification', {}) or {}).get('support', [])
            for s in support or []:
                if isinstance(s, str) and 'Syscall(s) detected' in s:
                    m = re.search(r':\s*([A-Za-z_,\s]+)$', s)
                    if m:
                        syscalls.extend([x.strip().lower() for x in m.group(1).split(',') if x.strip()])
            
            # Map syscalls to predicates
            cap_preds = self.capability_mapper.get_syscall_predicates(list(set(syscalls)))
            for pred in cap_preds:
                if pred not in added_caps:
                    lines.append(f"    ({pred} exploit_binary)")
                    added_caps.add(pred)
            
            # Check for crash type hints
            crash_type = data.get('crash_type', '') or data.get('classification', {}).get('type', '')
            if 'use-after-free' in crash_type.lower() or 'uaf' in crash_type.lower():
                if 'CAP_write_file' not in added_caps:
                    lines.append("    (CAP_write_file exploit_binary)")
                    added_caps.add('CAP_write_file')
            
        except Exception:
            pass
        
        return lines, added_caps

    def _goal_section(self, goal: str) -> List[str]:
        """Generate PDDL goal section based on goal description."""
        goal_lower = goal.lower()
        
        # Determine goal predicate
        if 'root' in goal_lower or 'priv' in goal_lower or 'escalat' in goal_lower:
            return ["  (:goal (controlled_user root))", ")"]
        elif 'read' in goal_lower:
            return ["  (:goal (user_can_read_file attacker g_attacker target_file))", ")"]
        elif 'write' in goal_lower:
            return ["  (:goal (user_can_write_file attacker g_attacker target_file))", ")"]
        else:
            # Default: privilege escalation
            return ["  (:goal (controlled_user root))", ")"]

    def generate_problem(self, problem_name: str, primitives: List[Primitive], 
                         out_path: str, goal: str, debug: bool = False) -> str:
        """
        Generate a PDDL problem file.
        
        Args:
            problem_name: Name for the problem
            primitives: List of primitives to include
            out_path: Output file path
            goal: Goal description string
            debug: Enable debug output
            
        Returns:
            Path to generated problem file
        """
        if debug:
            set_debug(True)
        
        _debug(f"generate_problem() called")
        _debug(f"  problem_name: {problem_name}")
        _debug(f"  primitives: {[p.name for p in primitives]}")
        _debug(f"  out_path: {out_path}")
        _debug(f"  goal: {goal}")
        
        objs = self._default_objects()
        _debug(f"  default objects: {list(objs.keys())}")
        
        # Build the problem
        lines: List[str] = []
        lines += self._header(problem_name)
        lines += self._objects_section(objs)
        _debug(f"  generated header and objects section ({len(lines)} lines)")
        
        # Init section
        init_lines = self._init_base_predicates(objs)
        _debug(f"  base predicates: {len(init_lines)} lines")
        
        cap_lines = self._capability_predicates_from_primitives(primitives)
        init_lines += cap_lines
        _debug(f"  capability predicates: {len(cap_lines)} lines")
        
        static_lines, static_caps = self._facts_from_static_analysis()
        init_lines += static_lines
        _debug(f"  static analysis facts: {len(static_lines)} lines, caps: {static_caps}")
        
        init_lines.append("  )")
        lines += init_lines
        
        # Goal section
        goal_lines = self._goal_section(goal)
        lines += goal_lines
        _debug(f"  goal section: {goal_lines}")
        
        # Write output
        content = "\n".join(lines) + "\n"
        _debug(f"  total PDDL content: {len(content)} chars, {len(lines)} lines")
        
        out_file = Path(out_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(content)
        _debug(f"  wrote to: {out_file}")
        
        return str(out_file)

    def domain_path(self) -> str:
        """Get path to the chainreactor domain.pddl file."""
        if not self.chainreactor_root:
            raise RuntimeError("ChainReactor root not set")
        d = self.chainreactor_root / 'domain.pddl'
        if not d.exists():
            raise FileNotFoundError(f"Domain not found at {d}")
        return str(d)

    def generate_problem_from_facts(self, problem_name: str, 
                                    facts: Dict[str, Any],
                                    out_path: str, 
                                    goal: str) -> str:
        """
        Generate a PDDL problem from extracted system facts.
        
        This is a more advanced method that takes pre-extracted facts
        (similar to chainreactor's FactsContainer) and generates
        a problem file.
        
        Args:
            problem_name: Name for the problem
            facts: Dictionary containing system facts
            out_path: Output file path
            goal: Goal description string
            
        Returns:
            Path to generated problem file
        """
        objs = self._default_objects()
        
        # Add users from facts
        if 'users' in facts:
            for user in facts['users']:
                user_obj = f"{self.normalize_string(user)}_u"
                group_obj = f"{self.normalize_string(user)}_g"
                if user_obj not in objs['user']:
                    objs['user'].append(user_obj)
                if group_obj not in objs['group']:
                    objs['group'].append(group_obj)
        
        # Add executables from facts
        if 'executables' in facts:
            for exe in facts['executables']:
                exe_obj = self.normalize_string(exe)
                if exe_obj not in objs['executable']:
                    objs['executable'].append(exe_obj)
                if exe_obj not in objs['file']:
                    objs['file'].append(exe_obj)
        
        # Build problem
        lines: List[str] = []
        lines += self._header(problem_name)
        lines += self._objects_section(objs)
        
        # Init section with enhanced facts
        init_lines = self._init_base_predicates(objs)
        
        # Add user-group predicates from facts
        if 'users' in facts:
            for user in facts['users']:
                u = f"{self.normalize_string(user)}_u"
                g = f"{self.normalize_string(user)}_g"
                init_lines.append(f"    (user_group {u} {g})")
                if user == 'root':
                    init_lines.append(f"    (user_is_admin {u})")
                    init_lines.append(f"    (group_is_admin {g})")
        
        # Add executable capabilities from facts
        if 'executables' in facts:
            for exe in facts['executables']:
                exe_name = self.normalize_string(exe)
                # Get capabilities for this binary
                binary_name = exe.split('/')[-1] if '/' in exe else exe
                caps = self.capability_mapper.get_binary_predicates(binary_name)
                for cap in caps:
                    init_lines.append(f"    ({cap} {exe_name})")
        
        init_lines.append("  )")
        lines += init_lines
        
        # Goal section
        lines += self._goal_section(goal)
        
        # Write output
        content = "\n".join(lines) + "\n"
        out_file = Path(out_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(content)
        
        return str(out_file)
