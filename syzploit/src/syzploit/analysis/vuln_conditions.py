"""
analysis.vuln_conditions — Pre/post condition analysis for CVE/vulnerability.

Generates structured preconditions (input constraints + kernel state
requirements) and postconditions (capabilities gained) for a given
vulnerability.  This feeds directly into exploit planning and generation
to ensure each phase's requirements are met.

Preconditions:
  - Input constraints: syscall args, ioctl commands, race timing, data sizes
  - Kernel state constraints: CONFIG_ options, module loaded, slab cache
    existence, KASAN/KASLR status, SELinux mode, refcount windows

Postconditions:
  - Capabilities: UAF dangling pointer, controlled data in freed region,
    arbitrary R/W, kernel address leak, cred overwrite, IP control

This module:
1. Extracts conditions from the RootCauseAnalysis + CrashReport
2. Enriches with exploit_knowledge technique dependencies
3. Generates an LLM prompt to discover implicit conditions from source
4. Produces a ``VulnConditions`` model consumed by planner and generator
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from ..core.log import console


# ── Condition taxonomy ────────────────────────────────────────────────


class ConditionCategory(str, Enum):
    """Category of a pre/post condition."""
    SYSCALL_INPUT = "syscall_input"
    IOCTL_INPUT = "ioctl_input"
    TIMING = "timing"
    MEMORY_LAYOUT = "memory_layout"
    KERNEL_CONFIG = "kernel_config"
    MODULE_STATE = "module_state"
    PROCESS_STATE = "process_state"
    SLAB_STATE = "slab_state"
    REFCOUNT = "refcount"
    SELINUX = "selinux"
    CAPABILITY = "capability"
    DEVICE = "device"


class CapabilityType(str, Enum):
    """Type of capability gained from exploiting a vulnerability."""
    DANGLING_PTR = "dangling_pointer"
    CONTROLLED_DATA = "controlled_data_in_freed_region"
    HEAP_OVERFLOW = "heap_overflow_write"
    STACK_OVERFLOW = "stack_overflow_write"
    INFO_LEAK = "kernel_address_leak"
    ARBITRARY_READ = "arbitrary_kernel_read"
    ARBITRARY_WRITE = "arbitrary_kernel_write"
    LIMITED_WRITE = "limited_kernel_write"
    IP_CONTROL = "instruction_pointer_control"
    CRED_OVERWRITE = "credential_overwrite"
    SELINUX_BYPASS = "selinux_bypass"
    ROOT_SHELL = "root_shell"
    CODE_EXEC = "kernel_code_execution"
    NAMESPACE_ESCAPE = "namespace_escape"


@dataclass
class Precondition:
    """A single precondition for triggering or exploiting a vulnerability."""
    id: str
    category: ConditionCategory
    description: str
    # What kernel state or input must be true
    constraint: str
    # How to check if this condition is met
    verification_method: str = ""
    # Is this an absolute requirement or helpful?
    required: bool = True
    # GDB command or check to verify at runtime
    gdb_check: str = ""
    # Kernel config option (e.g., CONFIG_BINDER_IPC=y)
    config_option: str = ""
    # Which exploit phase this condition is for
    phase: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category.value,
            "description": self.description,
            "constraint": self.constraint,
            "verification_method": self.verification_method,
            "required": self.required,
            "gdb_check": self.gdb_check,
            "config_option": self.config_option,
            "phase": self.phase,
        }


@dataclass
class Postcondition:
    """A capability gained after successful exploitation of a phase."""
    id: str
    capability: CapabilityType
    description: str
    # What the exploit gains
    provides: str
    # What kernel state changes
    kernel_state_change: str = ""
    # How to verify this was achieved
    verification_method: str = ""
    # GDB check to verify
    gdb_check: str = ""
    # What phase produces this
    phase: str = ""
    # What further exploitation this enables
    enables: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "capability": self.capability.value,
            "description": self.description,
            "provides": self.provides,
            "kernel_state_change": self.kernel_state_change,
            "verification_method": self.verification_method,
            "gdb_check": self.gdb_check,
            "phase": self.phase,
            "enables": self.enables,
        }


@dataclass
class VulnConditions:
    """Complete pre/post condition specification for a vulnerability.

    This is the primary output of the analysis, consumed by:
    - ``planner.py``: ensures each phase has its requirements met
    - ``generator.py``: provides input constraints for C code generation
    - ``gdb_exploit_monitor.py``: provides GDB checks for runtime verification
    - ``gdb_verifier.py``: provides phase-specific success criteria
    """
    cve_id: str = ""
    vuln_type: str = ""
    subsystem: str = ""

    # All preconditions organized by phase
    preconditions: List[Precondition] = field(default_factory=list)
    # All postconditions (capabilities) organized by phase
    postconditions: List[Postcondition] = field(default_factory=list)

    # Summary constraints for quick reference
    required_configs: List[str] = field(default_factory=list)
    required_modules: List[str] = field(default_factory=list)
    required_devices: List[str] = field(default_factory=list)
    required_capabilities: List[str] = field(default_factory=list)

    # Exploit chain: ordered list of (phase, preconditions, postconditions)
    exploit_chain: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "vuln_type": self.vuln_type,
            "subsystem": self.subsystem,
            "preconditions": [p.to_dict() for p in self.preconditions],
            "postconditions": [p.to_dict() for p in self.postconditions],
            "required_configs": self.required_configs,
            "required_modules": self.required_modules,
            "required_devices": self.required_devices,
            "required_capabilities": self.required_capabilities,
            "exploit_chain": self.exploit_chain,
        }

    def preconditions_for_phase(self, phase: str) -> List[Precondition]:
        return [p for p in self.preconditions if p.phase == phase or not p.phase]

    def postconditions_for_phase(self, phase: str) -> List[Postcondition]:
        return [p for p in self.postconditions if p.phase == phase]

    def all_gdb_checks(self) -> List[Dict[str, str]]:
        """Return all GDB checks for runtime verification."""
        checks = []
        for pre in self.preconditions:
            if pre.gdb_check:
                checks.append({
                    "type": "precondition",
                    "id": pre.id,
                    "phase": pre.phase,
                    "check": pre.gdb_check,
                    "description": pre.description,
                })
        for post in self.postconditions:
            if post.gdb_check:
                checks.append({
                    "type": "postcondition",
                    "id": post.id,
                    "phase": post.phase,
                    "check": post.gdb_check,
                    "description": post.description,
                })
        return checks

    def format_for_planner(self) -> str:
        """Format conditions as context for the exploit planner prompt."""
        parts = ["=== Vulnerability Pre/Post Conditions ==="]
        parts.append(f"CVE: {self.cve_id}  Type: {self.vuln_type}  "
                      f"Subsystem: {self.subsystem}")

        if self.required_configs:
            parts.append(f"\nRequired kernel configs: {', '.join(self.required_configs)}")
        if self.required_modules:
            parts.append(f"Required modules: {', '.join(self.required_modules)}")
        if self.required_devices:
            parts.append(f"Required devices: {', '.join(self.required_devices)}")

        # Group preconditions by phase
        phases_seen: Set[str] = set()
        for pre in self.preconditions:
            phase = pre.phase or "general"
            if phase not in phases_seen:
                phases_seen.add(phase)
                parts.append(f"\n--- Phase: {phase} ---")
                parts.append("PRECONDITIONS:")
            marker = "[REQUIRED]" if pre.required else "[optional]"
            parts.append(f"  {marker} {pre.description}")
            parts.append(f"    Constraint: {pre.constraint}")

        # Postconditions
        parts.append("\n--- Capabilities (Postconditions) ---")
        for post in self.postconditions:
            parts.append(f"  [{post.phase}] {post.capability.value}: {post.description}")
            if post.enables:
                parts.append(f"    Enables: {', '.join(post.enables)}")

        # Exploit chain
        if self.exploit_chain:
            parts.append("\n--- Exploit Chain ---")
            for i, link in enumerate(self.exploit_chain, 1):
                phase = link.get("phase", "?")
                needs = link.get("needs", [])
                gives = link.get("gives", [])
                parts.append(f"  {i}. {phase}: needs={needs} → gives={gives}")

        return "\n".join(parts)

    def format_for_generator(self) -> str:
        """Format conditions as context for code generation prompts."""
        parts = ["=== Input Constraints & Requirements ==="]

        # Input constraints for code
        input_conds = [p for p in self.preconditions
                       if p.category in (ConditionCategory.SYSCALL_INPUT,
                                          ConditionCategory.IOCTL_INPUT,
                                          ConditionCategory.TIMING)]
        if input_conds:
            parts.append("\nInput constraints your code MUST satisfy:")
            for c in input_conds:
                parts.append(f"  - {c.constraint}")

        # Memory/slab constraints
        mem_conds = [p for p in self.preconditions
                     if p.category in (ConditionCategory.MEMORY_LAYOUT,
                                        ConditionCategory.SLAB_STATE)]
        if mem_conds:
            parts.append("\nMemory layout requirements:")
            for c in mem_conds:
                parts.append(f"  - {c.constraint}")

        # Target capabilities
        parts.append("\nExpected capabilities after each phase:")
        for post in self.postconditions:
            parts.append(f"  [{post.phase}] {post.provides}")

        return "\n".join(parts)

    def format_for_monitor(self) -> str:
        """Format GDB checks for the exploit monitoring script."""
        checks = self.all_gdb_checks()
        if not checks:
            return ""

        parts = ["# Phase verification GDB checks"]
        for c in checks:
            parts.append(f"# [{c['type']}] {c['id']}: {c['description']}")
            parts.append(f"# Check: {c['check']}")
        return "\n".join(parts)


# ── Condition extraction ──────────────────────────────────────────────


# Common preconditions by vulnerability type
_VULN_TYPE_PRECONDITIONS: Dict[str, List[Dict[str, Any]]] = {
    "uaf": [
        {
            "id": "uaf_alloc",
            "category": ConditionCategory.SLAB_STATE,
            "description": "Target object must be allocated in a predictable slab cache",
            "constraint": "Object allocated via kmalloc-N or dedicated cache must be reachable",
            "phase": "trigger",
            "required": True,
        },
        {
            "id": "uaf_free_window",
            "category": ConditionCategory.TIMING,
            "description": "A free path must be reachable while references still exist",
            "constraint": "Race window or refcount bug allows free while pointer remains live",
            "phase": "trigger",
            "required": True,
        },
        {
            "id": "uaf_reclaim",
            "category": ConditionCategory.SLAB_STATE,
            "description": "Freed slot must be reclaimable with controlled data",
            "constraint": "Same-size allocation available via userspace syscall to fill freed slot",
            "phase": "spray",
            "required": True,
        },
    ],
    "oob_write": [
        {
            "id": "oob_adjacent",
            "category": ConditionCategory.MEMORY_LAYOUT,
            "description": "Target object must be adjacent to victim object in slab",
            "constraint": "Heap grooming places attacker-controlled object next to victim",
            "phase": "spray",
            "required": True,
        },
        {
            "id": "oob_size_control",
            "category": ConditionCategory.SYSCALL_INPUT,
            "description": "Write size or offset must be controllable",
            "constraint": "Userspace can influence the out-of-bounds write distance/size",
            "phase": "trigger",
            "required": True,
        },
    ],
    "double_free": [
        {
            "id": "df_trigger",
            "category": ConditionCategory.TIMING,
            "description": "Object must be freed twice",
            "constraint": "Race condition or logic bug causes double kfree on same pointer",
            "phase": "trigger",
            "required": True,
        },
        {
            "id": "df_reclaim_between",
            "category": ConditionCategory.SLAB_STATE,
            "description": "Allocation between the two frees gives controlled content",
            "constraint": "Re-allocate into freed slot between first and second free",
            "phase": "spray",
            "required": False,
        },
    ],
    "race_condition": [
        {
            "id": "race_cpu_pin",
            "category": ConditionCategory.PROCESS_STATE,
            "description": "Threads should be pinned to specific CPUs for reliable racing",
            "constraint": "Use sched_setaffinity to pin racing threads to separate CPUs",
            "phase": "setup",
            "required": False,
            "gdb_check": "info threads",
        },
        {
            "id": "race_timing",
            "category": ConditionCategory.TIMING,
            "description": "The race window must be hit reliably",
            "constraint": "Use userfaultfd/FUSE/futex to widen the race window",
            "phase": "trigger",
            "required": True,
        },
    ],
    "type_confusion": [
        {
            "id": "tc_type_mismatch",
            "category": ConditionCategory.SYSCALL_INPUT,
            "description": "Input must cause kernel to treat object as wrong type",
            "constraint": "Specific field values or flags cause type confusion in dispatch",
            "phase": "trigger",
            "required": True,
        },
    ],
}

# Common preconditions by subsystem
_SUBSYSTEM_PRECONDITIONS: Dict[str, List[Dict[str, Any]]] = {
    "binder": [
        {
            "id": "binder_device",
            "category": ConditionCategory.DEVICE,
            "description": "/dev/binder must be accessible",
            "constraint": "open(\"/dev/binder\", O_RDWR) must succeed",
            "phase": "setup",
            "required": True,
            "config_option": "CONFIG_ANDROID_BINDER_IPC=y",
        },
        {
            "id": "binder_mmap",
            "category": ConditionCategory.MEMORY_LAYOUT,
            "description": "binder mmap region must be established",
            "constraint": "mmap(NULL, MAP_SIZE, PROT_READ, MAP_PRIVATE, binder_fd, 0)",
            "phase": "setup",
            "required": True,
        },
        {
            "id": "binder_multi_proc",
            "category": ConditionCategory.PROCESS_STATE,
            "description": "Multiple processes needed for binder transactions",
            "constraint": "fork() to create client/server binder processes",
            "phase": "setup",
            "required": True,
        },
    ],
    "netfilter": [
        {
            "id": "nf_capability",
            "category": ConditionCategory.CAPABILITY,
            "description": "CAP_NET_ADMIN required for netfilter operations",
            "constraint": "Process must have CAP_NET_ADMIN or run in user namespace",
            "phase": "setup",
            "required": True,
        },
    ],
    "io_uring": [
        {
            "id": "iouring_setup",
            "category": ConditionCategory.SYSCALL_INPUT,
            "description": "io_uring must be available and set up",
            "constraint": "io_uring_setup() succeeds — requires kernel 5.1+",
            "phase": "setup",
            "required": True,
            "config_option": "CONFIG_IO_URING=y",
        },
    ],
    "pipe": [
        {
            "id": "pipe_setup",
            "category": ConditionCategory.SYSCALL_INPUT,
            "description": "Pipe pair must be created",
            "constraint": "pipe(fds) and potentially pipe buffer resizing via fcntl",
            "phase": "setup",
            "required": True,
        },
    ],
}

# Common postconditions by capability chain
_CAPABILITY_CHAINS: Dict[str, List[Dict[str, Any]]] = {
    "uaf_to_root": [
        {
            "phase": "trigger",
            "capability": CapabilityType.DANGLING_PTR,
            "provides": "Dangling pointer to freed kernel object",
            "enables": ["reclaim"],
            "gdb_check": "Check if kfree was called on target object",
        },
        {
            "phase": "spray",
            "capability": CapabilityType.CONTROLLED_DATA,
            "provides": "Controlled data placed in freed slot via reclaim",
            "enables": ["rw_primitive", "info_leak"],
            "gdb_check": "Check if kmalloc returned same address as freed ptr",
        },
        {
            "phase": "info_leak",
            "capability": CapabilityType.INFO_LEAK,
            "provides": "Leaked kernel text/heap address for KASLR bypass",
            "enables": ["rw_primitive", "priv_esc"],
        },
        {
            "phase": "rw_primitive",
            "capability": CapabilityType.ARBITRARY_WRITE,
            "provides": "Arbitrary kernel memory read/write via corrupted struct",
            "enables": ["priv_esc"],
        },
        {
            "phase": "priv_esc",
            "capability": CapabilityType.CRED_OVERWRITE,
            "provides": "Current process credentials overwritten to root (uid=0)",
            "enables": ["root_shell"],
            "gdb_check": "Break on commit_creds, check if uid in cred struct is 0",
        },
    ],
    "oob_to_root": [
        {
            "phase": "trigger",
            "capability": CapabilityType.HEAP_OVERFLOW,
            "provides": "Out-of-bounds write into adjacent slab object",
            "enables": ["controlled_data"],
        },
        {
            "phase": "spray",
            "capability": CapabilityType.CONTROLLED_DATA,
            "provides": "Victim struct fields corrupted via OOB write",
            "enables": ["rw_primitive"],
        },
        {
            "phase": "rw_primitive",
            "capability": CapabilityType.ARBITRARY_WRITE,
            "provides": "Arbitrary write via corrupted function pointer or size field",
            "enables": ["priv_esc"],
        },
        {
            "phase": "priv_esc",
            "capability": CapabilityType.CRED_OVERWRITE,
            "provides": "Root credentials installed",
            "enables": ["root_shell"],
        },
    ],
    "pipe_to_root": [
        {
            "phase": "trigger",
            "capability": CapabilityType.LIMITED_WRITE,
            "provides": "Write to arbitrary page via pipe buffer manipulation",
            "enables": ["priv_esc"],
        },
        {
            "phase": "priv_esc",
            "capability": CapabilityType.CRED_OVERWRITE,
            "provides": "Overwrite /etc/passwd or cred struct for root",
            "enables": ["root_shell"],
        },
    ],
}


def extract_conditions(
    *,
    cve_id: str = "",
    vuln_type: str = "",
    subsystem: str = "",
    crash_report: Any = None,
    root_cause: Any = None,
    exploit_plan: Any = None,
) -> VulnConditions:
    """Extract pre/post conditions from available analysis data.

    Combines:
    1. Static knowledge from vulnerability type and subsystem
    2. Crash report details (slab cache, object size, access type)
    3. Root cause analysis (trigger conditions, affected structs)
    4. Exploit plan steps (requires/provides)
    """
    conditions = VulnConditions(
        cve_id=cve_id,
        vuln_type=vuln_type,
        subsystem=subsystem,
    )

    # ── Type-based preconditions ──────────────────────────────────
    vtype_key = vuln_type.lower().replace("-", "_").replace(" ", "_")
    for vtype_pattern, precond_defs in _VULN_TYPE_PRECONDITIONS.items():
        if vtype_pattern in vtype_key or vtype_key in vtype_pattern:
            for pd in precond_defs:
                conditions.preconditions.append(Precondition(
                    id=pd["id"],
                    category=pd["category"],
                    description=pd["description"],
                    constraint=pd["constraint"],
                    phase=pd.get("phase", ""),
                    required=pd.get("required", True),
                    gdb_check=pd.get("gdb_check", ""),
                    config_option=pd.get("config_option", ""),
                ))

    # ── Subsystem-based preconditions ─────────────────────────────
    sub_key = subsystem.lower()
    for sub_pattern, precond_defs in _SUBSYSTEM_PRECONDITIONS.items():
        if sub_pattern in sub_key or sub_key in sub_pattern:
            for pd in precond_defs:
                conditions.preconditions.append(Precondition(
                    id=pd["id"],
                    category=pd["category"],
                    description=pd["description"],
                    constraint=pd["constraint"],
                    phase=pd.get("phase", ""),
                    required=pd.get("required", True),
                    gdb_check=pd.get("gdb_check", ""),
                    config_option=pd.get("config_option", ""),
                ))
                if pd.get("config_option"):
                    conditions.required_configs.append(pd["config_option"])

    # ── Crash report details ──────────────────────────────────────
    if crash_report:
        slab = getattr(crash_report, "slab_cache", "")
        obj_size = getattr(crash_report, "object_size", None)
        if slab:
            conditions.preconditions.append(Precondition(
                id="crash_slab",
                category=ConditionCategory.SLAB_STATE,
                description=f"Vulnerable object is in slab cache: {slab}",
                constraint=f"Target slab cache is '{slab}' "
                           f"(object size: {obj_size or 'unknown'} bytes)",
                phase="trigger",
                required=True,
            ))
        access_type = getattr(crash_report, "access_type", "")
        if access_type:
            conditions.preconditions.append(Precondition(
                id="crash_access",
                category=ConditionCategory.SYSCALL_INPUT,
                description=f"Vulnerability triggers on {access_type} access",
                constraint=f"The bug is a {access_type} of "
                           f"{getattr(crash_report, 'access_size', '?')} bytes",
                phase="trigger",
            ))

    # ── Root cause analysis ───────────────────────────────────────
    if root_cause:
        trigger_conds = getattr(root_cause, "trigger_conditions", [])
        for i, tc in enumerate(trigger_conds):
            conditions.preconditions.append(Precondition(
                id=f"rca_trigger_{i}",
                category=ConditionCategory.SYSCALL_INPUT,
                description=f"Trigger condition: {tc}",
                constraint=tc,
                phase="trigger",
                required=True,
            ))

        structs = getattr(root_cause, "affected_structs", [])
        for st in structs:
            conditions.preconditions.append(Precondition(
                id=f"struct_{st}",
                category=ConditionCategory.SLAB_STATE,
                description=f"Struct '{st}' must be allocatable",
                constraint=f"The kernel struct '{st}' is used in the vulnerable path",
                phase="trigger",
            ))

        syscalls = getattr(root_cause, "syscalls", [])
        for sc in syscalls:
            conditions.preconditions.append(Precondition(
                id=f"syscall_{sc}",
                category=ConditionCategory.SYSCALL_INPUT,
                description=f"Syscall '{sc}' must be available",
                constraint=f"syscall({sc}) must not be blocked by seccomp/SELinux",
                phase="setup",
            ))

        # Exploitation details for postconditions
        expl_details = getattr(root_cause, "exploitation_details", {})
        if expl_details:
            reclaim_obj = expl_details.get("reclaim_object_type", "")
            if reclaim_obj:
                conditions.preconditions.append(Precondition(
                    id="reclaim_object",
                    category=ConditionCategory.SLAB_STATE,
                    description=f"Reclaim using object type: {reclaim_obj}",
                    constraint=f"Use '{reclaim_obj}' to reclaim freed slab slot",
                    phase="spray",
                ))

    # ── Postconditions from capability chains ─────────────────────
    chain_key = None
    if "uaf" in vtype_key:
        chain_key = "uaf_to_root"
    elif "oob" in vtype_key:
        chain_key = "oob_to_root"
    elif "pipe" in vtype_key or "dirty" in vtype_key:
        chain_key = "pipe_to_root"

    if chain_key and chain_key in _CAPABILITY_CHAINS:
        for link in _CAPABILITY_CHAINS[chain_key]:
            conditions.postconditions.append(Postcondition(
                id=f"cap_{link['phase']}_{link['capability'].value}",
                capability=link["capability"],
                description=link.get("provides", ""),
                provides=link.get("provides", ""),
                phase=link["phase"],
                enables=link.get("enables", []),
                gdb_check=link.get("gdb_check", ""),
            ))
            conditions.exploit_chain.append({
                "phase": link["phase"],
                "needs": [p.id for p in conditions.preconditions
                          if p.phase == link["phase"]],
                "gives": [link["capability"].value],
            })

    # ── Exploit plan steps ────────────────────────────────────────
    if exploit_plan:
        steps = getattr(exploit_plan, "steps", [])
        for step in steps:
            step_requires = getattr(step, "requires", [])
            step_provides = getattr(step, "provides", [])
            for req in step_requires:
                # Only add if not already captured
                existing_ids = {p.id for p in conditions.preconditions}
                req_id = f"plan_{step.name}_{req}"
                if req_id not in existing_ids:
                    conditions.preconditions.append(Precondition(
                        id=req_id,
                        category=ConditionCategory.CAPABILITY,
                        description=f"Step '{step.name}' requires: {req}",
                        constraint=req,
                        phase=step.name,
                    ))
            for prov in step_provides:
                existing_ids = {p.id for p in conditions.postconditions}
                prov_id = f"plan_{step.name}_{prov}"
                if prov_id not in existing_ids:
                    conditions.postconditions.append(Postcondition(
                        id=prov_id,
                        capability=CapabilityType.CONTROLLED_DATA,
                        description=f"Step '{step.name}' provides: {prov}",
                        provides=prov,
                        phase=step.name,
                    ))

    # ── Collect required configs/modules/devices ──────────────────
    for pre in conditions.preconditions:
        if pre.config_option and pre.config_option not in conditions.required_configs:
            conditions.required_configs.append(pre.config_option)
        if pre.category == ConditionCategory.MODULE_STATE:
            conditions.required_modules.append(pre.constraint)
        if pre.category == ConditionCategory.DEVICE:
            conditions.required_devices.append(pre.constraint)
        if pre.category == ConditionCategory.CAPABILITY:
            conditions.required_capabilities.append(pre.constraint)

    return conditions


def generate_conditions_prompt(
    conditions: VulnConditions,
    source_snippets: Dict[str, str] = None,
) -> str:
    """Generate an LLM prompt to discover additional implicit conditions.

    The LLM reads the vulnerable source code and identifies conditions
    that static analysis missed (e.g., specific flag combinations,
    locking requirements, memory ordering constraints).
    """
    parts = [
        "Analyze the following kernel vulnerability and identify ALL "
        "preconditions and postconditions that are not already listed.",
        "",
        f"CVE: {conditions.cve_id}",
        f"Type: {conditions.vuln_type}",
        f"Subsystem: {conditions.subsystem}",
        "",
        "Already identified preconditions:",
    ]

    for pre in conditions.preconditions[:20]:
        parts.append(f"  - [{pre.phase}] {pre.description}")

    parts.append("\nAlready identified postconditions:")
    for post in conditions.postconditions[:10]:
        parts.append(f"  - [{post.phase}] {post.provides}")

    if source_snippets:
        parts.append("\n=== Vulnerable Source Code ===")
        for filename, code in list(source_snippets.items())[:3]:
            parts.append(f"\n--- {filename} ---")
            parts.append(code[:3000])

    parts.extend([
        "",
        "Identify additional preconditions and postconditions. For each, specify:",
        "1. Category (syscall_input, timing, memory_layout, kernel_config, "
        "   process_state, slab_state, refcount, selinux, capability, device)",
        "2. Description",
        "3. Concrete constraint (what must be true)",
        "4. Phase (setup, trigger, spray, reclaim, info_leak, rw_primitive, "
        "   priv_esc, cleanup)",
        "5. Whether it's required or optional",
        "6. A GDB command to verify it at runtime (if applicable)",
        "",
        "Focus on:",
        "- Lock ordering / locking requirements",
        "- Specific flag/argument values needed",
        "- Memory ordering constraints",
        "- Race window timing requirements",
        "- Kernel version specific behavior",
        "- Required slab cache properties (dedicated vs kmalloc-N)",
    ])

    return "\n".join(parts)
