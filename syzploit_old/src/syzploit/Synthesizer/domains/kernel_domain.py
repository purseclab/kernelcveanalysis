"""
kernel_domain.py

Composable PDDL domain builder for kernel exploit synthesis.

Instead of monolithic hardcoded domain strings, this module:
1. Loads a base domain definition from domains/base.pddl
2. Selectively loads technique modules from domains/techniques/
3. Selectively loads mitigation modules from domains/mitigations/
4. Composes them into a single valid PDDL domain

Technique and mitigation modules are loaded based on:
- Target platform (linux vs android)
- Available capabilities from kernel-research/libxdk
- Available technique implementations detected in the workspace
"""

import re
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Set, Any


class TargetPlatform(Enum):
    """Target platform for exploit synthesis."""
    LINUX_KERNEL = "linux"
    ANDROID_KERNEL = "android"
    GENERIC = "generic"


# Mapping of platform to the technique modules that are relevant
PLATFORM_TECHNIQUES: Dict[str, List[str]] = {
    "linux": [
        "msg_msg",
        "pipe_buffer_rop",
        "cross_cache",
        "dirty_pagetable",
        "seq_operations",
        "modprobe_hijack",
        "tty_struct",
        "sk_buff",
    ],
    "android": [
        "msg_msg",
        "pipe_buffer_rop",
        "cross_cache",
        "dirty_pagetable",
        "sk_buff",
    ],
    "generic": [
        "msg_msg",
        "pipe_buffer_rop",
        "cross_cache",
        "dirty_pagetable",
        "seq_operations",
        "tty_struct",
        "sk_buff",
    ],
}

# Mapping of platform to the mitigation modules that are relevant
PLATFORM_MITIGATIONS: Dict[str, List[str]] = {
    "linux": [
        "kaslr",
        "smep_smap",
    ],
    "android": [
        "kaslr",
        "pan_pac",
        "selinux",
    ],
    "generic": [
        "kaslr",
    ],
}


def _domains_dir() -> Path:
    """Return the directory containing PDDL domain/module files."""
    return Path(__file__).parent


def _read_pddl_file(path: Path) -> str:
    """Read a PDDL file, return empty string if not found."""
    if path.exists():
        return path.read_text()
    return ""


def _extract_actions(pddl_text: str) -> List[str]:
    """
    Extract all (:action ...) blocks from a PDDL fragment.
    Returns a list of complete action strings.
    """
    actions: List[str] = []
    # Match (:action ... ) with balanced parentheses
    depth = 0
    i = 0
    while i < len(pddl_text):
        if pddl_text[i:i+8] == "(:action":
            start = i
            depth = 1
            i += 8
            while i < len(pddl_text) and depth > 0:
                if pddl_text[i] == '(':
                    depth += 1
                elif pddl_text[i] == ')':
                    depth -= 1
                i += 1
            actions.append(pddl_text[start:i])
        else:
            i += 1
    return actions


def _extract_predicates(pddl_text: str) -> List[str]:
    """
    Extract predicate declarations from comments in module files.
    Lines starting with ';;' that contain '(' are treated as predicate
    declarations.  A single comment line may declare multiple predicates,
    e.g. ``;;   (pan_active) (pan_bypassed)`` — we must capture *all* of
    them, not just the first.
    """
    predicates: List[str] = []
    for line in pddl_text.split('\n'):
        stripped = line.strip()
        if stripped.startswith(';;') and '(' in stripped:
            # findall returns ALL matches on the line
            matches = re.findall(
                r'\(([a-z_]+(?:\s+\?[a-z]+\s*-\s*[a-z_]+)*)\)', stripped
            )
            for m in matches:
                predicates.append(f"    ({m})")
    return predicates


def _extract_constants(pddl_text: str) -> List[str]:
    """
    Extract constant declarations from comments.
    Lines like ';; Additional target_struct constants: MSG_MSG' are parsed.
    """
    constants: List[str] = []
    for line in pddl_text.split('\n'):
        stripped = line.strip()
        if stripped.startswith(';; Additional') and 'constants:' in stripped:
            # Parse "constants: MSG_MSG, PIPE_BUFFER"
            after_colon = stripped.split(':', 2)[-1].strip()
            for const_name in after_colon.split(','):
                const_name = const_name.strip()
                if const_name and const_name != "(none)" and const_name != "(none new)":
                    constants.append(const_name)
    return constants


class KernelDomain:
    """
    Composable PDDL domain builder.

    Loads base domain + technique modules + mitigation modules and merges
    them into a single valid PDDL domain definition.
    """

    def __init__(self, platform: TargetPlatform = TargetPlatform.GENERIC,
                 available_techniques: Optional[List[str]] = None,
                 available_mitigations: Optional[List[str]] = None):
        self.platform = platform
        self._available_techniques = available_techniques
        self._available_mitigations = available_mitigations

    @staticmethod
    def get_domain_name(platform: TargetPlatform) -> str:
        return {
            TargetPlatform.LINUX_KERNEL: "kernel_exploit",
            TargetPlatform.ANDROID_KERNEL: "kernel_exploit",
            TargetPlatform.GENERIC: "kernel_exploit",
        }.get(platform, "kernel_exploit")

    def _resolve_techniques(self) -> List[str]:
        """Determine which technique modules to load."""
        if self._available_techniques is not None:
            return self._available_techniques
        plat_key = self.platform.value
        return PLATFORM_TECHNIQUES.get(plat_key, PLATFORM_TECHNIQUES["generic"])

    def _resolve_mitigations(self) -> List[str]:
        """Determine which mitigation modules to load."""
        if self._available_mitigations is not None:
            return self._available_mitigations
        plat_key = self.platform.value
        return PLATFORM_MITIGATIONS.get(plat_key, PLATFORM_MITIGATIONS["generic"])

    def _load_module_text(self, subdir: str, name: str) -> str:
        """Load a PDDL module file from techniques/ or mitigations/."""
        path = _domains_dir() / subdir / f"{name}.pddl"
        return _read_pddl_file(path)

    def generate_domain(self, output_path: Optional[str] = None,
                        extra_actions: Optional[List[str]] = None) -> str:
        """
        Generate a composite PDDL domain by merging base + modules.

        Args:
            output_path: Optional path to write the domain file.
            extra_actions: Optional list of extra PDDL action strings to inject
                           (e.g. a PoC-derived action).

        Returns:
            Complete PDDL domain string.
        """
        base_text = _read_pddl_file(_domains_dir() / "base.pddl")

        # Collect actions + predicates + constants from modules
        all_module_actions: List[str] = []
        all_extra_predicates: List[str] = []
        all_extra_constants: Set[str] = set()

        for tech_name in self._resolve_techniques():
            mod_text = self._load_module_text("techniques", tech_name)
            if mod_text:
                all_module_actions.extend(_extract_actions(mod_text))
                all_extra_predicates.extend(_extract_predicates(mod_text))
                for c in _extract_constants(mod_text):
                    all_extra_constants.add(c)

        for mit_name in self._resolve_mitigations():
            mod_text = self._load_module_text("mitigations", mit_name)
            if mod_text:
                all_module_actions.extend(_extract_actions(mod_text))
                all_extra_predicates.extend(_extract_predicates(mod_text))
                for c in _extract_constants(mod_text):
                    all_extra_constants.add(c)

        if extra_actions:
            all_module_actions.extend(extra_actions)

        # Build the composite domain
        content = self._compose_domain(
            base_text, all_module_actions,
            all_extra_predicates, all_extra_constants
        )

        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            Path(output_path).write_text(content)

        return content

    def _compose_domain(self, base_text: str,
                        module_actions: List[str],
                        extra_predicates: List[str],
                        extra_constants: Set[str]) -> str:
        """
        Merge base domain text with module actions/predicates/constants.

        Strategy:
        - Insert extra constants into the existing (:constants ...) block
          or add a new one before predicates.
        - Insert extra predicates into the (:predicates ...) block.
        - Insert module actions before the closing ')' of the domain.
        """
        result = base_text

        # Deduplicate extra predicates
        seen_preds: Set[str] = set()
        unique_preds: List[str] = []
        for p in extra_predicates:
            p_stripped = p.strip()
            if p_stripped not in seen_preds:
                seen_preds.add(p_stripped)
                unique_preds.append(p_stripped)

        # Insert extra predicates before closing of (:predicates ...)
        if unique_preds:
            pred_close_pattern = re.compile(r'(\s*\)\s*\n\s*;;\s*----\s*Generic vulnerability)')
            pred_block = "\n    ;; ---- Module predicates ----\n"
            for p in unique_preds:
                pred_block += f"    {p}\n"
            match = pred_close_pattern.search(result)
            if match:
                result = result[:match.start()] + "\n" + pred_block + match.group(0) + result[match.end():]
            else:
                # Fallback: insert before first (:action
                first_action = result.find("(:action")
                if first_action > 0:
                    # Find the end of predicates block
                    pred_end = result.rfind(")", 0, first_action)
                    if pred_end > 0:
                        result = result[:pred_end] + "\n" + pred_block + result[pred_end:]

        # Insert extra target_struct constants
        if extra_constants:
            # Find existing target_struct line or add after types
            const_line = "    ;; Module target structs\n"
            for c in sorted(extra_constants):
                const_line += f"    ;; {c} - target_struct\n"
            # Insert before (:predicates
            pred_idx = result.find("(:predicates")
            if pred_idx > 0:
                result = result[:pred_idx] + const_line + "\n  " + result[pred_idx:]

        # Insert module actions before the closing ')' of the domain
        if module_actions:
            action_block = "\n  ;; ============ TECHNIQUE & MITIGATION ACTIONS ============\n\n"
            for action_str in module_actions:
                action_block += f"  {action_str}\n\n"

            # Find the last ')' which closes the domain
            last_paren = result.rfind(')')
            if last_paren > 0:
                result = result[:last_paren] + action_block + ")\n"

        return result

    def list_available_techniques(self) -> List[str]:
        """List all technique module PDDL files available on disk."""
        tech_dir = _domains_dir() / "techniques"
        if not tech_dir.exists():
            return []
        return [p.stem for p in tech_dir.glob("*.pddl")]

    def list_available_mitigations(self) -> List[str]:
        """List all mitigation module PDDL files available on disk."""
        mit_dir = _domains_dir() / "mitigations"
        if not mit_dir.exists():
            return []
        return [p.stem for p in mit_dir.glob("*.pddl")]
