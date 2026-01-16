"""
kernelresearch_adapter.py

Adapter for Google's kernel-research repository (libxdk/kernelXDK).
Extracts exploit primitives and ROP capabilities from libxdk headers
and generates corresponding PDDL capabilities.
"""

import os
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
from ..core import Primitive, PrimitiveRegistry


def _debug(msg: str, enabled: bool = True):
    """Print debug message if enabled."""
    if enabled:
        print(f"[DEBUG:KernelResearchAdapter] {msg}", file=sys.stderr)


# RopActionId mapping from Target.h -> PDDL capabilities
# Based on enum struct RopActionId in libxdk/include/xdk/target/Target.h
ROPACTION_TO_CAPS = {
    'MSLEEP': {
        'caps': ['CAP_kernel_sleep', 'CAP_timing_control'],
        'description': 'Sleep in kernel context for timing/race conditions',
    },
    'COMMIT_INIT_TASK_CREDS': {
        'caps': ['CAP_privilege_escalation', 'CAP_cred_overwrite', 'CAP_root'],
        'description': 'Overwrite current task credentials with init_task creds for root',
    },
    'SWITCH_TASK_NAMESPACES': {
        'caps': ['CAP_namespace_escape', 'CAP_container_escape'],
        'description': 'Switch task namespaces to escape containers/sandboxes',
    },
    'WRITE_WHAT_WHERE_64': {
        'caps': ['CAP_arb_write', 'CAP_kernel_write', 'CAP_64bit_write'],
        'description': 'Arbitrary 64-bit write primitive in kernel memory',
    },
    'FORK': {
        'caps': ['CAP_fork', 'CAP_process_control'],
        'description': 'Fork a new process from kernel context',
    },
    'TELEFORK': {
        'caps': ['CAP_telefork', 'CAP_process_control'],
        'description': 'Telefork (fork + exec) from kernel context',
    },
    'RET2USR': {
        'caps': ['CAP_ret2usr', 'CAP_code_exec', 'CAP_rip_control'],
        'description': 'Return to userspace code execution',
    },
}

# Additional capabilities from libxdk components
LIBXDK_COMPONENTS = {
    'PayloadBuilder': {
        'caps': ['CAP_rop_chain', 'CAP_payload_gen'],
        'description': 'ROP chain and payload construction',
        'header': 'payloads/PayloadBuilder.h',
    },
    'RopChain': {
        'caps': ['CAP_rop_chain', 'CAP_rip_control'],
        'description': 'ROP chain management and execution',
        'header': 'payloads/RopChain.h',
    },
    'StackPivot': {
        'caps': ['CAP_stack_pivot', 'CAP_rip_control'],
        'description': 'Stack pivoting for ROP chain setup',
        'header': 'pivot/StackPivot.h',
    },
    'PivotFinder': {
        'caps': ['CAP_gadget_finder', 'CAP_stack_pivot'],
        'description': 'Find stack pivot gadgets in kernel binary',
        'header': 'pivot/PivotFinder.h',
    },
    'LeakedBuffer': {
        'caps': ['CAP_info_leak', 'CAP_kaslr_bypass'],
        'description': 'Handle leaked kernel data for KASLR bypass',
        'header': 'leak/LeakedBuffer.h',
    },
    'Target': {
        'caps': ['CAP_target_detection'],
        'description': 'Target environment detection (kernelCTF, etc.)',
        'header': 'target/Target.h',
    },
    'TargetDb': {
        'caps': ['CAP_symbol_resolution', 'CAP_struct_info'],
        'description': 'Symbol and structure database for targets',
        'header': 'target/TargetDb.h',
    },
}

# Exploit technique capabilities (from samples)
EXPLOIT_TECHNIQUES = {
    'pipe_buf_rop': {
        'caps': ['CAP_pipe_buf', 'CAP_rop_chain', 'CAP_heap_spray'],
        'description': 'Pipe buffer based ROP exploitation',
    },
    'msg_msg': {
        'caps': ['CAP_msg_msg', 'CAP_heap_spray', 'CAP_cross_cache'],
        'description': 'msg_msg based heap exploitation',
    },
    'dirty_pagetable': {
        'caps': ['CAP_dirty_pagetable', 'CAP_arb_write'],
        'description': 'Dirty PageTable exploitation technique',
    },
    'cross_cache': {
        'caps': ['CAP_cross_cache', 'CAP_heap_spray'],
        'description': 'Cross-cache heap spray technique',
    },
}


class KernelResearchAdapter:
    """
    Adapter for kernel-research/libxdk repository.
    
    Extracts ROP actions, payload capabilities, and exploit techniques
    from libxdk headers and sample exploits.
    """
    
    def __init__(self, repo_path: Optional[str] = None, debug: bool = False) -> None:
        self.repo_path = repo_path
        self.debug = debug
        self._libxdk_path: Optional[Path] = None
        
        if repo_path:
            p = Path(repo_path)
            if p.exists():
                # Check if it's the kernel-research root or libxdk directly
                if (p / 'libxdk').exists():
                    self._libxdk_path = p / 'libxdk'
                elif (p / 'include' / 'xdk').exists():
                    self._libxdk_path = p
                    
        _debug(f"KernelResearchAdapter initialized", self.debug)
        _debug(f"  repo_path: {repo_path}", self.debug)
        _debug(f"  libxdk_path: {self._libxdk_path}", self.debug)

    def available(self) -> bool:
        """Check if kernel-research repo is available."""
        return bool(self.repo_path and os.path.isdir(self.repo_path))

    def _scan_rop_actions(self) -> Dict[str, Dict[str, Any]]:
        """Scan Target.h for RopActionId enum values."""
        if not self._libxdk_path:
            return ROPACTION_TO_CAPS
        
        target_h = self._libxdk_path / 'include' / 'xdk' / 'target' / 'Target.h'
        if not target_h.exists():
            _debug(f"Target.h not found at {target_h}", self.debug)
            return ROPACTION_TO_CAPS
        
        _debug(f"Scanning Target.h for RopActionId enum", self.debug)
        
        try:
            content = target_h.read_text()
            # Find enum struct RopActionId
            match = re.search(r'enum\s+struct\s+RopActionId\s*:\s*\w+\s*\{([^}]+)\}', content)
            if match:
                enum_body = match.group(1)
                # Parse entries like MSLEEP = 0x01,
                for entry in re.finditer(r'(\w+)\s*=\s*0x[\da-fA-F]+', enum_body):
                    action_name = entry.group(1)
                    if action_name not in ROPACTION_TO_CAPS:
                        _debug(f"  Found new RopActionId: {action_name}", self.debug)
                        # Add with generic caps
                        ROPACTION_TO_CAPS[action_name] = {
                            'caps': ['CAP_rop_action', f'CAP_{action_name.lower()}'],
                            'description': f'ROP action: {action_name}',
                        }
        except Exception as e:
            _debug(f"Error scanning Target.h: {e}", self.debug)
        
        return ROPACTION_TO_CAPS

    def _scan_components(self) -> Dict[str, Dict[str, Any]]:
        """Scan libxdk headers for available components."""
        if not self._libxdk_path:
            return LIBXDK_COMPONENTS
        
        include_dir = self._libxdk_path / 'include' / 'xdk'
        if not include_dir.exists():
            return LIBXDK_COMPONENTS
        
        _debug(f"Scanning libxdk components in {include_dir}", self.debug)
        
        for comp_name, comp_info in LIBXDK_COMPONENTS.items():
            header_path = include_dir / comp_info['header']
            if header_path.exists():
                _debug(f"  Found component: {comp_name}", self.debug)
            else:
                _debug(f"  Component not found: {comp_name} ({header_path})", self.debug)
        
        return LIBXDK_COMPONENTS

    def _scan_samples(self) -> List[Dict[str, Any]]:
        """Scan sample exploits to extract techniques used."""
        samples = []
        if not self._libxdk_path:
            return samples
        
        samples_dir = self._libxdk_path / 'samples'
        if not samples_dir.exists():
            return samples
        
        _debug(f"Scanning sample exploits in {samples_dir}", self.debug)
        
        for sample_dir in samples_dir.iterdir():
            if sample_dir.is_dir():
                exploit_cpp = sample_dir / 'exploit.cpp'
                if exploit_cpp.exists():
                    sample_info = {
                        'name': sample_dir.name,
                        'path': str(exploit_cpp),
                        'caps': [],
                    }
                    
                    try:
                        content = exploit_cpp.read_text()
                        # Look for technique indicators
                        if 'pipe' in content.lower():
                            sample_info['caps'].extend(['CAP_pipe_buf'])
                        if 'msg_msg' in content.lower():
                            sample_info['caps'].extend(['CAP_msg_msg'])
                        if 'cross' in content.lower() and 'cache' in content.lower():
                            sample_info['caps'].extend(['CAP_cross_cache'])
                        if 'RopChain' in content:
                            sample_info['caps'].extend(['CAP_rop_chain'])
                        if 'PayloadBuilder' in content:
                            sample_info['caps'].extend(['CAP_payload_gen'])
                        if 'commit_creds' in content.lower() or 'COMMIT_INIT_TASK_CREDS' in content:
                            sample_info['caps'].extend(['CAP_privilege_escalation'])
                    except Exception:
                        pass
                    
                    samples.append(sample_info)
                    _debug(f"  Sample {sample_dir.name}: {sample_info['caps']}", self.debug)
        
        return samples

    def list_primitives(self, registry: PrimitiveRegistry, debug: bool = False) -> List[Primitive]:
        """
        List all available primitives from kernel-research/libxdk.
        
        Extracts:
        - ROP actions from Target.h enum
        - Component capabilities from libxdk headers
        - Exploit techniques from sample exploits
        
        Args:
            registry: PrimitiveRegistry to add primitives to
            debug: Enable debug output
            
        Returns:
            List of Primitive objects
        """
        self.debug = debug or self.debug
        prims: List[Primitive] = []
        
        _debug("Listing kernel-research primitives...", self.debug)
        
        # Scan for ROP actions
        rop_actions = self._scan_rop_actions()
        for action_name, action_info in rop_actions.items():
            p = Primitive(
                name=f"xdk_rop_{action_name.lower()}",
                description=action_info.get('description', f'ROP action: {action_name}'),
                requirements={'rip_control': True},
                provides={
                    'caps': action_info.get('caps', []),
                    'rop_action': action_name,
                    'source': 'kernel-research/libxdk',
                }
            )
            registry.add(p)
            prims.append(p)
            _debug(f"  Added ROP action: {action_name} -> {action_info.get('caps', [])}", self.debug)
        
        # Scan for components
        components = self._scan_components()
        for comp_name, comp_info in components.items():
            p = Primitive(
                name=f"xdk_{comp_name.lower()}",
                description=comp_info.get('description', f'libxdk component: {comp_name}'),
                requirements={},
                provides={
                    'caps': comp_info.get('caps', []),
                    'component': comp_name,
                    'source': 'kernel-research/libxdk',
                }
            )
            registry.add(p)
            prims.append(p)
            _debug(f"  Added component: {comp_name} -> {comp_info.get('caps', [])}", self.debug)
        
        # Add exploit techniques
        for tech_name, tech_info in EXPLOIT_TECHNIQUES.items():
            p = Primitive(
                name=f"xdk_technique_{tech_name}",
                description=tech_info.get('description', f'Exploit technique: {tech_name}'),
                requirements={},
                provides={
                    'caps': tech_info.get('caps', []),
                    'technique': tech_name,
                    'source': 'kernel-research/libxdk',
                }
            )
            registry.add(p)
            prims.append(p)
            _debug(f"  Added technique: {tech_name} -> {tech_info.get('caps', [])}", self.debug)
        
        # Scan sample exploits
        samples = self._scan_samples()
        for sample in samples:
            if sample.get('caps'):
                p = Primitive(
                    name=f"xdk_sample_{sample['name']}",
                    description=f"Sample exploit: {sample['name']}",
                    requirements={},
                    provides={
                        'caps': list(set(sample.get('caps', []))),
                        'sample': sample['name'],
                        'source': 'kernel-research/libxdk',
                    }
                )
                registry.add(p)
                prims.append(p)
        
        _debug(f"  Total primitives: {len(prims)}", self.debug)
        return prims

    def generate_rop_chain(self, vmlinux: str, vmlinuz: Optional[str] = None) -> Optional[str]:
        """
        If rop_generator is present, generate a ROP chain.
        
        Args:
            vmlinux: Path to vmlinux ELF file
            vmlinuz: Optional path to compressed kernel image
            
        Returns:
            Path to generated ROP chain output file, or None
        """
        if not self.available():
            return None
            
        script = os.path.join(self.repo_path, 'rop_generator', 'angrop_rop_generator.py')
        if not os.path.exists(script):
            _debug(f"ROP generator script not found: {script}", self.debug)
            return None
            
        try:
            cmd = ['python3', script, vmlinux]
            if vmlinuz:
                cmd.append(vmlinuz)
                
            _debug(f"Running ROP generator: {' '.join(cmd)}", self.debug)
            
            with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                  text=True) as proc:
                out, err = proc.communicate(timeout=120)
                
                # Write output to file
                out_path = os.path.join(os.getcwd(), 'outdir', 'generated_rop.txt')
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with open(out_path, 'w') as f:
                    f.write(out)
                    
                _debug(f"ROP chain written to: {out_path}", self.debug)
                return out_path
                
        except subprocess.TimeoutExpired:
            _debug("ROP generator timed out", self.debug)
            return None
        except Exception as e:
            _debug(f"ROP generator error: {e}", self.debug)
            return None
