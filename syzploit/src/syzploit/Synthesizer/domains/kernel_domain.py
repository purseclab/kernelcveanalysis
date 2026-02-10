"""
kernel_domain.py

Standalone PDDL domain definitions for kernel exploit synthesis.
Supports both Linux and Android kernel exploitation scenarios.

This removes the dependency on chainreactor by providing self-contained
domain definitions tailored for kernel-level privilege escalation.
"""

from enum import Enum
from pathlib import Path
from typing import Optional


class TargetPlatform(Enum):
    """Target platform for exploit synthesis."""
    LINUX_KERNEL = "linux"
    ANDROID_KERNEL = "android"
    GENERIC = "generic"


class KernelDomain:
    """
    Provides PDDL domain definitions for kernel exploit synthesis.
    
    This class generates domain.pddl files tailored for kernel-level
    exploits, supporting both Linux and Android platforms.
    """
    
    def __init__(self, platform: TargetPlatform = TargetPlatform.GENERIC):
        self.platform = platform
    
    @staticmethod
    def get_domain_name(platform: TargetPlatform) -> str:
        """Get the PDDL domain name for a platform."""
        return {
            TargetPlatform.LINUX_KERNEL: "linux_kernel_exploit",
            TargetPlatform.ANDROID_KERNEL: "android_kernel_exploit",
            TargetPlatform.GENERIC: "kernel_exploit",
        }.get(platform, "kernel_exploit")
    
    def generate_domain(self, output_path: Optional[str] = None) -> str:
        """
        Generate the PDDL domain definition.
        
        Args:
            output_path: Optional path to write the domain file
            
        Returns:
            The PDDL domain content as a string
        """
        if self.platform == TargetPlatform.ANDROID_KERNEL:
            content = self._android_domain()
        elif self.platform == TargetPlatform.LINUX_KERNEL:
            content = self._linux_domain()
        else:
            content = self._generic_kernel_domain()
        
        if output_path:
            Path(output_path).write_text(content)
        
        return content
    
    def _generic_kernel_domain(self) -> str:
        """Generate a generic kernel exploit domain."""
        return '''(define (domain kernel_exploit)
  (:requirements :typing :equality)
  (:types
    primitive capability context - object
    vuln_primitive escalation_primitive - primitive
  )

  (:constants
    ; Vulnerability types
    UAF OOB_READ OOB_WRITE RACE DOUBLE_FREE TYPE_CONFUSION - vuln_primitive
    ; Escalation capabilities  
    ARB_READ ARB_WRITE CODE_EXEC CRED_OVERWRITE NAMESPACE_ESCAPE - capability
    ; Execution contexts
    KERNEL_CONTEXT USER_CONTEXT - context
  )

  (:predicates
    ; Vulnerability state
    (has_vulnerability ?v - vuln_primitive)
    (vulnerability_triggered ?v - vuln_primitive)
    
    ; Capability state
    (has_capability ?c - capability)
    (capability_stable ?c - capability)
    
    ; Context state
    (execution_context ?ctx - context)
    (context_escalated)
    
    ; Goal states
    (privilege_escalated)
    (kernel_code_execution)
    (container_escaped)
    
    ; Exploit building blocks
    (info_leak_available)
    (kaslr_bypassed)
    (heap_controlled)
    (stack_pivoted)
    (rop_chain_ready)
    (payload_prepared)
    
    ; Kernel state
    (kernel_locked)
    (preemption_disabled)
    (irq_disabled)
  )

  ; ============== VULNERABILITY TRIGGERING ==============
  ; These trigger actions execute the syzbot reproducer code.
  ; The reproducer IS the trigger implementation.
  
  (:action trigger_uaf
    :parameters ()
    :precondition (and
      (has_vulnerability UAF)
      (has_syzbot_reproducer)
      (not (vulnerability_triggered UAF))
    )
    :effect (and
      (vulnerability_triggered UAF)
      (heap_controlled)
    )
  )

  (:action trigger_oob_read
    :parameters ()
    :precondition (and
      (has_vulnerability OOB_READ)
      (has_syzbot_reproducer)
      (not (vulnerability_triggered OOB_READ))
    )
    :effect (and
      (vulnerability_triggered OOB_READ)
      (info_leak_available)
    )
  )

  (:action trigger_oob_write
    :parameters ()
    :precondition (and
      (has_vulnerability OOB_WRITE)
      (has_syzbot_reproducer)
      (not (vulnerability_triggered OOB_WRITE))
    )
    :effect (and
      (vulnerability_triggered OOB_WRITE)
      (has_capability ARB_WRITE)
    )
  )

  (:action trigger_race
    :parameters ()
    :precondition (and
      (has_vulnerability RACE)
      (has_syzbot_reproducer)
      (not (vulnerability_triggered RACE))
    )
    :effect (and
      (vulnerability_triggered RACE)
      (heap_controlled)
    )
  )

  ; ============== CAPABILITY BUILDING ==============

  (:action derive_arb_read_from_uaf
    :parameters ()
    :precondition (and
      (vulnerability_triggered UAF)
      (heap_controlled)
    )
    :effect (has_capability ARB_READ)
  )

  (:action derive_arb_write_from_uaf
    :parameters ()
    :precondition (and
      (vulnerability_triggered UAF)
      (heap_controlled)
    )
    :effect (has_capability ARB_WRITE)
  )

  (:action bypass_kaslr
    :parameters ()
    :precondition (and
      (has_capability ARB_READ)
      (not (kaslr_bypassed))
    )
    :effect (kaslr_bypassed)
  )

  (:action bypass_kaslr_via_info_leak
    :parameters ()
    :precondition (and
      (info_leak_available)
      (not (kaslr_bypassed))
    )
    :effect (kaslr_bypassed)
  )

  ; ============== EXPLOIT TECHNIQUES ==============

  (:action prepare_rop_chain
    :parameters ()
    :precondition (and
      (kaslr_bypassed)
      (has_capability ARB_WRITE)
    )
    :effect (and
      (rop_chain_ready)
      (payload_prepared)
    )
  )

  (:action perform_stack_pivot
    :parameters ()
    :precondition (and
      (rop_chain_ready)
      (has_capability ARB_WRITE)
    )
    :effect (stack_pivoted)
  )

  (:action execute_rop_payload
    :parameters ()
    :precondition (and
      (stack_pivoted)
      (payload_prepared)
    )
    :effect (has_capability CODE_EXEC)
  )

  (:action overwrite_cred_struct
    :parameters ()
    :precondition (and
      (has_capability CODE_EXEC)
      (kaslr_bypassed)
    )
    :effect (and
      (has_capability CRED_OVERWRITE)
      (capability_stable CRED_OVERWRITE)
    )
  )

  (:action commit_creds
    :parameters ()
    :precondition (has_capability CRED_OVERWRITE)
    :effect (privilege_escalated)
  )

  ; ============== DIRECT PATHS ==============

  (:action direct_cred_overwrite
    :parameters ()
    :precondition (and
      (has_capability ARB_WRITE)
      (kaslr_bypassed)
    )
    :effect (and
      (has_capability CRED_OVERWRITE)
      (privilege_escalated)
    )
  )

  (:action kernel_code_exec_from_rop
    :parameters ()
    :precondition (and
      (has_capability CODE_EXEC)
      (privilege_escalated)
    )
    :effect (kernel_code_execution)
  )

  (:action escape_container
    :parameters ()
    :precondition (and
      (privilege_escalated)
      (has_capability NAMESPACE_ESCAPE)
    )
    :effect (container_escaped)
  )

  (:action derive_namespace_escape
    :parameters ()
    :precondition (and
      (has_capability CODE_EXEC)
      (kaslr_bypassed)
    )
    :effect (has_capability NAMESPACE_ESCAPE)
  )
)
'''
    
    def _linux_domain(self) -> str:
        """Generate Linux kernel specific domain."""
        return '''(define (domain linux_kernel_exploit)
  (:requirements :typing :equality)
  (:types
    primitive capability context target_struct - object
    vuln_primitive escalation_primitive - primitive
  )

  (:constants
    ; Vulnerability types
    UAF OOB_READ OOB_WRITE RACE DOUBLE_FREE TYPE_CONFUSION INTEGER_OVERFLOW - vuln_primitive
    ; Escalation capabilities  
    ARB_READ ARB_WRITE CODE_EXEC CRED_OVERWRITE NAMESPACE_ESCAPE MODPROBE_HIJACK - capability
    ; Execution contexts
    KERNEL_CONTEXT USER_CONTEXT IRQ_CONTEXT - context
    ; Target structures for heap spraying
    CRED_STRUCT MSG_MSG SEQ_OPERATIONS TTYOPS PIPE_BUFFER SK_BUFF TIMERFD_CTX - target_struct
  )

  (:predicates
    ; Vulnerability state
    (has_vulnerability ?v - vuln_primitive)
    (vulnerability_triggered ?v - vuln_primitive)
    (vulnerability_object_size ?v - vuln_primitive ?size - object)
    
    ; Syzbot reproducer (original vulnerability trigger code)
    (has_syzbot_reproducer)
    
    ; Capability state
    (has_capability ?c - capability)
    (capability_stable ?c - capability)
    
    ; Context state
    (execution_context ?ctx - context)
    (context_escalated)
    
    ; Goal states
    (privilege_escalated)
    (kernel_code_execution)
    (container_escaped)
    (root_shell)
    
    ; Exploit building blocks
    (info_leak_available)
    (kaslr_bypassed)
    (smap_bypassed)
    (smep_bypassed)
    (kpti_bypassed)
    (heap_controlled)
    (heap_sprayed ?s - target_struct)
    (stack_pivoted)
    (rop_chain_ready)
    (payload_prepared)
    
    ; Kernel state
    (kernel_locked)
    (preemption_disabled)
    (irq_disabled)
    (rcu_read_locked)
  )

  ; ============== VULNERABILITY TRIGGERING ==============
  ; These trigger actions execute the syzbot reproducer code.
  ; The reproducer IS the trigger implementation.

  (:action trigger_uaf
    :parameters ()
    :precondition (and
      (has_vulnerability UAF)
      (has_syzbot_reproducer)
      (not (vulnerability_triggered UAF))
    )
    :effect (and
      (vulnerability_triggered UAF)
      (heap_controlled)
    )
  )

  (:action trigger_oob_read
    :parameters ()
    :precondition (and
      (has_vulnerability OOB_READ)
      (has_syzbot_reproducer)
      (not (vulnerability_triggered OOB_READ))
    )
    :effect (and
      (vulnerability_triggered OOB_READ)
      (info_leak_available)
    )
  )

  (:action trigger_oob_write
    :parameters ()
    :precondition (and
      (has_vulnerability OOB_WRITE)
      (has_syzbot_reproducer)
      (not (vulnerability_triggered OOB_WRITE))
    )
    :effect (and
      (vulnerability_triggered OOB_WRITE)
      (has_capability ARB_WRITE)
    )
  )

  (:action trigger_race_condition
    :parameters ()
    :precondition (and
      (has_vulnerability RACE)
      (has_syzbot_reproducer)
      (not (vulnerability_triggered RACE))
    )
    :effect (and
      (vulnerability_triggered RACE)
      (heap_controlled)
    )
  )

  (:action trigger_double_free
    :parameters ()
    :precondition (and
      (has_vulnerability DOUBLE_FREE)
      (has_syzbot_reproducer)
      (not (vulnerability_triggered DOUBLE_FREE))
    )
    :effect (and
      (vulnerability_triggered DOUBLE_FREE)
      (heap_controlled)
    )
  )

  ; ============== HEAP SPRAY TECHNIQUES ==============

  (:action spray_msg_msg
    :parameters ()
    :precondition (heap_controlled)
    :effect (heap_sprayed MSG_MSG)
  )

  (:action spray_pipe_buffer
    :parameters ()
    :precondition (heap_controlled)
    :effect (heap_sprayed PIPE_BUFFER)
  )

  (:action spray_sk_buff
    :parameters ()
    :precondition (heap_controlled)
    :effect (heap_sprayed SK_BUFF)
  )

  (:action spray_tty_struct
    :parameters ()
    :precondition (heap_controlled)
    :effect (heap_sprayed TTYOPS)
  )

  (:action spray_seq_operations
    :parameters ()
    :precondition (heap_controlled)
    :effect (heap_sprayed SEQ_OPERATIONS)
  )

  ; ============== CAPABILITY BUILDING ==============

  (:action derive_arb_read_from_msg_msg
    :parameters ()
    :precondition (heap_sprayed MSG_MSG)
    :effect (has_capability ARB_READ)
  )

  (:action derive_arb_write_from_msg_msg
    :parameters ()
    :precondition (heap_sprayed MSG_MSG)
    :effect (has_capability ARB_WRITE)
  )

  (:action derive_arb_read_from_pipe_buffer
    :parameters ()
    :precondition (heap_sprayed PIPE_BUFFER)
    :effect (has_capability ARB_READ)
  )

  (:action derive_arb_write_from_pipe_buffer
    :parameters ()
    :precondition (heap_sprayed PIPE_BUFFER)
    :effect (has_capability ARB_WRITE)
  )

  (:action derive_code_exec_from_tty
    :parameters ()
    :precondition (and
      (heap_sprayed TTYOPS)
      (smep_bypassed)
    )
    :effect (has_capability CODE_EXEC)
  )

  (:action derive_code_exec_from_seq_ops
    :parameters ()
    :precondition (and
      (heap_sprayed SEQ_OPERATIONS)
      (smep_bypassed)
    )
    :effect (has_capability CODE_EXEC)
  )

  ; ============== MITIGATION BYPASSES ==============

  (:action bypass_kaslr
    :parameters ()
    :precondition (and
      (has_capability ARB_READ)
      (not (kaslr_bypassed))
    )
    :effect (kaslr_bypassed)
  )

  (:action bypass_kaslr_via_info_leak
    :parameters ()
    :precondition (and
      (info_leak_available)
      (not (kaslr_bypassed))
    )
    :effect (kaslr_bypassed)
  )

  (:action bypass_smep
    :parameters ()
    :precondition (and
      (has_capability ARB_WRITE)
      (kaslr_bypassed)
    )
    :effect (smep_bypassed)
  )

  (:action bypass_smap
    :parameters ()
    :precondition (and
      (has_capability ARB_WRITE)
      (kaslr_bypassed)
    )
    :effect (smap_bypassed)
  )

  (:action bypass_kpti_via_trampoline
    :parameters ()
    :precondition (kaslr_bypassed)
    :effect (kpti_bypassed)
  )

  ; ============== ROP CHAIN BUILDING ==============

  (:action prepare_rop_chain
    :parameters ()
    :precondition (and
      (kaslr_bypassed)
      (has_capability ARB_WRITE)
    )
    :effect (and
      (rop_chain_ready)
      (payload_prepared)
    )
  )

  (:action perform_stack_pivot
    :parameters ()
    :precondition (and
      (rop_chain_ready)
      (has_capability ARB_WRITE)
      (smap_bypassed)
    )
    :effect (stack_pivoted)
  )

  (:action execute_rop_payload
    :parameters ()
    :precondition (and
      (stack_pivoted)
      (payload_prepared)
      (kpti_bypassed)
    )
    :effect (has_capability CODE_EXEC)
  )

  ; ============== PRIVILEGE ESCALATION ==============

  (:action overwrite_cred_struct
    :parameters ()
    :precondition (and
      (has_capability CODE_EXEC)
      (kaslr_bypassed)
    )
    :effect (and
      (has_capability CRED_OVERWRITE)
      (capability_stable CRED_OVERWRITE)
    )
  )

  (:action commit_creds_prepare_kernel_cred
    :parameters ()
    :precondition (has_capability CRED_OVERWRITE)
    :effect (privilege_escalated)
  )

  (:action direct_cred_overwrite
    :parameters ()
    :precondition (and
      (has_capability ARB_WRITE)
      (kaslr_bypassed)
    )
    :effect (and
      (has_capability CRED_OVERWRITE)
      (privilege_escalated)
    )
  )

  (:action hijack_modprobe_path
    :parameters ()
    :precondition (and
      (has_capability ARB_WRITE)
      (kaslr_bypassed)
    )
    :effect (and
      (has_capability MODPROBE_HIJACK)
      (privilege_escalated)
    )
  )

  ; ============== POST EXPLOITATION ==============

  (:action spawn_root_shell
    :parameters ()
    :precondition (privilege_escalated)
    :effect (root_shell)
  )

  (:action kernel_code_exec_from_rop
    :parameters ()
    :precondition (and
      (has_capability CODE_EXEC)
      (privilege_escalated)
    )
    :effect (kernel_code_execution)
  )

  (:action derive_namespace_escape
    :parameters ()
    :precondition (and
      (has_capability CODE_EXEC)
      (kaslr_bypassed)
    )
    :effect (has_capability NAMESPACE_ESCAPE)
  )

  (:action escape_container
    :parameters ()
    :precondition (and
      (privilege_escalated)
      (has_capability NAMESPACE_ESCAPE)
    )
    :effect (container_escaped)
  )
)
'''
    
    def _android_domain(self) -> str:
        """Generate Android kernel specific domain."""
        return '''(define (domain android_kernel_exploit)
  (:requirements :typing :equality)
  (:types
    primitive capability context target_struct selinux_context - object
    vuln_primitive escalation_primitive - primitive
  )

  (:constants
    ; Vulnerability types
    UAF OOB_READ OOB_WRITE RACE DOUBLE_FREE TYPE_CONFUSION BINDER_BUG - vuln_primitive
    ; Escalation capabilities  
    ARB_READ ARB_WRITE CODE_EXEC CRED_OVERWRITE SELINUX_BYPASS - capability
    ; Execution contexts
    KERNEL_CONTEXT USER_CONTEXT BINDER_CONTEXT - context
    ; Target structures
    BINDER_NODE BINDER_REF MSG_MSG PIPE_BUFFER SEQ_OPERATIONS - target_struct
    ; SELinux contexts
    UNTRUSTED_APP SYSTEM_SERVER INIT KERNEL - selinux_context
  )

  (:predicates
    ; Vulnerability state
    (has_vulnerability ?v - vuln_primitive)
    (vulnerability_triggered ?v - vuln_primitive)
    
    ; Syzbot reproducer (original vulnerability trigger code)
    (has_syzbot_reproducer)
    
    ; Capability state
    (has_capability ?c - capability)
    (capability_stable ?c - capability)
    
    ; Context state
    (execution_context ?ctx - context)
    (selinux_context ?se - selinux_context)
    (context_escalated)
    
    ; Goal states
    (privilege_escalated)
    (kernel_code_execution)
    (selinux_disabled)
    (root_shell)
    (adb_root)
    
    ; Android specific
    (in_untrusted_app)
    (escaped_sandbox)
    (binder_controlled)
    (zygote_compromised)
    
    ; Exploit building blocks
    (info_leak_available)
    (kaslr_bypassed)
    (pan_bypassed)
    (pac_bypassed)
    (mte_bypassed)
    (heap_controlled)
    (heap_sprayed ?s - target_struct)
    (stack_pivoted)
    (rop_chain_ready)
    (jop_chain_ready)
    (payload_prepared)
    
    ; Kernel state
    (kernel_locked)
    (preemption_disabled)
  )

  ; ============== ANDROID ENTRY POINTS ==============

  (:action start_from_untrusted_app
    :parameters ()
    :precondition (not (in_untrusted_app))
    :effect (and
      (in_untrusted_app)
      (selinux_context UNTRUSTED_APP)
      (execution_context USER_CONTEXT)
    )
  )

  ; ============== VULNERABILITY TRIGGERING ==============
  ; These trigger actions execute the syzbot reproducer code.
  ; The reproducer IS the trigger implementation.

  (:action trigger_uaf
    :parameters ()
    :precondition (and
      (has_vulnerability UAF)
      (has_syzbot_reproducer)
      (not (vulnerability_triggered UAF))
    )
    :effect (and
      (vulnerability_triggered UAF)
      (heap_controlled)
    )
  )

  (:action trigger_binder_bug
    :parameters ()
    :precondition (and
      (has_vulnerability BINDER_BUG)
      (has_syzbot_reproducer)
      (not (vulnerability_triggered BINDER_BUG))
    )
    :effect (and
      (vulnerability_triggered BINDER_BUG)
      (binder_controlled)
    )
  )

  (:action trigger_oob_read
    :parameters ()
    :precondition (and
      (has_vulnerability OOB_READ)
      (has_syzbot_reproducer)
      (not (vulnerability_triggered OOB_READ))
    )
    :effect (and
      (vulnerability_triggered OOB_READ)
      (info_leak_available)
    )
  )

  (:action trigger_oob_write
    :parameters ()
    :precondition (and
      (has_vulnerability OOB_WRITE)
      (has_syzbot_reproducer)
      (not (vulnerability_triggered OOB_WRITE))
    )
    :effect (and
      (vulnerability_triggered OOB_WRITE)
      (has_capability ARB_WRITE)
    )
  )

  (:action trigger_race_condition
    :parameters ()
    :precondition (and
      (has_vulnerability RACE)
      (has_syzbot_reproducer)
      (not (vulnerability_triggered RACE))
    )
    :effect (and
      (vulnerability_triggered RACE)
      (heap_controlled)
    )
  )

  ; ============== BINDER EXPLOITATION ==============

  (:action spray_binder_nodes
    :parameters ()
    :precondition (binder_controlled)
    :effect (heap_sprayed BINDER_NODE)
  )

  (:action spray_binder_refs
    :parameters ()
    :precondition (binder_controlled)
    :effect (heap_sprayed BINDER_REF)
  )

  (:action derive_arb_read_from_binder
    :parameters ()
    :precondition (heap_sprayed BINDER_NODE)
    :effect (has_capability ARB_READ)
  )

  (:action derive_arb_write_from_binder
    :parameters ()
    :precondition (heap_sprayed BINDER_NODE)
    :effect (has_capability ARB_WRITE)
  )

  ; ============== BINDER EPOLL UAF - IOVEC CORRUPTION TECHNIQUE ==============
  ; This is the correct exploitation path for binder_thread UAF via epoll
  ; Based on the badbinder exploit technique

  (:action setup_binder_epoll
    :parameters ()
    :precondition (and
      (has_vulnerability UAF)
      (has_syzbot_reproducer)
    )
    :effect (and
      (binder_controlled)
      (heap_controlled)
    )
  )

  (:action setup_iovec_spray
    :parameters ()
    :precondition (binder_controlled)
    :effect (heap_sprayed PIPE_BUFFER)
  )

  (:action trigger_binder_uaf
    :parameters ()
    :precondition (and
      (binder_controlled)
      (heap_sprayed PIPE_BUFFER)
    )
    :effect (vulnerability_triggered UAF)
  )

  (:action reclaim_with_iovec
    :parameters ()
    :precondition (vulnerability_triggered UAF)
    :effect (heap_controlled)
  )

  (:action corrupt_iovec_via_epoll
    :parameters ()
    :precondition (and
      (vulnerability_triggered UAF)
      (heap_controlled)
    )
    :effect (info_leak_available)
  )

  (:action leak_task_struct
    :parameters ()
    :precondition (info_leak_available)
    :effect (and
      (has_capability ARB_READ)
      (kaslr_bypassed)
    )
  )

  (:action setup_addr_limit_overwrite
    :parameters ()
    :precondition (and
      (has_capability ARB_READ)
      (kaslr_bypassed)
    )
    :effect (pan_bypassed)
  )

  (:action overwrite_addr_limit
    :parameters ()
    :precondition (pan_bypassed)
    :effect (has_capability ARB_WRITE)
  )

  (:action kernel_read_primitive
    :parameters ()
    :precondition (has_capability ARB_WRITE)
    :effect (capability_stable ARB_READ)
  )

  (:action kernel_write_primitive
    :parameters ()
    :precondition (has_capability ARB_WRITE)
    :effect (capability_stable ARB_WRITE)
  )

  (:action overwrite_cred
    :parameters ()
    :precondition (and
      (capability_stable ARB_WRITE)
      (kaslr_bypassed)
    )
    :effect (and
      (has_capability CRED_OVERWRITE)
      (privilege_escalated)
    )
  )

  ; ============== HEAP SPRAY TECHNIQUES ==============

  (:action spray_msg_msg
    :parameters ()
    :precondition (heap_controlled)
    :effect (heap_sprayed MSG_MSG)
  )

  (:action spray_pipe_buffer
    :parameters ()
    :precondition (heap_controlled)
    :effect (heap_sprayed PIPE_BUFFER)
  )

  (:action spray_seq_operations
    :parameters ()
    :precondition (heap_controlled)
    :effect (heap_sprayed SEQ_OPERATIONS)
  )

  (:action derive_arb_read_from_msg_msg
    :parameters ()
    :precondition (heap_sprayed MSG_MSG)
    :effect (has_capability ARB_READ)
  )

  (:action derive_arb_write_from_msg_msg
    :parameters ()
    :precondition (heap_sprayed MSG_MSG)
    :effect (has_capability ARB_WRITE)
  )

  ; ============== ARM64 MITIGATION BYPASSES ==============

  (:action bypass_kaslr
    :parameters ()
    :precondition (and
      (has_capability ARB_READ)
      (not (kaslr_bypassed))
    )
    :effect (kaslr_bypassed)
  )

  (:action bypass_kaslr_via_info_leak
    :parameters ()
    :precondition (and
      (info_leak_available)
      (not (kaslr_bypassed))
    )
    :effect (kaslr_bypassed)
  )

  (:action bypass_pan
    :parameters ()
    :precondition (and
      (has_capability ARB_WRITE)
      (kaslr_bypassed)
    )
    :effect (pan_bypassed)
  )

  (:action bypass_pac
    :parameters ()
    :precondition (and
      (has_capability ARB_READ)
      (info_leak_available)
    )
    :effect (pac_bypassed)
  )

  (:action bypass_mte
    :parameters ()
    :precondition (and
      (has_capability ARB_READ)
      (kaslr_bypassed)
    )
    :effect (mte_bypassed)
  )

  ; ============== CODE EXECUTION ==============

  (:action prepare_rop_chain
    :parameters ()
    :precondition (and
      (kaslr_bypassed)
      (has_capability ARB_WRITE)
    )
    :effect (and
      (rop_chain_ready)
      (payload_prepared)
    )
  )

  (:action prepare_jop_chain
    :parameters ()
    :precondition (and
      (kaslr_bypassed)
      (pac_bypassed)
      (has_capability ARB_WRITE)
    )
    :effect (and
      (jop_chain_ready)
      (payload_prepared)
    )
  )

  (:action perform_stack_pivot
    :parameters ()
    :precondition (and
      (rop_chain_ready)
      (has_capability ARB_WRITE)
      (pan_bypassed)
    )
    :effect (stack_pivoted)
  )

  (:action execute_rop_payload
    :parameters ()
    :precondition (and
      (stack_pivoted)
      (payload_prepared)
    )
    :effect (has_capability CODE_EXEC)
  )

  (:action execute_jop_payload
    :parameters ()
    :precondition (and
      (jop_chain_ready)
      (payload_prepared)
    )
    :effect (has_capability CODE_EXEC)
  )

  ; ============== PRIVILEGE ESCALATION ==============

  (:action overwrite_cred_struct
    :parameters ()
    :precondition (and
      (has_capability CODE_EXEC)
      (kaslr_bypassed)
    )
    :effect (and
      (has_capability CRED_OVERWRITE)
      (capability_stable CRED_OVERWRITE)
    )
  )

  (:action commit_creds_prepare_kernel_cred
    :parameters ()
    :precondition (has_capability CRED_OVERWRITE)
    :effect (privilege_escalated)
  )

  (:action direct_cred_overwrite
    :parameters ()
    :precondition (and
      (has_capability ARB_WRITE)
      (kaslr_bypassed)
    )
    :effect (and
      (has_capability CRED_OVERWRITE)
      (privilege_escalated)
    )
  )

  ; ============== SELINUX BYPASS ==============

  (:action disable_selinux_enforce
    :parameters ()
    :precondition (and
      (has_capability ARB_WRITE)
      (kaslr_bypassed)
    )
    :effect (and
      (has_capability SELINUX_BYPASS)
      (selinux_disabled)
    )
  )

  (:action patch_selinux_permissive
    :parameters ()
    :precondition (and
      (has_capability CODE_EXEC)
      (kaslr_bypassed)
    )
    :effect (and
      (has_capability SELINUX_BYPASS)
      (selinux_disabled)
    )
  )

  ; ============== POST EXPLOITATION ==============

  (:action escape_app_sandbox
    :parameters ()
    :precondition (and
      (in_untrusted_app)
      (privilege_escalated)
      (selinux_disabled)
    )
    :effect (escaped_sandbox)
  )

  (:action spawn_root_shell
    :parameters ()
    :precondition (and
      (privilege_escalated)
      (selinux_disabled)
    )
    :effect (root_shell)
  )

  (:action enable_adb_root
    :parameters ()
    :precondition (and
      (privilege_escalated)
      (selinux_disabled)
    )
    :effect (adb_root)
  )

  (:action compromise_zygote
    :parameters ()
    :precondition (and
      (escaped_sandbox)
      (has_capability CODE_EXEC)
    )
    :effect (zygote_compromised)
  )

  (:action kernel_code_exec_from_rop
    :parameters ()
    :precondition (and
      (has_capability CODE_EXEC)
      (privilege_escalated)
    )
    :effect (kernel_code_execution)
  )
)
'''
