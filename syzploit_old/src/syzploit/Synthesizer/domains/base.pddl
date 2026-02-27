;; ============================================================
;; Base PDDL domain for kernel exploit synthesis
;; 
;; This defines the generic types, predicates, and abstract
;; actions that all kernel exploit plans share, regardless of
;; specific technique or platform.
;;
;; Technique-specific and mitigation-specific actions are loaded
;; from domains/techniques/ and domains/mitigations/ and merged
;; by runtime into a single composite domain.
;; ============================================================

(define (domain kernel-exploit)
  (:requirements :strips :typing)

  (:types
    ;; Core types
    vuln_primitive   ;; vulnerability trigger (uaf, oob_read, oob_write, etc.)
    capability       ;; derived capability (arb_read, arb_write, code_exec, etc.)
    target_struct    ;; kernel struct for spray/corruption target
    context          ;; execution context (userspace, kernel, etc.)
  )

  (:constants
    USERSPACE KERNEL - context

    ;; Vulnerability primitives
    UAF OOB_READ OOB_WRITE RACE DOUBLE_FREE TYPE_CONFUSION
    INTEGER_OVERFLOW USE_BEFORE_INIT NULL_DEREF LOGIC_BUG - vuln_primitive

    ;; Capabilities (used in action effects like has_capability)
    ARB_READ ARB_WRITE CODE_EXEC CRED_OVERWRITE NAMESPACE_ESCAPE - capability

    ;; Target structs (used in spray/corrupt actions)
    MSG_MSG PIPE_BUFFER SEQ_OPERATIONS TTY_STRUCT SK_BUFF
    CRED_STRUCT TASK_STRUCT - target_struct
  )

  (:predicates
    ;; Vulnerability state
    (has_vuln ?v - vuln_primitive)
    (vuln_triggered ?v - vuln_primitive)

    ;; Heap / slab state
    (heap_controlled)
    (has_reclaimed)

    ;; Derived capabilities
    (has_capability ?c - capability)
    (has_info_leak)

    ;; Mitigation state
    (kaslr_bypassed)
    (kaslr_active)

    ;; Execution context
    (running_context ?ctx - context)

    ;; Target structs
    (sprayed_struct ?s - target_struct)
    (corrupted_struct ?s - target_struct)

    ;; Post-exploitation state
    (code_exec)
    (privilege_escalated)
    (root_shell)
  )

  ;; ---- Generic vulnerability triggers ----
  ;; The PoC is modeled as a PDDL action separately (injected at problem time).
  ;; These are generic abstract triggers.

  (:action trigger_uaf
    :parameters (?v - vuln_primitive)
    :precondition (and (has_vuln ?v) (running_context USERSPACE))
    :effect (and (vuln_triggered ?v))
  )

  (:action trigger_oob_read
    :parameters (?v - vuln_primitive)
    :precondition (and (has_vuln ?v) (running_context USERSPACE))
    :effect (and (vuln_triggered ?v) (has_info_leak))
  )

  (:action trigger_oob_write
    :parameters (?v - vuln_primitive)
    :precondition (and (has_vuln ?v) (running_context USERSPACE))
    :effect (and (vuln_triggered ?v) (heap_controlled))
  )

  (:action trigger_race_condition
    :parameters (?v - vuln_primitive)
    :precondition (and (has_vuln ?v) (running_context USERSPACE))
    :effect (and (vuln_triggered ?v))
  )

  (:action trigger_double_free
    :parameters (?v - vuln_primitive)
    :precondition (and (has_vuln ?v) (running_context USERSPACE))
    :effect (and (vuln_triggered ?v))
  )

  (:action trigger_type_confusion
    :parameters (?v - vuln_primitive)
    :precondition (and (has_vuln ?v) (running_context USERSPACE))
    :effect (and (vuln_triggered ?v) (heap_controlled))
  )

  (:action trigger_integer_overflow
    :parameters (?v - vuln_primitive)
    :precondition (and (has_vuln ?v) (running_context USERSPACE))
    :effect (and (vuln_triggered ?v) (heap_controlled))
  )

  ;; ---- Generic heap spray ----

  (:action spray_target_struct
    :parameters (?v - vuln_primitive ?s - target_struct)
    :precondition (and (vuln_triggered ?v))
    :effect (and (sprayed_struct ?s) (heap_controlled))
  )

  (:action reclaim_freed_object
    :parameters (?v - vuln_primitive ?s - target_struct)
    :precondition (and (vuln_triggered ?v) (sprayed_struct ?s))
    :effect (and (has_reclaimed) (corrupted_struct ?s))
  )

  ;; ---- Generic capability derivation ----

  (:action derive_arb_read
    :parameters (?s - target_struct)
    :precondition (and (corrupted_struct ?s) (has_reclaimed))
    :effect (and (has_capability ARB_READ) (has_info_leak))
  )

  (:action derive_arb_write
    :parameters (?s - target_struct)
    :precondition (and (corrupted_struct ?s) (has_reclaimed))
    :effect (and (has_capability ARB_WRITE))
  )

  (:action derive_info_leak
    :parameters (?s - target_struct)
    :precondition (and (corrupted_struct ?s))
    :effect (and (has_info_leak))
  )

  ;; ---- Generic privilege escalation ----

  (:action direct_cred_overwrite
    :parameters ()
    :precondition (and (has_capability ARB_WRITE) (kaslr_bypassed))
    :effect (and (privilege_escalated))
  )

  (:action commit_creds_prepare_kernel_cred
    :parameters ()
    :precondition (and (code_exec))
    :effect (and (privilege_escalated))
  )

  (:action spawn_root_shell
    :parameters ()
    :precondition (and (privilege_escalated))
    :effect (and (root_shell))
  )
)
