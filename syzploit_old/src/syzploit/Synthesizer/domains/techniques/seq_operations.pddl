;; seq_operations exploitation technique
;; Uses seq_operations struct for function pointer hijack

;; Additional target_struct constants: SEQ_OPERATIONS

(:action spray_seq_operations
  :parameters (?v - vuln_primitive)
  :precondition (and (vuln_triggered ?v))
  :effect (and (sprayed_struct SEQ_OPERATIONS) (heap_controlled))
)

(:action reclaim_with_seq_operations
  :parameters (?v - vuln_primitive)
  :precondition (and (vuln_triggered ?v) (sprayed_struct SEQ_OPERATIONS))
  :effect (and (has_reclaimed) (corrupted_struct SEQ_OPERATIONS))
)

(:action hijack_seq_ops_fptr
  :parameters ()
  :precondition (and (corrupted_struct SEQ_OPERATIONS) (kaslr_bypassed))
  :effect (and (code_exec))
)
