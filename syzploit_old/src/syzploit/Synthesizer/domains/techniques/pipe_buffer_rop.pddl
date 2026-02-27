;; pipe_buffer exploitation + ROP chain technique
;; Uses pipe_buffer struct for heap spray and ROP payload delivery

;; Additional target_struct constants: PIPE_BUFFER
;; Additional predicates:
;;   (rop_chain_ready)
;;   (stack_pivoted)

(:action spray_pipe_buffer
  :parameters (?v - vuln_primitive)
  :precondition (and (vuln_triggered ?v))
  :effect (and (sprayed_struct PIPE_BUFFER) (heap_controlled))
)

(:action reclaim_with_pipe_buffer
  :parameters (?v - vuln_primitive)
  :precondition (and (vuln_triggered ?v) (sprayed_struct PIPE_BUFFER))
  :effect (and (has_reclaimed) (corrupted_struct PIPE_BUFFER))
)

(:action prepare_rop_chain
  :parameters ()
  :precondition (and (kaslr_bypassed) (has_capability ARB_WRITE))
  :effect (and (rop_chain_ready))
)

(:action perform_stack_pivot
  :parameters ()
  :precondition (and (rop_chain_ready) (has_capability ARB_WRITE))
  :effect (and (stack_pivoted))
)

(:action execute_rop_payload
  :parameters ()
  :precondition (and (stack_pivoted) (rop_chain_ready))
  :effect (and (code_exec))
)

(:action derive_arb_read_from_pipe_buffer
  :parameters ()
  :precondition (and (corrupted_struct PIPE_BUFFER) (has_reclaimed))
  :effect (and (has_capability ARB_READ) (has_info_leak))
)
