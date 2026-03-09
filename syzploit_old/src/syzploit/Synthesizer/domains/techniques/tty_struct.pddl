;; tty_struct exploitation technique
;; Uses tty_struct/tty_operations for function pointer hijack

;; Additional target_struct constants: TTY_STRUCT

(:action spray_tty_struct
  :parameters (?v - vuln_primitive)
  :precondition (and (vuln_triggered ?v))
  :effect (and (sprayed_struct TTY_STRUCT) (heap_controlled))
)

(:action reclaim_with_tty_struct
  :parameters (?v - vuln_primitive)
  :precondition (and (vuln_triggered ?v) (sprayed_struct TTY_STRUCT))
  :effect (and (has_reclaimed) (corrupted_struct TTY_STRUCT))
)

(:action hijack_tty_ops_fptr
  :parameters ()
  :precondition (and (corrupted_struct TTY_STRUCT) (kaslr_bypassed))
  :effect (and (code_exec))
)
