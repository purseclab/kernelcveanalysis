;; msg_msg heap spray and exploitation technique
;; Adds msg_msg-specific spray, arb read/write derivation

;; Additional target_struct constants: MSG_MSG
;; Additional capability constants: (none new)

;; TYPES EXTENSION: (none — uses target_struct from base)
;; PREDICATES EXTENSION:
;;   (msg_queue_ready)
;;   (msg_spray_done)

(:action spray_msg_msg
  :parameters (?v - vuln_primitive)
  :precondition (and (vuln_triggered ?v))
  :effect (and (sprayed_struct MSG_MSG) (heap_controlled) (msg_spray_done))
)

(:action derive_arb_read_from_msg_msg
  :parameters ()
  :precondition (and (corrupted_struct MSG_MSG) (has_reclaimed))
  :effect (and (has_capability ARB_READ) (has_info_leak))
)

(:action derive_arb_write_from_msg_msg
  :parameters ()
  :precondition (and (corrupted_struct MSG_MSG) (has_reclaimed))
  :effect (and (has_capability ARB_WRITE))
)

(:action reclaim_with_msg_msg
  :parameters (?v - vuln_primitive)
  :precondition (and (vuln_triggered ?v) (sprayed_struct MSG_MSG))
  :effect (and (has_reclaimed) (corrupted_struct MSG_MSG))
)
