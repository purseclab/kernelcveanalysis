;; sk_buff exploitation technique
;; Uses sk_buff for heap spray and data corruption via networking

;; Additional target_struct constants: SK_BUFF

(:action spray_sk_buff
  :parameters (?v - vuln_primitive)
  :precondition (and (vuln_triggered ?v))
  :effect (and (sprayed_struct SK_BUFF) (heap_controlled))
)

(:action reclaim_with_sk_buff
  :parameters (?v - vuln_primitive)
  :precondition (and (vuln_triggered ?v) (sprayed_struct SK_BUFF))
  :effect (and (has_reclaimed) (corrupted_struct SK_BUFF))
)

(:action derive_arb_read_from_sk_buff
  :parameters ()
  :precondition (and (corrupted_struct SK_BUFF) (has_reclaimed))
  :effect (and (has_capability ARB_READ) (has_info_leak))
)
