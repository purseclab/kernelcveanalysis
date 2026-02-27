;; SMEP/SMAP bypass actions (x86_64 Linux)

;; Additional predicates:
;;   (smep_active)
;;   (smap_active)
;;   (smep_bypassed)
;;   (smap_bypassed)
;;   (kpti_active)
;;   (kpti_handled)

(:action bypass_smep
  :parameters ()
  :precondition (and (smep_active) (has_capability ARB_WRITE))
  :effect (and (smep_bypassed))
)

(:action bypass_smap
  :parameters ()
  :precondition (and (smap_active) (has_capability ARB_WRITE))
  :effect (and (smap_bypassed))
)

(:action handle_kpti_trampoline
  :parameters ()
  :precondition (and (kpti_active) (kaslr_bypassed))
  :effect (and (kpti_handled))
)
