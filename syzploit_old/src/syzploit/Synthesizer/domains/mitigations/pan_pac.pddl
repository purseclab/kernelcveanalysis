;; PAN/PAC/MTE bypass actions (ARM64, primarily Android)

;; Additional predicates:
;;   (pan_active) (pan_bypassed)
;;   (pac_active) (pac_bypassed)
;;   (mte_active) (mte_bypassed)
;;   (jop_chain_ready)

(:action bypass_pan
  :parameters ()
  :precondition (and (pan_active) (has_capability ARB_WRITE))
  :effect (and (pan_bypassed))
)

(:action bypass_pac
  :parameters ()
  :precondition (and (pac_active) (has_capability ARB_WRITE))
  :effect (and (pac_bypassed))
)

(:action bypass_mte
  :parameters ()
  :precondition (and (mte_active) (has_info_leak))
  :effect (and (mte_bypassed))
)

(:action prepare_jop_chain
  :parameters ()
  :precondition (and (kaslr_bypassed) (has_capability ARB_WRITE))
  :effect (and (jop_chain_ready))
)

(:action execute_jop_payload
  :parameters ()
  :precondition (and (jop_chain_ready))
  :effect (and (code_exec))
)
