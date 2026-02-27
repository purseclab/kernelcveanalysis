;; KASLR bypass actions
;; Applies to both Linux and Android kernels

;; Uses predicates from base: kaslr_bypassed, kaslr_active, has_info_leak, has_capability

(:action bypass_kaslr
  :parameters ()
  :precondition (and (has_capability ARB_READ) (kaslr_active))
  :effect (and (kaslr_bypassed))
)

(:action bypass_kaslr_via_info_leak
  :parameters ()
  :precondition (and (has_info_leak) (kaslr_active))
  :effect (and (kaslr_bypassed))
)
