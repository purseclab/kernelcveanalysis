;; Modprobe path overwrite technique (Linux-specific)
;; Overwrite modprobe_path to get arbitrary code execution as root

;; Additional predicates:
;;   (modprobe_path_overwritten)

(:action overwrite_modprobe_path
  :parameters ()
  :precondition (and (has_capability ARB_WRITE) (kaslr_bypassed))
  :effect (and (modprobe_path_overwritten))
)

(:action trigger_modprobe_exec
  :parameters ()
  :precondition (and (modprobe_path_overwritten))
  :effect (and (code_exec) (privilege_escalated))
)
