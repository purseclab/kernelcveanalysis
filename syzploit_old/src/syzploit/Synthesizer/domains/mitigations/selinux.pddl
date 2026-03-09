;; SELinux bypass and Android post-exploitation actions

;; Additional predicates:
;;   (selinux_active) (selinux_disabled)
;;   (sandbox_escaped) (adb_root_enabled)
;;   (binder_context)

(:action disable_selinux_enforce
  :parameters ()
  :precondition (and (has_capability ARB_WRITE) (kaslr_bypassed) (selinux_active))
  :effect (and (selinux_disabled))
)

(:action patch_selinux_permissive
  :parameters ()
  :precondition (and (has_capability ARB_WRITE) (kaslr_bypassed) (selinux_active))
  :effect (and (selinux_disabled))
)

(:action escape_app_sandbox
  :parameters ()
  :precondition (and (privilege_escalated) (selinux_disabled))
  :effect (and (sandbox_escaped))
)

(:action enable_adb_root
  :parameters ()
  :precondition (and (privilege_escalated) (selinux_disabled))
  :effect (and (adb_root_enabled))
)
