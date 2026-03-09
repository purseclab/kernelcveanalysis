;; Cross-cache reclamation technique
;; Allows reclaiming freed objects across slab caches via page-level reuse

;; Additional predicates:
;;   (cross_cache_ready)
;;   (pages_freed)

(:action free_slab_pages
  :parameters (?v - vuln_primitive)
  :precondition (and (vuln_triggered ?v))
  :effect (and (pages_freed))
)

(:action cross_cache_reclaim
  :parameters (?v - vuln_primitive ?s - target_struct)
  :precondition (and (pages_freed))
  :effect (and (sprayed_struct ?s) (has_reclaimed) (corrupted_struct ?s) (heap_controlled) (cross_cache_ready))
)
