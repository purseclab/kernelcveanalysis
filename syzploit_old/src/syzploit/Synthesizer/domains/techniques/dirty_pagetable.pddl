;; Dirty pagetable technique
;; Uses page table entry corruption for arbitrary kernel R/W

;; Additional predicates:
;;   (pte_corrupted)
;;   (physmap_mapped)

(:action corrupt_page_table_entry
  :parameters (?v - vuln_primitive)
  :precondition (and (vuln_triggered ?v) (heap_controlled))
  :effect (and (pte_corrupted))
)

(:action map_physmap_region
  :parameters ()
  :precondition (and (pte_corrupted))
  :effect (and (physmap_mapped) (has_capability ARB_READ) (has_capability ARB_WRITE))
)
