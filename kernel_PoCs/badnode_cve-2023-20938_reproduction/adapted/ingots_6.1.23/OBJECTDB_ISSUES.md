# ObjectDB Issues and Improvement Ideas

This note captures issues and idiosyncrasies encountered while using ObjectDB
to adapt `badnode` to `ingots_6.1.23`. The main query was: find reclaimable
kernel objects of size `<= 256` with useful pointer-like fields at the Binder
UAF leak offsets, especially `+88` and `+96`.

## Issues Encountered

### Kmalloc Calls Not Always Linked to Heap Objects

Several allocation records returned by `ObjectDb.get_all_kmalloc_calls()` had
`heap_object_id = NULL` even though they had enough type information to be
useful. These objects did not appear through the high-level object set returned
by `load_object_set_from_synthesis_dir()`.

Impact:

- High-level object queries missed viable candidates.
- The scanner had to manually collect unlinked kmalloc calls, group them by
  `struct_type`, recover the BTF type, and synthesize candidate objects.
- This made it hard to know whether a candidate was absent because it was not
  allocated or because the database failed to associate the allocation with a
  heap object.

Example workaround:

- `scripts/scan_object_db_offsets.py` loads both the high-level object set and
  raw kmalloc calls.
- For calls with `heap_object_id = NULL`, it resolves `struct_type` through BTF
  and adds a synthetic candidate.

Suggested improvement:

- Expose an API that returns all allocation-backed types, including partially
  linked or unlinked allocation records.
- Add a reason/status field such as `linked`, `btf_only`, `unresolved_type`, or
  `missing_heap_object`.
- If possible, fix the synthesis step so these kmalloc calls receive stable heap
  object IDs.

### Cache Names Need More Normalization

For exploit planning, the useful reclaim property was mostly object size and
underlying slab/page order, not the literal cache label. Some records reported
the cache as `default`, while others used specific cache names.

Impact:

- A `default` cache label was ambiguous during cross-cache planning.
- The search had to treat `default` as "go by size" instead of as a concrete
  cache.
- It was not obvious from the high-level API whether a `default` object was
  practically reclaimable with objects from the same size class.

Suggested improvement:

- Add normalized cache metadata:
  - effective allocation size
  - kmalloc bucket or named cache
  - slab object size
  - slab page order
  - whether the cache is `SLAB_ACCOUNT`
  - whether the object is allocated from a dedicated cache or generic kmalloc
- Provide a helper like `object.reclaim_class()` that groups objects by the
  allocator properties that matter for cross-cache reclaim.

### Pointer-Offset Queries Are Too Manual

The useful exploit question was not "show me all fields"; it was "which
allocated objects of size `<= N` have pointer fields at exact leak offsets, and
what do those pointers reference?"

Impact:

- We needed custom recursive BTF traversal to unwrap typedefs, qualifiers,
  arrays, anonymous structs, and anonymous unions.
- Scoring had to be implemented outside ObjectDB.
- Candidate quality depended on custom heuristics for interesting pointees such
  as `file`, `cred`, `task_struct`, `seq_file`, `epitem`, `list_head`, and
  `hlist_node`.

Suggested improvement:

- Add a first-class query helper for pointer fields at offsets, for example:

```python
objects.find_pointer_fields(
    max_size=256,
    offsets=[88, 96],
    allocated_only=True,
    flatten_embedded=True,
)
```

- Return structured hits containing:
  - object type and size
  - field path
  - byte offset
  - pointer target type
  - allocation sites
  - cache/reclaim metadata

### Allocation Reachability Is Not Captured

ObjectDB could identify structurally useful objects, but it did not tell us how
realistic each object was to allocate from an Android app context.

Examples:

- `struct fs_context` had a useful direct `cred` pointer at `+88`, but `fsopen()`
  was gated by permissions in the target environment.
- `struct rpc_cred` had a useful `cr_cred` pointer at `+88`, but its practical
  reachability on Android was weak.
- `struct file` was less direct, but easy to spray via `/dev/null` and produced
  reliable self-referential wait-list leaks.

Suggested improvement:

- Attach syscall or kernel API reachability metadata where possible.
- Provide optional tags such as `requires_cap_sys_admin`, `requires_mount_ns`,
  `requires_network`, `requires_binder`, `requires_debugfs`, or `android_likely`.
- Allow users to add local reachability annotations without modifying the core
  database.

### Global/KASLR Leak Discovery Could Be Easier

Some useful leaks are not heap topology leaks; they are pointers into stable
kernel text/data, such as file operation tables or other global structures.

Impact:

- The search found candidates like `struct seq_file`, where `op` at `+88` can
  provide a KASLR leak.
- Determining whether a pointer target is heap, text, rodata, data, or a module
  pointer still required manual interpretation.

Suggested improvement:

- Classify pointer targets by likely address class when symbol/BTF information
  is available:
  - heap object
  - kernel text
  - kernel rodata
  - kernel data
  - module text/data
  - percpu
- Add a query mode for "find KASLR-leaking objects under size N".

### Field Layout Validation Is Useful But Separate

The exploit needed exact offsets for `struct file`, `struct epitem`,
`struct inode`, and `struct super_block`. ObjectDB had enough BTF data to answer
this, but the flow required a separate custom script.

Example:

- `scripts/dump_offsets.py` validates offsets used by `exploit.c`, including
  `file->f_pos_lock.wait_list`, `file->f_inode`, `file->f_op`,
  `epitem->fllink`, `epitem->event.data`, `inode->i_sb`, and
  `super_block->s_blocksize`.

Suggested improvement:

- Add a small official CLI or API for resolving field paths:

```bash
objectdb field-offset ingots_6.1.23 'file.f_pos_lock.wait_list'
objectdb sizeof ingots_6.1.23 epitem
```

- Support anonymous struct/union recursion by default.

## Feature Requests

### Reclaim-Oriented Search

Add a query that starts from exploit constraints instead of type names:

```python
objects.find_reclaim_candidates(
    max_object_size=256,
    leak_offsets=[88, 96],
    pointer_targets=["file", "cred", "task_struct", "seq_file", "list_head"],
    require_user_reachable=True,
)
```

Useful output would include a ranked table with size, cache class, allocation
sites, field hits, pointer target types, and any known reachability constraints.

### Linked-List Shape Recognition

Many useful leaks are not direct semantic pointers but embedded list heads or
list nodes. ObjectDB could improve exploit usability by recognizing common
kernel container patterns:

- `struct list_head` self-pointer in an empty list
- `struct hlist_node` unlink primitive layout
- `wait_queue_head_t` list head at a stable offset
- `rb_node` parent/color layout
- object base recovery from embedded list-node pointer offsets

This would have made the `struct file` candidate easier to identify because the
useful leak was `file->f_pos_lock.wait_list` at `+88/+96`, not an obvious direct
pointer to another high-value object.

### Candidate Notes and Local Annotations

During analysis, some candidates were rejected for environmental reasons rather
than structural reasons. It would be useful to attach local notes to a database
or export:

- candidate is reachable/unreachable on Android
- candidate requires a permission
- candidate can be sprayed with a specific syscall sequence
- candidate leaks a self-pointer, global pointer, file pointer, or credential
  pointer
- candidate was tested and failed/succeeded

This would make iterative exploit development less dependent on external
markdown notes.

## Summary

ObjectDB was useful for quickly finding candidates once custom scripts bridged
the gaps. The highest-value improvements would be:

1. Make allocation-backed object discovery complete even when kmalloc calls are
   not linked to high-level heap objects.
2. Expose normalized allocator/reclaim metadata instead of relying on raw cache
   labels.
3. Add first-class pointer-at-offset and field-offset queries.
4. Support reachability and local exploit-development annotations.
5. Recognize common kernel container/list patterns that produce useful leaks.
