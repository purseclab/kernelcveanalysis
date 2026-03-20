# Linked-List Unlink Write Primitive

This primitive turns a corrupted linked-list unlink into a constrained kernel write. If an exploit can arrange for a kernel cleanup path to call an unlink helper such as `__hlist_del()` or `list_del()` on attacker-controlled `next` and `pprev` or `prev` pointers, the unlink operation writes attacker-chosen values to attacker-chosen kernel addresses. Binder-node cleanup is one concrete example of this pattern, but the primitive is not specific to Binder.

## Preconditions

- You already have a bug that lets you replace or corrupt a kernel object that will later be removed from a linked list.
- You can control the unlink-relevant pointer fields that the kernel will dereference during cleanup.
- You can keep enough of the surrounding object plausible that the kernel reaches the unlink path instead of crashing earlier in cleanup.
- You understand the unlink helper used by the target path:
  - `__hlist_del()` gives `*pprev = next`, and if `next` is non-zero also `next->pprev = pprev`.
  - doubly-linked `list_del()` style helpers give paired writes through `prev->next` and `next->prev`.
- If the surrounding cleanup logic needs additional believable fields, you can populate them with leak-assisted or conservative values.

## Usage

1. Call `init_list_unlink_write` with callbacks for spraying a fake object and triggering the cleanup path that performs the unlink.
2. Populate a fake object that contains the target list node and any surrounding fields needed to survive until unlink.
3. Call `execute_list_unlink_write_hlist` for the `hlist` form or `execute_list_unlink_write_list` for a doubly-linked list form.
4. Use `execute_list_unlink_zero` when you specifically want the one-write `*pprev = 0` shape from an `hlist` unlink.

## Key Concepts

- This is not a general arbitrary-write primitive. The write shape is constrained by linked-list unlink semantics.
- The hard part is usually not the unlink write itself, but getting cleanup far enough that the kernel actually performs the unlink on attacker-controlled pointers.
- `hlist` and doubly-linked-list unlinks have different write shapes. The primitive should document which one the target path uses.
- The reclaim carrier is separate from the primitive. Any bug that gives a fake object at the right address can feed this pattern.

## Binder Example

The badnode exploit family provides a good example. A freed `binder_node` is reclaimed with attacker-controlled bytes, and later Binder cleanup executes `__hlist_del()` on fields taken from the fake node. To make that work, the fake Binder object keeps a plausible work-list pointer and a refcount state that still reaches the final free path, while the `dead_node.next` and `dead_node.pprev` fields are replaced with attacker-selected addresses.

## How It Works

When the kernel removes an object from a linked structure, it trusts the node pointers already stored in that object. If an exploit corrupts or replaces the object before cleanup runs, those pointers no longer describe a legitimate list node. Instead, unlink writes attacker-chosen values through attacker-chosen addresses.

For the `hlist` case, the important effect is `*pprev = next`. When `next` is zero, that collapses into a one-shot zero write. For a doubly-linked list, unlink usually performs both `prev->next = next` and `next->prev = prev`. Different exploit families use one form or the other, but the underlying primitive is the same: steer a kernel unlink helper over attacker-controlled node pointers and treat the resulting stores as a constrained write primitive.
