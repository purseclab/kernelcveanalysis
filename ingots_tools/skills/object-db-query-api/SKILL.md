---
name: objectdb
description: Objectdb is a python library and cli which allows querying heap objects and related metadata in built linux kernels.
---

# Object DB Query API

Use the high-level `object_db` query API when you need to scan an existing `object_db.sqlite` for kernel objects with certain field layouts, pointer relationships, or kmalloc allocation properties.

Prefer this API over writing ad hoc SQL when the task is "find objects that look like X".

For simple lookups and summaries, use the packaged CLI first instead of writing Python immediately:

```bash
objectdb --kernel <kernel> stats
objectdb --kernel <kernel> sizeof file
objectdb --kernel <kernel> field-offset file.f_pos_lock.wait_list
objectdb --kernel <kernel> object <object-id>
objectdb --kernel <kernel> kmalloc-for-object <object-id>
objectdb --kernel <kernel> cache-for-object --object-id <object-id>
objectdb --kernel <kernel> objects-for-cache kmalloc-64
```

Use the CLI when the task is already covered by one of those built-in queries. Switch to the Python API when the user needs a custom predicate or a reusable scan script.

To build a synthesis object database in the standard `KEXPLOIT_DATA_DIR` layout, use:

```bash
objectdb create \
  --kernel ingots_5.10.107 \
  --codeql-db /path/to/codeql-db \
  --linux-src /path/to/linux-src \
  --compile-commands /path/to/compile_commands.json
```

That writes `metadata.json`, `compile_commands.json`, and `object_db.sqlite` under `$KEXPLOIT_DATA_DIR/synthesis/<kernel>/`. CodeQL queries supply all type layouts and allocation links; BTF and `bpftool` are not required. `--vmlinux` is optional metadata only. Extract CodeQL using the target architecture, configuration, and compiler options. Rebuild unsupported database schemas with `objectdb create`, including the initial CodeQL schema without field alternatives. IDs from BTF-backed databases are not preserved.

IDs identify entities within the extracted CodeQL database; do not reuse them across different extractions. Same-named types remain separate, so name lookups can return multiple results. Structs and unions are included even without a known allocation site. Allocation discovery covers supported allocator calls with inferable record types; a missing callsite does not prove that the type cannot be allocated.

When you need a standalone analysis script, generate one first with:

```bash
objectdb scaffold-script /tmp/object_scan.py
```

If the user wants the script to run without extra flags, bake in defaults:

```bash
objectdb scaffold-script /tmp/object_scan.py --default-db /path/to/object_db.sqlite
objectdb scaffold-script /tmp/object_scan.py --default-kernel ingots_5.10.107
```

That command writes a `uv run --script` template with an inline local-path dependency on this checkout's `object_db` package. After generation, edit the predicate in the script, then run it with either:

```bash
uv run /tmp/object_scan.py --db /path/to/object_db.sqlite
uv run /tmp/object_scan.py --synthesis-dir /path/to/synthesis/<kernel-or-metadata>
```

Prefer this scaffolded script path when the user wants a reusable one-off analysis rather than code inside the repository.

`--default-kernel` requires `KEXPLOIT_DATA_DIR` to be set when generating the script. Use `--default-db` when supplying a concrete SQLite path.

## Primary entrypoints

Load from a DB file:

```python
from pathlib import Path
from object_db import load_object_set

objects = load_object_set(Path("/path/to/object_db.sqlite"))
```

Load from a synthesis directory or `metadata.json`:

```python
from pathlib import Path
from object_db import load_object_set_from_synthesis_dir

objects = load_object_set_from_synthesis_dir(Path("/path/to/synthesis/kernel_name"))
objects = load_object_set_from_synthesis_dir(Path("/path/to/synthesis/kernel_name/metadata.json"))
```

## Core types

- `ObjectSet`
  - `get_all()`
  - `get_by_id(obj_id)`
  - `get_by_name(type_name)`
  - `filter(lambda obj: ...)`
  - `all_kmalloc_calls()`
  - `kmalloc_calls_for_object(obj_id)`
  - `linked_kmalloc_call_count()`

- `HeapObject`
  - fields: `id`, `type_id`, `type_name`, `type_kind`, `size`, `location`, `source_code`, `is_anon`, `fields`, `kmalloc_calls`
  - helpers:
    - `field_named(name)`
    - `field_at_offset(byte_offset)` (immediate members)
    - `fields_at_offset(byte_offset)` (all nested/overlapping matches)
    - `iter_fields()` (embedded records and fixed arrays)
    - `has_field_named(name)`
    - `has_pointer_field_at_offset(byte_offset)`
    - `has_pointer_to_type_name(name)`
    - `has_pointer_to_type_id(type_id)`
    - `is_allocated_from_cache(cache_name)`
    - `has_kmalloc_call(predicate)`

- `Field`
  - fields: `name`, `path`, `byte_offset`, `bit_offset`, `bitfield_size`, `type_id`, `type_name`, `type_kind`
  - helpers:
    - `is_pointer()`
    - `points_to_type_name(name)`
    - `points_to_type_id(type_id)`
    - `points_to_kind(kind)`

- `KmallocCall`
  - fields: `id`, `type_id`, `heap_object_id`, `call_site`, `call_type`, `struct_type`, `struct_def`, `struct_size`, `flags`, `alloc_size`, `is_flexible`, `kmalloc_cache_name`
  - helper:
    - `uses_cache(cache_name)`

## Common scan patterns

Objects of a given struct type:

```python
pipe_buffers = objects.get_by_name("pipe_buffer")
```

Objects with allocations recorded under an exact cache name:

```python
km64 = objects.filter(lambda obj: obj.is_allocated_from_cache("kmalloc-64"))
```

This matches recorded cache labels; it does not infer a kmalloc bucket from size. Ordinary kmalloc calls can have `kmalloc_cache_name=None`. `None` means that a cache name was not supplied or could not be resolved, and does not establish allocator compatibility.

Objects with a pointer field at a known offset:

```python
with_ptr = objects.filter(lambda obj: obj.has_pointer_field_at_offset(0x20))
```

Objects with any pointer to a target type:

```python
files = objects.filter(lambda obj: obj.has_pointer_to_type_name("file"))
```

Objects with a specific field name and allocation behavior:

```python
targets = objects.filter(
    lambda obj: obj.has_field_named("ops") and obj.is_allocated_from_cache("kmalloc-192")
)
```

Inspect the exact field:

```python
obj = objects.get_by_id(123)
if obj is not None:
    for field in obj.fields_at_offset(0x10):
        if field.is_pointer():
            print(field.path, field.type_name)
```

Inspect callsites:

```python
interesting = objects.filter(
    lambda obj: obj.has_kmalloc_call(lambda call: call.call_type == "kmalloc")
)
```

## Type graph inspection

For lower-level type inspection, use the CodeQL type graph instead of recreating BTF wrappers or writing SQL:

```python
from pathlib import Path
from object_db import ObjectDb

db = ObjectDb(Path("/path/to/object_db.sqlite"), read_only=True)
try:
    types = db.load_type_graph()
finally:
    db.close()

for record in types.get_by_name("file"):
    print(record.id, record.size, record.alignment, record.location)
    for member in types.members_of(record.id):
        member_type = types.unwrap(member.type_id)
        print(member.name, member.byte_offset, member_type.name)
```

`TypeInfo` carries `id`, `name`, `kind`, `size`, `alignment`, `referenced_type_id`, `element_count`, `location`, and `is_anon`. `TypeMember` carries `owner_type_id`, numeric `index`, `name`, `type_id`, `byte_offset`, `bit_offset`, and `bitfield_size`. `TypeGraph.get_type(type_id)` retrieves an exact type; `unwrap(type_id)` removes typedefs and qualifiers without following pointers. Missing sizes, offsets, and bitfield metadata remain `None`.

## Guidance

- Use `objectdb` CLI subcommands first for simple built-in queries and summaries.
- Use `objectdb create` when the object database does not exist yet and the user has the synthesis inputs.
- For a quick standalone workflow, use `scaffold-script` and then edit the generated lambda.
- Use `ObjectSet.filter(...)` for exploratory scans.
- Chain small predicates rather than building one huge lambda immediately.
- Prefer `type_name`, field offsets, pointer relationships, and cache names as the main discriminators.
- Fall back to the lower-level SQLAlchemy schema only when you need aggregation or raw table inspection.
- If you need a quick human-facing summary, use this API for narrowing and then print `HeapObject.location`, `source_code`, and `kmalloc_calls`.

Pointer predicates traverse embedded structs, unions, and fixed arrays without following pointers. `fields` and singular field helpers inspect immediate members. Cache names alone do not establish reclaim compatibility. Filtering an `ObjectSet` restricts calls to selected objects; keep the original set to inspect all imported calls.

CodeQL may resolve several declarations to one type ID. Its displayed location is a deterministic representative. Alternative field facts at the same member index are preserved; use plural field results to inspect them rather than assuming every fact belongs to one consistent translation-unit layout.
