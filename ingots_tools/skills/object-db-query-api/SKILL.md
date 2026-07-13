---
name: object-db-query-api
description: Use the high-level object_db wrapper API to scan kernel objects in Python by loading an ObjectSet and filtering HeapObject entries with helper predicates instead of raw SQL.
---

# Object DB Query API

Use the high-level `object_db` query API when you need to scan an existing `object_db.sqlite` for kernel objects with certain field layouts, pointer relationships, or kmalloc allocation properties.

Prefer this API over writing ad hoc SQL when the task is "find objects that look like X".

For simple lookups and summaries, use the packaged CLI first instead of writing Python immediately:

```bash
objectdb --kernel <kernel> stats
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
  --vmlinux /path/to/vmlinux \
  --linux-src /path/to/linux-src \
  --compile-commands /path/to/compile_commands.json
```

That writes `metadata.json`, `compile_commands.json`, and `object_db.sqlite` under `$KEXPLOIT_DATA_DIR/synthesis/<kernel>/`.

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

- `HeapObject`
  - fields: `id`, `type_id`, `type_name`, `type_kind`, `size`, `location`, `source_code`, `is_anon`, `fields`, `kmalloc_calls`
  - helpers:
    - `field_named(name)`
    - `field_at_offset(byte_offset)`
    - `has_field_named(name)`
    - `has_pointer_field_at_offset(byte_offset)`
    - `has_pointer_to_type_name(name)`
    - `has_pointer_to_type_id(type_id)`
    - `is_allocated_from_cache(cache_name)`
    - `has_kmalloc_call(predicate)`

- `Field`
  - fields: `name`, `byte_offset`, `bitfield_size`, `type_id`, `type_name`, `type_kind`
  - helpers:
    - `is_pointer()`
    - `points_to_type_name(name)`
    - `points_to_type_id(type_id)`
    - `points_to_kind(kind)`

- `KmallocCall`
  - fields: `id`, `call_site`, `call_type`, `struct_type`, `struct_def`, `struct_size`, `flags`, `alloc_size`, `is_flexible`, `kmalloc_cache_name`
  - helper:
    - `uses_cache(cache_name)`

## Common scan patterns

Objects of a given struct type:

```python
pipe_buffers = objects.get_by_name("pipe_buffer")
```

Objects allocated from a given kmalloc cache:

```python
km64 = objects.filter(lambda obj: obj.is_allocated_from_cache("kmalloc-64"))
```

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
field = obj.field_at_offset(0x10)
if field is not None and field.is_pointer():
    print(field.type_name)
```

Inspect callsites:

```python
interesting = objects.filter(
    lambda obj: obj.has_kmalloc_call(lambda call: call.call_type == "kmalloc")
)
```

## Guidance

- Use `objectdb` CLI subcommands first for simple built-in queries and summaries.
- Use `objectdb create` when the object database does not exist yet and the user has the synthesis inputs.
- For a quick standalone workflow, use `scaffold-script` and then edit the generated lambda.
- Use `ObjectSet.filter(...)` for exploratory scans.
- Chain small predicates rather than building one huge lambda immediately.
- Prefer `type_name`, field offsets, pointer relationships, and cache names as the main discriminators.
- Fall back to the lower-level SQLAlchemy schema only when you need aggregation or raw table inspection.
- If you need a quick human-facing summary, use this API for narrowing and then print `HeapObject.location`, `source_code`, and `kmalloc_calls`.
