# object_db

Shared object database, BTF type models, and CodeQL query integration used by `kexploit`.

High-level scan API:

```python
from pathlib import Path
from object_db import load_object_set

objects = load_object_set(Path("/path/to/object_db.sqlite"))
targets = objects.filter(lambda obj: obj.has_pointer_to_type_name("file"))
```

Standalone script template:

```bash
uv run objectdb scaffold-script /tmp/object_scan.py
uv run /tmp/object_scan.py --db /path/to/object_db.sqlite
```
