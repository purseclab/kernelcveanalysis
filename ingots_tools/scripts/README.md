# scripts

Collection of miscallaneous scripts that don't fit in with other tools

## object_db_query.py

Query common data from `object_db.sqlite` produced by synthesis setup.

Examples:

```bash
uv run objectdb create --kernel ingots_5.10.107 --codeql-db /path/to/codeql-db --vmlinux /path/to/vmlinux --linux-src /path/to/linux-src --compile-commands /path/to/compile_commands.json
uv run objectdb scaffold-script /tmp/object_scan.py
uv run objectdb --kernel ingots_5.10.107 stats
uv run objectdb --kernel ingots_5.10.107 cache-for-object --object-id 123
uv run objectdb --db /path/to/object_db.sqlite objects-for-cache kmalloc-64
uv run objectdb --kernel ingots_5.10.107 --json kmalloc-for-object 123
```
