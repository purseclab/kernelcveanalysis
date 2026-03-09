# scripts

Collection of miscallaneous scripts that don't fit in with other tools

## object_db_query.py

Query common data from `object_db.sqlite` produced by synthesis setup.

Examples:

```bash
uv run python scripts/object_db_query.py --kernel ingots_5.10.107 stats
uv run python scripts/object_db_query.py --kernel ingots_5.10.107 cache-for-object --object-id 123
uv run python scripts/object_db_query.py --db /path/to/object_db.sqlite objects-for-cache kmalloc-64
uv run python scripts/object_db_query.py --kernel ingots_5.10.107 --json kmalloc-for-object 123
```
