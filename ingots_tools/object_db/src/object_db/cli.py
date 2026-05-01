from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
from typing import Annotated, Any, Optional

from dotenv import load_dotenv
from kexploit_utils import synthesis_data_dir
from rich.console import Console
from rich.table import Table
import typer

from .query_api import HeapObject, ObjectSet, load_object_set
from .setup import setup_synthesis_object_db
from .synthesis_metadata import SynthesisMetadata

app = typer.Typer(help="Query common information from kexploit synthesis object_db.")
console = Console()
REPO_ROOT = Path(__file__).resolve().parents[3]
OBJECT_DB_PROJECT_DIR = REPO_ROOT / "object_db"


@dataclass
class AppContext:
    kernel: Optional[str]
    db: Optional[Path]
    json_output: bool


def _resolve_db_path(kernel: Optional[str], db: Optional[Path], *, must_exist: bool = True) -> Path:
    if db is not None:
        db_path = db
    else:
        if not kernel:
            raise typer.BadParameter("Either --db or --kernel must be provided.")
        db_path = synthesis_data_dir() / kernel / "object_db.sqlite"

    if must_exist and not db_path.exists():
        raise typer.BadParameter(f"object_db file not found: {db_path}")

    return db_path


def _normalize_cache_name(cache_name: str) -> Optional[str]:
    lowered = cache_name.strip().lower()
    if lowered in {"default", "<default>", "none", "null"}:
        return None
    return cache_name


def _display_cache_name(cache_name: Optional[str]) -> str:
    return cache_name if cache_name is not None else "<default>"


def _print_json(payload: Any):
    console.print_json(json.dumps(payload))


def _print_table(title: str, columns: list[str], rows: list[list[Any]]):
    table = Table(title=title)
    for column in columns:
        table.add_column(column)
    for row in rows:
        table.add_row(*[str(item) for item in row])
    console.print(table)


def _script_source_path(output_path: Path) -> str:
    resolved_output = output_path.expanduser().resolve()
    if resolved_output.is_relative_to(REPO_ROOT):
        return os.path.relpath(OBJECT_DB_PROJECT_DIR, resolved_output.parent)
    return str(OBJECT_DB_PROJECT_DIR)


def _render_script_template(output_path: Path) -> str:
    source_path = _script_source_path(output_path)
    return f"""#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = ["object_db"]
# [tool.uv.sources]
# object_db = {{ path = "{source_path}", editable = true }}
# ///

from argparse import ArgumentParser
from pathlib import Path

from object_db import load_object_set, load_object_set_from_synthesis_dir


def parse_args():
    parser = ArgumentParser(description="Scan an object_db with the high-level object_db API.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--db", type=Path, help="Path to object_db.sqlite")
    source.add_argument(
        "--synthesis-dir",
        type=Path,
        help="Path to a synthesis directory or metadata.json",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    if args.db is not None:
        objects = load_object_set(args.db)
    else:
        objects = load_object_set_from_synthesis_dir(args.synthesis_dir)

    # Replace this predicate with the scan you actually want.
    matches = objects.filter(lambda obj: obj.has_pointer_to_type_name("file"))

    print(f"matched {{len(matches)}} objects")
    for obj in matches:
        print(f"{{obj.id}}\\t{{obj.type_name}}\\t{{obj.location}}")


if __name__ == "__main__":
    main()
"""


@app.callback()
def configure(
    ctx: typer.Context,
    kernel: Annotated[
        Optional[str],
        typer.Option(help="Kernel name under $KEXPLOIT_DATA_DIR/synthesis/<kernel>/"),
    ] = None,
    db: Annotated[Optional[Path], typer.Option(help="Direct path to object_db.sqlite")] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Print JSON output instead of human-readable tables.")
    ] = False,
):
    ctx.obj = AppContext(kernel=kernel, db=db, json_output=json_output)


def _get_ctx(ctx: typer.Context) -> AppContext:
    app_ctx = ctx.obj
    if not isinstance(app_ctx, AppContext):
        raise typer.BadParameter("Failed to initialize app context.")
    return app_ctx


def _get_db_path(ctx: typer.Context) -> Path:
    app_ctx = _get_ctx(ctx)
    return _resolve_db_path(kernel=app_ctx.kernel, db=app_ctx.db)


def _load_objects(ctx: typer.Context) -> tuple[AppContext, Path, ObjectSet]:
    app_ctx = _get_ctx(ctx)
    db_path = _get_db_path(ctx)
    return app_ctx, db_path, load_object_set(db_path)


@app.command(help="Show cache names used for allocations of a specific object id and/or struct name.")
def cache_for_object(
    ctx: typer.Context,
    object_id: Annotated[
        Optional[int], typer.Option(help="Heap object id from the objects table.")
    ] = None,
    struct_name: Annotated[
        Optional[str], typer.Option(help="Struct name from kmalloc_calls.struct_type.")
    ] = None,
):
    if object_id is None and struct_name is None:
        raise typer.BadParameter("Provide --object-id and/or --struct-name.")

    app_ctx, _, objects = _load_objects(ctx)
    counts = objects.cache_counts(object_id=object_id, struct_name=struct_name)
    payload = [
        {"cache_name": _display_cache_name(cache_name), "call_count": call_count}
        for cache_name, call_count in sorted(counts.items(), key=lambda item: item[1], reverse=True)
    ]

    if app_ctx.json_output:
        _print_json({"selector": {"object_id": object_id, "struct_name": struct_name}, "results": payload})
        return

    if not payload:
        console.print("No matching kmalloc calls found.")
        return

    _print_table("Caches For Object", ["cache_name", "call_count"], [[row["cache_name"], row["call_count"]] for row in payload])


@app.command(help="List heap objects that have allocations from a specific kmalloc cache.")
def objects_for_cache(
    ctx: typer.Context,
    cache_name: Annotated[str, typer.Argument(help="Cache name. Use 'default' for default cache.")],
):
    app_ctx, _, objects = _load_objects(ctx)
    normalized_cache = _normalize_cache_name(cache_name)
    matching_objects = objects.objects_for_cache(normalized_cache)
    payload = [
        {
            "object_id": obj.id,
            "type_name": obj.type_name,
            "location": obj.location,
            "is_anon": obj.is_anon,
            "call_count": sum(1 for call in obj.kmalloc_calls if call.uses_cache(normalized_cache)),
        }
        for obj in matching_objects
    ]
    payload.sort(key=lambda row: row["call_count"], reverse=True)

    if app_ctx.json_output:
        _print_json({"cache_name": _display_cache_name(normalized_cache), "results": payload})
        return

    if not payload:
        console.print(f"No objects found for cache {_display_cache_name(normalized_cache)}.")
        return

    _print_table(
        f"Objects For Cache {_display_cache_name(normalized_cache)}",
        ["object_id", "type_name", "is_anon", "call_count", "location"],
        [[row["object_id"], row["type_name"], row["is_anon"], row["call_count"], row["location"]] for row in payload],
    )


@app.command(help="Show kmalloc callsites linked to an object id.")
def kmalloc_for_object(
    ctx: typer.Context,
    object_id: Annotated[int, typer.Argument(help="Heap object id from the objects table.")],
):
    app_ctx, _, objects = _load_objects(ctx)
    payload = [
        {
            "id": call.id,
            "call_site": call.call_site,
            "call_type": call.call_type,
            "struct_type": call.struct_type,
            "struct_size": call.struct_size,
            "flags": call.flags,
            "alloc_size": call.alloc_size,
            "is_flexible": call.is_flexible,
            "cache_name": _display_cache_name(call.kmalloc_cache_name),
        }
        for call in sorted(objects.kmalloc_calls_for_object(object_id), key=lambda call: call.id)
    ]

    if app_ctx.json_output:
        _print_json({"object_id": object_id, "results": payload})
        return

    if not payload:
        console.print(f"No kmalloc calls linked to object id {object_id}.")
        return

    _print_table(
        f"Kmalloc Calls For Object {object_id}",
        ["id", "call_type", "struct_type", "cache_name", "flags", "alloc_size", "call_site"],
        [[row["id"], row["call_type"], row["struct_type"], row["cache_name"], row["flags"], row["alloc_size"], row["call_site"]] for row in payload],
    )


def _object_payload(obj: HeapObject) -> dict[str, Any]:
    return {
        "object_id": obj.id,
        "type_id": obj.type_id,
        "location": obj.location,
        "is_anon": obj.is_anon,
        "type_name": obj.type_name,
        "type_kind": obj.type_kind,
        "type_size": obj.size,
    }


@app.command(help="Show details for a heap object and its BTF type metadata.")
def object(
    ctx: typer.Context,
    object_id: Annotated[int, typer.Argument(help="Heap object id from the objects table.")],
):
    app_ctx, _, objects = _load_objects(ctx)
    obj = objects.get_by_id(object_id)
    if obj is None:
        raise typer.BadParameter(f"Object id {object_id} was not found.")

    payload = _object_payload(obj)

    if app_ctx.json_output:
        _print_json(payload)
        return

    _print_table(f"Object {object_id}", ["field", "value"], [[k, v] for k, v in payload.items()])


@app.command(help="Show high-level object_db statistics.")
def stats(ctx: typer.Context):
    app_ctx, db_path, objects = _load_objects(ctx)
    top_caches = [
        {"cache_name": _display_cache_name(cache_name), "call_count": call_count}
        for cache_name, call_count in objects.top_caches(limit=10)
    ]
    payload = {
        "db_path": str(db_path),
        "total_objects": len(objects),
        "total_kmalloc_calls": len(objects.all_kmalloc_calls()),
        "linked_kmalloc_calls": objects.linked_kmalloc_call_count(),
        "distinct_caches": len(objects.cache_counts()),
        "top_caches": top_caches,
    }

    if app_ctx.json_output:
        _print_json(payload)
        return

    _print_table(
        "Object DB Stats",
        ["metric", "value"],
        [
            ["db_path", db_path],
            ["total_objects", len(objects)],
            ["total_kmalloc_calls", len(objects.all_kmalloc_calls())],
            ["linked_kmalloc_calls", objects.linked_kmalloc_call_count()],
            ["distinct_caches", len(objects.cache_counts())],
        ],
    )
    if top_caches:
        _print_table("Top Caches", ["cache_name", "call_count"], [[row["cache_name"], row["call_count"]] for row in top_caches])


@app.command(help="Create synthesis metadata and object_db.sqlite using the same layout as kexploit.")
def create(
    ctx: typer.Context,
    kernel: Annotated[str, typer.Option(help="Name of kernel to set up exploit synthesis for")],
    codeql_db: Annotated[Path, typer.Option(help="Path to codeql database for the kernel")],
    vmlinux: Annotated[Path, typer.Option(help="Path to vmlinux elf binary with debug info")],
    linux_src: Annotated[Path, typer.Option(help="Path to linux source code")],
    compile_commands: Annotated[Path, typer.Option(help="Path to linux compile commands")],
):
    synthesis_path = synthesis_data_dir() / kernel
    synthesis_path.mkdir(exist_ok=True)

    metadata = SynthesisMetadata(
        kernel_name=kernel,
        vmlinux=vmlinux,
        codeql_db=codeql_db,
        linux_src=linux_src,
        synthesis_data=synthesis_path,
    )
    shutil.copy(compile_commands, metadata.compile_commands_path())
    metadata.save()
    setup_synthesis_object_db(metadata)

    db_path = _resolve_db_path(kernel=kernel, db=None)
    metadata_path = db_path.parent / "metadata.json"
    app_ctx = _get_ctx(ctx)
    payload = {
        "kernel": kernel,
        "db_path": str(db_path),
        "metadata_path": str(metadata_path),
        "compile_commands_path": str(db_path.parent / "compile_commands.json"),
    }

    if app_ctx.json_output:
        _print_json(payload)
        return

    console.print(f"Created synthesis data for {kernel}")
    _print_table("Created Files", ["field", "value"], [[key, value] for key, value in payload.items()])


@app.command(help="Write a standalone uv script template for scanning object_db with the high-level API.")
def scaffold_script(
    ctx: typer.Context,
    output: Annotated[Path, typer.Argument(help="Where to write the script template.")],
    force: Annotated[bool, typer.Option(help="Overwrite the output file if it already exists.")] = False,
):
    output_path = output.expanduser().resolve()
    if output_path.exists() and not force:
        raise typer.BadParameter(f"Refusing to overwrite existing file: {output_path}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_render_script_template(output_path), encoding="utf-8")

    app_ctx = _get_ctx(ctx)
    payload = {
        "script_path": str(output_path),
        "object_db_source": _script_source_path(output_path),
        "run_with_db": f"uv run {output_path} --db /path/to/object_db.sqlite",
        "run_with_synthesis_dir": f"uv run {output_path} --synthesis-dir /path/to/synthesis/<kernel-or-metadata>",
    }

    if app_ctx.json_output:
        _print_json(payload)
        return

    console.print(f"Wrote object_db analysis template to {output_path}")
    _print_table("How To Run", ["field", "value"], [[key, value] for key, value in payload.items()])


def main():
    load_dotenv()
    app()


if __name__ == "__main__":
    main()
