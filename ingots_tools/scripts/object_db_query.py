from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Annotated, Any, Optional

from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from sqlalchemy import func, select
from sqlalchemy.engine import Engine, create_engine
from sqlalchemy.orm import Session
import typer

from object_db.object_db import DBBtfType, HeapObject, KmallocCall

app = typer.Typer(help="Query common information from kexploit synthesis object_db.")
console = Console()


@dataclass
class AppContext:
    db_path: Path
    json_output: bool


def _resolve_db_path(kernel: Optional[str], db: Optional[Path]) -> Path:
    if db is not None:
        db_path = db
    else:
        if not kernel:
            raise typer.BadParameter("Either --db or --kernel must be provided.")

        data_dir = os.environ.get("KEXPLOIT_DATA_DIR")
        if not data_dir:
            raise typer.BadParameter(
                "KEXPLOIT_DATA_DIR is not set. Set it in your environment or .env file."
            )
        db_path = Path(data_dir).expanduser().resolve() / "synthesis" / kernel / "object_db.sqlite"

    if not db_path.exists():
        raise typer.BadParameter(f"object_db file not found: {db_path}")

    return db_path


def _engine_for_context(ctx: AppContext) -> Engine:
    return create_engine(f"sqlite:///{ctx.db_path}")


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
    ctx.obj = AppContext(
        db_path=_resolve_db_path(kernel=kernel, db=db),
        json_output=json_output,
    )


def _get_ctx(ctx: typer.Context) -> AppContext:
    app_ctx = ctx.obj
    if not isinstance(app_ctx, AppContext):
        raise typer.BadParameter("Failed to initialize app context.")
    return app_ctx


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

    app_ctx = _get_ctx(ctx)
    engine = _engine_for_context(app_ctx)

    stmt = select(
        KmallocCall.kmalloc_cache_name,
        func.count(KmallocCall.id).label("call_count"),
    ).group_by(KmallocCall.kmalloc_cache_name)

    if object_id is not None:
        stmt = stmt.where(KmallocCall.heap_object_id == object_id)
    if struct_name is not None:
        stmt = stmt.where(KmallocCall.struct_type == struct_name)

    with Session(engine) as session:
        rows = session.execute(stmt).all()

    payload = [
        {"cache_name": _display_cache_name(cache_name), "call_count": call_count}
        for cache_name, call_count in rows
    ]

    if app_ctx.json_output:
        _print_json({"selector": {"object_id": object_id, "struct_name": struct_name}, "results": payload})
        return

    if not payload:
        console.print("No matching kmalloc calls found.")
        return

    _print_table(
        "Caches For Object",
        ["cache_name", "call_count"],
        [[row["cache_name"], row["call_count"]] for row in payload],
    )


@app.command(help="List heap objects that have allocations from a specific kmalloc cache.")
def objects_for_cache(
    ctx: typer.Context,
    cache_name: Annotated[str, typer.Argument(help="Cache name. Use 'default' for default cache.")],
):
    app_ctx = _get_ctx(ctx)
    engine = _engine_for_context(app_ctx)
    normalized_cache = _normalize_cache_name(cache_name)

    stmt = (
        select(
            HeapObject.id,
            DBBtfType.name.label("type_name"),
            HeapObject.location,
            HeapObject.is_anon,
            func.count(KmallocCall.id).label("call_count"),
        )
        .join(KmallocCall, KmallocCall.heap_object_id == HeapObject.id)
        .outerjoin(DBBtfType, DBBtfType.id == HeapObject.type_id)
        .group_by(HeapObject.id, DBBtfType.name, HeapObject.location, HeapObject.is_anon)
        .order_by(func.count(KmallocCall.id).desc())
    )

    if normalized_cache is None:
        stmt = stmt.where(KmallocCall.kmalloc_cache_name.is_(None))
    else:
        stmt = stmt.where(KmallocCall.kmalloc_cache_name == normalized_cache)

    with Session(engine) as session:
        rows = session.execute(stmt).all()

    payload = [
        {
            "object_id": object_id,
            "type_name": type_name,
            "location": location,
            "is_anon": is_anon,
            "call_count": call_count,
        }
        for object_id, type_name, location, is_anon, call_count in rows
    ]

    if app_ctx.json_output:
        _print_json({"cache_name": _display_cache_name(normalized_cache), "results": payload})
        return

    if not payload:
        console.print(f"No objects found for cache {_display_cache_name(normalized_cache)}.")
        return

    _print_table(
        f"Objects For Cache {_display_cache_name(normalized_cache)}",
        ["object_id", "type_name", "is_anon", "call_count", "location"],
        [
            [row["object_id"], row["type_name"], row["is_anon"], row["call_count"], row["location"]]
            for row in payload
        ],
    )


@app.command(help="Show kmalloc callsites linked to an object id.")
def kmalloc_for_object(
    ctx: typer.Context,
    object_id: Annotated[int, typer.Argument(help="Heap object id from the objects table.")],
):
    app_ctx = _get_ctx(ctx)
    engine = _engine_for_context(app_ctx)

    stmt = (
        select(
            KmallocCall.id,
            KmallocCall.call_site,
            KmallocCall.call_type,
            KmallocCall.struct_type,
            KmallocCall.struct_size,
            KmallocCall.flags,
            KmallocCall.alloc_size,
            KmallocCall.is_flexible,
            KmallocCall.kmalloc_cache_name,
        )
        .where(KmallocCall.heap_object_id == object_id)
        .order_by(KmallocCall.id)
    )

    with Session(engine) as session:
        rows = session.execute(stmt).all()

    payload = [
        {
            "id": call_id,
            "call_site": call_site,
            "call_type": call_type,
            "struct_type": struct_type,
            "struct_size": struct_size,
            "flags": flags,
            "alloc_size": alloc_size,
            "is_flexible": is_flexible,
            "cache_name": _display_cache_name(cache_name),
        }
        for call_id, call_site, call_type, struct_type, struct_size, flags, alloc_size, is_flexible, cache_name in rows
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
        [
            [
                row["id"],
                row["call_type"],
                row["struct_type"],
                row["cache_name"],
                row["flags"],
                row["alloc_size"],
                row["call_site"],
            ]
            for row in payload
        ],
    )


@app.command(help="Show details for a heap object and its BTF type metadata.")
def object(
    ctx: typer.Context,
    object_id: Annotated[int, typer.Argument(help="Heap object id from the objects table.")],
):
    app_ctx = _get_ctx(ctx)
    engine = _engine_for_context(app_ctx)

    stmt = (
        select(
            HeapObject.id,
            HeapObject.type_id,
            HeapObject.location,
            HeapObject.is_anon,
            DBBtfType.name,
            DBBtfType.kind,
            DBBtfType.size,
        )
        .outerjoin(DBBtfType, DBBtfType.id == HeapObject.type_id)
        .where(HeapObject.id == object_id)
    )

    with Session(engine) as session:
        row = session.execute(stmt).first()

    if row is None:
        raise typer.BadParameter(f"Object id {object_id} was not found.")

    (
        resolved_object_id,
        type_id,
        location,
        is_anon,
        type_name,
        type_kind,
        type_size,
    ) = row
    payload = {
        "object_id": resolved_object_id,
        "type_id": type_id,
        "location": location,
        "is_anon": is_anon,
        "type_name": type_name,
        "type_kind": type_kind,
        "type_size": type_size,
    }

    if app_ctx.json_output:
        _print_json(payload)
        return

    _print_table(
        f"Object {object_id}",
        ["field", "value"],
        [[k, v] for k, v in payload.items()],
    )


@app.command(help="Show high-level object_db statistics.")
def stats(ctx: typer.Context):
    app_ctx = _get_ctx(ctx)
    engine = _engine_for_context(app_ctx)

    with Session(engine) as session:
        total_objects = session.scalar(select(func.count(HeapObject.id))) or 0
        total_calls = session.scalar(select(func.count(KmallocCall.id))) or 0
        linked_calls = session.scalar(
            select(func.count(KmallocCall.id)).where(KmallocCall.heap_object_id.is_not(None))
        ) or 0
        distinct_caches = session.scalar(
            select(func.count(func.distinct(func.coalesce(KmallocCall.kmalloc_cache_name, "<default>"))))
        ) or 0

        top_cache_rows = session.execute(
            select(
                KmallocCall.kmalloc_cache_name,
                func.count(KmallocCall.id).label("call_count"),
            )
            .group_by(KmallocCall.kmalloc_cache_name)
            .order_by(func.count(KmallocCall.id).desc())
            .limit(10)
        ).all()

    top_caches = [
        {"cache_name": _display_cache_name(cache_name), "call_count": call_count}
        for cache_name, call_count in top_cache_rows
    ]

    payload = {
        "db_path": str(app_ctx.db_path),
        "total_objects": total_objects,
        "total_kmalloc_calls": total_calls,
        "linked_kmalloc_calls": linked_calls,
        "distinct_caches": distinct_caches,
        "top_caches": top_caches,
    }

    if app_ctx.json_output:
        _print_json(payload)
        return

    _print_table(
        "Object DB Stats",
        ["metric", "value"],
        [
            ["db_path", app_ctx.db_path],
            ["total_objects", total_objects],
            ["total_kmalloc_calls", total_calls],
            ["linked_kmalloc_calls", linked_calls],
            ["distinct_caches", distinct_caches],
        ],
    )
    if top_caches:
        _print_table(
            "Top Caches",
            ["cache_name", "call_count"],
            [[row["cache_name"], row["call_count"]] for row in top_caches],
        )


def main():
    load_dotenv()
    app()


if __name__ == "__main__":
    main()
