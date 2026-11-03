import os
from pathlib import Path
from tempfile import TemporaryDirectory

from .codeql import CodeqlContext
from .location import Location
from .object_db import OBJECT_DB_FILE_NAME, DBHeapObject, DBKmallocCall, ObjectDb
from .synthesis_metadata import SynthesisMetadata
from .type_graph import TypeKind


def extract_type_info(
    codeql: CodeqlContext,
    object_db: ObjectDb,
    metadata: SynthesisMetadata,
) -> None:
    graph = codeql.get_type_graph()
    object_db.save_type_graph(graph)
    objects = [
        DBHeapObject(
            id=record.id,
            type_id=record.id,
            location=record.location,
            source_code=Location.from_str(record.location).read_source(metadata)
            if record.location
            else "",
            is_anon=record.is_anon,
        )
        for record in graph.types.values()
        if record.kind in {TypeKind.STRUCT, TypeKind.UNION}
    ]
    object_db.save_heap_objects(objects)


def extract_kmalloc_calls(object_db: ObjectDb, codeql: CodeqlContext) -> None:
    object_ids = {obj.type_id: obj.id for obj in object_db.get_all_heap_objects()}
    calls: list[DBKmallocCall] = []
    for result in codeql.get_kmalloc_calls():
        call = DBKmallocCall.from_codeql_result(result)
        # The allocation query and type query export the same CodeQL entity IDs.
        call.heap_object_id = object_ids[result.type_id]
        calls.append(call)
    object_db.save_kmalloc_calls(calls)


def setup_synthesis_object_db(metadata: SynthesisMetadata) -> None:
    """Replace the database only after all CodeQL queries and imports succeed."""
    destination = metadata.data_path()
    destination.mkdir(parents=True, exist_ok=True)
    codeql = CodeqlContext(metadata.codeql_db)
    with TemporaryDirectory(prefix=".objectdb-", dir=destination) as temporary_dir:
        staged_path = Path(temporary_dir) / OBJECT_DB_FILE_NAME
        object_db = ObjectDb(staged_path)
        try:
            extract_type_info(codeql, object_db, metadata)
            extract_kmalloc_calls(object_db, codeql)
        finally:
            object_db.close()
        os.replace(staged_path, destination / OBJECT_DB_FILE_NAME)
