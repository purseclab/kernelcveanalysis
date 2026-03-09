import json
import subprocess
from typing import Optional

from .btf_types import BtfStruct, BtfTypes
from .codeql import CodeqlContext
from .object_db import HeapObject, KmallocCall, OBJECT_DB_FILE_NAME, ObjectDb
from .synthesis_metadata import SynthesisMetadata


def extract_type_info(
    codeql: CodeqlContext,
    object_db: ObjectDb,
    metadata: SynthesisMetadata,
):
    raw_json_output = subprocess.check_output(
        [
            "bpftool",
            "btf",
            "dump",
            "--json",
            "file",
            str(metadata.vmlinux),
        ]
    ).decode("utf-8")
    types = BtfTypes(json.loads(raw_json_output))

    codeql_structs = codeql.get_structs()
    mapping: dict[tuple[str, tuple[str, ...]], Optional[BtfStruct]] = {}

    ids = list(sorted(types.types.keys()))
    objects = [obj for type_id in ids if (obj := types.get_type(type_id)) is not None]
    object_db.save_btf_types(objects)

    for btf_type in types.types.values():
        if type(btf_type) is not BtfStruct:
            continue

        members = tuple(member.name for member in btf_type.members)
        mapping[(btf_type.name, members)] = btf_type

    for struct in codeql_structs:
        name = "(anon)" if struct.is_anon else struct.struct_name
        key = (name, tuple(struct.field_names))
        if key not in mapping:
            continue

        btf_type = mapping[key]
        mapping[key] = None

        if btf_type is None:
            print(f"warning: duplicate btf struct signature for {struct}")
            continue

        object_db.save_btf_type(btf_type)
        object_db.save_heap_object(
            HeapObject(
                id=struct.location.to_db_id(),
                type_id=btf_type.id,
                location=str(struct.location),
                source_code=struct.location.read_source(metadata),
                is_anon=struct.is_anon,
            )
        )


def extract_kmalloc_calls(object_db: ObjectDb, codeql: CodeqlContext):
    results = codeql.get_kmalloc_calls()
    for result in results:
        call = KmallocCall.from_codeql_result(result)

        heap_obj_id = result.struct_def.to_db_id()
        if object_db.get_heap_object(heap_obj_id):
            call.heap_object_id = heap_obj_id

        object_db.save_kmalloc_call(call)


def setup_synthesis_object_db(metadata: SynthesisMetadata):
    metadata.data_path().mkdir(exist_ok=True)
    codeql = CodeqlContext(metadata.codeql_db)
    object_db = ObjectDb(metadata.data_path() / OBJECT_DB_FILE_NAME)
    extract_type_info(codeql, object_db, metadata)
    extract_kmalloc_calls(object_db, codeql)
