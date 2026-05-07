from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Optional

from .btf_types import (
    BtfConst,
    BtfDeclTag,
    BtfMember,
    BtfPtr,
    BtfRestrict,
    BtfStruct,
    BtfType,
    BtfTypeTag,
    BtfTypedef,
    BtfUnion,
    BtfVolatile,
    BtfTypes,
)
from .object_db import DBHeapObject, DBKmallocCall, OBJECT_DB_FILE_NAME, ObjectDb
from .synthesis_metadata import METADATA_FILE_NAME, SynthesisMetadata


def _unwrap_qualifiers(btf_type: Optional[BtfType]) -> Optional[BtfType]:
    current = btf_type
    while isinstance(
        current,
        (BtfTypedef, BtfConst, BtfVolatile, BtfRestrict, BtfTypeTag, BtfDeclTag),
    ):
        current = current.type_id.type
    return current


def _resolve_member_type(member: BtfMember) -> Optional[BtfType]:
    return member.type_id.type


@dataclass(frozen=True)
class Field:
    name: str
    byte_offset: int
    bitfield_size: int
    type_id: int
    type_name: str
    type_kind: str
    _member_type: Optional[BtfType]

    def is_pointer(self) -> bool:
        return isinstance(_unwrap_qualifiers(self._member_type), BtfPtr)

    def points_to_type_name(self, name: str) -> bool:
        pointee = self._pointee_type()
        return pointee is not None and pointee.name == name

    def points_to_type_id(self, type_id: int) -> bool:
        pointee = self._pointee_type()
        return pointee is not None and pointee.id == type_id

    def points_to_kind(self, kind: str) -> bool:
        pointee = self._pointee_type()
        return pointee is not None and pointee.kind == kind

    def _pointee_type(self) -> Optional[BtfType]:
        member_type = _unwrap_qualifiers(self._member_type)
        if not isinstance(member_type, BtfPtr):
            return None
        return _unwrap_qualifiers(member_type.type_id.type)


@dataclass(frozen=True)
class KmallocCall:
    id: int
    call_site: str
    call_type: str
    struct_type: str
    struct_def: str
    struct_size: int
    flags: str
    alloc_size: Optional[int]
    is_flexible: bool
    kmalloc_cache_name: Optional[str]
    heap_object_id: Optional[int]

    def uses_cache(self, cache_name: Optional[str]) -> bool:
        return self.kmalloc_cache_name == cache_name


@dataclass(frozen=True)
class HeapObject:
    id: int
    type_id: int
    type_name: str
    type_kind: str
    size: Optional[int]
    location: str
    source_code: str
    is_anon: bool
    fields: list[Field]
    kmalloc_calls: list[KmallocCall]

    def field_named(self, name: str) -> Optional[Field]:
        for field in self.fields:
            if field.name == name:
                return field
        return None

    def field_at_offset(self, byte_offset: int) -> Optional[Field]:
        for field in self.fields:
            if field.byte_offset == byte_offset:
                return field
        return None

    def has_field_named(self, name: str) -> bool:
        return self.field_named(name) is not None

    def has_pointer_field_at_offset(self, byte_offset: int) -> bool:
        field = self.field_at_offset(byte_offset)
        return field is not None and field.is_pointer()

    def has_pointer_to_type_name(self, name: str) -> bool:
        return any(field.points_to_type_name(name) for field in self.fields)

    def has_pointer_to_type_id(self, type_id: int) -> bool:
        return any(field.points_to_type_id(type_id) for field in self.fields)

    def is_allocated_from_cache(self, cache_name: Optional[str]) -> bool:
        return any(call.uses_cache(cache_name) for call in self.kmalloc_calls)

    def has_kmalloc_call(self, predicate: Callable[[KmallocCall], bool]) -> bool:
        return any(predicate(call) for call in self.kmalloc_calls)


class ObjectSet:
    def __init__(self, objects: list[HeapObject], kmalloc_calls: Optional[list[KmallocCall]] = None):
        self._objects = objects
        self._kmalloc_calls = [] if kmalloc_calls is None else kmalloc_calls
        self._id_index = {obj.id: obj for obj in objects}
        self._name_index: dict[str, list[HeapObject]] = {}
        for obj in objects:
            self._name_index.setdefault(obj.type_name, []).append(obj)

    def get_all(self) -> list[HeapObject]:
        return list(self._objects)

    def get_by_id(self, obj_id: int) -> Optional[HeapObject]:
        return self._id_index.get(obj_id)

    def get_by_name(self, type_name: str) -> list[HeapObject]:
        return list(self._name_index.get(type_name, []))

    def filter(self, predicate: Callable[[HeapObject], bool]) -> "ObjectSet":
        filtered_objects = [obj for obj in self._objects if predicate(obj)]
        filtered_ids = {obj.id for obj in filtered_objects}
        filtered_calls = [call for call in self._kmalloc_calls if call.heap_object_id in filtered_ids]
        return ObjectSet(filtered_objects, filtered_calls)

    def all_kmalloc_calls(self) -> list[KmallocCall]:
        return list(self._kmalloc_calls)

    def kmalloc_calls_for_object(self, obj_id: int) -> list[KmallocCall]:
        obj = self.get_by_id(obj_id)
        if obj is None:
            return []
        return list(obj.kmalloc_calls)

    def objects_for_cache(self, cache_name: Optional[str]) -> list[HeapObject]:
        return [obj for obj in self._objects if obj.is_allocated_from_cache(cache_name)]

    def cache_counts(self, *, object_id: Optional[int] = None, struct_name: Optional[str] = None) -> dict[Optional[str], int]:
        counts: dict[Optional[str], int] = {}
        for call in self._kmalloc_calls:
            if object_id is not None and call.heap_object_id != object_id:
                continue
            if struct_name is not None and call.struct_type != struct_name:
                continue
            counts[call.kmalloc_cache_name] = counts.get(call.kmalloc_cache_name, 0) + 1
        return counts

    def top_caches(self, limit: int = 10) -> list[tuple[Optional[str], int]]:
        counts = self.cache_counts()
        return sorted(counts.items(), key=lambda item: item[1], reverse=True)[:limit]

    def linked_kmalloc_call_count(self) -> int:
        return sum(1 for call in self._kmalloc_calls if call.heap_object_id is not None)

    def __iter__(self) -> Iterator[HeapObject]:
        return iter(self._objects)

    def __len__(self) -> int:
        return len(self._objects)


def _field_from_member(member: BtfMember) -> Field:
    member_type = _resolve_member_type(member)
    if member_type is None:
        type_id = member.type_id.type_id
        type_name = "<unknown>"
        type_kind = "<unknown>"
    else:
        type_id = member_type.id
        type_name = member_type.name
        type_kind = member_type.kind

    return Field(
        name=member.name,
        byte_offset=member.bits_offset // 8,
        bitfield_size=member.bitfield_size,
        type_id=type_id,
        type_name=type_name,
        type_kind=type_kind,
        _member_type=member_type,
    )


def _kmalloc_call_from_db(call: DBKmallocCall) -> KmallocCall:
    return KmallocCall(
        id=call.id,
        call_site=call.call_site,
        call_type=call.call_type,
        struct_type=call.struct_type,
        struct_def=call.struct_def,
        struct_size=call.struct_size,
        flags=call.flags,
        alloc_size=call.alloc_size,
        is_flexible=call.is_flexible,
        kmalloc_cache_name=call.kmalloc_cache_name,
        heap_object_id=call.heap_object_id,
    )


def _heap_object_from_db(
    heap_object: DBHeapObject,
    btf_types: BtfTypes,
    kmalloc_calls_by_object_id: dict[int, list[KmallocCall]],
) -> HeapObject:
    btf_type = btf_types.get_type(heap_object.type_id)
    type_name = btf_type.name if btf_type is not None else "<unknown>"
    type_kind = btf_type.kind if btf_type is not None else "<unknown>"
    size = getattr(btf_type, "size", None) if btf_type is not None else None

    fields: list[Field] = []
    if isinstance(btf_type, (BtfStruct, BtfUnion)):
        fields = [_field_from_member(member) for member in btf_type.members]

    return HeapObject(
        id=heap_object.id,
        type_id=heap_object.type_id,
        type_name=type_name,
        type_kind=type_kind,
        size=size,
        location=heap_object.location,
        source_code=heap_object.source_code,
        is_anon=heap_object.is_anon,
        fields=fields,
        kmalloc_calls=kmalloc_calls_by_object_id.get(heap_object.id, []),
    )


def load_object_set(db_path: Path) -> ObjectSet:
    resolved_db_path = db_path.expanduser().resolve()
    if not resolved_db_path.exists():
        raise FileNotFoundError(f"object_db file not found: {resolved_db_path}")

    object_db = ObjectDb(resolved_db_path)
    try:
        btf_types = object_db.load_btf_types()
        heap_objects = object_db.get_all_heap_objects()
        db_kmalloc_calls = object_db.get_all_kmalloc_calls()
        kmalloc_calls_by_object_id: dict[int, list[KmallocCall]] = {}
        for call in db_kmalloc_calls:
            if call.heap_object_id is None:
                continue
            kmalloc_calls_by_object_id.setdefault(call.heap_object_id, []).append(
                _kmalloc_call_from_db(call)
            )

        objects = [
            _heap_object_from_db(heap_object, btf_types, kmalloc_calls_by_object_id)
            for heap_object in heap_objects
        ]
        all_calls = [_kmalloc_call_from_db(call) for call in db_kmalloc_calls]
        return ObjectSet(objects, all_calls)
    finally:
        object_db.close()


def load_object_set_from_synthesis_dir(path: Path) -> ObjectSet:
    resolved_path = path.expanduser().resolve()
    if resolved_path.name == METADATA_FILE_NAME:
        synthesis_dir = resolved_path.parent
    else:
        synthesis_dir = resolved_path

    SynthesisMetadata.load(synthesis_dir)
    db_path = synthesis_dir / OBJECT_DB_FILE_NAME
    if not db_path.exists():
        raise FileNotFoundError(f"object_db file not found: {db_path}")

    return load_object_set(db_path)
