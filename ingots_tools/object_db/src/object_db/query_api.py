from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from .object_db import OBJECT_DB_FILE_NAME, DBHeapObject, DBKmallocCall, ObjectDb
from .synthesis_metadata import METADATA_FILE_NAME, SynthesisMetadata
from .type_graph import TypeGraph, TypeInfo, TypeKind, TypeMember


@dataclass(frozen=True)
class Field:
    name: str
    byte_offset: int | None
    bitfield_size: int | None
    type_id: int
    type_name: str
    type_kind: str
    path: str
    bit_offset: int | None
    _types: TypeGraph

    def is_pointer(self) -> bool:
        return self._types.unwrap(self.type_id).kind == TypeKind.POINTER

    def points_to_type_name(self, name: str) -> bool:
        pointee = self._pointee_type()
        return pointee is not None and pointee.name == name

    def points_to_type_id(self, type_id: int) -> bool:
        pointee = self._pointee_type()
        return pointee is not None and pointee.id == type_id

    def points_to_kind(self, kind: str) -> bool:
        pointee = self._pointee_type()
        return pointee is not None and pointee.kind == kind

    def _pointee_type(self) -> TypeInfo | None:
        member_type = self._types.unwrap(self.type_id)
        if (
            member_type.kind != TypeKind.POINTER
            or member_type.referenced_type_id is None
        ):
            return None
        return self._types.unwrap(member_type.referenced_type_id)


@dataclass(frozen=True)
class KmallocCall:
    id: int
    call_site: str
    call_type: str
    type_id: int
    struct_type: str
    struct_def: str
    struct_size: int | None
    flags: str
    alloc_size: int | None
    is_flexible: bool
    kmalloc_cache_name: str | None
    heap_object_id: int | None

    def uses_cache(self, cache_name: str | None) -> bool:
        return self.kmalloc_cache_name == cache_name


def _field_from_member(member: TypeMember, types: TypeGraph) -> Field:
    record = types.get_type(member.type_id)
    return Field(
        name=member.name,
        byte_offset=member.byte_offset,
        bitfield_size=member.bitfield_size,
        type_id=record.id,
        type_name=record.name,
        type_kind=record.kind.value,
        path=member.name,
        bit_offset=member.bit_offset,
        _types=types,
    )


def _walk_fields(
    types: TypeGraph,
    type_id: int,
    base: int,
    prefix: str,
    visited: frozenset[int],
    max_offset: int | None,
) -> Iterator[Field]:
    record = types.unwrap(type_id)
    if record.id in visited:
        return
    visited = visited | {record.id}
    if record.kind == TypeKind.ARRAY:
        yield from _walk_array(types, record, base, prefix, visited, max_offset)
        return
    for member in types.members_of(record.id):
        field = _field_from_member(member, types)
        path = (
            f"{prefix}.{member.name}"
            if prefix and member.name
            else prefix or member.name
        )
        offset = None if field.byte_offset is None else base + field.byte_offset
        if max_offset is not None and offset is not None and offset > max_offset:
            continue
        yield Field(
            name=field.name,
            path=path,
            byte_offset=offset,
            bit_offset=field.bit_offset,
            bitfield_size=field.bitfield_size,
            type_id=field.type_id,
            type_name=field.type_name,
            type_kind=field.type_kind,
            _types=types,
        )
        if offset is not None:
            yield from _walk_fields(
                types, member.type_id, offset, path, visited, max_offset
            )


def _walk_array(
    types: TypeGraph,
    record: TypeInfo,
    base: int,
    prefix: str,
    visited: frozenset[int],
    max_offset: int | None,
) -> Iterator[Field]:
    if record.referenced_type_id is None or record.element_count is None:
        return
    element = types.get_type(record.referenced_type_id)
    size = element.size
    if size is None or size <= 0:
        return
    for index in range(record.element_count):
        offset = base + index * size
        if max_offset is not None and offset > max_offset:
            break
        path = f"{prefix}[{index}]"
        yield Field(
            name=f"[{index}]",
            path=path,
            byte_offset=offset,
            bit_offset=0,
            bitfield_size=0,
            type_id=element.id,
            type_name=element.name,
            type_kind=element.kind.value,
            _types=types,
        )
        yield from _walk_fields(types, element.id, offset, path, visited, max_offset)


@dataclass(frozen=True)
class HeapObject:
    id: int
    type_id: int
    type_name: str
    type_kind: str
    size: int | None
    location: str
    source_code: str
    is_anon: bool
    fields: list[Field]
    kmalloc_calls: list[KmallocCall]
    _types: TypeGraph

    def field_named(self, name: str) -> Field | None:
        return next((field for field in self.fields if field.name == name), None)

    def field_at_offset(self, byte_offset: int) -> Field | None:
        return next(
            (field for field in self.fields if field.byte_offset == byte_offset), None
        )

    def iter_fields(self) -> Iterator[Field]:
        """Walk embedded records and fixed arrays, without following pointers."""
        return _walk_fields(self._types, self.type_id, 0, "", frozenset(), None)

    def fields_at_offset(self, byte_offset: int) -> list[Field]:
        """Return every matching member, including union alternatives and nested fields."""
        return [
            field
            for field in _walk_fields(
                self._types, self.type_id, 0, "", frozenset(), byte_offset
            )
            if field.byte_offset == byte_offset
        ]

    def has_field_named(self, name: str) -> bool:
        return self.field_named(name) is not None

    def has_pointer_field_at_offset(self, byte_offset: int) -> bool:
        return any(field.is_pointer() for field in self.fields_at_offset(byte_offset))

    def has_pointer_to_type_name(self, name: str) -> bool:
        return any(field.points_to_type_name(name) for field in self.iter_fields())

    def has_pointer_to_type_id(self, type_id: int) -> bool:
        return any(field.points_to_type_id(type_id) for field in self.iter_fields())

    def is_allocated_from_cache(self, cache_name: str | None) -> bool:
        return any(call.uses_cache(cache_name) for call in self.kmalloc_calls)

    def has_kmalloc_call(self, predicate: Callable[[KmallocCall], bool]) -> bool:
        return any(predicate(call) for call in self.kmalloc_calls)


class ObjectSet:
    def __init__(
        self,
        objects: list[HeapObject],
        kmalloc_calls: list[KmallocCall] | None = None,
    ):
        self._objects = objects
        self._kmalloc_calls = [] if kmalloc_calls is None else kmalloc_calls
        self._id_index = {obj.id: obj for obj in objects}
        self._name_index: dict[str, list[HeapObject]] = {}
        for obj in objects:
            self._name_index.setdefault(obj.type_name, []).append(obj)

    def get_all(self) -> list[HeapObject]:
        return list(self._objects)

    def get_by_id(self, obj_id: int) -> HeapObject | None:
        return self._id_index.get(obj_id)

    def get_by_name(self, type_name: str) -> list[HeapObject]:
        return list(self._name_index.get(type_name, []))

    def filter(self, predicate: Callable[[HeapObject], bool]) -> "ObjectSet":
        """Restrict objects and calls to those objects; unlinked calls are excluded."""
        filtered_objects = [obj for obj in self._objects if predicate(obj)]
        filtered_ids = {obj.id for obj in filtered_objects}
        filtered_calls = [
            call for call in self._kmalloc_calls if call.heap_object_id in filtered_ids
        ]
        return ObjectSet(filtered_objects, filtered_calls)

    def all_kmalloc_calls(self) -> list[KmallocCall]:
        return list(self._kmalloc_calls)

    def kmalloc_calls_for_object(self, obj_id: int) -> list[KmallocCall]:
        obj = self.get_by_id(obj_id)
        if obj is None:
            return []
        return list(obj.kmalloc_calls)

    def objects_for_cache(self, cache_name: str | None) -> list[HeapObject]:
        return [obj for obj in self._objects if obj.is_allocated_from_cache(cache_name)]

    def cache_counts(
        self, *, object_id: int | None = None, struct_name: str | None = None
    ) -> dict[str | None, int]:
        counts: dict[str | None, int] = {}
        for call in self._kmalloc_calls:
            if object_id is not None and call.heap_object_id != object_id:
                continue
            if struct_name is not None and call.struct_type != struct_name:
                continue
            counts[call.kmalloc_cache_name] = counts.get(call.kmalloc_cache_name, 0) + 1
        return counts

    def top_caches(self, limit: int = 10) -> list[tuple[str | None, int]]:
        counts = self.cache_counts()
        return sorted(counts.items(), key=lambda item: item[1], reverse=True)[:limit]

    def linked_kmalloc_call_count(self) -> int:
        return sum(1 for call in self._kmalloc_calls if call.heap_object_id is not None)

    def __iter__(self) -> Iterator[HeapObject]:
        return iter(self._objects)

    def __len__(self) -> int:
        return len(self._objects)


def _kmalloc_call_from_db(call: DBKmallocCall) -> KmallocCall:
    return KmallocCall(
        id=call.id,
        call_site=call.call_site,
        call_type=call.call_type,
        type_id=call.type_id,
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
    types: TypeGraph,
    calls_by_object: dict[int, list[KmallocCall]],
) -> HeapObject:
    record = types.get_type(heap_object.type_id)
    return HeapObject(
        id=heap_object.id,
        type_id=record.id,
        type_name=record.name,
        type_kind=record.kind.value,
        size=record.size,
        location=heap_object.location,
        source_code=heap_object.source_code,
        is_anon=heap_object.is_anon,
        fields=[
            _field_from_member(member, types) for member in types.members_of(record.id)
        ],
        kmalloc_calls=calls_by_object.get(heap_object.id, []),
        _types=types,
    )


def load_object_set(db_path: Path) -> ObjectSet:
    resolved_path = db_path.expanduser().resolve()
    if not resolved_path.exists():
        raise FileNotFoundError(f"object_db file not found: {resolved_path}")
    object_db = ObjectDb(resolved_path, read_only=True)
    try:
        types = object_db.load_type_graph()
        heap_objects = object_db.get_all_heap_objects()
        all_calls = [
            _kmalloc_call_from_db(call) for call in object_db.get_all_kmalloc_calls()
        ]
        calls_by_object: dict[int, list[KmallocCall]] = {}
        for call in all_calls:
            if call.heap_object_id is not None:
                calls_by_object.setdefault(call.heap_object_id, []).append(call)
        objects = [
            _heap_object_from_db(obj, types, calls_by_object) for obj in heap_objects
        ]
        return ObjectSet(objects, all_calls)
    finally:
        object_db.close()


def load_object_set_from_synthesis_dir(path: Path) -> ObjectSet:
    resolved_path = path.expanduser().resolve()
    synthesis_dir = (
        resolved_path.parent
        if resolved_path.name == METADATA_FILE_NAME
        else resolved_path
    )
    SynthesisMetadata.load(synthesis_dir)
    return load_object_set(synthesis_dir / OBJECT_DB_FILE_NAME)
