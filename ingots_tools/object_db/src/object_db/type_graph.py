from collections import defaultdict
from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class TypeKind(StrEnum):
    STRUCT = "STRUCT"
    UNION = "UNION"
    POINTER = "PTR"
    ARRAY = "ARRAY"
    TYPEDEF = "TYPEDEF"
    QUALIFIED = "QUALIFIED"
    FUNCTION = "FUNC_PROTO"
    INTEGER = "INT"
    FLOAT = "FLOAT"
    ENUM = "ENUM"
    VOID = "VOID"
    OTHER = "OTHER"


class TypeInfo(BaseModel):
    """A type identified within one CodeQL database, not across rebuilds."""

    model_config = ConfigDict(frozen=True)

    id: int
    name: str
    kind: TypeKind
    size: int | None = None
    alignment: int | None = None
    referenced_type_id: int | None = None
    element_count: int | None = None
    location: str = ""
    is_anon: bool = False


class TypeMember(BaseModel):
    model_config = ConfigDict(frozen=True)

    owner_type_id: int
    index: int
    name: str
    type_id: int
    byte_offset: int | None
    bit_offset: int | None = 0
    bitfield_size: int | None = 0


class TypeGraph:
    def __init__(self, types: list[TypeInfo], members: list[TypeMember]):
        self.types = {record.id: record for record in types}
        if len(self.types) != len(types):
            raise ValueError("Duplicate CodeQL type identity in exported types")
        self._members: dict[int, list[TypeMember]] = defaultdict(list)
        self._names: dict[str, list[TypeInfo]] = defaultdict(list)
        for record in types:
            self._names[record.name].append(record)
        for member in sorted(members, key=lambda item: item.index):
            self._members[member.owner_type_id].append(member)
        self._validate_references(members)

    def _validate_references(self, members: list[TypeMember]) -> None:
        for record in self.types.values():
            if record.referenced_type_id is not None:
                self.get_type(record.referenced_type_id)
        for member in members:
            self.get_type(member.owner_type_id)
            self.get_type(member.type_id)

    def get_type(self, type_id: int) -> TypeInfo:
        return self.types[type_id]

    def get_by_name(self, name: str) -> list[TypeInfo]:
        return list(self._names.get(name, []))

    def members_of(self, type_id: int) -> list[TypeMember]:
        return list(self._members.get(type_id, []))

    def unwrap(self, type_id: int) -> TypeInfo:
        record = self.get_type(type_id)
        visited: set[int] = set()
        while record.kind in {TypeKind.TYPEDEF, TypeKind.QUALIFIED}:
            if record.id in visited or record.referenced_type_id is None:
                raise ValueError(f"Invalid alias chain for CodeQL type {type_id}")
            visited.add(record.id)
            record = self.get_type(record.referenced_type_id)
        return record
