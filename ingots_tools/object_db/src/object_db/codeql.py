import csv
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Self

from .location import Location
from .type_graph import TypeGraph, TypeInfo, TypeKind, TypeMember

CODEQL_QUERY_FOLDER = Path(__file__).resolve().parent / "codeql_queries"


class CodeqlQuery(StrEnum):
    KmallocCalls = "allocations.ql"
    Types = "types.ql"
    Fields = "fields.ql"
    Caches = "kmalloc_caches.ql"


class AllocType(StrEnum):
    KMALLOC = "kmalloc"
    KZALLOC = "kzalloc"
    KVMALLOC = "kvmalloc"
    KMEM_CACHE_ALLOC = "kmem_cache_alloc"
    KMEM_CACHE_ZALLOC = "kmem_cache_zalloc"
    UNKNOWN = "unknown"

    @classmethod
    def from_string(cls, name: str) -> Self:
        try:
            return cls(name)
        except ValueError:
            return cls.UNKNOWN


def _optional_int(value: str) -> int | None:
    return None if value in {"", "unknown", "-1"} else int(value)


@dataclass(frozen=True)
class CodeQlKmallocCallResult:
    call_site: Location
    call_type: AllocType
    type_id: int
    struct_type: str
    struct_def: Location
    struct_size: int | None
    flags: str
    alloc_size: int | None
    is_flexible: bool
    kmalloc_cache_name: str | None

    @classmethod
    def from_csv_row(cls, row: list[str]) -> Self:
        return cls(
            call_site=Location.from_str(row[0]),
            call_type=AllocType.from_string(row[1]),
            type_id=int(row[2]),
            struct_type=row[3],
            struct_def=Location.from_str(row[4]),
            struct_size=_optional_int(row[5]),
            flags=row[6],
            alloc_size=_optional_int(row[7]),
            is_flexible=row[8].lower() == "true",
            kmalloc_cache_name=None if row[9] == "default" else row[9],
        )


def _type_from_csv_row(row: list[str]) -> TypeInfo:
    type_id = int(row[0])
    referenced_id = int(row[5])
    return TypeInfo(
        id=type_id,
        name=row[1],
        kind=TypeKind(row[2]),
        size=_optional_int(row[3]),
        alignment=_optional_int(row[4]),
        referenced_type_id=None if referenced_id == type_id else referenced_id,
        element_count=_optional_int(row[6]),
        location=row[7],
        is_anon=row[8] == "1",
    )


def _member_from_csv_row(row: list[str]) -> TypeMember:
    return TypeMember(
        owner_type_id=int(row[0]),
        index=int(row[1]),
        name=row[2],
        type_id=int(row[3]),
        byte_offset=_optional_int(row[4]),
        bit_offset=_optional_int(row[5]),
        bitfield_size=_optional_int(row[6]),
    )


class CodeqlContext:
    def __init__(self, database_path: Path, query_folder: Path = CODEQL_QUERY_FOLDER):
        self.database_path = database_path.expanduser().resolve()
        self.query_folder = query_folder.expanduser().resolve()

    def run_query_raw(self, query: CodeqlQuery) -> str:
        with TemporaryDirectory() as directory:
            bqrs_path = str(Path(directory) / "output.bqrs")
            subprocess.run(
                [
                    "codeql",
                    "query",
                    "run",
                    str(self.query_folder / query.value),
                    "--database",
                    str(self.database_path),
                    "--output",
                    bqrs_path,
                ],
                cwd=self.query_folder,
                check=True,
            )
            result = subprocess.run(
                [
                    "codeql",
                    "bqrs",
                    "decode",
                    bqrs_path,
                    "--format=csv",
                    "--entities=id",
                    "--result-set=#select",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            return result.stdout

    def run_query(self, query: CodeqlQuery) -> Iterator[list[str]]:
        # StringIO preserves quoted newlines in CSV cells (splitlines does not).
        reader = csv.reader(StringIO(self.run_query_raw(query)))
        next(reader)
        return reader

    def get_kmalloc_calls(self) -> list[CodeQlKmallocCallResult]:
        return [
            CodeQlKmallocCallResult.from_csv_row(row)
            for row in self.run_query(CodeqlQuery.KmallocCalls)
        ]

    def get_type_graph(self) -> TypeGraph:
        types = [_type_from_csv_row(row) for row in self.run_query(CodeqlQuery.Types)]
        members = [
            _member_from_csv_row(row) for row in self.run_query(CodeqlQuery.Fields)
        ]
        return TypeGraph(types, members)
