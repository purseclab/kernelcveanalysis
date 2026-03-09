from collections import defaultdict
import csv
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from typing import Any, Optional

from .location import Location

CODEQL_QUERY_FOLDER = Path(__file__).resolve().parent / "codeql_queries"


class CodeqlQuery(StrEnum):
    KmallocCalls = "allocations.ql"
    Structs = "structs.ql"
    Caches = "kmalloc_caches.ql"


class AllocType(StrEnum):
    KMALLOC = "kmalloc"
    KZALLOC = "kzalloc"
    KVMALLOC = "kvmalloc"
    KMEM_CACHE_ALLOC = "kmem_cache_alloc"
    KMEM_CACHE_ZALLOC = "kmem_cache_zalloc"
    UNKNOWN = "unknown"

    @classmethod
    def from_string(cls, s: str):
        s = s.lower()
        if "kzalloc" in s:
            return cls.KZALLOC
        if "kmalloc" in s:
            return cls.KMALLOC
        if "kvmalloc" in s:
            return cls.KVMALLOC
        if "kmem_cache_alloc" in s:
            return cls.KMEM_CACHE_ALLOC
        if "kmem_cache_zalloc" in s:
            return cls.KMEM_CACHE_ZALLOC

        print(s)
        return cls.UNKNOWN


@dataclass
class CodeQlKmallocCallResult:
    call_site: Location
    call_type: AllocType
    struct_type: str
    struct_def: Location
    struct_size: int
    flags: str
    alloc_size: Optional[int]
    is_flexible: bool
    kmalloc_cache_name: Optional[str]

    @classmethod
    def from_csv_row(cls, row: list[Any]):
        raw_alloc_size = row[6].strip()
        alloc_size = int(raw_alloc_size) if raw_alloc_size.isdigit() else None
        cache_name = row[8]

        return cls(
            call_site=Location.from_str(row[0]),
            call_type=AllocType.from_string(row[1]),
            struct_type=row[2],
            struct_def=Location.from_str(row[3]),
            struct_size=int(row[4]),
            flags=row[5],
            alloc_size=alloc_size,
            is_flexible=row[7].lower() == "true",
            kmalloc_cache_name=(None if cache_name == "default" else cache_name),
        )


@dataclass
class CodeQlStructResult:
    struct_name: str
    is_anon: bool
    field_names: list[str]
    location: Location


class CodeqlContext:
    database_path: Path
    query_folder: Path

    def __init__(self, database_path: Path, query_folder: Path = CODEQL_QUERY_FOLDER):
        self.database_path = database_path
        self.query_folder = query_folder

    def run_query_raw(self, query: CodeqlQuery) -> str:
        with TemporaryDirectory() as dir:
            query_path = self.query_folder / str(query)
            bqrs_path = dir + "/output.bqrs"
            csv_path = dir + "/output.csv"

            subprocess.run(
                [
                    "codeql",
                    "query",
                    "run",
                    str(query_path),
                    "--database",
                    str(self.database_path),
                    "--output",
                    bqrs_path,
                ],
                cwd=str(self.query_folder),
                check=True,
            )

            subprocess.run(
                ["codeql", "bqrs", "decode", bqrs_path, "--output", csv_path, "--format", "csv"]
            )

            with open(csv_path, "r") as f:
                data = f.read()

        return data

    def run_query(self, query: CodeqlQuery):
        output = self.run_query_raw(query)
        reader = csv.reader(output.splitlines())
        next(reader)
        return reader

    def get_kmalloc_calls(self) -> list[CodeQlKmallocCallResult]:
        rows = self.run_query(CodeqlQuery.KmallocCalls)
        return [CodeQlKmallocCallResult.from_csv_row(row) for row in rows]

    def get_structs(self) -> list[CodeQlStructResult]:
        rows = self.run_query(CodeqlQuery.Structs)

        fields: dict[str, dict[str, str]] = defaultdict(dict)
        structs = []

        for row in rows:
            struct_name, is_anon, field_name, field_index, location_str = row
            location = Location.from_str(location_str)

            if struct_name not in fields:
                structs.append(
                    CodeQlStructResult(
                        struct_name=struct_name,
                        is_anon=bool(int(is_anon)),
                        field_names=[],
                        location=location,
                    )
                )

            fields[struct_name][field_index] = field_name

        for struct in structs:
            field_names = [(index, name) for index, name in fields[struct.struct_name].items()]
            field_names.sort(key=lambda info: info[0])
            struct.field_names = [name for _index, name in field_names]

        return structs
