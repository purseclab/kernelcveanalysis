import sqlite3
from pathlib import Path

from sqlalchemy import Boolean, ForeignKey, Integer, String, create_engine, select, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from .codeql import CodeQlKmallocCallResult
from .type_graph import TypeGraph, TypeInfo, TypeKind, TypeMember

OBJECT_DB_FILE_NAME = "object_db.sqlite"
SCHEMA_VERSION = 2


class Base(DeclarativeBase):
    pass


class DBType(Base):
    __tablename__ = "types"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String)
    kind: Mapped[str] = mapped_column(String)
    size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    alignment: Mapped[int | None] = mapped_column(Integer, nullable=True)
    referenced_type_id: Mapped[int | None] = mapped_column(
        ForeignKey("types.id", deferrable=True, initially="DEFERRED"),
        nullable=True,
        index=True,
    )
    element_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    location: Mapped[str] = mapped_column(String)
    is_anon: Mapped[bool] = mapped_column(Boolean)


class DBTypeMember(Base):
    __tablename__ = "fields"

    # One owner/index can have several extracted types or layouts across TUs.
    # Preserve every exported alternative rather than choosing one implicitly.
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    owner_type_id: Mapped[int] = mapped_column(ForeignKey("types.id"))
    index: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String)
    type_id: Mapped[int] = mapped_column(ForeignKey("types.id"))
    byte_offset: Mapped[int | None] = mapped_column(Integer, nullable=True)
    bit_offset: Mapped[int | None] = mapped_column(Integer, nullable=True)
    bitfield_size: Mapped[int | None] = mapped_column(Integer, nullable=True)


class DBHeapObject(Base):
    __tablename__ = "objects"

    id: Mapped[int] = mapped_column(primary_key=True)
    type_id: Mapped[int] = mapped_column(ForeignKey("types.id"), unique=True)
    location: Mapped[str] = mapped_column(String)
    source_code: Mapped[str] = mapped_column(String)
    is_anon: Mapped[bool] = mapped_column(Boolean)


class DBKmallocCall(Base):
    __tablename__ = "kmalloc_calls"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    call_site: Mapped[str] = mapped_column(String)
    call_type: Mapped[str] = mapped_column(String)
    type_id: Mapped[int] = mapped_column(ForeignKey("types.id"))
    struct_type: Mapped[str] = mapped_column(String)
    struct_def: Mapped[str] = mapped_column(String)
    struct_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    flags: Mapped[str] = mapped_column(String)
    alloc_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    is_flexible: Mapped[bool] = mapped_column(Boolean)
    kmalloc_cache_name: Mapped[str | None] = mapped_column(String, nullable=True)
    heap_object_id: Mapped[int | None] = mapped_column(
        ForeignKey("objects.id"), nullable=True
    )

    @classmethod
    def from_codeql_result(cls, result: CodeQlKmallocCallResult) -> "DBKmallocCall":
        return cls(
            call_site=str(result.call_site),
            call_type=result.call_type.value,
            type_id=result.type_id,
            struct_type=result.struct_type,
            struct_def=str(result.struct_def),
            struct_size=result.struct_size,
            flags=result.flags,
            alloc_size=result.alloc_size,
            is_flexible=result.is_flexible,
            kmalloc_cache_name=result.kmalloc_cache_name,
        )


class ObjectDb:
    def __init__(self, db_path: Path, *, read_only: bool = False):
        resolved_path = db_path.expanduser().resolve()
        mode = "ro" if read_only else "rwc"

        def connect() -> sqlite3.Connection:
            connection = sqlite3.connect(
                f"{resolved_path.as_uri()}?mode={mode}", uri=True
            )
            connection.execute("PRAGMA foreign_keys=ON")
            return connection

        self.engine = create_engine("sqlite://", creator=connect)
        try:
            self._initialize(read_only)
        except Exception:
            self.close()
            raise

    def _initialize(self, read_only: bool) -> None:
        with self.engine.connect() as connection:
            version = connection.scalar(text("PRAGMA user_version"))
            tables = connection.scalar(
                text("SELECT count(*) FROM sqlite_master WHERE type='table'")
            )
        if tables and version != SCHEMA_VERSION:
            raise ValueError(
                "Unsupported object_db schema. Rebuild this database with objectdb create (CodeQL only)."
            )
        if read_only:
            if not tables:
                raise ValueError(
                    "Empty object_db. Rebuild this database with objectdb create."
                )
            return
        Base.metadata.create_all(self.engine)
        with self.engine.begin() as connection:
            connection.execute(text(f"PRAGMA user_version={SCHEMA_VERSION}"))

    def close(self) -> None:
        self.engine.dispose()

    def save_type_graph(self, graph: TypeGraph) -> None:
        with Session(self.engine) as session:
            session.add_all(
                DBType(**record.model_dump()) for record in graph.types.values()
            )
            session.flush()
            session.add_all(
                DBTypeMember(**member.model_dump())
                for type_id in graph.types
                for member in graph.members_of(type_id)
            )
            session.commit()

    def load_type_graph(self) -> TypeGraph:
        with Session(self.engine) as session:
            types = [
                TypeInfo(
                    id=row.id,
                    name=row.name,
                    kind=TypeKind(row.kind),
                    size=row.size,
                    alignment=row.alignment,
                    referenced_type_id=row.referenced_type_id,
                    element_count=row.element_count,
                    location=row.location,
                    is_anon=row.is_anon,
                )
                for row in session.scalars(select(DBType).order_by(DBType.id))
            ]
            members = [
                TypeMember(
                    owner_type_id=row.owner_type_id,
                    index=row.index,
                    name=row.name,
                    type_id=row.type_id,
                    byte_offset=row.byte_offset,
                    bit_offset=row.bit_offset,
                    bitfield_size=row.bitfield_size,
                )
                for row in session.scalars(
                    select(DBTypeMember).order_by(DBTypeMember.index)
                )
            ]
        return TypeGraph(types, members)

    def save_heap_objects(self, objects: list[DBHeapObject]) -> None:
        with Session(self.engine) as session:
            session.add_all(objects)
            session.commit()

    def save_kmalloc_calls(self, calls: list[DBKmallocCall]) -> None:
        with Session(self.engine) as session:
            session.add_all(calls)
            session.commit()

    def get_all_kmalloc_calls(self) -> list[DBKmallocCall]:
        with Session(self.engine) as session:
            return list(
                session.scalars(select(DBKmallocCall).order_by(DBKmallocCall.id))
            )

    def get_all_heap_objects(self) -> list[DBHeapObject]:
        with Session(self.engine) as session:
            return list(session.scalars(select(DBHeapObject).order_by(DBHeapObject.id)))

    def get_heap_object(self, obj_id: int) -> DBHeapObject | None:
        with Session(self.engine) as session:
            return session.get(DBHeapObject, obj_id)
