"""Typed positive input-role evidence, uncertainty and operational failures."""

from dataclasses import dataclass
from enum import StrEnum

from .masking import FileIdentity, SourceSide


class RawInputKind(StrEnum):
    ASSEMBLER_INCBIN = 'assembler_incbin'
    ASSEMBLER_INCLUDE = 'assembler_include'
    MAKE_GENERATOR = 'make_generator'


class InputInventoryState(StrEnum):
    FULL = 'full'
    INCOMPLETE = 'incomplete'
    RETENTION_WITNESS = 'retention_witness'


class RawInputUnknownKind(StrEnum):
    MAKE_OPERAND = 'make_operand'
    ASM_OPERAND = 'asm_operand'
    MAKE_EXPANSION = 'make_expansion'


class RawInputFailureKind(StrEnum):
    UNSUPPORTED_COORDINATE = 'unsupported_coordinate'
    NATIVE_SCAN = 'native_scan'
    CONSUMER_READ = 'consumer_read'
    CONSUMER_PARSE = 'consumer_parse'
    NONREGULAR_CONSUMER = 'nonregular_consumer'
    INPUT_ALIAS = 'input_alias'
    FILE_BUDGET = 'file_budget'
    INPUT_BUDGET = 'input_budget'
    REFERENCE_BUDGET = 'reference_budget'
    TREE_BUDGET = 'tree_budget'
    DELTA_ROW_BUDGET = 'delta_row_budget'
    DELTA_PATH_BUDGET = 'delta_path_budget'
    PATH_BUDGET = 'path_budget'
    PROTOCOL = 'protocol'


@dataclass(frozen=True, slots=True)
class RawInputConsumer:
    path: str
    line: int
    kind: RawInputKind
    target: str | None = None


@dataclass(frozen=True, slots=True)
class RawInputUnknown:
    consumer_path: str
    line: int | None
    kind: RawInputUnknownKind
    operand: str | None
    source_sha256: str


@dataclass(frozen=True, slots=True)
class RawInputFailure:
    kind: RawInputFailureKind
    consumer_path: str | None = None
    line: int | None = None
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class RawInputObservation:
    state: InputInventoryState
    consumers: tuple[RawInputConsumer, ...] = ()
    unknowns: tuple[RawInputUnknown, ...] = ()
    failures: tuple[RawInputFailure, ...] = ()


class SourceRoleStatus(StrEnum):
    BLOCKED = 'blocked'
    OBSERVED_CLEAR = 'observed_clear'
    ASSUMED = 'assumed'


@dataclass(frozen=True, slots=True)
class SourceRoleEvidence:
    side: SourceSide
    revision: str
    path: str
    observation: RawInputObservation


@dataclass(frozen=True, slots=True)
class SourceRoleDecision:
    file: FileIdentity
    status: SourceRoleStatus
    evidence: tuple[SourceRoleEvidence, ...] = ()
