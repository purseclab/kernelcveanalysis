"""Universal denial for a bounded, validated classic seccomp subset.

This evaluates supplied bytes, not their installation/capture provenance. No
instruction pointer or argument value is assumed. Unsupported input retains.
"""

from collections import deque
from dataclasses import dataclass, field
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
import struct


LD_W_ABS = 0x20
JMP_JA = 0x05
JMP_JEQ_K = 0x15
JMP_JGT_K = 0x25
JMP_JGE_K = 0x35
JMP_JSET_K = 0x45
RET_K = 0x06

KILL_THREAD = 0x00000000
KILL_PROCESS = 0x80000000
TRAP = 0x00030000
ERRNO = 0x00050000
USER_NOTIF = 0x7FC00000
TRACE = 0x7FF00000
LOG = 0x7FFC0000
ALLOW = 0x7FFF0000
ACTION_MASK = 0xFFFF0000
U32_MASK = 0xFFFFFFFF
_MAX_INSNS = 4096
_DATA_BYTES = 64
_WIRE = struct.Struct("<HBBI")
_CONDITIONALS = frozenset({JMP_JEQ_K, JMP_JGT_K, JMP_JGE_K, JMP_JSET_K})
_SUPPORTED = _CONDITIONALS | {LD_W_ABS, JMP_JA, RET_K}
_DENY_ACTIONS = frozenset({KILL_THREAD, KILL_PROCESS, TRAP, ERRNO})


class Disposition(StrEnum):
    DENIED = "universally_denied"
    RETAIN = "not_proven"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class SyscallTarget:
    audit_arch: int
    number: int

    def __post_init__(self) -> None:
        if not 0 <= self.audit_arch <= U32_MASK:
            raise ValueError("audit_arch must be a uint32")
        if not -(1 << 31) <= self.number < (1 << 31):
            raise ValueError("seccomp_data.nr must fit int32")


@dataclass(frozen=True, slots=True)
class EvaluationBudget:
    max_instructions: int = _MAX_INSNS
    max_states: int = 16384

    def __post_init__(self) -> None:
        if not 1 <= self.max_instructions <= _MAX_INSNS or not 1 <= self.max_states <= 131072:
            raise ValueError("budget exceeds the bounded evaluator limits")


@dataclass(frozen=True, slots=True)
class Instruction:
    code: int
    jt: int
    jf: int
    k: int


@dataclass(frozen=True, slots=True)
class ValidatedProgram:
    instructions: tuple[Instruction, ...]
    digest: str


@dataclass(frozen=True, slots=True)
class UniversalResult:
    disposition: Disposition
    reason: str
    filter_sha256: str
    instruction_count: int
    explored_states: int = 0
    terminal_returns: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class PinnedSeccompFilter:
    """Immutable bytes whose application to the subject is a captured premise."""

    data: bytes
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        if not self.data or len(self.data) > _MAX_INSNS * _WIRE.size:
            raise ValueError("Seccomp filter exceeds the bounded input size")
        object.__setattr__(self, "digest", sha256(self.data).hexdigest())

    @classmethod
    def load(cls, path: Path, expected_sha256: str) -> "PinnedSeccompFilter":
        with path.open("rb") as source:
            result = cls(source.read(_MAX_INSNS * _WIRE.size + 1))
        if result.digest != expected_sha256:
            raise ValueError("Seccomp filter does not match the target profile hash")
        return result

    def evaluate(self, target: SyscallTarget) -> UniversalResult:
        return evaluate_filter(self.data, target)


@dataclass(frozen=True, slots=True)
class StackResult:
    disposition: Disposition
    reason: str
    denying_filter_index: int | None
    filters: tuple[UniversalResult, ...]


class ProgramRejected(ValueError):
    pass


def decode_program(data: bytes, budget: EvaluationBudget = EvaluationBudget()) -> ValidatedProgram:
    """Decode AArch64 little-endian sock_filter bytes and validate every slot."""
    if not data or len(data) % _WIRE.size:
        raise ProgramRejected("empty_or_nonintegral_instruction_bytes")
    count = len(data) // _WIRE.size
    if count > budget.max_instructions:
        raise ProgramRejected("instruction_budget")
    instructions = tuple(Instruction(*fields) for fields in _WIRE.iter_unpack(data))
    for pc, instruction in enumerate(instructions):
        _validate_instruction(instruction, pc, count)
    if instructions[-1].code != RET_K:
        raise ProgramRejected("last_instruction_is_not_ret_k")
    return ValidatedProgram(instructions, sha256(data).hexdigest())


def _validate_instruction(instruction: Instruction, pc: int, count: int) -> None:
    if instruction.code not in _SUPPORTED:
        raise ProgramRejected("unsupported_opcode")
    if instruction.code not in _CONDITIONALS and (instruction.jt or instruction.jf):
        raise ProgramRejected("noncanonical_unused_jump_fields")
    if instruction.code == LD_W_ABS:
        if instruction.k % 4 or instruction.k > _DATA_BYTES - 4:
            raise ProgramRejected("unaligned_or_out_of_bounds_seccomp_load")
    elif instruction.code == JMP_JA:
        _validate_target(pc + 1 + instruction.k, pc, count)
    elif instruction.code in _CONDITIONALS:
        _validate_target(pc + 1 + instruction.jt, pc, count)
        _validate_target(pc + 1 + instruction.jf, pc, count)


def _validate_target(target: int, pc: int, count: int) -> None:
    if not pc < target < count:
        raise ProgramRejected("nonforward_or_out_of_bounds_jump")


def _condition(code: int, accumulator: int, immediate: int) -> bool:
    if code == JMP_JEQ_K:
        return accumulator == immediate
    if code == JMP_JGE_K:
        return accumulator >= immediate
    if code == JMP_JGT_K:
        return accumulator > immediate
    if code == JMP_JSET_K:
        return accumulator & immediate != 0
    raise AssertionError("condition called with an unvalidated opcode")


def _load_word(offset: int, target: SyscallTarget) -> int | None:
    if offset == 0:
        return target.number & U32_MASK
    if offset == 4:
        return target.audit_arch
    # Both halves of IP and of every argument remain arbitrary uint32 values.
    return None


def evaluate_filter(data: bytes, target: SyscallTarget,
                    budget: EvaluationBudget = EvaluationBudget()) -> UniversalResult:
    """Prove denial only when an overapproximation reaches exclusively deny RETs.

    None is an unconstrained uint32 accumulator. Branches never constrain that
    value: both successors are explored, including infeasible combinations.
    This may retain a universally denied filter, but cannot justify a false
    denial by sampling arguments or assuming zero.
    """
    digest = sha256(data).hexdigest()
    try:
        program = decode_program(data, budget)
    except ProgramRejected as error:
        return UniversalResult(Disposition.UNKNOWN, str(error), digest, len(data) // _WIRE.size)
    pending: deque[tuple[int, int | None]] = deque([(0, 0)])
    visited: set[tuple[int, int | None]] = set()
    terminals: set[int] = set()
    while pending:
        pc, accumulator = pending.popleft()
        if (pc, accumulator) in visited:
            continue
        if len(visited) >= budget.max_states:
            return UniversalResult(Disposition.UNKNOWN, "state_budget", digest, len(program.instructions),
                                   len(visited), tuple(sorted(terminals)))
        visited.add((pc, accumulator))
        instruction = program.instructions[pc]
        if instruction.code == RET_K:
            terminals.add(instruction.k)
        elif instruction.code == LD_W_ABS:
            pending.append((pc + 1, _load_word(instruction.k, target)))
        elif instruction.code == JMP_JA:
            pending.append((pc + 1 + instruction.k, accumulator))
        elif accumulator is None:
            pending.append((pc + 1 + instruction.jt, None))
            pending.append((pc + 1 + instruction.jf, None))
        else:
            taken = _condition(instruction.code, accumulator, instruction.k)
            pending.append((pc + 1 + (instruction.jt if taken else instruction.jf), accumulator))
    denied = bool(terminals) and all(value & ACTION_MASK in _DENY_ACTIONS for value in terminals)
    return UniversalResult(Disposition.DENIED if denied else Disposition.RETAIN,
                           "every_abstract_terminal_denies" if denied else "non_deny_or_unknown_action_reachable",
                           digest, len(program.instructions), len(visited), tuple(sorted(terminals)))


def evaluate_stack(filters: tuple[bytes, ...], target: SyscallTarget,
                   budget: EvaluationBudget = EvaluationBudget()) -> StackResult:
    """One validated installed deny filter suffices; extra filters cannot relax it.

    The caller must establish that these bytes represent an actually applied
    filter of the target thread. This function establishes no such provenance.
    """
    if not filters or len(filters) > 64:
        return StackResult(Disposition.UNKNOWN, "empty_or_oversized_observed_stack", None, ())
    results = tuple(evaluate_filter(data, target, budget) for data in filters)
    for index, result in enumerate(results):
        if result.disposition is Disposition.DENIED:
            return StackResult(Disposition.DENIED, "a_validated_filter_universally_denies", index, results)
    return StackResult(Disposition.UNKNOWN, "no_individual_universal_denial_proved", None, results)
