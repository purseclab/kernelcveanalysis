import random
from hashlib import sha256
from pathlib import Path
import struct
from tempfile import TemporaryDirectory
import unittest

from seccomp_socket_oracle import interpret_concrete, interpret_kernel_socket
from kpatch.filter.policy_seccomp import (
    ACTION_MASK, ALLOW, ERRNO, KILL_PROCESS, KILL_THREAD, LOG, TRACE, TRAP, USER_NOTIF,
    Disposition, EvaluationBudget, PinnedSeccompFilter, SyscallTarget, evaluate_filter, evaluate_stack,
)


COUNTS: dict[str, int] = {"kernel_oracle_checks": 0, "random_programs": 0,
                          "random_denials": 0, "malformed_inputs": 0}
TARGET = SyscallTarget(0xC00000B7, 280)
DENY = {KILL_THREAD, KILL_PROCESS, TRAP, ERRNO}


def instruction(code: int, k: int = 0, jt: int = 0, jf: int = 0) -> bytes:
    return struct.pack("<HBBI", code, jt, jf, k)


def data_words(target: SyscallTarget, remaining: tuple[int, ...]) -> tuple[int, ...]:
    return (target.number & 0xFFFFFFFF, target.audit_arch, *remaining)


def check_oracles(test: unittest.TestCase, program: bytes, words: tuple[int, ...]) -> int:
    concrete = interpret_concrete(program, words)
    actual = interpret_kernel_socket(program, words)
    COUNTS["kernel_oracle_checks"] += 1
    test.assertEqual(actual, concrete)
    return actual


class PinnedFilterTests(unittest.TestCase):
    def test_load_checks_hash_and_retains_an_immutable_snapshot(self) -> None:
        program = instruction(0x06, ERRNO | 13)
        with TemporaryDirectory() as directory:
            path = Path(directory) / "filter.bpf"
            path.write_bytes(program)
            pinned = PinnedSeccompFilter.load(path, sha256(program).hexdigest())
            path.write_bytes(instruction(0x06, ALLOW))
            self.assertEqual(pinned.data, program)
            self.assertEqual(pinned.digest, sha256(program).hexdigest())
            self.assertEqual(pinned.evaluate(TARGET).disposition, Disposition.DENIED)
            with self.assertRaisesRegex(ValueError, "does not match"):
                PinnedSeccompFilter.load(path, pinned.digest)

    def test_loader_bounds_empty_and_oversized_files(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "filter.bpf"
            for program in (b"", b"x" * (4096 * 8 + 1)):
                with self.subTest(size=len(program)):
                    path.write_bytes(program)
                    with self.assertRaisesRegex(ValueError, "bounded input size"):
                        PinnedSeccompFilter.load(path, sha256(program).hexdigest())
            program = instruction(0x06, ERRNO) * 4096
            path.write_bytes(program)
            self.assertEqual(PinnedSeccompFilter.load(path, sha256(program).hexdigest()).data, program)

    def test_pinning_malformed_bytes_never_promotes_them_to_a_denial(self) -> None:
        for program in (b"1234567", instruction(0xFFFF) + instruction(0x06, ERRNO)):
            with self.subTest(program=program):
                pinned = PinnedSeccompFilter(program)
                self.assertEqual(pinned.evaluate(TARGET).disposition, Disposition.UNKNOWN)


class UniversalTests(unittest.TestCase):
    def test_action_classes_and_data(self) -> None:
        for action in [KILL_THREAD, KILL_PROCESS, TRAP, ERRNO, USER_NOTIF, TRACE, LOG, ALLOW,
                       0x00010000, 0x80010000, 0xFFFF0000]:
            for data in [0, 1, 0xFFFF]:
                with self.subTest(action=action, data=data):
                    program = instruction(0x06, action | data)
                    result = evaluate_filter(program, TARGET)
                    self.assertEqual(result.disposition is Disposition.DENIED, action in DENY)
                    check_oracles(self, program, data_words(TARGET, (0,) * 14))

    def test_nr_arch_and_forward_jumps(self) -> None:
        program = b"".join([
            instruction(0x20, 4), instruction(0x15, TARGET.audit_arch, jt=1),
            instruction(0x06, KILL_PROCESS), instruction(0x20, 0),
            instruction(0x35, 300, jf=1), instruction(0x06, ALLOW), instruction(0x06, ERRNO | 13),
        ])
        for target, expected in [(TARGET, Disposition.DENIED),
                                 (SyscallTarget(TARGET.audit_arch, 500), Disposition.RETAIN),
                                 (SyscallTarget(0x40000028, 500), Disposition.DENIED)]:
            with self.subTest(target=target):
                self.assertEqual(evaluate_filter(program, target).disposition, expected)
                check_oracles(self, program, data_words(target, (0xFFFFFFFF,) * 14))
        jump = instruction(0x05, 1) + instruction(0x06, ALLOW) + instruction(0x06, ERRNO)
        self.assertEqual(evaluate_filter(jump, TARGET).disposition, Disposition.DENIED)
        check_oracles(self, jump, data_words(TARGET, (0,) * 14))

    def test_unknown_arguments_are_not_zero_samples(self) -> None:
        program = (instruction(0x20, 16) + instruction(0x15, 0, jf=1)
                   + instruction(0x06, ERRNO | 1) + instruction(0x06, ALLOW))
        self.assertEqual(evaluate_filter(program, TARGET).disposition, Disposition.RETAIN)
        zero = check_oracles(self, program, data_words(TARGET, (0,) * 14))
        other = list(data_words(TARGET, (0,) * 14)); other[4] = 1
        nonzero = check_oracles(self, program, tuple(other))
        self.assertEqual(zero, ERRNO | 1)
        self.assertEqual(nonzero, ALLOW)

    def test_every_unknown_word_and_conditional_operator(self) -> None:
        for offset in range(8, 64, 4):
            for opcode in [0x15, 0x25, 0x35, 0x45]:
                with self.subTest(offset=offset, opcode=opcode):
                    both_deny = (instruction(0x20, offset) + instruction(opcode, 1, jf=1)
                                 + instruction(0x06, TRAP) + instruction(0x06, ERRNO | 3))
                    mixed = both_deny[:-8] + instruction(0x06, ALLOW)
                    self.assertEqual(evaluate_filter(both_deny, TARGET).disposition, Disposition.DENIED)
                    self.assertEqual(evaluate_filter(mixed, TARGET).disposition, Disposition.RETAIN)
                    for word in [0, 1, 0x80000000, 0xFFFFFFFF]:
                        values = list(data_words(TARGET, (0,) * 14)); values[offset // 4] = word
                        check_oracles(self, mixed, tuple(values))

    def test_uint32_comparisons_not_signed(self) -> None:
        target = SyscallTarget(TARGET.audit_arch, -1)
        for opcode, immediate in [(0x15, 0xFFFFFFFF), (0x25, 0x7FFFFFFF),
                                  (0x35, 0xFFFFFFFF), (0x45, 0x80000000)]:
            program = (instruction(0x20, 0) + instruction(opcode, immediate, jf=1)
                       + instruction(0x06, ERRNO) + instruction(0x06, ALLOW))
            self.assertEqual(evaluate_filter(program, target).disposition, Disposition.DENIED)
            check_oracles(self, program, data_words(target, (0,) * 14))

    def test_accumulator_initialization(self) -> None:
        program = instruction(0x15, 0, jf=1) + instruction(0x06, ERRNO) + instruction(0x06, ALLOW)
        self.assertEqual(evaluate_filter(program, TARGET).disposition, Disposition.DENIED)
        check_oracles(self, program, data_words(TARGET, (0,) * 14))

    def test_no_unsound_correlation_refinement(self) -> None:
        # The ALLOW is concretely infeasible, but the abstract evaluator retains
        # it because it deliberately does not correlate repeated unknown loads.
        program = b"".join([instruction(0x20, 16), instruction(0x15, 0, jf=3),
                            instruction(0x20, 16), instruction(0x15, 0, jt=2),
                            instruction(0x06, ALLOW), instruction(0x06, ERRNO), instruction(0x06, ERRNO)])
        self.assertEqual(evaluate_filter(program, TARGET).disposition, Disposition.RETAIN)
        for arg in [0, 1, 2, 0xFFFFFFFF]:
            words = list(data_words(TARGET, (0,) * 14)); words[4] = arg
            self.assertEqual(check_oracles(self, program, tuple(words)), ERRNO)

    def test_validation_rejects_entire_malformed_program(self) -> None:
        bad = {
            "empty": b"", "truncated": b"1234567", "too_many": instruction(0x06, ERRNO) * 4097,
            "load_unaligned": instruction(0x20, 1) + instruction(0x06, ERRNO),
            "load_past_data": instruction(0x20, 64) + instruction(0x06, ERRNO),
            "jump_past_end": instruction(0x05, 1) + instruction(0x06, ERRNO),
            "jump_uint32_overflow": instruction(0x05, 0xFFFFFFFF) + instruction(0x06, ERRNO),
            "conditional_past_end": instruction(0x15, 0, jt=1) + instruction(0x06, ERRNO),
            "bad_unused_fields": instruction(0x06, ERRNO, jt=1),
            "missing_final_ret": instruction(0x20, 0),
            "unreachable_bad_opcode": instruction(0x06, ERRNO) + instruction(0xFFFF) + instruction(0x06, ERRNO),
            "unreachable_bad_jump": instruction(0x06, ERRNO) + instruction(0x05, 200) + instruction(0x06, ERRNO),
        }
        for name, program in bad.items():
            with self.subTest(name=name):
                COUNTS["malformed_inputs"] += 1
                self.assertEqual(evaluate_filter(program, TARGET).disposition, Disposition.UNKNOWN)

    def test_unsupported_instructions_never_prove_denial(self) -> None:
        for opcode in [0x00, 0x28, 0x30, 0x40, 0x60, 0x80, 0x02, 0x04, 0x16, 0x07, 0x1D]:
            with self.subTest(opcode=opcode):
                program = instruction(opcode) + instruction(0x06, ERRNO)
                self.assertEqual(evaluate_filter(program, TARGET).disposition, Disposition.UNKNOWN)

    def test_budget_exhaustion_and_inputs(self) -> None:
        program = instruction(0x20, 0) + instruction(0x06, ERRNO)
        for budget in [EvaluationBudget(max_states=1), EvaluationBudget(max_instructions=1)]:
            self.assertEqual(evaluate_filter(program, TARGET, budget).disposition, Disposition.UNKNOWN)
        for kwargs in [{"max_states": 0}, {"max_states": 131073}, {"max_instructions": 4097}]:
            with self.assertRaises(ValueError):
                EvaluationBudget(**kwargs)
        for arch, nr in [(-1, 0), (1 << 32, 0), (0, 1 << 31), (0, -(1 << 31) - 1)]:
            with self.assertRaises(ValueError):
                SyscallTarget(arch, nr)

    def test_filter_stack_monotonicity(self) -> None:
        deny, allow = instruction(0x06, ERRNO), instruction(0x06, ALLOW)
        for filters in [(deny, allow), (allow, deny), (b"broken", deny), (deny, b"broken")]:
            self.assertEqual(evaluate_stack(filters, TARGET).disposition, Disposition.DENIED)
        for absent_filters in [(), (allow,), (b"broken",), (deny,) * 65]:
            self.assertEqual(evaluate_stack(absent_filters, TARGET).disposition, Disposition.UNKNOWN)

    def test_kernel_verifier_rejects_invalid_jumps(self) -> None:
        program = instruction(0x05, 500) + instruction(0x06, ERRNO)
        with self.assertRaises(OSError):
            interpret_kernel_socket(program, data_words(TARGET, (0,) * 14))

    def test_maximum_supported_program(self) -> None:
        program = instruction(0x20, 16) * 4095 + instruction(0x06, ERRNO | 7)
        result = evaluate_filter(program, TARGET)
        self.assertEqual(result.disposition, Disposition.DENIED)
        self.assertEqual(result.explored_states, 4096)
        self.assertEqual(interpret_concrete(program, data_words(TARGET, (0xFFFFFFFF,) * 14)), ERRNO | 7)
        # This host rejected a4096-slot socket attachment with ENOMEM; the
        # exact resource limit was not established. Test the full evaluator/
        # concrete bound above and a512-slot kernel chain below, no limit edits.
        shorter = instruction(0x20, 16) * 511 + instruction(0x06, ERRNO | 7)
        check_oracles(self, shorter, data_words(TARGET, (0xFFFFFFFF,) * 14))

    def test_forward_random_programs_against_kernel(self) -> None:
        rng = random.Random(0x5EC0)
        actions = [KILL_THREAD, KILL_PROCESS, TRAP | 1, ERRNO | 13, ALLOW, LOG, TRACE, USER_NOTIF, 0x00010000]
        boundaries = [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]
        for _ in range(120):
            count = rng.randrange(2, 25)
            slots: list[bytes] = []
            for pc in range(count - 1):
                opcode = rng.choice([0x20, 0x05, 0x15, 0x25, 0x35, 0x45, 0x06])
                if opcode == 0x20:
                    slots.append(instruction(opcode, rng.randrange(16) * 4))
                elif opcode == 0x05:
                    slots.append(instruction(opcode, rng.randrange(count - pc - 1)))
                elif opcode == 0x06:
                    slots.append(instruction(opcode, rng.choice(actions)))
                else:
                    slots.append(instruction(opcode, rng.choice(boundaries),
                                             rng.randrange(count - pc - 1), rng.randrange(count - pc - 1)))
            program = b"".join(slots) + instruction(0x06, rng.choice(actions))
            result = evaluate_filter(program, TARGET)
            COUNTS["random_programs"] += 1
            COUNTS["random_denials"] += result.disposition is Disposition.DENIED
            for sample in range(8):
                remaining = tuple(boundaries[sample % len(boundaries)] if sample < 5 else rng.getrandbits(32)
                                  for _ in range(14))
                actual = check_oracles(self, program, data_words(TARGET, remaining))
                if result.disposition is Disposition.DENIED:
                    self.assertIn(actual & ACTION_MASK, DENY)


if __name__ == "__main__":
    unittest.main()
