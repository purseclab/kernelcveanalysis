from pathlib import Path
import random
import unittest

from kpatch.filter.policy_analysis import _blank, _span_exclusion
from kpatch.filter.policy_clang import ClangFunction, ClangMetadataSpan, ClangSpan, SourcePoint
from kpatch.filter.policy_rules import GateExclusion
from kpatch.filter.policy_source import execution_spans


_PATH = Path('/policy-source-fixture.c')


def span(start: int, end: int) -> ClangSpan:
    return ClangSpan(start=SourcePoint(path=_PATH, offset=start, line=1, column=start + 1),
                     end=SourcePoint(path=_PATH, offset=end, line=1, column=end + 1))


def function(metadata: tuple[ClangMetadataSpan, ...]) -> ClangFunction:
    return ClangFunction(name='run', usr='c:@F@run', span=span(0, 32), body_span=span(0, 32),
                         is_static=True, declaration_coverage_complete=True, body_metadata_coverage_complete=True, body_metadata_spans=metadata)


class PolicySourceTests(unittest.TestCase):
    def test_runtime_masks_ignore_debug_reference_inventory(self) -> None:
        rng = random.Random(4242)
        for _ in range(100):
            intervals = tuple(ClangMetadataSpan(path=_PATH, start=start, end=rng.randint(start + 1, 32))
                              for start in (rng.randrange(32) for _ in range(rng.randrange(12))))
            requested = span(5, 27)
            expected = set(range(5, 27))
            actual = {byte for interval in execution_spans(function(intervals), requested, _PATH)
                      for byte in range(interval.start, interval.end)}
            self.assertEqual(actual, expected)

    def test_unknown_or_out_of_body_inventory_cannot_mask_code(self) -> None:
        legacy = function(()).model_copy(update={'declaration_coverage_complete': False})
        assembler = function(()).model_copy(update={'body_translation_effects': ('body_assembly',)})
        nonlocal_declaration = function(()).model_copy(update={'body_translation_effects': ('block_function_declaration',)})
        for candidate in (legacy, assembler, nonlocal_declaration):
            with self.subTest(candidate=candidate.body_metadata_spans):
                self.assertEqual(execution_spans(candidate, span(5, 27), _PATH), ())

    def test_audit_conversion_preserves_exact_requested_span(self) -> None:
        protected = ClangMetadataSpan(path=_PATH, start=2, end=3)
        candidate = function((protected,))
        runtime, = execution_spans(candidate, span(1, 3), _PATH)
        source = b'{a;}'
        exclusion = _span_exclusion(candidate, runtime, GateExclusion('seccomp', 'fixture'), source)
        self.assertEqual((exclusion.start, exclusion.end), (1, 3))
        self.assertEqual(_blank(source, (exclusion,)), b'{  }')


if __name__ == '__main__':
    unittest.main()
