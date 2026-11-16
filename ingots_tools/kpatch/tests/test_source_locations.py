import unittest

from kpatch.filter.source_locations import PositionChanges, SourcePositionExemptions, changed_identifier_positions


class SourceLocationTests(unittest.TestCase):
    def changes(self, old: str, new: str) -> PositionChanges:
        result = changed_identifier_positions(old.encode(), new.encode(), frozenset({'input', 'value'}))
        self.assertIsNotNone(result)
        assert result is not None
        return result

    def test_multiline_invocation_end_remains_observable(self) -> None:
        old = 'int run(int input) { return POSITION(\n input\n); }\n'
        new = 'int run(int value) { return POSITION(\n value); }\n'
        self.assertIn('POSITION', self.changes(old, new).lines)

    def test_spliced_identifier_extent_uses_original_physical_lines(self) -> None:
        old = 'int run(void) {return PO\\\nSITION();}\n'
        new = 'int run(void) {return POSITION();}\n'
        self.assertIn('POSITION', self.changes(old, new).lines)

    def test_columns_count_utf8_bytes_even_inside_ignored_comments(self) -> None:
        old = 'int run(void) {return /* é */ POSITION();}\n'
        new = 'int run(void) {return /* a */ POSITION();}\n'
        result = self.changes(old, new)
        self.assertIn('POSITION', result.columns)
        self.assertNotIn('POSITION', result.lines)

    def test_unmodified_uses_outside_function_permutation_are_compared(self) -> None:
        first = 'static int first(void) {return 7;}\n'
        second = 'static int second(void) {return 8;}\n'
        tail = 'int main(void) {return POSITION();}\n'
        self.assertIn('POSITION', self.changes(first + second + tail, second + first + '\n' + tail).lines)

    def test_same_total_line_count_does_not_hide_a_moved_use(self) -> None:
        old = 'int run(int input);\nint main(void) {return POSITION();}\n\n'
        new = '\nint run(int value);\nint main(void) {return POSITION();}\n'
        self.assertEqual(old.count('\n'), new.count('\n'))
        self.assertIn('POSITION', self.changes(old, new).lines)

    def test_ambiguous_header_comments_cannot_hide_later_identifiers(self) -> None:
        source = b'#include <path/*part>\nint run(int input);\n'
        self.assertIsNone(changed_identifier_positions(source, source.replace(b'input', b'value'), frozenset()))

    def test_exemption_only_covers_one_occurrence_including_its_group(self) -> None:
        old = b'int run(void) {printk("short", printk); return printk;}\n'
        new = old.replace(b'short', b'much longer wording')
        exemptions = SourcePositionExemptions(frozenset({old.index(b'printk')}), frozenset({new.index(b'printk')}))
        changes = changed_identifier_positions(old, new, frozenset(), exemptions=exemptions)
        self.assertIsNotNone(changes)
        assert changes is not None
        self.assertIn('printk', changes.columns)

    def test_exempt_callee_ignores_its_invocation_extent(self) -> None:
        old = b'int run(void) {printk("short");}\n'
        new = old.replace(b'short', b'much longer wording')
        exemptions = SourcePositionExemptions(frozenset({old.index(b'printk')}), frozenset({new.index(b'printk')}))
        changes = changed_identifier_positions(old, new, frozenset(), exemptions=exemptions)
        self.assertIsNotNone(changes)
        assert changes is not None
        self.assertNotIn('printk', changes.columns)


if __name__ == '__main__':
    unittest.main()
