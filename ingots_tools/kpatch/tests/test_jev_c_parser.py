import unittest

from kpatch.filter.jev.c_parser import (
    ItemKind,
    extract_item_references,
    parse_c_file,
)


class TestJevCParser(unittest.TestCase):
    def test_parse_functions_and_comments(self) -> None:
        source = """
/*
 * Calculate square of a number.
 */
static int square(int x)
{
    return x * x;
}

int add(int a, int b)
{
    return a + b;
}
"""
        parsed = parse_c_file("test.c", source)
        self.assertEqual(len(parsed.items), 2)
        
        sq = parsed.name_to_item["square"]
        self.assertEqual(sq.kind, ItemKind.FUNCTION)
        self.assertEqual(sq.start_line, 2)  # includes doc comment
        self.assertEqual(sq.end_line, 8)
        self.assertIn("Calculate square", sq.code)
        
        ad = parsed.name_to_item["add"]
        self.assertEqual(ad.kind, ItemKind.FUNCTION)
        self.assertEqual(ad.start_line, 10)
        self.assertEqual(ad.end_line, 13)

    def test_parse_structs_enums_unions(self) -> None:
        source = """
/* Point structure */
struct point {
    int x;
    int y;
};

typedef enum {
    COLOR_RED,
    COLOR_BLUE,
} color_t;

union payload {
    int val;
    char raw[4];
};
"""
        parsed = parse_c_file("types.h", source)
        self.assertIn("struct point", parsed.name_to_item)
        self.assertIn("color_t", parsed.name_to_item)
        self.assertIn("union payload", parsed.name_to_item)

        pt = parsed.name_to_item["struct point"]
        self.assertEqual(pt.kind, ItemKind.STRUCT)
        self.assertEqual(pt.start_line, 2)  # includes comment
        self.assertIn("int x;", pt.code)

    def test_parse_macros_and_includes(self) -> None:
        source = """
#include <linux/security.h>
#include "uring_cmd.h"

/* Max macro */
#define MAX(a, b) \\
    ((a) > (b) ? (a) : (b))

#define VERSION 1
"""
        parsed = parse_c_file("macro.c", source)
        self.assertEqual(len(parsed.includes), 2)
        self.assertEqual(parsed.includes[0].path, "linux/security.h")
        self.assertTrue(parsed.includes[0].is_system)
        self.assertEqual(parsed.includes[1].path, "uring_cmd.h")
        self.assertFalse(parsed.includes[1].is_system)

        self.assertIn("MAX", parsed.name_to_item)
        max_m = parsed.name_to_item["MAX"]
        self.assertEqual(max_m.kind, ItemKind.MACRO)
        self.assertEqual(max_m.start_line, 5)  # includes comment
        self.assertEqual(max_m.end_line, 8)

    def test_extract_references(self) -> None:
        source = """
int caller(struct point *p, struct io_ring_ctx *ctx)
{
    security_uring_cmd(p);
    file->f_op->uring_cmd(p);
    return square(p->x);
}
"""
        parsed = parse_c_file("test.c", source)
        caller = parsed.name_to_item["caller"]
        refs = extract_item_references(caller, source)

        self.assertIn("security_uring_cmd", refs.called_functions)
        self.assertIn("uring_cmd", refs.called_functions)
        self.assertIn("square", refs.called_functions)
        self.assertNotIn("return", refs.called_functions)

        self.assertIn("struct point", refs.referenced_types)
        self.assertIn("struct io_ring_ctx", refs.referenced_types)
        self.assertNotIn("int", refs.referenced_types)


if __name__ == "__main__":
    unittest.main()
