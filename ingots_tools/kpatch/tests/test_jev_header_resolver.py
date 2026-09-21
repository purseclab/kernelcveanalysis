import unittest

from kpatch.filter.jev.c_parser import IncludeDirective
from kpatch.filter.jev.header_resolver import resolve_include_candidates


class TestJevHeaderResolver(unittest.TestCase):
    def test_resolve_quote_include(self) -> None:
        inc = IncludeDirective(path="uring_cmd.h", is_system=False, line=10)
        cands = resolve_include_candidates("io_uring/uring_cmd.c", inc)
        self.assertEqual(cands[0], "io_uring/uring_cmd.h")
        self.assertIn("include/uring_cmd.h", cands)

    def test_resolve_system_include(self) -> None:
        inc = IncludeDirective(path="linux/security.h", is_system=True, line=5)
        cands = resolve_include_candidates("io_uring/uring_cmd.c", inc)
        self.assertEqual(cands[0], "include/linux/security.h")
        self.assertIn("include/uapi/linux/security.h", cands)
        self.assertIn("arch/x86/include/linux/security.h", cands)


if __name__ == "__main__":
    unittest.main()
