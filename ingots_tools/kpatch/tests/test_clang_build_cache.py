from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import kpatch.filter.policy_clang as policy_clang
from kpatch.filter.policy_clang import ClangToolchain


class ClangBuildCacheTests(unittest.TestCase):
    def test_source_edit_during_compilation_cannot_poison_cached_identity(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'policy_clang_worker.cpp'
            original = b'int original_worker;\n'
            source.write_bytes(original)
            compiler = root / 'compiler'
            compiler.write_text(
                f'#!{sys.executable}\n'
                'from pathlib import Path\nimport sys\n'
                f'Path({str(source)!r}).write_bytes(b"int changed_worker;\\n")\n'
                'input_file = next(Path(arg) for arg in sys.argv[1:] if arg.endswith(".cpp"))\n'
                'Path(sys.argv[sys.argv.index("-o") + 1]).write_bytes(input_file.read_bytes())\n'
            )
            compiler.chmod(0o755)
            toolchain = ClangToolchain(compiler, root, root, root / 'libclang.so', root, 'LLVM-test', root)
            with patch.object(policy_clang, '__file__', str(root / 'policy_clang.py')):
                binary = toolchain.build(root / 'cache')
            self.assertEqual(source.read_bytes(), b'int changed_worker;\n')
            self.assertEqual(binary.read_bytes(), original)
            self.assertEqual(tuple((root / 'cache').iterdir()), (binary,))


if __name__ == '__main__':
    unittest.main()
