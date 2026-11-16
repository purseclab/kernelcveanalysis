"""Positive include-hint batching preserves original fragments and callbacks."""
from collections.abc import Iterable
from pathlib import Path
import random
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from kpatch.filter.git_output import GitGrepRow
from kpatch.filter.include_hints import INCLUDE_HINT_PATTERN, literal_include_hints, needs_normalization
from kpatch.filter.source_filter import (
    SourceIncludeIndex, _BOOTSTRAP_FRAGMENT_BYTES, _BOOTSTRAP_FRAGMENT_SEPARATOR,
    _iter_git_grep, _may_need_normalization,
)
from kpatch.git import GitRepo


class BootstrapFragmentTests(unittest.TestCase):
    def scan(self, fragments: Iterable[bytes]) -> tuple[set[str], list[str]]:
        hints: set[str] = set()
        calls: list[str] = []

        def collect(text: str) -> frozenset[str]:
            calls.append(text)
            result = literal_include_hints(text)
            hints.update(result)
            return result

        index = SourceIncludeIndex('arm64')
        rows = (GitGrepRow(b'HEAD:unit.c', n, value) for n, value in enumerate(fragments, 1))
        with patch('kpatch.filter.source_filter.literal_include_hints', side_effect=collect):
            index._add_bootstrap_fragments(rows, b'HEAD:', None)
        return hints, calls

    def test_bulk_hints_cover_individual_boundaries_and_spellings(self) -> None:
        fragments = [
            b'"api.h"', b'<other.inc>', b'include STR(api.custom)', b'foo.custom',
            b'"unclosed\\', b'other.h"', b'??/', b'"trigraph.h"',
            b'??', b'/missing.h', b'#include "part\\', b'ial.h"',
            b'"escaped\\\"quote.h"', b'left\\\r', b'right.h', b'\0binary.h\0',
            b'"unterminated', b'isolated.h', b'"\xc2', b'\xa0quoted.h"',
            b'include\\\nnext.h', b'??=include??/\r\n"joined.h"',
        ]
        rng = random.Random(71)
        fragments += [bytes(rng.choices(b'abcxyz.h/<>"\\?= \t\r\n\0\xff', k=rng.randrange(1, 100)))
                      for _ in range(1000)]
        expected = set().union(*(literal_include_hints(value.decode('utf-8', errors='replace')) for value in fragments))
        actual, calls = self.scan(fragments)
        self.assertLessEqual(expected, actual)
        self.assertLess(len(calls), len(fragments) // 100)
        self.assertTrue(all(len(value.encode()) <= _BOOTSTRAP_FRAGMENT_BYTES * 3 for value in calls))

    def test_exact_byte_cap_and_giant_fragment_are_never_truncated(self) -> None:
        giant = b'X' * (_BOOTSTRAP_FRAGMENT_BYTES + 7) + b' "giant.h"'
        fragments = [b'"first.h"', b'X' * (_BOOTSTRAP_FRAGMENT_BYTES - 3), b'"boundary.h"',
                     giant, b'"last.h"']
        actual, calls = self.scan(fragments)
        expected = set().union(*(literal_include_hints(value.decode()) for value in fragments))
        self.assertLessEqual(expected, actual)
        self.assertIn(giant.decode(), calls)
        self.assertTrue(all(len(value.encode()) <= _BOOTSTRAP_FRAGMENT_BYTES
                            for value in calls if value != giant.decode()))
        self.assertEqual(sum(giant.decode() in value for value in calls), 1)

    def test_source_changes_and_eof_flush_without_mixing_resolution(self) -> None:
        index = SourceIncludeIndex('arm64', ('left/api.h', 'right/api.h'))
        rows = [GitGrepRow(b'HEAD:left/unit.c', 1, b'"api.h"'),
                GitGrepRow(b'HEAD:right/unit.c', 2, b'"api.h"'),
                GitGrepRow(b'HEAD:left/unit.c', 3, b'"api.h"')]
        callbacks: list[tuple[str, int, bytes]] = []
        index._add_bootstrap_fragments(rows, b'HEAD:', lambda *row: callbacks.append(row))
        self.assertEqual(index.includers('left/api.h'), ('left/unit.c',))
        self.assertEqual(index.includers('right/api.h'), ('right/unit.c',))
        self.assertEqual(callbacks, [('left/unit.c', 1, b'"api.h"'), ('right/unit.c', 2, b'"api.h"'),
                                     ('left/unit.c', 3, b'"api.h"')])

    def test_normalization_is_checked_on_original_not_synthetic_fragments(self) -> None:
        variants = [b'#include "part\\', b'??=include??/', b'#inc\\', b'"part\\']
        whitespace = [' ', '\t', '\r', '\v', '\f', '\x1c', '\x1d', '\x1e', '\x1f', '\u0085', '\u00a0', '\u2003']
        index = SourceIncludeIndex('arm64')
        rows: list[GitGrepRow] = []
        expected: set[str] = set()
        for n, (variant, suffix) in enumerate((v, w) for v in variants for w in whitespace):
            fragment = variant + suffix.encode()
            name = f'unit{n}.c'
            self.assertTrue(needs_normalization(fragment.decode()))
            self.assertTrue(_may_need_normalization(fragment))
            expected.add(name)
            rows.append(GitGrepRow(f'HEAD:{name}'.encode(), 1, fragment))
        index._add_bootstrap_fragments(rows, b'HEAD:', None)
        self.assertEqual(index.normalization_sources, expected)
        self.assertFalse(_may_need_normalization(b'"ordinary.h"'))
        self.assertFalse(_may_need_normalization(b'include normal.h'))

    def test_malformed_or_incomplete_native_rows_cannot_return_an_index(self) -> None:
        index = SourceIncludeIndex('arm64', ('api.h',))
        for path in (b'OTHER:unit.c', b'HEAD:', b'HEAD:\xff'):
            with self.subTest(path=path), self.assertRaises((ValueError, UnicodeError)):
                index._add_bootstrap_fragments([GitGrepRow(path, 1, b'"api.h"')], b'HEAD:', None)

        def failed_rows() -> Iterable[GitGrepRow]:
            yield GitGrepRow(b'HEAD:unit.c', 1, b'"api.h"')
            raise subprocess.CalledProcessError(2, 'git grep')
        with self.assertRaises(subprocess.CalledProcessError):
            index._add_bootstrap_fragments(failed_rows(), b'HEAD:', None)


class NativeBootstrapBatchTests(unittest.TestCase):
    def test_native_ere_and_pcre_preserve_individual_hints_and_full_reference_rows(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            git = ['git', '-C', directory]
            subprocess.run([*git, 'init', '-q'], check=True)
            subprocess.run([*git, 'config', 'user.name', 'Test'], check=True)
            subprocess.run([*git, 'config', 'user.email', 'test@example.invalid'], check=True)
            paths = ('api.h', 'other.inc', 'foo.custom', 'suffix.h')
            for name in paths:
                (root / name).write_bytes(b'')
            source = (b'#define FILE foo.custom\n#include STR(FILE)\n'
                      b'const char *literal = "api.h"; int WANTED; /* original row */\n'
                      b'#include "part\\\nsuffix.h"\n'
                      b'const char *other = "other.inc";\n' + b'"api.h";\n' * 10000
                      + b'#define BIG ' + b'A' * _BOOTSTRAP_FRAGMENT_BYTES + b' "suffix.h"\n')
            (root / 'unit.c').write_bytes(source)
            subprocess.run([*git, 'add', '.'], check=True)
            subprocess.run([*git, 'commit', '-qm', 'input'], check=True)
            repo = GitRepo(root)
            for pcre in (False, True):
                with self.subTest(pcre=pcre):
                    args = ['grep', '--threads=1', '--only-matching', '-n', '-z', '-a',
                            '-P' if pcre else '-E', '-e', INCLUDE_HINT_PATTERN, 'HEAD', '--']
                    individual = SourceIncludeIndex('arm64', paths)
                    rows = list(_iter_git_grep(repo, args))
                    for row in rows:
                        individual.add_line('unit.c', row.contents.decode(errors='replace'))
                    with patch('kpatch.filter.source_filter.literal_include_hints', wraps=literal_include_hints) as hints:
                        batched = SourceIncludeIndex.from_repository(repo, 'HEAD', 'arm64', prefer_pcre=pcre)
                    self.assertLess(hints.call_count, len(rows) // 100)
                    for name in paths:
                        self.assertLessEqual(set(individual.includers(name)), set(batched.includers(name)))
                    self.assertIn('unit.c', batched.normalization_sources)
                    self.assertIn('unit.c', batched.uncertain_sources)
                    hits: list[tuple[str, int, bytes]] = []
                    full = SourceIncludeIndex.from_repository(
                        repo, 'HEAD', 'arm64', prefer_pcre=pcre, reference_names=frozenset({'WANTED'}),
                        reference_hit=lambda *row: hits.append(row),
                    )
                    self.assertIn(('unit.c', 3, source.splitlines()[2]), hits)
                    self.assertIn('unit.c', full.includers('api.h'))
