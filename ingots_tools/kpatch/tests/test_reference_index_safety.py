from collections.abc import Iterator
from datetime import UTC, datetime
from contextlib import closing
from pathlib import Path
import os
import subprocess
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from kpatch.diff import Diff
from kpatch.filter import DeadCodeFilter, FilterContext
from kpatch.filter.git_output import GitGrepProtocolError, GitGrepRow
from kpatch.filter.reference_index import ReferenceIndex, spelling_guards
from kpatch.filter.repository_file import RepositoryFileReader
from kpatch.filter.source_filter import SourceIncludeIndex
from kpatch.git import CommitParent, GitCommit, GitRepo


class ReferenceIndexSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name)
        self.repo = GitRepo(self.path)
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Test")

    def git(self, *arguments: str) -> str:
        return subprocess.check_output(["git", "-C", str(self.path), *arguments], stderr=subprocess.PIPE).decode().strip()

    def commit(self, files: dict[str, str]) -> str:
        for relative, source in files.items():
            path = self.path / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source)
        self.git("add", ".")
        self.git("commit", "-qm", "reference safety", "--allow-empty")
        return self.git("rev-parse", "HEAD")

    def change(self, before: dict[str, str], after: dict[str, str]) -> GitCommit:
        parent = self.commit(before)
        child = self.commit(after)
        date = datetime(2026, 11, 6, tzinfo=UTC)
        return GitCommit(child, "Test", "test@example.invalid", date, date,
                         (CommitParent(parent, self.git("diff", parent, child)),), "reference safety")

    def assert_included_fragment_retains_helper(self, extension: str) -> None:
        fragment = "calls." + extension
        old = ('static int isolated_helper(void) { return 1; }\n'
               '#include "' + fragment + '"\n')
        commit = self.change({"unit.c": old, fragment: "int run(void) { return isolated_helper(); }\n"},
                             {"unit.c": old.replace("return 1", "return 2")})
        self.assertEqual(len(DeadCodeFilter().filter_commits([commit], FilterContext(self.repo), False)), 1)

    def test_included_inc_fragment_retains_reachable_helper(self) -> None:
        self.assert_included_fragment_retains_helper("inc")

    def test_included_text_fragment_retains_reachable_helper(self) -> None:
        self.assert_included_fragment_retains_helper("txt")

    def test_included_arbitrary_extension_retains_reachable_helper(self) -> None:
        self.assert_included_fragment_retains_helper("data")

    def test_macro_include_cannot_make_shared_include_scope_hide_live_caller(self) -> None:
        old = "static inline int isolated_helper(void) { return 1; }\n"
        commit = self.change({"api.h": old, "known.c": '#include "api.h"\n',
                              "opaque.c": '#define HEADER "api.h"\n#include HEADER\nint run(void) { return isolated_helper(); }\n'},
                             {"api.h": old.replace("return 1", "return 2")})
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            index.bind_includes(SourceIncludeIndex.from_repository(self.repo, commit.commit_id, "x86"), commit.commit_id)
            context = FilterContext(self.repo, file_reader=reader, reference_index=index)
            self.assertEqual(len(DeadCodeFilter().filter_commits([commit], context, False)), 1)

    def test_incremental_reference_update_includes_changed_unusual_text_paths(self) -> None:
        parent = self.commit({"unit.c": "int value;\n", "generated.data": "int untouched;\n"})
        child = self.commit({"generated.data": "int run(void) { return isolated_helper(); }\n"})
        names = frozenset({"isolated_helper"})
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            self.assertEqual(index.lookup(parent, names)["isolated_helper"], ())
            changed = index.changed_paths(parent, child)
            self.assertIn("generated.data", changed)
            sites = index.lookup(child, names, parent=parent, changed_paths=changed)["isolated_helper"]
            self.assertEqual({site.path for site in sites or ()}, {"generated.data"})
            self.assertEqual(index.stats().incremental_updates, 1)

    def test_historical_include_updates_mark_all_changed_input_spellings(self) -> None:
        parent = self.commit({'unit.c': 'int value;\n', 'calls.data': 'int existing;\n', 'api.h': 'int declared;\n'})
        graph = SourceIncludeIndex.from_repository(self.repo, parent, 'x86')
        child = self.commit({'calls.data': '#i\\\nnclude "api.h"\n',
                             'new.fragment': '#define HEADER "api.h"\n#include HEADER\n'})
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            index.bind_includes(graph, parent)
            before = graph.generation
            self.assertTrue(index.ensure_includes(child))
            self.assertIn('calls.data', graph.uncertain_sources)
            self.assertIn('new.fragment', graph.uncertain_sources)
            self.assertTrue(graph.has_path('new.fragment'))
            self.assertGreater(graph.generation, before)
            generation = graph.generation
            self.assertTrue(index.ensure_includes(child))
            self.assertEqual(graph.generation, generation)

    def test_forced_diff_color_cannot_hide_a_historical_include(self) -> None:
        parent = self.commit({'consumer.data': 'int value;\n', 'api.h': 'int declared;\n'})
        graph = SourceIncludeIndex.from_repository(self.repo, parent, 'x86')
        child = self.commit({'consumer.data': '#include "api.h"\nint value;\n'})
        self.git('config', 'color.ui', 'always')
        self.git('config', 'color.diff', 'always')
        self.assertIn('\x1b[', self.git('diff', parent, child))
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            index.bind_includes(graph, parent)
            self.assertTrue(index.ensure_includes(child))
            self.assertIn('consumer.data', graph.includers('api.h'))
            self.assertIn('consumer.data', graph.uncertain_sources)
            self.assertEqual(index._include_revision, child)
            self.assertIn(child, index._include_seen)

    def test_textconv_cannot_hide_a_historical_include(self) -> None:
        converter = self.path / '.git' / 'hide-source'
        converter.write_text('#!/bin/sh\nprintf "int converted;\\n"\n')
        converter.chmod(0o755)
        self.git('config', 'diff.conceal.textconv', str(converter))
        parent = self.commit({'.gitattributes': 'consumer.data diff=conceal\n',
                              'consumer.data': 'int value;\n', 'api.h': 'int declared;\n'})
        graph = SourceIncludeIndex.from_repository(self.repo, parent, 'x86')
        child = self.commit({'consumer.data': '#include "api.h"\nint value;\n'})
        self.assertEqual(self.git('diff', parent, child), '')
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            index.bind_includes(graph, parent)
            self.assertTrue(index.ensure_includes(child))
            self.assertIn('consumer.data', graph.includers('api.h'))
            self.assertIn('consumer.data', graph.uncertain_sources)
            self.assertEqual(index._include_revision, child)

    def test_binary_diff_suppression_cannot_hide_historical_include_hints(self) -> None:
        parent = self.commit({'consumer.data': '\0int value;\n', 'api.h': 'int declared;\n'})
        graph = SourceIncludeIndex.from_repository(self.repo, parent, 'x86')
        child = self.commit({'consumer.data': '\0int value;\n#include "api.h"\n'})
        self.assertIn('Binary files ', self.git('diff', parent, child))
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            index.bind_includes(graph, parent)
            self.assertTrue(index.ensure_includes(child))
            self.assertIn('consumer.data', graph.includers('api.h'))
            self.assertIn('consumer.data', graph.uncertain_sources)
            self.assertEqual(index._include_revision, child)

    def test_quoted_historical_paths_cannot_mutate_or_complete_the_include_index(self) -> None:
        self.git('config', 'core.quotePath', 'true')
        for filename in ('line\nname.data', 'escape\x1bname.data', 'tab\tname.data', 'café.data'):
            with self.subTest(filename=filename):
                parent = self.commit({filename: 'int value;\n', 'api.h': 'int declared;\n'})
                graph = SourceIncludeIndex.from_repository(self.repo, parent, 'x86')
                child = self.commit({filename: '#include "api.h"\nint value;\n'})
                self.assertIn('diff --git "', self.git('diff', parent, child))
                before_paths = set(graph._tracked_paths)
                before_uncertain = graph.uncertain_sources
                generation = graph.generation
                with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
                    index.bind_includes(graph, parent)
                    self.assertFalse(index.ensure_includes(child))
                    self.assertEqual(index._include_revision, parent)
                    self.assertNotIn(child, index._include_seen)
                    self.assertIn(child, index._include_failures)
                self.assertEqual(set(graph._tracked_paths), before_paths)
                self.assertEqual(graph.uncertain_sources, before_uncertain)
                self.assertEqual(graph.generation, generation)
                self.assertNotIn(filename, graph.includers('api.h'))

    def test_old_suffix_limited_negative_cache_cannot_hide_text_fragment_reference(self) -> None:
        revision = self.commit({"consumer.inc": "int run(void) { return isolated_helper(); }\n"})
        cache = self.path / ".git" / "old-reference-cache.sqlite"
        with closing(sqlite3.connect(cache)) as database:
            database.execute("CREATE TABLE queries (revision TEXT, name TEXT, sites BLOB NOT NULL, PRIMARY KEY(revision,name))")
            database.execute("INSERT INTO queries VALUES (?,?,?)", (revision, "v4:isolated_helper", b"[]"))
            database.commit()
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file, cache_path=cache) as index:
            sites = index.lookup(revision, frozenset({"isolated_helper"}))["isolated_helper"]
            self.assertEqual({site.path for site in sites or ()}, {"consumer.inc"})
            self.assertEqual(index.stats().repository_scans, 1)

    def test_hidden_submodule_changes_remain_opaque_include_inputs(self) -> None:
        parent = self.commit({'unit.c': 'int value;\n'})
        graph = SourceIncludeIndex.from_repository(self.repo, parent, 'x86')
        self.git('update-index', '--add', '--cacheinfo', f'160000,{parent},submodule')
        self.git('commit', '-qm', 'add opaque input')
        child = self.git('rev-parse', 'HEAD')
        self.git('config', 'diff.ignoreSubmodules', 'all')
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            index.bind_includes(graph, parent)
            self.assertEqual(index.changed_paths(parent, child), frozenset({'submodule'}))
            self.assertTrue(index.ensure_includes(child))
            self.assertTrue(graph.has_input('submodule'))
            self.assertFalse(graph.has_path('submodule'))
            self.assertIn('submodule', graph.uncertain_sources)

    def test_shared_reference_bootstrap_searches_unusual_text_paths(self) -> None:
        commit = self.change({"include/linux/api.h": "", "consumer.inc": "int run(void) { return isolated_helper(); }\n"},
                             {"include/linux/api.h": "static inline int isolated_helper(void) { return 1; }\n"})
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            index.observe_patch(commit.diff_str)
            names = index.begin_bootstrap(commit.commit_id)
            self.assertTrue(spelling_guards("isolated_helper") <= names)
            SourceIncludeIndex.from_repository(self.repo, commit.commit_id, "x86", reference_names=names,
                                               reference_hit=index.bootstrap_hit, prefer_pcre=True)
            index.finish_bootstrap()
            sites = index.lookup(commit.commit_id, frozenset({"isolated_helper"}))["isolated_helper"]
            self.assertIn("consumer.inc", {site.path for site in sites or ()})
            self.assertEqual(index.stats().repository_scans, 0)

    def test_native_reference_discovery_includes_compiler_accepted_nul_source(self) -> None:
        revision = self.commit({'consumer.c': '\0int run(void) { return isolated_helper(); }\n'})
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            sites = index.lookup(revision, frozenset({'isolated_helper'}))['isolated_helper']
            self.assertEqual({site.path for site in sites or ()}, {'consumer.c'})

    def test_binary_suppressed_negative_cache_is_not_reused(self) -> None:
        revision = self.commit({'consumer.c': '\0int run(void) { return isolated_helper(); }\n'})
        cache = self.path / '.git' / 'explicit-v5-cache.sqlite'
        with closing(sqlite3.connect(cache)) as database:
            database.execute('CREATE TABLE queries (revision TEXT, name TEXT, sites BLOB NOT NULL, PRIMARY KEY(revision,name))')
            database.execute('INSERT INTO queries VALUES (?,?,?)', (revision, 'v5:isolated_helper', b'[]'))
            database.commit()
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file, cache_path=cache) as index:
            sites = index.lookup(revision, frozenset({'isolated_helper'}))['isolated_helper']
            self.assertEqual({site.path for site in sites or ()}, {'consumer.c'})
            self.assertEqual(index.stats().repository_scans, 1)

    def test_reference_bootstrap_includes_nul_source(self) -> None:
        commit = self.change({'include/linux/api.h': '', 'consumer.c': '\0int run(void) { return isolated_helper(); }\n'},
                             {'include/linux/api.h': 'static inline int isolated_helper(void) { return 1; }\n'})
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            index.observe_patch(commit.diff_str)
            names = index.begin_bootstrap(commit.commit_id)
            SourceIncludeIndex.from_repository(self.repo, commit.commit_id, 'x86', reference_names=names,
                                               reference_hit=index.bootstrap_hit, prefer_pcre=True)
            index.finish_bootstrap()
            sites = index.lookup(commit.commit_id, frozenset({'isolated_helper'}))['isolated_helper']
            self.assertIn('consumer.c', {site.path for site in sites or ()})
            self.assertEqual(index.stats().repository_scans, 0)

    def test_forced_color_preserves_reference_paths_and_source_bytes(self) -> None:
        self.git('config', 'color.grep', 'always')
        paths = ('odd\nfilename.fragment', 'colon:name.data', 'escape\x1b[31m.fragment', 'café.inc')
        revision = self.commit({path: '\0int value = isolated_helper;\x1b[32m\n' for path in paths})
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            sites = index.lookup(revision, frozenset({'isolated_helper'}))['isolated_helper']
            self.assertEqual({site.path for site in sites or ()}, set(paths))
            self.assertEqual({site.line for site in sites or ()}, {1})

    def test_color_and_unusual_paths_preserve_include_edges_and_bootstrap(self) -> None:
        self.git('config', 'color.grep', 'always')
        paths = ('odd\nfilename.fragment', 'colon:name.data', 'escape\x1b[31m.fragment', 'café.inc')
        before = {path: '#include "api.h"\n\0int run(void) { return isolated_helper(); }\n' for path in paths}
        before['include/linux/api.h'] = ''
        before['api.h'] = 'int declaration;\n'
        commit = self.change(before, {'include/linux/api.h': 'static inline int isolated_helper(void) { return 1; }\n'})
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            index.observe_patch(commit.diff_str)
            names = index.begin_bootstrap(commit.commit_id)
            self.assertIn('isolated_helper', names)
            includes = SourceIncludeIndex.from_repository(
                self.repo, commit.commit_id, 'x86', reference_names=names,
                reference_hit=index.bootstrap_hit, prefer_pcre=True)
            self.assertEqual(set(includes.includers('api.h')), set(paths))
            self.assertTrue(set(paths) <= set(includes.uncertain_sources))
            index.finish_bootstrap()
            sites = index.lookup(commit.commit_id, frozenset({'isolated_helper'}))['isolated_helper']
            self.assertTrue(set(paths) <= {site.path for site in sites or ()})
            self.assertEqual(index.stats().repository_scans, 0)

    def test_old_transport_negative_caches_cannot_hide_reference_with_newline_in_path(self) -> None:
        path = 'odd\nfilename.fragment'
        revision = self.commit({path: 'int value = isolated_helper;\n'})
        cache = self.path / '.git' / 'explicit-old-transport-cache.sqlite'
        with closing(sqlite3.connect(cache)) as database:
            database.execute('CREATE TABLE queries (revision TEXT, name TEXT, sites BLOB NOT NULL, PRIMARY KEY(revision,name))')
            for version in ('v6', 'v7'):
                database.execute('INSERT INTO queries VALUES (?,?,?)', (revision, version + ':isolated_helper', b'[]'))
            database.commit()
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file, cache_path=cache) as index:
            sites = index.lookup(revision, frozenset({'isolated_helper'}))['isolated_helper']
            self.assertEqual({site.path for site in sites or ()}, {path})
            self.assertEqual(index.stats().repository_scans, 1)
        with closing(sqlite3.connect(cache)) as database:
            row = database.execute('SELECT sites FROM queries WHERE revision=? AND name=?',
                                   (revision, 'v8:isolated_helper')).fetchone()
            self.assertIsNotNone(row)
            assert row is not None
            self.assertNotEqual(row[0], b'[]')

    def test_anchor_reference_paths_are_literal_git_pathspecs(self) -> None:
        paths = (':(exclude)*', 'bracket[0].data', 'glob*.data', 'question?.data')
        sources = {path: 'int value = OLD_LIMIT;\n' for path in paths}
        sources['api.h'] = 'enum kind { OLD_LIMIT = 1 };\n'
        parent = self.commit(sources)
        child = self.commit({'api.h': 'enum kind { NEW_LIMIT = 1 };\n'})
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            index.plan_diffs((Diff.parse(self.git('diff', parent, child)),))
            self.assertTrue(index._pool)
            before = index.lookup(parent, frozenset({'OLD_LIMIT'}))['OLD_LIMIT']
            self.assertEqual({site.path for site in before or ()}, set(paths) | {'api.h'})
            sites = index.lookup(child, frozenset({'OLD_LIMIT'}))['OLD_LIMIT']
            self.assertEqual({site.path for site in sites or ()}, set(paths))

    def test_changed_reference_paths_are_literal_git_pathspecs(self) -> None:
        paths = (':(exclude)*', 'bracket[0].data', 'glob*.data', 'question?.data')
        parent = self.commit({'api.h': 'enum kind { OLD_LIMIT = 1 };\n'})
        sources = {path: 'int value = OLD_LIMIT;\n' for path in paths}
        sources['api.h'] = 'enum kind { NEW_LIMIT = 1 };\n'
        child = self.commit(sources)
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            index.plan_diffs((Diff.parse(self.git('diff', parent, child)),))
            self.assertTrue(index._pool)
            before = index.lookup(parent, frozenset({'OLD_LIMIT'}))['OLD_LIMIT']
            self.assertEqual({site.path for site in before or ()}, {'api.h'})
            sites = index.lookup(child, frozenset({'OLD_LIMIT'}))['OLD_LIMIT']
            self.assertEqual({site.path for site in sites or ()}, set(paths))

    def test_literal_pathspec_environment_preserves_reference_path_queries(self) -> None:
        filename = ':(exclude)*'
        parent = self.commit({'api.h': 'enum kind { OLD_LIMIT = 1 };\n',
                              filename: 'int value = OLD_LIMIT;\n'})
        child = self.commit({'api.h': 'enum kind { NEW_LIMIT = 1 };\n'})
        with patch.dict(os.environ, {'GIT_LITERAL_PATHSPECS': '1'}):
            with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
                index.plan_diffs((Diff.parse(self.git('diff', parent, child)),))
                self.assertTrue(index._pool)
                index.lookup(parent, frozenset({'OLD_LIMIT'}))
                sites = index.lookup(child, frozenset({'OLD_LIMIT'}))['OLD_LIMIT']
                self.assertEqual({site.path for site in sites or ()}, {filename})

    def test_malformed_reference_stream_cannot_persist_absence(self) -> None:
        revision = self.commit({'consumer.c': 'int value = isolated_helper;\n'})
        cache = self.path / '.git' / 'protocol-cache.sqlite'
        def malformed() -> Iterator[GitGrepRow]:
            yield GitGrepRow((revision + ':other.c').encode(), 1, b'int unrelated;')
            raise GitGrepProtocolError('truncated row')
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file, cache_path=cache) as index:
            with patch('kpatch.filter.reference_index._iter_git_grep', return_value=malformed()):
                with self.assertRaises(GitGrepProtocolError):
                    index.lookup(revision, frozenset({'isolated_helper'}))
            with closing(sqlite3.connect(cache)) as database:
                self.assertEqual(database.execute('SELECT COUNT(*) FROM queries').fetchone(), (0,))
            sites = index.lookup(revision, frozenset({'isolated_helper'}))['isolated_helper']
            self.assertEqual({site.path for site in sites or ()}, {'consumer.c'})

    def test_unexpected_revision_prefix_cannot_be_skipped_into_absence(self) -> None:
        revision = self.commit({'consumer.c': 'int value = isolated_helper;\n'})
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            def rows() -> Iterator[GitGrepRow]:
                yield GitGrepRow(b'wrong:consumer.c', 1, b'isolated_helper')
            with patch('kpatch.filter.reference_index._iter_git_grep', return_value=rows()):
                with self.assertRaises(ValueError):
                    index.lookup(revision, frozenset({'isolated_helper'}))
            sites = index.lookup(revision, frozenset({'isolated_helper'}))['isolated_helper']
            self.assertEqual({site.path for site in sites or ()}, {'consumer.c'})

    def test_non_utf8_filename_cannot_establish_reference_absence(self) -> None:
        filename = os.fsdecode(b'nonutf8-\xff.fragment')
        revision = self.commit({filename: 'int value = isolated_helper;\n'})
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            with self.assertRaises(UnicodeError):
                index.lookup(revision, frozenset({'isolated_helper'}))
        with self.assertRaises(UnicodeError):
            SourceIncludeIndex.from_repository(self.repo, revision, 'x86')

    def test_anchor_delta_scan_keeps_new_unusual_text_references(self) -> None:
        parent = self.commit({"api.h": "#define OLD_LIMIT 1\n", "consumer.data": "int value;\n"})
        child = self.commit({"api.h": "#define NEW_LIMIT 1\n", "consumer.data": "int value = OLD_LIMIT;\n"})
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            index.plan_diffs((Diff.parse(self.git("diff", parent, child)),))
            parent_sites = index.lookup(parent, frozenset({"OLD_LIMIT"}))["OLD_LIMIT"]
            self.assertEqual({site.path for site in parent_sites or ()}, {"api.h"})
            sites = index.lookup(child, frozenset({"OLD_LIMIT"}))["OLD_LIMIT"]
            self.assertEqual({site.path for site in sites or ()}, {"consumer.data"})


if __name__ == "__main__":
    unittest.main()
