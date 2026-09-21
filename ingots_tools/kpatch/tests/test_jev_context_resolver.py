from pathlib import Path
import unittest

from kpatch.filter.base import FilterContext, FilteredCommit
from kpatch.filter.jev.c_parser import parse_c_file
from kpatch.filter.jev.context_resolver import resolve_referenced_context
from kpatch.filter.repository_file import RepositoryFileReader
from kpatch.git import GitDb, GitRepo


class TestJevContextResolver(unittest.TestCase):
    def test_resolve_context_on_real_commit(self) -> None:
        db = GitDb(Path("db/filtered.sqlite"))
        repo = GitRepo(Path("linux"))
        commit = [c for c in db.commits_between() if c.commit_id.startswith("360941242f09")][0]
        
        with RepositoryFileReader(repo) as reader:
            src = reader.read_file(commit.commit_id, "io_uring/uring_cmd.c").decode("utf-8")
            parsed_c = parse_c_file("io_uring/uring_cmd.c", src)
            io_cmd = parsed_c.name_to_item["io_uring_cmd"]

            context_items = resolve_referenced_context(
                expanded_items=[io_cmd],
                source_file=parsed_c,
                source_content=src,
                commit_id=commit.commit_id,
                reader=reader,
                max_context_items=10,
            )

            # Check that intra-file helper was resolved
            self.assertTrue(any("io_req_uring_cleanup" in c for c in context_items))
            # Check that header helper was resolved
            self.assertTrue(any("security_uring_cmd" in c for c in context_items))
            # Check that header struct was resolved
            self.assertTrue(any("struct io_uring_cmd" in c for c in context_items))


if __name__ == "__main__":
    unittest.main()
