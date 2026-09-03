import unittest
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from kpatch.dataset import (
    Commit,
    CommitScope,
    Dataset,
    VulnCertainty,
    VulnSource,
    load_git_commits,
)


PATCH_EMAIL = """From 0123456789abcdef0123456789abcdef01234567 Mon Sep 17 00:00:00 2001
From: Alice Example <alice@example.com>
Date: Tue, 3 Jun 2014 12:27:07 +0000
Subject: Fix the bug

Fix the bug in the subsystem.

Signed-off-by: Alice Example <alice@example.com>
---
 fs/example.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/fs/example.c b/fs/example.c
index 1234567..89abcde 100644
--- a/fs/example.c
+++ b/fs/example.c
@@ -1 +1 @@
-old
+new
"""

RAW_PATCH = """diff --git a/fs/example.c b/fs/example.c
index 1234567..89abcde 100644
--- a/fs/example.c
+++ b/fs/example.c
@@ -1 +1 @@
-old
+new
"""


def make_commit(commit_id: str, patch_text: str) -> Commit:
    return Commit(
        source_url="https://example.com/source",
        summary="summary",
        evidence_group="group",
        certainty=VulnCertainty.HIGH,
        source_kind=VulnSource.CVE,
        commit_id=commit_id,
        commit_url="https://example.com/commit",
        patch_url="https://example.com/patch",
        patch_text=patch_text,
        commit_scope=CommitScope.UPSTREAM,
    )


class DatasetGitCommitTests(unittest.TestCase):
    def test_converts_patch_email_to_git_commit(self) -> None:
        commit = Dataset(records=[make_commit("commit", PATCH_EMAIL)]).to_git_commits()[0]

        self.assertEqual(commit.commit_id, "commit")
        self.assertEqual(commit.author_name, "Alice Example")
        self.assertEqual(commit.author_email, "alice@example.com")
        self.assertEqual(
            commit.author_date,
            datetime(2014, 6, 3, 12, 27, 7, tzinfo=UTC),
        )
        self.assertEqual(commit.committer_date, commit.author_date)
        self.assertEqual(len(commit.parents), 1)
        self.assertEqual(commit.parent.commit_id if commit.parent else None, "")
        self.assertEqual(
            commit.message,
            "Fix the bug\n\nFix the bug in the subsystem.\n\n"
            "Signed-off-by: Alice Example <alice@example.com>",
        )
        self.assertEqual(
            commit.diff_str,
            PATCH_EMAIL[PATCH_EMAIL.index("diff --git "):].rstrip("\n"),
        )

    def test_raw_patch_uses_metadata_sentinels(self) -> None:
        commit = Dataset(records=[make_commit("raw", RAW_PATCH)]).to_git_commits()[0]

        self.assertEqual(commit.author_name, "")
        self.assertEqual(commit.author_email, "")
        self.assertEqual(commit.author_date, datetime(1970, 1, 1, tzinfo=UTC))
        self.assertEqual(commit.committer_date, commit.author_date)
        self.assertEqual(commit.diff_str, RAW_PATCH.rstrip("\n"))

    def test_load_git_commits_loads_a_dataset_file(self) -> None:
        with TemporaryDirectory() as directory:
            dataset_path = Path(directory) / "dataset.json"
            dataset_path.write_text(
                Dataset(records=[make_commit("commit", RAW_PATCH)]).model_dump_json()
            )

            commits = load_git_commits(dataset_path)

        self.assertEqual([commit.commit_id for commit in commits], ["commit"])


if __name__ == "__main__":
    unittest.main()
