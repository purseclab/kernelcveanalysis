import argparse
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import extract_fix_commits as subject


class CommitUrlTests(unittest.TestCase):
    def test_compact_kernel_stable_url(self) -> None:
        link = subject.parse_linux_commit_url(
            "https://git.kernel.org/stable/c/"
            "5aa57d9f2d5311f19434d95b2a81610aa263e23b"
        )
        self.assertIsNotNone(link)
        assert link is not None
        self.assertEqual(
            link.patch_url,
            "https://git.kernel.org/pub/scm/linux/kernel/git/stable/"
            "linux.git/patch/?id=5aa57d9f2d5311f19434d95b2a81610aa263e23b",
        )

    def test_linux_github_commit(self) -> None:
        link = subject.parse_linux_commit_url(
            "https://github.com/torvalds/linux/commit/35f56c554eb1"
        )
        self.assertIsNotNone(link)
        assert link is not None
        self.assertEqual(link.commit_id, "35f56c554eb1")
        self.assertTrue(link.patch_url.endswith(".patch"))

    def test_unrelated_commit_is_rejected(self) -> None:
        self.assertIsNone(
            subject.parse_linux_commit_url(
                "https://github.com/example/not-linux/commit/35f56c554eb1"
            )
        )


class DatasetTests(unittest.TestCase):
    def test_cve_and_non_cve_findings_are_combined(self) -> None:
        full_hash_1 = "1" * 40
        full_hash_2 = "2" * 40
        full_hash_3 = "3" * 40
        nvd_payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2099-0001",
                        "references": [
                            {
                                "url": f"https://git.kernel.org/stable/c/{full_hash_1}",
                                "tags": ["Patch"],
                            },
                            {
                                "url": f"https://github.com/torvalds/linux/commit/{full_hash_2}",
                                "tags": ["Patch"],
                            },
                            {"url": "https://example.com/advisory"},
                        ],
                    }
                }
            ]
        }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cve_input = root / "cves.json"
            non_cve_input = root / "non-cves.json"
            cve_input.write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "cve": "CVE-2099-0001",
                                "source_url": "https://example.com/cve",
                                "summary": "CVE summary",
                                "certainty": "high",
                                "type": "lpe",
                            }
                        ]
                    }
                )
            )
            non_cve_input.write_text(
                json.dumps(
                    [
                        {
                            "identifier": "linux-test-finding",
                            "cve": None,
                            "source_url": "https://example.com/non-cve",
                            "summary": "Non-CVE summary",
                            "certainty": "high",
                            "type": "lpe",
                            "commit_url": f"https://github.com/torvalds/linux/commit/{full_hash_3}",
                        }
                    ]
                )
            )
            args = argparse.Namespace(
                cve_input=cve_input,
                non_cve_input=non_cve_input,
                cache_dir=root / "cache",
                api_key_env="TEST_NVD_API_KEY_DOES_NOT_EXIST",
                delay=0.0,
                refresh=False,
                limit=None,
            )

            def fake_fetch(url: str, **_kwargs: object) -> bytes:
                if url.startswith(subject.NVD_CVE_API):
                    return json.dumps(nvd_payload).encode()
                commit_id = url.removesuffix(".patch").split("/")[-1]
                if "?id=" in url:
                    commit_id = url.rsplit("?id=", 1)[1]
                return (
                    f"From {commit_id} Mon Sep 17 00:00:00 2001\n"
                    "Subject: test patch\n\n---\n"
                ).encode()

            with patch.object(subject, "fetch_bytes", side_effect=fake_fetch):
                dataset = subject.build_dataset(args)

        self.assertEqual(dataset["summary"]["cve_commit_records"], 2)
        self.assertEqual(dataset["summary"]["non_cve_commit_records"], 1)
        self.assertEqual(dataset["summary"]["records_with_patch_text"], 3)
        self.assertEqual(dataset["summary"]["errors"], 0)
        self.assertEqual(
            {record["commit_id"] for record in dataset["records"]},
            {full_hash_1, full_hash_2, full_hash_3},
        )
        cve_records = [record for record in dataset["records"] if record.get("cve")]
        self.assertTrue(all(len(record["nvd_reference_urls"]) == 3 for record in cve_records))


if __name__ == "__main__":
    unittest.main()
