import argparse
import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import extract_fix_commits as subject


class CommitUrlTests(unittest.TestCase):
    def test_normalized_commit_tree_categories(self) -> None:
        self.assertEqual(subject.commit_tree_category("stable-linux"), "stable")
        self.assertEqual(subject.commit_tree_category("upstream-linux"), "mainline")
        self.assertEqual(subject.commit_tree_category("android-kernel"), "android")
        self.assertEqual(subject.commit_tree_category("upstream-project"), "other")

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

    def test_general_project_commit_requires_patch_tag_in_nvd(self) -> None:
        url = "https://github.com/example/not-linux/commit/35f56c554eb1"
        link = subject.parse_commit_url(url)
        self.assertIsNotNone(link)
        assert link is not None
        self.assertEqual(link.scope, "upstream-project")
        self.assertEqual(subject.links_from_nvd_references([{"url": url}]), [])
        accepted = subject.links_from_nvd_references(
            [{"url": url, "tags": ["Patch"]}]
        )
        self.assertEqual(len(accepted), 1)

    def test_legacy_kernel_cgit_url(self) -> None:
        commit_id = "2b17c400aeb44daf041627722581ade527bb3c1d"
        link = subject.parse_commit_url(
            "https://git.kernel.org/cgit/linux/kernel/git/torvalds/"
            f"linux.git/commit/?id={commit_id}"
        )
        self.assertIsNotNone(link)
        assert link is not None
        self.assertIn("/pub/scm/linux/kernel/git/torvalds/linux.git/patch/", link.patch_url)

    def test_duplicate_commit_id_keeps_first_provider_candidate(self) -> None:
        commit_id = "4" * 40
        stable = subject.parse_commit_url(
            f"https://git.kernel.org/stable/c/{commit_id}"
        )
        upstream = subject.parse_commit_url(
            f"https://github.com/torvalds/linux/commit/{commit_id}"
        )
        assert stable is not None and upstream is not None
        links = subject.deduplicate_links([stable, upstream])
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0].patch_url, stable.patch_url)

    def test_gitlab_and_android_gitiles_urls(self) -> None:
        gitlab = subject.parse_commit_url(
            "https://gitlab.freedesktop.org/polkit/polkit/-/commit/"
            "a2bf5c9c83b6ae46cbd5c779d3055bff81ded683"
        )
        android = subject.parse_commit_url(
            "https://android.googlesource.com/kernel/common/+/19bb609b45fb"
        )
        self.assertIsNotNone(gitlab)
        self.assertIsNotNone(android)
        assert gitlab is not None and android is not None
        self.assertTrue(gitlab.patch_url.endswith(".patch"))
        self.assertEqual(android.patch_encoding, "base64")


class ProviderTests(unittest.TestCase):
    def test_android_row_is_scoped_to_requested_cve(self) -> None:
        page = b'''<table><tr><td>CVE-2099-0001</td><td>
        <a href="https://android.googlesource.com/kernel/common/+/111111111111">fix</a>
        </td></tr><tr><td>CVE-2099-0002</td><td>
        <a href="https://android.googlesource.com/kernel/common/+/222222222222">other</a>
        </td></tr></table>'''
        references = [
            {"url": "https://source.android.com/docs/security/bulletin/2099-01-01"}
        ]
        with patch.object(subject, "fetch_cached", return_value=page):
            links = subject.discover_android_bulletin_links(
                "CVE-2099-0001",
                references,
                source_cache_dir=Path("/unused"),
                refresh=False,
            )
        self.assertEqual([link.commit_id for link in links], ["111111111111"])

    def test_kernelctf_metadata_patch_commit(self) -> None:
        commit_id = "3" * 40
        finding = {
            "cve": "CVE-2099-0003",
            "source_url": (
                "https://github.com/google/security-research/tree/master/"
                "pocs/linux/kernelctf/CVE-2099-0003_lts"
            ),
        }
        metadata = {
            "vulnerability": {
                "cve": finding["cve"],
                "patch_commit": (
                    "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/"
                    f"linux.git/commit/?id={commit_id}"
                ),
            }
        }
        with patch.object(subject, "fetch_cached", return_value=json.dumps(metadata).encode()):
            links = subject.discover_kernelctf_links(
                finding, source_cache_dir=Path("/unused"), refresh=False
            )
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0].provider, "kernelctf-metadata")

    def test_gitiles_patch_resolves_full_commit(self) -> None:
        short_id = "19bb609b45fb"
        full_id = short_id + "a" * (40 - len(short_id))
        link = subject.parse_commit_url(
            f"https://android.googlesource.com/kernel/common/+/{short_id}"
        )
        assert link is not None
        diff = b"diff --git a/a b/a\n--- a/a\n+++ b/a\n"

        def fake_fetch(url: str, **_kwargs: object) -> bytes:
            if url.endswith("?format=JSON"):
                return b")]}'\n" + json.dumps({"commit": full_id}).encode()
            return base64.b64encode(diff)

        with patch.object(subject, "fetch_cached", side_effect=fake_fetch):
            commit_id, patch_text = subject.fetch_patch(
                link, source_cache_dir=Path("/unused"), refresh=False
            )
        self.assertEqual(commit_id, full_id)
        self.assertTrue(patch_text.startswith("diff --git"))

    def test_dirty_pipe_advisory_requires_explicit_fixed_link(self) -> None:
        fix = "9d2231c5d74e13b2a0546fee6737ee4446017903"
        introduced = "f6dd975583bd8ce088400648fd9819e4691c8958"
        page = f'''<p><a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id={fix}">was fixed</a></p>
        <p><a href="https://github.com/torvalds/linux/commit/{introduced}">introduced</a></p>'''.encode()
        references = [{"url": "https://dirtypipe.cm4all.com/"}]
        with patch.object(subject, "fetch_cached", return_value=page):
            links = subject.discover_advisory_links(
                "CVE-2022-0847",
                references,
                source_cache_dir=Path("/unused"),
                refresh=False,
            )
        self.assertEqual([link.commit_id for link in links], [fix])

    def test_ubuntu_patch_uses_cherry_picked_commit_for_named_cve(self) -> None:
        commit_id = "7109704705a4d80516de00779bba38b3844bff13"
        page = (
            "<pre>(cherry picked from commit " + commit_id + ")\n"
            "CVE-2023-32629</pre>"
        ).encode()
        references = [
            {
                "url": "https://lists.ubuntu.com/archives/kernel-team/2099/patch.html",
                "tags": ["Mailing List", "Patch"],
            }
        ]
        with patch.object(subject, "fetch_cached", return_value=page):
            links = subject.discover_advisory_links(
                "CVE-2023-32629",
                references,
                source_cache_dir=Path("/unused"),
                refresh=False,
            )
        self.assertEqual([link.commit_id for link in links], [commit_id])
        self.assertEqual(links[0].provider, "ubuntu-kernel-mailing-list")

    def test_source_backed_cve_advisory_requires_mapped_fix_links(self) -> None:
        entry = subject.SOURCE_BACKED_CVE_ADVISORIES["CVE-2026-53613"]
        page = (
            "CVE-2026-53613 Patch details "
            + " ".join(entry["commit_urls"])
        ).encode()
        with patch.object(subject, "fetch_cached", return_value=page):
            links = subject.discover_source_backed_cve_links(
                "CVE-2026-53613",
                source_cache_dir=Path("/unused"),
                refresh=False,
            )
        self.assertEqual(
            [link.commit_id for link in links],
            [
                "0d3d55975aa3492c62fd345eac38f41cd166c0b0",
                "0b010025a0e429bc80355c94db86a843395d49e2",
            ],
        )
        self.assertTrue(all(link.provider == "source-backed-cve-advisory" for link in links))

        incomplete_page = (
            "CVE-2026-53613 Patch details " + entry["commit_urls"][0]
        ).encode()
        with patch.object(subject, "fetch_cached", return_value=incomplete_page):
            with self.assertRaises(subject.FetchError):
                subject.discover_source_backed_cve_links(
                    "CVE-2026-53613",
                    source_cache_dir=Path("/unused"),
                    refresh=False,
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
                source_cache_dir=root / "source-cache",
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
        self.assertEqual(dataset["schema_version"], 3)
        self.assertEqual(
            dataset["summary"]["by_commit_tree"],
            {"mainline": 2, "stable": 1},
        )
        self.assertEqual(
            {record["commit_tree"] for record in dataset["records"]},
            {"mainline", "stable"},
        )
        self.assertEqual(
            {record["commit_id"] for record in dataset["records"]},
            {full_hash_1, full_hash_2, full_hash_3},
        )
        cve_records = [record for record in dataset["records"] if record.get("cve")]
        self.assertTrue(all(len(record["nvd_reference_urls"]) == 3 for record in cve_records))


if __name__ == "__main__":
    unittest.main()
