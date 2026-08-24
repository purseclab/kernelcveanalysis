# Running Log

## 2026-08-13 — Initial dataset research setup

- Goal: assemble a source-backed list of Linux CVEs with credible evidence of local privilege escalation (LPE) or remote code execution (RCE), without collecting exploit code.
- Checkpoint: `checkpoints/2026-08-13_initial_setup/`
- Workspace: fresh directory; no Git metadata or prior artifacts were present.
- Planned artifacts: source records, generated JSON, source-audit Markdown, and a Python generator/normalizer.
- Next step: query authoritative advisories, KernelCTF, Android security bulletins, vendor advisories, and detailed security writeups; record checked sources and classify evidence strength.

## 2026-08-13 — Source sweep and dataset generation

- Evidence sources checked: Google kernelCTF and its rules/submission documentation; Ubuntu/Canonical, Red Hat, Qualys, oss-security, NVD/CVE, Google Android Security Bulletins, CERT/CC, CISA, Apache, SUSE, ZDI, Theori, STAR Labs, JFrog, and selected Linux security research blogs.
- Dataset method: enumerate the kernelCTF Linux submission index, retain one auditable submission-directory URL per unique CVE, merge manually reviewed vendor/research records, preserve corroborating URLs, and classify evidence as high/medium/low. No exploit code is copied into the artifacts.
- Generated artifacts: `linux_lpe_rce_cves.json`, `SOURCES_CHECKED.md`, and `generate_dataset.py`.
- Result: 123 unique CVEs; 119 LPE, 4 RCE; 103 high-certainty and 20 medium-certainty records; 133 unique evidence URLs across primary and additional URL fields.
- Validation: JSON parser succeeded; all records have CVE, source URL, summary, certainty, and checked date; no duplicate CVEs; types are limited to LPE/RCE; generated summary matches record counts; generator compilation succeeded.
- Note: the direct CISA XZ alert URL was located but returned HTTP 403 to the browsing fetcher; it remains recorded as an authoritative source URL, while the source audit labels it `located` rather than `read`. The Canonical pedit COW advisory was directly verified and classified high because it states that a published exploit can elevate a local user to root in the stated deployment context.
- Checkpoint: `checkpoints/2026-08-13_dataset_generated/`
- Final status: artifacts are preserved in the checkpoint and ready for handoff; interpretation caveats are included in the JSON methodology and source audit.

## 2026-08-13 — Expansion sweep

- Scope: searched for additional Linux LPE/RCE evidence beyond the initial set, prioritizing older oss-security disclosures, detailed exploit research, vendor advisories, Qualys research, current Ubuntu notices, Google Android Security Bulletins, and 2026 kernelCTF-style submissions.
- New evidence families: futex, iptables compat, n_hdlc, XFRM, POSIX message queues, V4L2, CAN, io_uring, cls_route, needrestart, sudo, libblockdev/udisks, pam_namespace, HFS+, open-vm-tools, Dropbear, snap-confine, Android upstream-kernel EoP bulletins, GhostLock, Epollution, and Bad Epoll.
- Dataset method: added manually reviewed records to `generate_dataset.py`; retained primary and corroborating URLs; preserved conditions such as required capabilities, namespace scope, chained escalation stages, Android-only scope, and the disputed upstream CNA scope for CVE-2025-0927.
- Generated result: 162 unique CVEs; 158 LPE, 4 RCE; 128 high-certainty and 34 medium-certainty records; 179 unique evidence URLs across primary and additional URL fields.
- Validation: `python3 -m py_compile generate_dataset.py` succeeded; generator completed; JSON parsing and schema checks succeeded; no duplicate CVEs; all records have required evidence fields; generated summary matches record counts.
- Caveats: Android bulletin records are retained at medium certainty when the bulletin explicitly classifies local EoP but does not publish a detailed exploit. CVE-2025-6018/CVE-2025-6019 are a conditional chain, CVE-2025-0927 is distro-specific and scope-disputed, CVE-2026-15226 is scoped to a snap container namespace, and vendor-only cases such as CVE-2025-41244/CVE-2025-14282 remain medium.
- Checkpoint: `checkpoints/2026-08-13_expansion_generated/`

## 2026-08-13 — Optional caveat field

- Schema update: added an optional per-record `caveat` string to preserve prerequisites, deployment scope, conditional exploit chains, disputed CVE scope, and evidence limitations without overloading the primary evidence summary.
- Examples populated: CVE-2025-0927, CVE-2025-6018/CVE-2025-6019, CVE-2025-41244, CVE-2025-14282, CVE-2026-15226, CVE-2026-46242, and selected capability/combined-vulnerability cases.
- Result: 162 records remain unchanged in count; 12 records include `caveat`, while 150 omit the optional field.
- Validation: generator compilation, regeneration, JSON parsing, uniqueness, required-field, and optional-field checks all passed.
- Checkpoint: `checkpoints/2026-08-13_caveat_field/`

## 2026-08-16 — AI-lab and AI-assisted research expansion

- Scope: searched official OpenAI, Anthropic, and Google security-research announcements plus the named technical write-ups, upstream Linux commits, NVD/vendor records, and public tracker material needed to determine whether AI-reported findings were individually identifiable and relevant to Linux LPE/RCE.
- Strong aggregate evidence checked: OpenAI's Patch the Planet post says GPT-5.5-Cyber scanned more than 30 million Linux-kernel lines and produced 24 local-privilege-escalation exploits. The post does not publish the individual Linux CVE identifiers, so the aggregate claim is recorded in `SOURCES_CHECKED.md` but is not expanded into invented CVE records.
- Anthropic Mythos findings: added CVE-2024-47711 and CVE-2024-53057 as high-certainty LPE records because the public report describes a root-producing Linux kernel exploit chain and identifies the relevant vulnerability classes. Added the syzbot-reported ipset bug fixed by commit `35f56c554eb1b56b77b3cf197a6b00922d49033d` to the separate no-CVE artifact because no CVE assignment was located in the checked references.
- OpenAI-assisted finding: added CVE-2025-37899 as a high-certainty RCE record. Sean Heelan's public write-up says OpenAI o3 discovered the Linux ksmbd use-after-free and explains how it can provide kernel-context arbitrary code execution; NVD and the stable kernel fix are retained as corroboration.
- Google Big Sleep and other AI-lab material: checked official announcements and public tracker examples. The identifiable examples located were SQLite, FFmpeg, or PCRE2 issues rather than Linux LPE/RCE CVEs; aggregate or closed-source claims were not promoted into the CVE dataset.
- Generated result: 165 unique CVEs; 160 LPE, 5 RCE; 131 high-certainty and 34 medium-certainty records. The separate `non_cve_lpe_findings.json` contains 1 high-certainty Linux LPE finding.
- Artifacts updated: `generate_dataset.py`, `linux_lpe_rce_cves.json`, `non_cve_lpe_findings.json`, and `SOURCES_CHECKED.md`. The generator retains the prior fixed `TODAY` value so existing record dates remain reproducible; this pass is logged under 2026-08-16.
- Validation: generator execution, `python3 -m py_compile generate_dataset.py`, JSON parsing, uniqueness, required-field, type, and summary-count checks passed.
- Checkpoint: `checkpoints/2026-08-16_ai_research_generated/`

## 2026-08-17 — NVD Linux fixing-commit enrichment

- Goal: add a separate, reproducible post-generation pass that queries the NVD CVE API for every generated CVE, inspects all NVD reference URLs for upstream Linux Git commits, and records each fixing commit with its full patch text; include the generated non-CVE findings in the same output format.
- Pre-edit checkpoint: `checkpoints/2026-08-17_before_fix_commit_enrichment/`.
- Implementation: added `extract_fix_commits.py`, using only the Python standard library. It supports `NVD_API_KEY`, NVD-aware default pacing (6 seconds without a key, 0.6 with one), retries, per-CVE response caching, atomic output writes, `--refresh`, `--limit`, and `--strict`. Recognized links include compact `git.kernel.org/stable/c/<hash>`, full kernel.org cgit commit URLs, and GitHub Linux commit URLs.
- Output schema: `linux_lpe_rce_fix_commits.json` has one record per finding/commit association, preserving the source finding fields and adding `source_kind`, `commit_id`, `commit_url`, `patch_url`, and `patch_text`. CVE records additionally retain the complete NVD reference URL list and selected reference tags. CVEs with no recognized Linux commit link and all fetch failures are reported at top level rather than silently discarded.
- Full run: `python3 extract_fix_commits.py --strict` with no `NVD_API_KEY`; 165 CVE responses were cached under `.cache/nvd_cves/` and the existing non-CVE finding was processed through the same patch-fetch path.
- Result: 446 commit records containing 446 complete patches and zero errors. This comprises 445 CVE/commit records across 114 unique CVEs plus 1 non-CVE/commit record. NVD exposed no recognized upstream Linux commit URL for 51 input CVEs; those identifiers are retained in `cves_without_linux_commit_urls`.
- Validation: `python3 -m unittest -v test_extract_fix_commits.py` passed 4 tests; `python3 -m py_compile generate_dataset.py extract_fix_commits.py test_extract_fix_commits.py` succeeded; JSON parsing, summary counts, non-empty commit/patch fields, and uniqueness of finding/commit pairs all passed.
- Final checkpoint: `checkpoints/2026-08-17_fix_commit_enrichment_generated/`.

## 2026-08-19 — linux-cve-announce missing-patch research

- Goal: determine whether the upstream `linux-cve-announce` archive supplies fixing commits for the 51 CVEs in `linux_lpe_rce_fix_commits.json` whose NVD records had no recognized upstream Linux Git commit URL.
- Checkpoints: `checkpoints/2026-08-19_before_linux_cve_announce_research/` and `checkpoints/2026-08-19_linux_cve_announce_research/`.
- Sources/method: checked the Linux kernel CVE process documentation and exact-searched every missing identifier in the `linux-cve-announce.vger.kernel.org` public-inbox mirror at `https://yhbt.net/lore/linux-cve-announce/`. The canonical lore endpoint returned HTTP 403 to automated access. Search hits were read as raw messages and accepted only when the announcement explicitly stated that its fix addressed the missing CVE; incidental mentions were rejected.
- Result: 2 of 51 missing CVEs have usable alias-style announcements, providing 11 verified patch commits. CVE-2022-2586 is explicitly fixed by the announcement assigned CVE-2022-50213, which lists 7 stable commits: `77d3b5038b7462318f5183e2ad704b01d57215a2`, `fab2f61cc3b0e441b1749f017cfee75f9bbaded7`, `1a4b18b1ff11ba26f9a852019d674fde9d1d1cff`, `faafd9286f1355c76fe9ac3021c280297213330e`, `f4fa03410f7c5f5bd8f90e9c11e9a8c4b526ff6f`, `0d07039397527361850c554c192e749cfc879ea9`, and `470ee20e069a6d05ae549f7d0ef2bdbcee6a81b2`. CVE-2023-0179 is explicitly addressed by the announcement assigned CVE-2023-53033, which lists 4: `550efeff989b041f3746118c0ddd863c39ddc1aa`, `a8acfe2c6fb99f9375a9325807a179cd8c32e6e3`, `76ef74d4a379faa451003621a84e3498044e7aa3`, and `696e1a48b1a1b01edad542a1ef293665864a4dd0`.
- Non-results: 47 identifiers had no archive search result. Two additional identifiers had archive mentions but no applicable patch set: CVE-2021-4034 is cited only as motivation in the separate CVE-2022-49264 kernel hardening announcement, and CVE-2025-0927 was originally announced as unfixed and was later rejected as no longer valid.
- Validation: fetched all 11 listed cgit patch endpoints successfully; every response began with a `From <expected-40-character-commit-id>` patch header.
- Interpretation: the archive is authoritative for CVEs assigned by the Linux kernel CVE team, not a general patch source for user-space, Android-specific, or distribution-only CVEs. A missing archive result therefore does not prove that no fix exists elsewhere.

## 2026-08-19 — Missing-patch root causes and alternate sources

- Goal: explain why the 51 records were classified as having no Linux Git fixing URL and identify additional commit/patch sources.
- Checkpoints: `checkpoints/2026-08-19_before_missing_patch_source_research/` and `checkpoints/2026-08-19_missing_patch_source_research/`.
- Classification: 23/51 are user-space or product CVEs, 9/51 are Android kernel records, 2/51 are Ubuntu-specific kernel CVEs, 14/51 are legacy externally assigned upstream-kernel CVEs, 2/51 are aliases recovered from `linux-cve-announce`, and 1/51 (CVE-2025-0927) was rejected. Therefore most cannot be expected to have a `torvalds/linux` or kernel.org stable commit in NVD.
- Extractor limitation: `extract_fix_commits.py` only accepts GitHub repositories named `linux`/`linux-stable` and current-form kernel.org cgit URLs under `/pub/scm/linux/kernel/git/`. It does not accept old `git.kernel.org/cgit/...` or `/linus/<hash>` links, GitLab, general user-space GitHub repositories, Android Gitiles, Patchwork, or inline mailing-list patches, and it does not crawl referenced advisory pages.
- Existing NVD-reference evidence: 10 missing CVEs already have direct commit URLs in their cached NVD references when non-kernel repositories and old kernel.org URL forms are allowed. Examples include CVE-2021-32606 (`2b17c400...`), CVE-2022-23222 (`64620e0a...`), CVE-2022-41222 (`97113eb3...`), CVE-2021-4034 (polkit GitLab `a2bf5c9c...`), the needrestart CVEs, and CVE-2024-47176. NVD also links patch-only pages for older kernel CVEs and Patchwork submissions.
- Android evidence: official Android Security Bulletin rows expose 21 `android.googlesource.com/kernel/common` commits across 8 missing CVEs: CVE-2022-20421/20422/20423, CVE-2023-20937/20938/20941, and CVE-2023-21102/21106. A Gitiles `^!/?format=TEXT` endpoint was tested successfully and returned the patch diff.
- kernelCTF evidence: the existing Google kernelCTF `metadata.json` files directly provide `vulnerability.patch_commit` for four missing CVEs: CVE-2023-4004 (`87b5a5c2...`), CVE-2023-4569 (`90e5b346...`), CVE-2023-6560 (`820d070f...`), and CVE-2024-0193 (`7315dc1e...`). The current extractor reads neither the record's kernelCTF source directory nor its metadata.
- Distribution and patch-archive evidence: Ubuntu's CVE page and Debian Security Tracker identify Dirty Pipe's upstream fix `9d2231c5d74e13b2a0546fee6737ee4446017903`. Ubuntu kernel-team messages contain inline patches for CVE-2023-2640/32629, including upstream cherry-pick `7109704705a4d80516de00779bba38b3844bff13` for CVE-2023-32629. Patchwork `/mbox/` endpoints were verified to return complete mail patches for the Netfilter and io_uring cases.
- Recoverability estimate: at least 25 of the 51 already have direct commit IDs through the inspected alternate routes (including the 2 Linux-CVE aliases), before resolving patch-only mailing-list submissions to their merged commits. Additional legacy cases likely can be recovered by matching patch subjects or stable patch IDs.
- Recommended provider order: direct commit URL expansion; Linux-CVE aliases; Android bulletin/Gitiles; kernelCTF metadata; Ubuntu/Debian/Red Hat/SUSE trackers; Patchwork/lore mbox; upstream GitHub/GitLab security advisories and tag comparisons. Preserve whether a result is upstream, stable backport, Android, distribution, or downstream-vendor rather than treating all hashes as interchangeable.
