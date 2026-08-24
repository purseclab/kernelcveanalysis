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
