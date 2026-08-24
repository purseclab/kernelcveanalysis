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
