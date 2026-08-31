# Dataset Research and Maintenance Guide

## Purpose and scope

This directory contains a source-backed dataset of Linux local privilege
escalation (LPE) and remote code execution (RCE) findings, plus a derived
dataset of fixing commits and complete patch text.

Keep the project evidence-focused. It records that exploitation is possible
in a stated context; it does not claim universal exploitability, and it must
not copy exploit source code into this repository.

Include:

- Linux-kernel or Linux user-space CVEs with credible public evidence of LPE
  or RCE.
- Android findings only when an official Android bulletin identifies an
  upstream-kernel or kernel-component issue as local elevation of privilege.
- Findings without a CVE only in the separate non-CVE collection, after
  checking the CVE record, upstream history, and relevant trackers.

Do not include a finding merely because it has a high CVSS score, memory
corruption, an arbitrary read/write primitive, denial of service, or a patch.
The evidence must connect the issue to privilege escalation or remote code
execution. Do not invent individual entries from aggregate claims that do not
identify the findings.

## Research depth and non-execution policy

This is a dataset-curation project, not an exploit-validation or vulnerability-
analysis project. Do not compile, run, port, debug, or otherwise test exploits
or PoCs. Do not boot vulnerable kernels, reproduce crashes, weaponize a
primitive, or perform detailed source-code analysis to prove exploitability.

Use a quick plausibility check instead. Read the advisory, write-up, bulletin,
or PoC documentation far enough to confirm that it clearly concerns Linux LPE,
EoP, or RCE and that the claimed result and prerequisites are internally
consistent. A brief inspection of repository documentation, filenames, commit
messages, or obvious exploit structure is sufficient when the classification
is clear. Prefer authoritative statements and an additional corroborating
source over deeper independent analysis.

In this guide, “working exploit” or “demonstrated” means that the cited source
credibly reports or documents that result. It does not mean this project
independently executed or verified the exploit. If classification is not clear
after a quick check, leave the candidate out or retain it as an unresolved
research note; do not escalate into exploit development to decide.

## Files and sources of truth

| File | Role | Editing rule |
|---|---|---|
| `generate_dataset.py` | Primary source of hand-reviewed CVE records, kernelCTF mappings, non-CVE findings, and the source catalog. | Edit this to add or revise findings. |
| `linux_lpe_rce_cves.json` | Generated CVE dataset. | Never edit manually; regenerate it. |
| `non_cve_lpe_findings.json` | Generated non-CVE findings. | Never edit manually; edit `NON_CVE_FINDINGS` and regenerate. |
| `SOURCES_CHECKED.md` | Generated source audit, including sources that produced no records. | Never edit manually; edit `SOURCE_CATALOG` or record URLs and regenerate. |
| `extract_fix_commits.py` | Post-processing generator that discovers fixing commits and downloads patch text. | Add new commit-source adapters here, with narrow validation rules. |
| `linux_lpe_rce_fix_commits.json` | Generated one-record-per-finding/commit dataset. | Never edit manually; regenerate after the base datasets. |
| `test_extract_fix_commits.py` | Unit tests for commit URL parsing, source adapters, patch retrieval behavior, deduplication, and output fields. | Extend whenever parser/provider behavior changes. |
| `MISSING_FIX_COMMITS_AUDIT.md` | Manual investigation of the 25 unresolved CVEs as of 2026-08-21. | Treat it as research input, not as implemented parser behavior. Its newly identified sources and hashes are not yet all encoded in `extract_fix_commits.py`. |
| `RUNNING_LOG.md` | Append-only history of research sweeps, implementation changes, commands, counts, and limitations. | Append material work; do not rewrite history except to correct a clear error. |
| `checkpoints/` | Milestone snapshots used to preserve reproducibility. | Do not delete or rewrite existing checkpoints. |
| `.cache/nvd_cves/` | Cached NVD API responses. | Derived cache; reuse for resumable runs. |
| `.cache/fix_sources/` | Cached advisory, metadata, and patch responses. | Derived cache; reuse unless intentionally refreshing sources. |

This directory currently has no Git repository metadata. Use checkpoints and
the running log to preserve state, and do not assume `git diff` is available.

## Certainty gates

Assign certainty based on the evidence for exploitability, not the severity of
the underlying bug.

### High

Use `high` when at least one source provides strong, direct evidence such as:

- a source documenting a working exploit that obtains root, elevated
  privileges, or code execution;
- an accepted kernelCTF exploit submission;
- researcher or PoC documentation that clearly reports the LPE/RCE result;
- an authoritative project or vendor advisory that explicitly describes root
  or code execution and gives enough technical detail to make the claim
  unambiguous.

A strong demonstration may still require capabilities, namespaces, a second
bug, a particular kernel configuration, or a vulnerable service setup. Keep
`high` if the demonstrated claim is strong, but record every material
precondition in `caveat`.

### Medium

Use `medium` when a credible upstream project, vendor, CNA, or official
bulletin explicitly classifies the issue as LPE, EoP, or RCE, but no detailed
public exploitation demonstration was verified. Official Android bulletin EoP
rows normally fall here unless stronger evidence is available.

### Low

`low` is reserved for weak or indirect evidence. Prefer leaving a candidate
out and recording the source search in `SOURCE_CATALOG` instead of adding a
speculative low-certainty record. Never promote a record solely from an NVD
description, CVSS privileges/impact fields, a news article, or an unverified
PoC claim.

When sources disagree, preserve the disagreement in `caveat`, prefer the most
authoritative source for `source_url`, and choose the lower defensible
certainty. Rejected, disputed, or distribution-only CVEs must say so plainly.

## Type gates

- Use `lpe` when a local attacker can cross a privilege boundary. Say whether
  that means host root, kernel execution, container root, or only root inside a
  namespace.
- Use `rce` only when a remote input path can lead to code execution. A remote
  crash or memory-corruption condition without credible code-execution
  evidence is insufficient.
- Do not relabel an RCE as LPE merely because successful RCE would run with a
  privileged service account.
- If a demonstrated result requires a vulnerability chain, identify each
  stage and do not claim that either component is independently sufficient.

## Source selection and recording

Prefer sources in this order:

1. Upstream project advisories, commits, mailing-list disclosures, and Linux
   CVE announcements.
2. Accepted kernelCTF submissions and official Android Security Bulletins.
3. Distribution or vendor trackers such as Ubuntu, Red Hat, SUSE, Debian, and
   CERT/CC.
4. Detailed original researcher disclosures from established teams.
5. NVD/CVE records as corroboration and as indexes to primary material.

News reports, search-result snippets, exploit indexes, and mirrors are useful
for discovery but should not be the sole evidence when a primary source can be
found. Use archived or mirrored material when the original is unavailable,
and explain that limitation.

For each source checked, add a `SOURCE_CATALOG` entry when it represents a new
source family, a material targeted search, or an important negative result:

```python
{
    "group": "Short source name",
    "url": "https://authoritative.example/item",
    "checked": "read",  # read, searched, enumerated, or located
    "result": "What the source established, or why it produced no entry.",
}
```

Use the check labels consistently:

- `read`: the relevant page/message/content was inspected.
- `searched`: the source or tracker was queried for candidates.
- `enumerated`: a collection or index was systematically traversed.
- `located`: the source was identified but could not be fully read; never
  treat this as equivalent to verification.

## Adding a CVE record

Before adding a record:

1. Confirm the CVE identity and affected Linux component. Check for rejected,
   disputed, reserved, duplicate, or alias status.
2. Establish LPE/EoP or RCE impact from the source itself with a quick
   plausibility check. Separate a source-documented exploit path from a
   theoretical primitive, without executing the exploit or undertaking a
   detailed independent code analysis.
3. Record prerequisites: required capabilities, user namespaces, kernel
   configuration, service exposure, package version, architecture, container
   boundary, race reliability, and required chain components.
4. Seek independent corroboration, especially when the primary source is a
   PoC repository or researcher blog.
5. Add the record to `MANUAL_RECORDS`, or add an accepted standard kernelCTF
   submission to `KERNELCTF_SUBMISSIONS`.

A normal manual record is:

```python
{
    "cve": "CVE-YYYY-NNNN",
    "source_url": "https://best-direct-evidence.example/",
    "summary": "Who established what impact, by what broad path, and in what context.",
    "evidence_group": "Upstream project / researcher",
    "certainty": "high",  # or medium
    "caveat": "Optional but required for material scope or prerequisites.",
    "additional_source_urls": [
        "https://independent-corroboration.example/",
        "https://upstream.example/commit-or-advisory",
    ],
    "type": "lpe",  # or rce
}
```

Field rules:

- `source_url`: the strongest direct evidence, not automatically the NVD page.
- `summary`: a compact evidence statement. Attribute the claim and describe
  the demonstrated impact; do not copy vendor prose wholesale.
- `evidence_group`: a stable, human-readable source family label.
- `certainty`: exactly `high`, `medium`, or exceptionally `low`, using the
  gates above.
- `type`: `lpe` or `rce`.
- `caveat`: required when scope could otherwise be overstated. Include
  capability requirements, namespace-only impact, conditional chains,
  disputed scope, and evidence limitations.
- `additional_source_urls`: only relevant corroboration, upstream fixes, and
  authoritative trackers. Avoid generic home pages and duplicate URL forms.
- `checked_on`: generated by the script; do not add it manually.

`merge_records()` merges duplicate CVE assertions, keeps the first primary
source, accumulates additional URLs/evidence groups/caveats, and raises the
certainty to the highest supplied value. Review merged output carefully: the
mechanical highest-certainty rule does not resolve contradictory evidence for
you.

`TODAY` in `generate_dataset.py` is intentionally fixed. Do not bump it merely
to add one record because that rewrites `checked_on` for every existing record
and falsely implies a complete re-review. Change it only for a documented full
dataset sweep, or first refactor the generator to support per-record review
dates.

## Adding a non-CVE finding

Use `NON_CVE_FINDINGS` only after failing to locate a CVE assignment in
appropriate CVE/NVD, upstream, and vendor sources. Use a stable identifier,
set `cve` to `None`, explain the unsuccessful CVE search in `caveat`, and
include a verified full commit hash and commit URL when one exists.

If a CVE is assigned later, migrate the finding into the CVE records rather
than retaining two identities for the same issue.

## Fixing-commit research

Run `extract_fix_commits.py` only after regenerating the base datasets. It
currently discovers commits through:

- direct NVD references, including supported current and legacy kernel.org,
  GitHub, GitLab, and Android Gitiles forms;
- official Android bulletin rows;
- kernelCTF `metadata.json`;
- explicitly verified Linux-CVE alias announcements;
- narrowly parsed researcher/Ubuntu advisory patterns already implemented;
- explicit commit data in non-CVE findings.

Do not assume a CVE in `cves_without_fix_commits` has no fix. That field means
the implemented providers found no defensible commit. Consult
`MISSING_FIX_COMMITS_AUDIT.md`; most of its additional results were found
manually and still require parser implementations and tests.

When adding a provider:

1. Require CVE-scoped evidence. Incidental mention of a CVE is not enough.
2. Prefer explicit language such as “fixes,” “fixed by,” or an authoritative
   patch field. Do not scrape every hash from an advisory.
3. For mailing-list patches, match the submitted patch to the merged commit by
   normalized subject and preferably Git patch-id/diff, not subject alone.
4. For pull requests, confirm that the PR was merged and retain every commit
   that belongs to the security fix, excluding unrelated commits.
5. Treat tag comparisons and fixed-version history as inferred unless an
   advisory explicitly binds the resulting hashes to the CVE. Preserve that
   confidence/provenance rather than presenting inference as exact mapping.
6. Resolve rejected/duplicate CVEs to their canonical identifier without
   hiding the alias relationship.
7. Preserve tree identity. `commit_tree` is `stable`, `mainline`, `android`,
   or `other`; `commit_scope` carries finer provenance. Mainline and stable
   backport hashes are not interchangeable.
8. Emit one record for every unique finding/commit association. Multi-part
   fixes and stable backports must remain separate records with separate patch
   text.
9. Fetch and validate the patch. For mail-style patches, the `From` header
   must resolve to the expected full commit ID.
10. Add focused unit fixtures for successful extraction, false-positive
    rejection, deduplication, scope/tree classification, and failure behavior.

Never paste manually researched hashes directly into
`linux_lpe_rce_fix_commits.json`. Encode a reproducible provider or explicit,
source-backed mapping in Python, test it, and regenerate the output.

## Regeneration and validation

The project uses only the Python standard library.

Regenerate the base datasets:

```sh
python3 generate_dataset.py
```

`generate_dataset.py` does not parse command-line options. Even
`python3 generate_dataset.py --help` regenerates all three outputs.

Run local validation:

```sh
python3 -m py_compile generate_dataset.py extract_fix_commits.py test_extract_fix_commits.py
python3 -m unittest -v test_extract_fix_commits.py
```

Regenerate fixing commits using caches where available:

```sh
python3 extract_fix_commits.py --strict
```

Without `NVD_API_KEY`, uncached NVD requests are paced at six seconds each;
with a key, the default is 0.6 seconds. Set `NVD_API_KEY` in the environment,
not in source files or logs. `--refresh` ignores all relevant caches and can
make the run substantially longer. `--limit` still writes the selected output
path, so use a temporary output for experiments:

```sh
python3 extract_fix_commits.py --limit 3 --output /tmp/lpe-fix-smoke.json --strict
```

After generation, verify at minimum:

- JSON parsing succeeds.
- CVE identifiers and non-CVE identifiers are unique in their base datasets.
- Required fields are present and certainty/type values use the allowed
  vocabulary.
- Summary totals match the actual records.
- Every fixing-commit record has `commit_id`, `commit_url`, `patch_url`,
  `patch_text`, `commit_provider`, `commit_scope`, and `commit_tree`.
- Every `(CVE or identifier, commit_id)` association is unique.
- Every `commit_tree` is one of `stable`, `mainline`, `android`, or `other`.
- A strict full run reports zero errors before replacing a known-good derived
  dataset. If a remote source is temporarily unavailable, preserve the prior
  artifact and log the failed run rather than silently accepting data loss.

As of the last full generated baseline, the base dataset has 165 CVEs and one
non-CVE finding. The fixing-commit dataset has 503 records, all with patch
text, covering 140 CVEs and leaving 25 unresolved by implemented providers.
These are comparison baselines, not hard-coded acceptance criteria for future
research.

## Research-session checklist

For each material sweep or parser change:

1. Read the latest `RUNNING_LOG.md` entries and inspect current artifacts.
2. Create `checkpoints/YYYY-MM-DD_short_description/` before risky edits or a
   long refresh. Include `RUNNING_LOG.md` and the scripts/docs being changed;
   keep the checkpoint reasonably small.
3. Search current authoritative sources. Record the query scope, pages read,
   negative results, access failures, aliases, and ambiguous evidence. Keep
   review at dataset-triage depth; do not run PoCs or begin exploit analysis.
4. Update source assertions in Python, not generated JSON/Markdown.
5. Regenerate in dependency order: base datasets first, fixing commits second.
6. Run compilation, unit tests, and structural/count validation.
7. Inspect record diffs or normalized summaries. Because Git may be absent,
   compare against the pre-edit checkpoint with `cmp`, `diff`, or hashes.
8. Append `RUNNING_LOG.md` with the goal, sources, decisions, commands, result
   counts, failures, caveats, and checkpoint path.
9. Create a final milestone checkpoint containing the changed source files,
   generated artifacts when reasonably sized, tests, and running log.

Favor conservative inclusion, explicit provenance, and reproducible parsing.
When evidence is uncertain, document the uncertainty instead of smoothing it
away.
