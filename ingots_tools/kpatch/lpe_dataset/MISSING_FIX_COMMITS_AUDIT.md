# Audit of CVEs Without Extracted Fix Commits

Checked 2026-08-21 against the 25 entries in
`linux_lpe_rce_fix_commits.json.cves_without_linux_commit_urls`.

## Result

The field name is misleading for these records: it means that no supported
commit URL was discovered by the extractor, not that no fix exists.

- 19 CVEs have a specific commit or commit series supported by an upstream,
  vendor, disclosure, or patch-to-merge match.
- 3 more have strong release/tag-history candidates, but the advisory does not
  directly bind every candidate hash to the CVE.
- CVE-2023-2640 has complete Ubuntu patch mail and fixed package versions, but
  the applicable commit hash varies by Ubuntu kernel tree and is not present in
  the referenced mail.
- CVE-2024-3094 was remediated by removing the compromised XZ releases and
  returning to known-good code; it has no single conventional fixing commit.
- CVE-2025-0927 was rejected by the Linux CNA, so no canonical CVE fix should
  be expected even though Ubuntu shipped downstream package changes.

## Per-CVE Findings

| CVE | Finding | Why the current extractor misses it |
|---|---|---|
| CVE-2015-3245 | Historical upstream libuser changeset `d73aa2a5a9ce5bdd349dff46e3e4885f2b194a95` ([Ubuntu tracker](https://ubuntu.com/security/CVE-2015-3245)). | NVD has vendor advisories; Ubuntu names a retired fedorahosted changeset, whose original patch endpoint no longer works. |
| CVE-2015-3246 | Same libuser changeset `d73aa2a5a9ce5bdd349dff46e3e4885f2b194a95` ([Ubuntu tracker](https://ubuntu.com/security/CVE-2015-3246)). | Same retired-forge problem; one changeset fixes both related CVEs. |
| CVE-2017-1000253 | Linux mainline [`a87938b2e246b81b4fb713edb371a9fa3c5c3c86`](https://github.com/torvalds/linux/commit/a87938b2e246b81b4fb713edb371a9fa3c5c3c86). | The hash appears in CVE/NVD description prose rather than a reference URL. |
| CVE-2017-2636 | Linux mainline [`82f2341c94d270421f383641b7cd670e474db56b`](https://github.com/torvalds/linux/commit/82f2341c94d270421f383641b7cd670e474db56b), `tty: n_hdlc: get rid of racy n_hdlc.tbuf`. | NVD links the disclosure and patch discussion, not the merged Git commit; resolving it requires subject/diff matching. |
| CVE-2019-18683 | Linux mainline [`6dcd5d7a7a29c1e4b8016a06aed78cd650cd8c27`](https://github.com/torvalds/linux/commit/6dcd5d7a7a29c1e4b8016a06aed78cd650cd8c27), `media: vivid: Fix wrong locking...`. | NVD links a lore patch email. The extractor does not match an emailed patch to its merged commit. |
| CVE-2021-3156 | sudo fix series [`1f863857...`](https://github.com/sudo-project/sudo/commit/1f8638577d0c80a4ff864a2aad80a0d95488e9a8), [`b301b46b...`](https://github.com/sudo-project/sudo/commit/b301b46b79c6e2a76d530fa36d05992e74952ee8), and [`c4d38408...`](https://github.com/sudo-project/sudo/commit/c4d384082fdbc8406cf19e08d05db4cded920a55). | NVD points to advisories/releases; the upstream patch set is identified in vendor tracking rather than a direct NVD Git URL. |
| CVE-2021-42013 | Apache SVN revisions r1893977, r1893980, and r1893982, mirrored as Git commits [`c3a95d75...`](https://github.com/apache/httpd/commit/c3a95d75da7815b1bcebd99e499573688c936297), [`dc55176e...`](https://github.com/apache/httpd/commit/dc55176ebcf16cbaea2b32f1b7fc6dd450a84666), and [`8c9b41ff...`](https://github.com/apache/httpd/commit/8c9b41ffb34b101f9d6d3e838766e71bccf974e0). | Apache's authoritative advisory uses SVN revision identifiers. The NVD item tagged `Patch` is not the code fix. |
| CVE-2022-1015 | Linux mainline [`6e1acfa387b9ff82cfc7db8cc3b6959221a95851`](https://github.com/torvalds/linux/commit/6e1acfa387b9ff82cfc7db8cc3b6959221a95851). | Red Hat/Ubuntu tracking identifies the upstream patch; NVD does not expose it as a supported commit URL. |
| CVE-2022-1786 | Linux 5.10 stable [`29f077d070519a88a793fbc70f1e6484dc6d9e35`](https://github.com/gregkh/linux/commit/29f077d070519a88a793fbc70f1e6484dc6d9e35), explicitly linked by the [oss-security disclosure](https://www.openwall.com/lists/oss-security/2022/05/24/4). | The finding's primary disclosure contains the commit, but the extractor only mines NVD plus its currently implemented providers. |
| CVE-2022-1972 | Rejected duplicate of CVE-2022-2078; the canonical issue is fixed by Linux [`fecf31ee395b0295f2d7260aa29946b7605f7c85`](https://github.com/torvalds/linux/commit/fecf31ee395b0295f2d7260aa29946b7605f7c85). | The rejected NVD record has no useful references and the extractor does not resolve general CVE aliases/duplicates. |
| CVE-2022-2588 | Linux mainline [`9ad36309e2719a884f946678e0296be10f0bb4c1`](https://github.com/torvalds/linux/commit/9ad36309e2719a884f946678e0296be10f0bb4c1), `net_sched: cls_route: remove from list when handle is 0`. | NVD links the submitted mailing-list patch, requiring subject/diff matching to the merged hash. |
| CVE-2023-2640 | Ubuntu-specific three-patch series, including [reverting the unsafe xattr change](https://lists.ubuntu.com/archives/kernel-team/2023-July/140923.html), plus fixed Ubuntu package versions. | This is an Ubuntu SAUCE regression, not a mainline Linux defect. The mail contains patch text but no final applied hash, and Ubuntu maintains many release/flavour trees with different commit IDs. |
| CVE-2023-4911 | glibc main fix [`1056e5b4...`](https://github.com/bminor/glibc/commit/1056e5b4c3f2d90ed2b4a55f96add28da2f4c8fa), with branch backports `dcc367f1...`, `c84018a0...`, `22955ad8...`, `b4e23c75...`, and `750a45a7...`. | The hashes are in glibc advisory/repository metadata, not direct NVD references; sourceware/cgit and advisory metadata are unsupported. |
| CVE-2024-10224 | Module::ScanDeps 1.36 security changes [`30d43e2d...`](https://github.com/rschupp/Module-ScanDeps/commit/30d43e2df13cfca74833b3aa8a641679427c5cd8) and [`e1f2e14c...`](https://github.com/rschupp/Module-ScanDeps/commit/e1f2e14c5bee4d78c94b0cddf120e81af104f6dd). | The advisory names patched version 1.36; the hashes require comparing the 1.35 and 1.36 tags. This is strong release-history attribution, not an explicit NVD mapping. |
| CVE-2024-3094 | No canonical fix commit. The response was to remove malicious XZ 5.6.0/5.6.1 artifacts and revert/use known-good 5.4.x code ([CISA alert](https://www.cisa.gov/news-events/alerts/2024/03/29/reported-supply-chain-compromise-affecting-xz-utils-data-compression-library-cve-2024-3094)). | The payload was introduced through compromised release tarballs/build machinery and does not map cleanly to one normal upstream Git fixing commit. |
| CVE-2025-0927 | Rejected by the Linux CNA ([Ubuntu tracker](https://ubuntu.com/security/CVE-2025-0927)); Ubuntu package versions nevertheless contain downstream changes. | Rejected identifiers should be represented as such, not forced to have a canonical upstream security commit. Mapping Ubuntu versions would require package/tree-specific tracking. |
| CVE-2025-14282 | Dropbear PR #391 commits [`e0251be2...`](https://github.com/mkj/dropbear/commit/e0251be2354e1a5c6eccfc2cf4b64243625dafcc), `b47fe5df...`, `73e4e70e...`, `a4043dac...`, plus PR #394 follow-up `d1937316...`. | NVD references pull requests, but the extractor does not expand a PR to all merged commits. |
| CVE-2025-32463 | sudo [`fffcc07c536d8eb69df4fb2d24a094982b09086c`](https://github.com/sudo-project/sudo/commit/fffcc07c536d8eb69df4fb2d24a094982b09086c), whose message explicitly says it fixes the CVE; `7a6ee32a...` is related deprecation hardening. | NVD links the advisory/fixed release rather than the underlying commits. |
| CVE-2025-41244 | open-vm-tools [`3ab0685c1cf7981c84898d546a73d6db6dcd3823`](https://github.com/vmware/open-vm-tools/commit/3ab0685c1cf7981c84898d546a73d6db6dcd3823), whose message names the CVE. | The disclosure points to a patch branch/tree; the parser handles commit URLs but not tree views or patch bundles. |
| CVE-2025-6018 | SUSE pam-config [`2b6e7eab27ccf84da4c71e48bce3c6d7e874c30d`](https://github.com/SUSE/pam-config/commit/2b6e7eab27ccf84da4c71e48bce3c6d7e874c30d), `Don't add pam_env twice`, matches the vendor-described root cause and timing. | NVD has vendor/disclosure pages only. This is a strong repository-history inference, but the commit itself does not name the CVE. |
| CVE-2025-6019 | libblockdev [`46b54414f66e965e3c37f8f51e621f96258ae22e`](https://github.com/storaged-project/libblockdev/commit/46b54414f66e965e3c37f8f51e621f96258ae22e), `Don't allow suid and dev set on fs resize`. | NVD exposes advisories and fixed versions; resolving the hash requires project/tag or downstream-backport metadata. |
| CVE-2025-6020 | linux-pam 1.7.1 series [`475bd60c...`](https://github.com/linux-pam/linux-pam/commit/475bd60c552b98c7eddb3270b0b4196847c0072e), [`592d84e1...`](https://github.com/linux-pam/linux-pam/commit/592d84e1265d04c3104acee815a503856db503a1), and [`976c2007...`](https://github.com/linux-pam/linux-pam/commit/976c20079358d133514568fc7fd95c02df8b5773). | The advisory says to upgrade to 1.7.1; the security series must be recovered from the release/tag history, so attribution should retain an inferred confidence marker. |
| CVE-2026-15226 | snapd [`f32fe221c5bcccac3a328efb89fe06286405385e`](https://github.com/canonical/snapd/commit/f32fe221c5bcccac3a328efb89fe06286405385e), `snap-confine: harden seccomp template`. | The very new NVD/Canonical record gives product/version remediation but no Git URL. |
| CVE-2026-3888 | snapd [`d3e2c3d85f9a0571fabfc079f89d0135a07afd67`](https://github.com/canonical/snapd/commit/d3e2c3d85f9a0571fabfc079f89d0135a07afd67), with CVE-named refinement [`526c05267090156118ef0ba3017c031afc7aa789`](https://github.com/canonical/snapd/commit/526c05267090156118ef0ba3017c031afc7aa789). | NVD/Canonical name fixed snapd versions; the extractor does not map versions/changelogs to commits. |
| CVE-2026-8933 | snapd [`2cafc7a46ba77ad92725263c590470a63a7c8c6b`](https://github.com/canonical/snapd/commit/2cafc7a46ba77ad92725263c590470a63a7c8c6b), `use O_NOFOLLOW when creating replica of base rootfs`. | The record only exposes fixed version 2.76.1; mapping that release to its security commit requires changelog/tag analysis. |

## Parser Gaps Exposed by the Audit

The next regeneration pass should distinguish `no_supported_source` from
`no_fix_commit_exists`, and add providers for:

1. Commit hashes in CVE description text, not only reference URLs.
2. The finding's own `source_url` and `additional_urls`.
3. Rejected/duplicate CVE aliases.
4. Pull-request expansion with merge-state and commit-list validation.
5. Mailing-list patch-to-merged-commit matching by subject and patch-id.
6. Fixed-release/tag comparisons, marked as inferred unless an advisory binds
   the commits explicitly.
7. SVN-to-Git revision mapping and retired-forge preservation.
8. Ubuntu package/source-tree commits, keeping release and flavour identity.
9. Explicit terminal states such as `rejected`, `release_remediation`, and
   `patch_available_commit_unresolved`.

The script should also retain attribution confidence per CVE/commit pair;
otherwise exact CVE-tagged commits and tag-diff candidates appear equally
authoritative.
