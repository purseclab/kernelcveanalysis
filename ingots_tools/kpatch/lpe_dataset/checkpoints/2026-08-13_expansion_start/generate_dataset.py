#!/usr/bin/env python3
"""Generate a source-backed Linux LPE/RCE CVE dataset.

The input records below are intentionally small, hand-reviewed source
assertions.  The script supplies common fields for source families, merges
duplicate CVEs, and writes both the JSON dataset and a Markdown source audit.
It uses only the Python standard library.

This dataset records evidence that exploitation is possible; it is not an
exploit collection and deliberately does not copy exploit code.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
TODAY = date(2026, 8, 13).isoformat()
JSON_PATH = ROOT / "linux_lpe_rce_cves.json"
SOURCES_PATH = ROOT / "SOURCES_CHECKED.md"


SOURCE_CATALOG = [
    {
        "group": "Google kernelCTF",
        "url": "https://github.com/google/security-research/tree/master/pocs/linux/kernelctf",
        "checked": "enumerated",
        "result": "The directory index contains per-CVE exploit submissions with exploit artifacts, metadata, and vulnerability/exploit documentation. Spot checks included CVE-2023-32233, CVE-2024-0193, and CVE-2024-1085.",
    },
    {
        "group": "Google kernelCTF rules",
        "url": "https://google.github.io/security-research/kernelctf/rules.html",
        "checked": "read",
        "result": "Confirms kernelCTF is designed to demonstrate exploitation of Linux kernel 0-days and 1-days and requires a working exploit submission for accepted entries.",
    },
    {
        "group": "Google kernelCTF exploit documentation spot check",
        "url": "https://github.com/google/security-research/blob/master/pocs/linux/kernelctf/CVE-2024-1085_lts/docs/exploit.md",
        "checked": "read",
        "result": "Detailed exploit documentation ends in a root shell, directly supporting LPE classification.",
    },
    {
        "group": "Google kernelCTF exploit documentation spot check",
        "url": "https://github.com/google/security-research/blob/master/pocs/linux/kernelctf/CVE-2023-32233_mitigation/docs/exploit.md",
        "checked": "read",
        "result": "Documents UAF exploitation, RIP control, and the path to kernel code execution; directly supports LPE classification.",
    },
    {
        "group": "Google kernelCTF metadata spot check",
        "url": "https://raw.githubusercontent.com/google/security-research/master/pocs/linux/kernelctf/CVE-2024-1085_lts/metadata.json",
        "checked": "read",
        "result": "Records a CVE, vulnerable versions, required capabilities, and successful exploit stability (10/10 in the cited target).",
    },
    {
        "group": "Ubuntu Security Tracker",
        "url": "https://ubuntu.com/security/cves",
        "checked": "searched",
        "result": "Used to locate and verify Canonical descriptions for Linux-kernel LPE and arbitrary-code-execution cases.",
    },
    {
        "group": "Red Hat Product Security",
        "url": "https://access.redhat.com/security/vulnerabilities",
        "checked": "searched",
        "result": "Used for vendor advisories describing Linux-kernel privilege escalation and Linux userland LPE/RCE cases.",
    },
    {
        "group": "Qualys Threat Research",
        "url": "https://www.qualys.com/research/security-advisories",
        "checked": "searched",
        "result": "Used for detailed LPE/RCE research, including exploit development or independent root-validation claims.",
    },
    {
        "group": "Openwall oss-security",
        "url": "https://www.openwall.com/lists/oss-security/",
        "checked": "searched",
        "result": "Used for maintainer/researcher disclosure messages that explicitly state LPE or root escalation.",
    },
    {
        "group": "NVD / CVE records",
        "url": "https://nvd.nist.gov/",
        "checked": "searched",
        "result": "Used as corroboration and to locate public exploit/advisory references; NVD-only mentions were not generally promoted to high certainty.",
    },
    {
        "group": "Google Android Security Bulletins",
        "url": "https://source.android.com/docs/security/bulletin",
        "checked": "searched",
        "result": "Used for Android/Linux kernel entries whose official tables classify issues as EoP and state local escalation impact.",
    },
    {
        "group": "Google Android Security Bulletin, April 2023",
        "url": "https://source.android.com/docs/security/bulletin/2023-04-01",
        "checked": "read",
        "result": "Kernel table explicitly lists CVE-2022-4696 and CVE-2023-20941 as EoP with no additional execution privileges needed.",
    },
    {
        "group": "Google Android Security Bulletin, May 2023",
        "url": "https://source.android.com/docs/security/bulletin/2023-05-01",
        "checked": "read",
        "result": "Kernel table explicitly lists CVE-2023-21102 and CVE-2023-21106 as EoP, and a kernel-components table lists CVE-2023-0266 as EoP.",
    },
    {
        "group": "Google Android Security Bulletin, November 2024",
        "url": "https://source.android.com/docs/security/bulletin/2024-11-01",
        "checked": "read",
        "result": "Kernel table explicitly lists CVE-2024-36978 and CVE-2024-46740 as EoP with no additional execution privileges needed.",
    },
    {
        "group": "Red Hat Dirty COW advisory",
        "url": "https://access.redhat.com/security/vulnerabilities/DirtyCow",
        "checked": "read",
        "result": "Explicitly identifies CVE-2016-5195 as kernel local privilege escalation and says an exploit was found in the wild.",
    },
    {
        "group": "Red Hat Dirty Pipe advisory",
        "url": "https://access.redhat.com/security/vulnerabilities/RHSB-2022-002",
        "checked": "read",
        "result": "Explains that an unprivileged local user can write to read-only page-cache-backed files and escalate privileges.",
    },
    {
        "group": "CISA / US-CERT Dirty Pipe bulletin",
        "url": "https://content.govdelivery.com/accounts/USDHSCISA/bulletins/30e4b95",
        "checked": "read",
        "result": "Calls CVE-2022-0847 a Linux privilege-escalation vulnerability and says a local attacker could take control.",
    },
    {
        "group": "Qualys PwnKit advisory",
        "url": "https://www.openwall.com/lists/oss-security/2022/01/25/11",
        "checked": "read",
        "result": "Qualys disclosure explicitly calls CVE-2021-4034 local privilege escalation from any user to root.",
    },
    {
        "group": "Qualys Sequoia advisory",
        "url": "https://blog.qualys.com/vulnerabilities-threat-research/2021/07/20/sequoia-a-local-privilege-escalation-vulnerability-in-linuxs-filesystem-layer-cve-2021-33909",
        "checked": "read",
        "result": "Reports an independently developed exploit obtaining full root privileges on multiple default Linux installations.",
    },
    {
        "group": "Qualys Baron Samedit advisory",
        "url": "https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit",
        "checked": "read",
        "result": "Describes a local sudo vulnerability exploitable by an unprivileged local user; Qualys identified it as a privilege-escalation issue.",
    },
    {
        "group": "Qualys Linux PIE/stack corruption advisory",
        "url": "https://threatprotect.qualys.com/2017/09/26/linux-piestack-corruption-cve-20171000253/",
        "checked": "read",
        "result": "Explicitly calls CVE-2017-1000253 Linux local privilege escalation and describes exploitation through a SUID PIE binary.",
    },
    {
        "group": "ZDI eBPF advisory",
        "url": "https://www.thezdi.com/blog/2020/4/8/cve-2020-8835-linux-kernel-privilege-escalation-via-improper-ebpf-program-verification",
        "checked": "read",
        "result": "Detailed write-up describes an exploit using the Linux eBPF feature to achieve local privilege escalation.",
    },
    {
        "group": "Google Project Zero Netfilter write-up",
        "url": "https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html",
        "checked": "read",
        "result": "States that CVE-2021-22555 is powerful enough to bypass modern mitigations and achieve kernel code execution.",
    },
    {
        "group": "Alexander Popov Linux kernel research",
        "url": "https://a13xp0p0v.github.io/2021/02/09/CVE-2021-26708.html",
        "checked": "read",
        "result": "Detailed exploit research explicitly describes local privilege escalation on Fedora 33.",
    },
    {
        "group": "Theori CVE-2022-32250 research",
        "url": "https://theori.io/blog/linux-kernel-exploit-cve-2022-32250-with-mqueue",
        "checked": "read",
        "result": "Detailed Linux-kernel exploit write-up for the nftables UAF; the related CVE record explicitly describes root escalation.",
    },
    {
        "group": "Canonical Dirty Frag advisory",
        "url": "https://canonical.com/blog/dirty-frag-linux-vulnerability-fixes-available",
        "checked": "read",
        "result": "Explicitly identifies CVE-2026-43284 and CVE-2026-43500 as Linux-kernel LPEs and says the published exploit elevates a local user to root.",
    },
    {
        "group": "Canonical Fragnesia advisory",
        "url": "https://canonical.com/blog/fragnesia-linux-vulnerability-fixes-available",
        "checked": "read",
        "result": "Explicitly identifies CVE-2026-46300 as a Linux-kernel LPE affecting ESP/IPsec modules.",
    },
    {
        "group": "Canonical DirtyClone advisory",
        "url": "https://canonical.com/blog/dirtyclone-linux-vulnerability-fixes-available",
        "checked": "read",
        "result": "Says CVE-2026-43503 allows a local user to elevate to root and that the published exploit executes in a non-container deployment.",
    },
    {
        "group": "JFrog DirtyClone research",
        "url": "https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/",
        "checked": "read",
        "result": "Detailed research says JFrog developed a privilege-escalation exploit and demonstrated root access on Linux distributions.",
    },
    {
        "group": "Qualys ssh-keysign-pwn research",
        "url": "https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path",
        "checked": "read",
        "result": "Detailed Linux-kernel analysis says the flaw permits an unprivileged local user to execute arbitrary commands as root.",
    },
    {
        "group": "Canonical ssh-keysign-pwn advisory",
        "url": "https://ubuntu.com/blog/ssh-keysign-pwn-linux-vulnerability-fixes-available",
        "checked": "read",
        "result": "Corroborates public PoC availability for CVE-2026-46333, though the bulletin's direct impact is information disclosure rather than root escalation.",
    },
    {
        "group": "Canonical pedit COW advisory",
        "url": "https://ubuntu.com/blog/pedit-cow-linux-vulnerability-fixes-available",
        "checked": "read",
        "result": "Explicitly identifies CVE-2026-46331 as a Linux-kernel LPE and says a published exploit lets a local user elevate to root on non-container deployments.",
    },
    {
        "group": "CERT/CC Copy Fail advisory",
        "url": "https://kb.cert.org/vuls/id/260001",
        "checked": "read",
        "result": "Describes a public 732-byte PoC that modifies a setuid binary's page-cache contents to obtain root.",
    },
    {
        "group": "Qualys regreSSHion research",
        "url": "https://blog.qualys.com/vulnerabilities-threat-research/2024/07/01/regresshion-remote-unauthenticated-code-execution-vulnerability-in-openssh-server",
        "checked": "read",
        "result": "Detailed research identifies unauthenticated remote code execution as root on glibc-based Linux systems and says Qualys developed a working exploit.",
    },
    {
        "group": "CISA XZ alert",
        "url": "https://www.cisa.gov/news-events/alerts/2024/03/29/reported-supply-chain-compromise-affecting-xz-utils-data-compression-library-cve-2024-3094",
        "checked": "located",
        "result": "Authoritative alert for the Linux xz-utils supply-chain backdoor; included as RCE evidence rather than LPE evidence.",
    },
    {
        "group": "Apache HTTP Server security advisories",
        "url": "https://httpd.apache.org/security/vulnerabilities_24.html",
        "checked": "read",
        "result": "Official Apache page describes path traversal and conditional remote code execution for CVE-2021-42013.",
    },
    {
        "group": "Ubuntu cups-filters advisory",
        "url": "https://ubuntu.com/security/notices/USN-7043-1",
        "checked": "read",
        "result": "Describes the cups-filters chain in which a remote attacker can cause arbitrary code execution through crafted printer data.",
    },
]


# The selected slug is the most useful submission directory for each unique
# CVE.  The full index is the enumeration source; individual directories are
# linked in the generated records for auditability.
KERNELCTF_SUBMISSIONS = {
    "CVE-2023-0461": "CVE-2023-0461_mitigation",
    "CVE-2023-31436": "CVE-2023-31436_mitigation",
    "CVE-2023-32233": "CVE-2023-32233_mitigation",
    "CVE-2023-3390": "CVE-2023-3390_lts_cos_mitigation",
    "CVE-2023-3609": "CVE-2023-3609_cos_mitigation",
    "CVE-2023-3611": "CVE-2023-3611_lts_mitigation",
    "CVE-2023-3776": "CVE-2023-3776_lts",
    "CVE-2023-3777": "CVE-2023-3777_lts",
    "CVE-2023-4004": "CVE-2023-4004_lts_cos_mitigation",
    "CVE-2023-4015": "CVE-2023-4015_lts",
    "CVE-2023-4147": "CVE-2023-4147_lts_cos",
    "CVE-2023-4206": "CVE-2023-4206_lts_cos",
    "CVE-2023-4207": "CVE-2023-4207_lts_cos",
    "CVE-2023-4208": "CVE-2023-4208_lts_cos_mitigation",
    "CVE-2023-4244": "CVE-2023-4244_lts",
    "CVE-2023-4569": "CVE-2023-4569_lts",
    "CVE-2023-4622": "CVE-2023-4622_lts",
    "CVE-2023-4623": "CVE-2023-4623_lts_cos",
    "CVE-2023-4921": "CVE-2023-4921_lts_cos_mitigation",
    "CVE-2023-5197": "CVE-2023-5197_lts_cos",
    "CVE-2023-52433": "CVE-2023-52433_mitigation",
    "CVE-2023-52447": "CVE-2023-52447_cos",
    "CVE-2023-52620": "CVE-2023-52620_lts_cos_mitigation",
    "CVE-2023-52924": "CVE-2023-52924_mitigation",
    "CVE-2023-52925": "CVE-2023-52925_mitigation",
    "CVE-2023-52926": "CVE-2023-52926_lts",
    "CVE-2023-52927": "CVE-2023-52927_cos",
    "CVE-2023-5345": "CVE-2023-5345_lts_mitigation",
    "CVE-2023-5717": "CVE-2023-5717_mitigation",
    "CVE-2023-6111": "CVE-2023-6111_lts",
    "CVE-2023-6560": "CVE-2023-6560_mitigation",
    "CVE-2023-6817": "CVE-2023-6817_lts_cos",
    "CVE-2023-6931": "CVE-2023-6931_lts_cos",
    "CVE-2023-6932": "CVE-2023-6932_cos",
    "CVE-2024-0193": "CVE-2024-0193_lts",
    "CVE-2024-0582": "CVE-2024-0582_mitigation",
    "CVE-2024-1085": "CVE-2024-1085_lts",
    "CVE-2024-1086": "CVE-2024-1086_lts_mitigation",
    "CVE-2024-26581": "CVE-2024-26581_lts_cos_mitigation",
    "CVE-2024-26582": "CVE-2024-26582_lts",
    "CVE-2024-26585": "CVE-2024-26585_lts_cos",
    "CVE-2024-26642": "CVE-2024-26642_lts",
    "CVE-2024-26808": "CVE-2024-26808_cos",
    "CVE-2024-26809": "CVE-2024-26809_lts_cos",
    "CVE-2024-26824": "CVE-2024-26824_mitigation",
    "CVE-2024-26924": "CVE-2024-26924_cos",
    "CVE-2024-26925": "CVE-2024-26925_lts_cos",
    "CVE-2024-27397": "CVE-2024-27397_mitigation",
    "CVE-2024-36972": "CVE-2024-36972_lts_cos",
    "CVE-2024-36978": "CVE-2024-36978_cos",
    "CVE-2024-39503": "CVE-2024-39503_lts_cos",
    "CVE-2024-41009": "CVE-2024-41009_lts_cos",
    "CVE-2024-41010": "CVE-2024-41010_lts",
    "CVE-2024-45016": "CVE-2024-45016_lts_cos_mitigation",
    "CVE-2024-49861": "CVE-2024-49861_lts",
    "CVE-2024-50066": "CVE-2024-50066_mitigation",
    "CVE-2024-50164": "CVE-2024-50164_lts",
    "CVE-2024-53125": "CVE-2024-53125_lts",
    "CVE-2024-53141": "CVE-2024-53141_lts",
    "CVE-2024-53164": "CVE-2024-53164_lts_cos_mitigation",
    "CVE-2024-57947": "CVE-2024-57947_mitigation",
    "CVE-2024-58239": "CVE-2024-58239_mitigation",
    "CVE-2024-58240": "CVE-2024-58240_cos",
    "CVE-2025-21700": "CVE-2025-21700_lts_cos_mitigation",
    "CVE-2025-21701": "CVE-2025-21701_lts_cos",
    "CVE-2025-21702": "CVE-2025-21702_lts_cos",
    "CVE-2025-21756": "CVE-2025-21756_lts_cos",
    "CVE-2025-21836": "CVE-2025-21836_lts",
    "CVE-2025-37752": "CVE-2025-37752_cos",
    "CVE-2025-37756": "CVE-2025-37756_mitigation",
    "CVE-2025-38001": "CVE-2025-38001_lts_cos_mitigation",
    "CVE-2025-38083": "CVE-2025-38083_cos_mitigation",
    "CVE-2025-38350": "CVE-2025-38350_cos",
    "CVE-2025-38477": "CVE-2025-38477_cos",
    "CVE-2025-38500": "CVE-2025-38500_lts_cos_mitigation",
    "CVE-2025-38502": "CVE-2025-38502_lts",
    "CVE-2025-38616": "CVE-2025-38616_lts_cos_mitigation",
}


MANUAL_RECORDS = [
    {
        "cve": "CVE-2016-5195",
        "source_url": "https://access.redhat.com/security/vulnerabilities/DirtyCow",
        "summary": "Red Hat describes Dirty COW as a Linux-kernel local privilege-escalation flaw: an unprivileged local user could gain write access to read-only mappings, modify setuid files, and increase privileges; Red Hat also notes an exploit was found in the wild.",
        "evidence_group": "Red Hat advisory",
        "certainty": "high",
        "type": "lpe",
    },
    {
        "cve": "CVE-2017-1000253",
        "source_url": "https://threatprotect.qualys.com/2017/09/26/linux-piestack-corruption-cve-20171000253/",
        "summary": "Qualys explicitly calls this Linux PIE/stack corruption a local privilege-escalation vulnerability and describes an unprivileged user exploiting a SUID PIE binary.",
        "evidence_group": "Qualys",
        "certainty": "high",
        "type": "lpe",
    },
    {
        "cve": "CVE-2018-18955",
        "source_url": "https://github.com/scheatkode/CVE-2018-18955",
        "summary": "The public write-up and exploit repository describe a Linux local-root exploit caused by mishandling nested user namespaces and UID/GID mappings.",
        "evidence_group": "Public exploit write-up",
        "certainty": "high",
        "type": "lpe",
    },
    {
        "cve": "CVE-2019-13272",
        "source_url": "https://access.redhat.com/articles/4292201",
        "summary": "Red Hat says an unprivileged local user can exploit the Linux PTRACE_TRACEME flaw to escalate privileges; Ubuntu also records root access and CISA KEV inclusion.",
        "evidence_group": "Red Hat advisory",
        "certainty": "high",
        "type": "lpe",
        "additional_source_urls": ["https://ubuntu.com/security/CVE-2019-13272"],
    },
    {
        "cve": "CVE-2020-8835",
        "source_url": "https://www.thezdi.com/blog/2020/4/8/cve-2020-8835-linux-kernel-privilege-escalation-via-improper-ebpf-program-verification",
        "summary": "ZDI provides a detailed exploit write-up for improper eBPF verification and states that it achieves local privilege escalation; Ubuntu corroborates possible administrative privilege gain.",
        "evidence_group": "ZDI / Ubuntu",
        "certainty": "high",
        "type": "lpe",
        "additional_source_urls": ["https://ubuntu.com/security/CVE-2020-8835"],
    },
    {
        "cve": "CVE-2020-27786",
        "source_url": "https://ubuntu.com/security/CVE-2020-27786",
        "summary": "Ubuntu describes a Linux-kernel MIDI use-after-free whose controlled memory corruption could permit privilege escalation for a local account with device access.",
        "evidence_group": "Ubuntu advisory",
        "certainty": "medium",
        "type": "lpe",
    },
    {
        "cve": "CVE-2021-22555",
        "source_url": "https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html",
        "summary": "Google security research describes a Netfilter heap out-of-bounds write that is powerful enough for kernel code execution; the associated public exploit is a local privilege-escalation exploit.",
        "evidence_group": "Google Project Zero / Netfilter",
        "certainty": "high",
        "type": "lpe",
        "additional_source_urls": ["https://nvd.nist.gov/vuln/detail/CVE-2021-22555"],
    },
    {
        "cve": "CVE-2021-26708",
        "source_url": "https://a13xp0p0v.github.io/2021/02/09/CVE-2021-26708.html",
        "summary": "Alexander Popov's detailed exploit research demonstrates local privilege escalation in the Linux virtual-socket race-condition bugs on Fedora 33.",
        "evidence_group": "Detailed research blog",
        "certainty": "high",
        "type": "lpe",
    },
    {
        "cve": "CVE-2021-31440",
        "source_url": "https://www.thezdi.com/blog/2021/5/26/cve-2021-31440-an-incorrect-bounds-calculation-in-the-linux-kernel-ebpf-verifier",
        "summary": "ZDI documents an incorrect eBPF-verifier bounds calculation and its exploitability in the Linux kernel; the associated demonstration identifies local privilege escalation.",
        "evidence_group": "ZDI",
        "certainty": "high",
        "type": "lpe",
    },
    {
        "cve": "CVE-2021-33909",
        "source_url": "https://blog.qualys.com/vulnerabilities-threat-research/2021/07/20/sequoia-a-local-privilege-escalation-vulnerability-in-linuxs-filesystem-layer-cve-2021-33909",
        "summary": "Qualys reports an exploit for the Linux filesystem-layer flaw and says it obtained full root privileges on default Ubuntu, Debian, and Fedora installations.",
        "evidence_group": "Qualys Sequoia",
        "certainty": "high",
        "type": "lpe",
    },
    {
        "cve": "CVE-2021-3493",
        "source_url": "https://ubuntu.com/security/CVE-2021-3493",
        "summary": "Canonical states that Ubuntu's OverlayFS/user-namespace capability-validation flaw can be used by a local attacker to gain elevated privileges.",
        "evidence_group": "Ubuntu advisory",
        "certainty": "medium",
        "type": "lpe",
    },
    {
        "cve": "CVE-2021-3156",
        "source_url": "https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit",
        "summary": "Qualys describes Baron Samedit as a local sudo heap overflow exploitable by an unprivileged local user; its coordinated disclosures identify root privilege escalation.",
        "evidence_group": "Qualys",
        "certainty": "high",
        "type": "lpe",
    },
    {
        "cve": "CVE-2021-4034",
        "source_url": "https://www.openwall.com/lists/oss-security/2022/01/25/11",
        "summary": "Qualys's PwnKit advisory explicitly identifies a local privilege escalation from any user to root in polkit's SUID-root pkexec.",
        "evidence_group": "Qualys / oss-security",
        "certainty": "high",
        "type": "lpe",
    },
    {
        "cve": "CVE-2022-0185",
        "source_url": "https://www.openwall.com/lists/oss-security/2022/01/25/14",
        "summary": "The oss-security disclosure includes a detailed exploit/write-up and explicitly says the Linux-kernel heap overflow makes local privilege escalation from an unprivileged user to root possible.",
        "evidence_group": "oss-security detailed write-up",
        "certainty": "high",
        "type": "lpe",
    },
    {
        "cve": "CVE-2022-0492",
        "source_url": "https://www.openwall.com/lists/oss-security/2022/02/04/1",
        "summary": "The Linux kernel cgroups disclosure says release_agent could be used under certain circumstances to escalate privilege and bypass namespace isolation.",
        "evidence_group": "oss-security",
        "certainty": "medium",
        "type": "lpe",
    },
    {
        "cve": "CVE-2022-0847",
        "source_url": "https://access.redhat.com/security/vulnerabilities/RHSB-2022-002",
        "summary": "Red Hat explains that Dirty Pipe lets an unprivileged local user write to page-cache-backed read-only files and thereby escalate privileges; CISA separately says a local attacker could take control.",
        "evidence_group": "Red Hat / CISA Dirty Pipe",
        "certainty": "high",
        "type": "lpe",
        "additional_source_urls": ["https://content.govdelivery.com/accounts/USDHSCISA/bulletins/30e4b95"],
    },
    {
        "cve": "CVE-2022-1015",
        "source_url": "https://anatomic.rip/cve-2022-1015/",
        "summary": "A detailed analysis identifies the Linux Netfilter validation flaw and links a local privilege-escalation exploit for the CVE.",
        "evidence_group": "Detailed research blog",
        "certainty": "high",
        "type": "lpe",
    },
    {
        "cve": "CVE-2022-1729",
        "source_url": "https://www.openwall.com/lists/oss-security/2022/05/20/2",
        "summary": "The disclosure explicitly states that a race in the Linux perf subsystem leads to local privilege escalation to root.",
        "evidence_group": "oss-security",
        "certainty": "medium",
        "type": "lpe",
    },
    {
        "cve": "CVE-2022-1972",
        "source_url": "https://www.openwall.com/lists/oss-security/2022/06/02/1",
        "summary": "The disclosure states that the Linux Netfilter out-of-bounds write can be exploited for privilege escalation to root and reports confirmation on Ubuntu.",
        "evidence_group": "oss-security",
        "certainty": "high",
        "type": "lpe",
    },
    {
        "cve": "CVE-2022-23222",
        "source_url": "https://ubuntu.com/security/CVE-2022-23222",
        "summary": "Ubuntu describes an eBPF-verifier pointer-arithmetic flaw that allows local users to gain privileges or possibly execute arbitrary code; Red Hat's tracker labels it local privilege escalation.",
        "evidence_group": "Ubuntu / Red Hat",
        "certainty": "medium",
        "type": "lpe",
        "additional_source_urls": ["https://bugzilla.redhat.com/show_bug.cgi?id=2043520"],
    },
    {
        "cve": "CVE-2022-2586",
        "source_url": "https://www.openwall.com/lists/oss-security/2022/08/09/5",
        "summary": "Canonical's oss-security disclosure says the Netfilter cross-table reference UAF was found exploitable for local privilege escalation.",
        "evidence_group": "Canonical / oss-security",
        "certainty": "medium",
        "type": "lpe",
    },
    {
        "cve": "CVE-2022-32250",
        "source_url": "https://theori.io/blog/linux-kernel-exploit-cve-2022-32250-with-mqueue",
        "summary": "Theori published a detailed Linux-kernel exploit write-up for the nftables UAF; the CVE record states that a local user can escalate privileges to root.",
        "evidence_group": "Theori / NVD",
        "certainty": "high",
        "type": "lpe",
        "additional_source_urls": ["https://nvd.nist.gov/vuln/detail/CVE-2022-32250"],
    },
    {
        "cve": "CVE-2023-0179",
        "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-0179",
        "summary": "Public reporting and the CVE's Linux-kernel Netfilter description associate the stack underflow with arbitrary code execution and possible local root escalation; retained at medium certainty because the evidence is less detailed than the kernelCTF entries.",
        "evidence_group": "NVD / public security reporting",
        "certainty": "medium",
        "type": "lpe",
    },
    {
        "cve": "CVE-2023-0386",
        "source_url": "https://access.redhat.com/errata/RHSA-2023%3A1984",
        "summary": "Red Hat describes the OverlayFS/FUSE flaw as low-privileged-user privilege escalation; the CVE record explains that a local user can execute a capable file and escalate privileges.",
        "evidence_group": "Red Hat",
        "certainty": "medium",
        "type": "lpe",
        "additional_source_urls": ["https://www.cve.org/CVERecord?id=CVE-2023-0386"],
    },
    {
        "cve": "CVE-2023-2640",
        "source_url": "https://ubuntu.com/security/notices/USN-8297-1",
        "summary": "Canonical's Linux-kernel security notice says the Ubuntu OverlayFS permission-check flaw can let a local attacker gain elevated privileges.",
        "evidence_group": "Ubuntu OverlayFS advisories",
        "certainty": "medium",
        "type": "lpe",
    },
    {
        "cve": "CVE-2023-32629",
        "source_url": "https://ubuntu.com/security/CVE-2023-32629",
        "summary": "Ubuntu explicitly identifies this Ubuntu OverlayFS issue as a local privilege-escalation vulnerability and says a local attacker could gain elevated privileges.",
        "evidence_group": "Ubuntu",
        "certainty": "medium",
        "type": "lpe",
    },
    {
        "cve": "CVE-2023-4911",
        "source_url": "https://www.qualys.com/2023/10/03/cve-2023-4911/looney-tunables-local-privilege-escalation-glibc-ld-so.txt",
        "summary": "Qualys's Looney Tunables advisory identifies a glibc dynamic-loader local privilege escalation affecting major Linux distributions; the CVE record preserves the same advisory.",
        "evidence_group": "Qualys",
        "certainty": "high",
        "type": "lpe",
    },
    {
        "cve": "CVE-2024-1086",
        "source_url": "https://github.com/Notselwyn/CVE-2024-1086",
        "summary": "A public proof-of-concept repository describes a universal Linux-kernel nf_tables UAF-to-root exploit, reports broad distro coverage, and reports 99.4% success in KernelCTF images.",
        "evidence_group": "Public PoC / KernelCTF",
        "certainty": "high",
        "type": "lpe",
        "additional_source_urls": ["https://goldbergsecurity.co.uk/writeups/cve-2024-1086-nftables"],
    },
    {
        "cve": "CVE-2024-36972",
        "source_url": "https://starlabs.sg/advisories/24/24-36972/",
        "summary": "STAR Labs explicitly states that a local attacker can exploit the Linux unix_gc race/double-free to achieve local privilege escalation to root.",
        "evidence_group": "STAR Labs / KernelCTF",
        "certainty": "high",
        "type": "lpe",
    },
    {
        "cve": "CVE-2024-50264",
        "source_url": "https://swarm.ptsecurity.com/kernel-hack-drill-and-a-new-approach-to-exploiting-cve-2024-50264-in-the-linux-kernel/",
        "summary": "PT SWARM describes the Linux-kernel vsock UAF as a privilege-escalation case and documents exploit research; Ubuntu marks it high priority because local users can elevate privileges.",
        "evidence_group": "PT SWARM / Ubuntu",
        "certainty": "high",
        "type": "lpe",
        "additional_source_urls": ["https://ubuntu.com/security/CVE-2024-50264"],
    },
    {
        "cve": "CVE-2025-6018",
        "source_url": "https://www.suse.com/security/cve/CVE-2025-6018.html",
        "summary": "SUSE explicitly describes a Linux PAM/pam-config local privilege escalation from an unprivileged local user to an allow_active user and potentially full system control.",
        "evidence_group": "SUSE",
        "certainty": "medium",
        "type": "lpe",
    },
    {
        "cve": "CVE-2026-31431",
        "source_url": "https://kb.cert.org/vuls/id/260001",
        "summary": "CERT/CC describes Copy Fail as a Linux-kernel LPE and documents a public 732-byte PoC that modifies a setuid binary in page cache to obtain root; this is corroborated by Ubuntu and CISA/KEV reporting.",
        "evidence_group": "CERT/CC / Ubuntu / CISA",
        "certainty": "high",
        "type": "lpe",
        "additional_source_urls": ["https://ubuntu.com/blog/copy-fail-vulnerability-fixes-available", "https://access.redhat.com/security/vulnerabilities/RHSB-2026-002"],
    },
    {
        "cve": "CVE-2026-43284",
        "source_url": "https://canonical.com/blog/dirty-frag-linux-vulnerability-fixes-available",
        "summary": "Canonical explicitly identifies Dirty Frag as a Linux-kernel LPE and says the published exploit elevates a local user to root; container escape is an additional possible impact.",
        "evidence_group": "Canonical Dirty Frag",
        "certainty": "high",
        "type": "lpe",
    },
    {
        "cve": "CVE-2026-43500",
        "source_url": "https://canonical.com/blog/dirty-frag-linux-vulnerability-fixes-available",
        "summary": "Canonical groups CVE-2026-43500 with Dirty Frag, explicitly classifies it as a Linux-kernel LPE, and states that the published exploit elevates a local user to root.",
        "evidence_group": "Canonical Dirty Frag",
        "certainty": "high",
        "type": "lpe",
    },
    {
        "cve": "CVE-2026-46300",
        "source_url": "https://canonical.com/blog/fragnesia-linux-vulnerability-fixes-available",
        "summary": "Canonical explicitly identifies Fragnesia as a Linux-kernel local privilege escalation affecting ESP-in-TCP/IPsec components.",
        "evidence_group": "Canonical Fragnesia",
        "certainty": "medium",
        "type": "lpe",
    },
    {
        "cve": "CVE-2026-43503",
        "source_url": "https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/",
        "summary": "JFrog's detailed DirtyClone research says it developed a privilege-escalation exploit and demonstrated that an unprivileged local Linux user can gain root by manipulating page cache.",
        "evidence_group": "JFrog / Canonical DirtyClone",
        "certainty": "high",
        "type": "lpe",
        "additional_source_urls": ["https://canonical.com/blog/dirtyclone-linux-vulnerability-fixes-available"],
    },
    {
        "cve": "CVE-2026-46331",
        "source_url": "https://ubuntu.com/blog/pedit-cow-linux-vulnerability-fixes-available",
        "summary": "Canonical's security blog identifies pedit COW as a Linux-kernel local privilege-escalation vulnerability and says a published exploit lets a local user elevate to root on non-container deployments.",
        "evidence_group": "Canonical pedit COW",
        "certainty": "high",
        "type": "lpe",
    },
    {
        "cve": "CVE-2026-46333",
        "source_url": "https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path",
        "summary": "Qualys describes a Linux-kernel ptrace-path logic flaw permitting unprivileged local users to disclose sensitive files and execute arbitrary commands as root.",
        "evidence_group": "Qualys ssh-keysign-pwn",
        "certainty": "high",
        "type": "lpe",
    },
    {
        "cve": "CVE-2022-4696",
        "source_url": "https://source.android.com/docs/security/bulletin/2023-04-01",
        "summary": "The official Android Security Bulletin lists the upstream Linux-kernel io_uring issue as EoP and says the kernel issue could lead to local escalation of privilege with no additional execution privileges needed.",
        "evidence_group": "Google Android Security Bulletin",
        "certainty": "medium",
        "type": "lpe",
    },
    {
        "cve": "CVE-2023-20941",
        "source_url": "https://source.android.com/docs/security/bulletin/2023-04-01",
        "summary": "The official Android Security Bulletin lists the upstream Linux-kernel USB issue as EoP and says the kernel issue could lead to local escalation of privilege with no additional execution privileges needed.",
        "evidence_group": "Google Android Security Bulletin",
        "certainty": "medium",
        "type": "lpe",
    },
    {
        "cve": "CVE-2023-21102",
        "source_url": "https://source.android.com/docs/security/bulletin/2023-05-01",
        "summary": "The official Android Security Bulletin lists the upstream Linux-kernel EFI issue as EoP and states that the kernel vulnerability could lead to local escalation of privilege with no additional execution privileges needed.",
        "evidence_group": "Google Android Security Bulletin",
        "certainty": "medium",
        "type": "lpe",
    },
    {
        "cve": "CVE-2023-21106",
        "source_url": "https://source.android.com/docs/security/bulletin/2023-05-01",
        "summary": "The official Android Security Bulletin lists the upstream Linux-kernel GPU issue as EoP and states that the kernel vulnerability could lead to local escalation of privilege with no additional execution privileges needed.",
        "evidence_group": "Google Android Security Bulletin",
        "certainty": "medium",
        "type": "lpe",
    },
    {
        "cve": "CVE-2023-0266",
        "source_url": "https://source.android.com/docs/security/bulletin/2023-05-01",
        "summary": "The official Android Security Bulletin lists this upstream Linux-kernel issue as EoP in the kernel-components section, with system execution privileges needed.",
        "evidence_group": "Google Android Security Bulletin",
        "certainty": "medium",
        "type": "lpe",
    },
    {
        "cve": "CVE-2024-36978",
        "source_url": "https://source.android.com/docs/security/bulletin/2024-11-01",
        "summary": "The official Android Security Bulletin lists the upstream Linux-kernel networking issue as EoP and says the kernel issue could lead to local escalation of privilege with no additional execution privileges needed.",
        "evidence_group": "Google Android Security Bulletin",
        "certainty": "medium",
        "type": "lpe",
    },
    {
        "cve": "CVE-2024-46740",
        "source_url": "https://source.android.com/docs/security/bulletin/2024-11-01",
        "summary": "The official Android Security Bulletin lists the upstream Linux-kernel Binder issue as EoP and says the kernel issue could lead to local escalation of privilege with no additional execution privileges needed.",
        "evidence_group": "Google Android Security Bulletin",
        "certainty": "medium",
        "type": "lpe",
    },
    {
        "cve": "CVE-2024-6387",
        "source_url": "https://blog.qualys.com/vulnerabilities-threat-research/2024/07/01/regresshion-remote-unauthenticated-code-execution-vulnerability-in-openssh-server",
        "summary": "Qualys reports a signal-handler race in OpenSSH sshd enabling unauthenticated remote code execution as root on glibc-based Linux systems and says it developed a working exploit.",
        "evidence_group": "Qualys regreSSHion",
        "certainty": "high",
        "type": "rce",
    },
    {
        "cve": "CVE-2024-3094",
        "source_url": "https://www.cisa.gov/news-events/alerts/2024/03/29/reported-supply-chain-compromise-affecting-xz-utils-data-compression-library-cve-2024-3094",
        "summary": "CISA's alert documents the xz-utils supply-chain backdoor in Linux distributions; the backdoored OpenSSH path provides evidence of remote code execution capability rather than local privilege escalation.",
        "evidence_group": "CISA XZ Utils alert",
        "certainty": "high",
        "type": "rce",
    },
    {
        "cve": "CVE-2021-42013",
        "source_url": "https://httpd.apache.org/security/vulnerabilities_24.html",
        "summary": "The official Apache advisory describes path traversal in Apache HTTP Server 2.4.49/2.4.50 and says it can allow remote code execution when CGI scripts are enabled in the affected path.",
        "evidence_group": "Apache HTTP Server",
        "certainty": "medium",
        "type": "rce",
    },
    {
        "cve": "CVE-2024-47176",
        "source_url": "https://ubuntu.com/security/notices/USN-7043-1",
        "summary": "Ubuntu's cups-filters advisory describes a multi-component printing attack in which a remote attacker can cause arbitrary code execution through crafted printer data.",
        "evidence_group": "Ubuntu cups-filters",
        "certainty": "medium",
        "type": "rce",
    },
]


def kernelctf_records() -> list[dict[str, Any]]:
    base = "https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/"
    records = []
    for cve, slug in KERNELCTF_SUBMISSIONS.items():
        records.append(
            {
                "cve": cve,
                "source_url": base + slug,
                "summary": "Google's kernelCTF repository contains an accepted Linux-kernel exploit submission for this CVE, with an exploit artifact and submission documentation. A working kernel exploit is direct evidence of practical kernel code execution and therefore supports local privilege escalation classification in the kernelCTF target context.",
                "evidence_group": "Google kernelCTF",
                "certainty": "high",
                "type": "lpe",
            }
        )
    return records


def merge_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    certainty_rank = {"low": 0, "medium": 1, "high": 2}
    merged: dict[str, dict[str, Any]] = {}
    for record in records:
        cve = record["cve"]
        item = dict(record)
        item["checked_on"] = TODAY
        if cve not in merged:
            merged[cve] = item
            continue

        current = merged[cve]
        current_urls = current.setdefault("additional_source_urls", [])
        for url in [item["source_url"], *item.get("additional_source_urls", [])]:
            if url != current["source_url"] and url not in current_urls:
                current_urls.append(url)
        if certainty_rank[item["certainty"]] > certainty_rank[current["certainty"]]:
            current["certainty"] = item["certainty"]
        groups = [current.get("evidence_group"), item.get("evidence_group")]
        current["evidence_group"] = " / ".join(dict.fromkeys(g for g in groups if g))
        if current.get("type") != item.get("type"):
            current["type"] = " / ".join(dict.fromkeys([current.get("type"), item.get("type")]))
    return sorted(merged.values(), key=lambda record: record["cve"])


def make_dataset(records: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(record.get("type", "unspecified") for record in records)
    certainty = Counter(record["certainty"] for record in records)
    return {
        "schema_version": 1,
        "generated_on": TODAY,
        "scope": "Linux kernel and Linux software CVEs with public evidence that local privilege escalation or remote code execution is possible. Android records are included only when the Android bulletin identifies an upstream Linux-kernel or kernel-component EoP issue.",
        "methodology": {
            "certainty": {
                "high": "Working exploit, accepted kernelCTF exploit submission, or detailed research/advisory with explicit root/code-execution claim.",
                "medium": "Credible vendor or official bulletin explicitly classifies the issue as LPE/EoP/RCE but does not provide a detailed public exploit demonstration.",
                "low": "Reserved for weak or indirect mentions; no current records were promoted solely on that basis.",
            },
            "limitations": [
                "KernelCTF records are evidence of a working exploit submission in the named target context; they do not imply every distribution or configuration is exploitable.",
                "A CVE can require capabilities, namespaces, kernel configuration, a vulnerable package build, or a separate foothold; this dataset records evidence, not universal exploitability.",
                "KernelCTF submissions were enumerated from the repository index and spot-checked at the exploit/metadata level; the generated per-CVE links are the submission directories for follow-up review.",
                "RCE records describe Linux software or Linux distributions and are intentionally not relabeled as LPE.",
            ],
        },
        "summary": {
            "records": len(records),
            "by_type": dict(sorted(counts.items())),
            "by_certainty": dict(sorted(certainty.items())),
        },
        "records": records,
    }


def make_sources_markdown(dataset: dict[str, Any]) -> str:
    lines = [
        "# Sources checked",
        "",
        f"Research date: {TODAY}",
        "",
        "This file is generated by `generate_dataset.py`. It records the source families and pages checked during the sweep, including sources that were used for methodology or corroboration but did not produce a record.",
        "",
        "## Search approach",
        "",
        "I searched and spot-checked Google kernelCTF, Canonical/Ubuntu CVE pages and security notices, Red Hat advisories, Qualys research, oss-security disclosures, NVD/CVE records, Google Android Security Bulletins, and selected upstream project advisories. The target evidence was an explicit LPE/EoP/RCE statement, a detailed exploit write-up, a working PoC claim, or an accepted kernelCTF exploit submission.",
        "",
        "## Source catalog",
        "",
        "| Evidence group | URL | Check | Result |",
        "|---|---|---|---|",
    ]
    for source in SOURCE_CATALOG:
        result = source["result"].replace("|", "\\|")
        lines.append(f"| {source['group']} | <{source['url']}> | {source['checked']} | {result} |")

    evidence_urls: dict[str, dict[str, list[str]]] = {}
    for record in dataset["records"]:
        urls = [record["source_url"], *record.get("additional_source_urls", [])]
        for url in urls:
            entry = evidence_urls.setdefault(url, {"cves": [], "groups": []})
            if record["cve"] not in entry["cves"]:
                entry["cves"].append(record["cve"])
            group = record.get("evidence_group", "")
            if group and group not in entry["groups"]:
                entry["groups"].append(group)

    lines.extend(
        [
            "",
            "## Evidence URLs emitted into the JSON",
            "",
            "This inventory includes every primary and additional evidence URL in the generated JSON. KernelCTF per-CVE directory URLs are enumerated record links; the repository index, rules, and spot-checked submission pages establish how those links should be interpreted.",
            "",
            "| URL | CVE(s) | Evidence group(s) |",
            "|---|---|---|",
        ]
    )
    for url in sorted(evidence_urls):
        entry = evidence_urls[url]
        cves = ", ".join(entry["cves"])
        groups = ", ".join(entry["groups"]).replace("|", "\\|")
        lines.append(f"| <{url}> | {cves} | {groups} |")

    lines.extend(
        [
            "",
            "## Generated record coverage",
            "",
            f"The generated dataset contains **{dataset['summary']['records']} unique CVEs**: {dataset['summary']['by_type'].get('lpe', 0)} LPE, {dataset['summary']['by_type'].get('rce', 0)} RCE, and {dataset['summary']['by_certainty'].get('high', 0)} high-certainty records.",
            "",
            "Each JSON record has a primary `source_url`. When a CVE was independently supported by more than one source, the other URLs are retained under `additional_source_urls`.",
            "",
            "## Interpretation cautions",
            "",
            "- `high` does not mean universally exploitable; it means the evidence for exploitability is strong in at least one stated context.",
            "- Android Security Bulletin EoP entries are retained as medium certainty when the bulletin classifies the issue but does not publish a detailed exploit.",
            "- KernelCTF entries are deliberately numerous because the repository is a dataset of accepted Linux-kernel exploit submissions. The per-CVE links point to submission directories, while the index and rules pages establish the dataset's meaning.",
            "- No exploit source code is copied into this project.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    records = merge_records(kernelctf_records() + MANUAL_RECORDS)
    dataset = make_dataset(records)
    JSON_PATH.write_text(json.dumps(dataset, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    SOURCES_PATH.write_text(make_sources_markdown(dataset), encoding="utf-8")
    print(f"wrote {JSON_PATH} ({len(records)} records)")
    print(f"wrote {SOURCES_PATH} ({len(SOURCE_CATALOG)} source entries)")


if __name__ == "__main__":
    main()
