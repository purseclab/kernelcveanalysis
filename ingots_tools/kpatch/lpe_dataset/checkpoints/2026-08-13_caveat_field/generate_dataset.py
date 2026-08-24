#!/usr/bin/env python3
"""Generate a source-backed Linux LPE/RCE CVE dataset.

The input records below are intentionally small, hand-reviewed source
assertions.  The script supplies common fields for source families, merges
duplicate CVEs, and writes both the JSON dataset and a Markdown source audit.
Records may also carry an optional `caveat` field for scope, prerequisite,
conditional-chain, or evidence-quality notes.
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
    {
        "group": "Openwall Linux futex disclosure",
        "url": "https://www.openwall.com/lists/oss-security/2014/06/05/22",
        "checked": "read",
        "result": "Solar Designer's disclosure explicitly titles CVE-2014-3153 a Linux-kernel futex local privilege-escalation vulnerability and describes unprivileged ring-0 control.",
    },
    {
        "group": "Red Hat userhelper advisory",
        "url": "https://access.redhat.com/solutions/1539123",
        "checked": "read",
        "result": "Red Hat says CVE-2015-3245 and CVE-2015-3246 can be combined for local privilege escalation to root on affected RHEL systems.",
    },
    {
        "group": "Openwall iptables compat disclosure",
        "url": "https://www.openwall.com/lists/oss-security/2016/06/24/5",
        "checked": "read",
        "result": "The disclosure describes CVE-2016-4997 as kernel memory corruption that can lead to privilege elevation or kernel code execution for an unprivileged namespaced user.",
    },
    {
        "group": "Alexander Popov CVE-2017-2636 research",
        "url": "https://a13x0p0v.github.io/2017/03/24/CVE-2017-2636.html",
        "checked": "read",
        "result": "The detailed write-up documents a working exploit that obtains root privileges from the Linux n_hdlc double-free.",
    },
    {
        "group": "Red Hat CVE-2017-2636 advisory",
        "url": "https://access.redhat.com/security/vulnerabilities/CVE-2017-2636",
        "checked": "located",
        "result": "Vendor page corroborates the affected Linux kernel driver and vulnerability scope.",
    },
    {
        "group": "Openwall XFRM disclosure",
        "url": "https://openwall.com/lists/oss-security/2017/03/29/2",
        "checked": "read",
        "result": "The disclosure describes out-of-bounds XFRM access leading to local privilege escalation when the attacker has the relevant namespace capability.",
    },
    {
        "group": "Lexfo POSIX mq_notify research",
        "url": "https://blog.lexfo.fr/cve-2017-11176-linux-kernel-exploitation-part4.html",
        "checked": "read",
        "result": "The final part of a detailed exploit series demonstrates arbitrary kernel code execution and obtaining root credentials from CVE-2017-11176.",
    },
    {
        "group": "Alexander Popov V4L2 research",
        "url": "https://a13x0p0v.github.io/2020/02/15/CVE-2019-18683.html",
        "checked": "read",
        "result": "The detailed research documents a V4L2 vivid-driver exploit that gains local privilege escalation and bypasses common kernel mitigations.",
    },
    {
        "group": "Openwall CAN ISOTP disclosure",
        "url": "https://www.openwall.com/lists/oss-security/2021/05/12/1",
        "checked": "read",
        "result": "The disclosure includes an exploit log ending with uid=0(root) for the Linux CAN ISOTP race/UAF and identifies CVE-2021-32606.",
    },
    {
        "group": "Openwall CAN BCM disclosure",
        "url": "https://www.openwall.com/lists/oss-security/2021/06/19/1",
        "checked": "read",
        "result": "The disclosure calls CVE-2021-3609 a proven Linux local privilege-escalation-to-root issue and links the proof of concept.",
    },
    {
        "group": "Openwall io_uring disclosure",
        "url": "https://www.openwall.com/lists/oss-security/2021/09/18/2",
        "checked": "read",
        "result": "The disclosure says the unprivileged io_uring bug is straightforward to exploit for local privilege escalation and records the patch/CVE process.",
    },
    {
        "group": "Openwall io_uring invalid-free disclosure",
        "url": "https://www.openwall.com/lists/oss-security/2022/05/24/4",
        "checked": "read",
        "result": "The disclosure reports a proof of concept demonstrating local privilege escalation for CVE-2022-1786.",
    },
    {
        "group": "Openwall cls_route disclosure",
        "url": "https://www.openwall.com/lists/oss-security/2022/08/09/6",
        "checked": "read",
        "result": "The Canonical/Ubuntu disclosure says the cls_route use-after-free was found exploitable for local privilege escalation, subject to namespace capabilities.",
    },
    {
        "group": "Qualys needrestart research",
        "url": "https://blog.qualys.com/vulnerabilities-threat-research/2024/11/19/qualys-tru-uncovers-five-local-privilege-escalation-vulnerabilities-in-needrestart",
        "checked": "read",
        "result": "Qualys reports five needrestart/Module::ScanDeps vulnerabilities, says functional exploits were developed, and describes unprivileged users reaching full root.",
    },
    {
        "group": "Canonical needrestart advisory",
        "url": "https://canonical.com/blog/needrestart-local-privilege-escalation",
        "checked": "read",
        "result": "Canonical provides package-level confirmation and remediation context for the needrestart local privilege-escalation disclosures.",
    },
    {
        "group": "Openwall sudo chroot disclosure",
        "url": "https://www.openwall.com/lists/oss-security/2025/06/30/3",
        "checked": "read",
        "result": "The sudo maintainer describes CVE-2025-32463 as allowing an attacker to load a shared library and run arbitrary commands as root through sudo's chroot option.",
    },
    {
        "group": "Openwall libblockdev disclosure",
        "url": "https://www.openwall.com/lists/oss-security/2025/06/17/4",
        "checked": "read",
        "result": "The detailed Qualys disclosure describes CVE-2025-6018/CVE-2025-6019 and their chain from an unprivileged session to root via udisks and polkit.",
    },
    {
        "group": "Openwall pam_namespace disclosure",
        "url": "https://www.openwall.com/lists/oss-security/2025/06/17/1",
        "checked": "read",
        "result": "The disclosure describes CVE-2025-6020 and notes a proof of concept demonstrating local privilege escalation to root through pam_namespace path handling.",
    },
    {
        "group": "SSD HFS+ research",
        "url": "https://ssd-disclosure.com/ssd-advisory-linux-kernel-hfsplus-slab-out-of-bounds-write/",
        "checked": "read",
        "result": "SSD documents a detailed Ubuntu-specific HFS+ exploit achieving local privilege escalation, while noting the upstream CNA disputed the CVE scope because of CAP_SYS_ADMIN filesystem-image requirements.",
    },
    {
        "group": "Openwall open-vm-tools disclosure",
        "url": "https://www.openwall.com/lists/oss-security/2025/09/29/10",
        "checked": "read",
        "result": "VMware's advisory states that a non-admin guest user can exploit CVE-2025-41244 to escalate to root on the same virtual machine.",
    },
    {
        "group": "Openwall Dropbear disclosure",
        "url": "https://www.openwall.com/lists/oss-security/2025/12/16/2",
        "checked": "read",
        "result": "The Dropbear release notice describes CVE-2025-14282 as privilege escalation via Unix socket forwarding that can allow arbitrary programs to run as root under the stated conditions.",
    },
    {
        "group": "Qualys snap-confine research",
        "url": "https://blog.qualys.com/vulnerabilities-threat-research/2026/03/17/cve-2026-3888-important-snap-flaw-enables-local-privilege-escalation-to-root",
        "checked": "read",
        "result": "Qualys reports a working time-based exploit that turns an unprivileged Ubuntu Desktop user into root through snap-confine.",
    },
    {
        "group": "Ubuntu snap security notices",
        "url": "https://ubuntu.com/security/notices/USN-8579-1",
        "checked": "read",
        "result": "Ubuntu's notice documents CVE-2026-8933 and CVE-2026-15226 as local snap confinement/privilege issues and provides fixed package versions.",
    },
    {
        "group": "Ubuntu snap CVE pages",
        "url": "https://ubuntu.com/security/CVE-2026-8933",
        "checked": "read",
        "result": "Ubuntu states that a local unprivileged attacker can bypass intended snap-confine restrictions and execute arbitrary code, with successful exploitation reaching root.",
    },
    {
        "group": "Ubuntu snap CVE pages",
        "url": "https://ubuntu.com/security/CVE-2026-15226",
        "checked": "read",
        "result": "Ubuntu describes a local confinement/namespace escalation in which a confined snap can create and execute setuid binaries; the impact is scoped to the container namespace rather than established host root.",
    },
    {
        "group": "Ubuntu snap CVE pages",
        "url": "https://ubuntu.com/security/CVE-2026-3888",
        "checked": "read",
        "result": "Ubuntu's CVE page corroborates the snap-confine local root issue and affected release scope.",
    },
    {
        "group": "kernelCTF Bad Epoll submission",
        "url": "https://github.com/J-jaeyoung/security-research/blob/submit-cve-2026-46242/pocs/linux/kernelctf/CVE-2026-46242_lts_cos/docs/exploit.md",
        "checked": "read",
        "result": "The kernelCTF exploit write-up documents a reliable Linux root shell from CVE-2026-46242.",
    },
    {
        "group": "Openwall Bad Epoll disclosure",
        "url": "https://www.openwall.com/lists/oss-security/2026/07/08/13",
        "checked": "read",
        "result": "Openwall reproduces the Bad Epoll kernelCTF submission and its claim that an unprivileged process becomes root.",
    },
    {
        "group": "NebuSec GhostLock research",
        "url": "https://nebusec.ai/research/ionstack-part-2/",
        "checked": "read",
        "result": "NebuSec documents a stable local privilege-escalation/container-escape exploit for CVE-2026-43499 that reaches root without special privileges or configuration.",
    },
    {
        "group": "Openwall GhostLock disclosure",
        "url": "https://www.openwall.com/lists/oss-security/2026/07/08/12",
        "checked": "read",
        "result": "Openwall provides independent disclosure context for the GhostLock Linux-kernel vulnerability.",
    },
    {
        "group": "kernelCTF Epollution submission",
        "url": "https://github.com/2045castor/security-research/blob/submit_final/pocs/linux/kernelctf/CVE-2026-43074_lts/docs/exploit.md",
        "checked": "read",
        "result": "The kernelCTF exploit documentation describes a data-only privilege-escalation chain that clears effective-UID credentials and yields a root helper.",
    },
    {
        "group": "Google Android Security Bulletin October 2022",
        "url": "https://source.android.com/docs/security/bulletin/2022-10-01?hl=en",
        "checked": "read",
        "result": "The official Android bulletin classifies several upstream-kernel vulnerabilities as local elevation of privilege, with affected components and prerequisite privilege information.",
    },
    {
        "group": "Google Android Security Bulletin February 2023",
        "url": "https://source.android.com/docs/security/bulletin/2023-02-01?hl=en",
        "checked": "read",
        "result": "The official Android bulletin lists multiple upstream-kernel local elevation-of-privilege issues and states that no additional execution privileges are needed for the listed impacts.",
    },
    {
        "group": "Google Android Security Bulletin May 2024",
        "url": "https://source.android.com/docs/security/bulletin/2024-05-01?hl=en",
        "checked": "read",
        "result": "The official Android bulletin classifies CVE-2023-4622 as an upstream-kernel local elevation-of-privilege issue.",
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
        "caveat": "This is the first stage of the published CVE-2025-6018/CVE-2025-6019 chain; by itself it obtains the allow_active context, while the second CVE provides the root-capable action.",
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
    {
        "cve": "CVE-2014-3153",
        "source_url": "https://www.openwall.com/lists/oss-security/2014/06/05/22",
        "summary": "Solar Designer's oss-security disclosure explicitly identifies the Linux futex flaw as a local privilege-escalation vulnerability and states that an unprivileged user can obtain ring-0 control.",
        "evidence_group": "Openwall / Solar Designer",
        "certainty": "high",
        "type": "lpe",
    },
    {
        "cve": "CVE-2015-3245",
        "source_url": "https://access.redhat.com/solutions/1539123",
        "summary": "Red Hat states that the userhelper vulnerability can be combined with the related libuser issue for local privilege escalation to root on affected RHEL systems.",
        "evidence_group": "Red Hat advisory",
        "certainty": "medium",
        "caveat": "Red Hat describes exploitation in combination with CVE-2015-3246 rather than as an unconditional standalone root escalation.",
        "type": "lpe",
    },
    {
        "cve": "CVE-2015-3246",
        "source_url": "https://access.redhat.com/solutions/1539123",
        "summary": "Red Hat states that the libuser vulnerability can be combined with the related userhelper issue for local privilege escalation to root on affected RHEL systems.",
        "evidence_group": "Red Hat advisory",
        "certainty": "medium",
        "caveat": "Red Hat describes exploitation in combination with CVE-2015-3245 rather than as an unconditional standalone root escalation.",
        "type": "lpe",
    },
    {
        "cve": "CVE-2016-4997",
        "source_url": "https://www.openwall.com/lists/oss-security/2016/06/24/5",
        "summary": "The Linux-kernel compat IPT_SO_SET_REPLACE disclosure describes memory corruption that can lead to privilege elevation or kernel code execution, including for an unprivileged user operating with user and network namespaces.",
        "evidence_group": "Openwall / Linux kernel disclosure",
        "certainty": "high",
        "caveat": "The disclosure's unprivileged trigger assumes access to user and network namespaces; it does not imply unrestricted exploitation on every kernel configuration.",
        "type": "lpe",
    },
    {
        "cve": "CVE-2017-2636",
        "source_url": "https://a13x0p0v.github.io/2017/03/24/CVE-2017-2636.html",
        "summary": "Alexander Popov's detailed Linux n_hdlc double-free research includes a working exploit that gains root privileges and bypasses SMEP; the write-up identifies the issue as affecting several mainstream distributions.",
        "evidence_group": "Alexander Popov research",
        "certainty": "high",
        "additional_source_urls": [
            "https://access.redhat.com/security/vulnerabilities/CVE-2017-2636"
        ],
        "type": "lpe",
    },
    {
        "cve": "CVE-2017-7184",
        "source_url": "https://openwall.com/lists/oss-security/2017/03/29/2",
        "summary": "The XFRM framework disclosure describes out-of-bounds reads and writes that can be used for local privilege escalation when the attacker has the relevant network-namespace capability.",
        "evidence_group": "Openwall / Chaitin disclosure",
        "certainty": "high",
        "caveat": "The stated exploitation path requires the relevant network-namespace capability, including CAP_NET_ADMIN.",
        "type": "lpe",
    },
    {
        "cve": "CVE-2017-11176",
        "source_url": "https://blog.lexfo.fr/cve-2017-11176-linux-kernel-exploitation-part4.html",
        "summary": "Lexfo's detailed POSIX message-queue exploit series ends with arbitrary kernel code execution and root credentials, providing direct evidence of Linux local privilege escalation.",
        "evidence_group": "Lexfo research",
        "certainty": "high",
        "additional_source_urls": [
            "https://blog.lexfo.fr/cve-2017-11176-linux-kernel-exploitation-part1.html",
            "https://blog.lexfo.fr/cve-2017-11176-linux-kernel-exploitation-part3.html",
            "https://ubuntu.com/security/CVE-2017-11176"
        ],
        "type": "lpe",
    },
    {
        "cve": "CVE-2019-18683",
        "source_url": "https://a13x0p0v.github.io/2020/02/15/CVE-2019-18683.html",
        "summary": "A detailed V4L2 vivid-driver research write-up documents a Linux local privilege-escalation exploit that gains kernel-thread control and bypasses KASLR, SMEP, and SMAP on Ubuntu Server.",
        "evidence_group": "Alexander Popov research",
        "certainty": "high",
        "additional_source_urls": [
            "https://www.cve.org/CVERecord?id=CVE-2019-18683",
            "https://www.openwall.com/lists/oss-security/2019/11/02/1"
        ],
        "type": "lpe",
    },
    {
        "cve": "CVE-2021-32606",
        "source_url": "https://www.openwall.com/lists/oss-security/2021/05/12/1",
        "summary": "The Linux CAN ISOTP race/UAF disclosure includes exploit details and a run ending with uid=0(root), directly demonstrating local privilege escalation.",
        "evidence_group": "Openwall / Linux kernel disclosure",
        "certainty": "high",
        "additional_source_urls": [
            "https://www.openwall.com/lists/oss-security/2021/05/13/2"
        ],
        "type": "lpe",
    },
    {
        "cve": "CVE-2021-3609",
        "source_url": "https://www.openwall.com/lists/oss-security/2021/06/19/1",
        "summary": "The CAN BCM race disclosure calls CVE-2021-3609 a proven Linux local privilege-escalation-to-root issue and links a proof of concept adapted for Ubuntu 20.04.",
        "evidence_group": "Openwall / Linux kernel disclosure",
        "certainty": "high",
        "additional_source_urls": [
            "https://github.com/nrb547/kernel-exploitation/blob/main/cve-2021-3609/cve-2021-3609.md"
        ],
        "type": "lpe",
    },
    {
        "cve": "CVE-2021-41073",
        "source_url": "https://www.openwall.com/lists/oss-security/2021/09/18/2",
        "summary": "The io_uring disclosure says the controllable kernel-buffer free is reachable by an unprivileged user and is straightforward to exploit for local privilege escalation.",
        "evidence_group": "Openwall / Linux kernel disclosure",
        "certainty": "high",
        "type": "lpe",
    },
    {
        "cve": "CVE-2022-1786",
        "source_url": "https://www.openwall.com/lists/oss-security/2022/05/24/4",
        "summary": "The io_uring invalid-free disclosure reports a proof of concept demonstrating local privilege escalation and identifies affected Linux, Android, and ChromeOS kernel versions.",
        "evidence_group": "Openwall / Linux kernel disclosure",
        "certainty": "high",
        "additional_source_urls": [
            "https://source.android.com/docs/security/bulletin/2022-10-01?hl=en"
        ],
        "type": "lpe",
    },
    {
        "cve": "CVE-2022-2588",
        "source_url": "https://www.openwall.com/lists/oss-security/2022/08/09/6",
        "summary": "The cls_route use-after-free disclosure says ZDI found the issue exploitable for local privilege escalation; the stated prerequisite is CAP_NET_ADMIN in a user and network namespace.",
        "evidence_group": "Openwall / Canonical disclosure",
        "certainty": "medium",
        "caveat": "The reported LPE requires CAP_NET_ADMIN in a user and network namespace; the disclosure does not establish a universal unprivileged-host exploit.",
        "type": "lpe",
    },
    {
        "cve": "CVE-2022-20409",
        "source_url": "https://source.android.com/docs/security/bulletin/2022-10-01?hl=en",
        "summary": "Google's Android Security Bulletin classifies this kernel issue as local elevation of privilege in a kernel component, with system execution privileges listed as the prerequisite; it does not provide a detailed public exploit.",
        "evidence_group": "Google Android Security Bulletin",
        "certainty": "medium",
        "type": "lpe",
    },
    {
        "cve": "CVE-2022-20421",
        "source_url": "https://source.android.com/docs/security/bulletin/2022-10-01?hl=en",
        "summary": "Google's Android Security Bulletin classifies this upstream-kernel issue as local elevation of privilege with no additional execution privileges needed; the bulletin is the evidence, without a detailed public exploit.",
        "evidence_group": "Google Android Security Bulletin",
        "certainty": "medium",
        "type": "lpe",
    },
    {
        "cve": "CVE-2022-20422",
        "source_url": "https://source.android.com/docs/security/bulletin/2022-10-01?hl=en",
        "summary": "Google's Android Security Bulletin classifies this upstream-kernel issue as local elevation of privilege with no additional execution privileges needed; the bulletin is the evidence, without a detailed public exploit.",
        "evidence_group": "Google Android Security Bulletin",
        "certainty": "medium",
        "type": "lpe",
    },
    {
        "cve": "CVE-2022-20423",
        "source_url": "https://source.android.com/docs/security/bulletin/2022-10-01?hl=en",
        "summary": "Google's Android Security Bulletin classifies this upstream-kernel issue as local elevation of privilege with no additional execution privileges needed; the bulletin is the evidence, without a detailed public exploit.",
        "evidence_group": "Google Android Security Bulletin",
        "certainty": "medium",
        "type": "lpe",
    },
    {
        "cve": "CVE-2022-39189",
        "source_url": "https://source.android.com/docs/security/bulletin/2023-02-01?hl=en",
        "summary": "Google's Android Security Bulletin classifies this upstream-kernel issue as local elevation of privilege with no additional execution privileges needed; the bulletin does not publish a detailed exploit.",
        "evidence_group": "Google Android Security Bulletin",
        "certainty": "medium",
        "type": "lpe",
    },
    {
        "cve": "CVE-2022-39842",
        "source_url": "https://source.android.com/docs/security/bulletin/2023-02-01?hl=en",
        "summary": "Google's Android Security Bulletin classifies this upstream-kernel issue as local elevation of privilege with no additional execution privileges needed; the bulletin does not publish a detailed exploit.",
        "evidence_group": "Google Android Security Bulletin",
        "certainty": "medium",
        "type": "lpe",
    },
    {
        "cve": "CVE-2022-41222",
        "source_url": "https://source.android.com/docs/security/bulletin/2023-02-01?hl=en",
        "summary": "Google's Android Security Bulletin classifies this upstream-kernel issue as local elevation of privilege with no additional execution privileges needed; the bulletin does not publish a detailed exploit.",
        "evidence_group": "Google Android Security Bulletin",
        "certainty": "medium",
        "type": "lpe",
    },
    {
        "cve": "CVE-2023-20937",
        "source_url": "https://source.android.com/docs/security/bulletin/2023-02-01?hl=en",
        "summary": "Google's Android Security Bulletin classifies this upstream-kernel issue as local elevation of privilege with no additional execution privileges needed; the bulletin does not publish a detailed exploit.",
        "evidence_group": "Google Android Security Bulletin",
        "certainty": "medium",
        "type": "lpe",
    },
    {
        "cve": "CVE-2023-20938",
        "source_url": "https://source.android.com/docs/security/bulletin/2023-02-01?hl=en",
        "summary": "Google's Android Security Bulletin classifies this upstream-kernel issue as local elevation of privilege with no additional execution privileges needed; the bulletin does not publish a detailed exploit.",
        "evidence_group": "Google Android Security Bulletin",
        "certainty": "medium",
        "type": "lpe",
    },
    {
        "cve": "CVE-2023-4622",
        "source_url": "https://source.android.com/docs/security/bulletin/2024-05-01?hl=en",
        "summary": "Google's Android Security Bulletin classifies CVE-2023-4622 as an upstream-kernel local elevation-of-privilege issue; no detailed public exploit is included in the bulletin.",
        "evidence_group": "Google Android Security Bulletin",
        "certainty": "medium",
        "type": "lpe",
    },
    {
        "cve": "CVE-2024-48990",
        "source_url": "https://blog.qualys.com/vulnerabilities-threat-research/2024/11/19/qualys-tru-uncovers-five-local-privilege-escalation-vulnerabilities-in-needrestart",
        "summary": "Qualys reports CVE-2024-48990 as one of five needrestart/Module::ScanDeps vulnerabilities with functional exploits, allowing an unprivileged local user to reach full root on affected Linux systems.",
        "evidence_group": "Qualys needrestart research",
        "certainty": "high",
        "additional_source_urls": [
            "https://canonical.com/blog/needrestart-local-privilege-escalation"
        ],
        "type": "lpe",
    },
    {
        "cve": "CVE-2024-48991",
        "source_url": "https://blog.qualys.com/vulnerabilities-threat-research/2024/11/19/qualys-tru-uncovers-five-local-privilege-escalation-vulnerabilities-in-needrestart",
        "summary": "Qualys reports CVE-2024-48991 as one of five needrestart/Module::ScanDeps vulnerabilities with functional exploits, allowing an unprivileged local user to reach full root on affected Linux systems.",
        "evidence_group": "Qualys needrestart research",
        "certainty": "high",
        "additional_source_urls": [
            "https://canonical.com/blog/needrestart-local-privilege-escalation"
        ],
        "type": "lpe",
    },
    {
        "cve": "CVE-2024-48992",
        "source_url": "https://blog.qualys.com/vulnerabilities-threat-research/2024/11/19/qualys-tru-uncovers-five-local-privilege-escalation-vulnerabilities-in-needrestart",
        "summary": "Qualys reports CVE-2024-48992 as one of five needrestart/Module::ScanDeps vulnerabilities with functional exploits, allowing an unprivileged local user to reach full root on affected Linux systems.",
        "evidence_group": "Qualys needrestart research",
        "certainty": "high",
        "additional_source_urls": [
            "https://canonical.com/blog/needrestart-local-privilege-escalation"
        ],
        "type": "lpe",
    },
    {
        "cve": "CVE-2024-10224",
        "source_url": "https://blog.qualys.com/vulnerabilities-threat-research/2024/11/19/qualys-tru-uncovers-five-local-privilege-escalation-vulnerabilities-in-needrestart",
        "summary": "Qualys reports CVE-2024-10224 as one of five needrestart/Module::ScanDeps vulnerabilities with functional exploits, allowing an unprivileged local user to reach full root on affected Linux systems.",
        "evidence_group": "Qualys needrestart research",
        "certainty": "high",
        "additional_source_urls": [
            "https://canonical.com/blog/needrestart-local-privilege-escalation"
        ],
        "type": "lpe",
    },
    {
        "cve": "CVE-2024-11003",
        "source_url": "https://blog.qualys.com/vulnerabilities-threat-research/2024/11/19/qualys-tru-uncovers-five-local-privilege-escalation-vulnerabilities-in-needrestart",
        "summary": "Qualys reports CVE-2024-11003 as one of five needrestart/Module::ScanDeps vulnerabilities with functional exploits, allowing an unprivileged local user to reach full root on affected Linux systems.",
        "evidence_group": "Qualys needrestart research",
        "certainty": "high",
        "additional_source_urls": [
            "https://canonical.com/blog/needrestart-local-privilege-escalation"
        ],
        "type": "lpe",
    },
    {
        "cve": "CVE-2025-0927",
        "source_url": "https://ssd-disclosure.com/ssd-advisory-linux-kernel-hfsplus-slab-out-of-bounds-write/",
        "summary": "SSD documents a detailed HFS+ kernel heap-overflow exploit achieving local privilege escalation on Ubuntu 22.04 active sessions.",
        "evidence_group": "SSD research / Ubuntu advisory",
        "certainty": "high",
        "caveat": "The upstream Linux-kernel CNA disputed/rejected the CVE scope because mounting the crafted image requires CAP_SYS_ADMIN in the initial namespace. This record preserves the Ubuntu-specific precondition rather than treating the issue as a universal unprivileged LPE.",
        "additional_source_urls": [
            "https://ubuntu.com/security/CVE-2025-0927"
        ],
        "type": "lpe",
    },
    {
        "cve": "CVE-2025-32463",
        "source_url": "https://www.openwall.com/lists/oss-security/2025/06/30/3",
        "summary": "The sudo maintainer states that an attacker can abuse sudo's chroot option to load an arbitrary shared library and run arbitrary commands as root, even when the attacker is not listed in sudoers.",
        "evidence_group": "Openwall / sudo disclosure",
        "certainty": "high",
        "type": "lpe",
    },
    {
        "cve": "CVE-2025-6018",
        "source_url": "https://www.openwall.com/lists/oss-security/2025/06/17/4",
        "summary": "The detailed Qualys disclosure describes CVE-2025-6018 as the first stage of a Linux desktop escalation chain: an unprivileged SSH user can influence PAM environment handling and obtain the local allow_active polkit context; chained with CVE-2025-6019, the path reaches root.",
        "evidence_group": "Qualys / Openwall disclosure",
        "certainty": "high",
        "caveat": "This record describes the first stage of a conditional chain; full root requires the separately affected CVE-2025-6019 component and the applicable desktop/udisks environment.",
        "type": "lpe",
    },
    {
        "cve": "CVE-2025-6019",
        "source_url": "https://www.openwall.com/lists/oss-security/2025/06/17/4",
        "summary": "The detailed Qualys disclosure describes CVE-2025-6019 in libblockdev/udisks as a second-stage local escalation: the allow_active context can be used to obtain full root, and the published chain combines it with CVE-2025-6018 for an effectively unprivileged-to-root path.",
        "evidence_group": "Qualys / Openwall disclosure",
        "certainty": "high",
        "caveat": "The effectively unprivileged path is a chain with CVE-2025-6018 and depends on the affected polkit/udisks desktop configuration; this is not a standalone universal kernel-style LPE.",
        "type": "lpe",
    },
    {
        "cve": "CVE-2025-6020",
        "source_url": "https://www.openwall.com/lists/oss-security/2025/06/17/1",
        "summary": "The linux-pam pam_namespace disclosure describes a malicious user altering root-operated paths from another mount namespace and says a proof of concept demonstrates local privilege escalation to root through symlink/race behavior.",
        "evidence_group": "Openwall / ANSSI disclosure",
        "certainty": "high",
        "type": "lpe",
    },
    {
        "cve": "CVE-2025-41244",
        "source_url": "https://www.openwall.com/lists/oss-security/2025/09/29/10",
        "summary": "VMware's security advisory states that a non-admin guest user can exploit the open-vm-tools issue to escalate to root on the same virtual machine; the advisory does not publish a detailed exploit.",
        "evidence_group": "VMware / Openwall advisory",
        "certainty": "medium",
        "caveat": "This is guest-local escalation to root within the same virtual machine, not a demonstrated host escape, and the vendor advisory does not include a detailed public exploit.",
        "additional_source_urls": [
            "https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/36149"
        ],
        "type": "lpe",
    },
    {
        "cve": "CVE-2025-14282",
        "source_url": "https://www.openwall.com/lists/oss-security/2025/12/16/2",
        "summary": "Dropbear's release/security notice says the Unix stream-forwarding flaw can let an authenticated user run arbitrary programs as root when the host exposes suitable root-owned Unix sockets; this is explicit local privilege-escalation evidence with environmental conditions.",
        "evidence_group": "Dropbear / Openwall advisory",
        "certainty": "medium",
        "caveat": "The escalation requires authentication and suitable root-owned Unix sockets or other host-side programs; the advisory does not establish that every Dropbear deployment is exploitable.",
        "additional_source_urls": [
            "https://github.com/mkj/dropbear/pull/391"
        ],
        "type": "lpe",
    },
    {
        "cve": "CVE-2026-15226",
        "source_url": "https://ubuntu.com/security/CVE-2026-15226",
        "summary": "Ubuntu describes a local snap confinement/namespace escalation in which a confined snap can create and execute setuid binaries and perform privileged actions inside its container namespace. This is included as scoped LPE evidence, not as a demonstrated host-root escape.",
        "evidence_group": "Ubuntu snap advisory",
        "certainty": "medium",
        "caveat": "The documented impact is inside the snap's container/namespace boundary; no host-root escape is established by the cited Ubuntu advisory.",
        "type": "lpe",
    },
    {
        "cve": "CVE-2026-3888",
        "source_url": "https://blog.qualys.com/vulnerabilities-threat-research/2026/03/17/cve-2026-3888-important-snap-flaw-enables-local-privilege-escalation-to-root",
        "summary": "Qualys reports a working time-based exploit for Ubuntu snap-confine that turns an unprivileged local Ubuntu Desktop user into full root; Ubuntu's CVE page and security notice corroborate the issue and fixes.",
        "evidence_group": "Qualys / Ubuntu snap advisory",
        "certainty": "high",
        "additional_source_urls": [
            "https://ubuntu.com/security/CVE-2026-3888",
            "https://ubuntu.com/security/notices/USN-8102-1"
        ],
        "type": "lpe",
    },
    {
        "cve": "CVE-2026-8933",
        "source_url": "https://ubuntu.com/security/CVE-2026-8933",
        "summary": "Ubuntu states that a local unprivileged attacker can bypass snap-confine restrictions and execute arbitrary code, with successful exploitation reaching full root; the accompanying notice supplies fixed versions.",
        "evidence_group": "Ubuntu snap advisory",
        "certainty": "high",
        "additional_source_urls": [
            "https://ubuntu.com/security/notices/USN-8579-1"
        ],
        "type": "lpe",
    },
    {
        "cve": "CVE-2026-43074",
        "source_url": "https://github.com/2045castor/security-research/blob/submit_final/pocs/linux/kernelctf/CVE-2026-43074_lts/docs/exploit.md",
        "summary": "The kernelCTF Epollution exploit documentation reports a data-only Linux privilege-escalation chain that changes effective-UID credentials and reliably obtains a root helper on the stated LTS target.",
        "evidence_group": "Google kernelCTF / Epollution",
        "certainty": "high",
        "additional_source_urls": [
            "https://github.com/2045castor/security-research/tree/submit_final/pocs/linux/kernelctf/CVE-2026-43074_lts"
        ],
        "type": "lpe",
    },
    {
        "cve": "CVE-2026-43499",
        "source_url": "https://nebusec.ai/research/ionstack-part-2/",
        "summary": "NebuSec's detailed GhostLock research documents a stable local privilege-escalation/container-escape exploit reaching root without special privileges or configuration; the write-up reports high reliability on the affected Linux kernel range.",
        "evidence_group": "NebuSec / GhostLock research",
        "certainty": "high",
        "additional_source_urls": [
            "https://www.openwall.com/lists/oss-security/2026/07/08/12"
        ],
        "type": "lpe",
    },
    {
        "cve": "CVE-2026-46242",
        "source_url": "https://www.openwall.com/lists/oss-security/2026/07/08/13",
        "summary": "The Bad Epoll kernelCTF disclosure and linked exploit write-up document an unprivileged Linux process becoming root, including a reliable root-shell result on the stated LTS target; Android exploitation was described as ongoing rather than established here.",
        "evidence_group": "Openwall / Google kernelCTF",
        "certainty": "high",
        "caveat": "The root result is demonstrated on the named Linux kernelCTF target; the cited material does not establish Android exploitation, which was described as ongoing.",
        "additional_source_urls": [
            "https://github.com/J-jaeyoung/security-research/blob/submit-cve-2026-46242/pocs/linux/kernelctf/CVE-2026-46242_lts_cos/docs/exploit.md"
        ],
        "type": "lpe",
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
        caveats = [current.get("caveat"), item.get("caveat")]
        caveats = list(dict.fromkeys(caveat for caveat in caveats if caveat))
        if caveats:
            current["caveat"] = " ".join(caveats)
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
            "record_fields": {
                "caveat": "Optional per-record note for prerequisites, deployment scope, conditional exploit chains, disputed CVE scope, or evidence limitations.",
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
            "Each JSON record has a primary `source_url`. When a CVE was independently supported by more than one source, the other URLs are retained under `additional_source_urls`. Records may include an optional `caveat` field for prerequisites, scope limits, conditional chains, disputed CVE scope, or evidence limitations.",
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
