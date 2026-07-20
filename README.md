# Repository Contents

This repository presents the results of our research on Linux and Android exploitation.


## [Kexploit: Automatic PoC Adaptation](ingots_tools/kexploit/)
Kexploit is a framework for automatically adapting Android/Linux kernel exploit proofs-of-concept (PoCs) across different kernel versions.

## Docker setup

All Docker setup for Ingots agent sandboxes is centralized in
`ingots_tools/kexploit_utils`. Build the maintained images from the
`ingots_tools` workspace with:

```bash
uv run kexploit-utils build-all
```


## [Crash Analyzer](syzbot_repro_analysis/)
Crash Analyzer is a tool to attempt reproducing crashes detected by syzbot in a given target Android environment..


## [Android Environment Analyzer](ingots_tools/android_env/)
A toolkit for auditing an Android device’s runtime environment and mapping the access-control boundaries between process domains. 


## [Vulnerability Knowledge Base (VKB)](vkb/)

- A lightweight version of the VKB (excluding PoC source code) is available in: `vulnerabilities_nopocs.db`.

- The full version of the VKB, including the source code for proof-of-concept exploits, can be downloaded here: [vulnerabilities.db](https://www.cs.purdue.edu/homes/antoniob/shared/vulnerabilities.db).


