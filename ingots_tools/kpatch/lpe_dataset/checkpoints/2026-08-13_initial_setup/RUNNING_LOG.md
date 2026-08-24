# Running Log

## 2026-08-13 — Initial dataset research setup

- Goal: assemble a source-backed list of Linux CVEs with credible evidence of local privilege escalation (LPE) or remote code execution (RCE), without collecting exploit code.
- Checkpoint: `checkpoints/2026-08-13_initial_setup/`
- Workspace: fresh directory; no Git metadata or prior artifacts were present.
- Planned artifacts: source records, generated JSON, source-audit Markdown, and a Python generator/normalizer.
- Next step: query authoritative advisories, KernelCTF, Android security bulletins, vendor advisories, and detailed security writeups; record checked sources and classify evidence strength.
