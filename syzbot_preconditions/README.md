# Kernel Primitives Characterization


## Purpose

This small heuristic tool parses Linux kernel crash logs (KASAN, BUG, general protection faults, etc.),
extracts the stack frames, allocation/free traces and object metadata, pulls nearby source snippets
when available, and produces both a compact triage report and a richer JSON report with
evidence-driven static analysis (including a best-effort exploitability judgment and path constraints).

The analyzer is intentionally conservative: it reports the low-level primitive (e.g. "null-pointer-deref",
"use-after-free", "out-of-bounds") and a human-friendly `overview` that explains the reasoning
and relevant evidence lines. It also supports optional LLM enrichment if you configure a local model
or API keys.

## Quick start

1) Human-readable summary of a crash log:

```bash
python3 crash_analyzer.py crashlog.txt
```

2) Emit full JSON (parsed fields, fetched snippets, per-snippet evidence, strong heuristics):

```bash
python3 crash_analyzer.py crashlog.txt --json
```

3) Prefer a local kernel source tree when fetching context lines:

```bash
python3 crash_analyzer.py crashlog.txt --source-root /path/to/linux --json
```

4) Compact triage JSON suitable for automation:

```bash
python3 crash_analyzer.py crashlog.txt --json-report > triage.json
```

5) Generate an HTML report (includes fetched snippets and evidence):

```bash
python3 crash_analyzer.py crashlog.txt --html-report /tmp/crash_report.html
```

6) Download and analyze a syzkaller bug page (attachments + embedded <pre> text):

```bash
python3 crash_analyzer.py --syz-bug 'https://syzkaller.appspot.com/bug?extid=FEEDBEEF' --json
```

## Notes on source fetching

- If the crash log includes links to viewers (GitHub, android.googlesource, git.kernel.org), the tool will
  try to fetch the single file and extract the requested fragment using the URL fragment (#L123 or #123).
- If you provide `--source-root` pointing at a matching kernel source checkout, local files are preferred
  to remote fetches (faster and more reliable for offline analysis).

## LLM integration (optional)

The analyzer contains optional LLM-driven enrichment to produce more natural preconditions and
reasoning. There are two main modes:

- Local transformers model: configure `TRANSFORMERS_DIRECT_MODEL` and install `transformers`, `torch`,
  and related runtimes in a virtual environment. This is disabled by default.
- API-based providers: the code has a small OpenAI helper (`get_openai_response`) you can enable by
  setting appropriate API keys.
- To enable utilize OpenAI, fill in the `.env` file with your key or set the environment variable directly:
```bash
export OPENAI_API_KEY="sk-..."
```

If you don't want LLM calls, the analyzer will still produce the full static analysis (`strong_report`)
which includes `overview`, `preconditions`, `path_constraints`, and supporting evidence.

## Dependencies and environment

- Python 3.8+ recommended.
- Network access is required to fetch remote source files or to run API-based LLM calls.
- Optional: Installing `transformers` and `torch` enables the local LLM path. On many systems a CPU-only
  install is easiest (pip wheels). Use a virtualenv to avoid polluting system packages.

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

If you encounter binary import errors (for example with Pillow or compiled extensions), prefer using the
project's venv or a system package manager to install the required native libs.

## Output fields (JSON)

Top-level keys in the full JSON output (`--json`) include:

- `parsed`: structured fields extracted from the log (kind, access, frames, object_info, allocated_by, freed_by)
- `snippets`: fetched source snippets keyed by link/local id (contains `function_snippet`, `file`, `line`)
- `evidence`: per-snippet heuristic evidence (dereference counts, deref expressions, alloc/free calls)
- `strong_report` (produced by `stronger_heuristics`): a best-effort analysis containing:
  - `primitive`: low-level bug primitive (null-pointer-deref, use-after-free, out-of-bounds, etc.)
  - `vulnerability`: what an attacker could do (arbitrary_read/arbitrary_write/info-leak/DoS)
  - `confidence`: 0.0..1.0 score
  - `exploitability`: LOW/MEDIUM/HIGH (heuristic aggregation)
  - `preconditions` / `postconditions`: natural-language pre/postconditions
  - `path_constraints`: structured list of input and kernel-state checks (file/line/code/why_it_blocks)
  - `overview`: compact summary with `exploitability`, `rationale`, and a `primitive_capabilities`

## Examples and debugging tips

- If `path_constraints` is empty but snippets exist, try increasing `--source-root` coverage or ensure the
  fetched snippets include the function header (we attempt to walk to the function start but remote viewers
  sometimes return truncated fragments).
- KASAN frames and shadow-memory helpers are filtered out by default. If you need them, you can modify
  the frame-filtering heuristics in `parse_crash_log()`.
- If the static analysis and LLM disagree (e.g., static reports HIGH but LLM reports LOW), examine the
  `strong_report.support` array and `overview.confidence_breakdown` to see which signals influenced the verdict.

## Common commands summary

```bash
# basic summary
python3 crash_analyzer.py crash.txt

# full JSON with local source context
python3 crash_analyzer.py crash.txt --json --source-root ~/linux

# compact triage JSON
python3 crash_analyzer.py crash.txt --json-report > triage.json

# analyze a syzkaller bug page (downloads attachments)
python3 crash_analyzer.py --syz-bug 'https://syzkaller.appspot.com/bug?extid=ff97a14204e1de3f1a08' --json
```
