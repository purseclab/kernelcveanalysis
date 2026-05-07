---
name: exploit-running-log-checkpoints
description: Use when working on exploit development or vulnerability research and maintaining RUNNING_LOG.md plus milestone checkpoints. Applies before and after code edits, experiments, reliability work, debugging, reproductions, and any session where findings or issues should persist for later agents.
---

# Running Log And Checkpoints

Use this skill to keep exploit work recoverable and understandable across long debugging and research sessions.

## Terms

- `RUNNING_LOG.md`: the append-only project work log.
- `checkpoints/`: the milestone snapshot directory.

## Start Of Work

1. Check the current directory and `git status --short`.
2. Read the tail of `RUNNING_LOG.md` to understand the latest state.
3. Before risky edits or long experiments, create a checkpoint:
   - Directory name: `checkpoints/YYYY-MM-DD_short_descriptive_milestone/`
   - Examples: `checkpoints/2026-05-07_before_cleanup_change/`, `checkpoints/2026-05-07_minimal_repro_success/`
4. Copy the relevant current artifacts into the checkpoint:
   - Always include `RUNNING_LOG.md` when it exists.
   - Include source files, wrappers, configs, binaries, and scripts that may be changed or are needed to reproduce the run.
   - For executed experiments, include the launcher or wrapper, captured logs, traces, result files, and exact binary or artifact used when available.

## Updating RUNNING_LOG.md

Append entries; do not rewrite history unless correcting a clear typo or explicitly asked.

Each material entry should include:

- Goal or hypothesis.
- Checkpoint directory.
- Files or binaries used, especially if running an older checkpoint binary.
- Exact command or enough command detail to reproduce important runs.
- Relevant runtime parameters, resource limits, environment, privileges, and setup assumptions.
- Important environment variables and tuning knobs.
- Result counts such as attempts, successes, rejected candidates, crashes, hangs, panics, or timeouts.
- Key trace or log evidence, including addresses only when useful for comparing patterns.
- Failure mode and current interpretation.
- Next steps or open questions.

Keep entries concise but durable. Future agents should be able to answer "what changed, what was tested, what happened, and where are the artifacts?"

## During Experiments

- Update the log after each significant run, not only at the end of the session.
- If a run is interrupted or crashes, record that explicitly.
- If a long-running command is active, do not final-answer until it exits or is intentionally stopped.
- If you change a wrapper only for an experiment, store that wrapper inside the checkpoint run folder.
- Preserve user changes. Do not revert or delete checkpoints unless the user explicitly asks.

## Staging

- Do not stage checkpoint directories by default.
- If asked to stage exploit-relevant work, stage source, wrappers, binaries, configs, generated artifacts, and `RUNNING_LOG.md` as requested, while leaving checkpoints unstaged unless explicitly included.

## Final Response

Before finalizing, verify:

- `RUNNING_LOG.md` has the latest result.
- Any required checkpoint exists and contains the relevant artifacts.
- No required long-running command or debug session is still running.
- The final answer reports the important outcome, artifact paths, and any unrun or failed verification.
