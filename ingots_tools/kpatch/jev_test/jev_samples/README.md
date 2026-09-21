# JEV security-classification samples

This directory contains 20 paired C security-review cases. Each odd-numbered
sample contains a vulnerability; the following even-numbered sample implements
the corresponding fix. The source filenames and source text intentionally do
not reveal the expected verdict to the model.

`manifest.json` records the ground truth, weakness family, and the reasoning
needed to score each result. The snippets are self-contained analysis fixtures:
external functions stand in for documented system or kernel APIs, and comments
state the attacker and concurrency assumptions that are necessary for review.

The pairs cover:

1. Double-fetch race versus a stable snapshot
2. Asynchronous object lifetime without versus with a retained reference
3. Integer truncation versus checked size arithmetic
4. Format-string injection versus a fixed format
5. Authorization against request fields versus the loaded object
6. Path validation/open race versus constrained `openat2`
7. Uninitialized structure padding versus full initialization
8. Unlocked object lifetime versus a reference acquired under the lock
9. Shell command injection versus argument-vector process creation
10. One-byte heap overflow versus checked allocation for a terminator

Run all samples from the `kpatch` directory with:

```bash
OPENROUTER_API_KEY=... uv run run_jev_trials.py
```

The runner writes raw model output and derived predictions to
`jev_trial_results.json`.
